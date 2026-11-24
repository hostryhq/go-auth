package auth

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hostryhq/go-auth/internal/authctx"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
)

// DefaultStepUpWindow is how fresh an OTP must be for x-step-up (ADR-0005 section 3).
const DefaultStepUpWindow = 10 * time.Minute

const codeInvalidToken = "auth.invalid_token"

// Guard is the HTTP middleware factory of a service. It verifies credentials,
// enforces each route's declared Policy before the handler runs, and puts the
// principal and the go-common tenancy context on the request context. Every
// failure path refuses; there is no path to a handler that skips a check.
type Guard struct {
	Catalogue *Catalogue
	// Tenant verifies tenant-realm access tokens. Vendor verifies vendor-realm
	// tokens and is nil in services that serve no vendor routes.
	Tenant *Verifier
	Vendor *Verifier
	// Services verifies service tokens; nil in a service with no internal routes.
	Services *ServiceVerifier
	// SupportCallers are the services whose service token must accompany a
	// support token (ADR-0013 V2 item 5). Default: ["admin"].
	SupportCallers []string
	Approvals      *ApprovalChecker
	// Audit is the service's vendor_access_log hook. A service that accepts
	// vendor or support tokens must set it; without it those requests are refused.
	Audit        VendorAuditSink
	Clock        clock.Clock
	StepUpWindow time.Duration
	Log          *slog.Logger
}

func (g *Guard) now() time.Time {
	if g.Clock == nil {
		return clock.System.Now()
	}
	return g.Clock.Now()
}

func (g *Guard) log() *slog.Logger {
	if g.Log == nil {
		return slog.Default()
	}
	return g.Log
}

func (g *Guard) supportCallers() []string {
	if len(g.SupportCallers) == 0 {
		return []string{"admin"}
	}
	return g.SupportCallers
}

// Handle registers h on mux behind the guard. It panics at start-up when the
// policy is invalid, when a path under /internal/v1 is not declared internal
// (or the reverse), or when the guard lacks what the policy needs.
func (g *Guard) Handle(mux *http.ServeMux, pattern string, p Policy, h http.Handler) {
	path := patternPath(pattern)
	if strings.HasPrefix(path, InternalPrefix) != p.Internal && !p.Public {
		panic("auth: route " + pattern + ": internal routes must live under " + InternalPrefix + " and be declared internal, and the reverse")
	}
	mux.Handle(pattern, g.Wrap(p, h))
}

// Wrap guards h with p. It panics at start-up if p is invalid.
func (g *Guard) Wrap(p Policy, h http.Handler) http.Handler {
	if g.Catalogue == nil {
		panic("auth: guard has no catalogue")
	}
	if err := p.Validate(g.Catalogue); err != nil {
		panic(err.Error())
	}
	if !p.Public {
		if g.Tenant == nil && !p.Internal {
			panic("auth: guard has no tenant verifier")
		}
		if p.Internal && g.Services == nil {
			panic("auth: guard has no service verifier for internal route " + p.OperationID)
		}
		if p.realm() == RealmVendor && g.Vendor == nil {
			panic("auth: guard has no vendor verifier for route " + p.OperationID)
		}
	}
	authz := &Authorizer{Catalogue: g.Catalogue, Clock: g.Clock}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Public {
			h.ServeHTTP(w, r)
			return
		}
		g.serve(w, r, p, authz, h)
	})
}

func unauthenticated() error {
	return apperr.New(apperr.Unauthenticated, codeInvalidToken, "invalid or missing credentials")
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (g *Guard) serve(w http.ResponseWriter, r *http.Request, p Policy, authz *Authorizer, next http.Handler) {
	ctx := authctx.Set(r.Context(), authctx.Authorizer, authz)
	fail := func(err error) { apperr.WriteProblem(w, r.WithContext(ctx), err) }
	refused := func(reason string) {
		g.log().WarnContext(ctx, "request refused", "operation", p.OperationID, "reason", reason)
		fail(unauthenticated())
	}

	// Service token: required on internal routes, and a support token needs one.
	var svc *Claims
	if tok := r.Header.Get(ServiceTokenHeader); tok != "" {
		if g.Services == nil {
			refused("service token on a service with no registry")
			return
		}
		c, err := g.Services.Verify(tok)
		if err != nil {
			refused(err.Error())
			return
		}
		svc = c
	}
	if p.Internal {
		if svc == nil {
			refused("internal route without service token")
			return
		}
		if !slices.Contains(p.Callers, svc.Issuer) {
			g.log().WarnContext(ctx, "caller not on x-service-callers", "operation", p.OperationID, "caller", svc.Issuer)
			fail(apperr.New(apperr.Forbidden, "auth.caller_not_allowed", "caller not allowed"))
			return
		}
	}

	if p.ServiceOnly {
		g.serveService(w, r, ctx, p, svc, next, fail)
		return
	}

	// User, vendor or support token.
	verifier := g.Tenant
	if p.realm() == RealmVendor {
		verifier = g.Vendor
	}
	tok := bearer(r)
	if tok == "" {
		refused("no bearer token")
		return
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		refused(err.Error())
		return
	}
	if !g.typeAllowedOnRoute(p, c, svc) {
		refused("token type not accepted on this route: " + string(c.Type))
		return
	}
	pr := NewPrincipal(c, tok)
	if svc != nil {
		pr.ServiceCaller = svc.Issuer
		if svc.TenantID != "" && c.TenantID != "" && svc.TenantID != c.TenantID {
			refused("service token tenant differs from the user token tenant")
			return
		}
	}

	// Tenancy context (tenant realm only). Vendor routes get theirs from the
	// path through VendorTenant.
	if p.realm() == RealmTenant {
		tid, err := ids.Parse(c.TenantID)
		if err != nil {
			refused("bad tid")
			return
		}
		tc := tenancy.Context{TenantID: tid, ActorID: c.Subject, DeviceID: c.DeviceID}
		if c.Type == TypeDevice || c.Type == TypePin {
			if o := singleOutlet(c.Grants); o != "" {
				tc.OutletID = ids.ID(o)
			}
		}
		ctx = tenancy.With(ctx, tc)
	}

	var gate *auditState
	if pr.IsVendorActor() {
		if g.Audit == nil {
			g.log().ErrorContext(ctx, "vendor-authority request but no audit sink configured", "operation", p.OperationID)
			fail(apperr.New(apperr.Internal, "audit.unavailable", ""))
			return
		}
		gate = &auditState{sink: g.Audit, entry: newEntry(r, pr, g.now(), p.OperationID), none: p.VendorAuditNone}
		ctx = authctx.Set(ctx, authctx.Audit, gate)
	}
	denyAudited := func(err error) {
		if gate != nil && !gate.none {
			e := gate.entry
			e.Outcome = OutcomeRefused
			if rerr := g.Audit.RecordRefused(ctx, e); rerr != nil {
				g.log().ErrorContext(ctx, "could not record refused vendor request", "operation", p.OperationID, "error", rerr)
			}
		}
		fail(err)
	}

	if err := g.authorize(r, p, authz, &pr); err != nil {
		denyAudited(err)
		return
	}

	ctx = authctx.Set(ctx, authctx.Principal, pr)
	req := r.WithContext(ctx)
	if gate != nil && !gate.none {
		w = &auditGate{ResponseWriter: w, r: req, st: gate}
	}
	next.ServeHTTP(w, req)
}

func (g *Guard) typeAllowedOnRoute(p Policy, c *Claims, svc *Claims) bool {
	switch {
	case p.AllowDrain:
		return c.Type == TypeDrain
	case p.realm() == RealmVendor:
		return c.Type == TypeUser
	}
	switch c.Type {
	case TypeUser, TypePin, TypeDevice:
		return true
	case TypeSupport:
		// A support token is useless without the admin service token (ADR-0013 V2).
		return svc != nil && slices.Contains(g.supportCallers(), svc.Issuer)
	}
	return false // drain tokens only on drain routes; approval and service tokens are not bearers
}

// authorize applies the route's permission, new-device caution and step-up.
func (g *Guard) authorize(r *http.Request, p Policy, authz *Authorizer, pr *Principal) error {
	if p.AllowDrain {
		return nil // type already pinned to drain; the route needs no permission
	}
	def, _ := g.Catalogue.Get(p.Permission)
	now := g.now()
	if pr.UnderCaution(now) && (def.StrongOnly || p.StepUp) {
		pr.Approved = g.Approvals.Check(r, *pr, p.OperationID) == nil
		if !pr.Approved {
			// Scope reports approval_required for strong_only; step-up routes
			// that are not strong_only are refused here.
			if _, err := authz.Scope(*pr, p.Permission); err != nil {
				return err
			}
			return apperr.New(apperr.Forbidden, CodeApprovalRequired, "approval required for this operation on a new device")
		}
	}
	if _, err := authz.Scope(*pr, p.Permission); err != nil {
		return err
	}
	if p.StepUp {
		window := g.StepUpWindow
		if window == 0 {
			window = DefaultStepUpWindow
		}
		if !pr.StepUpFresh(now, window) {
			return apperr.New(apperr.Forbidden, CodeStepUpRequired, "a fresh one-time code is required")
		}
	}
	return nil
}

// serveService handles a ServiceOnly operation: the service token is the only
// credential. The tenant, if any, comes from its tenant claim and must parse;
// an operation that needs a tenant and has none is refused.
func (g *Guard) serveService(w http.ResponseWriter, r *http.Request, ctx context.Context, p Policy, svc *Claims, next http.Handler, fail func(error)) {
	pr := Principal{Type: TypeService, Subject: svc.Issuer, TenantID: svc.TenantID, ServiceCaller: svc.Issuer}
	if svc.TenantID != "" {
		tid, err := ids.Parse(svc.TenantID)
		if err != nil {
			fail(unauthenticated())
			return
		}
		ctx = tenancy.With(ctx, tenancy.Context{TenantID: tid, ActorID: svc.Issuer})
	} else if !p.NoTenant {
		fail(apperr.New(apperr.Unauthenticated, "auth.tenant_missing", "tenant context missing"))
		return
	}
	ctx = authctx.Set(ctx, authctx.Principal, pr)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func singleOutlet(gs []Grant) string {
	one := ""
	for _, g := range gs {
		for _, o := range g.Outlets {
			if o == "*" {
				return ""
			}
			if one != "" && o != one {
				return ""
			}
			one = o
		}
	}
	return one
}
