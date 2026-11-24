package auth

import (
	"context"
	"sort"
	"time"

	"github.com/hostryhq/go-auth/internal/authctx"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"
)

// Error codes returned by the authorisation checks.
const (
	CodeUnauthenticated   = "auth.unauthenticated"
	CodePermissionDenied  = "auth.permission_denied"
	CodeApprovalRequired  = "approval_required" // A2.2
	CodeStepUpRequired    = "auth.step_up_required"
	CodeResourceNotFound  = "resource.not_found"
	CodeGrantNotPermitted = "grant_not_permitted" // A2.4 G7 (used by grantlimit)
)

// OutletScope is the set of outlets a caller may reach for one permission:
// every outlet, or a set of ids (ADR-0003 A1.4). The zero value is empty.
type OutletScope struct {
	all bool
	ids []string // sorted, unique
}

// AllOutlets is the organisation-wide scope.
func AllOutlets() OutletScope { return OutletScope{all: true} }

// OnlyOutlets is a scope of the given outlets.
func OnlyOutlets(ids ...string) OutletScope {
	m := map[string]struct{}{}
	for _, id := range ids {
		if id != "" {
			m[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return OutletScope{ids: out}
}

// All reports an organisation-wide scope.
func (s OutletScope) All() bool { return s.all }

// Empty reports that no outlet is in scope.
func (s OutletScope) Empty() bool { return !s.all && len(s.ids) == 0 }

// IDs returns the outlet ids of a restricted scope (nil when All). Repositories
// bind it as the outlet_id predicate parameter.
func (s OutletScope) IDs() []string { return append([]string(nil), s.ids...) }

// Contains reports whether the outlet is in scope.
func (s OutletScope) Contains(outletID string) bool {
	if s.all {
		return outletID != ""
	}
	i := sort.SearchStrings(s.ids, outletID)
	return outletID != "" && i < len(s.ids) && s.ids[i] == outletID
}

// Covers reports whether s includes every outlet of other.
func (s OutletScope) Covers(other OutletScope) bool {
	if s.all {
		return true
	}
	if other.all {
		return false
	}
	for _, id := range other.ids {
		if !s.Contains(id) {
			return false
		}
	}
	return true
}

// Intersect narrows s by a request's outlet_id filter (A1.4 item 4). An empty
// filter leaves s unchanged.
func (s OutletScope) Intersect(filter []string) OutletScope {
	if len(filter) == 0 {
		return s
	}
	if s.all {
		return OnlyOutlets(filter...)
	}
	var keep []string
	for _, id := range filter {
		if s.Contains(id) {
			keep = append(keep, id)
		}
	}
	return OnlyOutlets(keep...)
}

// Authorizer evaluates permissions for a principal against the catalogue.
type Authorizer struct {
	Catalogue *Catalogue
	Clock     clock.Clock
}

func (a *Authorizer) now() time.Time {
	if a.Clock == nil {
		return clock.System.Now()
	}
	return a.Clock.Now()
}

func denied() error {
	return apperr.New(apperr.Forbidden, CodePermissionDenied, "permission denied")
}

// ceilingDenies applies the token-type ceilings that no grant can lift:
// strong_only never in pin, device or drain sessions (ADR-0005 section 5), and
// the support ceiling (A2.5).
func ceilingDenies(p Principal, def Permission) bool {
	switch p.Type {
	case TypeDrain:
		return true
	case TypePin, TypeDevice:
		return def.StrongOnly
	case TypeSupport:
		if def.StrongOnly || def.OwnerGrant || def.Sensitive {
			return true
		}
		if p.Mode == ModeAct {
			return !(def.SupportViewable || def.SupportActable)
		}
		return !def.SupportViewable
	}
	return false
}

// Scope returns the outlets at which p holds perm, applying the type ceilings
// and the new-device caution. It fails closed: an unknown permission, a
// drain token or a ceiling gives an error, never a wider scope.
func (a *Authorizer) Scope(p Principal, perm string) (OutletScope, error) {
	def, ok := a.Catalogue.Get(perm)
	if !ok || ceilingDenies(p, def) {
		return OutletScope{}, denied()
	}
	if def.StrongOnly && p.UnderCaution(a.now()) && !p.Approved {
		return OutletScope{}, apperr.New(apperr.Forbidden, CodeApprovalRequired, "approval required for this operation on a new device")
	}
	var scope OutletScope
	var ids []string
	for _, g := range p.Grants {
		if !grantHas(g, perm, p.Type != TypeSupport) {
			continue
		}
		for _, o := range g.Outlets {
			if o == "*" {
				scope.all = true
			} else {
				ids = append(ids, o)
			}
		}
	}
	if scope.all {
		return AllOutlets(), nil
	}
	scope = OnlyOutlets(ids...)
	if scope.Empty() {
		return scope, denied()
	}
	return scope, nil
}

func grantHas(g Grant, perm string, wildcardOK bool) bool {
	for _, x := range g.Perms {
		if x == perm || (wildcardOK && x == Wildcard) {
			return true
		}
	}
	return false
}

func fromCtx(ctx context.Context) (Principal, *Authorizer, error) {
	p, ok := PrincipalFrom(ctx)
	a, ok2 := authctx.Get(ctx, authctx.Authorizer).(*Authorizer)
	if !ok || !ok2 {
		return Principal{}, nil, apperr.New(apperr.Unauthenticated, CodeUnauthenticated, "authentication required")
	}
	return p, a, nil
}

// ScopeFor returns the caller's outlet scope for a permission (ADR-0003 A1.4).
// Repositories take it as the argument of every list, search, count, report
// and export over an outlet-scoped table. For a device token the scope is the
// device's outlet (its grant).
func ScopeFor(ctx context.Context, permission string) (OutletScope, error) {
	p, a, err := fromCtx(ctx)
	if err != nil {
		return OutletScope{}, err
	}
	return a.Scope(p, permission)
}

// Require checks that the caller holds permission at outletID. The outlet is
// the stored resource's, never the request's. outletID "" asks for the
// organisation-wide permission and needs an all-outlets grant.
//
// A caller who holds the permission at other outlets but not this one gets
// 404, as for a foreign tenant (A1.4 item 4); one who does not hold it at all
// gets 403.
func Require(ctx context.Context, permission, outletID string) error {
	scope, err := ScopeFor(ctx, permission)
	if err != nil {
		return err
	}
	if scope.All() || (outletID != "" && scope.Contains(outletID)) {
		return nil
	}
	if outletID == "" {
		return denied()
	}
	return apperr.New(apperr.NotFound, CodeResourceNotFound, "resource not found")
}
