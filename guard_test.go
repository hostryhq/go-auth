package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/testkit"
)

var tenantA = testkit.TenantA

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected a start-up panic (fail closed)", name)
		}
	}()
	f()
}

// IST-16: a route that declares nothing never reaches a handler; the route
// table is refused at start-up.
func TestRoutesFailClosedAtStartup(t *testing.T) {
	h := newHarness(t)
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	mux := http.NewServeMux()
	g := h.guard
	mustPanic(t, "empty policy", func() { g.Handle(mux, "GET /v1/a", auth.Policy{}, ok) })
	mustPanic(t, "operation id but no permission", func() { g.Handle(mux, "GET /v1/a", auth.Policy{OperationID: "a"}, ok) })
	mustPanic(t, "permission not in the catalogue", func() { g.Handle(mux, "GET /v1/a", auth.Policy{OperationID: "a", Permission: "made.up"}, ok) })
	mustPanic(t, "permission and drain together", func() {
		g.Handle(mux, "GET /v1/a", auth.Policy{OperationID: "a", Permission: authtest.OrderRead, AllowDrain: true}, ok)
	})
	mustPanic(t, "public with a permission", func() { g.Handle(mux, "GET /v1/a", auth.Policy{Public: true, Permission: authtest.OrderRead}, ok) })
	mustPanic(t, "internal path not declared internal", func() {
		g.Handle(mux, "GET /internal/v1/a", auth.Policy{OperationID: "a", Permission: authtest.OrderRead}, ok)
	})
	mustPanic(t, "internal declared on a public path", func() {
		g.Handle(mux, "GET /v1/a", auth.Policy{OperationID: "a", ServiceOnly: true, Internal: true, Callers: []string{"x"}}, ok)
	})
	mustPanic(t, "internal without callers", func() {
		g.Handle(mux, "GET /internal/v1/a", auth.Policy{OperationID: "a", ServiceOnly: true, Internal: true}, ok)
	})
	mustPanic(t, "vendor route without admin permission", func() {
		g.Handle(mux, "GET /internal/v1/vendor/a", auth.Policy{OperationID: "a", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.OrderRead}, ok)
	})
	mustPanic(t, "x-vendor-audit none outside the directory class", func() {
		g.Handle(mux, "GET /internal/v1/vendor/a", auth.Policy{OperationID: "a", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.AdminDeviceRead, VendorAuditNone: true}, ok)
	})
	mustPanic(t, "no catalogue", func() { (&auth.Guard{}).Wrap(auth.Policy{Public: true}, ok) })
}

// IST-17: the strong_only ceiling online, generated from the catalogue. pin,
// device and support tokens, even holding the owner wildcard, are refused on
// every strong_only permission; a strong session is not.
func TestStrongOnlyCeilingOnEveryStrongPermission(t *testing.T) {
	h := newHarness(t)
	mux := http.NewServeMux()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	var strong []auth.Permission
	for _, p := range h.cat.All() {
		if p.StrongOnly {
			strong = append(strong, p)
			h.guard.Handle(mux, "POST /v1/strong/"+p.Name, auth.Policy{OperationID: "op." + p.Name, Permission: p.Name}, ok)
		}
	}
	if len(strong) < 5 {
		t.Fatalf("catalogue has only %d strong_only permissions", len(strong))
	}
	adminSvc := h.svcToken("admin", self, "")
	for _, p := range strong {
		path := "/v1/strong/" + p.Name
		do := func(token, svc string) int { return doOn(mux, "POST", path, token, svc) }
		owner := authtest.OwnerGrants()
		explicit := authtest.Grants(nil, p.Name)
		if got := do(h.tenant.Mint(authtest.Spec{Type: auth.TypeUser, Tenant: tenantA, Grants: owner}), ""); got != 200 {
			t.Errorf("%s: strong session with the owner wildcard: %d, want 200", p.Name, got)
		}
		for _, c := range []struct {
			name  string
			token string
			svc   string
		}{
			{"pin + wildcard", h.tenant.Mint(authtest.Spec{Type: auth.TypePin, Tenant: tenantA, Grants: owner}), ""},
			{"pin + explicit", h.tenant.Mint(authtest.Spec{Type: auth.TypePin, Tenant: tenantA, Grants: explicit}), ""},
			{"device + wildcard", h.tenant.Mint(authtest.Spec{Type: auth.TypeDevice, Tenant: tenantA, Grants: owner}), ""},
			{"device + explicit", h.tenant.Mint(authtest.Spec{Type: auth.TypeDevice, Tenant: tenantA, Grants: explicit}), ""},
			{"support view + wildcard", h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA, Grants: owner}), adminSvc},
			{"support view + explicit", h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA, Grants: explicit}), adminSvc},
			{"support act + explicit", h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Mode: auth.ModeAct, Tenant: tenantA, Grants: explicit}), adminSvc},
		} {
			if got := do(c.token, c.svc); got != http.StatusForbidden {
				t.Errorf("%s with %s: %d, want 403", p.Name, c.name, got)
			}
		}
	}
}

func doOn(mux *http.ServeMux, method, path, token, svc string) int {
	hr := httptest.NewRequest(method, path, nil)
	hr.Header.Set("Authorization", "Bearer "+token)
	if svc != "" {
		hr.Header.Set(auth.ServiceTokenHeader, svc)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, hr)
	return rec.Code
}

// TC-02: the tenant comes from the verified token; a tenant id in a header or
// body is never read. With a token for tenant A the handler runs for A.
func TestTenantContextComesFromTokenOnly(t *testing.T) {
	h := newHarness(t)
	tok := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.Grants([]string{testkit.OutletA.String()}, authtest.OrderRead), Subject: "member-7"})
	rec := h.do(req{method: "GET", path: "/v1/orders?tenant_id=" + asString(testkit.TenantB), token: tok,
		header: map[string]string{"X-Tenant-Id": asString(testkit.TenantB), "Tenant-Id": asString(testkit.TenantB)}})
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if h.seen.TenantID != tenantA || h.seen.ActorID != "member-7" {
		t.Fatalf("tenancy context = %+v", h.seen)
	}
}

func TestMissingOrBadCredentialsNeverReachTheHandler(t *testing.T) {
	h := newHarness(t)
	good := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants()})
	for name, r := range map[string]req{
		"no header":        {method: "GET", path: "/v1/orders"},
		"garbage":          {method: "GET", path: "/v1/orders", token: "x.y.z"},
		"basic scheme":     {method: "GET", path: "/v1/orders", header: map[string]string{"Authorization": "Basic " + good}},
		"tampered payload": {method: "GET", path: "/v1/orders", token: tamper(good)},
	} {
		rec := h.do(r)
		if rec.Code != http.StatusUnauthorized || h.hit {
			t.Errorf("%s: status %d hit=%v", name, rec.Code, h.hit)
		}
		if c := problemCode(t, rec); c != "auth.invalid_token" {
			t.Errorf("%s: code %q leaks which check failed", name, c)
		}
	}
	clkTok := good
	h.clk.Advance(16 * time.Minute)
	if rec := h.do(req{method: "GET", path: "/v1/orders", token: clkTok}); rec.Code != 401 {
		t.Errorf("expired token: %d", rec.Code)
	}
}

func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	return strings.Join(parts, ".")
}

// Permission checks: no permission, wrong permission and unknown token types are refused.
func TestPermissionEnforcedBeforeHandler(t *testing.T) {
	h := newHarness(t)
	readOnly := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.Grants(nil, authtest.OrderRead)})
	if rec := h.do(req{method: "GET", path: "/v1/orders", token: readOnly}); rec.Code != 200 {
		t.Fatalf("read: %d", rec.Code)
	}
	rec := h.do(req{method: "POST", path: "/v1/orders", token: readOnly})
	if rec.Code != 403 || h.hit {
		t.Fatalf("create without permission: %d hit=%v", rec.Code, h.hit)
	}
	noGrants := h.tenant.Mint(authtest.Spec{Tenant: tenantA})
	if rec := h.do(req{method: "GET", path: "/v1/orders", token: noGrants}); rec.Code != 403 {
		t.Fatalf("no grants: %d", rec.Code)
	}
	// An approval token or a service token is not an access token.
	appr := h.tenant.Mint(authtest.Spec{Type: auth.TypeApproval, Tenant: tenantA})
	if rec := h.do(req{method: "GET", path: "/v1/orders", token: appr}); rec.Code != 401 {
		t.Fatalf("approval token as bearer: %d", rec.Code)
	}
}

// TST-27 / A13: realms are separate. A vendor token is refused by tenant
// routes, a tenant token by vendor routes, and a vendor token never gets a
// tenant context from anywhere but the path helper.
func TestRealmsAreSeparate(t *testing.T) {
	h := newHarness(t)
	vend := h.vendor.Mint(authtest.Spec{Grants: authtest.Grants(nil, authtest.AdminDeviceRead, authtest.OrderRead)})
	if rec := h.do(req{method: "GET", path: "/v1/orders", token: vend}); rec.Code != 401 || h.hit {
		t.Fatalf("vendor token on a tenant route: %d hit=%v", rec.Code, h.hit)
	}
	tn := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants()})
	admin := h.svcToken("admin", self, "")
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/devices", token: tn, svc: admin}); rec.Code != 401 || h.hit {
		t.Fatalf("tenant token on a vendor route: %d hit=%v", rec.Code, h.hit)
	}
	// A vendor-realm token that claims a tenant is not a vendor token.
	c := h.vendor.Claims(authtest.Spec{Grants: authtest.Grants(nil, authtest.AdminDeviceRead)})
	c.TenantID = asString(tenantA)
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/devices", token: h.vendor.MintClaims(c), svc: admin}); rec.Code != 401 {
		t.Fatalf("vendor token naming a tenant: %d", rec.Code)
	}
	// A support token is not a vendor-realm token either.
	sup := h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA, Grants: authtest.Grants(nil, authtest.AdminDeviceRead)})
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/devices", token: sup, svc: admin}); rec.Code != 401 {
		t.Fatalf("support token on a vendor route: %d", rec.Code)
	}
}

// ADR-0013 V2 item 5 and ADR-0005 A2.5: a support token works only with a
// service token from admin, only within the view/act ceiling, and every
// request is recorded.
func TestSupportTokenRules(t *testing.T) {
	h := newHarness(t)
	view := h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA, Subject: "support:vu-9", Ticket: "TCK-42",
		Grants: authtest.Grants(nil, authtest.ReportView, authtest.ReportEdit, authtest.BillCancel, authtest.OrderCreate)})
	admin := h.svcToken("admin", self, "")

	if rec := h.do(req{method: "GET", path: "/v1/reports", token: view}); rec.Code != 401 {
		t.Fatalf("support token alone must be useless, got %d", rec.Code)
	}
	if rec := h.do(req{method: "GET", path: "/v1/reports", token: view, svc: h.svcToken("identity", self, "")}); rec.Code != 401 {
		t.Fatalf("support token with a service token from a service other than admin: %d", rec.Code)
	}
	rec := h.do(req{method: "GET", path: "/v1/reports", token: view, svc: admin})
	if rec.Code != 200 || h.seen.TenantID != tenantA {
		t.Fatalf("view read: %d tenant %v", rec.Code, h.seen.TenantID)
	}
	for name, r := range map[string]req{
		"view mode cannot write":          {method: "PUT", path: "/v1/reports"},
		"sensitive permission":            {method: "POST", path: "/v1/bills/cancel"},
		"permission not support_viewable": {method: "POST", path: "/v1/orders"},
		"step-up never satisfied":         {method: "POST", path: "/v1/exports"},
	} {
		r.token, r.svc = view, admin
		if got := h.do(r); got.Code != 403 {
			t.Errorf("%s: %d, want 403", name, got.Code)
		}
	}
	act := h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Mode: auth.ModeAct, Tenant: tenantA, Subject: "support:vu-9",
		Grants: authtest.Grants(nil, authtest.ReportEdit, authtest.BillCancel, auth.Wildcard)})
	if got := h.do(req{method: "PUT", path: "/v1/reports", token: act, svc: admin}); got.Code != 200 {
		t.Errorf("act mode on a support_actable permission: %d", got.Code)
	}
	for name, r := range map[string]req{
		"act mode, sensitive":        {method: "POST", path: "/v1/bills/cancel"},
		"act mode, wildcard ignored": {method: "POST", path: "/v1/orders"},
		"act mode, strong_only":      {method: "POST", path: "/v1/members"},
	} {
		r.token, r.svc = act, admin
		if got := h.do(r); got.Code != 403 {
			t.Errorf("%s: %d, want 403", name, got.Code)
		}
	}

	// Every request made with a support token is recorded: the two successes in
	// the request's own transaction, the refusals in their own.
	var ok, refused int
	for _, e := range h.sink.Snapshot() {
		if e.TokenType != auth.TypeSupport || e.VendorUser != "vu-9" {
			t.Errorf("entry %+v", e)
		}
		if e.Outcome == auth.OutcomeOK {
			ok++
		} else {
			refused++
		}
	}
	if ok != 2 || refused != 7 {
		t.Errorf("audit rows ok=%d refused=%d, want 2 and 7", ok, refused)
	}
	first := h.sink.Snapshot()[0]
	if first.TenantID != asString(tenantA) || first.ActionKey != "listReports" || first.Ticket != "TCK-42" || first.VendorUser != "vu-9" || first.SupportSession == "" {
		t.Errorf("entry fields: %+v", first)
	}
}

// IST-34: service-to-service. Unknown caller, wrong audience, expired, a
// token whose iss does not match its registry key, a life over 60 s, or a
// caller not on x-service-callers is refused, and /internal/v1 is refused
// without a service token however the request arrived.
func TestInternalRoutesAndServiceTokens(t *testing.T) {
	h := newHarness(t)
	path := "/internal/v1/series"
	call := func(svc string) *httptest.ResponseRecorder { return h.do(req{method: "POST", path: path, svc: svc}) }

	if r := call(h.svcToken("identity", self, asString(tenantA))); r.Code != 200 || h.seen.TenantID != tenantA {
		t.Fatalf("allowed caller: %d tenant %v", r.Code, h.seen.TenantID)
	}
	if r := call(""); r.Code != 401 || h.hit {
		t.Fatalf("no service token: %d hit=%v", r.Code, h.hit)
	}
	// A user token is not a substitute for a service token.
	user := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants()})
	if rec := h.do(req{method: "POST", path: path, token: user}); rec.Code != 401 {
		t.Fatalf("user token on internal route: %d", rec.Code)
	}
	if r := call(h.svcToken("tenancy", self, asString(tenantA))); r.Code != 403 || h.hit {
		t.Fatalf("caller not on x-service-callers: %d", r.Code)
	}
	if r := call(h.svcToken("identity", "svc-other", asString(tenantA))); r.Code != 401 {
		t.Fatalf("wrong audience: %d", r.Code)
	}
	rogue := authtest.NewServiceRegistry(h.clk, "identity")
	tok, _ := rogue.Signer("identity").Sign(self, asString(tenantA))
	if r := call(tok); r.Code != 401 {
		t.Fatalf("a key that is not in the registry: %d", r.Code)
	}
	now := h.clk.Now()
	c := auth.Claims{Issuer: "identity", Audience: auth.Audience{self}, Subject: "identity", Type: auth.TypeService,
		TenantID: asString(tenantA), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), JTI: "j"}
	if r := call(h.reg.Forge("identity", "identity", c)); r.Code != 200 {
		t.Fatalf("control: hand-forged but valid token: %d", r.Code)
	}
	if r := call(h.reg.Forge("tenancy", "identity", c)); r.Code != 401 {
		t.Fatalf("signed by another service's key under identity's kid: %d", r.Code)
	}
	if r := call(h.reg.Forge("tenancy", "tenancy", c)); r.Code != 401 {
		t.Fatalf("iss identity but key and kid of tenancy: %d", r.Code)
	}
	long := c
	long.ExpiresAt = now.Add(5 * time.Minute).Unix()
	if r := call(h.reg.Forge("identity", "identity", long)); r.Code != 401 {
		t.Fatalf("service token living 5 minutes: %d", r.Code)
	}
	expiring := h.svcToken("identity", self, asString(tenantA))
	h.clk.Advance(61 * time.Second)
	if r := call(expiring); r.Code != 401 {
		t.Fatalf("expired service token: %d", r.Code)
	}
}

// Asynchronous work: the tenant comes from the service token's claim and must
// exist unless the operation is declared cross-tenant.
func TestServiceOnlyTenantClaim(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(req{method: "POST", path: "/internal/v1/series", svc: h.svcToken("identity", self, "")}); rec.Code != 401 || h.hit {
		t.Fatalf("no tenant claim on a tenant operation: %d", rec.Code)
	}
	if rec := h.do(req{method: "POST", path: "/internal/v1/series", svc: h.svcToken("identity", self, "not-a-uuid")}); rec.Code != 401 {
		t.Fatalf("bad tenant claim: %d", rec.Code)
	}
	if rec := h.do(req{method: "GET", path: "/internal/v1/feeds/revocations", svc: h.svcToken("identity", self, "")}); rec.Code != 200 {
		t.Fatalf("declared cross-tenant feed: %d", rec.Code)
	}
	// A user token for tenant A with a service token claiming tenant B.
	h.guard.Handle(h.mux, "GET /internal/v1/both", auth.Policy{OperationID: "both", Permission: authtest.OrderRead, Internal: true, Callers: []string{"identity"}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	user := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants()})
	if rec := h.do(req{method: "GET", path: "/internal/v1/both", token: user, svc: h.svcToken("identity", self, asString(testkit.TenantB))}); rec.Code != 401 {
		t.Fatalf("service token for B with a user token for A: %d", rec.Code)
	}
	if rec := h.do(req{method: "GET", path: "/internal/v1/both", token: user, svc: h.svcToken("identity", self, asString(tenantA))}); rec.Code != 200 {
		t.Fatalf("matching tenants: %d", rec.Code)
	}
}

// Internal calls keep working with identity stopped: service tokens verify
// against the local registry, never against identity.
func TestInternalCallsNeedNoIdentity(t *testing.T) {
	h := newHarness(t)
	ks := auth.NewCachedKeySet(&fakeLoader{err: http.ErrServerClosed}, nil) // identity's JWKS is unreachable
	h.guard.Tenant.Keys = ks
	if rec := h.do(req{method: "POST", path: "/internal/v1/series", svc: h.svcToken("identity", self, asString(tenantA))}); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
}

// The drain token is the only credential a revoked device gets: valid on the
// quarantine upload and nothing else (IST-24, generated from the route table).
func TestDrainTokenOnlyOnDrainRoutes(t *testing.T) {
	h := newHarness(t)
	drain := h.tenant.Mint(authtest.Spec{Type: auth.TypeDrain, Tenant: tenantA, Grants: authtest.OwnerGrants()})
	if rec := h.do(req{method: "POST", path: "/v1/sync/quarantine", token: drain}); rec.Code != 200 {
		t.Fatalf("drain on its route: %d", rec.Code)
	}
	for _, r := range []req{
		{method: "GET", path: "/v1/orders"}, {method: "POST", path: "/v1/orders"}, {method: "POST", path: "/v1/members"},
		{method: "POST", path: "/v1/exports"}, {method: "POST", path: "/v1/bills/cancel"},
	} {
		r.token = drain
		if rec := h.do(r); rec.Code != 401 || h.hit {
			t.Errorf("drain token on %s %s: %d", r.method, r.path, rec.Code)
		}
	}
	user := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants()})
	if rec := h.do(req{method: "POST", path: "/v1/sync/quarantine", token: user}); rec.Code != 401 {
		t.Fatalf("a user token on the drain route: %d", rec.Code)
	}
	h.clk.Advance(6 * time.Minute)
	if rec := h.do(req{method: "POST", path: "/v1/sync/quarantine", token: drain}); rec.Code != 401 {
		t.Fatalf("drain token after 5 minutes: %d", rec.Code)
	}
}

// A2.2 / IST-13 (the go-auth half): inside the 24-hour window a strong_only or
// step-up operation is refused with approval_required unless the request
// carries an approval token bound to this operation, body and session, once.
func TestNewDeviceCaution(t *testing.T) {
	h := newHarness(t)
	until := h.clk.Now().Add(24 * time.Hour)
	spec := authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants(), CautionUntil: until, Session: "s-1", AMR: []string{auth.AMROTP}, AuthTime: h.clk.Now()}
	user := h.tenant.Mint(spec)

	if rec := h.do(req{method: "GET", path: "/v1/orders", token: user}); rec.Code != 200 {
		t.Fatalf("reads and trading are not blocked: %d", rec.Code)
	}
	body := `{"name":"Asha"}`
	post := func(approval string) int {
		r := req{method: "POST", path: "/v1/members", body: body, token: user, header: map[string]string{}}
		if approval != "" {
			r.header[auth.ApprovalHeader] = approval
		}
		rec := h.do(r)
		if rec.Code == 403 {
			if c := problemCode(t, rec); c != auth.CodeApprovalRequired {
				t.Errorf("code %q", c)
			}
		}
		return rec.Code
	}
	if got := post(""); got != 403 || h.hit {
		t.Fatalf("strong_only inside the window without approval: %d", got)
	}
	approve := func(mut func(*authtest.Spec)) string {
		s := authtest.Spec{Type: auth.TypeApproval, Tenant: tenantA, Session: "s-1", Operation: "addMember", BodyHash: auth.BodyHash([]byte(body)), TargetHash: auth.TargetHash("POST", "/v1/members", auth.BodyHash([]byte(body))), Label: "Add member Asha"}
		if mut != nil {
			mut(&s)
		}
		return h.tenant.Mint(s)
	}
	for name, tok := range map[string]string{
		"another operation": approve(func(s *authtest.Spec) { s.Operation = "editTax" }),
		"another body":      approve(func(s *authtest.Spec) { s.BodyHash = auth.BodyHash([]byte(`{"name":"Eve"}`)) }),
		"another session":   approve(func(s *authtest.Spec) { s.Session = "s-2" }),
		"another path": approve(func(s *authtest.Spec) {
			s.TargetHash = auth.TargetHash("POST", "/v1/members/other", auth.BodyHash([]byte(body)))
		}),
		"another method": approve(func(s *authtest.Spec) {
			s.TargetHash = auth.TargetHash("PUT", "/v1/members", auth.BodyHash([]byte(body)))
		}),
		"no target":       approve(func(s *authtest.Spec) { s.TargetHash = "" }),
		"another tenant":  approve(func(s *authtest.Spec) { s.Tenant = testkit.TenantB }),
		"an access token": user,
	} {
		if got := post(tok); got != 403 {
			t.Errorf("approval for %s accepted: %d", name, got)
		}
	}
	good := approve(nil)
	if got := post(good); got != 200 || !h.hit {
		t.Fatalf("a matching approval must release exactly this operation: %d", got)
	}
	if got := post(good); got != 403 {
		t.Fatalf("approval replayed: %d", got)
	}
	// A step-up operation that is not strong_only is blocked too.
	if rec := h.do(req{method: "POST", path: "/v1/exports", token: user}); rec.Code != 403 || problemCode(t, rec) != auth.CodeApprovalRequired {
		t.Fatalf("step-up operation inside the window: %d", rec.Code)
	}
	// After the window the block is gone.
	h.clk.Advance(24*time.Hour + time.Minute)
	later := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants(), CautionUntil: until})
	if rec := h.do(req{method: "POST", path: "/v1/members", token: later}); rec.Code != 200 {
		t.Fatalf("after the window: %d", rec.Code)
	}
}

// Step-up (ADR-0005 section 3, A2.3): a fresh OTP is needed; the vendor-assisted
// code never counts; old auth_time does not count.
func TestStepUp(t *testing.T) {
	h := newHarness(t)
	now := h.clk.Now()
	mk := func(amr []string, at time.Time) string {
		return h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants(), AMR: amr, AuthTime: at})
	}
	status := func(tok string) (int, string) {
		rec := h.do(req{method: "POST", path: "/v1/exports", token: tok})
		if rec.Code == 403 {
			return rec.Code, problemCode(t, rec)
		}
		return rec.Code, ""
	}
	if c, _ := status(mk([]string{auth.AMROTP}, now)); c != 200 {
		t.Fatalf("fresh OTP: %d", c)
	}
	if c, code := status(mk([]string{auth.AMROTP}, now.Add(-11*time.Minute))); c != 403 || code != auth.CodeStepUpRequired {
		t.Fatalf("stale OTP: %d %s", c, code)
	}
	if c, code := status(mk([]string{auth.AMRVendorCode}, now)); c != 403 || code != auth.CodeStepUpRequired {
		t.Fatalf("vendor_code must never satisfy step-up: %d %s", c, code)
	}
	if c, code := status(mk([]string{auth.AMRVendorCode, auth.AMROTP}, now)); c != 200 {
		t.Fatalf("a real OTP alongside vendor_code still counts: %d %s", c, code)
	}
}

// IC-29 / ADR-0013 V5: requests on a vendor user's authority are recorded in
// the request's own transaction, and fail closed when the record cannot be written.
func TestVendorRoutesAreAuditedAndFailClosed(t *testing.T) {
	h := newHarness(t)
	admin := h.svcToken("admin", self, "")
	vend := h.vendor.Mint(authtest.Spec{Subject: "vu-3", Grants: authtest.Grants(nil, authtest.AdminDeviceRead, authtest.AdminOrgRead)})
	list := req{method: "GET", path: "/internal/v1/vendor/devices", token: vend, svc: admin}

	if rec := h.do(list); rec.Code != 200 || h.seen.TenantID != tenantA {
		t.Fatalf("vendor read: %d tenant %v", rec.Code, h.seen.TenantID)
	}
	c, r := h.db.counts()
	rows := h.sink.Snapshot()
	if c != 1 || r != 0 || len(rows) != 1 {
		t.Fatalf("commits=%d rollbacks=%d rows=%d, want exactly one row in one committed transaction", c, r, len(rows))
	}
	e := rows[0]
	if e.VendorUser != "vu-3" || e.ActionKey != "adminListDevices" || e.TargetID != "device-9" || e.ResultCount != 3 ||
		e.TenantID != asString(tenantA) || e.Outcome != auth.OutcomeOK || e.TokenType != auth.TypeUser {
		t.Fatalf("entry: %+v", e)
	}

	// Without the admin service token the route is unreachable.
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/devices", token: vend}); rec.Code != 401 {
		t.Fatalf("no service token: %d", rec.Code)
	}
	// Another service's token is not enough.
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/devices", token: vend, svc: h.svcToken("identity", self, "")}); rec.Code != 403 {
		t.Fatalf("caller not admin: %d", rec.Code)
	}

	// Refused for lack of permission: 403 and a "refused" row, no handler.
	h.sink.Entries = nil
	revoke := req{method: "POST", path: "/internal/v1/vendor/devices/revoke", token: vend, svc: admin}
	if rec := h.do(revoke); rec.Code != 403 || h.hit {
		t.Fatalf("missing admin.device.revoke: %d hit=%v", rec.Code, h.hit)
	}
	if rows := h.sink.Snapshot(); len(rows) != 1 || rows[0].Outcome != auth.OutcomeRefused || rows[0].ActionKey != "adminRevokeDevice" {
		t.Fatalf("refused request not recorded: %+v", rows)
	}

	// The audit row cannot be written: nothing is committed, nothing returned.
	h.sink.Entries = nil
	h.sink.FailInTx = true
	c0, _ := h.db.counts()
	rec := h.do(list)
	if rec.Code != 500 || problemCode(t, rec) != "audit.write_failed" {
		t.Fatalf("audit write failure must fail the request: %d %q", rec.Code, rec.Body.String())
	}
	if c1, _ := h.db.counts(); c1 != c0 {
		t.Fatal("transaction committed although the audit row failed")
	}
	h.sink.FailInTx = false

	// A refusal that cannot be recorded is still a refusal.
	h.sink.FailRefused = true
	if rec := h.do(revoke); rec.Code != 403 {
		t.Fatalf("unrecordable refusal: %d", rec.Code)
	}
	h.sink.FailRefused = false

	// Directory reads carry x-vendor-audit: none and write no row.
	h.sink.Entries = nil
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/orgs", token: vend, svc: admin}); rec.Code != 200 || len(h.sink.Snapshot()) != 0 {
		t.Fatalf("directory read: %d rows=%d", rec.Code, len(h.sink.Snapshot()))
	}
}

// A handler that answers a vendor-authority request without recording it
// cannot get the success out: the response is replaced by an error.
func TestUnrecordedVendorAccessCannotRespond(t *testing.T) {
	h := newHarness(t)
	sup := h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA, Grants: authtest.Grants(nil, authtest.ReportView)})
	rec := h.do(req{method: "GET", path: "/v1/forgetful", token: sup, svc: h.svcToken("admin", self, "")})
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "data") || problemCode(t, rec) != "audit.not_recorded" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
	// The same handler for a normal member is unaffected.
	user := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.Grants(nil, authtest.ReportView)})
	if rec := h.do(req{method: "GET", path: "/v1/forgetful", token: user}); rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
}

// A vendor-authority request on a service with no audit sink is refused.
func TestNoSinkRefusesVendorAuthority(t *testing.T) {
	h := newHarness(t)
	h.guard.Audit = nil
	sup := h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA, Grants: authtest.Grants(nil, authtest.ReportView)})
	if rec := h.do(req{method: "GET", path: "/v1/reports", token: sup, svc: h.svcToken("admin", self, "")}); rec.Code != 500 || h.hit {
		t.Fatalf("%d hit=%v", rec.Code, h.hit)
	}
}

// ADR-0013 V3 item 4: VendorTenant needs a vendor principal holding the permission.
func TestVendorTenantHelperRequiresVendorPrincipalAndPermission(t *testing.T) {
	h := newHarness(t)
	ctx := h.tenant.ContextFor(t.Context(), h.cat, authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants()})
	if _, err := auth.VendorTenant(ctx, authtest.AdminDeviceRead, testkit.TenantB); err == nil {
		t.Fatal("a tenant principal must not obtain another tenant's context")
	}
	vctx := h.vendor.ContextFor(t.Context(), h.cat, authtest.Spec{Grants: authtest.Grants(nil, authtest.AdminOrgRead)})
	if _, err := auth.VendorTenant(vctx, authtest.AdminDeviceRead, testkit.TenantB); err == nil {
		t.Fatal("vendor principal without the permission")
	}
	if _, err := auth.VendorTenant(vctx, authtest.AdminOrgRead, "not-an-id"); err == nil {
		t.Fatal("bad organisation id")
	}
}
