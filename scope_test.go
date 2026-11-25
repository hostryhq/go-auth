package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/testkit"
)

const (
	outX = "outlet-x"
	outY = "outlet-y"
)

func kindOf(err error) (apperr.Kind, bool) {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e.Kind, true
	}
	return 0, false
}

// ADR-0003 A1.4: ScopeFor and Require. An outlet outside the caller's scope for
// a permission is 404, as for a foreign tenant; a caller who does not hold the
// permission at all is 403; the outlet comes from the stored resource.
func TestScopeForAndRequire(t *testing.T) {
	h := newHarness(t)
	cat := h.cat
	ctx := func(spec authtest.Spec) context.Context {
		spec.Tenant = testkit.TenantA
		return h.tenant.ContextFor(t.Context(), cat, spec)
	}
	x := ctx(authtest.Spec{Grants: authtest.Grants([]string{outX}, authtest.OrderRead)})
	both := ctx(authtest.Spec{Grants: []auth.Grant{
		{Outlets: []string{outX}, Perms: []string{authtest.OrderRead}},
		{Outlets: []string{outY}, Perms: []string{authtest.OrderRead, authtest.OrderCreate}},
	}})
	org := ctx(authtest.Spec{Grants: authtest.Grants(nil, authtest.OrderRead)})
	owner := ctx(authtest.Spec{Grants: authtest.OwnerGrants()})

	s, err := auth.ScopeFor(x, authtest.OrderRead)
	if err != nil || s.All() || !slices.Equal(s.IDs(), []string{outX}) {
		t.Fatalf("scoped: %v %v", s, err)
	}
	if s, _ := auth.ScopeFor(both, authtest.OrderRead); !slices.Equal(s.IDs(), []string{outX, outY}) {
		t.Fatalf("union of grants: %v", s.IDs())
	}
	if s, _ := auth.ScopeFor(both, authtest.OrderCreate); !slices.Equal(s.IDs(), []string{outY}) {
		t.Fatalf("scope is per permission: %v", s.IDs())
	}
	for name, c := range map[string]context.Context{"org-wide": org, "owner wildcard": owner} {
		if s, err := auth.ScopeFor(c, authtest.OrderRead); err != nil || !s.All() {
			t.Fatalf("%s: %v %v", name, s, err)
		}
	}

	if err := auth.Require(x, authtest.OrderRead, outX); err != nil {
		t.Fatal(err)
	}
	if k, ok := kindOf(auth.Require(x, authtest.OrderRead, outY)); !ok || k != apperr.NotFound {
		t.Fatalf("outlet outside scope must be 404, got kind %v", k)
	}
	if k, ok := kindOf(auth.Require(x, authtest.OrderCreate, outX)); !ok || k != apperr.Forbidden {
		t.Fatalf("permission not held at all must be 403, got %v", k)
	}
	if err := auth.Require(org, authtest.OrderRead, outY); err != nil {
		t.Fatal(err)
	}
	// Organisation-level permission ("" outlet) needs an all-outlets grant.
	if k, _ := kindOf(auth.Require(x, authtest.OrderRead, "")); k != apperr.Forbidden {
		t.Fatal("outlet-scoped member must not pass an organisation-level check")
	}
	if err := auth.Require(org, authtest.OrderRead, ""); err != nil {
		t.Fatal(err)
	}
	// Fail closed: unknown permission, no principal.
	if _, err := auth.ScopeFor(owner, "made.up"); err == nil {
		t.Fatal("unknown permission must be refused even for the owner wildcard")
	}
	if k, _ := kindOf(auth.Require(context.Background(), authtest.OrderRead, outX)); k != apperr.Unauthenticated {
		t.Fatal("no principal must be unauthenticated")
	}
}

func TestScopeCeilingsForNonStrongTokens(t *testing.T) {
	h := newHarness(t)
	for _, typ := range []auth.TokenType{auth.TypePin, auth.TypeDevice} {
		ctx := h.tenant.ContextFor(t.Context(), h.cat, authtest.Spec{Type: typ, Tenant: testkit.TenantA, Grants: authtest.OwnerGrants()})
		if err := auth.Require(ctx, authtest.MemberAdd, ""); err == nil {
			t.Errorf("%s token with the owner wildcard passed a strong_only check", typ)
		}
		if err := auth.Require(ctx, authtest.OrderCreate, ""); err != nil {
			t.Errorf("%s token must keep ordinary permissions: %v", typ, err)
		}
	}
	drain := h.tenant.ContextFor(t.Context(), h.cat, authtest.Spec{Type: auth.TypeDrain, Tenant: testkit.TenantA, Grants: authtest.OwnerGrants()})
	if err := auth.Require(drain, authtest.OrderRead, ""); err == nil {
		t.Error("a drain token holds no permission")
	}
}

// A device token's scope is its own outlet, and the tenancy context carries it.
func TestDeviceTokenScopeAndTenancyOutlet(t *testing.T) {
	h := newHarness(t)
	tok := h.tenant.Mint(authtest.Spec{Type: auth.TypeDevice, Tenant: testkit.TenantA, Device: "kds-1",
		Grants: authtest.Grants([]string{testkit.OutletA.String()}, authtest.OrderRead)})
	rec := h.do(req{method: "GET", path: "/v1/orders", token: tok})
	if rec.Code != 200 || h.seen.OutletID != testkit.OutletA || h.seen.DeviceID != "kds-1" {
		t.Fatalf("%d %+v", rec.Code, h.seen)
	}
}

func TestOutletScopeOperations(t *testing.T) {
	a := auth.OnlyOutlets("b", "a", "a", "")
	if !slices.Equal(a.IDs(), []string{"a", "b"}) || a.Empty() || a.All() {
		t.Fatalf("%v", a.IDs())
	}
	if !(auth.OutletScope{}).Empty() || auth.OnlyOutlets().Contains("") || auth.AllOutlets().Contains("") {
		t.Fatal("empty scope and empty outlet id must contain nothing")
	}
	if got := auth.AllOutlets().Intersect([]string{"c"}); !slices.Equal(got.IDs(), []string{"c"}) {
		t.Fatalf("all ∩ filter: %v", got.IDs())
	}
	if got := a.Intersect([]string{"b", "z"}); !slices.Equal(got.IDs(), []string{"b"}) {
		t.Fatalf("filter outside scope must be dropped: %v", got.IDs())
	}
	if got := a.Intersect([]string{"z"}); !got.Empty() {
		t.Fatalf("a filter wholly outside scope leaves nothing: %v", got.IDs())
	}
	if !a.Intersect(nil).Contains("a") {
		t.Fatal("no filter keeps scope")
	}
	if !auth.AllOutlets().Covers(a) || a.Covers(auth.AllOutlets()) || !a.Covers(auth.OnlyOutlets("a")) || a.Covers(auth.OnlyOutlets("a", "q")) {
		t.Fatal("Covers")
	}
}

// ServiceTransport adds the service token and passes the user's token on, so the
// callee authorises as the user (ADR-0005 section 9).
func TestServiceTransportPassesBothCredentials(t *testing.T) {
	h := newHarness(t)
	var gotSvc, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotSvc, gotAuth = r.Header.Get(auth.ServiceTokenHeader), r.Header.Get("Authorization")
	}))
	defer srv.Close()
	user := h.tenant.Mint(authtest.Spec{Tenant: testkit.TenantA, Grants: authtest.OwnerGrants()})

	// The guard puts the principal on the context; replay that here.
	var principalCtx context.Context
	h.guard.Handle(h.mux, "GET /v1/relay", auth.Policy{OperationID: "relay", Permission: authtest.OrderRead}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principalCtx = r.Context()
	}))
	h.do(req{method: "GET", path: "/v1/relay", token: user})

	c := &http.Client{Transport: &auth.ServiceTransport{Signer: h.reg.Signer("identity"), Audience: self}}
	r, _ := http.NewRequestWithContext(principalCtx, "GET", srv.URL, nil)
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer "+user {
		t.Fatal("the user's token was not passed on")
	}
	claims, err := h.reg.Verifier(self).Verify(gotSvc)
	if err != nil || claims.Issuer != "identity" || claims.TenantID != testkit.TenantA.String() {
		t.Fatalf("service token: %+v %v", claims, err)
	}
	if r.Header.Get(auth.ServiceTokenHeader) != "" {
		t.Fatal("the caller's request must not be modified")
	}
}
