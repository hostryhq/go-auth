package auth_test

import (
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
)

// x-permission-widened-by (A2.5): a step-up route that a support token in act
// mode may reach through a support_actable permission, with the admin service
// token; nothing else is widened.
func TestPermissionWidenedForSupportActMode(t *testing.T) {
	h := newHarness(t)
	admin := h.svcToken("admin", self, "")
	act := func(perms ...string) string {
		return h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Mode: auth.ModeAct, Tenant: tenantA, Subject: "support:vu-9",
			Grants: authtest.Grants(nil, perms...)})
	}
	post := func(token, svc string) int {
		return h.do(req{method: "POST", path: "/v1/imports", token: token, svc: svc}).Code
	}
	if got := post(act(authtest.CatalogImport), admin); got != 200 {
		t.Errorf("act mode holding the widening permission: %d, want 200", got)
	}
	if got := post(act(authtest.CatalogImport), ""); got != 401 {
		t.Errorf("without the admin service token: %d, want 401", got)
	}
	if got := post(act(authtest.CatalogImport), h.svcToken("identity", self, "")); got != 401 {
		t.Errorf("with a service token from another service: %d, want 401", got)
	}
	if got := post(act(authtest.MenuImport), admin); got != 403 {
		t.Errorf("act mode holding only the step-up permission: %d, want 403", got)
	}
	view := h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA, Grants: authtest.Grants(nil, authtest.CatalogImport)})
	if got := post(view, admin); got != 403 {
		t.Errorf("view mode is not widened: %d, want 403", got)
	}
	// A normal strong session still needs the route's own permission and OTP.
	user := h.tenant.Mint(authtest.Spec{Type: auth.TypeUser, Tenant: tenantA, Grants: authtest.Grants(nil, authtest.CatalogImport)})
	if got := post(user, ""); got != 403 {
		t.Errorf("a user holding only the widening permission: %d, want 403", got)
	}
}

func TestPolicyWidenedByValidation(t *testing.T) {
	cat := authtest.Catalogue()
	for name, p := range map[string]auth.Policy{
		"unknown permission":   {OperationID: "x", Permission: authtest.MenuImport, WidenedBy: "nope.nothing"},
		"not support_actable":  {OperationID: "x", Permission: authtest.MenuImport, WidenedBy: authtest.OrderCreate},
		"same as x-permission": {OperationID: "x", Permission: authtest.CatalogImport, WidenedBy: authtest.CatalogImport},
		"authenticated route":  {OperationID: "x", Authenticated: true, WidenedBy: authtest.CatalogImport},
		"drain route":          {OperationID: "x", AllowDrain: true, WidenedBy: authtest.CatalogImport},
	} {
		if err := p.Validate(cat); err == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
	ok := auth.Policy{OperationID: "x", Permission: authtest.MenuImport, WidenedBy: authtest.CatalogImport}
	if err := ok.Validate(cat); err != nil {
		t.Errorf("valid widening refused: %v", err)
	}
}

// strong_only in a pin or device session is strong_session_required, not a
// generic permission_denied (RM-M5); services no longer rewrite it.
func TestStrongSessionRequiredCode(t *testing.T) {
	h := newHarness(t)
	for _, typ := range []auth.TokenType{auth.TypePin, auth.TypeDevice} {
		tok := h.tenant.Mint(authtest.Spec{Type: typ, Tenant: tenantA, Grants: authtest.Grants(nil, authtest.MemberAdd)})
		rec := h.do(req{method: "POST", path: "/v1/members", token: tok})
		if rec.Code != 403 || problemCode(t, rec) != auth.CodeStrongSessionRequired {
			t.Errorf("%s session on strong_only: %d %q", typ, rec.Code, problemCode(t, rec))
		}
	}
	// A strong user session without the grant is a plain denial.
	user := h.tenant.Mint(authtest.Spec{Type: auth.TypeUser, Tenant: tenantA, Grants: authtest.Grants(nil, authtest.OrderRead)})
	if rec := h.do(req{method: "POST", path: "/v1/members", token: user}); problemCode(t, rec) != auth.CodePermissionDenied {
		t.Errorf("user without the permission: %q", problemCode(t, rec))
	}
}
