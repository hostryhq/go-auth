package auth_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/tenancy"
)

// modesHarness adds the routes of the authenticated, public-with-callers and
// platform-audit modes to the standard harness.
type modesHarness struct {
	*harness
	psink *authtest.MemoryPlatformSink
}

func newModesHarness(t *testing.T) *modesHarness {
	t.Helper()
	h := &modesHarness{harness: newHarness(t), psink: &authtest.MemoryPlatformSink{}}
	h.guard.PlatformAudit = h.psink
	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hit = true
		h.seen, _ = tenancy.From(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	platform := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hit = true
		auth.SetAuditTarget(r.Context(), "vendor-user-7")
		err := auth.WithPlatformAuditedTx(r.Context(), h.db.db, func(context.Context, *sql.Tx) error { return nil })
		if err != nil {
			apperr.WriteProblem(w, r, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	wrongHelper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hit = true
		if err := auth.WithAuditedTx(r.Context(), h.db.db, func(context.Context, *sql.Tx) error { return nil }); err != nil {
			apperr.WriteProblem(w, r, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	forgetful := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hit = true
		io.WriteString(w, "data")
	})
	g, m := h.guard, h.mux
	g.Handle(m, "GET /v1/me", auth.Policy{OperationID: "getMe", Authenticated: true}, plain)
	g.Handle(m, "GET /internal/v1/vendor/me", auth.Policy{OperationID: "adminMe", Authenticated: true, PlatformAudit: true, Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}}, platform)
	g.Handle(m, "POST /internal/v1/vendor/signin", auth.Policy{OperationID: "vendorSignIn", Public: true, Internal: true, Callers: []string{"admin"}}, plain)
	g.Handle(m, "POST /internal/v1/setup", auth.Policy{OperationID: "setup", Public: true, Internal: true, Callers: []string{auth.AnyCaller}}, plain)
	g.Handle(m, "GET /internal/v1/vendor/users", auth.Policy{OperationID: "adminListUsers", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.AdminOrgRead, PlatformAudit: true}, platform)
	g.Handle(m, "GET /internal/v1/vendor/wrong", auth.Policy{OperationID: "adminWrong", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.AdminOrgRead, PlatformAudit: true}, wrongHelper)
	g.Handle(m, "GET /internal/v1/vendor/forgetful", auth.Policy{OperationID: "adminForgetful", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.AdminOrgRead, PlatformAudit: true}, forgetful)
	return h
}

func TestAuthenticatedMode(t *testing.T) {
	h := newModesHarness(t)
	noGrants := h.tenant.Mint(authtest.Spec{Tenant: tenantA})
	if rec := h.do(req{method: "GET", path: "/v1/me", token: noGrants}); rec.Code != 200 || h.seen.TenantID != tenantA {
		t.Fatalf("any valid token, no permission needed: %d tenant %v", rec.Code, h.seen.TenantID)
	}
	cases := map[string]req{
		"no token":                  {method: "GET", path: "/v1/me"},
		"drain token":               {method: "GET", path: "/v1/me", token: h.tenant.Mint(authtest.Spec{Type: auth.TypeDrain, Tenant: tenantA})},
		"support token, no service": {method: "GET", path: "/v1/me", token: h.tenant.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: tenantA})},
		"vendor token on tenant":    {method: "GET", path: "/v1/me", token: h.vendor.Mint(authtest.Spec{Subject: "vu-1"})},
		"approval token":            {method: "GET", path: "/v1/me", token: h.tenant.Mint(authtest.Spec{Type: auth.TypeApproval, Tenant: tenantA})},
	}
	for name, r := range cases {
		if rec := h.do(r); rec.Code != 401 || h.hit {
			t.Errorf("%s: %d hit=%v, want 401 and no handler", name, rec.Code, h.hit)
		}
	}
	// A tenant token on the vendor-realm authenticated route is refused.
	admin := h.svcToken("admin", self, "")
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/me", token: noGrants, svc: admin}); rec.Code != 401 || h.hit {
		t.Fatalf("tenant token on vendor realm: %d", rec.Code)
	}
	// A vendor token with the admin service token is accepted, and audited without a tenant.
	vend := h.vendor.Mint(authtest.Spec{Subject: "vu-3"})
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/me", token: vend, svc: admin}); rec.Code != 200 {
		t.Fatalf("vendor authenticated: %d %s", rec.Code, rec.Body.String())
	}
	if rows := h.psink.Snapshot(); len(rows) != 1 || rows[0].TenantID != "" || rows[0].ActionKey != "adminMe" {
		t.Fatalf("platform row: %+v", rows)
	}
}

func TestPublicWithNamedCallers(t *testing.T) {
	h := newModesHarness(t)
	user := h.tenant.Mint(authtest.Spec{Tenant: tenantA, Grants: authtest.OwnerGrants()})
	vend := h.vendor.Mint(authtest.Spec{Subject: "vu-1"})
	signin := func(r req) *httptest.ResponseRecorder {
		r.method, r.path = "POST", "/internal/v1/vendor/signin"
		return h.do(r)
	}

	if rec := signin(req{svc: h.svcToken("admin", self, "")}); rec.Code != 200 || !h.hit {
		t.Fatalf("named caller: %d", rec.Code)
	}
	if rec := signin(req{svc: h.svcToken("identity", self, "")}); rec.Code != 403 || h.hit {
		t.Fatalf("wrong caller must be refused: %d hit=%v", rec.Code, h.hit)
	}
	if rec := signin(req{}); rec.Code != 401 || h.hit {
		t.Fatalf("no service token: %d hit=%v", rec.Code, h.hit)
	}
	for name, tok := range map[string]string{"tenant user token": user, "vendor token": vend} {
		if rec := signin(req{token: tok, svc: h.svcToken("admin", self, "")}); rec.Code != 401 || h.hit {
			t.Errorf("%s on a public-callers route: %d hit=%v, want 401 and no handler", name, rec.Code, h.hit)
		}
		if rec := signin(req{token: tok}); rec.Code != 401 || h.hit {
			t.Errorf("%s alone: %d hit=%v", name, rec.Code, h.hit)
		}
	}
	// The any-caller form still needs a valid service token.
	setup := func(svc string) *httptest.ResponseRecorder {
		return h.do(req{method: "POST", path: "/internal/v1/setup", svc: svc})
	}
	if rec := setup(h.svcToken("tenancy", self, "")); rec.Code != 200 {
		t.Fatalf("any caller: %d", rec.Code)
	}
	if rec := setup(""); rec.Code != 401 || h.hit {
		t.Fatalf("any caller without a service token: %d hit=%v", rec.Code, h.hit)
	}
	if rec := setup("not-a-token"); rec.Code != 401 || h.hit {
		t.Fatalf("any caller with a bad service token: %d hit=%v", rec.Code, h.hit)
	}
}

func TestNewModesFailClosedAtStartup(t *testing.T) {
	h := newHarness(t)
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	mux := http.NewServeMux()
	g := h.guard
	mustPanic(t, "public internal without callers", func() {
		g.Handle(mux, "POST /internal/v1/a", auth.Policy{OperationID: "a", Public: true, Internal: true}, ok)
	})
	mustPanic(t, "public with callers on a non-internal path", func() {
		g.Handle(mux, "POST /v1/a", auth.Policy{OperationID: "a", Public: true, Callers: []string{"admin"}}, ok)
	})
	mustPanic(t, "public internal with a permission", func() {
		g.Handle(mux, "POST /internal/v1/a", auth.Policy{OperationID: "a", Public: true, Internal: true, Callers: []string{"admin"}, Permission: authtest.OrderRead}, ok)
	})
	mustPanic(t, "any caller mixed with names", func() {
		g.Handle(mux, "POST /internal/v1/a", auth.Policy{OperationID: "a", Public: true, Internal: true, Callers: []string{"*", "admin"}}, ok)
	})
	mustPanic(t, "authenticated with a permission", func() {
		g.Handle(mux, "GET /v1/a", auth.Policy{OperationID: "a", Authenticated: true, Permission: authtest.OrderRead}, ok)
	})
	mustPanic(t, "authenticated with step-up", func() {
		g.Handle(mux, "GET /v1/a", auth.Policy{OperationID: "a", Authenticated: true, StepUp: true}, ok)
	})
	mustPanic(t, "platform audit on a tenant route", func() {
		g.Handle(mux, "GET /v1/a", auth.Policy{OperationID: "a", Permission: authtest.OrderRead, PlatformAudit: true}, ok)
	})
	mustPanic(t, "vendor route with neither admin permission nor authenticated", func() {
		g.Handle(mux, "GET /internal/v1/vendor/a", auth.Policy{OperationID: "a", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, ServiceOnly: true}, ok)
	})
}

func TestPlatformAuditIsTenantlessAndFailsClosed(t *testing.T) {
	h := newModesHarness(t)
	admin := h.svcToken("admin", self, "")
	vend := h.vendor.Mint(authtest.Spec{Subject: "vu-3", Grants: authtest.Grants(nil, authtest.AdminOrgRead)})
	list := req{method: "GET", path: "/internal/v1/vendor/users", token: vend, svc: admin}

	if rec := h.do(list); rec.Code != 200 {
		t.Fatalf("platform vendor read: %d %s", rec.Code, rec.Body.String())
	}
	c, r := h.db.counts()
	rows := h.psink.Snapshot()
	if c != 1 || r != 0 || len(rows) != 1 || len(h.sink.Snapshot()) != 0 {
		t.Fatalf("commits=%d rollbacks=%d platform rows=%d tenant rows=%d", c, r, len(rows), len(h.sink.Snapshot()))
	}
	if e := rows[0]; e.TenantID != "" || e.VendorUser != "vu-3" || e.ActionKey != "adminListUsers" || e.TargetID != "vendor-user-7" || e.Outcome != auth.OutcomeOK {
		t.Fatalf("entry: %+v", e)
	}

	// Refused for lack of permission: a "refused" platform row, no handler.
	h.psink.Entries = nil
	weak := h.vendor.Mint(authtest.Spec{Subject: "vu-4"})
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/users", token: weak, svc: admin}); rec.Code != 403 || h.hit {
		t.Fatalf("missing permission: %d hit=%v", rec.Code, h.hit)
	}
	if rows := h.psink.Snapshot(); len(rows) != 1 || rows[0].Outcome != auth.OutcomeRefused || rows[0].TenantID != "" {
		t.Fatalf("refused row: %+v", rows)
	}

	// The platform row cannot be written: nothing commits, nothing returned.
	h.psink.Entries = nil
	h.psink.FailInTx = true
	c0, _ := h.db.counts()
	if rec := h.do(list); rec.Code != 500 || problemCode(t, rec) != "audit.write_failed" {
		t.Fatalf("sink failure must fail the request: %d %q", rec.Code, rec.Body.String())
	}
	if c1, _ := h.db.counts(); c1 != c0 {
		t.Fatal("transaction committed although the platform audit row failed")
	}
	h.psink.FailInTx = false

	// No platform sink configured: refused before the handler.
	h.guard.PlatformAudit = nil
	if rec := h.do(list); rec.Code != 500 || h.hit {
		t.Fatalf("no platform sink: %d hit=%v", rec.Code, h.hit)
	}
	h.guard.PlatformAudit = h.psink

	// The tenant helper on a platform route cannot record, so it fails closed;
	// a handler that never records cannot get a success out.
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/wrong", token: vend, svc: admin}); rec.Code != 500 {
		t.Fatalf("tenant helper on platform route: %d", rec.Code)
	}
	if rec := h.do(req{method: "GET", path: "/internal/v1/vendor/forgetful", token: vend, svc: admin}); rec.Code != 500 || strings.Contains(rec.Body.String(), "data") {
		t.Fatalf("unrecorded platform access: %d %q", rec.Code, rec.Body.String())
	}
}

func TestRequestBodyHashIsOverExactBytesAndRestoresBody(t *testing.T) {
	const body = "{\"b\": 1,  \"a\":2}\n" // odd spacing: must not be re-serialised
	mk := func(b string) *http.Request { return httptest.NewRequest("POST", "/v1/x", strings.NewReader(b)) }

	r := mk(body)
	got, err := auth.RequestBodyHash(r)
	if err != nil || got != auth.BodyHash([]byte(body)) {
		t.Fatalf("hash %q err %v", got, err)
	}
	if rest, _ := io.ReadAll(r.Body); string(rest) != body {
		t.Fatalf("body not restored: %q", rest)
	}
	if err := auth.VerifyBodyHash(mk(body), got); err != nil {
		t.Fatalf("matching body refused: %v", err)
	}
	for name, b := range map[string]string{"changed byte": strings.Replace(body, "2", "3", 1), "reformatted": `{"b":1,"a":2}`, "empty": ""} {
		if err := auth.VerifyBodyHash(mk(b), got); err == nil {
			t.Errorf("%s: tampered body accepted", name)
		}
	}
	// An empty body hashes the empty string (SHA-256, base64url, no padding).
	const emptyHash = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	if h, err := auth.RequestBodyHash(httptest.NewRequest("GET", "/v1/x", nil)); err != nil || h != emptyHash {
		t.Fatalf("empty body hash %q err %v", h, err)
	}
	if err := auth.VerifyBodyHash(mk(strings.Repeat("a", 1<<20+1)), got); err == nil {
		t.Fatal("oversized body accepted")
	}
}
