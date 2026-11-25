package auth_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/hostryhq/go-common/testkit"
)

// fakeDB is a database/sql connector that records commits and rollbacks, so
// tests can prove what the transaction did without a real database.
type fakeDB struct {
	mu        sync.Mutex
	commits   int
	rollbacks int
	db        *sql.DB
}

func newFakeDB() *fakeDB {
	f := &fakeDB{}
	f.db = sql.OpenDB(f)
	return f
}

func (f *fakeDB) Connect(context.Context) (driver.Conn, error) { return &fakeConn{f}, nil }
func (f *fakeDB) Driver() driver.Driver                        { return nil }
func (f *fakeDB) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.commits, f.rollbacks
}

type fakeConn struct{ f *fakeDB }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return &fakeTx{c.f}, nil }
func (c *fakeConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

type fakeTx struct{ f *fakeDB }

func (t *fakeTx) Commit() error   { t.f.mu.Lock(); t.f.commits++; t.f.mu.Unlock(); return nil }
func (t *fakeTx) Rollback() error { t.f.mu.Lock(); t.f.rollbacks++; t.f.mu.Unlock(); return nil }

// harness is a guarded mux over the sample catalogue with both realms, a
// service key registry and a vendor audit sink.
type harness struct {
	clk    *testkit.FakeClock
	cat    *auth.Catalogue
	tenant *authtest.Issuer
	vendor *authtest.Issuer
	reg    *authtest.ServiceRegistry
	sink   *authtest.MemorySink
	used   *auth.MemorySingleUse
	db     *fakeDB
	guard  *auth.Guard
	mux    *http.ServeMux
	// seen is the tenancy context the last handler saw.
	seen tenancy.Context
	hit  bool
}

const self = "svc-test"

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{clk: testkit.NewClock(), cat: authtest.Catalogue(), sink: &authtest.MemorySink{}, db: newFakeDB()}
	h.tenant = authtest.NewTenantIssuer(h.clk)
	h.vendor = authtest.NewVendorIssuer(h.clk)
	h.reg = authtest.NewServiceRegistry(h.clk, "admin", "identity", "tenancy", self)
	h.used = auth.NewMemorySingleUse(h.clk)
	h.guard = &auth.Guard{
		Catalogue: h.cat,
		Tenant:    h.tenant.Verifier(),
		Vendor:    h.vendor.Verifier(),
		Services:  h.reg.Verifier(self),
		Approvals: &auth.ApprovalChecker{Verifier: h.tenant.Verifier(), Used: h.used},
		Audit:     h.sink,
		Clock:     h.clk,
	}
	h.mux = http.NewServeMux()
	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hit = true
		h.seen, _ = tenancy.From(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	// audited does what a real vendor-route handler does: its database work goes
	// through WithAuditedTx.
	auditedFor := func(perm string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.hit = true
			ctx := r.Context()
			if p, _ := auth.PrincipalFrom(ctx); p.Realm == auth.RealmVendor {
				c, err := auth.VendorTenant(ctx, perm, testkit.TenantA)
				if err != nil {
					apperr.WriteProblem(w, r, err)
					return
				}
				ctx = c
				auth.SetAuditTarget(ctx, "device-9")
			}
			h.seen, _ = tenancy.From(ctx)
			err := auth.WithAuditedTx(ctx, h.db.db, func(ctx context.Context, tx *sql.Tx) error { auth.SetResultCount(ctx, 3); return nil })
			if err != nil {
				apperr.WriteProblem(w, r, err)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
	}
	audited := auditedFor("")
	forgetful := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hit = true
		io.WriteString(w, "data") // success without ever recording the vendor access
	})
	g, m := h.guard, h.mux
	g.Handle(m, "GET /v1/orders", auth.Policy{OperationID: "listOrders", Permission: authtest.OrderRead}, plain)
	g.Handle(m, "POST /v1/orders", auth.Policy{OperationID: "createOrder", Permission: authtest.OrderCreate}, plain)
	g.Handle(m, "POST /v1/bills/cancel", auth.Policy{OperationID: "cancelBill", Permission: authtest.BillCancel}, plain)
	g.Handle(m, "GET /v1/reports", auth.Policy{OperationID: "listReports", Permission: authtest.ReportView}, audited)
	g.Handle(m, "PUT /v1/reports", auth.Policy{OperationID: "editReport", Permission: authtest.ReportEdit}, audited)
	g.Handle(m, "GET /v1/forgetful", auth.Policy{OperationID: "forgetful", Permission: authtest.ReportView}, forgetful)
	g.Handle(m, "POST /v1/members", auth.Policy{OperationID: "addMember", Permission: authtest.MemberAdd}, plain)
	g.Handle(m, "POST /v1/exports", auth.Policy{OperationID: "exportReports", Permission: authtest.ReportView, StepUp: true}, plain)
	g.Handle(m, "POST /v1/tax", auth.Policy{OperationID: "editTax", Permission: authtest.TaxSettingsEdit, StepUp: true}, plain)
	g.Handle(m, "POST /v1/sync/quarantine", auth.Policy{OperationID: "quarantineUpload", AllowDrain: true}, plain)
	g.Handle(m, "POST /internal/v1/series", auth.Policy{OperationID: "issueSeries", ServiceOnly: true, Internal: true, Callers: []string{"identity"}}, plain)
	g.Handle(m, "GET /internal/v1/feeds/revocations", auth.Policy{OperationID: "revocations", ServiceOnly: true, Internal: true, Callers: []string{"identity"}, NoTenant: true}, plain)
	g.Handle(m, "GET /internal/v1/vendor/devices", auth.Policy{OperationID: "adminListDevices", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.AdminDeviceRead}, auditedFor(authtest.AdminDeviceRead))
	g.Handle(m, "POST /internal/v1/vendor/devices/revoke", auth.Policy{OperationID: "adminRevokeDevice", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.AdminDeviceRevok}, auditedFor(authtest.AdminDeviceRevok))
	g.Handle(m, "GET /internal/v1/vendor/orgs", auth.Policy{OperationID: "adminListOrgs", Realm: auth.RealmVendor, Internal: true, Callers: []string{"admin"}, Permission: authtest.AdminOrgRead, DirectoryClass: true, VendorAuditNone: true}, auditedFor(authtest.AdminOrgRead))
	return h
}

type req struct {
	method, path, body string
	token              string
	svc                string // service token
	header             map[string]string
}

func (h *harness) do(r req) *httptest.ResponseRecorder {
	h.hit = false
	h.seen = tenancy.Context{}
	hr := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
	if r.token != "" {
		hr.Header.Set("Authorization", "Bearer "+r.token)
	}
	if r.svc != "" {
		hr.Header.Set(auth.ServiceTokenHeader, r.svc)
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, hr)
	return rec
}

func (h *harness) svcToken(from, aud, tenant string) string {
	tok, err := h.reg.Signer(from).Sign(aud, tenant)
	if err != nil {
		panic(err)
	}
	return tok
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p apperr.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem body: %q", rec.Body.String())
	}
	return p.Code
}

func asString(id ids.ID) string { return id.String() }
