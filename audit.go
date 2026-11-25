package auth

import (
	"context"
	"database/sql"
	"net/http"
	"sync"
	"time"

	"github.com/hostryhq/go-auth/internal/authctx"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/logx"
	"github.com/hostryhq/go-common/tenancy"
)

// Outcomes of a vendor access record.
const (
	OutcomeOK      = "ok"
	OutcomeRefused = "refused"
)

// VendorAccessEntry is one row of a service's vendor_access_log (ADR-0013 V5).
// It holds ids and fixed-pattern values only: no passwords, TOTP codes, OTPs,
// tokens, free text or full phone numbers. The reason text stays with the
// record that owns it in identity.
type VendorAccessEntry struct {
	ID             ids.ID
	Time           time.Time
	TenantID       string // the organisation concerned
	VendorUser     string
	TokenType      TokenType // vendor user token ("user" in the vendor realm) or "support"
	SupportSession string
	ActionKey      string // the operation id
	TargetID       string
	Ticket         string
	Outcome        string
	ResultCount    int
	RequestID      string
}

// VendorAuditSink is the hook each service implements over its own
// vendor_access_log table and outbox (ADR-0013 V5). go-auth calls it; it does
// not know the table.
type VendorAuditSink interface {
	// RecordInTx writes the row inside the request's own transaction. An error
	// fails the transaction: nothing changes and no data is returned.
	RecordInTx(ctx context.Context, tx tenancy.Execer, e VendorAccessEntry) error
	// RecordRefused writes a "refused" row in a short transaction of its own,
	// for a request go-auth refused before the handler.
	RecordRefused(ctx context.Context, e VendorAccessEntry) error
}

// PlatformAuditSink is the tenant-less counterpart of VendorAuditSink for
// vendor actions that concern no organisation (vendor sign-in is the owner's
// own; identity and tenancy routes on vendor users, setup, directory-wide
// operations). The row has no tenant and no pseudo-tenant: the table behind
// it is a platform table, not an RLS tenant table (ADR-0013 V5 item 3).
type PlatformAuditSink interface {
	// RecordPlatformInTx writes the row inside the request's own transaction.
	// An error fails the transaction (fail closed).
	RecordPlatformInTx(ctx context.Context, tx tenancy.Execer, e VendorAccessEntry) error
	// RecordPlatformRefused writes a "refused" row in a short transaction of
	// its own, for a request go-auth refused before the handler.
	RecordPlatformRefused(ctx context.Context, e VendorAccessEntry) error
}

// auditState is the per-request audit record being built. The guard creates
// it for requests on a vendor user's authority.
type auditState struct {
	mu       sync.Mutex
	sink     VendorAuditSink
	platform PlatformAuditSink // set instead of sink on a Policy.PlatformAudit route
	entry    VendorAccessEntry
	none     bool // x-vendor-audit: none (directory reads)
	recorded bool
}

func auditFrom(ctx context.Context) *auditState {
	s, _ := authctx.Get(ctx, authctx.Audit).(*auditState)
	return s
}

func (s *auditState) isRecorded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recorded
}

// SetAuditTarget names the record the request acted on (a device id, an
// organisation id). A no-op outside vendor-authority requests.
func SetAuditTarget(ctx context.Context, targetID string) {
	if s := auditFrom(ctx); s != nil {
		s.mu.Lock()
		s.entry.TargetID = targetID
		s.mu.Unlock()
	}
}

// SetResultCount records how many records a read returned.
func SetResultCount(ctx context.Context, n int) {
	if s := auditFrom(ctx); s != nil {
		s.mu.Lock()
		s.entry.ResultCount = n
		s.mu.Unlock()
	}
}

// WithAuditedTx is tenancy.WithTx plus the vendor access hook. For a request
// on a vendor user's authority it writes the vendor_access_log row inside the
// same transaction, after the handler's own work and before commit. If the row
// cannot be written the transaction rolls back and the error is returned, so
// nothing changes and no data leaves (fail closed, IC-29). A failing handler
// rolls its row back with it, so there is one row per action that happened and
// none for one that did not. Other principals get plain tenancy.WithTx.
//
// Call it once per request; a second call in the same request writes no second row.
func WithAuditedTx(ctx context.Context, db tenancy.TxBeginner, fn func(ctx context.Context, tx *sql.Tx) error) error {
	p, ok := PrincipalFrom(ctx)
	if !ok || !p.IsVendorActor() {
		return tenancy.WithTx(ctx, db, fn)
	}
	st := auditFrom(ctx)
	if st == nil || st.sink == nil { // also a platform route: wrong helper, fail closed
		return apperr.New(apperr.Internal, "audit.unavailable", "")
	}
	if st.none {
		return tenancy.WithTx(ctx, db, fn)
	}
	return tenancy.WithTx(ctx, db, func(ctx context.Context, tx *sql.Tx) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		st.mu.Lock()
		if st.recorded {
			st.mu.Unlock()
			return nil
		}
		e := st.entry
		st.mu.Unlock()
		e.Outcome = OutcomeOK
		if tc, ok := tenancy.From(ctx); ok {
			e.TenantID = tc.TenantID.String()
		}
		if err := st.sink.RecordInTx(ctx, tx, e); err != nil {
			return apperr.Wrap(apperr.Internal, "audit.write_failed", "", err)
		}
		// Marked after the write; if Commit fails the response is an error
		// anyway and the gate below refuses any success status.
		st.mu.Lock()
		st.recorded = true
		st.mu.Unlock()
		return nil
	})
}

// WithPlatformAuditedTx is the helper for Policy.PlatformAudit routes: a plain
// transaction with no tenant context, plus the platform vendor access row in
// the same transaction for a vendor user's request. Same guarantees as
// WithAuditedTx: the row is written after the handler's own work and before
// commit, a failed write rolls everything back (fail closed), and one row is
// written per request. Calling it on a route that is not PlatformAudit, or
// without a vendor principal's audit state, fails closed for vendor actors;
// for other principals it is a plain transaction.
func WithPlatformAuditedTx(ctx context.Context, db tenancy.TxBeginner, fn func(ctx context.Context, tx *sql.Tx) error) error {
	p, ok := PrincipalFrom(ctx)
	var st *auditState
	if ok && p.IsVendorActor() {
		st = auditFrom(ctx)
		if st == nil || st.platform == nil {
			return apperr.New(apperr.Internal, "audit.unavailable", "")
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if st != nil {
		st.mu.Lock()
		done := st.recorded
		e := st.entry
		st.mu.Unlock()
		if !done {
			e.Outcome = OutcomeOK
			e.TenantID = ""
			if err := st.platform.RecordPlatformInTx(ctx, tx, e); err != nil {
				_ = tx.Rollback()
				return apperr.Wrap(apperr.Internal, "audit.write_failed", "", err)
			}
			st.mu.Lock()
			st.recorded = true
			st.mu.Unlock()
		}
	}
	return tx.Commit()
}

// VendorTenant returns a context whose tenancy context is the organisation a
// vendor-realm route names in its path (ADR-0013 V3 item 4). It is the one
// helper for that: it requires a vendor-realm principal holding permission.
// Tenant ids never come from anywhere else on a vendor route.
func VendorTenant(ctx context.Context, permission string, orgID ids.ID) (context.Context, error) {
	p, a, err := fromCtx(ctx)
	if err != nil {
		return ctx, err
	}
	if p.Realm != RealmVendor || p.Type != TypeUser {
		return ctx, denied()
	}
	if _, err := a.Scope(p, permission); err != nil {
		return ctx, err
	}
	if _, err := ids.Parse(orgID.String()); err != nil {
		return ctx, apperr.New(apperr.NotFound, CodeResourceNotFound, "resource not found")
	}
	if st := auditFrom(ctx); st != nil {
		st.mu.Lock()
		st.entry.TenantID = orgID.String()
		st.mu.Unlock()
	}
	return tenancy.With(ctx, tenancy.Context{TenantID: orgID, ActorID: p.Subject}), nil
}

// auditGate refuses to let a success response out for a vendor-authority
// request whose audit row was never written (a handler that skipped
// WithAuditedTx). The row is the condition for the response, not an
// afterthought (ADR-0013 V5 item 2).
type auditGate struct {
	http.ResponseWriter
	r       *http.Request
	st      *auditState
	decided bool
	blocked bool
}

func (g *auditGate) decide(code int) {
	if g.decided {
		return
	}
	g.decided = true
	if code < 400 && !g.st.isRecorded() {
		g.blocked = true
		apperr.WriteProblem(g.ResponseWriter, g.r, apperr.New(apperr.Internal, "audit.not_recorded", ""))
	}
}

func (g *auditGate) WriteHeader(code int) {
	g.decide(code)
	if !g.blocked {
		g.ResponseWriter.WriteHeader(code)
	}
}

func (g *auditGate) Write(b []byte) (int, error) {
	g.decide(http.StatusOK)
	if g.blocked {
		return len(b), nil
	}
	return g.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the real writer.
func (g *auditGate) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func newEntry(r *http.Request, p Principal, now time.Time, op string) VendorAccessEntry {
	return VendorAccessEntry{
		ID: ids.New(), Time: now, TenantID: p.TenantID, VendorUser: p.VendorUser(),
		TokenType: p.Type, SupportSession: p.SessionID, ActionKey: op, Ticket: p.Ticket,
		RequestID: logx.RequestID(r.Context()),
	}
}
