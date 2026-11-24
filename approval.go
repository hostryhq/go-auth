package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/hostryhq/go-common/clock"
)

// ApprovalHeader carries an approval token (A2.2).
const ApprovalHeader = "Hostry-Approval"

const maxApprovalBody = 1 << 20

// SingleUse records token ids that have been used. Use returns true the first
// time a jti is seen and false after. Services with several instances back it
// with their database; MemorySingleUse serves one process and tests.
type SingleUse interface {
	Use(jti string, expires time.Time) bool
}

// MemorySingleUse is an in-memory SingleUse.
type MemorySingleUse struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	clock clock.Clock
}

// NewMemorySingleUse returns an empty store.
func NewMemorySingleUse(c clock.Clock) *MemorySingleUse {
	if c == nil {
		c = clock.System
	}
	return &MemorySingleUse{seen: map[string]time.Time{}, clock: c}
}

// Use implements SingleUse and forgets entries past their expiry.
func (m *MemorySingleUse) Use(jti string, expires time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	for k, e := range m.seen {
		if now.After(e) {
			delete(m.seen, k)
		}
	}
	if _, dup := m.seen[jti]; dup {
		return false
	}
	m.seen[jti] = expires
	return true
}

// ApprovalChecker verifies approval tokens (A2.2 item 6): ES256, type
// approval, bound to the caller's session, the operation id and a hash of the
// request body, 5 minutes, single use.
type ApprovalChecker struct {
	Verifier *Verifier // tenant realm; AllowTypes is forced to approval
	Used     SingleUse
}

// BodyHash is the value an approval token's bh claim must carry for body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var errApproval = errors.New("approval refused")

// Check verifies the request's approval token for principal p and operation op.
// It reads the body (bounded) and restores it for the handler.
func (a *ApprovalChecker) Check(r *http.Request, p Principal, op string) error {
	tok := r.Header.Get(ApprovalHeader)
	if tok == "" || a == nil || a.Verifier == nil || a.Used == nil {
		return errApproval
	}
	v := *a.Verifier
	v.AllowTypes = []TokenType{TypeApproval}
	c, err := v.Verify(tok)
	if err != nil {
		return err
	}
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, maxApprovalBody+1))
		if err != nil || len(body) > maxApprovalBody {
			return errApproval
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	if c.TenantID != p.TenantID || c.SessionID == "" || c.SessionID != p.SessionID || c.Operation != op || op == "" {
		return errApproval
	}
	if subtle.ConstantTimeCompare([]byte(c.BodyHash), []byte(BodyHash(body))) != 1 {
		return errApproval
	}
	if !a.Used.Use(c.JTI, time.Unix(c.ExpiresAt, 0)) {
		return errApproval
	}
	return nil
}
