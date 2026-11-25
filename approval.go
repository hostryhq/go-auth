package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
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

// TargetHash is the value an approval token's th claim must carry: lowercase
// hex SHA-256 over METHOD, a newline, the concrete request path (ids filled
// in, escaped form), a newline and the body hash (BodyHash). It binds the
// approval to one resource, not only to an operation id (SR-H1).
func TargetHash(method, path, bodyHash string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(method) + "\n" + path + "\n" + bodyHash))
	return hex.EncodeToString(sum[:])
}

// RequestTargetHash computes TargetHash for r, given the body hash already computed.
func RequestTargetHash(r *http.Request, bodyHash string) string {
	return TargetHash(r.Method, r.URL.EscapedPath(), bodyHash)
}

var errApproval = errors.New("approval refused")

// readBody returns the exact request body bytes as sent and restores r.Body
// so the handler can read it again. A body over 1 MiB is refused.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxApprovalBody+1))
	if err != nil || len(body) > maxApprovalBody {
		return nil, errApproval
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// RequestBodyHash computes the approval body hash (bh) of r: SHA-256 over the
// exact request body bytes as sent, no re-serialisation, base64url without
// padding; an empty body hashes the empty string. The body is read and
// restored. Use it on the device or admin side that requests an approval.
func RequestBodyHash(r *http.Request) (string, error) {
	body, err := readBody(r)
	if err != nil {
		return "", err
	}
	return BodyHash(body), nil
}

// VerifyBodyHash checks that the body of r hashes to want (the bh claim of an
// approval token). It reads and restores the body and compares in constant
// time; a mismatch returns the same refusal as any other approval failure.
func VerifyBodyHash(r *http.Request, want string) error {
	got, err := RequestBodyHash(r)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errApproval
	}
	return nil
}

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
	body, err := readBody(r)
	if err != nil {
		return err
	}
	if c.TenantID != p.TenantID || c.SessionID == "" || c.SessionID != p.SessionID || c.Operation != op || op == "" {
		return errApproval
	}
	if subtle.ConstantTimeCompare([]byte(c.BodyHash), []byte(BodyHash(body))) != 1 {
		return errApproval // same rule as VerifyBodyHash, on the bytes already read
	}
	// SR-H1: method, concrete path and body; a token without th is refused.
	if c.TargetHash == "" || subtle.ConstantTimeCompare([]byte(c.TargetHash), []byte(RequestTargetHash(r, BodyHash(body)))) != 1 {
		return errApproval
	}
	if !a.Used.Use(c.JTI, time.Unix(c.ExpiresAt, 0)) {
		return errApproval
	}
	return nil
}
