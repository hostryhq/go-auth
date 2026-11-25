package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"
)

// Vendor approval grant (ADR-0014 A2.6): the one verifier every executing
// service uses. A grant is a compact ES256 JWS signed by identity's vendor
// realm key. It proves that two vendor users (requester and a different
// approver) agreed to one exact action on one organisation; the executing
// service recomputes the subject from its own state and consumes the jti in
// the action's own transaction.

// Error codes of the grant checks (api-specs common/vendor.yaml, 403).
const (
	CodeGrantRequired        = "grant.required"
	CodeGrantInvalid         = "grant.invalid"
	CodeGrantExpired         = "grant.expired"
	CodeGrantSubjectMismatch = "grant.subject_mismatch"
	CodeGrantUsed            = "grant.used"
)

// GrantType is the typ claim of a vendor approval grant.
const GrantType = "vendor_approval"

// MaxGrantLifetime is the longest exp - iat of a grant (A2.6: 300 seconds).
const MaxGrantLifetime = 300 * time.Second

// GrantClaims are the claims of a verified grant.
type GrantClaims struct {
	Issuer      string `json:"iss"`
	Realm       Realm  `json:"realm"`
	Audience    string `json:"aud"`
	Type        string `json:"typ"`
	JTI         string `json:"jti"`
	ApprovalID  string `json:"approval_id"`
	Kind        string `json:"kind"`
	Org         string `json:"org"`
	Requester   string `json:"requester"`
	Approver    string `json:"approver"`
	SubjectHash string `json:"subject_hash"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
}

// GrantUsed is the single-use hook. MarkUsed records jti and reports whether
// it was the first use. A service with a database implements it over
// approval_grant_used inside the action's transaction (and then leaves
// GrantVerifier.Used nil and consumes the jti itself, in that transaction).
type GrantUsed interface {
	MarkUsed(ctx context.Context, jti string, expires time.Time) (first bool, err error)
}

// MemoryGrantUsed is an in-memory GrantUsed for one process and tests.
type MemoryGrantUsed struct {
	mu   sync.Mutex
	seen map[string]time.Time
	clk  clock.Clock
}

// NewMemoryGrantUsed returns an empty store (nil clock means the system clock).
func NewMemoryGrantUsed(c clock.Clock) *MemoryGrantUsed {
	if c == nil {
		c = clock.System
	}
	return &MemoryGrantUsed{seen: map[string]time.Time{}, clk: c}
}

// MarkUsed implements GrantUsed.
func (m *MemoryGrantUsed) MarkUsed(_ context.Context, jti string, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clk.Now()
	for k, e := range m.seen {
		if now.After(e) {
			delete(m.seen, k)
		}
	}
	if _, dup := m.seen[jti]; dup {
		return false, nil
	}
	m.seen[jti] = expires
	return true, nil
}

// GrantWant is what the executing service expects, all taken from its own
// state or the verified request, never from the grant or a caller-sent value.
type GrantWant struct {
	// Kind is the action's grant kind (org_suspend, tax_rule_set_publish...).
	Kind string
	// Org is the organisation in the path.
	Org string
	// Approver is the subject of the bearer vendor token; it must equal the
	// grant's approver.
	Approver string
	// SubjectHash recomputes the subject hash (see SubjectHash) from the
	// executor's own stored state. It is called after every other check passes.
	SubjectHash func() (string, error)
}

// GrantVerifier verifies vendor approval grants under the vendor key set.
type GrantVerifier struct {
	Keys     KeySet // vendor realm keys, looked up by kid, never fetched
	Issuer   string
	Audience string // the executing service, e.g. "tenancy"
	Clock    clock.Clock
	Skew     time.Duration // zero means DefaultSkew
	// Used, if set, is consumed after every check passes. Leave nil when the
	// service consumes the jti in its own transaction.
	Used GrantUsed
}

func grantErr(code, detail string) error { return apperr.New(apperr.Forbidden, code, detail) }

func grantInvalid() error { return grantErr(CodeGrantInvalid, "vendor approval grant is not valid") }

// SubjectHash is the lower-case hex SHA-256 of the kind and its fields joined
// by single newlines (A2.6 item 2). The per-kind field list lives with the
// executing service, in the order the contract gives.
func SubjectHash(kind string, fields ...string) string {
	sum := sha256.Sum256([]byte(kind + "\n" + strings.Join(fields, "\n")))
	return hex.EncodeToString(sum[:])
}

// Verify checks token against want. Every failure is a 403 *apperr.Error:
// grant.required (empty token), grant.invalid (signature, kid, typ, realm,
// iss, aud, kind, org, approver, lifetime), grant.expired,
// grant.subject_mismatch and grant.used. The response never says which
// invalid check failed.
func (v *GrantVerifier) Verify(ctx context.Context, token string, want GrantWant) (*GrantClaims, error) {
	if token == "" {
		return nil, grantErr(CodeGrantRequired, "a vendor approval grant is required")
	}
	if v == nil || v.Keys == nil || v.Issuer == "" || v.Audience == "" || want.Kind == "" || want.SubjectHash == nil {
		return nil, grantInvalid() // misconfiguration fails closed
	}
	p, err := parseCompact(token)
	if err != nil {
		return nil, grantInvalid()
	}
	pub, err := v.Keys.Key(p.kid)
	if err != nil {
		return nil, grantInvalid()
	}
	if err := verifySig(p, pub); err != nil {
		return nil, grantInvalid()
	}
	var c GrantClaims
	if err := json.Unmarshal(p.payload, &c); err != nil {
		return nil, grantInvalid()
	}
	if c.Issuer != v.Issuer || c.Audience != v.Audience || c.Realm != RealmVendor || c.Type != GrantType ||
		c.JTI == "" || c.ApprovalID == "" || c.Requester == "" || c.Approver == "" || c.SubjectHash == "" ||
		c.IssuedAt == 0 || c.ExpiresAt == 0 {
		return nil, grantInvalid()
	}
	if c.Kind != want.Kind || c.Org != want.Org {
		return nil, grantInvalid()
	}
	if c.Approver == c.Requester || want.Approver == "" || c.Approver != want.Approver {
		return nil, grantInvalid()
	}
	now := v.clk().Now()
	skew := v.Skew
	if skew == 0 {
		skew = DefaultSkew
	}
	if c.ExpiresAt-c.IssuedAt <= 0 || time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > MaxGrantLifetime ||
		time.Unix(c.IssuedAt, 0).After(now.Add(skew)) {
		return nil, grantInvalid()
	}
	if now.After(time.Unix(c.ExpiresAt, 0)) {
		return nil, grantErr(CodeGrantExpired, "vendor approval grant has expired")
	}
	mine, err := want.SubjectHash()
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(mine), []byte(c.SubjectHash)) != 1 {
		return nil, grantErr(CodeGrantSubjectMismatch, "the action no longer matches what was approved")
	}
	if v.Used != nil {
		first, err := v.Used.MarkUsed(ctx, c.JTI, time.Unix(c.ExpiresAt, 0))
		if err != nil {
			return nil, err
		}
		if !first {
			return nil, grantErr(CodeGrantUsed, "vendor approval grant was already used")
		}
	}
	return &c, nil
}

func (v *GrantVerifier) clk() clock.Clock {
	if v.Clock == nil {
		return clock.System
	}
	return v.Clock
}
