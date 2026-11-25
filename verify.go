package auth

import (
	"encoding/json"
	"time"

	"github.com/hostryhq/go-common/clock"
)

// DefaultSkew is the tolerated clock difference for iat and nbf (IC-01).
const DefaultSkew = 60 * time.Second

// Verifier verifies access-style tokens for one realm: ES256 only, with the
// issuer, audience, realm, type, expiry and issued-at checks of ADR-0005
// section 2 and threat-model control IC-01. Keys come from Keys only.
type Verifier struct {
	Keys     KeySet
	Issuer   string
	Audience string
	Realm    Realm
	// AllowTypes lists accepted token types. Empty means the access types:
	// user, pin, device, drain and support.
	AllowTypes []TokenType
	Clock      clock.Clock
	Skew       time.Duration // zero means DefaultSkew
}

var accessTypes = []TokenType{TypeUser, TypePin, TypeDevice, TypeDrain, TypeSupport}

func (v *Verifier) clock() clock.Clock {
	if v.Clock == nil {
		return clock.System
	}
	return v.Clock
}

func (v *Verifier) skew() time.Duration {
	if v.Skew == 0 {
		return DefaultSkew
	}
	return v.Skew
}

func (v *Verifier) typeAllowed(t TokenType) bool {
	allowed := v.AllowTypes
	if len(allowed) == 0 {
		allowed = accessTypes
	}
	for _, a := range allowed {
		if a == t {
			return true
		}
	}
	return false
}

// Verify checks a compact token and returns its claims. Every refusal is a
// *VerifyError.
func (v *Verifier) Verify(token string) (*Claims, error) {
	p, err := parseCompact(token)
	if err != nil {
		return nil, err
	}
	pub, err := v.Keys.Key(p.kid)
	if err != nil {
		return nil, err
	}
	if err := verifySig(p, pub); err != nil {
		return nil, err
	}
	var c Claims
	if err := json.Unmarshal(p.payload, &c); err != nil {
		return nil, refuse(ReasonClaims)
	}
	if c.Issuer == "" || c.Issuer != v.Issuer {
		return nil, refuse(ReasonIssuer)
	}
	if !c.Audience.Has(v.Audience) {
		return nil, refuse(ReasonAudience)
	}
	if c.Realm != v.Realm {
		return nil, refuse(ReasonRealm)
	}
	if !v.typeAllowed(c.Type) {
		return nil, refuse(ReasonType)
	}
	if c.Subject == "" || c.JTI == "" || c.IssuedAt == 0 || c.ExpiresAt == 0 {
		return nil, refuse(ReasonClaims)
	}
	if v.Realm == RealmTenant && c.TenantID == "" {
		return nil, refuse(ReasonClaims) // exactly one tenant per token (IC-11)
	}
	if v.Realm == RealmVendor && c.TenantID != "" {
		return nil, refuse(ReasonClaims) // a vendor token names no tenant
	}
	if err := checkTimes(&c, v.clock().Now(), v.skew()); err != nil {
		return nil, err
	}
	return &c, nil
}

func checkTimes(c *Claims, now time.Time, skew time.Duration) error {
	if now.After(time.Unix(c.ExpiresAt, 0)) {
		return refuse(ReasonExpired)
	}
	if c.NotBefore != 0 && time.Unix(c.NotBefore, 0).After(now.Add(skew)) {
		return refuse(ReasonNotYet)
	}
	if time.Unix(c.IssuedAt, 0).After(now.Add(skew)) {
		return refuse(ReasonIssuedAt)
	}
	max, ok := maxLifetime[c.Type]
	if !ok || time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > max {
		return refuse(ReasonLifetime)
	}
	return nil
}
