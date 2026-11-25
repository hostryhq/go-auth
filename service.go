package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/tenancy"
)

// ServiceTokenHeader carries the 60-second service token (ADR-0005 section 9).
// The user's or vendor user's access token stays in Authorization, so a call
// made on someone's behalf carries both credentials (ADR-0013 V2).
const ServiceTokenHeader = "Hostry-Service-Token"

// ServiceTokenLifetime is the fixed life of a service token.
const ServiceTokenLifetime = 60 * time.Second

// ServiceSigner mints service tokens for one calling service. The private key
// is a deploy secret, referenced by name and loaded by the caller's main.
type ServiceSigner struct {
	Name  string // this service's name: becomes iss and the kid
	Key   *ecdsa.PrivateKey
	Clock clock.Clock
}

func (s *ServiceSigner) now() time.Time {
	if s.Clock == nil {
		return clock.System.Now()
	}
	return s.Clock.Now()
}

// Sign returns a token naming the callee as audience and, for work done
// outside a user request, the tenant being acted for (may be empty).
func (s *ServiceSigner) Sign(audience, tenantID string) (string, error) {
	if s.Name == "" || s.Key == nil || audience == "" {
		return "", errors.New("auth: service signer needs name, key and audience")
	}
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", err
	}
	now := s.now()
	c := Claims{
		Issuer: s.Name, Audience: Audience{audience}, Subject: s.Name, Type: TypeService,
		TenantID: tenantID, IssuedAt: now.Unix(), ExpiresAt: now.Add(ServiceTokenLifetime).Unix(),
		JTI: hex.EncodeToString(jti[:]),
	}
	return signES256(s.Key, s.Name, c)
}

func signES256(key *ecdsa.PrivateKey, kid string, claims any) (string, error) {
	hb, _ := json.Marshal(header{Alg: "ES256", Typ: "JWT", Kid: kid})
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(in))
	r, sv, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ServiceVerifier verifies service tokens against the service key registry
// deployed with the stack. The registry's key id is the service name, and a
// token's iss must equal the name of the key that verified it (IC-25).
type ServiceVerifier struct {
	Registry KeySet
	Self     string // this service's name: the required aud
	Clock    clock.Clock
	Skew     time.Duration
}

// Verify checks signature, iss against the registry, aud, expiry and the
// 60-second life.
func (v *ServiceVerifier) Verify(token string) (*Claims, error) {
	p, err := parseCompact(token)
	if err != nil {
		return nil, err
	}
	pub, err := v.Registry.Key(p.kid)
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
	if c.Issuer == "" || c.Issuer != p.kid {
		return nil, refuse(ReasonServiceIss)
	}
	if !c.Audience.Has(v.Self) || v.Self == "" {
		return nil, refuse(ReasonAudience)
	}
	if c.Type != TypeService {
		return nil, refuse(ReasonType)
	}
	if c.JTI == "" || c.IssuedAt == 0 || c.ExpiresAt == 0 {
		return nil, refuse(ReasonClaims)
	}
	ck, skew := v.Clock, v.Skew
	if ck == nil {
		ck = clock.System
	}
	if skew == 0 {
		skew = DefaultSkew
	}
	if err := checkTimes(&c, ck.Now(), skew); err != nil {
		return nil, err
	}
	return &c, nil
}

// ServiceTransport is an http.RoundTripper that adds a service token to each
// outbound call and passes the caller's access token on, so the callee
// authorises as the user (ADR-0005 section 9). The tenant claim is taken from
// the request's tenancy context.
type ServiceTransport struct {
	Base     http.RoundTripper // nil means http.DefaultTransport
	Signer   *ServiceSigner
	Audience string
}

// RoundTrip implements http.RoundTripper. The original request is not modified.
func (t *ServiceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tenant := ""
	if tc, ok := tenancy.From(r.Context()); ok {
		tenant = tc.TenantID.String()
	}
	tok, err := t.Signer.Sign(t.Audience, tenant)
	if err != nil {
		return nil, err
	}
	r2 := r.Clone(r.Context())
	r2.Header.Set(ServiceTokenHeader, tok)
	if r2.Header.Get("Authorization") == "" {
		if p, ok := PrincipalFrom(r.Context()); ok && p.raw != "" {
			r2.Header.Set("Authorization", "Bearer "+p.raw)
		}
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r2)
}
