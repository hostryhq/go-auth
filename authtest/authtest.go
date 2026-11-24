// Package authtest is the test issuer for go-auth: it mints tokens, builds
// principals and contexts, and supplies a sample permission catalogue and a
// vendor audit sink, so other services' unit, contract and integration tests
// never hand-roll tokens. Import it from _test.go files and test doubles
// only. Keys are generated per test run; nothing here is a secret and no
// production code may depend on it.
package authtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/internal/authctx"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
)

// Names used by the default issuers.
const (
	TenantIssuerName = "hostry-identity"
	TenantAudience   = "hostry-tenant"
	VendorIssuerName = "hostry-identity-vendor"
	VendorAudience   = "hostry-vendor"
)

// Issuer mints tokens for one realm with its own ES256 key.
type Issuer struct {
	Realm    auth.Realm
	Name     string // iss
	Audience string
	Kid      string
	Clock    clock.Clock

	key *ecdsa.PrivateKey
	mu  sync.Mutex
	seq int
}

func newIssuer(realm auth.Realm, name, aud, kid string, clk clock.Clock) *Issuer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	if clk == nil {
		clk = clock.System
	}
	return &Issuer{Realm: realm, Name: name, Audience: aud, Kid: kid, Clock: clk, key: k}
}

// NewTenantIssuer is the issuer of tenant-realm tokens.
func NewTenantIssuer(clk clock.Clock) *Issuer {
	return newIssuer(auth.RealmTenant, TenantIssuerName, TenantAudience, "test-tenant-1", clk)
}

// NewVendorIssuer is the issuer of vendor-realm tokens, with a separate key,
// issuer and audience (ADR-0005 section 10).
func NewVendorIssuer(clk clock.Clock) *Issuer {
	return newIssuer(auth.RealmVendor, VendorIssuerName, VendorAudience, "test-vendor-1", clk)
}

// PublicKey is the issuer's verification key.
func (i *Issuer) PublicKey() *ecdsa.PublicKey { return &i.key.PublicKey }

// KeySet is a key set holding this issuer's key.
func (i *Issuer) KeySet() *auth.StaticKeySet {
	return auth.NewStaticKeySet(auth.KeyDoc{Keys: map[string]*ecdsa.PublicKey{i.Kid: i.PublicKey()}})
}

// Verifier is a verifier configured for this issuer.
func (i *Issuer) Verifier() *auth.Verifier {
	return &auth.Verifier{Keys: i.KeySet(), Issuer: i.Name, Audience: i.Audience, Realm: i.Realm, Clock: i.Clock}
}

// Spec describes a token. Zero fields take defaults for the type.
type Spec struct {
	Type         auth.TokenType
	Tenant       ids.ID // tid; ignored for vendor-realm tokens
	Subject      string
	Device       string
	Session      string
	AMR          []string
	AuthTime     time.Time
	Grants       []auth.Grant
	CautionUntil time.Time
	Mode         string
	Ticket       string
	Operation    string // approval tokens
	BodyHash     string // approval tokens
	TTL          time.Duration
}

// Claims builds the claim set for s, with defaults filled in.
func (i *Issuer) Claims(s Spec) auth.Claims {
	i.mu.Lock()
	i.seq++
	n := i.seq
	i.mu.Unlock()
	now := i.Clock.Now()
	if s.Type == "" {
		s.Type = auth.TypeUser
	}
	if s.TTL == 0 {
		s.TTL = 15 * time.Minute
		if s.Type == auth.TypeDrain || s.Type == auth.TypeApproval {
			s.TTL = 5 * time.Minute
		}
	}
	c := auth.Claims{
		Issuer: i.Name, Audience: auth.Audience{i.Audience}, Realm: i.Realm, Type: s.Type,
		Subject: s.Subject, DeviceID: s.Device, SessionID: s.Session, AMR: s.AMR, Grants: s.Grants,
		Mode: s.Mode, Ticket: s.Ticket, Operation: s.Operation, BodyHash: s.BodyHash,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(s.TTL).Unix(), JTI: "jti-" + strconv.Itoa(n),
	}
	if i.Realm == auth.RealmTenant {
		c.TenantID = s.Tenant.String()
	}
	if !s.AuthTime.IsZero() {
		c.AuthTime = s.AuthTime.Unix()
	}
	if !s.CautionUntil.IsZero() {
		c.CautionUntil = s.CautionUntil.Unix()
	}
	switch s.Type {
	case auth.TypeUser:
		if c.Subject == "" {
			c.Subject = "member-1"
			if i.Realm == auth.RealmVendor {
				c.Subject = "vendor-user-1"
			}
		}
		if len(c.AMR) == 0 {
			c.AMR = []string{auth.AMROTP}
			if i.Realm == auth.RealmVendor {
				c.AMR = []string{"pwd", "totp"}
			}
		}
		if c.AuthTime == 0 {
			c.AuthTime = now.Unix()
		}
		if c.SessionID == "" {
			c.SessionID = "sess-1"
		}
	case auth.TypePin:
		defaults(&c, "member-pin-1", "pin-sess-1", now)
		if len(c.AMR) == 0 {
			c.AMR = []string{auth.AMRPin}
		}
		if c.DeviceID == "" {
			c.DeviceID = "device-1"
		}
	case auth.TypeDevice:
		if c.DeviceID == "" {
			c.DeviceID = "device-1"
		}
		if c.Subject == "" {
			c.Subject = "device:" + c.DeviceID
		}
	case auth.TypeDrain:
		if c.DeviceID == "" {
			c.DeviceID = "device-1"
		}
		if c.Subject == "" {
			c.Subject = "device:" + c.DeviceID
		}
	case auth.TypeSupport:
		if c.Subject == "" {
			c.Subject = "support:vendor-user-1"
		}
		if c.Mode == "" {
			c.Mode = auth.ModeView
		}
		if c.SessionID == "" {
			c.SessionID = "support-sess-1"
		}
		if c.Ticket == "" {
			c.Ticket = "TCK-0001"
		}
	case auth.TypeApproval:
		if c.Subject == "" {
			c.Subject = "member-1"
		}
	}
	return c
}

func defaults(c *auth.Claims, sub, sid string, now time.Time) {
	if c.Subject == "" {
		c.Subject = sub
	}
	if c.SessionID == "" {
		c.SessionID = sid
	}
	if c.AuthTime == 0 {
		c.AuthTime = now.Unix()
	}
}

// Mint returns a correctly signed token for s.
func (i *Issuer) Mint(s Spec) string { return i.MintClaims(i.Claims(s)) }

// MintClaims signs arbitrary claims with the issuer's key, for negative tests
// (wrong audience, expired, over-long life).
func (i *Issuer) MintClaims(c auth.Claims) string {
	return i.sign(map[string]any{"alg": "ES256", "typ": "JWT", "kid": i.Kid}, c)
}

// MintWithHeader signs valid claims under a header with extra fields, such as
// jku, x5u, jwk or crit (IC-01).
func (i *Issuer) MintWithHeader(s Spec, extra map[string]any) string {
	h := map[string]any{"alg": "ES256", "typ": "JWT", "kid": i.Kid}
	for k, v := range extra {
		h[k] = v
	}
	return i.sign(h, i.Claims(s))
}

// MintWithKid signs valid claims under another key id.
func (i *Issuer) MintWithKid(s Spec, kid string) string {
	return i.sign(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid}, i.Claims(s))
}

// ForgeNone is an unsigned token with alg none.
func (i *Issuer) ForgeNone(s Spec) string {
	return encode(map[string]any{"alg": "none", "typ": "JWT", "kid": i.Kid}, i.Claims(s)) + "."
}

// ForgeHS256 is the classic confusion attack: an HS256 token keyed with the
// public key bytes.
func (i *Issuer) ForgeHS256(s Spec) string {
	in := encode(map[string]any{"alg": "HS256", "typ": "JWT", "kid": i.Kid}, i.Claims(s))
	pub := elliptic.Marshal(elliptic.P256(), i.key.PublicKey.X, i.key.PublicKey.Y) //nolint:staticcheck // the attack uses these bytes
	m := hmac.New(sha256.New, pub)
	m.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// ForgeES384 is a token declaring ES384 and signed with a P-384 key.
func (i *Issuer) ForgeES384(s Spec) string {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	in := encode(map[string]any{"alg": "ES384", "typ": "JWT", "kid": i.Kid}, i.Claims(s))
	sum := sha512.Sum384([]byte(in))
	r, sv, _ := ecdsa.Sign(rand.Reader, k, sum[:])
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	sv.FillBytes(sig[48:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ForgeWithOtherKey signs with a fresh key but this issuer's kid.
func (i *Issuer) ForgeWithOtherKey(s Spec) string {
	other := newIssuer(i.Realm, i.Name, i.Audience, i.Kid, i.Clock)
	return other.Mint(s)
}

// Forge signs claims with signerService's key under key id kid, for negative
// tests: an iss that does not match the registry key, or an over-long life.
func (r *ServiceRegistry) Forge(signerService, kid string, c auth.Claims) string {
	k, ok := r.keys[signerService]
	if !ok {
		panic(fmt.Sprintf("authtest: no service %q in registry", signerService))
	}
	i := &Issuer{key: k}
	return i.sign(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid}, c)
}

func encode(header map[string]any, claims any) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
}

func (i *Issuer) sign(header map[string]any, claims any) string {
	in := encode(header, claims)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, sum[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ServiceRegistry is a service key registry with a signer per service.
type ServiceRegistry struct {
	clk  clock.Clock
	keys map[string]*ecdsa.PrivateKey
}

// NewServiceRegistry creates keys for the named services.
func NewServiceRegistry(clk clock.Clock, services ...string) *ServiceRegistry {
	r := &ServiceRegistry{clk: clk, keys: map[string]*ecdsa.PrivateKey{}}
	for _, s := range services {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		r.keys[s] = k
	}
	return r
}

// KeySet is the registry's public keys, keyed by service name.
func (r *ServiceRegistry) KeySet() *auth.StaticKeySet {
	doc := auth.KeyDoc{Keys: map[string]*ecdsa.PublicKey{}}
	for n, k := range r.keys {
		doc.Keys[n] = &k.PublicKey
	}
	return auth.NewStaticKeySet(doc)
}

// Signer returns the named service's signer.
func (r *ServiceRegistry) Signer(name string) *auth.ServiceSigner {
	k, ok := r.keys[name]
	if !ok {
		panic(fmt.Sprintf("authtest: no service %q in registry", name))
	}
	return &auth.ServiceSigner{Name: name, Key: k, Clock: r.clk}
}

// Verifier is the verifier a service named self would use.
func (r *ServiceRegistry) Verifier(self string) *auth.ServiceVerifier {
	return &auth.ServiceVerifier{Registry: r.KeySet(), Self: self, Clock: r.clk}
}

// Grants builds one grant. outlets is a list of outlet ids, or nil/["*"] for
// the whole organisation.
func Grants(outlets []string, perms ...string) []auth.Grant {
	if len(outlets) == 0 {
		outlets = []string{"*"}
	}
	return []auth.Grant{{Outlets: outlets, Perms: perms}}
}

// OwnerGrants is the owner role: every permission at every outlet.
func OwnerGrants() []auth.Grant { return Grants(nil, auth.Wildcard) }

// Context installs a principal, the authorizer for cat and, for tenant-realm
// principals, the go-common tenancy context, on ctx. It stands in for the
// guard in unit tests of service and repository code.
func Context(ctx context.Context, cat *auth.Catalogue, clk clock.Clock, p auth.Principal) context.Context {
	ctx = authctx.Set(ctx, authctx.Authorizer, &auth.Authorizer{Catalogue: cat, Clock: clk})
	ctx = authctx.Set(ctx, authctx.Principal, p)
	if p.Realm == auth.RealmTenant && p.TenantID != "" {
		ctx = tenancy.With(ctx, tenancy.Context{TenantID: ids.ID(p.TenantID), ActorID: p.Subject, DeviceID: p.DeviceID})
	}
	return ctx
}

// ContextFor mints nothing: it builds the principal for s directly and installs it.
func (i *Issuer) ContextFor(ctx context.Context, cat *auth.Catalogue, s Spec) context.Context {
	c := i.Claims(s)
	return Context(ctx, cat, i.Clock, auth.NewPrincipal(&c, ""))
}
