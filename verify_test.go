package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/testkit"
)

func reasonOf(err error) string {
	var ve *auth.VerifyError
	if errors.As(err, &ve) {
		return ve.Reason
	}
	return "not-a-verify-error"
}

// IST-01: the verification matrix. Every case is refused, with the reason that
// proves the right check caught it.
func TestVerifierRefusesBadTokens(t *testing.T) {
	clk := testkit.NewClock()
	iss := authtest.NewTenantIssuer(clk)
	v := iss.Verifier()
	ok := authtest.Spec{Tenant: testkit.TenantA, Grants: authtest.OwnerGrants()}

	if _, err := v.Verify(iss.Mint(ok)); err != nil {
		t.Fatalf("a good token must verify: %v", err)
	}

	now := clk.Now()
	claims := func(mut func(*auth.Claims)) string {
		c := iss.Claims(ok)
		mut(&c)
		return iss.MintClaims(c)
	}
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"alg none", iss.ForgeNone(ok), auth.ReasonAlg},
		{"alg HS256 keyed with the public key", iss.ForgeHS256(ok), auth.ReasonAlg},
		{"alg ES384", iss.ForgeES384(ok), auth.ReasonAlg},
		{"unknown kid", iss.MintWithKid(ok, "nope"), auth.ReasonUnknownKey},
		{"signed by another key under the right kid", iss.ForgeWithOtherKey(ok), auth.ReasonSignature},
		{"jku header", iss.MintWithHeader(ok, map[string]any{"jku": "https://attacker.example/keys"}), auth.ReasonHeader},
		{"x5u header", iss.MintWithHeader(ok, map[string]any{"x5u": "https://attacker.example/c"}), auth.ReasonHeader},
		{"embedded jwk header", iss.MintWithHeader(ok, map[string]any{"jwk": map[string]string{"kty": "EC"}}), auth.ReasonHeader},
		{"crit header", iss.MintWithHeader(ok, map[string]any{"crit": []string{"exp"}}), auth.ReasonHeader},
		{"wrong issuer", claims(func(c *auth.Claims) { c.Issuer = "someone-else" }), auth.ReasonIssuer},
		{"wrong audience", claims(func(c *auth.Claims) { c.Audience = auth.Audience{"other"} }), auth.ReasonAudience},
		{"wrong realm", claims(func(c *auth.Claims) { c.Realm = auth.RealmVendor }), auth.ReasonRealm},
		{"wrong type (approval is not an access token)", iss.Mint(authtest.Spec{Type: auth.TypeApproval, Tenant: testkit.TenantA}), auth.ReasonType},
		{"unknown type", claims(func(c *auth.Claims) { c.Type = "root" }), auth.ReasonType},
		{"expired", claims(func(c *auth.Claims) { c.ExpiresAt = now.Add(-time.Second).Unix() }), auth.ReasonExpired},
		{"nbf in the future", claims(func(c *auth.Claims) { c.NotBefore = now.Add(5 * time.Minute).Unix() }), auth.ReasonNotYet},
		{"iat more than 60s ahead", claims(func(c *auth.Claims) {
			c.IssuedAt = now.Add(61 * time.Second).Unix()
			c.ExpiresAt = now.Add(5 * time.Minute).Unix()
		}), auth.ReasonIssuedAt},
		{"lifetime longer than the type allows", claims(func(c *auth.Claims) { c.ExpiresAt = now.Add(time.Hour).Unix() }), auth.ReasonLifetime},
		{"no tenant", claims(func(c *auth.Claims) { c.TenantID = "" }), auth.ReasonClaims},
		{"no jti", claims(func(c *auth.Claims) { c.JTI = "" }), auth.ReasonClaims},
		{"not a JWS", "abc", auth.ReasonMalformed},
		{"empty", "", auth.ReasonMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.token)
			if got := reasonOf(err); got != tc.want {
				t.Fatalf("reason = %q, want %q (err %v)", got, tc.want, err)
			}
		})
	}

	t.Run("iat within the 60s skew is accepted", func(t *testing.T) {
		tok := claims(func(c *auth.Claims) {
			c.IssuedAt = now.Add(59 * time.Second).Unix()
			c.ExpiresAt = now.Add(5 * time.Minute).Unix()
		})
		if _, err := v.Verify(tok); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a token expires with the clock", func(t *testing.T) {
		tok := iss.Mint(ok)
		clk.Advance(16 * time.Minute)
		if got := reasonOf(errOf(v.Verify(tok))); got != auth.ReasonExpired {
			t.Fatalf("reason = %q", got)
		}
	})
}

func errOf(_ *auth.Claims, err error) error { return err }

// A jku header must never cause a fetch: the verifier has no way to make one,
// and the token is refused before any key lookup (IC-01).
func TestVerifierMakesNoOutboundCallForJKU(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	clk := testkit.NewClock()
	iss := authtest.NewTenantIssuer(clk)
	tok := iss.MintWithHeader(authtest.Spec{Tenant: testkit.TenantA}, map[string]any{"jku": srv.URL, "x5u": srv.URL})
	if _, err := iss.Verifier().Verify(tok); reasonOf(err) != auth.ReasonHeader {
		t.Fatalf("got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("verifier made %d outbound calls", hits.Load())
	}
}

type fakeLoader struct {
	calls atomic.Int32
	doc   auth.KeyDoc
	err   error
}

func (f *fakeLoader) Load(context.Context) (auth.KeyDoc, error) {
	f.calls.Add(1)
	return f.doc, f.err
}

// IST-02: rotation. A key published ahead of use verifies as soon as it is in
// the set; a revoked kid is refused; a failed refresh keeps the previous set;
// and no token can trigger a refresh.
func TestKeyRotationAndRevocation(t *testing.T) {
	clk := testkit.NewClock()
	oldK := authtest.NewTenantIssuer(clk)
	newK := authtest.NewTenantIssuer(clk)
	newK.Kid = "test-tenant-2"
	spec := authtest.Spec{Tenant: testkit.TenantA}

	ld := &fakeLoader{doc: auth.KeyDoc{Keys: oldK.KeySet().Keys()}}
	ks := auth.NewCachedKeySet(ld, nil)
	if err := ks.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	v := &auth.Verifier{Keys: ks, Issuer: oldK.Name, Audience: oldK.Audience, Realm: auth.RealmTenant, Clock: clk}

	if _, err := v.Verify(oldK.Mint(spec)); err != nil {
		t.Fatalf("current key: %v", err)
	}
	before := ld.calls.Load()
	if got := reasonOf(errOf(v.Verify(newK.Mint(spec)))); got != auth.ReasonUnknownKey {
		t.Fatalf("a key not yet published must be unknown, got %q", got)
	}
	if ld.calls.Load() != before {
		t.Fatal("verifying a token with an unknown kid triggered a key fetch")
	}

	// The next key is published ahead of its first use.
	keys := oldK.KeySet().Keys()
	keys["test-tenant-2"] = newK.PublicKey()
	ld.doc = auth.KeyDoc{Keys: keys}
	if err := ks.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(newK.Mint(spec)); err != nil {
		t.Fatalf("pre-published key must verify: %v", err)
	}
	if _, err := v.Verify(oldK.Mint(spec)); err != nil {
		t.Fatalf("retired-but-published key must still verify: %v", err)
	}

	// A failed refresh keeps the set.
	ld.err = errors.New("jwks down")
	if err := ks.Refresh(context.Background()); err == nil {
		t.Fatal("expected refresh error")
	}
	if _, err := v.Verify(newK.Mint(spec)); err != nil {
		t.Fatalf("set lost after failed refresh: %v", err)
	}

	// Emergency rotation: the old kid is revoked.
	ld.err = nil
	ld.doc = auth.KeyDoc{Keys: keys, Revoked: []string{oldK.Kid}}
	if err := ks.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := reasonOf(errOf(v.Verify(oldK.Mint(spec)))); got != auth.ReasonRevokedKey {
		t.Fatalf("revoked kid: got %q", got)
	}
	if _, err := v.Verify(newK.Mint(spec)); err != nil {
		t.Fatalf("new key after revocation: %v", err)
	}
}

func TestParseJWKSRefusesNonP256(t *testing.T) {
	if _, err := auth.ParseJWKS([]byte(`{"keys":[{"kty":"RSA","kid":"a","n":"x","e":"AQAB"}]}`)); err == nil {
		t.Fatal("RSA key must be refused, not skipped")
	}
	if _, err := auth.ParseJWKS([]byte(`{"keys":[{"kty":"EC","crv":"P-384","kid":"a","x":"AA","y":"AA"}]}`)); err == nil {
		t.Fatal("P-384 key must be refused")
	}
}
