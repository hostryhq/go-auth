package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/testkit"
)

// vectors is a copy of api-specs common/vendor-grant.vectors.v1.json.
type vectors struct {
	SubjectHash []struct {
		Kind        string            `json:"kind"`
		Fields      map[string]string `json:"fields"`
		Text        string            `json:"text"`
		SubjectHash string            `json:"subject_hash"`
	} `json:"subject_hash"`
	ExamplePack  map[string]string `json:"example_pack"`
	ExampleGrant struct {
		Token  string           `json:"token"`
		Claims auth.GrantClaims `json:"claims"`
	} `json:"example_grant"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vendor-grant.vectors.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSubjectHashVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.SubjectHash {
		var fields []string
		switch c.Kind {
		case "org_suspend":
			fields = []string{c.Fields["organisation_id"], "suspended"}
		case "org_reinstate":
			fields = []string{c.Fields["organisation_id"], "active"}
		case "org_close":
			fields = []string{c.Fields["organisation_id"], "closed"}
		case "tax_rule_set_publish":
			fields = []string{c.Fields["rule_set_id"], c.Fields["content_hash"], c.Fields["effective_date"]}
		default:
			t.Fatalf("vector for unknown kind %s", c.Kind)
		}
		if got := auth.SubjectHash(c.Kind, fields...); got != c.SubjectHash {
			t.Errorf("%s: SubjectHash %s, want %s", c.Kind, got, c.SubjectHash)
		}
	}
}

// vendorSigner mints grants with its own key under a chosen kid.
type vendorSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newVendorSigner(kid string) *vendorSigner {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &vendorSigner{key: k, kid: kid}
}

func (s *vendorSigner) keys() *auth.StaticKeySet {
	return auth.NewStaticKeySet(auth.KeyDoc{Keys: map[string]*ecdsa.PublicKey{s.kid: &s.key.PublicKey}})
}

func (s *vendorSigner) mint(kid string, c auth.GrantClaims) string {
	hb, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	pb, _ := json.Marshal(c)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(in))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const (
	grantOrg      = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60"
	grantApprover = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a78"
)

type grantFixture struct {
	clk    *testkit.FakeClock
	signer *vendorSigner
	v      *auth.GrantVerifier
	claims auth.GrantClaims
}

func newGrantFixture() *grantFixture {
	clk := testkit.NewClock()
	s := newVendorSigner("vendor-realm-1")
	now := clk.Now().Unix()
	return &grantFixture{
		clk: clk, signer: s,
		v: &auth.GrantVerifier{Keys: s.keys(), Issuer: "https://identity.hostry.invalid/vendor", Audience: "tenancy",
			Clock: clk, Used: auth.NewMemoryGrantUsed(clk)},
		claims: auth.GrantClaims{
			Issuer: "https://identity.hostry.invalid/vendor", Realm: auth.RealmVendor, Audience: "tenancy", Type: auth.GrantType,
			JTI: "jti-1", ApprovalID: "ap-1", Kind: "org_suspend", Org: grantOrg,
			Requester: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a66", Approver: grantApprover,
			SubjectHash: auth.SubjectHash("org_suspend", grantOrg, "suspended"),
			IssuedAt:    now, ExpiresAt: now + 300,
		},
	}
}

func (f *grantFixture) want() auth.GrantWant {
	return auth.GrantWant{Kind: "org_suspend", Org: grantOrg, Approver: grantApprover,
		SubjectHash: func() (string, error) { return auth.SubjectHash("org_suspend", grantOrg, "suspended"), nil }}
}

func grantCode(t *testing.T, err error) string {
	t.Helper()
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("not an apperr: %v", err)
	}
	if ae.Kind != apperr.Forbidden {
		t.Errorf("grant refusals are 403, got kind %v", ae.Kind)
	}
	return ae.Code
}

func TestGrantVerifyExampleFromContract(t *testing.T) {
	v := loadVectors(t)
	raw, err := base64.RawURLEncoding.DecodeString(v.ExamplePack["vendor-realm-1"])
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	c := v.ExampleGrant.Claims
	clk := testkit.NewClock()
	clk.Set(time.Unix(c.IssuedAt+10, 0))
	gv := &auth.GrantVerifier{Keys: auth.NewStaticKeySet(auth.KeyDoc{Keys: map[string]*ecdsa.PublicKey{"vendor-realm-1": pub}}),
		Issuer: c.Issuer, Audience: c.Audience, Clock: clk, Used: auth.NewMemoryGrantUsed(clk)}
	want := auth.GrantWant{Kind: c.Kind, Org: c.Org, Approver: c.Approver,
		SubjectHash: func() (string, error) { return auth.SubjectHash("org_suspend", c.Org, "suspended"), nil }}
	got, err := gv.Verify(context.Background(), v.ExampleGrant.Token, want)
	if err != nil || got.JTI != c.JTI || got.ApprovalID != c.ApprovalID {
		t.Fatalf("contract example grant: %v %+v", err, got)
	}
	if _, err := gv.Verify(context.Background(), v.ExampleGrant.Token, want); grantCode(t, err) != auth.CodeGrantUsed {
		t.Errorf("replay of the contract example: %v", err)
	}
	clk.Set(time.Unix(c.ExpiresAt+1, 0))
	if _, err := gv.Verify(context.Background(), v.ExampleGrant.Token, want); grantCode(t, err) != auth.CodeGrantExpired {
		t.Errorf("after exp: %v", err)
	}
}

func TestGrantVerifyRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(f *grantFixture, c *auth.GrantClaims, kid *string, w *auth.GrantWant)
		code string
	}{
		{"accepted", func(*grantFixture, *auth.GrantClaims, *string, *auth.GrantWant) {}, ""},
		{"wrong kid", func(_ *grantFixture, _ *auth.GrantClaims, kid *string, _ *auth.GrantWant) { *kid = "vendor-realm-2" }, auth.CodeGrantInvalid},
		{"wrong audience", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) { c.Audience = "billing" }, auth.CodeGrantInvalid},
		{"wrong issuer", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) {
			c.Issuer = "https://evil.invalid"
		}, auth.CodeGrantInvalid},
		{"tenant realm", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) { c.Realm = auth.RealmTenant }, auth.CodeGrantInvalid},
		{"wrong typ", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) { c.Type = "approval" }, auth.CodeGrantInvalid},
		{"other kind", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) { c.Kind = "org_close" }, auth.CodeGrantInvalid},
		{"other org", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) {
			c.Org = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99"
		}, auth.CodeGrantInvalid},
		{"approver is not the bearer", func(_ *grantFixture, _ *auth.GrantClaims, _ *string, w *auth.GrantWant) { w.Approver = "someone-else" }, auth.CodeGrantInvalid},
		{"approver is requester", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) { c.Requester = c.Approver }, auth.CodeGrantInvalid},
		{"lifetime over 300s", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) {
			c.ExpiresAt = c.IssuedAt + 301
		}, auth.CodeGrantInvalid},
		{"expired", func(f *grantFixture, _ *auth.GrantClaims, _ *string, _ *auth.GrantWant) {
			f.clk.Advance(301 * time.Second)
		}, auth.CodeGrantExpired},
		{"tampered subject: executor state moved", func(_ *grantFixture, _ *auth.GrantClaims, _ *string, w *auth.GrantWant) {
			w.SubjectHash = func() (string, error) { return auth.SubjectHash("org_suspend", grantOrg, "active"), nil }
		}, auth.CodeGrantSubjectMismatch},
		{"tampered subject: forged hash in claims", func(_ *grantFixture, c *auth.GrantClaims, _ *string, _ *auth.GrantWant) {
			c.SubjectHash = auth.SubjectHash("org_suspend", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99", "suspended")
		}, auth.CodeGrantSubjectMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGrantFixture()
			c, kid, w := f.claims, f.signer.kid, f.want()
			tc.edit(f, &c, &kid, &w)
			_, err := f.v.Verify(context.Background(), f.signer.mint(kid, c), w)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || grantCode(t, err) != tc.code {
				t.Fatalf("got %v, want %s", err, tc.code)
			}
		})
	}
}

func TestGrantVerifyMalformedAndMissing(t *testing.T) {
	f := newGrantFixture()
	if _, err := f.v.Verify(context.Background(), "", f.want()); grantCode(t, err) != auth.CodeGrantRequired {
		t.Errorf("no grant: %v", err)
	}
	good := f.signer.mint(f.signer.kid, f.claims)
	for name, tok := range map[string]string{
		"garbage":       "not.a.jws",
		"bad signature": good[:len(good)-4] + "AAAA",
		"foreign key":   newVendorSigner(f.signer.kid).mint(f.signer.kid, f.claims),
	} {
		if _, err := f.v.Verify(context.Background(), tok, f.want()); grantCode(t, err) != auth.CodeGrantInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGrantSingleUse(t *testing.T) {
	f := newGrantFixture()
	tok := f.signer.mint(f.signer.kid, f.claims)
	if _, err := f.v.Verify(context.Background(), tok, f.want()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.Verify(context.Background(), tok, f.want()); grantCode(t, err) != auth.CodeGrantUsed {
		t.Errorf("replay: %v", err)
	}
	// A refused grant is not consumed: a subject mismatch leaves the jti free.
	g := newGrantFixture()
	c := g.claims
	c.JTI = "jti-2"
	tok = g.signer.mint(g.signer.kid, c)
	w := g.want()
	w.SubjectHash = func() (string, error) { return "other", nil }
	if _, err := g.v.Verify(context.Background(), tok, w); err == nil {
		t.Fatal("mismatch accepted")
	}
	if _, err := g.v.Verify(context.Background(), tok, g.want()); err != nil {
		t.Errorf("a refused grant must not burn its jti: %v", err)
	}
}
