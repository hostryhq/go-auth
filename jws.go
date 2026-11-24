package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
)

// Reasons a token is refused. They are for logs and tests; responses carry a
// single generic code so a caller learns nothing about which check failed.
const (
	ReasonMalformed   = "malformed"
	ReasonAlg         = "alg_not_es256"
	ReasonHeader      = "forbidden_header" // jku, x5u, x5c, jwk, crit
	ReasonUnknownKey  = "unknown_kid"
	ReasonRevokedKey  = "revoked_kid"
	ReasonSignature   = "bad_signature"
	ReasonIssuer      = "wrong_issuer"
	ReasonAudience    = "wrong_audience"
	ReasonRealm       = "wrong_realm"
	ReasonType        = "wrong_type"
	ReasonExpired     = "expired"
	ReasonNotYet      = "not_yet_valid"
	ReasonIssuedAt    = "bad_iat"
	ReasonLifetime    = "lifetime_too_long"
	ReasonClaims      = "bad_claims"
	ReasonServiceIss  = "service_iss_mismatch"
	ReasonTooLarge    = "too_large"
	ReasonKeyUnusable = "key_unusable"
)

// VerifyError is returned for every refused token.
type VerifyError struct{ Reason string }

func (e *VerifyError) Error() string { return "auth: token refused: " + e.Reason }

func refuse(reason string) error { return &VerifyError{Reason: reason} }

// header is the decoded JOSE header. Only alg, typ and kid are accepted; the
// presence of any key-bearing or extension header refuses the token.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid"`
}

var forbiddenHeaders = []string{"jku", "x5u", "x5c", "x5t", "x5t#S256", "jwk", "crit"}

// parsed is a split, header-checked compact JWS.
type parsed struct {
	kid       string
	signingIn string // header.payload, the signed bytes
	payload   []byte
	sig       []byte
}

// parseCompact splits and checks the structure and header of a compact JWS.
// It does not touch any key.
func parseCompact(tok string) (*parsed, error) {
	if len(tok) > MaxTokenBytes {
		return nil, refuse(ReasonTooLarge)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, refuse(ReasonMalformed)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, refuse(ReasonMalformed)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(hb, &raw); err != nil {
		return nil, refuse(ReasonMalformed)
	}
	for _, f := range forbiddenHeaders {
		if _, bad := raw[f]; bad {
			return nil, refuse(ReasonHeader)
		}
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, refuse(ReasonMalformed)
	}
	// Exact match: "none", "HS256", "RS256", "ES384" and "es256" are all refused.
	if h.Alg != "ES256" {
		return nil, refuse(ReasonAlg)
	}
	if h.Kid == "" {
		return nil, refuse(ReasonUnknownKey)
	}
	pl, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, refuse(ReasonMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, refuse(ReasonSignature)
	}
	return &parsed{kid: h.Kid, signingIn: parts[0] + "." + parts[1], payload: pl, sig: sig}, nil
}

// verifySig checks the ES256 signature (raw r||s) with a P-256 key.
func verifySig(p *parsed, pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve != elliptic.P256() {
		return refuse(ReasonKeyUnusable)
	}
	sum := sha256.Sum256([]byte(p.signingIn))
	r := new(big.Int).SetBytes(p.sig[:32])
	s := new(big.Int).SetBytes(p.sig[32:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return refuse(ReasonSignature)
	}
	return nil
}
