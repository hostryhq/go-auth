// Package auth is the shared Hostry authentication and authorisation library
// (ADR-0005 section 11). Every service verifies tokens, resolves the tenant
// context and checks permissions through it; nothing here issues tokens
// except short-lived service tokens (section 9).
package auth

import (
	"encoding/json"
	"fmt"
	"time"
)

// Realm separates tenant users from Hostry vendor staff (ADR-0005 section 10).
type Realm string

// Realms.
const (
	RealmTenant Realm = "tenant"
	RealmVendor Realm = "vendor"
)

// TokenType is the `typ` claim.
type TokenType string

// Token types (ADR-0005 section 2, A2.2).
const (
	TypeUser     TokenType = "user"     // strong session (OTP sign-in, or vendor user)
	TypePin      TokenType = "pin"      // shared-device staff session
	TypeDevice   TokenType = "device"   // KDS, hub
	TypeDrain    TokenType = "drain"    // revoked device: quarantine upload and wipe order only
	TypeSupport  TokenType = "support"  // vendor staff acting in a tenant (view or act mode)
	TypeApproval TokenType = "approval" // single-operation approval (A2.2)
	TypeService  TokenType = "service"  // service-to-service (section 9)
)

// Authentication method references (`amr`).
const (
	AMRPin        = "pin"
	AMROTP        = "otp"
	AMRVendorCode = "vendor_code" // never satisfies step-up (A2.3)
)

// Support modes.
const (
	ModeView = "view"
	ModeAct  = "act"
)

// Grant is one entry of the `grants` claim. Outlets is ["*"] or outlet ids;
// Perms are permission strings, or the single owner wildcard "*".
type Grant struct {
	Outlets []string `json:"outlets"`
	Perms   []string `json:"perms"`
}

// Audience is the `aud` claim, accepted as a string or a list.
type Audience []string

// UnmarshalJSON accepts "x" or ["x", ...].
func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud: %w", err)
	}
	*a = many
	return nil
}

// MarshalJSON writes a single audience as a string.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Has reports whether v is one of the audiences.
func (a Audience) Has(v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}

// Claims is the verified claim set of any Hostry token. Fields not used by a
// token type are empty. Times are Unix seconds.
type Claims struct {
	Issuer       string    `json:"iss"`
	Audience     Audience  `json:"aud"`
	Subject      string    `json:"sub"`
	Realm        Realm     `json:"realm,omitempty"`
	Type         TokenType `json:"typ"`
	TenantID     string    `json:"tid,omitempty"`
	DeviceID     string    `json:"did,omitempty"`
	SessionID    string    `json:"sid,omitempty"`
	AMR          []string  `json:"amr,omitempty"`
	AuthTime     int64     `json:"auth_time,omitempty"`
	Grants       []Grant   `json:"grants,omitempty"`
	CautionUntil int64     `json:"caution_until,omitempty"` // A2.2: new-device binding under caution
	Mode         string    `json:"mode,omitempty"`          // support tokens: view or act
	Ticket       string    `json:"ticket,omitempty"`        // support tokens: ticket reference (audit)
	Operation    string    `json:"op,omitempty"`            // approval tokens: operation id
	BodyHash     string    `json:"bh,omitempty"`            // approval tokens: base64url sha256 of the body
	TargetHash   string    `json:"th,omitempty"`            // approval tokens: hex sha256 of METHOD\npath\nbh (SR-H1)
	Label        string    `json:"lbl,omitempty"`           // approval tokens: human-readable subject shown to the approver
	IssuedAt     int64     `json:"iat"`
	NotBefore    int64     `json:"nbf,omitempty"`
	ExpiresAt    int64     `json:"exp"`
	JTI          string    `json:"jti"`
}

// Maximum lifetimes by token type (ADR-0005 section 2). A token claiming a
// longer life than its type allows is refused even if correctly signed.
var maxLifetime = map[TokenType]time.Duration{
	TypeUser:     15 * time.Minute,
	TypePin:      15 * time.Minute,
	TypeDevice:   15 * time.Minute,
	TypeDrain:    5 * time.Minute,
	TypeSupport:  15 * time.Minute,
	TypeApproval: 5 * time.Minute,
	TypeService:  60 * time.Second,
}

// MaxTokenBytes is the size above which a token is refused (ADR-0005: target
// under 4 KB, issuing fails above 6 KB).
const MaxTokenBytes = 8 * 1024
