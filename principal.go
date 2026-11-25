package auth

import (
	"context"
	"strings"
	"time"

	"github.com/hostryhq/go-auth/internal/authctx"
)

// Principal is the verified caller of a request. It is built only from a
// verified token (by the guard, or by authtest in tests), never from request
// fields.
type Principal struct {
	Realm        Realm
	Type         TokenType
	TenantID     string // empty for vendor-realm tokens
	Subject      string // member id, "device:<id>", or "support:<vendor user>"
	DeviceID     string
	SessionID    string
	AMR          []string
	AuthTime     time.Time
	Grants       []Grant
	CautionUntil time.Time // zero when the binding is not under caution
	Mode         string    // support tokens: view or act
	Ticket       string    // support tokens
	JTI          string
	// Approved is true when a valid approval token (A2.2) accompanied this
	// request, bound to its operation, body and session.
	Approved bool
	// ServiceCaller is the iss of the verified service token that came with
	// the request, if any.
	ServiceCaller string

	// widenPerm and widenBy are set by the guard from the route's policy
	// (x-permission-widened-by): in act mode a support token is judged on
	// widenBy where the route asks for widenPerm.
	widenPerm, widenBy string

	raw string // the bearer token, kept only to pass on to callees; never logged
}

// NewPrincipal builds a principal from verified claims. raw is the bearer
// token, retained for ServiceTransport only.
func NewPrincipal(c *Claims, raw string) Principal {
	p := Principal{
		Realm: c.Realm, Type: c.Type, TenantID: c.TenantID, Subject: c.Subject,
		DeviceID: c.DeviceID, SessionID: c.SessionID, AMR: c.AMR, Grants: c.Grants,
		Mode: c.Mode, Ticket: c.Ticket, JTI: c.JTI, raw: raw,
	}
	if c.AuthTime != 0 {
		p.AuthTime = time.Unix(c.AuthTime, 0)
	}
	if c.CautionUntil != 0 {
		p.CautionUntil = time.Unix(c.CautionUntil, 0)
	}
	return p
}

// String never includes the token.
func (p Principal) String() string { return "principal(" + string(p.Type) + ":" + p.Subject + ")" }

// IsVendorActor reports whether the request is made on a vendor user's
// authority: a vendor-realm token, or a support token in a tenant (ADR-0013 V5).
func (p Principal) IsVendorActor() bool { return p.Realm == RealmVendor || p.Type == TypeSupport }

// VendorUser returns the vendor user id for audit: the subject, without the
// "support:" prefix of support tokens.
func (p Principal) VendorUser() string { return strings.TrimPrefix(p.Subject, "support:") }

// UnderCaution reports whether the token's binding is inside its 24-hour
// new-device window at now (A2.2).
func (p Principal) UnderCaution(now time.Time) bool {
	return !p.CautionUntil.IsZero() && now.Before(p.CautionUntil)
}

// StepUpFresh reports whether the principal satisfies x-step-up (ADR-0005
// section 3): a strong user session with a fresh OTP, within window. The
// vendor-assisted code never counts (A2.3), and a support token never does
// (A2.5).
func (p Principal) StepUpFresh(now time.Time, window time.Duration) bool {
	if p.Type != TypeUser || p.Realm != RealmTenant || p.AuthTime.IsZero() {
		return false
	}
	otp := false
	for _, m := range p.AMR {
		if m == AMROTP {
			otp = true
		}
	}
	return otp && !now.Before(p.AuthTime) && now.Sub(p.AuthTime) <= window
}

// PrincipalFrom returns the principal placed by the guard.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := authctx.Get(ctx, authctx.Principal).(Principal)
	return p, ok
}
