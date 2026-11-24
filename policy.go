package auth

import (
	"fmt"
	"strings"
)

// InternalPrefix is the path prefix of service-to-service operations
// (ADR-0005 section 9). go-auth refuses these routes without a service token
// whatever the reverse proxy does.
const InternalPrefix = "/internal/v1"

// Policy is what an OpenAPI operation declares about its own protection
// (x-permission, x-step-up, x-service-callers, x-vendor-audit). It is built
// from the generated spec table. Every route needs one, and a policy that
// declares nothing is refused at start-up: the route table fails closed.
type Policy struct {
	// OperationID is the unique operationId. It is the audit action key and
	// the operation an approval token is bound to.
	OperationID string
	// Permission is x-permission.
	Permission string
	// StepUp is x-step-up: a fresh OTP is needed (auth_time within 10 minutes).
	StepUp bool
	// Public is an explicit "no authentication" declaration, for health and
	// readiness only. It cannot be combined with anything else.
	Public bool
	// Internal marks an /internal/v1 operation. Callers is x-service-callers.
	Internal bool
	Callers  []string
	// ServiceOnly is an internal operation done by a service on its own
	// authority (asynchronous work); no user token is expected.
	ServiceOnly bool
	// NoTenant allows a ServiceOnly operation with no tenant claim (the
	// cross-tenant feeds of TC-07). Everything else needs a tenant.
	NoTenant bool
	// Realm is the token realm; the default is the tenant realm.
	Realm Realm
	// AllowDrain accepts only a drain token (quarantine upload, wipe order).
	AllowDrain bool
	// VendorAuditNone is x-vendor-audit: none, allowed on directory-class
	// vendor operations only (DirectoryClass).
	VendorAuditNone bool
	DirectoryClass  bool
}

func (p Policy) realm() Realm {
	if p.Realm == "" {
		return RealmTenant
	}
	return p.Realm
}

// Validate checks the policy against the catalogue. It is the start-up check
// behind IST-16: no route reaches a handler without a declared, known
// permission (or an explicit Public, ServiceOnly or AllowDrain declaration).
func (p Policy) Validate(cat *Catalogue) error {
	if p.Public {
		if p.Permission != "" || p.StepUp || p.Internal || p.ServiceOnly || p.AllowDrain || p.Realm != "" {
			return fmt.Errorf("auth: policy %q: Public cannot be combined with other declarations", p.OperationID)
		}
		return nil
	}
	if p.OperationID == "" {
		return fmt.Errorf("auth: policy without an operation id")
	}
	if p.Realm != "" && p.Realm != RealmTenant && p.Realm != RealmVendor {
		return fmt.Errorf("auth: policy %q: unknown realm %q", p.OperationID, p.Realm)
	}
	modes := 0
	for _, b := range []bool{p.Permission != "", p.ServiceOnly, p.AllowDrain} {
		if b {
			modes++
		}
	}
	if modes != 1 {
		return fmt.Errorf("auth: policy %q declares no permission (or declares conflicting modes); refused", p.OperationID)
	}
	if p.Internal && len(p.Callers) == 0 {
		return fmt.Errorf("auth: policy %q: internal operation without x-service-callers", p.OperationID)
	}
	if !p.Internal && len(p.Callers) > 0 {
		return fmt.Errorf("auth: policy %q: callers declared on a non-internal operation", p.OperationID)
	}
	if p.ServiceOnly && (!p.Internal || p.realm() != RealmTenant) {
		return fmt.Errorf("auth: policy %q: ServiceOnly needs an internal tenant-realm operation", p.OperationID)
	}
	if p.NoTenant && !p.ServiceOnly {
		return fmt.Errorf("auth: policy %q: NoTenant only applies to ServiceOnly", p.OperationID)
	}
	if p.AllowDrain && (p.StepUp || p.realm() != RealmTenant) {
		return fmt.Errorf("auth: policy %q: drain routes take no step-up and are tenant-realm", p.OperationID)
	}
	if p.Permission != "" {
		if _, ok := cat.Get(p.Permission); !ok {
			return fmt.Errorf("auth: policy %q: permission %q is not in the catalogue", p.OperationID, p.Permission)
		}
	}
	if p.realm() == RealmVendor {
		if !p.Internal || !strings.HasPrefix(p.Permission, "admin.") {
			return fmt.Errorf("auth: policy %q: vendor routes are internal and need an admin.* permission", p.OperationID)
		}
	}
	if p.VendorAuditNone && !(p.DirectoryClass && p.realm() == RealmVendor) {
		return fmt.Errorf("auth: policy %q: x-vendor-audit: none is allowed on directory-class vendor operations only", p.OperationID)
	}
	return nil
}

// patternPath returns the path part of a ServeMux pattern ("GET /v1/x/{id}").
func patternPath(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = strings.TrimSpace(pattern[i+1:])
	}
	if i := strings.IndexByte(pattern, '/'); i > 0 { // strip a host part
		pattern = pattern[i:]
	}
	return pattern
}
