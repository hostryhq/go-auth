package auth

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// Permission is one entry of the platform permission catalogue (ADR-0005
// section 7). The catalogue lives in api-specs/common and is generated into
// this type; organisations cannot invent permissions.
type Permission struct {
	Name  string `json:"name"`
	Owner string `json:"owner"` // owning service
	// Sensitive: a reason and an audit record are required.
	Sensitive bool `json:"sensitive,omitempty"`
	// StrongOnly: never usable in a pin, device or drain session, and not in a
	// sync intent.
	StrongOnly bool `json:"strong_only,omitempty"`
	// SupportViewable: a support token in view mode may use it.
	SupportViewable bool `json:"support_viewable,omitempty"`
	// SupportActable (A2.5): a support token in act mode may use it. Default false.
	SupportActable bool `json:"support_actable,omitempty"`
	// OwnerGrant (A2.4): only an owner may put it in a role or assign it.
	OwnerGrant bool `json:"owner_grant,omitempty"`
}

// Wildcard is the owner role's single permission wildcard. There are no
// partial wildcards.
const Wildcard = "*"

var permName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Catalogue is the validated set of permissions.
type Catalogue struct{ perms map[string]Permission }

// NewCatalogue validates and indexes ps. The lints are the CI rules of the
// ADR: names are well formed and unique; every strong_only permission is
// owner_grant (A2.4 G2); support_actable is refused on a sensitive, strong_only
// or owner_grant permission (A2.5).
func NewCatalogue(ps ...Permission) (*Catalogue, error) {
	c := &Catalogue{perms: make(map[string]Permission, len(ps))}
	for _, p := range ps {
		if !permName.MatchString(p.Name) {
			return nil, fmt.Errorf("auth: catalogue: bad permission name %q", p.Name)
		}
		if _, dup := c.perms[p.Name]; dup {
			return nil, fmt.Errorf("auth: catalogue: duplicate permission %q", p.Name)
		}
		if p.StrongOnly && !p.OwnerGrant {
			return nil, fmt.Errorf("auth: catalogue: %q is strong_only and must be owner_grant", p.Name)
		}
		if p.SupportActable && (p.Sensitive || p.StrongOnly || p.OwnerGrant) {
			return nil, fmt.Errorf("auth: catalogue: %q cannot be support_actable (sensitive, strong_only or owner_grant)", p.Name)
		}
		c.perms[p.Name] = p
	}
	return c, nil
}

// LoadCatalogue reads the generated catalogue JSON (an array of Permission).
func LoadCatalogue(b []byte) (*Catalogue, error) {
	var ps []Permission
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil, fmt.Errorf("auth: catalogue: %w", err)
	}
	return NewCatalogue(ps...)
}

// Get returns the permission, if it is in the catalogue.
func (c *Catalogue) Get(name string) (Permission, bool) {
	p, ok := c.perms[name]
	return p, ok
}

// All returns the permissions sorted by name. Tests are generated from it: one
// case per strong_only permission (IST-17).
func (c *Catalogue) All() []Permission {
	out := make([]Permission, 0, len(c.perms))
	for _, p := range c.perms {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
