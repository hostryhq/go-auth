// Package grantlimit evaluates the grant limits of ADR-0005 Amendment A2.4
// (rules G1 to G6). Identity calls it at write time, inside the transaction
// that changes roles, assignments, members or devices, with the actor's
// effective permissions read from stored assignments, never from the caller's
// token (G7): a 15-minute-old token of a demoted manager grants nothing.
//
// The evaluator is pure: it takes data and answers allow or refuse. It does not
// check step-up, strong sessions or the new-device caution; those are route
// level (go-auth guard). Refusal is 403 grant_not_permitted.
package grantlimit

import (
	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
)

// Permission names the rules depend on.
const (
	PermRoleManage       = "role.manage"
	PermMemberRoleAssign = "member.role.assign"
	PermDeviceRevoke     = "device.revoke"
)

// Holdings is what a member effectively holds: for each permission, the
// outlets where they hold it (the union of organisation-wide roles and roles
// scoped to outlets). The owner role is marked separately: it holds
// everything, including every owner_grant permission.
type Holdings struct {
	MemberID string
	Owner    bool
	Perms    map[string]auth.OutletScope
}

// Holds reports whether the member holds perm at every outlet of scope.
func (h Holdings) Holds(perm string, scope auth.OutletScope) bool {
	if h.Owner {
		return true
	}
	have, ok := h.Perms[perm]
	return ok && have.Covers(scope)
}

// HoldsOrgWide reports whether the member holds perm organisation-wide.
func (h Holdings) HoldsOrgWide(perm string) bool { return h.Holds(perm, auth.AllOutlets()) }

// Role is a named set of permissions. It may contain the owner wildcard only
// if it is the built-in owner role.
type Role struct {
	ID    string
	Perms []string
}

// Evaluator holds the catalogue the rules read the owner_grant flag from.
type Evaluator struct{ Catalogue *auth.Catalogue }

func notPermitted(why string) error {
	return apperr.New(apperr.Forbidden, auth.CodeGrantNotPermitted, why)
}

// containsOwnerGrant reports whether the role has a permission only an owner
// may hand out: an owner_grant permission, or the wildcard.
func (e Evaluator) containsOwnerGrant(r Role) bool {
	for _, p := range r.Perms {
		if p == auth.Wildcard {
			return true
		}
		if def, ok := e.Catalogue.Get(p); ok && def.OwnerGrant {
			return true
		}
	}
	return false
}

func (e Evaluator) unknownPerm(r Role) bool {
	for _, p := range r.Perms {
		if p == auth.Wildcard {
			continue
		}
		if _, ok := e.Catalogue.Get(p); !ok {
			return true
		}
	}
	return false
}

// holdsRole reports whether actor holds every permission of r at scope.
func (e Evaluator) holdsRole(actor Holdings, r Role, scope auth.OutletScope) bool {
	if actor.Owner {
		return true
	}
	for _, p := range r.Perms {
		if p == auth.Wildcard || !actor.Holds(p, scope) {
			return false
		}
	}
	return true
}

// CanWriteRole decides creating (before == nil) or editing a role (G1, G2).
// The actor needs role.manage organisation-wide and must hold, organisation-
// wide, every permission the role has before and after the edit. A role with an
// owner_grant permission can be written only by an owner.
func (e Evaluator) CanWriteRole(actor Holdings, before *Role, after Role) error {
	if e.unknownPerm(after) {
		return notPermitted("role contains a permission that is not in the catalogue")
	}
	if !actor.HoldsOrgWide(PermRoleManage) {
		return notPermitted("role administration not permitted")
	}
	touched := []Role{after}
	if before != nil {
		if e.unknownPerm(*before) {
			return notPermitted("role contains a permission that is not in the catalogue")
		}
		touched = append(touched, *before)
	}
	for _, r := range touched {
		if e.containsOwnerGrant(r) && !actor.Owner {
			return notPermitted("only an owner may change a role with owner-only permissions")
		}
		if !e.holdsRole(actor, r, auth.AllOutlets()) {
			return notPermitted("cannot grant a permission you do not hold")
		}
	}
	return nil
}

// Assignment is a change to a member's role assignment.
type Assignment struct {
	Target Holdings // the member whose assignment changes
	Role   Role
	// OwnerRole marks the built-in owner role.
	OwnerRole bool
	Scope     auth.OutletScope
	// Remove is true for unassigning.
	Remove bool
	// OwnerCount is the number of active owners before the change (G3).
	OwnerCount int
}

// CanAssign decides assigning, unassigning or re-scoping a role (G1 to G4).
func (e Evaluator) CanAssign(actor Holdings, a Assignment) error {
	if actor.MemberID != "" && actor.MemberID == a.Target.MemberID {
		return notPermitted("nobody changes their own assignments") // G4, the owner included
	}
	if a.OwnerRole {
		if !actor.Owner {
			return notPermitted("only an owner can assign or remove the owner role") // G3
		}
		if a.Remove && a.Target.Owner && a.OwnerCount <= 1 {
			return notPermitted("the last owner cannot be removed") // G3, ADR-0005 section 7
		}
		return nil
	}
	if e.unknownPerm(a.Role) || a.Scope.Empty() {
		return notPermitted("unknown permission or empty scope")
	}
	if !actor.Holds(PermMemberRoleAssign, a.Scope) {
		return notPermitted("role assignment not permitted at this scope")
	}
	if e.containsOwnerGrant(a.Role) && !actor.Owner {
		return notPermitted("only an owner may assign a role with owner-only permissions") // G2
	}
	if !e.holdsRole(actor, a.Role, a.Scope) {
		return notPermitted("cannot assign a permission you do not hold at this scope") // G1
	}
	return nil
}

// CanAdminister decides deactivating, removing, authorising a PIN reset for or
// clearing a lockout of a member (G4, G5). A non-owner may do so only if the
// target's effective permissions at scope are a subset of theirs and include no
// owner_grant permission.
func (e Evaluator) CanAdminister(actor Holdings, target Holdings, scope auth.OutletScope) error {
	if actor.MemberID != "" && actor.MemberID == target.MemberID {
		return notPermitted("nobody changes their own status") // G4
	}
	if scope.Empty() {
		return notPermitted("empty scope")
	}
	if actor.Owner {
		return nil
	}
	if target.Owner {
		return notPermitted("only an owner may administer an owner")
	}
	for perm, have := range target.Perms {
		overlap := have
		if !scope.All() {
			overlap = have.Intersect(scope.IDs())
			if overlap.Empty() {
				continue
			}
		}
		if def, ok := e.Catalogue.Get(perm); ok && def.OwnerGrant {
			return notPermitted("target holds owner-only permissions")
		}
		if !actor.Holds(perm, overlap) {
			return notPermitted("target holds permissions you do not hold")
		}
	}
	return nil
}

// Device is the part of a device record rule G6 needs.
type Device struct {
	// Personal devices are revoked only by their account holder or an owner.
	Personal        bool
	AccountMemberID string
	// Outlet is the outlet the device is bound to.
	Outlet string
}

// CanRevokeDevice decides device revocation (G6). A non-owner with
// device.revoke may revoke outlet devices in their scope.
func (e Evaluator) CanRevokeDevice(actor Holdings, d Device) error {
	if actor.Owner {
		return nil
	}
	if d.Personal {
		if actor.MemberID != "" && actor.MemberID == d.AccountMemberID {
			return nil
		}
		return notPermitted("a personal device is revoked only by its holder or an owner")
	}
	if d.Outlet == "" || !actor.Holds(PermDeviceRevoke, auth.OnlyOutlets(d.Outlet)) {
		return notPermitted("device revocation not permitted for this outlet")
	}
	return nil
}
