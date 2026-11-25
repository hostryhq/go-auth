package grantlimit_test

import (
	"errors"
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/go-common/apperr"
)

func holds(id string, perms map[string]auth.OutletScope) grantlimit.Holdings {
	return grantlimit.Holdings{MemberID: id, Perms: perms}
}

func org(perms ...string) map[string]auth.OutletScope {
	m := map[string]auth.OutletScope{}
	for _, p := range perms {
		m[p] = auth.AllOutlets()
	}
	return m
}

func wantRefused(t *testing.T, name string, err error) {
	t.Helper()
	var e *apperr.Error
	if !errors.As(err, &e) || e.Kind != apperr.Forbidden || e.Code != auth.CodeGrantNotPermitted {
		t.Errorf("%s: want 403 grant_not_permitted, got %v", name, err)
	}
}

func wantAllowed(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: want allowed, got %v", name, err)
	}
}

// IST-30 / A2.4: the delegation ceiling.
func TestRoleWriteRulesG1G2(t *testing.T) {
	ev := grantlimit.Evaluator{Catalogue: authtest.Catalogue()}
	owner := grantlimit.Holdings{MemberID: "o1", Owner: true}
	manager := holds("m1", org(authtest.RoleManage, authtest.OrderCreate, authtest.OrderRead, authtest.BillCancel, authtest.MemberRoleAssign))

	// G1: nothing beyond what the actor holds.
	wantAllowed(t, "role within own permissions", ev.CanWriteRole(manager, nil, grantlimit.Role{ID: "cashier", Perms: []string{authtest.OrderCreate, authtest.OrderRead}}))
	wantRefused(t, "role with a permission the manager lacks", ev.CanWriteRole(manager, nil, grantlimit.Role{ID: "r", Perms: []string{authtest.OrderCreate, authtest.ReportView}}))
	// G2: owner-grant permissions are the owner's even when the manager holds them.
	holdsStrong := holds("m2", org(authtest.RoleManage, authtest.MemberAdd))
	wantRefused(t, "owner_grant permission by a non-owner who holds it", ev.CanWriteRole(holdsStrong, nil, grantlimit.Role{ID: "r", Perms: []string{authtest.MemberAdd}}))
	wantAllowed(t, "owner writes an owner_grant role", ev.CanWriteRole(owner, nil, grantlimit.Role{ID: "r", Perms: []string{authtest.MemberAdd}}))
	// Without role.manage nothing is allowed; role.manage at one outlet is not organisation-wide.
	wantRefused(t, "no role.manage", ev.CanWriteRole(holds("m3", org(authtest.OrderCreate)), nil, grantlimit.Role{Perms: []string{authtest.OrderCreate}}))
	scopedMgr := holds("m4", map[string]auth.OutletScope{authtest.RoleManage: auth.OnlyOutlets("x"), authtest.OrderCreate: auth.AllOutlets()})
	wantRefused(t, "role.manage at one outlet only", ev.CanWriteRole(scopedMgr, nil, grantlimit.Role{Perms: []string{authtest.OrderCreate}}))
	// Editing: the permissions before the edit count too, so a manager cannot
	// edit (and so rewrite) a role that holds more than they do.
	before := grantlimit.Role{ID: "gm", Perms: []string{authtest.OrderCreate, authtest.ReportView}}
	wantRefused(t, "edit of a role holding more than the actor", ev.CanWriteRole(manager, &before, grantlimit.Role{ID: "gm", Perms: []string{authtest.OrderCreate}}))
	// Wildcards and unknown permissions.
	wantRefused(t, "wildcard role by a manager", ev.CanWriteRole(manager, nil, grantlimit.Role{Perms: []string{auth.Wildcard}}))
	wantRefused(t, "unknown permission", ev.CanWriteRole(owner, nil, grantlimit.Role{Perms: []string{"made.up"}}))
}

func TestAssignmentRulesG1toG4(t *testing.T) {
	ev := grantlimit.Evaluator{Catalogue: authtest.Catalogue()}
	owner := grantlimit.Holdings{MemberID: "o1", Owner: true}
	otherOwner := grantlimit.Holdings{MemberID: "o2", Owner: true}
	waiter := holds("w1", org(authtest.OrderCreate))
	manager := holds("m1", map[string]auth.OutletScope{
		authtest.MemberRoleAssign: auth.OnlyOutlets("x"),
		authtest.OrderCreate:      auth.OnlyOutlets("x"),
		authtest.OrderRead:        auth.OnlyOutlets("x"),
	})
	cashier := grantlimit.Role{ID: "cashier", Perms: []string{authtest.OrderCreate, authtest.OrderRead}}

	wantAllowed(t, "assign within own scope and permissions", ev.CanAssign(manager, grantlimit.Assignment{Target: waiter, Role: cashier, Scope: auth.OnlyOutlets("x")}))
	wantRefused(t, "assign at an outlet outside own scope", ev.CanAssign(manager, grantlimit.Assignment{Target: waiter, Role: cashier, Scope: auth.OnlyOutlets("y")}))
	wantRefused(t, "assign organisation-wide with an outlet scope", ev.CanAssign(manager, grantlimit.Assignment{Target: waiter, Role: cashier, Scope: auth.AllOutlets()}))
	wantRefused(t, "assign a role with a permission not held", ev.CanAssign(manager, grantlimit.Assignment{Target: waiter, Role: grantlimit.Role{Perms: []string{authtest.ReportView}}, Scope: auth.OnlyOutlets("x")}))
	wantRefused(t, "assign an administration role", ev.CanAssign(manager, grantlimit.Assignment{Target: waiter, Role: grantlimit.Role{Perms: []string{authtest.MemberRoleAssign}}, Scope: auth.OnlyOutlets("x")}))
	wantRefused(t, "empty scope", ev.CanAssign(manager, grantlimit.Assignment{Target: waiter, Role: cashier}))
	// G4: nobody changes their own assignments, the owner included.
	wantRefused(t, "manager self-assignment", ev.CanAssign(manager, grantlimit.Assignment{Target: manager, Role: cashier, Scope: auth.OnlyOutlets("x")}))
	wantRefused(t, "owner self-assignment", ev.CanAssign(owner, grantlimit.Assignment{Target: owner, Role: cashier, Scope: auth.AllOutlets()}))
	// G3: the owner role.
	ownerRole := grantlimit.Assignment{Target: waiter, OwnerRole: true, Scope: auth.AllOutlets()}
	wantRefused(t, "manager makes an owner", ev.CanAssign(manager, ownerRole))
	wantAllowed(t, "owner makes an owner", ev.CanAssign(owner, ownerRole))
	rm := grantlimit.Assignment{Target: otherOwner, OwnerRole: true, Remove: true, OwnerCount: 2}
	wantRefused(t, "manager removes an owner", ev.CanAssign(manager, rm))
	wantAllowed(t, "owner removes another owner", ev.CanAssign(owner, rm))
	rm.OwnerCount = 1
	wantRefused(t, "last owner cannot be removed", ev.CanAssign(owner, rm))
}

func TestAdministerRulesG5(t *testing.T) {
	ev := grantlimit.Evaluator{Catalogue: authtest.Catalogue()}
	owner := grantlimit.Holdings{MemberID: "o1", Owner: true}
	manager := holds("m1", org(authtest.OrderCreate, authtest.OrderRead, authtest.BillCancel))
	cashier := holds("c1", org(authtest.OrderCreate))
	otherManager := holds("m2", org(authtest.OrderCreate, authtest.OrderRead, authtest.BillCancel))
	superManager := holds("m3", org(authtest.OrderCreate, authtest.OrderRead, authtest.BillCancel, authtest.ReportView))
	admin := holds("a1", org(authtest.OrderCreate, authtest.MemberAdd))
	all := auth.AllOutlets()

	wantAllowed(t, "manager administers a cashier", ev.CanAdminister(manager, cashier, all))
	wantAllowed(t, "manager administers an equal manager", ev.CanAdminister(manager, otherManager, all))
	wantRefused(t, "target holds more", ev.CanAdminister(manager, superManager, all))
	wantRefused(t, "target holds an owner_grant permission", ev.CanAdminister(holds("m9", org(authtest.OrderCreate, authtest.MemberAdd)), admin, all))
	wantRefused(t, "target is an owner", ev.CanAdminister(manager, owner, all))
	wantAllowed(t, "owner administers anyone", ev.CanAdminister(owner, admin, all))
	wantRefused(t, "self", ev.CanAdminister(manager, manager, all))
	wantRefused(t, "owner on self", ev.CanAdminister(owner, owner, all))
	wantRefused(t, "empty scope", ev.CanAdminister(owner, cashier, auth.OutletScope{}))
	// Only the target's holdings at the scope count.
	elsewhere := holds("e1", map[string]auth.OutletScope{authtest.ReportView: auth.OnlyOutlets("y"), authtest.OrderCreate: auth.OnlyOutlets("x")})
	scopedMgr := holds("m5", map[string]auth.OutletScope{authtest.OrderCreate: auth.OnlyOutlets("x")})
	wantAllowed(t, "target's extra permission is at another outlet", ev.CanAdminister(scopedMgr, elsewhere, auth.OnlyOutlets("x")))
	wantRefused(t, "same target judged at the outlet where they hold more", ev.CanAdminister(scopedMgr, elsewhere, auth.OnlyOutlets("x", "y")))
}

func TestDeviceRevokeRulesG6(t *testing.T) {
	ev := grantlimit.Evaluator{Catalogue: authtest.Catalogue()}
	owner := grantlimit.Holdings{MemberID: "o1", Owner: true}
	mgr := holds("m1", map[string]auth.OutletScope{authtest.DeviceRevoke: auth.OnlyOutlets("x")})
	wantAllowed(t, "outlet device in scope", ev.CanRevokeDevice(mgr, grantlimit.Device{Outlet: "x"}))
	wantRefused(t, "outlet device out of scope", ev.CanRevokeDevice(mgr, grantlimit.Device{Outlet: "y"}))
	wantRefused(t, "device with no outlet", ev.CanRevokeDevice(mgr, grantlimit.Device{}))
	wantRefused(t, "personal device of someone else", ev.CanRevokeDevice(mgr, grantlimit.Device{Personal: true, AccountMemberID: "m2"}))
	wantAllowed(t, "personal device by its holder", ev.CanRevokeDevice(holds("m2", nil), grantlimit.Device{Personal: true, AccountMemberID: "m2"}))
	wantAllowed(t, "personal device by an owner", ev.CanRevokeDevice(owner, grantlimit.Device{Personal: true, AccountMemberID: "m2"}))
	wantRefused(t, "no device.revoke", ev.CanRevokeDevice(holds("m3", org(authtest.OrderRead)), grantlimit.Device{Outlet: "x"}))
}
