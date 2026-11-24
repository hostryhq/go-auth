package authtest

import (
	"context"
	"errors"
	"sync"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/tenancy"
)

// Sample permission names, a slice of what the real catalogue will hold.
const (
	OrderCreate      = "order.create"
	OrderRead        = "order.read"
	BillCancel       = "bill.cancel"
	ReportView       = "report.view"
	ReportEdit       = "report.edit"
	MemberAdd        = "member.add"
	RoleManage       = "role.manage"
	MemberRoleAssign = "member.role.assign"
	DeviceRevoke     = "device.revoke"
	SupportCodeNew   = "support.code.create"
	TaxSettingsEdit  = "tax.settings.edit"
	AdminOrgRead     = "admin.org.read"
	AdminDeviceRead  = "admin.device.read"
	AdminDeviceRevok = "admin.device.revoke"
)

// Catalogue returns a small valid catalogue that exercises every flag.
// Service tests use it with the test issuer; the real catalogue is generated
// from api-specs/common.
func Catalogue() *auth.Catalogue {
	c, err := auth.NewCatalogue(
		auth.Permission{Name: OrderCreate, Owner: "orders"},
		auth.Permission{Name: OrderRead, Owner: "orders", SupportViewable: true},
		auth.Permission{Name: BillCancel, Owner: "billing", Sensitive: true},
		auth.Permission{Name: ReportView, Owner: "reports", SupportViewable: true},
		auth.Permission{Name: ReportEdit, Owner: "reports", SupportActable: true},
		auth.Permission{Name: MemberAdd, Owner: "identity", StrongOnly: true, OwnerGrant: true},
		auth.Permission{Name: RoleManage, Owner: "identity", StrongOnly: true, OwnerGrant: true},
		auth.Permission{Name: MemberRoleAssign, Owner: "identity", StrongOnly: true, OwnerGrant: true},
		auth.Permission{Name: DeviceRevoke, Owner: "identity", StrongOnly: true, OwnerGrant: true},
		auth.Permission{Name: SupportCodeNew, Owner: "identity", StrongOnly: true, OwnerGrant: true},
		auth.Permission{Name: TaxSettingsEdit, Owner: "tenancy", StrongOnly: true, OwnerGrant: true, Sensitive: true},
		auth.Permission{Name: AdminOrgRead, Owner: "tenancy"},
		auth.Permission{Name: AdminDeviceRead, Owner: "identity"},
		auth.Permission{Name: AdminDeviceRevok, Owner: "identity"},
	)
	if err != nil {
		panic(err)
	}
	return c
}

// MemorySink is an in-memory vendor audit sink with failure injection.
type MemorySink struct {
	mu      sync.Mutex
	Entries []auth.VendorAccessEntry
	// FailInTx makes RecordInTx fail, to prove the request fails closed.
	FailInTx bool
	// FailRefused makes RecordRefused fail.
	FailRefused bool
}

// RecordInTx implements auth.VendorAuditSink. The row is not rolled back by
// the tests' fake transactions; use Count to see what was written.
func (m *MemorySink) RecordInTx(_ context.Context, _ tenancy.Execer, e auth.VendorAccessEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailInTx {
		return errors.New("injected audit failure")
	}
	m.Entries = append(m.Entries, e)
	return nil
}

// RecordRefused implements auth.VendorAuditSink.
func (m *MemorySink) RecordRefused(_ context.Context, e auth.VendorAccessEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailRefused {
		return errors.New("injected audit failure")
	}
	m.Entries = append(m.Entries, e)
	return nil
}

// Snapshot returns a copy of the recorded entries.
func (m *MemorySink) Snapshot() []auth.VendorAccessEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]auth.VendorAccessEntry(nil), m.Entries...)
}
