package auth_test

import (
	"errors"
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
)

// IST-18: a strong_only action has no intent. The table refuses to be built
// with one, so a hand-crafted operation naming it finds no entry.
func TestIntentTableHasNoStrongOnlyIntents(t *testing.T) {
	cat := authtest.Catalogue()
	for _, p := range cat.All() {
		if !p.StrongOnly {
			continue
		}
		if _, err := auth.NewIntentTable(cat, auth.Intent{Name: "do." + p.Name, Permission: p.Name}); err == nil {
			t.Errorf("intent for strong_only permission %s was accepted", p.Name)
		}
	}
	if _, err := auth.NewIntentTable(cat, auth.Intent{Name: "no.permission"}); err == nil {
		t.Error("intent without a permission accepted (CI gate)")
	}
	if _, err := auth.NewIntentTable(cat, auth.Intent{Name: "x", Permission: "made.up"}); err == nil {
		t.Error("intent with an unknown permission accepted")
	}
	if _, err := auth.NewIntentTable(cat, auth.Intent{Name: "a", Permission: authtest.OrderCreate}, auth.Intent{Name: "a", Permission: authtest.OrderRead}); err == nil {
		t.Error("duplicate intent accepted")
	}
}

func TestIntentStructuralCheck(t *testing.T) {
	cat := authtest.Catalogue()
	tab, err := auth.NewIntentTable(cat,
		auth.Intent{Name: "order.create", Permission: authtest.OrderCreate, DeviceKinds: []string{"pos", "waiter"}, SessionTypes: []auth.TokenType{auth.TypePin, auth.TypeUser}},
		auth.Intent{Name: "bill.cancel", Permission: authtest.BillCancel, DeviceKinds: []string{"pos"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tab.Check("order.create", "pos", auth.TypePin); err != nil {
		t.Fatal(err)
	}
	if _, err := tab.Check("member.add", "pos", auth.TypeUser); !errors.Is(err, auth.ErrUnknownIntent) {
		t.Fatalf("hand-crafted strong_only intent: %v", err)
	}
	if _, err := tab.Check("bill.cancel", "kds", auth.TypePin); !errors.Is(err, auth.ErrIntentNotAllowed) {
		t.Fatalf("a kds cannot cancel a bill: %v", err)
	}
	if _, err := tab.Check("order.create", "pos", auth.TypeDevice); !errors.Is(err, auth.ErrIntentNotAllowed) {
		t.Fatalf("session type not allowed: %v", err)
	}
}

// The catalogue lints that CI relies on (ADR-0005 A2.4 G2, A2.5).
func TestCatalogueLints(t *testing.T) {
	bad := map[string]auth.Permission{
		"strong_only without owner_grant": {Name: "a.b", StrongOnly: true},
		"support_actable and sensitive":   {Name: "a.b", SupportActable: true, Sensitive: true},
		"support_actable and strong_only": {Name: "a.b", SupportActable: true, StrongOnly: true, OwnerGrant: true},
		"support_actable and owner_grant": {Name: "a.b", SupportActable: true, OwnerGrant: true},
		"name with no dot":                {Name: "order"},
		"wildcard name":                   {Name: "*"},
		"partial wildcard":                {Name: "order.*"},
		"upper case":                      {Name: "Order.Create"},
	}
	for name, p := range bad {
		if _, err := auth.NewCatalogue(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := auth.NewCatalogue(auth.Permission{Name: "a.b"}, auth.Permission{Name: "a.b"}); err == nil {
		t.Error("duplicate accepted")
	}
	c, err := auth.LoadCatalogue([]byte(`[{"name":"bill.cancel","owner":"billing","sensitive":true},{"name":"report.view","support_viewable":true}]`))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := c.Get("bill.cancel"); !ok || !p.Sensitive {
		t.Fatal("load")
	}
}
