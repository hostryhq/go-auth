// Package scopetest is the generated test T14 of ADR-0003 Amendment A1.4: for
// every outlet-scoped resource, a member scoped to outlet X sees nothing of
// outlet Y in lists, searches and reads, and a member with an organisation-wide
// grant sees both. A service registers one Resource per x-outlet-scoped
// resource and calls RunT14 from its own test suite; the harness drives the
// service's real methods, so a list that forgets the scope fails here.
package scopetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/testkit"
)

// Fixed outlets of the harness, in tenant A.
const (
	OutletX = "018f0000-0000-7000-8000-0000000000a1"
	OutletY = "018f0000-0000-7000-8000-0000000000a2"
)

// Resource is one outlet-scoped resource. The functions are the service's own
// code path: they must call auth.ScopeFor / auth.Require with ctx, exactly as a
// handler would, and must not take the caller's scope from anywhere else.
type Resource struct {
	Name       string // for failure messages
	Permission string // the permission the list and read operations require
	// Seed stores one row in outlet x and one in outlet y of the tenant in ctx
	// and returns their ids. It runs with an organisation-wide principal.
	Seed func(ctx context.Context, outletX, outletY string) (idX, idY string, err error)
	// List returns the ids of the rows the caller may see (list, search, report
	// or export: whichever the resource offers).
	List func(ctx context.Context) ([]string, error)
	// ListFiltered is List with the request's outlet_id filter; optional.
	ListFiltered func(ctx context.Context, outletIDs []string) ([]string, error)
	// Get reads one row by id; a row outside the caller's scope must give a
	// not-found error.
	Get func(ctx context.Context, id string) error
}

func isNotFound(err error) bool {
	var e *apperr.Error
	return errors.As(err, &e) && e.Kind == apperr.NotFound
}

// Check runs the T14 cases for r and returns what failed.
func Check(ctx context.Context, cat *auth.Catalogue, r Resource) []string {
	clk := testkit.NewClock()
	iss := authtest.NewTenantIssuer(clk)
	as := func(outlets ...string) context.Context {
		return iss.ContextFor(ctx, cat, authtest.Spec{Tenant: testkit.TenantA, Grants: authtest.Grants(outlets, r.Permission)})
	}
	var bad []string
	fail := func(format string, a ...any) { bad = append(bad, r.Name+": "+fmt.Sprintf(format, a...)) }

	idX, idY, err := r.Seed(as(), OutletX, OutletY)
	if err != nil {
		return []string{r.Name + ": seed failed: " + err.Error()}
	}
	for _, c := range []struct {
		name         string
		ctx          context.Context
		mine, theirs string
	}{
		{"scoped to X", as(OutletX), idX, idY},
		{"scoped to Y", as(OutletY), idY, idX},
	} {
		got, err := r.List(c.ctx)
		if err != nil {
			fail("%s: list failed: %v", c.name, err)
		} else {
			if !slices.Contains(got, c.mine) {
				fail("%s: list misses the caller's own outlet row", c.name)
			}
			if slices.Contains(got, c.theirs) {
				fail("%s: list leaks a row of another outlet", c.name)
			}
		}
		if err := r.Get(c.ctx, c.theirs); !isNotFound(err) {
			fail("%s: read of another outlet's row must be 404, got %v", c.name, err)
		}
		if err := r.Get(c.ctx, c.mine); err != nil {
			fail("%s: read of own outlet row failed: %v", c.name, err)
		}
		if r.ListFiltered != nil {
			if got, err := r.ListFiltered(c.ctx, []string{outletOf(c.theirs, idX, idY)}); err == nil && len(got) > 0 {
				fail("%s: outlet_id filter widened the scope", c.name)
			}
		}
	}
	got, err := r.List(as())
	if err != nil || !slices.Contains(got, idX) || !slices.Contains(got, idY) {
		fail("organisation-wide grant must see both outlets (got %v, err %v)", got, err)
	}
	if r.ListFiltered != nil {
		if got, err := r.ListFiltered(as(), []string{OutletY}); err != nil || slices.Contains(got, idX) || !slices.Contains(got, idY) {
			fail("organisation-wide grant with an outlet_id filter must return only that outlet (got %v, err %v)", got, err)
		}
	}
	// No grant of the permission at all: refused, nothing returned.
	none := iss.ContextFor(ctx, cat, authtest.Spec{Tenant: testkit.TenantA, Grants: authtest.Grants([]string{OutletX}, r.Permission+"_other")})
	if got, err := r.List(none); err == nil || len(got) > 0 {
		fail("a caller without the permission must be refused (got %v, err %v)", got, err)
	}
	return bad
}

func outletOf(id, idX, idY string) string {
	if id == idX {
		return OutletX
	}
	return OutletY
}

// RunT14 runs Check for each resource as a subtest.
func RunT14(t *testing.T, cat *auth.Catalogue, resources ...Resource) {
	t.Helper()
	for _, r := range resources {
		t.Run(r.Name, func(t *testing.T) {
			for _, msg := range Check(context.Background(), cat, r) {
				t.Error(msg)
			}
		})
	}
}
