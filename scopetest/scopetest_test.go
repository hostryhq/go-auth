package scopetest_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-auth/scopetest"
	"github.com/hostryhq/go-common/apperr"
)

// repo is an in-memory outlet-scoped store whose service methods behave as the
// ADR requires: they take the caller's scope from go-auth.
type repo struct {
	mu   sync.Mutex
	rows map[string]string // id -> outlet
	n    int
	// leak makes List ignore the caller's scope, the bug T14 exists to catch.
	leak bool
	// trustFilter makes ListFiltered use the request's outlet filter as the
	// scope instead of intersecting it.
	trustFilter bool
}

func (r *repo) Seed(_ context.Context, x, y string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = map[string]string{"row-x": x, "row-y": y}
	return "row-x", "row-y", nil
}

func (r *repo) list(scope auth.OutletScope) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for id, o := range r.rows {
		if r.leak || scope.Contains(o) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func (r *repo) List(ctx context.Context) ([]string, error) {
	scope, err := auth.ScopeFor(ctx, "order.read")
	if err != nil {
		return nil, err
	}
	return r.list(scope), nil
}

func (r *repo) ListFiltered(ctx context.Context, filter []string) ([]string, error) {
	scope, err := auth.ScopeFor(ctx, "order.read")
	if err != nil {
		return nil, err
	}
	if r.trustFilter {
		return r.list(auth.OnlyOutlets(filter...)), nil
	}
	return r.list(scope.Intersect(filter)), nil
}

func (r *repo) Get(ctx context.Context, id string) error {
	r.mu.Lock()
	o, ok := r.rows[id]
	r.mu.Unlock()
	if !ok {
		return apperr.New(apperr.NotFound, "resource.not_found", "")
	}
	return auth.Require(ctx, "order.read", o)
}

func resource(r *repo) scopetest.Resource {
	return scopetest.Resource{Name: "orders", Permission: "order.read", Seed: r.Seed, List: r.List, ListFiltered: r.ListFiltered, Get: r.Get}
}

func TestT14PassesForAScopedRepository(t *testing.T) {
	scopetest.RunT14(t, authtest.Catalogue(), resource(&repo{}))
}

// The harness must fail a repository that forgets the scope, or the
// generated test proves nothing.
func TestT14CatchesLeaks(t *testing.T) {
	cat := authtest.Catalogue()
	if bad := scopetest.Check(context.Background(), cat, resource(&repo{leak: true})); len(bad) == 0 {
		t.Fatal("a list that ignores the caller's scope passed T14")
	}
	if bad := scopetest.Check(context.Background(), cat, resource(&repo{trustFilter: true})); len(bad) == 0 {
		t.Fatal("a list that trusts the request's outlet filter passed T14")
	}
	noGetScope := resource(&repo{})
	noGetScope.Get = func(context.Context, string) error { return nil } // never 404s
	if bad := scopetest.Check(context.Background(), cat, noGetScope); len(bad) == 0 {
		t.Fatal("a read that returns another outlet's row passed T14")
	}
}
