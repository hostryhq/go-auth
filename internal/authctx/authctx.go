// Package authctx holds the context keys of go-auth. It is internal so that
// only go-auth's own packages (the guard, and authtest for tests) can place a
// principal on a context; application code cannot forge one.
package authctx

import "context"

type key int

// Keys.
const (
	Principal key = iota
	Authorizer
	Audit
)

// Set stores v under k.
func Set(ctx context.Context, k key, v any) context.Context { return context.WithValue(ctx, k, v) }

// Get returns the value under k, or nil.
func Get(ctx context.Context, k key) any { return ctx.Value(k) }
