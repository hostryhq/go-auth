# go-auth

Shared Go authentication and authorisation library for every Hostry service (ADR-0005 section 11, ADR-0003 A1.4, ADR-0013 V2/V5). Standard library plus `go-common` only. It verifies tokens and enforces permissions; it never issues user tokens, stores credentials or verifies PIN proofs (that is `identity`).

## Packages

| Package | What |
|---|---|
| `auth` (module root) | ES256-only token verification, key sets (`KeySet`, `CachedKeySet`, `StaticKeySet`, JWKS parser), claims, `Guard` HTTP middleware, `Policy` (x-permission, x-step-up, x-service-callers, x-vendor-audit), `Require` / `ScopeFor` / `OutletScope`, permission `Catalogue`, intent table, service tokens (`ServiceSigner`, `ServiceVerifier`, `ServiceTransport`), approval tokens, vendor access log hook (`VendorAuditSink`, `WithAuditedTx`, `VendorTenant`) |
| `authtest` | Test issuer: mints valid and forged tokens, principals, contexts, a sample catalogue, a service key registry, an in-memory audit sink. Tests and doubles only |
| `grantlimit` | Grant-limit evaluator, ADR-0005 A2.4 rules G1 to G6 |
| `scopelint`, `cmd/scopelint` | CI lint: every statement on an outlet-scoped table carries a bound `outlet_id` predicate (ADR-0003 A1.4 item 5) |
| `scopetest` | Generated test T14: one `Resource` per `x-outlet-scoped` resource |

## Use

```go
g := &auth.Guard{Catalogue: cat, Tenant: tenantVerifier, Services: svcVerifier, Approvals: ..., Audit: sink}
g.Handle(mux, "GET /v1/orders", auth.Policy{OperationID: "listOrders", Permission: "order.read"}, ordersHandler)
```

`Handle` panics at start-up for a route that declares no permission, an unknown permission, or an `/internal/v1` path not declared internal. In a handler or service:

```go
scope, err := auth.ScopeFor(ctx, "order.read")      // pass scope to every list/search/report/export
err = auth.Require(ctx, "bill.cancel", bill.OutletID) // outlet from the stored row, never the request
```

Vendor-authority requests (vendor token on a vendor route, support token on a tenant route) must do their database work through `auth.WithAuditedTx`, which writes the service's `vendor_access_log` row in the same transaction; a success response without that row is replaced by a 500.

## Conventions fixed here (to be recorded in api-specs)

- User, vendor and support tokens travel in `Authorization: Bearer`; the 60-second service token in `Hostry-Service-Token` (so a call made for a user carries both); an approval token in `Hostry-Approval`.
- Refused tokens always answer 401 `auth.invalid_token`; the reason is logged, never returned.
- Denials: 403 `auth.permission_denied`, `approval_required` (A2.2), `auth.step_up_required`, `grant_not_permitted` (A2.4); an outlet outside the caller's scope is 404.

## Test and lint

```
go vet ./...
go test -race ./...
go run ./cmd/scopelint -tables tables.json ./repository ./service   # in a service repo
```

Local development against an unmerged `go-common`: use an uncommitted `go.work` (git-ignored) that lists `.` and `../go-common`. Private modules need `GOPRIVATE=github.com/hostryhq/*`.
