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

Policy modes beyond `Permission`: `Authenticated: true` (x-permission: authenticated; any valid token of the realm, no permission, no step-up); `Public: true, Internal: true, Callers: [...]` (public with x-service-callers; service token only, a user or vendor token on the request is refused; `auth.AnyCaller` = `"*"` accepts any registered service and must be the only entry); `PlatformAudit: true` on organisation-less vendor routes (set `Guard.PlatformAudit` to a `PlatformAuditSink`, do the work in `auth.WithPlatformAuditedTx`; the row has no tenant). Approval body hash: `auth.RequestBodyHash` / `auth.VerifyBodyHash` (SHA-256 over the exact body bytes as sent; body is restored).

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

## Phase 2 additions

- `GrantVerifier` (grant.go): the one verifier of vendor approval grants (ADR-0014 A2.6). ES256 under the vendor key set by `kid`; checks iss, realm, aud, typ, kind, org, approver (equals the bearer vendor subject, differs from the requester), lifetime (at most 300 s), exp, then the executor SubjectHash recomputation and the single-use hook (`GrantUsed`; leave it nil to consume the jti in the action transaction). Refusals are 403 `grant.required|invalid|expired|subject_mismatch|used`.
- `Policy.WidenedBy` (`x-permission-widened-by`): a `support_actable` permission that opens a step-up route to a support token in act mode, with the admin service token; step-up is not asked of it.
- `strong_session_required` (403): a `strong_only` permission asked in a pin or device session. Services stop rewriting it.
