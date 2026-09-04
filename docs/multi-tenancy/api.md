# Multi-Tenancy — API

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-09-03

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Tenant routes are `RouteAuthSession` under `/api/v1/tenants`, registered on the
`hasTenants` predicate.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`TenantService.`) |
|---|---|---|---|---|---|
| Create tenant | `POST /api/v1/tenants/` | `CreateTenant` | same as REST | **MISSING — docs/13** | `CreateTenant` |
| List tenants | `GET /api/v1/tenants/` | `ListTenants` | same as REST | **MISSING — docs/13** | `ListTenants` |
| Get tenant | `GET /api/v1/tenants/{tenantID}` | `GetTenant` | same as REST | **MISSING — docs/13** | `GetTenant` |
| Delete tenant | `DELETE /api/v1/tenants/{tenantID}` | `DeleteTenant` | same as REST | **MISSING — docs/13** | `DeleteTenant` |
| Tenant barrier status | `GET /api/v1/tenants/{tenantID}/barrier/status` | `TenantBarrierStatus` | same as REST | **MISSING — docs/13** | `TenantBarrierStatus` |
| Tenant barrier init | `POST /api/v1/tenants/{tenantID}/barrier/init` | `TenantBarrierInit` | same as REST | **MISSING — docs/13** | `TenantBarrierInit` |
| Tenant barrier unseal | `POST /api/v1/tenants/{tenantID}/barrier/unseal` | `TenantBarrierUnseal` | same as REST | **MISSING — docs/13** | `TenantBarrierUnseal` |
| Update entitlements | `PUT /api/v1/tenants/{tenantID}/entitlements` | `UpdateTenantEntitlements` | same as REST | **MISSING — docs/13** | `UpdateTenantEntitlements` |
| Update quotas | `PUT /api/v1/tenants/{tenantID}/quotas` | `UpdateTenantQuotas` | same as REST | **MISSING — docs/13** | `UpdateTenantQuotas` |

**MCP carries none of the tenant surface.** Nine gaps, recorded rather than
omitted. Tenant administration is an operator activity and an MCP tool server is
not an operator console, so the absence is arguable — but it is nine tier-level
capabilities present on four transports and absent on one, which is tracked debt.

## Tenancy is enforced by middleware, not by these routes

The more important half of this feature has no capability rows: **every
`/api/v1` route in `GroupAPIv1` runs behind tenant middleware**
(`pkg/api/rest/middleware_tenant.go`, `middleware_tenant_dao.go`;
`pkg/api/grpc/interceptor_tenant.go`; `pkg/api/tenantgate`). The gate admits or
refuses the request; it does not narrow the key namespace.

Two groups deliberately sit outside it:

- **`GroupUsers`** — the route table states the reason: *"the user plane is
  identity-scoped, not tenant-scoped."*
- **`GroupRoot`** — health, discovery and trust bootstrap, which precede any
  identity at all.

The **`system` tenant** is the control-plane exception. The SO/bootstrap
certificate is always scoped to it so the control plane functions before any
tenant barrier unseals ([`../init-ceremony/api.md`](../init-ceremony/api.md)),
and when a SPIFFE trust domain is configured the SAN is
`spiffe://<td>/tenant/system/user/<CN>`.

## What actually narrows the key namespace

**A tenant-scoped backend does, and a handler that resolves a key without one is
unscoped.** `xkms.TenantScopedBackend` is what makes a key ID resolve only
inside its tenant. A handler reaches it through
`XKMSService.LookupTenantBackend` (by backend name) or
`xkms.ScopeBackendToTenant` (from a backend it already holds), with the tenant
taken from the authenticated identity and never from request params.

This matters because a key ID on these transports is a **common name, which is
unique only within a tenant**. Resolved against an unscoped backend it matches
whichever tenant's key is listed first. MCP's `export_key` did exactly that and
handed one tenant another tenant's wrapped key material (#166); the same
first-match-on-CN scan was also duplicated inline in `seal` and `unseal`.

The same scan existed on **gRPC and REST** and was fixed in #221. All three
transports now reach the shared lookup through a per-transport
`lookupTenantBackend(ctx, name)` that supplies `callerTenantID(ctx)`; each
transport keeps its own one-line helper because each gets the identity from its
own context, but the scoping decision itself is made in exactly one place.

The two transports were **not** equally exposed, and the difference is worth
knowing before reading the fix:

- **gRPC acted on the unscoped result.** `DeleteKey`, `RotateKey`, `ExportKey`,
  `CopyKey`, `EncryptAsym` and `GetTLSCertificate` resolved the CN against an
  unscoped backend and then operated on the attributes they got back. A caller
  holding no key of that name could delete, rotate or export another tenant's
  key. This was reproduced end to end before the fix.
- **REST only pre-checked with it.** `DecryptHandler` and `EncryptAsymHandler`
  used the resolved attributes for this transport's 404 and for the
  symmetric/asymmetric branch, then delegated the operation to the service layer
  with `TenantID` set — and the service re-resolves scoped. So the exposure was
  an existence oracle (whether *any* tenant holds that CN) and a possible wrong
  branch, not cross-tenant key use. Scoping the pre-check closes the oracle and
  removes the reliance on a second layer catching it.

The system tenant is not a scope: a system-scoped caller resolves against the
unscoped backend and sees every key, which is what the control plane needs.

Still outstanding: the FROST paths (`pkg/api/grpc/service_frost.go`, build tag
`frost`) carry the same inline CN scan. They cannot use this helper as written,
because `getFrostBackend()` resolves to the concrete key **provider** and so
unwraps any tenant scoping — the same structural problem as #163. Tracked
separately rather than guessed at here.

The system tenant is not a scope: a system-scoped caller resolves against the
unscoped backend and sees every key, which is what the control plane needs.

## Request and response schemas

`pkg/api/transport/types.go` and `types_tenant_test.go`'s subjects:
`CreateTenantRequest`/`Response`, `GetTenantResponse`, `ListTenantsResponse`,
`TenantBarrierInitRequest`, `TenantBarrierUnsealRequest`,
`TenantBarrierStatusResponse`, `UpdateTenantEntitlementsRequest`/`Response`,
`UpdateTenantQuotasRequest`/`Response`.

Entitlements carry the permitted isolation modes and the three boolean grants
(`allow-raft`, `allow-volume`, `allow-system-managed`). Quotas are `int64`
fields where **`0` means the system default**, not zero — a client that treats
`0` as "no allowance" will misreport every default-configured tenant.

Tenant barrier status is the same `BarrierStatus` shape as the system barrier.

## Status and error mapping

| Condition | REST | gRPC / Unix |
|---|---|---|
| success | 200 | `OK` |
| tenant barrier sealed (from `status`) | 200 | `OK` |
| isolation mode not entitled | 403 | `PermissionDenied` |
| quota exceeded | 429 | `ResourceExhausted` |
| operation needs an unsealed tenant barrier | 409 | `FailedPrecondition` |
| tenant not found — **including cross-tenant access** | 404 | `NotFound` |
| tenancy not configured | route absent (404) | `Unimplemented` |

Cross-tenant access is deliberately **404, not 403**. A permission-denied answer
would confirm that the tenant exists, making tenant IDs enumerable.

## Pagination

`ListTenants` is bounded by the deployment's tenant count and returned whole.
Tenant-scoped list operations elsewhere page normally.

## Versioning and deprecation

`/api/v1/tenants/*`, gRPC package `xkmsv1`. Nothing deprecated.

Two contracts external tooling depends on: the `0`-means-default quota
convention, and cross-tenant access surfacing as not-found. Changing either
silently changes behaviour every caller already relies on.
