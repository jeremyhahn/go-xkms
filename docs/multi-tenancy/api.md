# Multi-Tenancy — API

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-10-04

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Tenant routes are `RouteAuthPermission` under `/api/v1/tenants`, registered on
the `hasTenants` predicate. Each demands the permission gRPC enforces for the
same RPC (the **Permission** column): tenant metadata is `tenants:*`. An authenticated session alone reaches none
of them. Admin and Owner hold every one of them by default, except
`tenants:set_quotas`, which no qrdb built-in role grants (see the plan-change
note below).

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`TenantService.`) | Permission |
|---|---|---|---|---|---|---|
| Create tenant | `POST /api/v1/tenants/` | `CreateTenant` | same as REST | `xkms.createTenant` | `CreateTenant` | `tenants:create` |
| List tenants | `GET /api/v1/tenants/` | `ListTenants` | same as REST | `xkms.listTenants` | `ListTenants` | `tenants:list` |
| Get tenant | `GET /api/v1/tenants/{tenantID}` | `GetTenant` | same as REST | `xkms.getTenant` | `GetTenant` | `tenants:read` |
| Delete tenant | `DELETE /api/v1/tenants/{tenantID}` | `DeleteTenant` | same as REST | `xkms.deleteTenant` | `DeleteTenant` | `tenants:delete` |
| Update entitlements | `PUT /api/v1/tenants/{tenantID}/entitlements` | `UpdateTenantEntitlements` | same as REST | `xkms.updateTenantEntitlements` | `UpdateTenantEntitlements` | `tenants:set_entitlements` |
| Update quotas | `PUT /api/v1/tenants/{tenantID}/quotas` | `UpdateTenantQuotas` | same as REST | `xkms.updateTenantQuotas` | `UpdateTenantQuotas` | `tenants:set_quotas` |

**MCP carries the full tenant administration surface** (go-xkms#773), with
the same permissions as gRPC and REST (`pkg/api/mcp/authz.go:232-240`).

**The tenant a request names is bound to the caller in `XKMSService`, once,
for every transport** (go-xkms#1112; `pkg/xkms/tenant_binding.go`). The RBAC
gate binds the caller's *own* tenant as its target
(`pkg/auth/authorize.go:61`), so the self-scoped `tenants:*`
grants a Tenant Admin holds pass for any tenant ID; the
service binding is what confines them. `GetTenant` and `DeleteTenant` refuse a tenant-scoped caller naming another
tenant with the answer a nonexistent tenant gets (see "Status and error
mapping"); `ListTenants` returns only the caller's own tenant
(`pkg/xkms/servicer_tenant.go:127`). No handler carries a check of its own.
`CreateTenant` is not bound: a new tenant cannot yet belong to anyone.

**Plan changes are platform-only** (go-xkms#1113). `UpdateTenantEntitlements`
and `UpdateTenantQuotas` require qrdb's dedicated `tenants:set_entitlements` /
`tenants:set_quotas` on every transport — never `tenants:update` — and the
service admits only a platform (system-tenant) identity
(`pkg/xkms/servicer_tenant.go:313,340`): a Tenant Admin is refused with the
not-found answer even for its own tenant. The service check is load-bearing,
not belt-and-braces: both permissions are self-scoped in qrdb and qrdb's
built-in Admin role grants `tenants:set_entitlements`. No built-in role
grants `tenants:set_quotas`, so changing quotas needs a custom role granting
it to a system-tenant identity.

## Tenancy is enforced by middleware, not by these routes

The more important half of this feature has no capability rows: **every
`/api/v1` route in `GroupAPIv1` runs behind tenant middleware**
(`pkg/api/rest/middleware_tenant.go`;
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

The mirror-image defect is a **write** that carries no tenant. MCP's
`import_key` passed none to the service, so a tenant's imported key landed in
the untenanted namespace and that tenant's own reads could not find it — not a
disclosure, but a key the owner cannot reach (#222, the #162/#163 family).
`import_key`, `get_import_parameters` and `copy_key` now take the tenant from
`tenantForRequest`, which supplies the authenticated caller's and **refuses a
request that names one of its own** with `ErrTenantIDNotAccepted`. Their params
structs carry a `tenant_id` field solely so that refusal is reachable: without
the field the decoder discarded a caller-supplied tenant silently.

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
`UpdateTenantEntitlementsRequest`/`Response`,
`UpdateTenantQuotasRequest`/`Response`.

Entitlements carry the permitted isolation modes and the three boolean grants
(`allow-raft`, `allow-volume`, `allow-system-managed`). Quotas are `int64`
fields where **`0` means the system default**, not zero — a client that treats
`0` as "no allowance" will misreport every default-configured tenant.

Tenant barrier status is the same `BarrierStatus` shape as the system barrier.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| success | 200 | `OK` | `result` |
| caller lacks the route's permission | 403 | `PermissionDenied` | JSON-RPC error with `wire.CodePermissionDenied` (`ErrCodeForbidden`) |
| tenant barrier sealed (from `status`) | 200 | `OK` | `result` |
| isolation mode not entitled | 403 | `PermissionDenied` | JSON-RPC internal error |
| quota exceeded | 429 | `ResourceExhausted` | JSON-RPC internal error |
| operation needs an unsealed tenant barrier | 409 | `FailedPrecondition` | JSON-RPC internal error |
| tenant not found — **including cross-tenant access** | 404 | `NotFound` | `JSONRPCCodeNotFound` |
| tenant-scoped caller changes a plan, even its own | 404 | `NotFound` | `JSONRPCCodeNotFound` |
| tenancy not configured | route absent (404) | `Unimplemented` | JSON-RPC internal error |

Cross-tenant access is deliberately **not distinguishable from not-found** on
any transport. A permission-denied answer would confirm that the tenant
exists, making tenant IDs enumerable. The service's refusal,
`*xkms.TenantBindingError` (`pkg/xkms/tenant_binding.go:34`), unwraps to and
renders exactly as `qrdbsdk.ErrTenantMissing` — the error go-qrdb's
TenantService returns for an unknown tenant — so status *and* body match a
genuine miss: REST `pkg/api/rest/errors.go:130`, gRPC
`pkg/api/grpc/service_tenant.go:86`, MCP
`pkg/api/mcp/errors_tenant.go:57`. Before go-xkms#1112 the REST and
MCP handler checks answered `seal.ErrTenantNotFound` ("qrdb/seal: tenant not
found") while a genuine miss answered "tenant: not found", and gRPC answered
a genuine miss with `Internal`; both differences were enumeration oracles
and are gone.

The permission gate does not reopen that oracle. It decides before any tenant
lookup, from the caller's grant alone, so a caller without the permission gets
the same `403` for every `{tenantID}`, and a caller with it still gets the
service's identical `404` for another tenant's ID and for one that does not
exist.

## Pagination

`ListTenants` (`GET /api/v1/tenants/`) pages through the same shared
`transport.PageRequestFromQuery` implementation every REST list endpoint
uses; see [`../key-management/api.md`](../key-management/api.md)
§"Pagination" for the `page` / `page_size` / `sort_field` / `sort_order`
query parameters and the **400** an invalid one gets. With no `page`
parameter every tenant is returned whole, which is the common case given
deployments' typically small tenant counts. Tenant-scoped list operations
elsewhere page normally too.

## Versioning and deprecation

`/api/v1/tenants/*`, gRPC package `xkmsv1`. Nothing deprecated.

Two contracts external tooling depends on: the `0`-means-default quota
convention, and cross-tenant access surfacing as not-found. Changing either
silently changes behaviour every caller already relies on.
