# Multi-Tenancy — Engineering Contract

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-09-28

## Exported surface — `sdk/go/transport`

```go
type TenantService interface {
	CreateTenant(ctx, req *CreateTenantRequest) (*CreateTenantResponse, error)
	GetTenant(ctx, tenantID string) (*GetTenantResponse, error)
	ListTenants(ctx) (*ListTenantsResponse, error)
	DeleteTenant(ctx, tenantID string) error
	TenantBarrierInit(ctx, req *TenantBarrierInitRequest) error
	TenantBarrierUnseal(ctx, req *TenantBarrierUnsealRequest) error
	TenantBarrierStatus(ctx, tenantID string) (*TenantBarrierStatusResponse, error)
	UpdateTenantEntitlements(ctx, req *UpdateTenantEntitlementsRequest) (*UpdateTenantEntitlementsResponse, error)
	UpdateTenantQuotas(ctx, req *UpdateTenantQuotasRequest) (*UpdateTenantQuotasResponse, error)
}
```

Server side: `pkg/api/rest/handlers_tenant.go` plus `middleware_tenant.go` and
`middleware_tenant_dao.go`; `pkg/api/grpc/interceptor_tenant.go`;
`pkg/api/tenantgate`. Composition: `sdk/go/tenant_compose.go`,
`sdk/go/tenant_factories.go`. Per-tenant state:
`pkg/seal/platform_store_tenant.go`, `pkg/xkms/backend_tenant.go`.

## Isolation modes

`prefix` (default), `barrier`, `volume`, `raft` — set at creation, and gated by
the tenant's entitlements.

## Entitlements and quotas

**Entitlements** — what a tenant is permitted to be:

| Field | CLI flag |
|---|---|
| permitted isolation modes | `--isolation-modes prefix,barrier,volume,raft` |
| dedicated Raft databases | `--allow-raft` |
| dedicated-volume storage | `--allow-volume` |
| system-managed auto-unseal | `--allow-system-managed` |

**Quotas** — how much a tenant may consume (all `int64`; `0` = system default):

`--max-databases`, `--max-keys`, `--max-collections`, `--max-storage-bytes`,
`--max-users`, `--max-roles`, `--max-certificates`.

Keep them separate. A tenant that is entitled to `raft` but quota-limited to one
database is a coherent configuration; collapsing the two makes every plan change
a code change.

## Invariants

- **TenantService is required; there is no barrier-registry-only fallback
  (BREAKING).** `pkg/xkms.XKMSService`'s tenant servicer methods
  (`CreateTenant`, `GetTenant`, `ListTenants`, `DeleteTenant`,
  `TenantBarrierInit`, `TenantBarrierUnseal`, `TenantBarrierStatus`,
  `UpdateTenantEntitlements`, `UpdateTenantQuotas`) all require
  `SetTenantService` to have been called; a nil `TenantService` returns
  `ErrTenantServiceNotConfigured` rather than falling back to direct
  `*seal.BarrierRegistry` operations. `pkg/api/rest.NewTenantHandlers`
  enforces the same rule at construction: it now returns `(*TenantHandlers,
  error)` and rejects a `BarrierRegistry` configured without a `TenantService`
  composed on the `XKMSService`, so a misconfigured deployment fails server
  startup instead of exposing routes that 500 under load.
- **A tenant ID named in a request is bound to the caller in
  `XKMSService`, never in a transport** (go-xkms#1112). The RBAC gate binds
  the caller's own tenant as its target (`pkg/auth/authorize.go:61`), so it
  cannot tell whether a *requested* tenant is the caller's.
  `bindTenantTarget` (`pkg/xkms/tenant_binding.go:67`) admits a cross-tenant
  identity (`auth.IsCrossTenant`) for any target and a tenant-scoped one only
  for its own tenant; it guards `GetTenant`, `DeleteTenant`,
  `TenantBarrierInit`, `TenantBarrierUnseal`, `TenantBarrierStatus`
  (`pkg/xkms/servicer_tenant.go:94,144,191,246,283`),
  `BarrierEnableEncryption` (`pkg/xkms/servicer_barrier.go:384`; an empty
  `TenantID` is the system barrier and is refused to a tenant) and the SPIFFE
  tenant of `SignCSR` (`pkg/xkms/servicer_ca.go:178`). `ListTenants` filters
  to the caller's tenant (`pkg/xkms/servicer_tenant.go:127`). The gRPC
  tenant RPCs no longer carry a barrier-registry fallback that bypassed the
  servicer; with no `XKMSService` they answer `Unavailable`.
- **Plan changes are platform-only** (go-xkms#1113).
  `requirePlatformScope` (`pkg/xkms/tenant_binding.go:88`) refuses every
  tenant-scoped caller, including one naming its own tenant
  (`pkg/xkms/servicer_tenant.go:313,340`); the transports gate on
  `tenants:set_entitlements` / `tenants:set_quotas`
  (`pkg/auth/permissions.go:147-148`), never `tenants:update`.
- **Isolation mode is fixed at creation.** There is no in-place upgrade from
  `prefix` to `barrier`; that is a data migration.
- **A requested mode outside the tenant's entitlements is refused**, not
  silently downgraded.
- **`GroupUsers` routes are not tenant-scoped.** The route table says so
  explicitly: *"the user plane is identity-scoped, not tenant-scoped."* Do not
  add tenant middleware to it.
- **A tenant's data is unavailable while that tenant's barrier is sealed**,
  independently of the system barrier.
- **The `system` tenant is the control plane.** The SO certificate carries it so
  the control plane functions before any tenant barrier unseals.
- **Quota `0` means system default**, not "zero allowed". Every quota field
  shares this convention.
- **Deleting a tenant is not a way to release a barrier's key material** — treat
  it as a destructive operation with its own review.
- **Concurrency.** Tenant scoping is per-request context; barrier operations for
  different tenants are independent.
- **Import/export is tenant-scoped at the wrapper, not per transport.**
  `xkms.TenantScopedBackend` implements `xkms.ImportExporter` and stamps the
  tenant on every attribute set, so BYOK import, wrapped export and raw
  material export address the tenant's namespace the same way `GetKey` does.
  Callers must never reach the capability through `KeyProvider()`, which
  returns the base provider and discards the scoping — resolve it with the
  service layer's `importExportFor` instead. The tenant survives the read
  path because both key providers persist it in the key metadata record
  (PKCS#8 since its schema v1, symmetric since its schema v3).
- **A transport must not withhold the tenant from an import.** MCP did, on the
  reasoning that an imported key persisted no record to read it back from
  (#162). That reason lapsed with #163 and the withholding then only sent a
  tenant's import to the untenanted namespace, where the importing tenant's own
  reads could not find it (#222). Every transport now passes the authenticated
  caller's tenant to `XKMSService.ImportKey`.
- **A copy carries the export's own import token.** `ExportKey` wraps under a
  wrapping key the exporting backend mints for that export and names it by the
  token it returns, so the token identifies the material, not the destination.
  `CopyKey` must pass it through untouched; asking the destination for fresh
  parameters and overwriting it points `ImportKey` at the wrong wrapping key
  and the unwrap fails (#222). The destination attributes take the destination
  backend's store type and the source's digest and partition, and the tenant is
  stamped by the scoped backend's `ImportKey`, never assembled by the caller.

## Error semantics

| Condition | Meaning |
|---|---|
| tenant not found | wrong ID, or deleted |
| isolation mode not entitled | the operator has not granted it |
| quota exceeded | the tenant is at its limit for that resource |
| tenant barrier sealed | not an error — a state, like the system barrier |
| cross-tenant access | resolved as not-found, not as forbidden: `*xkms.TenantBindingError` (`pkg/xkms/tenant_binding.go:34`) unwraps to and renders as `qrdbsdk.ErrTenantMissing`, the error a genuine miss returns |
| tenant-scoped plan change | the same not-found refusal, even for the caller's own tenant |

**Fail closed:** an unentitled mode, an exceeded quota, or a sealed tenant
barrier all refuse. Cross-tenant access surfaces as not-found rather than
permission-denied, so tenant existence is not enumerable.

## Configuration

Per tenant, at creation: `--id`, `--name`, `--isolation`,
`--barrier-auto-unseal` (entitlement-gated). Afterwards, by the operator:
`update-entitlements` and `update-quotas`.

Tenant barrier strategies are the same set as the system barrier —
`passphrase` (default), `none`, `shamir`, `tpm2`, `pkcs11`, `awskms`, `gcpkms`,
`azurekv`, `vault` — see
[`../sealing-and-barrier/engineering.md`](../sealing-and-barrier/engineering.md).

## Persistence

Tenant records, entitlements and quotas persist through go-qrdb. Per-tenant
barrier state is `pkg/seal/platform_store_tenant.go`; tenant-scoped key
resolution is `pkg/xkms/backend_tenant.go`.

## Test strategy

- **Middleware** — `pkg/api/rest/middleware_tenant_test.go`,
  `middleware_tenant_dao_test.go`; `pkg/api/grpc/interceptor_tenant_test.go`,
  `interceptor_tenant_stream_test.go`; `pkg/api/{grpc,unix,mcp}/tenant*_test.go`.
- **Tenant binding** — `pkg/xkms/tenant_binding_test.go` (service layer,
  against go-qrdb's real TenantService over an in-memory barrier: A → B
  refused as not-found for every tenant operation, refusal equals a genuine
  miss, A → A allowed except plan changes, system identity reaches every
  tenant, `ListTenants` filtered, enable-encryption and CSR targets bound).
  Per-transport not-found mapping:
  `pkg/api/rest/handlers_tenant_test.go`,
  `pkg/api/grpc/service_tenant_isolation_test.go`
  (`TestTenantRPCs_CrossTenantBinding`),
  `pkg/api/mcp/handlers_tenant_admin_test.go`.
- **Handlers** — `pkg/api/rest/handlers_tenant_test.go`.
- **Scoped operations** — `pkg/api/rest/handlers_keyops_tenant_test.go`,
  `pkg/api/mcp/handlers_keyops_tenant_test.go`,
  `pkg/api/transport/{grpc,unix}/*_tenant_test.go`.
- **Isolation** — `pkg/seal/tenant_volume_isolation_test.go`,
  `tenant_metadata_store_test.go`, `pkg/server/tenant_node_barrier_test.go`.
- **Backend scoping** — `pkg/xkms/backend_tenant_test.go`;
  tenant-scoped import/export —
  `pkg/xkms/servicer_key_tenant_import_test.go`,
  `pkg/xkms/servicer_key_tenant_copy_test.go`,
  `pkg/keyprovider/symmetric/metadata_test.go`.
- **Tenant-scoped BYOK over MCP** —
  `pkg/api/mcp/handlers_keyops_tenant_import_test.go` runs the real ceremony
  against the software backend and asserts which namespace the key lands in,
  which a fake that ignores the import token could not show.

The stream interceptor test matters: tenant scoping on a streaming RPC is easy
to get right for the first message and wrong for the rest.

## Observability

Tenant ID is part of the request context and appears alongside the correlation
ID. `AuditFilter.Tenant` filters the audit log by tenant
([`../audit-log/`](../audit-log/engineering.md)). Per-tenant barrier state is
worth surfacing: a tenant reporting an outage while its barrier is sealed is a
different incident from a system-wide one.
