# Multi-Tenancy — Engineering Contract

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-08-19

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

## Error semantics

| Condition | Meaning |
|---|---|
| tenant not found | wrong ID, or deleted |
| isolation mode not entitled | the operator has not granted it |
| quota exceeded | the tenant is at its limit for that resource |
| tenant barrier sealed | not an error — a state, like the system barrier |
| cross-tenant access | resolved as not-found, not as forbidden |

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
- **Handlers** — `pkg/api/rest/handlers_tenant_test.go`,
  `handlers_tenant_helpers_test.go`.
- **Scoped operations** — `pkg/api/rest/handlers_keyops_tenant_test.go`,
  `pkg/api/mcp/handlers_keyops_tenant_test.go`,
  `pkg/api/transport/{grpc,unix}/*_tenant_test.go`.
- **Isolation** — `pkg/seal/tenant_volume_isolation_test.go`,
  `tenant_metadata_store_test.go`, `pkg/server/tenant_node_barrier_test.go`.
- **Backend scoping** — `pkg/xkms/backend_tenant_test.go`.

The stream interceptor test matters: tenant scoping on a streaming RPC is easy
to get right for the first message and wrong for the rest.

## Observability

Tenant ID is part of the request context and appears alongside the correlation
ID. `AuditFilter.Tenant` filters the audit log by tenant
([`../audit-log/`](../audit-log/engineering.md)). Per-tenant barrier state is
worth surfacing: a tenant reporting an outage while its barrier is sealed is a
different incident from a system-wide one.
