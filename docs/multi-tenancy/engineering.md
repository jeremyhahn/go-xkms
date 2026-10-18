# Multi-Tenancy — Engineering Contract

> **Status: NORMATIVE** · Feature: `multi-tenancy` · Repo: `go-xkms` · Last verified: 2026-10-12

## Exported surface — `sdk/go/transport`

```go
type TenantService interface {
	CreateTenant(ctx, req *CreateTenantRequest) (*CreateTenantResponse, error)
	GetTenant(ctx, tenantID string) (*GetTenantResponse, error)
	ListTenants(ctx) (*ListTenantsResponse, error)
	DeleteTenant(ctx, tenantID string) error
	UpdateTenantEntitlements(ctx, req *UpdateTenantEntitlementsRequest) (*UpdateTenantEntitlementsResponse, error)
	UpdateTenantQuotas(ctx, req *UpdateTenantQuotasRequest) (*UpdateTenantQuotasResponse, error)
}
```

Server side: `pkg/api/rest/handlers_tenant.go` plus `middleware_tenant.go`;
`pkg/api/grpc/interceptor_tenant.go`;
`pkg/api/tenantgate`. Composition: `sdk/go/tenant_compose.go`,
`sdk/go/tenant_factories.go`. Per-tenant state:
`pkg/seal/platform_store_tenant.go`, `pkg/xkms/backend_tenant.go`.

## The tenant gate — `pkg/api/tenantgate`

```go
func Access(identity *auth.Identity, registry *seal.BarrierRegistry) (*seal.TenantBarrier, error)
```

Every transport makes the same tenant-admission decision through this one
function (`pkg/api/tenantgate/tenantgate.go:110`), not a per-transport copy:

| Case | Result |
|---|---|
| cross-tenant identity (`auth.IsCrossTenant`: nil, empty tenant, or the system tenant; `pkg/auth/auth.go:113`) | pass through, no barrier |
| no barrier registry | pass through, no barrier |
| tenant not in the registry | `*ErrTenantNotFound` |
| tenant barrier sealed | `*ErrTenantSealed` |
| otherwise | the tenant's `*seal.TenantBarrier` |

Each transport maps the result onto its own wire shape and, on success,
injects the barrier with `auth.WithTenantBarrier`:

| Transport | Gate | Not found | Sealed |
|---|---|---|---|
| REST (and QUIC, which is HTTP/3 on the same listener) | `Server.TenantMiddleware` (`pkg/api/rest/middleware_tenant.go:37`) | 403 (`:51`) | 503 (`:55`) |
| gRPC | `TenantUnaryInterceptor` / `TenantStreamInterceptor` (`pkg/api/grpc/interceptor_tenant.go:87`, `:104`) | `PermissionDenied` (`:47`) | `Unavailable` (`:52`) |
| gRPC over the Unix socket | the same two interceptors, chained first (`pkg/api/unix/grpc_server.go:292-293`) | as gRPC | as gRPC |
| MCP | `Server.tenantAccess` (`pkg/api/mcp/tenant.go:39`), run before `authorizeMethod` (`pkg/api/mcp/module_support.go:124-128`) | `ErrCodeForbidden` -32003 | `ErrCodeServiceUnavailable` -32004 (`pkg/api/mcp/types.go:72`, `:78`) |

Any other error is an internal error on every transport. The package lives
in `pkg/api` rather than `pkg/auth` to avoid an import cycle: `pkg/auth`
would need `pkg/seal`, which imports `pkg/audit`, which imports `pkg/auth`
(`pkg/api/tenantgate/tenantgate.go:34-40`).

## Ownership scopes — `pkg/scope`

```go
type Scope string // Tenant ("tenant"), User ("user"), Service ("service")

func Parse(s string) (Scope, error)                  // *InvalidScopeError
func TenantName(tenantID string) string              // "" and the system tenant -> "system"
func IsSystem(tenantID string) bool
func Root(tenantID, feature string) (string, error)  // "{tenant}/{feature}/"
func Prefix(tenantID, feature string, sc Scope, owner string) (string, error)
func SharedPrefix(tenantID, feature string) (string, error)            // .../shared/
func PersonalPrefix(tenantID, feature, subject string) (string, error) // .../users/{subject}/
func SharedSuffix(feature string) (string, error)    // "/{feature}/shared/", for cross-tenant scans

type Principal struct{ TenantID, Subject string; Authenticated, ServiceAccess bool }
func PrincipalOf(id *auth.Identity) Principal         // nil -> unauthenticated
func PrincipalFromContext(ctx context.Context) Principal
type Target struct{ TenantID string; Scope Scope; Owner string }
func (p Principal) Authorize(t Target) error
```

Errors: `*InvalidScopeError`, `*InvalidSegmentError` (a tenant, feature or
owner that is not exactly one key segment), and the refusals
`*UnauthenticatedError` (no identity), `*CrossTenantError`, `*CrossUserError`,
`*ServiceScopeError`, which match `ErrRefused`. `Authorize` grants no tenant
an exception: a system-tenant principal naming another tenant gets
`*CrossTenantError` like any other. `ServiceAccess` is set by the feature after checking its own
service permission; `pkg/scope` carries no permission model.

The whole package is exported through `sdk/go` for hosts that store objects
in the same layout: `ObjectScope` (`ObjectScopeTenant`, `ObjectScopeUser`,
`ObjectScopeService`), `ParseObjectScope`, `ScopePrincipal`, `ScopeTarget`,
`ScopePrincipalOf`, `ScopePrincipalFromContext`, `ScopeSystemTenant`,
`ScopeTenantName`, `ScopeIsSystem`, the keyspace helpers `ScopeTenantRoot`,
`ScopeFeatureRoot`, `ScopePrefix`, `ScopeFeaturePrefix`, `ScopeOwnersRoot`,
`ScopeSharedPrefix`, `ScopePersonalPrefix`, `ScopeSharedSuffix`, and the errors
`ErrScopeRefused`, `ScopeCrossTenantError`,
`ScopeCrossUserError`, `ScopeServiceError`, `ScopeInvalidScopeError`,
`ScopeInvalidSegmentError` (`sdk/go/scope.go`).

Adopters: `pkg/staticpw` (store prefixes), `pkg/tpm2/policy` (registry keys and
scope names; the SDK's `TPMPolicyScopeName` is `scope.TenantName`),
`pkg/ssh/scope` (its `Scope` is this one) and `pkg/ssh/tenancy` (every SSH
request is bound with `Authorize`). Tests: `pkg/scope/scope_test.go`
and `sdk/go/scope_test.go`.

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
  `ownTenant` (`pkg/xkms/tenant_binding.go:86`), over `qrdbsdk.OwnTenant`,
  admits a caller only for its own tenant — the system tenant included
  (go-xkms#1406). It guards the SPIFFE tenant of `SignCSR`,
  `IssueCertificate` and the issuing tenant of `RevokeCertificate`
  (`pkg/xkms/servicer_ca.go:175,406,478`), the TPM policy and object-policy
  tenant, and `RotateScopeKeys`. A caller with no identity is the system
  tenant here (`pkg/auth/auth.go:133`): in-process SDK callers carry none.
- **The tenant registry is the system tenant's.** `admitTenantRecord`
  (`pkg/xkms/tenant_binding.go:101`) lets a system-tenant caller read and
  delete any tenant record and binds every other caller to its own; it guards
  `GetTenant` and `DeleteTenant` (`pkg/xkms/servicer_tenant.go:91,140`).
  `ListTenants` filters with it (`pkg/xkms/servicer_tenant.go:123`).
  Administering the record grants no reach into the tenant's objects.
- **Plan changes are system-only** (go-xkms#1113). A
  `qrdbsdk.IdentityIsSystemTenant` check refuses every tenant-scoped caller,
  including one naming its own tenant (`pkg/xkms/servicer_tenant.go:165,192`); the transports gate on
  `tenants:set_entitlements` / `tenants:set_quotas`
  (`pkg/auth/permissions.go:147-148`), never `tenants:update`.
- **The tenant gate grants no reach.** `tenantgate.Access` selects the tenant
  barrier a request runs under; a nil or system-tenant identity passes it
  with no tenant barrier and is still confined to the system tenant by the
  service binding and `pkg/scope`. `auth.IsCrossTenant` survives only for
  tenant IAM administration in `pkg/acme/admin`.
- **Every unix-socket caller carries an identity.** xkmsd's socket is the
  qrdb node's TLS listener and authenticates through the node chain like any
  network transport. The sign server's socket (`pkg/api/unix`) attaches
  `uid:<peer uid>`, the system tenant and `auth_method=unix-peer`
  (`unix.PeerAuthMethod`) to every peer its credential policy admits, ahead
  of the tenant and embedder interceptors (`pkg/api/unix/peercred.go`,
  `grpc_server.go`).
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

Per-tenant storage volumes come from go-qrdb's volume pools
(`Storage.VolumePools`). When the barrier is enabled, a datastore path is set
and no pool is configured, the embedded node gets one pool named
`default`, rooted at `<datastore-path>/tenant-volumes`
(`pkg/embeddednode/embedded_node.go:339`).

## Test strategy

- **Middleware** — `pkg/api/rest/middleware_tenant_test.go`;
  `pkg/api/grpc/interceptor_tenant_test.go`,
  `interceptor_tenant_stream_test.go`; `pkg/api/{grpc,unix,mcp}/tenant*_test.go`.
- **Tenant binding** — `pkg/xkms/tenant_binding_test.go` (service layer,
  against go-qrdb's real TenantService over an in-memory barrier: A → B
  refused as not-found for every tenant operation, refusal equals a genuine
  miss, A → A allowed except plan changes, a system or absent identity
  refused for every other tenant's target but owning the tenant registry,
  `ListTenants` filtered, enable-encryption and CSR targets bound).
- **No identity, no lift** — `pkg/scope/scope_test.go` (a nil principal and a
  system principal naming another tenant are both refused).
- **Unix-socket identity** — `pkg/api/unix/peer_identity_test.go` (an
  admitted peer carries `uid:<uid>` in the system tenant, a refused peer
  reaches no handler, SSH RPCs are served to the peer over the socket).
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
