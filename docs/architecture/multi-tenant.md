# Multi-Tenant Architecture

Go-xkms supports isolated, multi-tenant deployments where each tenant has independent data encryption, storage partitioning, and barrier management. This document covers the TenantDAOFactory pattern, barrier routing, and context propagation. The daemon and embedded SDK node both use the shared `pkg/server.BuildTenantInfra` composer to wire per-tenant infrastructure.

> For the per-tenant **isolation modes** (prefix / barrier / volume / raft), **entitlements**, **system-managed auto-unseal**, and **hardware-backed** per-tenant sealing (TPM 2.0 / PKCS#11 / cloud KMS), see [Per-Tenant Barrier Isolation → Isolation modes & hardware-backed composition](../seal/tenant-barriers.md#isolation-modes--hardware-backed-composition). That lifecycle is delegated to go-qrdb's `TenantService`; go-xkms contributes the hardware seal strategies and composes them via `sdk/go` (`NewHardwareStrategyRegistry` / `NewHardwareTenantService`).

## Tenant Isolation Model

Each tenant gets:
1. **Independent DEK (Data Encryption Key)**: Encrypted with tenant-specific barrier sealing strategy
2. **Partitioned Storage**: Separate KVStore namespace via TenantBarrier
3. **Tenant Barrier**: Manages unseal/seal lifecycle independent of system barrier
4. **Tenant ID Context**: Propagated through request context and stored on entities

Entities explicitly track tenancy via a `TenantID` field:

```go
type PasswordEntity struct {
    ID       uint64 `json:"id"`
    Name     string `json:"name"`
    TenantID string `json:"tenant_id" index:"true"`  // Tenant partition key
}

type TeamEntity struct {
    ID       uint64 `json:"id"`
    Name     string `json:"name"`
    TenantID string `json:"tenant_id" index:"true"`  // Tenant partition key
}
```

This enables:
- Fast tenant-scoped queries via indexed lookups
- Explicit audit trails showing which tenant owns which entity
- Defense-in-depth if encryption is somehow bypassed

## TenantDAOFactory Pattern

The factory creates per-tenant DAO stores, bridging barriers, KVStore adapters, and typed DAO layers:

```
TenantBarrier[tenant-1] (storage.Backend with tenant-1 DEK)
  -> kvadapter.KVStoreAdapter (kvstore.KVStore interface)
    -> DAOStore / DAOTeamStore (typed entity persistence)
```

### Usage

```go
import "github.com/jeremyhahn/go-xkms/pkg/staticpw"

// Initialize factory with system KVStore and barrier registry
systemKVStore, _ := initSystemKVStore()
barrierRegistry, _ := initBarrierRegistry()

factory, err := staticpw.NewTenantDAOFactory(systemKVStore, barrierRegistry)
if err != nil {
    log.Fatal(err)  // nil args rejected
}

// Get per-tenant password store
pwStore, err := factory.PasswordStoreForTenant("acme-corp")
if err != nil {
    // Barrier unavailable, sealed, or tenant not found
}

// Store is automatically encrypted with tenant's DEK
pw := &staticpw.StaticPassword{
    Name:     "prod-db",
    Password: "secret",
    TenantID: "acme-corp",
}
pwStore.Add(pw)  // Data transparently encrypted

// Get system-level store (shared across tenants)
sysPwStore, err := factory.SystemPasswordStore()

// Get per-tenant team store
teamStore, err := factory.TeamStoreForTenant("acme-corp")
```

### BarrierRegistryAccessor

The factory consumes a minimal interface to access tenant barriers:

```go
type BarrierRegistryAccessor interface {
    // GetTenantBarrier returns the storage backend for a tenant.
    // The backend transparently encrypts/decrypts with the tenant's DEK.
    // Returns an error if the tenant is not registered or the barrier is sealed.
    GetTenantBarrier(tenantID string) (storage.Backend, error)
}
```

Implementations include:
- `BarrierRegistry` (full registry from `pkg/seal`)
- Mock implementations for testing
- Custom adapters for advanced scenarios

## Tenant Context Propagation

### Request Context Extraction

Identity is extracted from authentication (JWT, mTLS) and stored in the request context:

```go
// JWT claim: "tenant_id": "acme-corp"
// mTLS cert OU[0]: "acme-corp"
identity := auth.NewIdentity(userID, roles, tenantID)
```

### REST Middleware

The `TenantMiddleware` in the REST API enforces tenant scoping:

```go
// In server setup
router.Use(s.TenantMiddleware())
```

Behavior:

| Case                        | Action                                    |
|-----------------------------|-------------------------------------------|
| No identity (unauthenticated) | Pass through (auth middleware handles rejection) |
| Cross-tenant-scoped TenantID (`""` or the reserved `system` tenant) | Pass through (system-level or bootstrap operation) |
| No barrier registry        | Pass through (tenant enforcement disabled)        |
| Tenant not in registry     | Return 403 Forbidden                              |
| Tenant barrier sealed      | Return 503 Service Unavailable                    |
| All checks pass            | Inject TenantBarrier into context, continue       |

```go
// Middleware injects barrier into context
ctx := auth.WithTenantBarrier(r.Context(), tenantBarrier)
r = r.WithContext(ctx)

// Downstream handlers retrieve it
tb, _ := auth.GetTenantBarrier(r.Context())
```

### The Shared Tenant Gate (pkg/api/tenantgate)

REST, gRPC (network and Unix domain socket), QUIC, and MCP all enforce tenant
scoping through one transport-neutral function, `tenantgate.Access`, instead
of five hand-mirrored copies of the same decision:

```go
// pkg/api/tenantgate
func Access(identity *auth.Identity, registry *seal.BarrierRegistry) (*seal.TenantBarrier, error)
```

Each transport calls `tenantgate.Access` with the caller's identity and the
process's `*seal.BarrierRegistry`, then maps the result onto its own wire
shape:

| Transport | Gate | Not found | Sealed |
|-----------|------|-----------|--------|
| REST | `Server.TenantMiddleware()` | 403 | 503 |
| gRPC (network + Unix socket) | `grpc.TenantUnaryInterceptor` / `TenantStreamInterceptor` | `PermissionDenied` | `Unavailable` |
| QUIC | `Server.tenantMiddleware` | 403 | 503 |
| MCP | `Server.tenantAccess` (called from `handleRequest` before `authorizeMethod`) | JSON-RPC -32003 | JSON-RPC -32004 |

The Unix domain socket gRPC listener chains the identical
`grpc.TenantUnaryInterceptor` / `TenantStreamInterceptor` constructors the
network gRPC server uses, configured with its own `*seal.BarrierRegistry`
captured at construction time. That listener sets no authentication
interceptor -- its trust boundary is the socket's file mode and directory
permissions, not identity -- so in practice every call there carries a nil
identity and the gate is a no-op passthrough; it is wired for parity with
every other transport rather than because enforcement is needed today.

`tenantgate` cannot live in `pkg/auth` (which already owns
`auth.IsCrossTenant`): `pkg/auth` would have to import `pkg/seal` for
`*seal.BarrierRegistry` / `*seal.TenantBarrier`, but `pkg/seal` already
imports `pkg/audit`, and `pkg/audit` imports `pkg/auth` -- `auth -> seal`
would close that cycle. `pkg/api/tenantgate` sits above both, mirroring how
`pkg/api/initgate` is the transport-neutral seam for the init-ceremony
public-method table.

## Identity Model

The auth.Identity type (a qrdb-shaped alias, `pkg/auth.Identity`) tracks tenancy:

```go
type Identity struct {
    Subject  string
    Roles    []string
    TenantID string  // "" or the reserved "system" tenant = system-level
    Metadata map[string]string
}

// IsCrossTenant reports whether the identity has cross-tenant scope: a nil
// identity, an identity rooted in the reserved system tenant, or one with an
// empty TenantID are all treated as platform-scoped. Anything else is bound
// to its own tenant. This is pkg/auth.IsCrossTenant, not a method on
// Identity -- Identity is a type alias for qrdb's identity shape and defines
// no xkms-local methods.
func IsCrossTenant(id *Identity) bool {
    if id == nil {
        return true
    }
    return id.TenantID == qrdbsdk.SystemTenantID || id.TenantID == ""
}

```

There is no role-based exemption from tenant scoping. Cross-tenant scope is
qrdb's system-tenant rule alone: the system tenant's Security Officer is
cross-tenant because it is a system-tenant identity, and a tenant-local
officer is confined to its tenant. A former `identity.HasRole("so")` bypass
compared a role name against the role identifiers identities carry, so it
matched only unverified token claims (go-xkms#1074); see
[`../rbac/architecture.md`](../rbac/architecture.md).

### JWT Extraction

```go
// Token claim
{
  "sub": "alice@acme.com",
  "roles": ["user", "owner"],
  "tenant_id": "acme-corp"  // Tenant claim
}
```

### mTLS Extraction

```go
// Certificate OU chain: ["acme-corp", "users"]
// TenantID = OU[0]
tenant := cert.Subject.OrganizationalUnit[0]
```

## Tenant Lifecycle

### Registration

When a tenant is initialized:

```go
barrierRegistry.RegisterTenantDefault(tenantID)
// or with explicit config
barrierRegistry.RegisterTenant(ctx, tenantID, base, config, strategies...)
```

The barrier creates a new DEK encrypted with the configured sealing strategy.

### Access

```go
// Factory caches KVStore adapters per tenant
pwStore, _ := factory.PasswordStoreForTenant(tenantID)
pwStore.Add(pw)  // Encrypted with tenant DEK
```

Caching uses lock-free `sync.Map` for efficient concurrent access.

### Seal/Unseal

```go
// Barrier can be sealed independently
barrierRegistry.SealTenant(tenantID)
// API returns 503 for sealed tenants

// Unseal with credentials
barrierRegistry.UnsealTenant(tenantID, password)
```

### Deregistration

```go
// Invalidate factory cache for the tenant
factory.InvalidateTenant(tenantID)

// Unregister from barrier registry
barrierRegistry.DeregisterTenant(tenantID)
```

## Querying Tenant Data

The DAO layer supports tenant-scoped queries via indexing:

```go
pwStore, _ := factory.PasswordStoreForTenant("acme-corp")

// List all passwords (already scoped to tenant)
passwords, _ := pwStore.List()

// The returned passwords have TenantID="acme-corp"
for _, pw := range passwords {
    fmt.Println(pw.TenantID)  // "acme-corp"
}

// Query by folder (tenant-scoped)
folders, _ := pwStore.ListFolders()
```

System-level stores are accessed separately:

```go
// System passwords (TenantID empty or varies)
sysPwStore, _ := factory.SystemPasswordStore()
sysPasswords, _ := sysPwStore.List()
```

## Error Handling

```go
pwStore, err := factory.PasswordStoreForTenant(tenantID)
if err == staticpw.ErrInvalidTenant {
    // TenantID is empty or fails validation
}
if err == staticpw.ErrTenantBarrierUnavailable {
    // Barrier not registered, sealed, or resolution failed
    // Check wrapped error for details
    if errors.Is(err, sealerrors.ErrBarrierSealed) {
        // Barrier is sealed; request unseal
    }
}
```

## Best Practices

1. **Always extract tenant from identity** - don't trust URL parameters
2. **Use TenantDAOFactory** - don't create KVStore adapters manually
3. **Invalidate cache after seal** - call `factory.InvalidateTenant(tenantID)`
4. **Log tenant IDs** - aids debugging and compliance audits
5. **Fail closed on seal** - return 503, don't fall back to system store
6. **No role-based tenant exemptions** - cross-tenant scope comes only from the system tenant
7. **Test isolation** - create separate test tenants, don't share data
