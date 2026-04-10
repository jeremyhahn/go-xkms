# Multi-Tenant Architecture

Go-xkms supports isolated, multi-tenant deployments where each tenant has independent data encryption, storage partitioning, and barrier management. This document covers the TenantDAOFactory pattern, barrier routing, and context propagation.

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
| Empty TenantID             | Pass through (system-level operation)              |
| SO role (Security Officer) | Pass through (cross-tenant access allowed)        |
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

### gRPC Interceptors

gRPC uses unary and stream interceptors for the same tenant enforcement:

```go
// In gRPC server options
grpc.ChainUnaryInterceptor(
    s.TenantInterceptor(),
    // ... other interceptors
)
```

Interceptors follow the same logic as REST middleware, extracting identity from metadata and validating tenant barriers.

## Identity Model

The auth.Identity type tracks tenancy:

```go
type Identity struct {
    UserID   string
    Roles    []string
    TenantID string  // Empty = system-level, else = tenant-scoped
}

// Check cross-tenant access
func (id *Identity) IsCrossTenant() bool {
    return id.TenantID == ""
}

// SO role gets cross-tenant privileges
func (id *Identity) HasRole(role string) bool {
    for _, r := range id.Roles {
        if r == role {
            return true
        }
    }
    return false
}
```

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
barrierRegistry.RegisterTenant(tenantID)
// or with explicit config
barrierRegistry.RegisterTenantWithConfig(tenantID, base, config, strategies...)
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
6. **SO role exceptions** - document cross-tenant operations
7. **Test isolation** - create separate test tenants, don't share data
