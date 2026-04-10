# Per-Tenant Barrier Isolation

The `pkg/seal` package provides multi-tenant barrier isolation through `TenantBarrier` and `BarrierRegistry`. Each tenant gets a key-prefixed view of the shared system barrier, ensuring cryptographic isolation without separate barriers per tenant.

## Architecture

```
  Tenant A         Tenant B         System
     |                |               |
 TenantBarrier    TenantBarrier    Barrier
 (prefix: "a/")   (prefix: "b/")     |
     |                |               |
     +-------+--------+---------------+
             |
      storage.Backend (file, memory, etc.)
```

All tenants share one `Barrier` (and one DEK). Isolation is achieved by prefixing every storage key with `tenantID + "/"`. Tenant A writing `"secrets/db"` stores it as `"a/secrets/db"` in the underlying barrier.

## BarrierRegistry

`BarrierRegistry` manages the system barrier and all tenant barriers.

| Method | Description |
|--------|-------------|
| `NewBarrierRegistry(system)` | Creates registry wrapping the system barrier |
| `System()` | Returns the system barrier |
| `Tenant(tenantID)` | Returns the `TenantBarrier` for a tenant |
| `RegisterTenant(tenantID)` | Creates and registers a new tenant barrier |
| `UnregisterTenant(tenantID)` | Removes a tenant barrier |
| `ListTenants()` | Returns sorted list of tenant IDs |
| `Close()` | Closes all tenant barriers (not the system barrier) |

## TenantBarrier

`TenantBarrier` implements `storage.Backend` with tenant-scoped keys. It delegates all crypto to the underlying system barrier.

| Method | Behavior |
|--------|----------|
| `Get(ctx, key)` | Reads `prefix + key` from barrier |
| `Put(ctx, key, val)` | Writes `prefix + key` to barrier |
| `Delete(ctx, key)` | Deletes `prefix + key` from barrier |
| `Exists(ctx, key)` | Checks `prefix + key` in barrier |
| `List(ctx, prefix)` | Lists matching keys, strips tenant prefix from results |
| `Close()` | No-op (system barrier lifecycle managed by registry) |
| `IsSealed()` | Delegates to system barrier |

## Configuration

```go
type TenantBarrierConfig struct {
    Enabled   bool     `json:"enabled"`            // false = single-tenant mode
    TenantIDs []string `json:"tenant_ids,omitempty"` // pre-register on startup
}
```

When `Enabled` is `false` (default), the system operates in single-tenant mode for backward compatibility. All operations use the system barrier directly.

## Usage

```go
barrier, _ := seal.NewBarrier(logger, base, config, strategies...)
barrier.Initialize(ctx, creds)

registry, _ := seal.NewBarrierRegistry(barrier)
tb, _ := registry.RegisterTenant("acme-corp")

// Tenant-scoped operations
tb.Put(ctx, "keys/signing-key", keyData)   // stored as "acme-corp/keys/signing-key"
data, _ := tb.Get(ctx, "keys/signing-key")       // reads "acme-corp/keys/signing-key"
keys, _ := tb.List(ctx, "keys/")                 // returns ["keys/signing-key"] (prefix stripped)
```

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrEmptyTenantID` | Empty tenant ID provided |
| `ErrNilSystemBarrier` | Nil system barrier passed to constructor |
| `ErrTenantNotFound` | Tenant ID not registered |
| `ErrTenantAlreadyExists` | Tenant ID already registered |

## Cross-References

- [Barrier Encryption Architecture](README.md) -- barrier basics, sealing strategies, Shamir
- [Configuration Reference](../configuration/README.md)
