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

The diagram above shows **prefix isolation** — the lightest mode, where tenants share the system DEK and are separated by a `tenantID + "/"` key prefix. This is no longer the only model: a tenant can instead be given its **own DEK** via a dedicated per-tenant barrier (`barrier`/`volume`/`raft` isolation), and that DEK can be sealed by a **hardware strategy** (TPM 2.0, PKCS#11, cloud KMS). See [Isolation modes & hardware-backed composition](#isolation-modes--hardware-backed-composition) below. The composition is delegated to go-qrdb's `TenantService`; go-xkms contributes the hardware seal strategies.

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

## Isolation modes & hardware-backed composition

Per-tenant lifecycle (isolation, entitlements, quotas, key-management mode) is owned by go-qrdb's `TenantService`. go-xkms composes its hardware seal strategies on top so a per-tenant barrier can be sealed by dedicated hardware. The server wires this in `initializeBarrierRegistry`; the `XKMSService` tenant servicer delegates to it.

### Isolation modes

| Mode | Per-tenant DEK | Storage | Notes |
|------|----------------|---------|-------|
| `prefix` (default) | No (shares system DEK) | Shared system store, `tenantID/` prefix | Lightest; barrier isolation is opt-in |
| `barrier` | Yes | Pooled per-tenant Pebble (volume pool) | Own DEK + `tenantID/` namespace |
| `volume` | Yes | Dedicated filesystem `DataRoot` | Own local Raft host, encrypted under the tenant DEK |
| `raft` | Yes | Dedicated `DataRoot` + per-database Raft group | Phase-4 dedicated-raft |

Dedicated-isolation modes draw their per-tenant storage from a **volume pool** (`BuildVolumePoolSubsystem`, rooted at `{Storage.Path}/tenant-volumes`). Without a pool, `prefix` is the only available mode.

### Entitlements

Isolation modes and the dedicated-storage features are **entitlement-gated** (`quota.Entitlements`): `AllowedIsolationModes`, `AllowVolumeStorage`, `AllowDedicatedRaft`, `AllowSystemManagedBarrier`, `AllowDedicatedWAL`. xkms operates its own tenants as the trust anchor, so its operator default (`xkmsDefaultEntitlements`) is permissive; downstream multi-tenant planes tighten these per plan.

### Key-management modes (two-phase, §3.6)

- **Self-managed** (secure default): `CreateTenant` registers the per-tenant barrier **sealed and uninitialized**. The tenant admin drives Phase 2 (`TenantBarrierInit`) with their own passphrase / strategy; the server never holds the tenant key.
- **System-managed auto-unseal** (`WithBarrierAutoUnseal(true)`, entitlement-gated): the tenant DEK is wrapped under the **system barrier** (`SystemBarrierStrategy`), so the barrier is initialized at create and re-attached **credential-free at boot** via `RestoreVolumeTenants`. This mode also enables **credential-free enable-encryption migration** (tenants starting with `StrategySystemBarrier` or `StrategyNone` can transparently migrate to keyed strategies without supplying unlock credentials).

### Hardware seal strategies per tenant

A tenant barrier is sealed by the strategy named at init (`TenantBarrierInit --strategy tpm2|pkcs11|awskms|gcpkms|azurekv|vault`). The strategy is resolved from a `StrategyRegistry` that go-xkms seeds with its hardware/cloud strategies.

### SDK composition helpers (`go-xkms/sdk/go`)

```go
// Build a registry seeded with go-qrdb software strategies + xkms hardware strategies.
reg, _ := xkmssdk.NewHardwareStrategyRegistry(tpm2Strategy, pkcs11Strategy /*, ...*/)

// One-call: compose go-qrdb's TenantService over a barrier registry with the
// xkms hardware strategies injected (used by go-quicbaas and the xkms server).
svc, _ := xkmssdk.NewHardwareTenantService(store, registry, logger, strategies,
    qrdbsdk.WithTenantDefaultEntitlements(ents))

info, _ := svc.CreateTenant(ctx, "acme", "Acme", xkmssdk.TenantIsolationVolume,
    xkmssdk.WithBarrierAutoUnseal(true))
```

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
