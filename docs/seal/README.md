# Barrier Encryption Architecture

The barrier subsystem provides transparent at-rest encryption for go-xkms's `storage.Backend` layer. A `Barrier` wraps any storage backend and encrypts all values with AES-256-GCM before they reach the underlying store. Keys (paths) remain in plaintext; only values are encrypted.

## Three-Layer Architecture

The barrier implementation is split across three repositories to enable reuse at different levels of the stack:

| Layer | Repository | Package | Provides |
|-------|-----------|---------|----------|
| Interfaces + memguard | **go-quicraft** | `pkg/seal` | `SealingStrategy`, `Barrier`, `SymmetricEncrypter` interfaces; `GuardedBuffer` memory protection |
| Rich barrier | **go-qrdb** | `pkg/seal` | `ExtendedBarrier` with Shamir secret sharing, multi-tenant barriers, storage wrapping, recovery keys, root token generation |
| Hardware strategies | **go-xkms** | `pkg/seal` | `SealingStrategy` implementations for TPM2, PKCS#11, AWS KMS, GCP KMS, Azure KV, Vault; `PlatformSealer`; adapter layer |

go-xkms imports the barrier from go-qrdb (which itself embeds go-quicraft's minimal barrier) and registers hardware-backed sealing strategies. The `pkg/seal` package in go-xkms contains:

- **Hardware strategy implementations**: `strategy_tpm2.go`, `strategy_pkcs11.go`, `strategy_cloud.go`
- **Software strategy**: `strategy_software.go` (Argon2id + AES-256-GCM fallback)
- **Shamir strategy**: `strategy_shamir.go` (M-of-N root key splitting)
- **Adapter layer**: `adapter.go` bridges go-xkms types to go-qrdb interfaces
- **PlatformSealer**: `platform_sealer.go` for sealing arbitrary data
- **Barrier wrapper**: `barrier.go` composes the go-qrdb barrier with local strategies
- **Tenant barriers**: `tenant_barrier.go`, `barrier_registry.go` for multi-tenant isolation

### Import Paths

```go
import (
    // go-qrdb barrier (rich features: Shamir, multi-tenant, recovery)
    qrdbseal "github.com/jeremyhahn/go-qrdb/pkg/seal"

    // go-xkms hardware strategies and adapters
    "github.com/jeremyhahn/go-xkms/pkg/seal"
)
```

## Architecture Overview

```
  Application
      |
  KeyStore / xKMSService
      |
  storage.Backend  (Barrier)          -- go-xkms pkg/seal (wrapper)
      |                |
      |   ExtendedBarrier              -- go-qrdb pkg/seal
      |       |
      |   StrategyAdapter(s)           -- go-xkms pkg/seal/adapter.go
      |       |
      |   SealingStrategy impls        -- go-xkms (TPM2, PKCS#11, Cloud KMS)
      |                |
      |   encrypt(DEK, value) / decrypt(DEK, ciphertext)
      |                |
  storage.Backend  (file, memory, pebble, qrdb)
      |
  Persistent Storage
```

The Barrier sits between the application's key store and the raw storage backend. It implements `storage.Backend` itself, so any code expecting a storage backend can use a Barrier without modification.

## Seal/Unseal Lifecycle

```
             Initialize(creds)
                   |
                   v
  +----------+         +------------+
  |  SEALED  | ------> |  UNSEALED  |
  |  (init)  |  Unseal |            |
  +----------+ <------ +------------+
                  Seal
```

**States:**

| State | DEK Available | Storage Operations | Transitions To |
|-------|---------------|-------------------|----------------|
| Sealed (default) | No | All return `ErrSealed` | Unsealed (via `Initialize` or `Unseal`) |
| Unsealed | Yes | Encrypt on write, decrypt on read | Sealed (via `Seal` or `Close`) |

**Lifecycle:**

1. **Initialize** -- Called once for a new barrier. Generates a 32-byte root key, seals it with the best available strategy, persists the sealed blob, derives the DEK, and transitions to unsealed.
2. **Unseal** -- Loads the persisted sealed root key blob, unseals it with the matching strategy, derives the DEK, and transitions to unsealed.
3. **Seal** -- Zeros the DEK in memory and transitions to sealed. All subsequent operations return `ErrSealed`. Idempotent.
4. **Close** -- Calls `Seal`, then closes the underlying storage backend.

## Root Key Management

### Generation

On `Initialize`, a 32-byte root key is generated from `crypto/rand`:

```go
rootKey := make([]byte, 32)
io.ReadFull(rand.Reader, rootKey)
```

### Sealing

The root key is sealed by the best available `SealingStrategy` and persisted as a JSON-encoded `SealedRootKey` blob at the configured `RootKeyPath` in the underlying storage backend.

### DEK Derivation

A Data Encryption Key (DEK) is derived from the root key using HKDF-SHA256:

```
DEK = HKDF-SHA256(rootKey, salt=nil, info="go-xkms/barrier/v1", length=32)
```

The root key is zeroed immediately after DEK derivation. The DEK is held in memory only while the barrier is unsealed.

### Key Zeroing

- Root key: zeroed immediately after DEK derivation.
- DEK: zeroed when `Seal()` or `Close()` is called.
- Zeroing uses a byte-by-byte overwrite loop.

## Encrypted Value Format

Every value stored through the barrier is encrypted as:

```
+----------+----------+----------------------------+
| version  |  nonce   |    ciphertext + GCM tag    |
|  1 byte  | 12 bytes |      variable length       |
+----------+----------+----------------------------+
```

| Field | Size | Description |
|-------|------|-------------|
| version | 1 byte | Format version (currently `0x01`) |
| nonce | 12 bytes | Random AES-GCM nonce from `crypto/rand` |
| ciphertext + tag | N + 16 bytes | AES-256-GCM encrypted payload with 16-byte authentication tag |

Minimum encrypted value size: 29 bytes (1 + 12 + 16).

## Sealing Strategies

Each strategy implements the `SealingStrategy` interface:

```go
type SealingStrategy interface {
    ID() StrategyID
    Available() bool
    HardwareBacked() bool
    SealRootKey(ctx context.Context, rootKey []byte, creds Credentials) (*SealedRootKey, error)
    UnsealRootKey(ctx context.Context, sealed *SealedRootKey, creds Credentials) ([]byte, error)
}
```

### Strategy Comparison

| Strategy | ID | Hardware | Key Protection | Credentials Used |
|----------|----|----------|----------------|-----------------|
| Software | `software` | No | Argon2id + AES-256-GCM | Password for Argon2id KDF |
| TPM 2.0 | `tpm2` | Yes | TPM SRK hierarchy, optional PCR binding | May be used as authorization value |
| PKCS#11 | `pkcs11` | Yes | HSM token wrapping key | N/A (token session auth) |
| AWS KMS | `awskms` | Yes | AWS KMS CMK envelope encryption | N/A (IAM/external auth) |
| GCP KMS | `gcpkms` | Yes | GCP KMS key ring envelope encryption | N/A (IAM/external auth) |
| Azure KV | `azurekv` | Yes | Azure Key Vault key encryption | N/A (Azure AD auth) |
| Vault | `vault` | Yes | HashiCorp Vault transit engine | N/A (Vault token auth) |

### Default Preference Order

When `BarrierConfig.PreferenceOrder` is not set, the barrier selects the first available strategy in this order:

1. `tpm2`
2. `pkcs11`
3. `awskms`
4. `gcpkms`
5. `azurekv`
6. `vault`
7. `software`

Hardware-backed strategies are always preferred over the software fallback.

### Software Strategy Details

The software strategy uses Argon2id for password-based key derivation:

| Parameter | Value |
|-----------|-------|
| Time cost | 3 iterations |
| Memory cost | 64 MiB |
| Parallelism | 4 threads |
| Key length | 32 bytes |
| Salt length | 16 bytes (random) |

Process:
1. Generate 16-byte random salt
2. Derive 32-byte key: `Argon2id(password, salt, t=3, m=64K, p=4)`
3. Generate 12-byte random nonce
4. Encrypt root key: `AES-256-GCM(derivedKey, nonce, rootKey)`
5. Persist `SealedRootKey{salt, nonce, ciphertext}`

### Hardware Strategy Details (TPM2, PKCS#11, Cloud KMS)

Hardware strategies delegate to the `types.Sealer` interface:

```go
type Sealer interface {
    Seal(ctx context.Context, data []byte, opts *SealOptions) (*SealedData, error)
    Unseal(ctx context.Context, sealed *SealedData, opts *UnsealOptions) ([]byte, error)
    CanSeal() bool
}
```

The root key is wrapped by the hardware backend and stored as `SealedRootKey.SealedData`. The `Credentials.Secret` field is unused for cloud KMS strategies (authentication is handled externally via IAM, service accounts, etc.).

## PlatformSealer

`PlatformSealer` is a separate component that provides a `types.Sealer` implementation for sealing arbitrary data (not just root keys) across multiple backend sealers. It automatically tags sealed data with the strategy used and routes unseal operations to the correct backend.

```go
sealer, _ := seal.NewPlatformSealer(logger, config, sealerMap)

// Seal with best available strategy
sealed, _ := sealer.Seal(ctx, plaintext, nil)

// Unseal (automatically routes to correct backend)
plaintext, _ := sealer.Unseal(ctx, sealed, nil)

// Seal with a specific strategy
sealed, _ = sealer.SealWith(ctx, seal.StrategyTPM2, plaintext, nil)
```

## Configuration

### BarrierConfig

```go
type BarrierConfig struct {
    // Strategy selection order. First available wins.
    // Default: tpm2 > pkcs11 > awskms > gcpkms > azurekv > vault > software
    PreferenceOrder []StrategyID

    // Storage key for the sealed root key blob. Must be non-empty.
    RootKeyPath string

    // Audit logger for seal/unseal events. Nil disables audit logging.
    AuditLogger audit.Logger
}
```

### SealerConfig (for PlatformSealer)

```go
type SealerConfig struct {
    PreferenceOrder []StrategyID
    AuditLogger     audit.Logger
}
```

## Audit Logging

All barrier operations emit audit events when an `AuditLogger` is configured:

| Action | Resource | Outcome |
|--------|----------|---------|
| `initialize` | `barrier` | `allow` on success, `deny` on failure |
| `unseal` | `barrier` | `allow` on success, `deny` on failure |
| `seal` | `barrier` | `allow` |

Audit failures are silently ignored to avoid blocking barrier operations.

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrSealed` | Storage operation attempted while barrier is sealed |
| `ErrAlreadyUnsealed` | `Unseal` called on an already-unsealed barrier |
| `ErrAlreadyInitialized` | `Initialize` called when root key already exists |
| `ErrNotInitialized` | `Unseal` called before `Initialize` |
| `ErrInvalidCredentials` | Wrong password, token, or auth value |
| `ErrNoAvailableStrategy` | No registered strategy reports as available |
| `ErrStrategyNotFound` | Sealed blob references an unregistered strategy |
| `ErrStrategyMismatch` | PlatformSealer metadata missing strategy tag |
| `ErrCorruptRootKey` | Root key blob failed to deserialize or has wrong format |
| `ErrNilSealedData` | Nil pointer passed to unseal operation |
| `ErrEncryptorNotAvailable` | Encryptor not available (barrier not unsealed) |
| `ErrHardwareEncryptorRequired` | Master key not exportable from hardware-backed strategy |

## Security Properties

- **Encryption**: AES-256-GCM with random 12-byte nonces (NIST SP 800-38D).
- **Key derivation**: HKDF-SHA256 (RFC 5869) for DEK derivation from root key.
- **Password KDF**: Argon2id (RFC 9106) with 64 MiB memory cost for software strategy.
- **Key zeroing**: Root key and DEK are explicitly zeroed when no longer needed.
- **Atomic state**: Lock-free `atomic.Int32` for seal state, `atomic.Value` for DEK and strategy. No mutex contention on hot paths.
- **Nonce uniqueness**: Each encrypt operation generates a fresh random nonce. With AES-256-GCM and 96-bit nonces, the birthday bound is ~2^48 encryptions under the same key.
- **No key in plaintext on disk**: The root key is always wrapped by a sealing strategy before being persisted.

## Threat Model

| Threat | Mitigation |
|--------|------------|
| Storage compromise (disk theft) | All values encrypted with AES-256-GCM |
| Root key extraction from memory | DEK zeroed on seal; root key zeroed immediately after derivation |
| Brute-force password attack | Argon2id with 64 MiB memory cost (software strategy) |
| Replay of sealed root key | Hardware strategies bind to specific hardware identity (TPM SRK, HSM slot) |
| Downgrade to weaker strategy | Sealed root key records the strategy ID; unseal requires matching strategy |

## Go API Examples

### Basic Barrier Usage

```go
package main

import (
    "context"
    "log/slog"

    "github.com/jeremyhahn/go-xkms/pkg/seal"
    "github.com/jeremyhahn/go-xkms/pkg/storage/memory"
)

func main() {
    logger := slog.Default()
    base := memory.New()

    barrier, err := seal.NewBarrier(
        logger,
        base,
        seal.BarrierConfig{
            RootKeyPath: "sys/barrier/root-key",
        },
        seal.NewSoftwareStrategy(),
    )
    if err != nil {
        panic(err)
    }
    defer barrier.Close()

    ctx := context.Background()
    creds := seal.Credentials{Secret: "my-secure-passphrase"}

    // First-time initialization
    if err := barrier.Initialize(ctx, creds); err != nil {
        panic(err)
    }

    // Store encrypted data
    if err := barrier.Put(ctx, "secrets/db-password", []byte("hunter2")); err != nil {
        panic(err)
    }

    // Retrieve and decrypt
    plaintext, err := barrier.Get(ctx, "secrets/db-password")
    if err != nil {
        panic(err)
    }
    // plaintext == []byte("hunter2")

    // Seal the barrier
    barrier.Seal()

    // All operations now return ErrSealed
    _, err = barrier.Get(ctx, "secrets/db-password")
    // err == seal.ErrSealed

    // Unseal to resume
    if err := barrier.Unseal(ctx, creds); err != nil {
        panic(err)
    }
}
```

### Multi-Strategy Barrier

```go
barrier, err := seal.NewBarrier(
    logger,
    base,
    seal.BarrierConfig{
        RootKeyPath: "sys/barrier/root-key",
        PreferenceOrder: []seal.StrategyID{
            seal.StrategyTPM2,
            seal.StrategySoftware,
        },
    },
    seal.NewTPM2Strategy(tpmSealer),
    seal.NewSoftwareStrategy(),
)
```

### PlatformSealer for Arbitrary Data

```go
sealers := map[seal.StrategyID]types.Sealer{
    seal.StrategyTPM2:     tpmSealer,
    seal.StrategySoftware: softwareSealer,
}

platformSealer, err := seal.NewPlatformSealer(logger, seal.SealerConfig{}, sealers)
if err != nil {
    panic(err)
}

sealed, err := platformSealer.Seal(ctx, []byte("sensitive data"), nil)
// sealed.Metadata["seal:strategy"] == "tpm2" (or whichever was best)

plaintext, err := platformSealer.Unseal(ctx, sealed, nil)
```

## Shamir Secret Sharing (StrategyShamir)

The `shamir` strategy splits the root key itself into M-of-N Shamir shares using `pkg/threshold/shamir`. Unlike credential-based strategies where a password protects the root key, the root key IS the Shamir secret. No password is needed for initialization or unsealing.

| Strategy | ID | Hardware | Key Protection | Credentials Used |
|----------|----|----------|----------------|-----------------|
| Shamir | `shamir` | No | M-of-N Shamir secret sharing | None (root key is the secret) |

### Dual-Mode Operation

All Shamir barrier methods operate in one of two modes depending on whether `StrategyShamir` is registered:

| Mode | Strategy Registered | Shamir Secret | Use Case |
|------|-------------------|---------------|----------|
| **Direct** | `StrategyShamir` | Root key itself | Multi-party root key custody |
| **Credential** | Any other (e.g. `software`) | Credential password | Password-based unsealing with quorum |

In direct mode, reconstructed shares yield the root key directly. In credential mode, reconstructed shares yield the password that is then passed to the underlying strategy's `UnsealRootKey`.

### Configuration

```go
seal.BarrierConfig{
    RootKeyPath:     "sys/barrier/root-key",
    PreferenceOrder: []seal.StrategyID{seal.StrategyShamir},
    Shamir: &seal.ShamirConfig{
        Threshold:   3,  // M: minimum shares to reconstruct
        TotalShares: 5,  // N: total shares generated
    },
}
```

`ShamirConfig` must be set on `BarrierConfig.Shamir` for any Shamir method to work. The `Threshold` must be >= 2 and <= `TotalShares`.

### Initialization

`InitializeShamir` generates a root key, seals it with the best available strategy, and splits the secret into N shares:

```go
shamirStrat, _ := seal.NewShamirStrategy(shareStore, 3, 5)

barrier, _ := seal.NewBarrier(logger, base, seal.BarrierConfig{
    RootKeyPath:     "sys/barrier/root-key",
    PreferenceOrder: []seal.StrategyID{seal.StrategyShamir},
    Shamir:          &seal.ShamirConfig{Threshold: 3, TotalShares: 5},
}, shamirStrat)

result, err := barrier.InitializeShamir(ctx, seal.Credentials{})
// result.Shares: ["base64share1", "base64share2", ..., "base64share5"]
// result.Threshold: 3
// result.TotalShares: 5
// Distribute shares to key holders. The barrier is now unsealed.
```

### Share-Based Unsealing

Two methods support unsealing from Shamir shares:

**Stateful (one-at-a-time):** `UnsealWithShare` accumulates shares in an internal quorum accumulator with a 5-minute TTL. When the threshold is met, the barrier unseals automatically.

```go
progress, _ := barrier.UnsealWithShare(ctx, shares[0])
// progress.Required: 3, progress.Submitted: 1, progress.Complete: false

progress, _ = barrier.UnsealWithShare(ctx, shares[1])
// progress.Submitted: 2, progress.Complete: false

progress, _ = barrier.UnsealWithShare(ctx, shares[2])
// progress.Submitted: 3, progress.Complete: true
// Barrier is now unsealed.
```

The accumulator rejects duplicate shares (`ErrShamirDuplicateShare`) and resets if the TTL expires (`ErrShamirQuorumExpired`).

**Stateless (batch):** `UnsealWithShares` takes all shares in a single call.

```go
err := barrier.UnsealWithShares(ctx, shares[:3])
// Barrier is now unsealed (or error if shares are invalid).
```

### Rekey (Share Rotation)

`Rekey` generates new Shamir shares for the existing root key without changing the root key itself. The barrier must be unsealed and `StrategyShamir` must be registered.

```go
result, err := barrier.Rekey(ctx, 4, 7)
// Old shares are deleted. New 4-of-7 shares returned.
// result.Shares: ["newshare1", ..., "newshare7"]
// The root key and DEK are unchanged.
```

Use this when an operator leaves and their share must be invalidated.

### Recovery Keys

Recovery keys are an independent Shamir split of the DEK (not the root key) for disaster recovery. The shares are returned for offline storage and are NOT persisted.

```go
// Generate (barrier must be unsealed)
result, err := barrier.GenerateRecoveryKeys(ctx, 3, 5)
// result.Shares: store these offline (paper, safe deposit boxes)
// Only metadata (threshold/total) is persisted.

// Recover (barrier must be sealed)
err = barrier.RecoverWithKeys(ctx, recoveryShares[:3])
// Barrier is now unsealed with the recovered DEK.

// Check and delete
exists, _ := barrier.HasRecoveryKeys()
err = barrier.DeleteRecoveryKeys()
```

### Root Token Generation

`GenerateRootToken` produces a one-time admin token by proving knowledge of the master key through Shamir share reconstruction. The token is `HMAC-SHA256(DEK, random_nonce || "go-xkms/root-token/v1")`.

```go
token, err := barrier.GenerateRootToken(ctx, shares[:3])
// token.Token: hex-encoded HMAC-SHA256 value
// token.CreatedAt: time.Time
// The barrier state is unchanged (works whether sealed or unsealed).
```

The caller provides enough shares to reconstruct the secret. In direct mode, the reconstructed root key is verified by deriving the DEK and performing a canary encrypt/decrypt cycle. In credential mode, the password is verified by unsealing the root key blob.

### Shamir Error Reference

| Error | Condition |
|-------|-----------|
| `ErrShamirNotConfigured` | `BarrierConfig.Shamir` is nil |
| `ErrShamirThresholdInvalid` | Threshold < 2 or threshold > total |
| `ErrShamirDuplicateShare` | Same share submitted twice to accumulator |
| `ErrShamirQuorumExpired` | Accumulator TTL (5 min) elapsed |
| `ErrShamirQuorumIncomplete` | Not enough shares provided |
| `ErrShamirCombineFailed` | Share reconstruction failed |
| `ErrShamirShareNotFound` | Requested share index not in storage |
| `ErrShamirNoSharesFound` | No shares exist in storage |
| `ErrShamirVerificationFailed` | Share integrity check failed |
| `ErrShamirStorageFailed` | Storage backend operation failed |
| `ErrShamirNilStorage` | Nil storage passed to `NewShamirStrategy` |
| `ErrShamirSplitFailed` | Shamir split operation failed |
| `ErrShamirSerializationFailed` | JSON marshal/unmarshal failure |
| `ErrRecoveryKeysNotFound` | No recovery key metadata in storage |
| `ErrRootTokenVerificationFailed` | Share verification failed during token generation |

## GetMasterKey

`GetMasterKey` returns a copy of the DEK for external integration (e.g., go-dragondb). The barrier must be unsealed.

```go
dek, err := barrier.GetMasterKey()
if err != nil {
    // err == ErrSealed, ErrEncryptorNotAvailable, or ErrHardwareEncryptorRequired
}
defer mem.Zero(dek) // caller must zero when done
// dek is a copy; modifying it does not affect the barrier.
```

## GuardedBuffer (pkg/crypto/mem)

`GuardedBuffer` provides OS-level memory protection for sensitive key material.

**Linux implementation:**

| Protection | Mechanism |
|-----------|-----------|
| Overflow/underflow detection | Leading + trailing guard pages (`mprotect(PROT_NONE)`) |
| Swap prevention | `mlock` locks data pages into RAM |
| Cleanup | `Free()` zeros data, then `munlock` + `munmap` |
| Concurrent safety | `atomic.Bool` for freed state (lock-free) |

**Memory layout:**
```
[guard page PROT_NONE | data pages PROT_READ|PROT_WRITE | guard page PROT_NONE]
```

On non-Linux platforms, the implementation degrades to a heap allocation with guaranteed zeroing on `Free`.

```go
buf, err := mem.NewGuardedBuffer(32)
if err != nil { ... }
defer buf.Free() // zeros + munlock + munmap

buf.Write(secretKey)       // copy data in
data := buf.Bytes()        // read interior slice
buf.Zero()                 // overwrite with zeros without freeing

clone, _ := buf.Clone()    // independent copy with same protections
defer clone.Free()
```

After `Free()`, any call to `Bytes()`, `Write()`, `Zero()`, or `Clone()` panics.

## See Also

- [LUKS + Barrier Layered Architecture](barrier.md) -- LUKS storage backend and dual-layer encryption
- [API Reference](api.md) -- REST endpoint reference for barrier operations
- [PIN Management](pin.md) -- PIN-based authentication for barrier unseal
- [Configuration Reference](../configuration/README.md)
- [Backend Documentation](../backends/README.md)
