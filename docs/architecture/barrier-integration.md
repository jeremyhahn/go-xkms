# Barrier Integration Architecture

Transparent authenticated encryption at rest across three composable layers.

## Three-Layer Architecture

```
go-quicraft/pkg/seal/     EpochBarrier: AEAD, HKDF-SHA256, epoch rotation, safety tracking
        ^
go-qrdb/pkg/seal/         StorageBarrier: Shamir m-of-n, tenant isolation, root key persistence
        ^
go-xkms/pkg/seal/         Type alias + BarrierConfig, hardware strategies (TPM2, PKCS#11, cloud KMS)
```

Each layer composes the one below it. go-xkms consumers interact with
`seal.Barrier` (a type alias for `qrdbseal.StorageBarrier`), which internally
delegates cryptographic operations to go-quicraft's `EpochBarrier`.

## Layer 1 -- go-quicraft EpochBarrier

The core cryptographic primitive. Holds a 32-byte root key in a memguard
enclave and derives per-epoch data encryption keys (DEKs) via HKDF-SHA256.

**Key derivation:**

```
DEK = HKDF-SHA256(rootKey, salt, info="quicraft/barrier/v1/" || deploymentID || epoch)
```

The `deploymentID` is bound into the HKDF info parameter so two clusters
sharing the same root key produce independent DEKs.

**Supported algorithms:**

| ID   | Algorithm            | Key Size | Nonce Size |
|------|----------------------|----------|------------|
| 0x01 | AES-128-GCM          | 16B      | 12B        |
| 0x02 | AES-192-GCM          | 24B      | 12B        |
| 0x03 | AES-256-GCM          | 32B      | 12B        |
| 0x04 | ChaCha20-Poly1305    | 32B      | 12B        |
| 0x05 | XChaCha20-Poly1305   | 32B      | 24B        |

Default selection is automatic: AES-256-GCM on CPUs with AES-NI (x86-64 or
ARM64 crypto extensions), ChaCha20-Poly1305 otherwise.

**Wire format:**

```
[epoch:8 big-endian][algID:1][nonce:N][ciphertext+tag]
```

The algorithm identifier is embedded in every ciphertext so decryption is
self-describing with no out-of-band negotiation. Each ciphertext is bound to
its epoch via AAD (little-endian epoch), preventing cross-epoch splicing.

**Epoch rotation:**

`Rotate()` increments the epoch, derives a new DEK, and installs it as the
current cipher. Old DEKs remain available for reading data encrypted under
previous epochs. `PurgeEpochsBefore(minEpoch)` removes old DEKs when they are
no longer needed, respecting in-flight reference counts.

**Hardware mode:**

When a `SealingStrategy` provides a `BarrierEncryptor`, the EpochBarrier
delegates all encrypt/decrypt operations to the hardware-backed encryptor and
skips epoch-based DEK derivation. `Rotate` and `PurgeEpochsBefore` return
`ErrHardwareMode` in this configuration.

**Concurrency model:**

Encrypt and Decrypt use a two-phase fast path:
1. Atomic check of `b.unsealed` (zero contention).
2. RLock for the cipher operation (prevents TOCTOU with Seal).

Seal, Unseal, Initialize, and Rotate acquire the exclusive write lock.

**Brute-force protection:**

After 5 consecutive failed Unseal attempts, exponential backoff activates
(1s base, doubling per attempt, capped at 60s). Backoff state is persisted in
the sealed root key blob to survive process restarts.

## Layer 2 -- go-qrdb StorageBarrier

Wraps a `StorageBackend` with transparent encryption. All values written
through the barrier are encrypted via the EpochBarrier; keys remain in
plaintext. Adds lifecycle management, Shamir secret sharing, and tenant
isolation.

**Lifecycle:**

1. **Initialize** -- Generate root key, seal with best available strategy,
   persist sealed blob, transition to unsealed.
2. **Unseal** -- Load sealed blob from storage, unseal via matching strategy,
   re-derive DEKs for all known epochs, transition to unsealed.
3. **Seal** -- Zero root key and DEKs from memory, block all storage
   operations until next Unseal.

**Strategy selection:**

Strategies are evaluated in preference order. The first available strategy
wins:

```
TPM2 > PKCS#11 > AWS KMS > GCP KMS > Azure KV > Vault > Shamir > Software
```

**Tenant isolation:**

`TenantBarrier` wraps a `StorageBarrier` with a namespace prefix
(`{tenantID}/`). Each tenant gets an independent barrier with its own root
key, seal state, and strategy. The `BarrierRegistry` manages the system
barrier and all tenant barriers:

```go
registry, _ := seal.NewBarrierRegistry(systemBarrier)
tenant, _   := registry.RegisterTenant("acme-corp")
registry.InitializeTenant(ctx, "acme-corp", creds)
```

## Layer 3 -- go-xkms Barrier

go-xkms defines `Barrier` as a type alias for `qrdbseal.StorageBarrier`:

```go
type Barrier = qrdbseal.StorageBarrier
```

No adapter layer is needed because `storage.Backend` and
`qrdbseal.StorageBackend` are interface-compatible. go-xkms provides:

- `BarrierConfig` with `PreferenceOrder`, `RootKeyPath`, `AuditLogger`, and
  `Shamir` fields.
- `NewBarrier()` and `NewTenantBarrier()` constructors that translate config
  and delegate to go-qrdb.
- `SoftwareStrategy` that defers passphrase binding to Seal/Unseal time
  (unlike go-quicraft's version which binds at construction).
- `NewShamirStrategy()` for Shamir m-of-n with storage-backed shares.

**What lives in go-xkms:**

| Component | File | Description |
|-----------|------|-------------|
| TPM2 Strategy | `pkg/seal/strategy_tpm2.go` | TPM 2.0 SRK hierarchy wrapping |
| PKCS#11 Strategy | `pkg/seal/strategy_pkcs11.go` | HSM token wrapping key |
| Cloud Strategies | `pkg/seal/strategy_cloud.go` | AWS KMS, GCP KMS, Azure KV, Vault |
| PlatformSealer | `pkg/seal/platform_sealer.go` | Strategy routing for arbitrary data |
| Policy | `pkg/seal/policy/` | TPM PCR attestation policies |

## Shamir M-of-N Initialization Ceremony

Shamir secret sharing supports two modes:

**Direct mode** (ShamirStrategy registered): The root key itself is split
into N shares. Reconstruction yields the root key directly.

**Credential mode** (no ShamirStrategy): The barrier is initialized with a
password, then the password is split into N shares. Reconstruction yields the
password, which unseals the barrier normally.

**Initialization flow:**

```
InitializeShamir(ctx, creds)
  |-- validate threshold (2 <= M <= N)
  |-- Initialize barrier (generate root key, seal, persist)
  |-- Split secret into N shares via Shamir polynomial interpolation
  '-- Return ShamirInitResult{Shares, Threshold, TotalShares}
```

Security officers receive one share each. Shares must be stored separately in
secure, offline media.

**Unseal flow (incremental):**

```
UnsealWithShare(ctx, shareValue)
  |-- Load or create ShareAccumulator (TTL: 5 minutes default)
  |-- Add share, check for duplicates
  |-- If threshold not met: return QuorumProgress{Required, Submitted, Complete=false}
  '-- If threshold met: reconstruct secret, unseal barrier, return Complete=true
```

**Unseal flow (batch):**

```
UnsealWithShares(ctx, shareValues)
  |-- Validate len(shares) >= threshold
  |-- Reconstruct secret from shares
  '-- Unseal barrier (direct or credential mode)
```

The quorum accumulator expires after the configured TTL (default 5 minutes).
If the threshold is not met within this window, accumulated shares are
discarded and the ceremony must restart.

## AEAD Safety Tracking

The EpochBarrier enforces two safety limits per epoch to prevent cryptographic
degradation:

**BytesTracker** -- Tracks total plaintext bytes encrypted with a single DEK.
Default limit: 350GB per NIST SP 800-38D. When the limit is reached,
`ErrBytesLimitExceeded` is returned and key rotation is required. The tracker
resets automatically on `Rotate()`.

**NonceTracker** -- Detects nonce reuse via a set of observed nonces. Nonce
reuse is catastrophic for all AEAD ciphers (breaks authentication for AES-GCM,
leaks keystream for ChaCha20-Poly1305). Returns `ErrNonceReuse` on detection.
The tracker clears automatically on `Rotate()`.

Both trackers use atomic operations and are lock-free on the hot path.

## SDK Barrier Service

The `BarrierServicer` interface exposes 17 operations available across all
transports (REST, gRPC, QUIC, MCP, Unix, embedded):

| Operation                     | Description                                       |
|-------------------------------|---------------------------------------------------|
| `BarrierInitialize`           | Initialize barrier with a secret                  |
| `BarrierUnseal`               | Unseal barrier with a secret                      |
| `BarrierSeal`                 | Seal barrier, block all operations                |
| `BarrierStatus`               | Query seal state, strategy, hardware-backed flag   |
| `BarrierInitializeShamir`     | Initialize with Shamir m-of-n, return shares      |
| `BarrierUnsealWithShare`      | Submit single share toward quorum                 |
| `BarrierUnsealWithShares`     | Submit all shares at once (batch unseal)           |
| `BarrierShamirListShares`     | List share metadata (count, threshold, total)      |
| `BarrierShamirDeleteShare`    | Delete a specific share by index                  |
| `BarrierShamirDeleteAllShares`| Delete all shares                                 |
| `BarrierShamirVerify`         | Verify share integrity                            |
| `BarrierRekey`                | Generate new shares with new threshold             |
| `BarrierGenerateRecoveryKeys` | Generate disaster recovery keys                   |
| `BarrierRecoverWithKeys`      | Recover using recovery keys                       |
| `BarrierDeleteRecoveryKeys`   | Delete stored recovery keys                       |
| `BarrierHasRecoveryKeys`      | Check if recovery keys exist                      |
| `BarrierGenerateRootToken`    | Generate root token from Shamir shares            |

## Configuration

```go
config := seal.BarrierConfig{
    PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
    RootKeyPath:     "barrier/root-key",
    Shamir: &seal.ShamirConfig{
        Threshold:   3,
        TotalShares: 5,
        QuorumTTL:   5 * time.Minute,
    },
}

barrier, _ := seal.NewBarrier(logger, storageBackend, config,
    seal.NewSoftwareStrategy(),
)
```

The `PreferenceOrder` field controls strategy selection priority. If omitted,
`DefaultPreferenceOrder` is used (hardware-first). The `RootKeyPath` specifies
the storage key where the sealed root key blob is persisted.

## See Also

- [Architecture Overview](overview.md) -- Three-layer dependency architecture
- [Storage Architecture](storage.md) -- Consolidated storage layer from go-qrdb
