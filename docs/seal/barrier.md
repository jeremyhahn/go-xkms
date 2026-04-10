# LUKS Storage Backend and Layered Barrier Architecture

The `pkg/storage/luks/` package provides a `storage.Backend` implementation backed by a LUKS2 encrypted volume. When combined with the barrier from `pkg/seal/`, this creates a layered encryption architecture where LUKS provides kernel-level full-disk encryption and the barrier provides application-level AES-256-GCM encryption.

## Layered Architecture

The barrier ALWAYS wraps the base storage backend. LUKS is an optional base layer underneath.

```
Desktop (no LUKS):  passwords --> Barrier --> filestorage.Backend
Desktop (LUKS):     passwords --> Barrier --> luks.Backend --> filestorage.Backend
```

When LUKS is active, data passes through two independent encryption layers:

| Layer | Encryption | Scope | Key Management |
|-------|-----------|-------|----------------|
| Barrier (inner) | AES-256-GCM | Per-value | Root key sealed by strategy (TPM2, software, etc.) |
| LUKS (outer) | AES-256-XTS | Full volume | Passphrase via Argon2id (kernel dm-crypt) |

The barrier encrypts each value individually before writing it to the storage backend. If that backend happens to be a LUKS volume, the already-encrypted ciphertext is written to a LUKS-encrypted filesystem. This is defense-in-depth: LUKS protects the volume at the kernel level (FIPS-validated dm-crypt), and the barrier protects individual values at the application level.

## pkg/storage/luks Package

### VolumeOperator Interface

The `VolumeOperator` interface decouples the storage backend from any concrete LUKS implementation. The xkey module's `luks.Volume` satisfies this contract.

```go
type VolumeOperator interface {
    Exists() bool
    IsLUKS() bool
    IsMounted() bool
    IsOpen() bool
    GetMountPoint() string
    Create(sizeBytes int64, passphrase string) error
    Unlock(passphrase string) error
    Lock() error
}
```

### Backend

`luks.Backend` implements `storage.Backend`. When the volume is unlocked, all operations delegate to a `filestorage.Backend` rooted at the LUKS mount point. When locked, every operation returns `ErrVolumeLocked`.

```go
b := luks.NewBackend(volumeOperator)

// First-time setup: create volume, unlock, prepare delegate.
b.Initialize(64*1024*1024, "passphrase")

// Subsequent startups: just unlock.
b.Unlock("passphrase")

// Storage operations (delegated to file backend on mount point).
b.Put(ctx, "key", []byte("value"))
data, _ := b.Get(ctx, "key")

// Lock when done.
b.Lock()
```

State management uses `sync/atomic` for lock-free fast-path checks. The mutex protects only the delegate pointer assignment during Unlock/Lock transitions.

### Error Types

| Error | Condition |
|-------|-----------|
| `ErrVolumeLocked` | Storage operation attempted while volume is locked |
| `ErrVolumeAlreadyUnlocked` | `Unlock` called on an already-unlocked backend |
| `ErrVolumeNotInitialized` | Volume does not exist on disk |
| `ErrInitializeRequiresPassphrase` | `Initialize` called with empty passphrase |
| `ErrDelegateCreateFailed` | File storage delegate could not be created on mount point |
| `ErrVolumeLockFailed` | Volume could not be locked (unmount/close failed) |

## Barrier Integration

The barrier sits above whatever base backend is in use. The application constructs the storage stack at startup:

```
Without LUKS:
    base := filestorage.New("/home/user/.xkey/data")
    barrier := seal.NewBarrier(logger, base, barrierConfig, strategies...)

With LUKS:
    luksBackend := luks.NewBackend(volume)
    luksBackend.Unlock(passphrase)
    barrier := seal.NewBarrier(logger, luksBackend, barrierConfig, strategies...)
```

In both cases, the barrier is initialized and unsealed identically. The barrier does not know or care whether its underlying backend is a plain filesystem or a LUKS volume.

## Barrier Auto-Unseal

When the software sealing strategy is used, the barrier requires a password to unseal. To enable unattended startup, the barrier password can be TPM-sealed for automatic retrieval.

### Flow

```
Boot
  |
  v
TPM2 available?
  |
  +-- Yes: UnsealData(BarrierAutoUnsealBlobID) --> password
  |         |
  |         v
  |        Barrier.Unseal(password)
  |
  +-- No:  Prompt user for barrier password
            |
            v
           Barrier.Unseal(password)
```

### Configuration

The auto-unseal blob ID is stored in the application configuration:

| Field | Description |
|-------|-------------|
| `BarrierAutoUnsealBlobID` | Sealed blob ID containing the barrier password |

When non-empty, the application attempts to unseal the blob via the TPM2 seal service at startup. If the PCR state matches, the barrier password is recovered and the barrier unseals without user interaction.

On shutdown, the auto-unseal blob is re-sealed with current PCR values to account for kernel or firmware updates that changed the measured boot state.

## Password Encryption Behind Barrier

Static passwords (and other sensitive data) are stored through the barrier backend. This means all stored values are transparently encrypted by the barrier's AES-256-GCM layer:

```
Password store --> Barrier.Put(ctx, "staticpw/myserver.json", encrypted_pw) --> AES-256-GCM --> base backend
```

When LUKS is also active, the write passes through both encryption layers before reaching disk. The password store itself may also encrypt individual password fields with a symmetric encrypter, providing a third layer for the password value specifically.

## Security Properties

| Property | LUKS Layer | Barrier Layer |
|----------|-----------|---------------|
| Algorithm | AES-256-XTS (dm-crypt) | AES-256-GCM |
| Scope | Full volume | Per-value |
| FIPS compliant | Yes (kernel dm-crypt) | Application-level |
| Key protection | Passphrase + Argon2id | Root key sealed by strategy |
| Key in memory | dm-crypt kernel keyring | DEK zeroed on seal |
| Auth tag | None (XTS mode) | 16-byte GCM tag per value |

The GCM authentication tag on the barrier layer provides integrity verification that XTS mode alone does not offer. An attacker who modifies ciphertext in the LUKS volume would still fail the GCM tag check when the barrier decrypts.

## See Also

- [Barrier Encryption Architecture](README.md) -- Barrier design, sealing strategies, Shamir
- [API Reference](api.md) -- REST endpoints for barrier operations
- [PIN Management](pin.md) -- PIN-based barrier authentication
