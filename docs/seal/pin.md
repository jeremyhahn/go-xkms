# PIN Management

The `pkg/pin` package provides dual-PIN management with two backend implementations: software hash-based (`SoftwareBackend`) and TPM 2.0 platform auth-based (`TPM2Backend`). A `Service` wraps the chosen backend and serves as the single entry point for all PIN operations, including FIDO2 authenticator integration.

## PIN Model

The PIN model supports two roles. The SO PIN authorizes administrative operations such as setting or resetting the user PIN. The user PIN gates day-to-day authentication and barrier unseal.

```
  +------------------+        authorizes        +------------------+
  |    SO PIN        | -----------------------> |  User PIN Setup  |
  |  (administrator) |                          |  Lockout Reset   |
  +------------------+                          +------------------+
                                                        |
                                                        v
                                                +------------------+
                                                |    User PIN      |
                                                |  (daily auth)    |
                                                +------------------+
                                                        |
                                                        v
                                                +------------------+
                                                |  Barrier Unseal  |
                                                |  Key Operations  |
                                                +------------------+
```

| Role | Purpose | Set By | Required For |
|------|---------|--------|--------------|
| SO PIN | Administrative control | First setup or current SO PIN holder | Setting/resetting user PIN |
| User PIN | Daily authentication | SO PIN authorization | Barrier unseal, key operations |

Minimum PIN length is 6 characters, enforced by both the `Service` and backends.

## Backend Comparison

| Feature | Software (`SoftwareBackend`) | TPM 2.0 (`TPM2Backend`) |
|---------|------------------------------|--------------------------|
| Hash algorithm | Argon2id (default) / PBKDF2 (FIPS) | None -- TPM verifies directly |
| SO PIN | Hashed and stored in `storage.Backend` | Not supported (returns `ErrPINNotSet`) |
| User PIN | Hashed and stored in `storage.Backend` | PlatformSRK password auth via `PlatformAuthProvider` |
| Lockout | None -- hash cost is the security mechanism | TPM Dictionary Attack Protection (hardware counters) |
| Persistence | PINRecord JSON blobs in `storage.Backend` | TPM hardware state |
| FIDO2 hash | Cached in `mem.GuardedBuffer` | Cached in `mem.GuardedBuffer` |

## PINBackend Interface

Both backends implement this interface:

```go
type PINBackend interface {
    Strategy() StrategyID
    SetSOPIN(currentSOPIN, newSOPIN string) error
    SetUserPIN(soPIN, newUserPIN string) error
    ChangeSOPIN(currentSOPIN, newSOPIN string) error
    ChangeUserPIN(currentUserPIN, newUserPIN string) error
    VerifySOPIN(pin string) error
    VerifyUserPIN(pin string) error
    IsInitialized() bool
    SOPINSet() bool
    UserPINSet() bool
    GetLockoutStatus() *LockoutStatus
    ResetLockout(soPIN string) error
}
```

## Software Backend

`SoftwareBackend` hashes PINs with a configurable algorithm and persists the results as JSON blobs via a `storage.Backend`.

### Hash Configuration

`HashConfig` selects the algorithm and its parameters. Three constructors are provided:

| Constructor | Algorithm | Parameters |
|-------------|-----------|------------|
| `DefaultHashConfig()` | Argon2id | time=3, memory=64 MiB, threads=4, keyLen=32, saltLen=16 |
| `FIPSHashConfig()` | PBKDF2-SHA256 | iterations=600000, keyLen=32, saltLen=16 |
| `AutoDetectHashConfig()` | Auto | Calls `fips.Enabled()` -- PBKDF2 when true, Argon2id otherwise |

### PINRecord Format

Each PIN (SO and user) is stored as an independent PINRecord:

```json
{
  "algorithm": "argon2id",
  "hash": "<base64>",
  "salt": "<base64>",
  "params": {
    "time": 3,
    "memory": 65536,
    "threads": 4,
    "key_len": 32
  }
}
```

For PBKDF2 records the `params` field contains:

```json
{
  "hash": "SHA-256",
  "iterations": 600000,
  "key_len": 32
}
```

Records are stored under the keys `so-pin` and `user-pin` in the `storage.Backend`.

### Verification

PIN verification re-derives the hash from the stored salt and parameters, then performs a constant-time comparison using `crypto/subtle.ConstantTimeCompare`.

### Lockout

`SoftwareBackend` does not implement lockout counters. `GetLockoutStatus()` returns `nil` and `ResetLockout()` returns `nil`. The hash cost (Argon2id memory-hardness or PBKDF2 iteration count) serves as the brute-force protection mechanism.

## TPM2 Backend

`TPM2Backend` delegates user PIN verification to the TPM via a `PlatformAuthProvider`. The user PIN is the PlatformSRK's `UserAuth` (password auth) value. The TPM accepts or rejects the PIN directly -- no local hash is stored.

### PlatformAuthProvider Interface

```go
type PlatformAuthProvider interface {
    VerifyAuth(pin string) error
    ChangeAuth(currentPIN, newPIN string) error
    GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error)
    DictionaryAttackLockoutReset(lockoutAuth []byte) error
    IsProvisioned() bool
}
```

### Operations

| Operation | Implementation |
|-----------|----------------|
| `VerifyUserPIN(pin)` | Calls `platformStore.VerifyAuth(pin)` -- TPM accepts or rejects |
| `ChangeUserPIN(current, new)` | Calls `platformStore.ChangeAuth(current, new)` -- recreates primary with new auth |
| `SetUserPIN(_, pin)` | Verifies PIN against existing SRK auth; caches FIDO2 hash on success |
| `SetSOPIN` / `VerifySOPIN` / `ChangeSOPIN` | Not supported -- returns `ErrPINNotSet` |

### Lockout

`TPM2Backend` reports real TPM dictionary attack protection counters. `GetLockoutStatus()` queries `PlatformAuthProvider.GetLockoutInfo()` and returns a `LockoutStatus` with `FailedAttempts`, `MaxAttempts`, `IsLocked`, and `RecoverySeconds`.

On auth failure, the backend queries DA counters and returns:

- `ErrTPMLocked` when `failedAttempts >= maxFail` (lockout active).
- `ErrPINInvalidWithStatus` otherwise, with remaining attempt count.

`ResetLockout(lockoutAuth)` calls `DictionaryAttackLockoutReset` on the provider.

## FIDO2 Integration

Both backends cache the CTAP2-mandated PIN hash (`SHA-256(PIN)[:16]`) in a `mem.GuardedBuffer` (mlock'd, guard-paged memory). The hash is computed and cached when:

- A user PIN is set (`SetUserPIN`).
- A user PIN is changed (`ChangeUserPIN`).
- A user PIN is verified after restart (`VerifyUserPIN` -- lazy recomputation when no cached hash exists).

The `Service` also supports a `FIDO2PINHashSetter` callback to push updated hashes to the FIDO2 authenticator:

```go
svc.SetFIDO2HashSetter(func(hash []byte) {
    authenticator.UpdatePINHash(hash)
})
```

Both backends implement `FIDO2HashVerifier` for verifying incoming FIDO2 PIN hashes via constant-time comparison against the cached `GuardedBuffer`.

## Barrier Integration

The typical flow combines PIN verification with barrier unseal:

```go
// 1. Verify user PIN
if err := svc.VerifyUserPIN(userPIN); err != nil {
    return err
}

// 2. Unseal barrier using PIN as credential
creds := seal.Credentials{Secret: userPIN}
if err := barrier.Unseal(ctx, creds); err != nil {
    return err
}

// 3. Storage is now accessible
data, err := barrier.Get("secrets/api-key")
```

## Go API

### Software Backend

```go
import (
    "log/slog"
    "github.com/jeremyhahn/go-xkms/pkg/pin"
    filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

store, err := filestorage.New("/var/lib/xkms/pin")
if err != nil {
    return err
}

hashConfig := pin.AutoDetectHashConfig()
backend, err := pin.NewSoftwareBackend(store, hashConfig)
if err != nil {
    return err
}

svc := pin.NewService(backend, slog.Default())

// First-time SO PIN setup
err = svc.SetSOPIN("", "my-so-pin-123")

// Set user PIN (requires SO PIN)
err = svc.SetUserPIN("my-so-pin-123", "my-user-pin-456")

// Daily verification
err = svc.VerifyUserPIN("my-user-pin-456")
```

### TPM2 Backend

```go
import (
    "log/slog"
    "github.com/jeremyhahn/go-xkms/pkg/pin"
)

backend := pin.NewTPM2Backend(platformKeyStore)
svc := pin.NewService(backend, slog.Default())

// Verify user PIN (delegates to TPM SRK auth)
err := svc.VerifyUserPIN("my-tpm-pin")

// Change user PIN (recreates SRK with new auth)
err = svc.ChangeUserPIN("my-tpm-pin", "new-tpm-pin")

// Check DA lockout status
if status := svc.GetLockoutStatus(); status != nil && status.IsLocked {
    log.Printf("TPM locked, recovery in %d seconds", status.RecoverySeconds)
}
```

## Error Reference

| Error | Type | Condition |
|-------|------|-----------|
| `ErrPINNotSet` | sentinel | Operation requires a PIN that has not been set |
| `ErrPINInvalid` | sentinel | Provided PIN does not match |
| `ErrPINTooShort` | sentinel | PIN is shorter than 6 characters |
| `ErrPINAlreadySet` | sentinel | Attempted to set a PIN that is already set (use Change) |
| `ErrSOPINRequired` | sentinel | Operation requires SO PIN authorization |
| `ErrInvalidCurrentPIN` | sentinel | Current PIN verification failed during a change |
| `ErrStateCorrupted` | sentinel | PIN state contains invalid JSON |
| `ErrStrategyNotSet` | sentinel | No PIN strategy has been configured |
| `ErrUnsupportedHashAlgorithm` | sentinel | Unknown hash algorithm in `HashConfig` or `PINRecord` |
| `ErrTPMLocked` | struct | TPM DA lockout active; includes `LockoutStatus` |
| `ErrPINInvalidWithStatus` | struct | Auth failure with remaining attempts via `LockoutStatus` |
| `ErrStoragePersistFailed` | struct | Failed to write PIN record to `storage.Backend` |
| `ErrStorageLoadFailed` | struct | Failed to read PIN record from `storage.Backend` |
| `ErrUnsupportedPBKDF2Hash` | struct | Unsupported hash function specified for PBKDF2 |

## Security Properties

- **Argon2id** (RFC 9106) with 64 MiB memory, 3 iterations, 4 threads -- resistant to GPU/ASIC brute force.
- **PBKDF2** (NIST SP 800-132) with 600,000 iterations for FIPS 140 compliance.
- **Constant-time comparison** via `crypto/subtle.ConstantTimeCompare` -- prevents timing side-channels.
- **mlock'd guard-paged memory** for FIDO2 hash via `mem.GuardedBuffer` -- prevents swap and detects buffer overruns.
- **Lock-free concurrency** -- all mutable state managed through `atomic.Pointer`, `atomic.Bool`, and `atomic.Pointer[mem.GuardedBuffer]`.
- **Independent random salts** -- each PIN (SO and user) uses its own random 16-byte salt from `crypto/rand`.
- **Zeroed intermediate values** -- raw PIN bytes and intermediate hashes are zeroed via `mem.Zero` after use.

## See Also

- [Barrier Encryption Architecture](README.md)
- [CLI PIN Commands](../usage/cli/pin.md)
- [Configuration Reference](../configuration/README.md)
- [Setup and Unlock Flow](../../xkey/docs/architecture/setup-and-unlock-flow.md)
