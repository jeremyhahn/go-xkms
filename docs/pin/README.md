# Unified PIN Service

The `pkg/pin` package provides PIN management with two pluggable backend implementations: **TPM2** and **Software**. The `Service` type is the single entry point for all PIN operations. It delegates verification to the backend's native mechanism and manages the FIDO2 authenticator hash callback.

## Architecture

```
Caller
  |
  v
+------------------+     FIDO2PINHashSetter callback
|    Service        |------------------------------> Authenticator
|  (single entry    |                                (SHA-256(PIN)[:16])
|   point)          |
+--------+---------+
         |
         v
+------------------+
|   PINBackend     |  <-- interface
+------------------+
  |              |
  v              v
TPM2         Software
(SRK auth)   (Argon2id/PBKDF2)
```

**Service** (`service.go`) wraps a `PINBackend`, validates PIN length (minimum 6 characters), pushes FIDO2 hashes to the authenticator on set/change, and delegates all verification to the backend.

**PINBackend** (`backend.go`) is the interface each backend implements. Methods cover SO PIN and user PIN lifecycle: `Set`, `Change`, `Verify`, plus `GetLockoutStatus` and `ResetLockout`.

All mutable state in backend implementations uses `sync/atomic` operations (`atomic.Bool`, `atomic.Pointer`) for lock-free concurrent access.

## Backend Comparison

| Aspect | TPM2 | Software |
|--------|------|----------|
| Strategy ID | `tpm2` | `software` |
| PIN verification | PlatformSRK password auth via `PlatformAuthProvider` | Argon2id or PBKDF2 hash + constant-time compare |
| SO PIN | Not supported (returns `ErrPINNotSet`) | Hash-based, persisted to `storage.Backend` |
| User PIN | PlatformSRK auth value | Hash-based, persisted to `storage.Backend` |
| Lockout | TPM dictionary attack protection (hardware counters) | None (hash is the security boundary) |
| FIDO2 hash | Cached in `mem.GuardedBuffer` on verify/set/change | Cached in `mem.GuardedBuffer` on verify/set/change |
| Concurrency | `atomic.Bool` + `atomic.Pointer` | `atomic.Bool` + `atomic.Pointer` |
| Constructor | `NewTPM2Backend(platformAuthProvider)` | `NewSoftwareBackend(store, hashConfig)` |

## TPM2 Backend

The TPM2 backend delegates all user PIN verification to the TPM 2.0 hardware through the `PlatformAuthProvider` interface. The user PIN IS the PlatformSRK's password auth value.

### How it works

- **VerifyUserPIN**: Calls `platformStore.VerifyAuth(pin)`, which executes `tpm.VerifyAuth(srkHandle, pin)`. The TPM accepts or rejects the auth value.
- **ChangeUserPIN**: Calls `platformStore.ChangeAuth(currentPIN, newPIN)`, which recreates the PlatformSRK with the new auth value.
- **SetUserPIN**: Verifies the PIN matches the PlatformSRK's existing auth, then caches the FIDO2 hash. The `soPIN` parameter is ignored (exists to satisfy the interface).
- **Lockout**: Real TPM dictionary attack counters are queried via `GetLockoutInfo()`. Auth failures return `ErrPINInvalidWithStatus` (with remaining attempts) or `ErrTPMLocked` when the DA counter is exhausted.
- **SO PIN**: Not stored or supported. `SetSOPIN`, `ChangeSOPIN`, and `VerifySOPIN` all return `ErrPINNotSet`.
- **Initialization**: `IsInitialized()` returns `platformStore.IsProvisioned()`. If the platform is provisioned at construction time, `UserPINSet()` is optimistically set to `true`.

### PlatformAuthProvider interface

```go
type PlatformAuthProvider interface {
    VerifyAuth(pin string) error
    ChangeAuth(currentPIN, newPIN string) error
    GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error)
    DictionaryAttackLockoutReset(lockoutAuth []byte) error
    IsProvisioned() bool
}
```

The pin package detects TPM authorization failures (`TPM_RC_BAD_AUTH`, `TPM_RC_AUTH_FAIL`) via string matching on the error message, keeping the package decoupled from `go-tpm` types.

## Software Backend

The software backend uses Argon2id or PBKDF2 password hashing to protect PINs at rest. PINs are hashed with a random salt and stored as `PINRecord` JSON blobs in a `storage.Backend`.

### How it works

- **Hashing**: Each PIN is hashed using the configured algorithm. The hash, salt, and algorithm-specific parameters are stored together in a `PINRecord`.
- **Verification**: The hash is re-derived from the stored salt and parameters, then compared using `subtle.ConstantTimeCompare`.
- **Persistence**: Both SO and user PIN records are persisted to `storage.Backend` (file or memory) and survive process restarts. Pass `nil` for the store parameter for in-memory-only operation (tests).
- **Initialization on construction**: `NewSoftwareBackend` loads existing records from storage and sets `SOPINSet()`/`UserPINSet()` accordingly.
- **Lockout**: None. `GetLockoutStatus()` returns `nil` and `ResetLockout()` is a no-op. The hash itself is the security boundary.
- **SO and User PIN**: Both are fully supported with a PKCS#11-style flow (set SO PIN first, then set user PIN with SO PIN authorization).

### Algorithm selection

- **Default**: Argon2id (`time=3, memory=64 MiB, threads=4, keyLen=32, saltLen=16`)
- **FIPS 140 mode**: PBKDF2 with SHA-256 and 600,000 iterations (NIST SP 800-132)
- **Auto-detection**: `AutoDetectHashConfig()` returns `FIPSHashConfig()` when `fips.Enabled()` is true, otherwise `DefaultHashConfig()`

## HashConfig

`HashConfig` holds configurable parameters for PIN hashing. Only the parameters relevant to the selected algorithm need to be populated.

```go
type HashConfig struct {
    Algorithm  HashAlgorithm  // "argon2id" or "pbkdf2"
    Time       uint32         // Argon2id: passes over memory
    Memory     uint32         // Argon2id: memory usage in KiB
    Threads    uint8          // Argon2id: degree of parallelism
    KeyLen     uint32         // Output key length in bytes
    SaltLen    int            // Random salt length in bytes
    PBKDF2Hash types.HashName // PBKDF2: underlying hash ("SHA-256", "SHA-384", "SHA-512")
    Iterations int            // PBKDF2: iteration count
}
```

Preset configurations:

| Function | Algorithm | Parameters |
|----------|-----------|------------|
| `DefaultHashConfig()` | Argon2id | time=3, memory=64 MiB, threads=4, keyLen=32, saltLen=16 |
| `FIPSHashConfig()` | PBKDF2 | hash=SHA-256, iterations=600000, keyLen=32, saltLen=16 |
| `AutoDetectHashConfig()` | Auto | Selects based on `fips.Enabled()` |

## PINRecord

Each PIN (SO or user) is stored as a self-describing JSON record that includes the algorithm, hash, salt, and algorithm-specific parameters. This allows verification without out-of-band parameter knowledge.

```go
type PINRecord struct {
    Algorithm string          `json:"algorithm"`        // "argon2id" or "pbkdf2"
    Hash      []byte          `json:"hash"`             // Derived key bytes
    Salt      []byte          `json:"salt"`             // Random salt
    Params    json.RawMessage `json:"params,omitempty"` // Algorithm-specific parameters
}
```

Storage keys: `"so-pin"` for the SO PIN record, `"user-pin"` for the user PIN record.

## FIDO2 Integration

The Service integrates with FIDO2/CTAP2 authenticators. When a user PIN is set or changed:

1. The backend stores/verifies the PIN using its native mechanism.
2. `Service.pushFIDO2Hash` computes `SHA-256(PIN)[:16]` (the CTAP2-mandated 16-byte PIN hash).
3. The hash is pushed to the authenticator via the registered `FIDO2PINHashSetter` callback.

Both backends cache the 16-byte FIDO2 hash in a `mem.GuardedBuffer` (`mlock`'d, guard-paged memory on Linux) via `atomic.Pointer`. After a restart, the hash is lazily recomputed on the first successful `VerifyUserPIN` call.

Backends that cache the FIDO2 hash also implement the `FIDO2HashVerifier` interface, allowing the Service to verify incoming FIDO2 PIN hashes without knowing the raw PIN:

```go
type FIDO2HashVerifier interface {
    VerifyFIDO2Hash(hash []byte) bool
}
```

### Secure memory

- The FIDO2 hash is held in `mem.GuardedBuffer` (mlock'd, guard-paged) rather than a plain `[]byte`.
- All intermediate PIN plaintexts are zeroed via `mem.Zero()` after use.
- Call `Close()` on the backend to free the guarded buffer when done.

### Registering the callback

```go
svc.SetFIDO2HashSetter(func(hash []byte) {
    authenticator.SetPINHash(hash)
})
```

## Usage

```go
import (
    "log/slog"

    "github.com/jeremyhahn/go-xkms/pkg/pin"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
    filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// --- TPM2 backend (via PlatformKeyStore) ---
tpm2Backend := pin.NewTPM2Backend(platformKeyStore)
svc := pin.NewService(tpm2Backend, slog.Default())

// Verify user PIN (PlatformSRK auth)
err := svc.VerifyUserPIN("my-user-pin")

// Change user PIN (recreates SRK with new auth)
err = svc.ChangeUserPIN("my-user-pin", "new-user-pin")

// Check TPM lockout status
status := svc.GetLockoutStatus()
if status != nil && status.IsLocked {
    err = svc.ResetLockout("lockout-auth")
}

// --- Software backend with file persistence ---
store, _ := filestorage.New("/path/to/pin-data")
hashConfig := pin.AutoDetectHashConfig()
swBackend, _ := pin.NewSoftwareBackend(store, hashConfig)
defer swBackend.Close()
svc = pin.NewService(swBackend, slog.Default())

// Initialize: set SO PIN, then user PIN
err = svc.SetSOPIN("", "my-secure-so-pin")
err = svc.SetUserPIN("my-secure-so-pin", "my-user-pin")

// Verify
err = svc.VerifyUserPIN("my-user-pin")

// Change
err = svc.ChangeUserPIN("my-user-pin", "new-user-pin")

// --- Software backend in-memory (tests) ---
swBackend, _ = pin.NewSoftwareBackend(nil, pin.DefaultHashConfig())
defer swBackend.Close()
svc = pin.NewService(swBackend, slog.Default())
```

## Error Reference

### Sentinel errors

| Error | Meaning |
|-------|---------|
| `ErrPINNotSet` | PIN has not been configured |
| `ErrPINInvalid` | Provided PIN is incorrect |
| `ErrPINLocked` | Too many failed attempts; lockout active |
| `ErrPINTooShort` | PIN is shorter than 6 characters |
| `ErrPINAlreadySet` | PIN is already set; use `Change` instead |
| `ErrInvalidCurrentPIN` | Current PIN verification failed during change |
| `ErrSOPINRequired` | SO PIN must be set before user PIN (software backend) |
| `ErrHierarchyAuthMismatch` | TPM hierarchy has auth from a previous session; factory reset required |
| `ErrUnsupportedHashAlgorithm` | Unknown hash algorithm in HashConfig or PINRecord |
| `ErrStateCorrupted` | Legacy state file contains invalid data |
| `ErrStrategyNotSet` | No PIN strategy has been configured |

### Typed errors

| Error type | Meaning |
|------------|---------|
| `*ErrTPMLocked` | TPM is locked out due to DA protection; includes `LockoutStatus` with recovery time |
| `*ErrPINInvalidWithStatus` | Auth failure with DA counter info (remaining attempts, max attempts) |
| `*ErrStoragePersistFailed` | Failed to write PIN record to `storage.Backend`; wraps cause |
| `*ErrStorageLoadFailed` | Failed to read PIN record from `storage.Backend`; wraps cause |
| `*ErrUnsupportedPBKDF2Hash` | Unsupported hash function specified for PBKDF2 (valid: SHA-256, SHA-384, SHA-512) |

## Security Properties

- **TPM2 backend**: PIN verification is hardware-enforced. The TPM's dictionary attack protection provides rate limiting with configurable lockout thresholds and recovery intervals. PIN values never leave the TPM boundary for verification.
- **Software backend**: PINs are protected by memory-hard (Argon2id) or iteration-hard (PBKDF2) key derivation. Each PIN record includes a unique random salt. Verification uses `subtle.ConstantTimeCompare` to prevent timing side channels.
- **FIDO2 hash**: Stored in `mlock`'d, guard-paged memory (`mem.GuardedBuffer`) to prevent swapping to disk. Intermediate values are zeroed after use.
- **Lock-free concurrency**: All mutable state uses `atomic.Bool` and `atomic.Pointer` with no mutexes. The `fido2Guard` pointer is swapped atomically, and the old buffer is freed after replacement.
- **Minimum PIN length**: 6 characters, enforced by both the Service and the backends.

## Legacy Types

The package retains deprecated types for backward compatibility:

- `TPMPINManager` -- legacy TPM-based PIN manager using hierarchy auth. Use `NewService` with `TPM2Backend` instead.
- `FilePINManager` -- legacy file-based PIN manager using Argon2id and file persistence. Use `NewService` with `SoftwareBackend` instead.
- `PINManager` -- deprecated interface. Use `PINBackend` instead.
- `PINManagerAdapter` -- wraps a `PINBackend` to satisfy the deprecated `PINManager` interface. `SetMaxAttempts` is a no-op.

These types will be removed in a future release.

## See Also

- [PIN Management (Barrier Integration)](../seal/pin.md)
- [Setup and Unlock Flow](../../xkey/docs/architecture/setup-and-unlock-flow.md)
