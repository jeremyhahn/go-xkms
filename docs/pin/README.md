# PIN Management

PIN management is **owned by go-qrdb**. The `PINBackend` interface,
`pin.Service`, `SoftwareBackend`, `FIDO2HashVerifier`, and every sentinel
error live in `go-qrdb/pkg/pin`. xkms contributes hardware-backed
implementations of that interface: `pkg/pintpm2` for TPM 2.0 platforms,
which any binary composes into a qrdb server via
`qrdbserver.WithPINBackend`.

This document covers both sides of that boundary:

- the qrdb-owned `PINBackend` contract and Service that consumers use;
- the xkms-owned TPM2 backend (`pkg/pintpm2`) and its
  `PlatformAuthProvider` hook.

> Phase 2 moved the PIN service down to qrdb. Earlier revisions of this
> document described `pkg/pin` as an xkms package; that package no longer
> exists. The TPM 2.0 backend lives in `pkg/pintpm2` and the PIN service it
> plugs into lives in `go-qrdb/pkg/pin`.

## Architecture

```
Caller (xkmsd / quicbaasd / xkmsctl)
   |
   v
+--------------------+      FIDO2PINHashSetter callback
|  pin.Service       |--------------------------------> Authenticator
|  (qrdb, single     |                                  (SHA-256(PIN)[:16])
|   entry point)     |
+----------+---------+
           |
           v
+--------------------+
|   pin.PINBackend   |   interface defined in go-qrdb/pkg/pin
+--------------------+
        |
   +----+----------------------+
   |                           |
   v                           v
SoftwareBackend          TPM2Backend (xkms/pkg/pintpm2)
(Argon2id / PBKDF2)      delegates to PlatformAuthProvider
qrdb-owned                xkms-owned
```

`pin.Service` (qrdb) wraps a `PINBackend`, validates PIN length (minimum 6
characters), pushes FIDO2 hashes to the authenticator on set/change, and
delegates every verification call to the backend.

`PINBackend` (qrdb) is the interface each backend implements. Methods cover
SO PIN and user PIN lifecycle: `Set`, `Change`, `Verify`, plus
`GetLockoutStatus` and `ResetLockout`.

All mutable state in xkms's TPM2 backend uses `sync/atomic` operations
(`atomic.Bool`, `atomic.Pointer`) for lock-free concurrent access — see
`pkg/pintpm2/backend.go:56`.

## Backend Comparison

| Aspect | TPM2 (xkms) | Software (qrdb) |
|--------|-------------|-----------------|
| Repository | `go-xkms/pkg/pintpm2` | `go-qrdb/pkg/pin` |
| Strategy ID | `pin.StrategyTPM2` | `pin.StrategySoftware` |
| PIN verification | PlatformSRK password auth via `PlatformAuthProvider` | Argon2id or PBKDF2 hash + constant-time compare |
| SO PIN | Not supported (returns `pin.ErrPINNotSet`) | Hash-based, persisted to `storage.Backend` |
| User PIN | PlatformSRK auth value | Hash-based, persisted to `storage.Backend` |
| Lockout | TPM dictionary attack protection (hardware counters) | None (hash is the security boundary) |
| FIDO2 hash | Cached in `enclave.MemoryEnclave` on verify/set/change | Cached via go-qrdb's own protected-memory mechanism on verify/set/change |
| Concurrency | `atomic.Bool` + `atomic.Pointer` | `atomic.Bool` + `atomic.Pointer` |
| Constructor | `pintpm2.NewTPM2Backend(platformAuthProvider)` | `pin.NewSoftwareBackend(store, hashConfig)` |

## TPM2 Backend (`pkg/pintpm2`)

The TPM2 backend delegates all user PIN verification to the TPM 2.0
hardware through the `PlatformAuthProvider` interface defined alongside it
(`pkg/pintpm2/providers.go:22`). The user PIN IS the PlatformSRK's password
auth value.

```go
import (
    "github.com/jeremyhahn/go-qrdb/pkg/pin"
    "github.com/jeremyhahn/go-xkms/pkg/pintpm2"
)

backend := pintpm2.NewTPM2Backend(platformKeyStore)
svc := pin.NewService(backend, slog.Default())
```

The composing binary (xkmsd, quicbaasd) wires the backend into the qrdb
server via `qrdbserver.WithPINBackend(backend)`. Source:
`pkg/pintpm2/backend.go:68`.

### Conformance

```go
// pkg/pintpm2/backend.go:35
var (
    _ pin.PINBackend        = (*TPM2Backend)(nil)
    _ pin.FIDO2HashVerifier = (*TPM2Backend)(nil)
)
```

The backend satisfies both the canonical qrdb `PINBackend` interface and
the optional `FIDO2HashVerifier` extension, so `pin.Service` can verify
incoming FIDO2 PIN hashes without ever holding the raw PIN.

### How it works

- **VerifyUserPIN**: Calls `platformStore.VerifyAuth(pin)`, which executes `tpm.VerifyAuth(srkHandle, pin)`. A correct PIN returns `nil`; an incorrect PIN returns `ErrAuthFailed`; a probe or transport fault (invalid template, missing handle) returns `ErrAuthProbeRejected` and is never misreported as an invalid PIN — see [TPM 2.0 backend](../backends/tpm2.md) for the auth-probe details.
- **ChangeUserPIN**: Calls `platformStore.ChangeAuth(currentPIN, newPIN)`, which recreates the PlatformSRK with the new auth value.
- **SetUserPIN**: Verifies the PIN matches the PlatformSRK's existing auth, then caches the FIDO2 hash. The `soPIN` parameter is ignored (exists to satisfy the interface).
- **Lockout**: Real TPM dictionary attack counters are queried via `GetLockoutInfo()`. Auth failures return `ErrPINInvalidWithStatus` (with remaining attempts) or `ErrTPMLocked` when the DA counter is exhausted.
- **SO PIN**: Not stored or supported. `SetSOPIN`, `ChangeSOPIN`, and `VerifySOPIN` all return `ErrPINNotSet`.
- **Initialization**: `IsInitialized()` returns `platformStore.IsProvisioned()`. `UserPINSet()` is reported only when the platform is provisioned AND `IsAuthReady()` is true. A readable SRK proves nothing about its auth value — one left by a prior TPM owner looks identical — so reporting a PIN as set from provisioning alone would claim a credential the backend has never seen and cannot check, and every attempt against it spends one of the TPM's dictionary-attack retries. Verification itself stays available whenever the SRK is provisioned, and a successful `SetUserPIN`/`VerifyUserPIN` confirms the auth value.

### First-Boot SRK Enrollment

`PlatformKeyStore.EnrollPlatformSRK(userPIN string) error` is the entry point
for binding a PIN to the Platform SRK on first boot. It must complete
successfully before the TPM2 PIN backend is usable end-to-end.

- **Idempotent**: returns `ErrPlatformSRKAlreadyEnrolled` when `IsAuthReady()`
  is already `true`. A daemon can call it unconditionally on every boot and
  treat that sentinel as a no-op.
- **Empty PIN rejected**: an empty `userPIN` returns
  `ErrPlatformSRKEnrollEmptyPIN`. First-boot enrollment must bind a real PIN.
- Reuses the existing `Initialize`/`ensureSRKAuth` machinery; no new TPM
  primitives are introduced.

**`IsInitialized` vs `IsAuthReady`** — these are distinct predicates:

| Predicate | Meaning |
|-----------|---------|
| `IsInitialized()` | The SRK object exists in the TPM. May be `true` when the SRK was created by a prior TPM owner with unknown auth. Using this alone to activate the TPM2 PIN backend is insufficient. A failed `ChangeAuth` re-probes the handle and resets this from what is actually there: a PIN change evicts the SRK before recreating it, so when the recreate fails the key may be gone, and the next `Initialize` must recreate rather than verify (#448). |
| `IsAuthReady()` | The SRK's auth value is known-good — set by this application or confirmed via `VerifyAuth`. This is the correct predicate for selecting the TPM2 PIN backend. |

`SetAuthReady(bool)` is an explicit override for a caller that has confirmed
the auth value by other means. It must NOT be used to infer readiness from
persisted configuration: a persisted `PINStrategy == "tpm2"` records which
backend was selected before, not that this session has confirmed the SRK's
auth value. Asserting readiness from it marks an unverified SRK known-good,
which suppresses enrollment and makes the PIN backend claim a credential
nobody has checked.

`VerifyAuth` and `ChangeAuth` set readiness themselves when they succeed, so
a confirmed auth value survives the rest of the process without any override.
A `ChangeAuth` that fails clears it: changing the auth evicts the persistent
SRK before recreating it, so a failure part-way leaves what the SRK holds
unknown.

Boot lifecycle:

1. **First boot** — call `EnrollPlatformSRK(userPIN)`. The SRK is created
   with `userPIN` as its authorization value and `authReady` is marked.
2. **Subsequent boots** — `EnrollPlatformSRK` returns
   `ErrPlatformSRKAlreadyEnrolled` when `authReady`. Otherwise the auth value
   is unconfirmed for this process, and the first successful `VerifyAuth`
   confirms it. A persisted `PINStrategy` does NOT restore `authReady`: it
   records which backend was selected before, not that the SRK's auth has been
   checked.

### PlatformAuthProvider interface

```go
type PlatformAuthProvider interface {
    VerifyAuth(pin string) error
    ChangeAuth(currentPIN, newPIN string) error
    GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error)
    DictionaryAttackLockoutReset(lockoutAuth []byte) error
    IsProvisioned() bool
    IsAuthReady() bool
}
```

`IsProvisioned` and `IsAuthReady` answer different questions and the backend
needs both: the SRK existing is not evidence about its auth value.

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
- **Auto-detection**: `AutoDetectHashConfig()` returns `FIPSHashConfig()` when `crypto/fips140.Enabled()` is true, otherwise `DefaultHashConfig()`

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

The TPM2 backend caches the 16-byte FIDO2 hash in a go-enclave `MemoryEnclave` (`mlock`'d, guard-paged memory on Linux) via `atomic.Pointer`. After a restart, the hash is lazily recomputed on the first successful `VerifyUserPIN` call.

Backends that cache the FIDO2 hash also implement the `FIDO2HashVerifier` interface, allowing the Service to verify incoming FIDO2 PIN hashes without knowing the raw PIN:

```go
type FIDO2HashVerifier interface {
    VerifyFIDO2Hash(hash []byte) bool
}
```

### Secure memory

- The FIDO2 hash is held in a go-enclave `MemoryEnclave` (mlock'd, guard-paged) rather than a plain `[]byte`.
- All intermediate PIN plaintexts are zeroed via `enclave.Wipe()` after use.
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

    "github.com/jeremyhahn/go-qrdb/pkg/pin"
    "github.com/jeremyhahn/go-xkms/pkg/pintpm2"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
    filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// --- TPM2 backend (via PlatformKeyStore) ---
tpm2Backend := pintpm2.NewTPM2Backend(platformKeyStore)
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
| `ErrPlatformSRKAlreadyEnrolled` | `EnrollPlatformSRK` called when `IsAuthReady()` is already `true`; treat as a no-op on subsequent boots |
| `ErrPlatformSRKEnrollEmptyPIN` | `EnrollPlatformSRK` called with an empty `userPIN`; first-boot enrollment must bind a real PIN |

### Typed errors

| Error type | Meaning |
|------------|---------|
| `*ErrTPMLocked` | TPM is locked out due to DA protection; includes `LockoutStatus` with recovery time |
| `*ErrPINInvalidWithStatus` | Auth failure with DA counter info (remaining attempts, max attempts) |
| `*ErrStoragePersistFailed` | Failed to write PIN record to `storage.Backend`; wraps cause |
| `*ErrStorageLoadFailed` | Failed to read PIN record from `storage.Backend`; wraps cause |
| `*ErrUnsupportedPBKDF2Hash` | Unsupported hash function specified for PBKDF2 (valid: SHA-256, SHA-384, SHA-512) |
| `*ErrAuthProbeRejected` | TPM rejected the auth-probe `TPM2_Create` for a reason other than an authorization failure (template fault, transport error); never a wrong-PIN signal and must not be collapsed into `ErrAuthFailed` |

## Security Properties

- **TPM2 backend**: PIN verification is hardware-enforced. PIN values never leave the TPM boundary for verification. Dictionary-attack throttling is effective only when the Platform SRK (at `0x81000002`) has its `NoDA` attribute cleared — a standard SRK template sets `NoDA = true`, which leaves PIN brute-forcing unthrottled despite the TPM DA counter plumbing being present. The Platform SRK used for PIN verification is provisioned with `NoDA = false` so each wrong PIN increments the hardware DA counter toward lockout, while a correct PIN authorizes normally.
- **Software backend**: PINs are protected by memory-hard (Argon2id) or iteration-hard (PBKDF2) key derivation. Each PIN record includes a unique random salt. Verification uses `subtle.ConstantTimeCompare` to prevent timing side channels.
- **FIDO2 hash**: Stored in `mlock`'d, guard-paged memory (go-enclave `MemoryEnclave`) to prevent swapping to disk. Intermediate values are zeroed after use.
- **Lock-free concurrency**: All mutable state uses `atomic.Bool` and `atomic.Pointer` with no mutexes. The `fido2Enclave` pointer is swapped atomically, and the old enclave is destroyed after replacement.
- **Minimum PIN length**: 6 characters, enforced by both the Service and the backends.

## Composition into qrdb

The composing binary registers the chosen backend on the qrdb server:

```go
import (
    qrdbserver "github.com/jeremyhahn/go-qrdb/pkg/server"
    "github.com/jeremyhahn/go-xkms/pkg/pintpm2"
)

backend := pintpm2.NewTPM2Backend(platformKeyStore)

srv, err := qrdbserver.New(
    qrdbserver.WithPINBackend(backend),
    // ...
)
```

`WithPINBackend` is the only seam xkms uses to hand its TPM2 implementation
to qrdb. There is no global registration; every backend instance is
explicitly composed by the binary that owns the process.

## See Also

- [PIN Management (Barrier Integration)](../seal/pin.md)
- [Setup and Unlock Flow](../../xkey/docs/architecture/setup-and-unlock-flow.md)
