# Unified PIN Architecture

## Overview

go-xkms operates three independent PIN subsystems -- FIDO2, PKCS#11, and file-based -- each with its own storage format and persistence mechanism. The **PINCoordinator** unifies them through an observer-pattern fan-out so that a PIN change in any subsystem propagates to the others automatically. This delivers a single-PIN user experience similar to YubiKey Bio Multi-Protocol Edition (MPE), where one PIN unlocks FIDO2, PIV, and OpenPGP simultaneously.

Neither the CTAP2 specification nor the PKCS#11 standard mandates or prohibits cross-protocol PIN sharing. The coordinator is an application-level integration layer, not a standard requirement.

## PIN Subsystems

| Subsystem | Package | Hash Format | Storage Location | Needs Raw PIN |
|-----------|---------|-------------|------------------|---------------|
| FilePINManager | `pkg/pin` | Argon2id (64 MiB, 3 iter, 4 threads) | `~/.xkey/pin/state.json` | Yes |
| FIDO2 Authenticator | `xkey/pkg/authenticator` | SHA-256(PIN)[:16] | Authenticator state file | No (hash only) |
| PKCS#11 Module | `pkg/pkcs11/module` | SHA-256(PIN) | Token state | Yes |

Each subsystem retains its native hash format. The coordinator does not normalize formats; each subscriber receives the raw PIN and/or hash and converts locally.

## PIN Hierarchy

```
SO PIN (Security Officer / Admin)
  |-- xkey SO PIN --> Argon2id --> SMK (Storage Master Key)
  |-- PKCS#11 SO PIN (token.SOPinHash)
  +-- TPM Hierarchy Passwords (endorsement, lockout, owner)

User PIN (Day-to-day operations)
  |-- FIDO2 PIN (state.PINHash = SHA-256(PIN)[:16])
  |-- PKCS#11 User PIN (token.UserPinHash = SHA-256(PIN))
  |-- Key Manager UMK derivation (Argon2id from PIN hash)
  +-- Barrier unseal credential
```

### Key Derivation Chain

```
SO PIN --Argon2id--> SMK --AES-GCM--> unwrap AK --AES-GCM--> unwrap CMK (SO copy)
User PIN --SHA-256[:16]--> PINHash --Argon2id--> UMK --AES-GCM--> unwrap CMK (User copy)
CMK --AES-GCM--> unwrap credential private keys
```

## PINCoordinator Architecture

The coordinator is a stateless fan-out mechanism. It never stores PINs or hashes.

```
                          +------------------+
                          | PINCoordinator   |
                          |  (stateless)     |
    NotifyUserPINChanged  |                  |  OnUserPINChanged
   ---------------------->|  fan-out, skip   |--------------------->  Subscriber A
                          |  callerName      |--------------------->  Subscriber B
                          |                  |--------------------->  Subscriber N
                          +------------------+
```

### Core Interface

```go
type PINSubscriber interface {
    OnUserPINChanged(rawPIN string, pinHash []byte) error
    Name() string
}
```

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| Caller exclusion via `callerName` | Prevents circular notification loops |
| Error isolation (logged, never propagated) | Primary PIN change always succeeds regardless of subscriber failures |
| Snapshot-then-iterate under RLock | Thread-safe concurrent Register + Notify |
| Async notifications via goroutines | CTAP2 handlers dispatch in fire-and-forget goroutines |
| Two notification methods | `NotifyUserPINChanged` (raw + hash) vs `NotifyUserPINChangedHashOnly` (hash only, for SO reset) |

### API

| Method | Parameters | Description |
|--------|-----------|-------------|
| `NewPINCoordinator` | `enabled bool, logger *slog.Logger` | Creates coordinator; all Notify calls are no-ops when disabled |
| `Register` | `sub PINSubscriber` | Thread-safe subscriber registration |
| `NotifyUserPINChanged` | `callerName, rawPIN string, pinHash []byte` | Fan-out to all subscribers except caller |
| `NotifyUserPINChangedHashOnly` | `callerName string, pinHash []byte` | Delegates with empty rawPIN; used by SO reset flows |
| `IsEnabled` | -- | Returns enabled state |

## Subscriber Implementations

### FIDO2PINSubscriber

**Name:** `"fido2"` | **File:** `xkey/pkg/authenticator/pin_subscriber_fido2.go`

| Action | Detail |
|--------|--------|
| Update state | `state.PINHash = pinHash`, `PINSet = true`, reset retries |
| KeyManager sync (SO unlocked, no user key) | `InitializeUserPIN(pinHash)` -- wraps CMK with new UMK |
| KeyManager sync (SO unlocked, user key exists) | `ResetUserPIN(pinHash)` -- re-wraps CMK with new UMK |
| KeyManager sync (SO locked) | Sets `PINSyncPending = true` for deferred resolution |
| Persist | `storage.SaveState(state)` |
| On empty pinHash | Returns `ErrFIDO2PINHashEmpty` |

### PKCS11PINSubscriber

**Name:** `"pkcs11"` | **File:** `xkey/pkg/authenticator/pin_subscriber_pkcs11.go`

| Action | Detail |
|--------|--------|
| Forward raw PIN | Calls `setter.SetUserPin(rawPIN)` via `PKCS11PINSetter` interface |
| On empty rawPIN (hash-only) | Skips gracefully, returns nil |
| On nil setter | Returns `ErrPKCS11SetterNil` |

### FilePINSubscriber

**Name:** `"file"` | **File:** `xkey/pkg/authenticator/pin_subscriber_file.go`

| Action | Detail |
|--------|--------|
| Forward raw PIN | Calls `setter.SetUserPIN(soPIN, rawPIN)` via `FilePINSetter` interface |
| SO PIN | Held at construction time (`NewFilePINSubscriber(setter, soPIN, logger)`) |
| On empty rawPIN (hash-only) | Skips gracefully, returns nil |
| On nil setter | Returns `ErrFilePINSetterNil` |

## Sequence Flows

### PIN Set via Chrome WebAuthn (FIDO2 origin)

```
Chrome --> CTAP2 authenticatorClientPIN(setPIN)
  --> handleSetPIN: state.PINHash = SHA-256(PIN)[:16], state saved
  --> goroutine: PINCoordinator.NotifyUserPINChanged("fido2", rawPIN, hash)
       |--> PKCS11PINSubscriber.OnUserPINChanged(rawPIN, hash)
       |      --> token.SetUserPin(rawPIN)
       +--> FilePINSubscriber.OnUserPINChanged(rawPIN, hash)
              --> manager.SetUserPIN(soPIN, rawPIN)
```

### PIN Set via CLI (File origin)

```
xkey pin set-user --> FilePINManager.SetUserPIN(soPIN, rawPIN)
  --> PINCoordinator.NotifyUserPINChanged("file", rawPIN, argon2Hash)
       |--> FIDO2PINSubscriber.OnUserPINChanged(rawPIN, argon2Hash)
       |      --> state.PINHash = argon2Hash, PINSet = true
       |      --> KeyManager sync (if SO unlocked)
       +--> PKCS11PINSubscriber.OnUserPINChanged(rawPIN, argon2Hash)
              --> token.SetUserPin(rawPIN)
```

### PIN Set via GUI (File origin)

Same flow as CLI; the GUI calls `FilePINManager.SetUserPIN` and propagation follows the "file" path.

### SO Resets User PIN (hash-only)

```
SO --> authenticatorConfig(vendorResetUserPIN)
  --> handleVendorResetUserPIN: state.PINHash = newHash, state saved
  --> goroutine: PINCoordinator.NotifyUserPINChangedHashOnly("fido2", hash)
       |--> PKCS11PINSubscriber: rawPIN == "" --> skip (no raw PIN available)
       +--> FilePINSubscriber: rawPIN == "" --> skip (no raw PIN available)
```

Hash-only notifications cannot propagate to subsystems that require the raw PIN string. This is by design -- the SO reset forces the user to set a new PIN via a raw-PIN path to complete full synchronization.

## Deferred Sync

When a FIDO2 PIN is set before the SO PIN is configured, the KeyManager cannot derive key material because the key hierarchy (SMK, AK, CMK) does not exist yet.

```
Timeline:
  1. User sets FIDO2 PIN via Chrome    --> PINHash stored, PINSyncPending = true
  2. Admin configures SO PIN           --> KeyManager.InitializeSOPIN()
  3. Admin unlocks with SO PIN         --> KeyManager.UnlockWithSOPIN()
     --> detects PINSyncPending && PINSet && PINHash present
     --> calls InitializeUserPIN(PINHash) or ResetUserPIN(PINHash)
     --> clears PINSyncPending = false
```

## Key Wrapping Integration

The KeyManager uses AES-256-GCM for all key wrapping and Argon2id for key derivation from PINs.

```
+--------+     Argon2id      +-----+    AES-GCM     +----+    AES-GCM     +-----+
| SO PIN | ----------------> | SMK | -------------> | AK | -------------> | CMK |
+--------+                   +-----+   (wrap AK)    +----+  (wrap CMK-SO) +-----+
                                                                            |
                                                                  AES-GCM  |  AES-GCM
                                                                  (wrap)   |  (wrap)
                                                                    v      v
                                                          +------------+  +-------------+
                                                          | Attest Key |  | Cred PrivKey |
                                                          +------------+  +-------------+

+----------+   SHA-256[:16]   +---------+   Argon2id   +-----+   AES-GCM     +-----+
| User PIN | ---------------> | PINHash | -----------> | UMK | ------------> | CMK |
+----------+                  +---------+              +-----+ (wrap CMK-U)  +-----+
```

### Dual-Wrapped CMK

The Credential Master Key (CMK) is wrapped twice:

| Copy | Wrapped By | Purpose |
|------|-----------|---------|
| `WrappedCMKSO` | AK (Admin Key) | SO access: allows SO to reset user PIN without knowing it |
| `WrappedCMKUser` | UMK (User Master Key) | User access: daily credential operations via user PIN |

### UMK Derivation Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | Argon2id |
| Time | 3 iterations |
| Memory | 64 MiB |
| Parallelism | 4 |
| Key size | 32 bytes (AES-256) |
| Salt size | 32 bytes |

## Configuration

| Setting | Default | CLI Flag | YAML | JSON |
|---------|---------|----------|------|------|
| Unified PIN | `true` | `--unified-pin` | `unified-pin` | `unified_pin` |

When disabled (`--unified-pin=false`):
- No `PINCoordinator` is created
- Each subsystem manages PINs independently
- PIN changes do not propagate across subsystems

### Wiring (cmd/xkey/cmd/fido2.go)

The FIDO2 daemon command wires the coordinator at device startup:

1. Creates `PINCoordinator` if `Config.UnifiedPIN` is true
2. Registers `FIDO2PINSubscriber` (always present)
3. Registers `PKCS11PINSubscriber` and `FilePINSubscriber` when those subsystems are configured
4. Calls `auth.SetPINCoordinator(coord)` so CTAP2 handlers can dispatch notifications

## Security Considerations

| Property | Implementation |
|----------|---------------|
| No PIN storage in coordinator | Stateless propagation; coordinator holds no PIN material |
| Format-independent hashing | Each subsystem retains its own hash format (Argon2id, SHA-256[:16], SHA-256) |
| GPU/ASIC resistance | Argon2id with 64 MiB memory for file-based and UMK derivation |
| Timing attack prevention | `crypto/subtle.ConstantTimeCompare` for all PIN verification |
| Crash safety | Atomic file writes (temp + rename) prevent partial state |
| Lock-free retry counters | `atomic.Int32` for PIN retry tracking |
| Key material cleanup | `clearBytes()` zeroes sensitive buffers after use |
| File permissions | State files created with `0600` (owner read/write only) |
| Independent salts | Each PIN role (SO, User) uses its own random salt |
| Error isolation | Subscriber failures are logged at Warn level but never block the primary PIN change |

## Source Files

### PINCoordinator (xkey/pkg/authenticator/)

| File | Description |
|------|-------------|
| `pin_coordinator.go` | PINCoordinator and PINSubscriber interface |
| `pin_coordinator_test.go` | Coordinator unit tests |
| `pin_subscriber_fido2.go` | FIDO2 subscriber implementation |
| `pin_subscriber_fido2_test.go` | FIDO2 subscriber tests |
| `pin_subscriber_pkcs11.go` | PKCS#11 subscriber and PKCS11PINSetter interface |
| `pin_subscriber_pkcs11_test.go` | PKCS#11 subscriber tests |
| `pin_subscriber_file.go` | File subscriber and FilePINSetter interface |
| `pin_subscriber_file_test.go` | File subscriber tests |
| `key_manager.go` | KeyManager with UMK derivation and deferred PINSyncPending |
| `config.go` | `Config.UnifiedPIN` field |
| `types.go` | `AuthenticatorState` with PINHash, PINSet, PINSyncPending, WrappedCMK* |

### PINManager Strategies (pkg/pin/)

| File | Description |
|------|-------------|
| `file.go` | FilePINManager (Argon2id, JSON persistence) |
| `tpm2.go` | TPMPINManager (Argon2id + TPM hierarchy auth) |
| `pkcs11.go` | PKCS11PINManager (token-native operations) |
| `pin.go` | PINManager interface and shared types |

### Wiring

| File | Description |
|------|-------------|
| `xkey/cmd/xkey/cmd/fido2.go` | Coordinator creation and subscriber registration |
| `xkey/cmd/xkey/cmd/pin.go` | CLI PIN commands with optional coordinator propagation |

## See Also

- [PIN Management (PINManager Interface and Strategies)](../seal/pin.md)
- [CLI PIN Commands](../usage/cli/pin.md)
- [FIDO2 Authenticator Architecture](../fido2/authenticator/architecture.md)
- [PKCS#11 Module Security](../pkcs11/module/security.md)
- [Setup and Unlock Flow](../../xkey/docs/architecture/setup-and-unlock-flow.md)
