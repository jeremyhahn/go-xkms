# Authenticator Architecture

> This document covers the FIDO2-specific view of the unified PIN system. For the project-wide PIN architecture covering all subsystems, see [Unified PIN Architecture](../../architecture/pin-architecture.md).

## Unified PIN Architecture

xkey operates three independent PIN subsystems. The **PINCoordinator** unifies them
through an observer-pattern fan-out so that a PIN change in any subsystem propagates
to the others automatically.

### PIN Subsystems

| Subsystem | Storage Format | Location |
|-----------|---------------|----------|
| FilePINManager | Argon2id hash | `~/.xkey/pin/state.json` |
| FIDO2 Authenticator | SHA-256(PIN)[:16] | Authenticator state file |
| PKCS#11 Module | SHA-256(PIN) | Token state |

Each subsystem retains its own storage format. The coordinator does not normalize
formats -- each subscriber receives the raw PIN and/or hash and converts locally.

### PIN Hierarchy

```
SO PIN (Admin)
  +-- xkey SO PIN / Key Manager SMK derivation
  +-- PKCS#11 SO PIN (default=SO PIN, overridable)
  +-- TPM Hierarchy Passwords

User PIN (Day-to-day)
  +-- FIDO2 PIN, SHA-256[:16] (default=User PIN, overridable via --unified-pin=false)
  +-- PKCS#11 User PIN, SHA-256 (default=User PIN, overridable)
  +-- Key Manager UMK derivation
```

### PINCoordinator

`pin_coordinator.go` -- pure propagation mechanism, stores no PINs.

```go
type PINCoordinator struct {
    subscribers []PINSubscriber
    enabled     bool
    logger      *slog.Logger
    mu          sync.RWMutex
}
```

**API:**

- `NewPINCoordinator(enabled bool, logger *slog.Logger) *PINCoordinator`
- `Register(sub PINSubscriber)` -- thread-safe subscriber registration
- `NotifyUserPINChanged(callerName, rawPIN string, pinHash []byte) error` -- fan-out,
  skips the subscriber whose `Name()` matches `callerName`
- `NotifyUserPINChangedHashOnly(callerName string, pinHash []byte) error` -- delegates
  to `NotifyUserPINChanged` with empty `rawPIN`; used by SO reset flows
- `IsEnabled() bool`

**Design decisions:**

- Subscriber errors are logged at Warn level but never propagated. The primary PIN
  change always succeeds regardless of subscriber failures.
- `callerName` exclusion prevents circular notification loops.
- Notifications are fire-and-forget via goroutines in the CTAP2 command handlers
  (`cmd_clientpin.go`, `cmd_config.go`).
- A snapshot of the subscriber slice is taken under RLock before iteration, so
  Register and Notify are safe for concurrent use.

### PINSubscriber Interface

```go
type PINSubscriber interface {
    OnUserPINChanged(rawPIN string, pinHash []byte) error
    Name() string
}
```

Subscribers that require the raw PIN (PKCS#11, File) return nil when `rawPIN` is
empty. Subscribers that only need the hash (FIDO2) return an error when `pinHash`
is empty.

### Subscriber Implementations

**FIDO2PINSubscriber** (`pin_subscriber_fido2.go`, Name: `"fido2"`)

Updates `AuthenticatorState.PINHash`, sets `PINSet = true`, resets retries, and
persists state. If a `KeyManager` is present and SO-unlocked, syncs the user key
material. If SO is locked, sets `PINSyncPending = true` for deferred sync.

**PKCS11PINSubscriber** (`pin_subscriber_pkcs11.go`, Name: `"pkcs11"`)

Forwards `rawPIN` to the `PKCS11PINSetter` interface (`SetUserPin(pin string)`).
Skips gracefully on hash-only notifications.

**FilePINSubscriber** (`pin_subscriber_file.go`, Name: `"file"`)

Forwards `rawPIN` to the `FilePINSetter` interface (`SetUserPIN(soPIN, newUserPIN string) error`).
Holds the SO PIN at construction time. Skips gracefully on hash-only notifications.

### Sequence Flows

**PIN set via Chrome WebAuthn:**

```
Chrome -> CTAP2 setPIN -> handleSetPIN -> state saved
  -> goroutine: PINCoordinator.NotifyUserPINChanged("fido2", rawPIN, hash)
       -> PKCS11PINSubscriber.OnUserPINChanged(rawPIN, hash)
       -> FilePINSubscriber.OnUserPINChanged(rawPIN, hash)
```

**PIN set via CLI:**

```
CLI -> FilePINManager.SetUserPIN()
  -> PINCoordinator.NotifyUserPINChanged("file", rawPIN, hash)
       -> FIDO2PINSubscriber.OnUserPINChanged(rawPIN, hash)
       -> PKCS11PINSubscriber.OnUserPINChanged(rawPIN, hash)
```

**SO resets User PIN (hash-only):**

```
SO -> handleVendorResetUserPIN -> state saved
  -> goroutine: PINCoordinator.NotifyUserPINChangedHashOnly("fido2", hash)
       -> PKCS11PINSubscriber: skips (no rawPIN)
       -> FilePINSubscriber: skips (no rawPIN)
```

### Deferred Sync

When a FIDO2 PIN is set before the SO PIN is configured, the `KeyManager` cannot
derive key material. The `FIDO2PINSubscriber` sets `PINSyncPending = true` on the
authenticator state. When SO later unlocks via `KeyManager.UnlockWithSOPIN()`, the
pending sync executes automatically:

```go
// key_manager.go - UnlockWithSOPIN()
if km.state.PINSyncPending && km.state.PINSet && len(km.state.PINHash) > 0 {
    // Initialize or reset user key material
    km.state.PINSyncPending = false
}
```

### Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `--unified-pin` | `true` | Enable/disable PIN coordination |
| `Config.UnifiedPIN` | `true` | YAML: `unified-pin`, JSON: `unified_pin` |

When disabled, no `PINCoordinator` is created. Each subsystem manages PINs
independently.

### Wiring (cmd/xkey/cmd/fido2.go)

The `fido2` command wires the coordinator at device startup:

1. Creates `PINCoordinator` if `Config.UnifiedPIN` is true
2. Registers `FIDO2PINSubscriber` (always present)
3. Additional subscribers (PKCS#11, File) are registered when those subsystems
   are configured
4. Calls `auth.SetPINCoordinator(coord)` so CTAP2 handlers can dispatch
   notifications

### Source Files

```
xkey/pkg/authenticator/
  pin_coordinator.go          PINCoordinator implementation
  pin_coordinator_test.go     Coordinator unit tests
  pin_subscriber_fido2.go     FIDO2 subscriber
  pin_subscriber_fido2_test.go
  pin_subscriber_pkcs11.go    PKCS#11 subscriber
  pin_subscriber_pkcs11_test.go
  pin_subscriber_file.go      File PIN manager subscriber
  pin_subscriber_file_test.go
  cmd_clientpin.go            CTAP2 SetPIN/ChangePIN (notification call sites)
  cmd_config.go               Vendor resetUserPIN (hash-only notification)
  key_manager.go              Deferred PINSyncPending handling
  config.go                   UnifiedPIN config field
```
