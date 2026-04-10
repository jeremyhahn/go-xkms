# xKey Architecture

xKey is the desktop GUI and CLI application for go-xkms, built with Wails (Go backend) and Svelte (frontend). It provides hardware security key management, FIDO2 authentication, OATH tokens, and enterprise policy enforcement.

## Layer Architecture

```
+------------------------------------------------------+
|                  Frontend (Svelte)                    |
|   Login Gate | Setup Wizard | Admin Shell | User App  |
+------------------------------------------------------+
                        |
                   Wails Bindings
                        |
+------------------------------------------------------+
|               GUI Services Layer                      |
|  AuthService | SetupWizardService | PINService | ...  |
+------------------------------------------------------+
                        |
+------------------------------------------------------+
|              Config / Policy Layer                    |
|  Unified Config | Policy Integrity | Migration        |
+------------------------------------------------------+
                        |
+------------------------------------------------------+
|            go-xkms SDK (sdk/go)                      |
|  Transport abstraction (gRPC, REST, QUIC, embedded)   |
+------------------------------------------------------+
                        |
+------------------------------------------------------+
|              go-xkms Core Library                    |
|  Backends | Storage | Crypto | TPM2 | PKCS#11        |
+------------------------------------------------------+
```

The GUI services layer is the boundary between the Wails frontend and the go-xkms library. Reusable logic belongs in `go-xkms/pkg/` or `go-xkms/sdk/go/`, never in `xkey/`. The xkey layer is strictly for GUI services, Wails bindings, and UI-specific glue.

## Unified Configuration

Phase 2 replaced the split config (CLI YAML + GUI JSON) with a single YAML file at `~/.config/xkey/xkey.yaml`.

```
~/.config/xkey/
  xkey.yaml            # Unified config (all sections)
  xkey_policy.hmac     # Policy integrity tag (enterprise mode)
```

### Load Order

1. `~/.config/xkey/xkey.yaml` (user config)
2. `/etc/xkey/xkey.yaml` (system fallback)
3. `DefaultConfig()` (built-in defaults)

Environment variables with the `XKEY_` prefix override any loaded value. Viper handles merging.

### Migration

On first load, if the unified config does not exist but legacy files do (`~/.xkey/config.yaml` or `~/.config/xkey/gui.json`), automatic migration merges them into the unified format. Legacy files are preserved for rollback.

See [configuration.md](configuration.md) for complete field reference.

## Enterprise Mode Detection

Enterprise mode uses state-driven inference rather than a config flag:

```
HMAC file exists?
    |
   yes --> Enterprise mode (auth gate required)
    |
    no --> Personal mode (barrier unseal sufficient)
```

This design allows the application to load policy without requiring the SO PIN at startup. Tamper detection is deferred to SO login, when the PIN is available to derive the verification key.

## Authentication Gate

```
                    +--------+
                    | locked |
                    +--------+
                   /          \
          User PIN              SO PIN
            /                      \
     +------+                +----------+
     | user |                | so_admin |
     +------+                +----------+
         \                      /
          \      Logout        /
           \                  /
            +------+  +------+
            | locked |
            +--------+
```

### Personal Mode Flow

```
App Start -> Barrier Unseal -> SetModeUser() -> Main App
```

No login gate. Barrier unseal (password or TPM auto-unseal) is the only authentication.

### Enterprise Mode Flow

```
App Start -> Login Gate -> [User PIN | SO PIN] -> [User App | Admin Shell]
```

SO login triggers HMAC verification. The result is cached in an atomic bool for the session.

### Session State

`AuthService` uses `sync/atomic` for lock-free state management:

- `mode` (`atomic.Value`): current `AuthMode` (locked, user, so_admin)
- `policyVerified` (`atomic.Bool`): HMAC verified this session
- `tamperDetected` (`atomic.Bool`): HMAC mismatch detected

## Policy Integrity

The HMAC tamper detection chain:

```
SO PIN + random salt
    |
    v
Argon2id (memory-hard stretching)
    |
    v
HKDF-SHA256 (domain separation: "xkey-policy-integrity")
    |
    v
32-byte HMAC key
    |
    v
HMAC-SHA256(key, canonical_json(PolicySection))
    |
    v
Tag stored in xkey_policy.hmac
```

Verification occurs on SO login. A fresh salt is generated on each policy write, preventing salt reuse across policy revisions.

See [enterprise-mode.md](enterprise-mode.md) for full details.

## Admin vs User UI Separation

The frontend routes to different app shells based on `AuthMode`:

| AuthMode | App Shell | Capabilities |
|----------|-----------|-------------|
| `so_admin` | Admin shell | Policy editor, PIN management, TPM provisioning, HMAC re-signing |
| `user` | User app | Filtered navigation based on policy `user_can_*` fields |
| `locked` | Login gate | PIN entry only |

The SO can switch to user mode for testing. Logout always returns to `locked`.

## Setup Workflows

### Personal Setup (10 steps)

Standard first-run wizard for standalone use. Configures storage, PINs, TPM, password protection, auto-unseal, and saves config with `setup_complete=true`.

### Enterprise Setup (Two Phases)

**Phase A: SO Provisioning (7 steps)**

The SO configures barrier, data directory, SO PIN, TPM keys, platform key store, security policy, and policy HMAC. Setup is intentionally left incomplete (`setup_complete=false`).

**Phase B: User Onboarding (4 steps)**

The user verifies SO PIN, sets their User PIN, initializes/unseals barrier, and marks `setup_complete=true`.

### Startup State Router

`GetStartupState()` produces a `StartupState` struct that the frontend uses to determine the initial view:

```go
type StartupState struct {
    SetupComplete        bool   // true = show login or main app
    EnterpriseMode       bool   // HMAC file exists
    EnterpriseWizardMode string // "" | "so_provisioning" | "user_onboarding"
    SOPINSet             bool
    UserPINSet           bool
    PolicyVerified       bool
}
```

## Key Packages

| Package | Path | Responsibility |
|---------|------|---------------|
| `config` | `xkey/pkg/config/` | Unified config, policy, HMAC, migration |
| `services` | `xkey/pkg/gui/services/` | GUI service layer (auth, setup, PIN, TPM, etc.) |
| `events` | `xkey/pkg/gui/events/` | Frontend event system |
| `authenticator` | `xkey/pkg/authenticator/` | CTAP2 authenticator implementation |
| `uhid` | `xkey/pkg/uhid/` | Linux UHID virtual USB HID interface |
| `virtualdevice` | `xkey/pkg/virtualdevice/` | Native virtual device |
