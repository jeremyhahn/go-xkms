# Enterprise Setup Architecture

## Overview

xkey supports two deployment modes:

- **Personal** -- Single-user, no authentication gate. Barrier unseal is sufficient for daily use.
- **Enterprise** -- Security Officer (SO) provisions the device first, then users onboard with SO authorization. A policy HMAC ensures configuration integrity.

Enterprise mode is detected by the existence of the HMAC file at `~/.config/xkey/xkey_policy.hmac`, not by a config flag. This allows the application to load policy without requiring the SO PIN at startup.

## Deployment Modes

### Personal Mode

Personal mode is the default for standalone desktop use.

- Single user, no authentication gate after barrier unseal
- All features available without restriction
- Setup wizard: 6 steps (Welcome, Deployment Mode, Operating Mode, Security, Storage, Summary)

### Enterprise Mode

Enterprise mode adds organizational security controls.

- SO provisions the device and defines a security policy
- Users onboard with SO authorization and receive a User PIN
- Policy controls which features users can access via `user_can_*` permission flags
- The `policy:` section of the config is HMAC-protected against tampering

## Unified Config Architecture

All configuration lives in a single YAML file following XDG conventions.

| Path | Priority | Description |
|------|----------|-------------|
| `~/.config/xkey/xkey.yaml` | User-level (primary) | Per-user config |
| `/etc/xkey/xkey.yaml` | System-wide (fallback) | Organizational defaults |

Environment variables override both files using the `XKEY_` prefix (e.g., `XKEY_LOG_LEVEL=debug`).

### Config Sections

```yaml
policy:           # SO-controlled, HMAC-protected
backend:          # Cryptographic backend selection (software, tpm2, pkcs11, phone)
fido2:            # FIDO2/WebAuthn authenticator settings
oath:             # OATH TOTP/HOTP module
phone:            # Phone-as-a-token backend
xkmsd:            # Remote xkmsd server connection
tpm:              # Direct TPM access parameters
password_protection:  # Barrier/encryption at-rest
trust:            # Root certificates and system trust
attestation:      # Attestation authority
log:              # Logging settings
gui:              # User preferences (theme, window, auto-unseal)
state:            # Managed by app (setup_complete, barrier_initialized)
```

The `policy:` section is the only section protected by HMAC integrity verification. All other sections can be freely modified by the user.

Package: `xkey/pkg/config/`

## Policy HMAC Tamper Detection

### Key Derivation

The SO PIN is stretched through a two-stage derivation chain:

```
SO_PIN
  |
  v
Argon2id(SO_PIN, salt, t=3, m=64MB, p=4, keyLen=32)
  |
  v
HKDF-SHA256(intermediate, salt, info="xkey-policy-integrity", len=32)
  |
  v
HMAC-SHA256(derived_key, canonical_json(policy)) --> tag
```

### HMAC File Format

Stored at `~/.config/xkey/xkey_policy.hmac` as JSON:

```json
{
  "version": 1,
  "algorithm": "HMAC-SHA256",
  "salt": "<base64>",
  "hmac": "<base64>",
  "tpm_nv_index": 0
}
```

A fresh random salt (16 bytes) is generated on every write. The file is written atomically using temp-file-plus-rename for crash safety.

### Canonical JSON

HMAC is computed over the JSON encoding of the `PolicySection` struct. Because `encoding/json` marshals struct fields in declaration order, the output is deterministic without requiring sorted-key canonicalization.

### Tamper Scenarios

| Scenario | Result |
|----------|--------|
| Policy modified, HMAC intact | HMAC mismatch detected on SO login; SO-only mode |
| HMAC file deleted | No enterprise mode detected; device operates as personal mode (effective factory reset of enterprise policy) |
| Both intact | Policy verified; normal enterprise operation |

### TPM Integration

- **With TPM2**: Policy hash can also be stored in TPM NV RAM (`tpm_nv_index` field) for auto-verification without requiring the SO PIN at every startup.
- **Without TPM**: SO PIN is required at startup to re-derive the key and verify the HMAC.

## Setup Wizard Flows

### Enterprise SO Provisioning (6 Steps)

| Step | Screen | Description |
|------|--------|-------------|
| 1 | Welcome | Environment probe, system info |
| 2 | Deployment Mode | Select Enterprise |
| 3 | Enterprise Security Policy | Organization name, min PIN length, storage requirements, TPM requirements, user permission toggles |
| 4 | Security | Platform policy, password protection settings |
| 5 | Storage | Barrier initialization, storage type selection |
| 6 | Summary | Review and apply |

The apply phase executes 7 backend steps in sequence:
1. Barrier initialization
2. Data directory creation
3. SO PIN provisioning
4. TPM key provisioning
5. Platform key store setup
6. Security policy write
7. HMAC computation and write

### Enterprise User Onboarding (3 Steps)

| Step | Screen | Description |
|------|--------|-------------|
| 1 | Welcome | Policy summary display (org name, requirements) |
| 2 | Set User PIN | Requires SO PIN for authorization |
| 3 | Done | Barrier storage initialized, setup marked complete |

The wizard flow is determined by the `WizardFlow` type: `'setup'` for provisioning, `'user_onboarding'` for user enrollment.

## Auth Gate and Dual UI

### Application Lifecycle

```
Start --> Setup Complete?
            |
         No: Setup Wizard
            |
         Yes: Enterprise Mode?
                |
             No: Auto-enter User App (barrier unseal only)
                |
             Yes: Auth Login Gate
                    |
                 SO PIN --> AdminApp (SO Admin)
                 User PIN --> User App
```

### Auth Modes

| Mode | Value | Description |
|------|-------|-------------|
| Locked | `locked` | No user authenticated |
| User | `user` | Regular user authenticated |
| SO Admin | `so_admin` | Security Officer authenticated |

### AdminApp (SO Admin)

Navigation sections:

**Overview**: Dashboard, Device Status

**Security**: Policy Editor, PIN Management

**System**: Audit Log, Factory Reset, Settings

The AdminApp sidebar displays an "SO ADMIN" badge and a pulsing security indicator in the header. The SO can switch to User Mode or log out.

### User App

Full navigation with all device features. In enterprise mode, navigation items are conditionally hidden based on policy permissions (audit log, sealed data, trust store).

In personal mode, the auth gate is skipped entirely -- barrier unseal is the only required authentication.

## Policy Permissions

The `PolicySection` contains permission flags that control user access in enterprise mode:

| Field | Default | Controls |
|-------|---------|----------|
| `user_can_configure_auto_unseal` | `true` | Auto-unseal settings access |
| `user_can_configure_theme` | `true` | Theme toggle availability |
| `user_can_manage_trust_store` | `true` | Trust store visibility and management |
| `user_can_view_audit_log` | `true` | Audit log visibility |
| `user_can_manage_sealed_data` | `true` | Sealed data access |
| `user_can_change_own_pin` | `true` | User PIN change access |

Additional policy fields govern security requirements:

| Field | Description |
|-------|-------------|
| `min_pin_length` | Minimum PIN length (default: 6) |
| `require_so_pin` | SO PIN must be set |
| `require_user_pin` | User PIN must be set |
| `require_encrypted_storage` | Barrier encryption required |
| `require_tpm` | TPM hardware required |
| `require_platform_policy` | Platform PCR binding required |
| `allowed_backends` | Whitelist of permitted backends |
| `organization_name` | Displayed in user onboarding |
| `policy_version` | Incremented on policy updates |

## Factory Reset

Factory reset is available only in the AdminApp and requires two-factor confirmation:

1. Type the exact phrase `FACTORY RESET`
2. Enter the SO PIN (minimum 6 characters)

The reset destroys:
- All FIDO2 credentials and authenticator state
- All stored passwords and OATH tokens
- All PIV certificates and keys
- TPM provisioned keys and platform policy
- Barrier encrypted storage and sealed data
- Security policy and HMAC integrity data
- All configuration and preferences

After reset, the device returns to factory state and the setup wizard runs on next launch.

## Key Files

### Backend (Go)

| File | Purpose |
|------|---------|
| `xkey/pkg/config/config.go` | Top-level `Config` struct and validation |
| `xkey/pkg/config/load.go` | XDG path resolution, Viper loading |
| `xkey/pkg/config/save.go` | Atomic config persistence |
| `xkey/pkg/config/policy.go` | `PolicySection` struct, canonical JSON, defaults |
| `xkey/pkg/config/policy_integrity.go` | HMAC compute, verify, write, key derivation |
| `xkey/pkg/gui/services/setup_wizard_service.go` | Wizard backend (ApplySetup, ApplySOProvisioning, ApplyUserOnboarding) |
| `xkey/pkg/gui/services/auth_service.go` | Auth gate (LoginSO, LoginUser, mode management) |

### Frontend (Svelte/TypeScript)

| File | Purpose |
|------|---------|
| `xkey/frontend/src/views/SetupWizard.svelte` | Multi-flow setup wizard UI |
| `xkey/frontend/src/views/AdminApp.svelte` | SO Admin app shell and navigation |
| `xkey/frontend/src/views/FactoryReset.svelte` | Factory reset confirmation flow |
| `xkey/frontend/src/lib/components/AuthLoginGate.svelte` | Login overlay for enterprise mode |
| `xkey/frontend/src/lib/stores/auth.ts` | Auth state store (mode, policy, tamper detection) |
| `xkey/frontend/src/lib/stores/wizard.ts` | Wizard state store (flow, step, choices, progress) |
