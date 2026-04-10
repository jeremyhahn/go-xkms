# xKey Enterprise Mode

Enterprise mode enables organization-managed security policy with tamper detection, role-based authentication, and SO/User separation. It is designed for deployments where a Security Officer (SO) provisions devices before handing them to end users.

## Mode Detection

Enterprise mode is detected by the existence of the HMAC file:

```
~/.config/xkey/xkey_policy.hmac
```

No config flag is needed. The application infers the mode from filesystem state:

| HMAC File Exists | Mode | Auth Gate |
|------------------|------|-----------|
| No | Personal | None (barrier unseal is sufficient) |
| Yes | Enterprise | SO PIN or User PIN required at login |

## Policy Section

The `policy:` section of the unified config holds 24 SO-controlled fields that govern security requirements, backend selection, and user permissions. These fields are covered by the HMAC integrity tag.

### Security Requirements

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_pin_length` | int | 6 | Minimum PIN length for SO and User PINs |
| `require_so_pin` | bool | true | Require SO PIN to be set |
| `require_user_pin` | bool | true | Require User PIN to be set |
| `require_encrypted_storage` | bool | true | Require encrypted storage backend |
| `storage_type` | string | "barrier" | Storage type: barrier, luks |
| `require_tpm` | bool | false | Require TPM hardware |
| `require_platform_policy` | bool | false | Require PCR-based platform policy |
| `platform_pcrs` | []int | nil | PCR indices for platform binding |
| `platform_pcr_bank` | string | "" | PCR hash bank (sha256, sha384) |
| `require_password_protection` | bool | false | Require password store encryption |
| `password_protection_mode` | string | "" | tpm_sealed, aes_software, none |

### Backend Control

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_backends` | []string | nil | Whitelist of permitted backends |
| `default_backend` | string | "" | Default backend for new keys |

### FIDO2 Policy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fido2_always_uv` | bool | false | Force user verification on all FIDO2 ops |
| `fido2_require_resident_key` | bool | false | Require discoverable credentials |
| `attestation_mode` | string | "" | Attestation enforcement mode |

### Auto-Unseal Policy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_auto_unseal` | bool | false | Allow TPM-based auto-unseal |
| `user_can_configure_auto_unseal` | bool | true | User can modify auto-unseal settings |

### User Permissions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `user_can_configure_theme` | bool | true | User can change UI theme |
| `user_can_manage_trust_store` | bool | true | User can add/remove trust roots |
| `user_can_view_audit_log` | bool | true | User can view audit logs |
| `user_can_manage_sealed_data` | bool | true | User can seal/unseal data |
| `user_can_change_own_pin` | bool | true | User can change their own PIN |

### Organization

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `organization_name` | string | "" | Organization name for display |
| `policy_version` | int | 1 | Policy schema version |

## Policy Integrity (HMAC Tamper Detection)

### Key Derivation

The HMAC key is derived from the SO PIN through a two-stage process:

```
SO_PIN + salt
    |
    v
Argon2id(time=3, memory=64MB, threads=4, keyLen=32)
    |
    v
HKDF-SHA256(intermediate, salt, "xkey-policy-integrity")
    |
    v
32-byte HMAC key
```

Argon2id provides memory-hard password stretching. HKDF provides domain separation so the policy integrity key is cryptographically independent of other keys derived from the same SO PIN.

### Canonical JSON

The policy section is serialized to JSON using Go's `encoding/json`, which marshals struct fields in declaration order. This produces a deterministic byte representation without requiring sorted-key canonicalization.

```
HMAC-SHA256(key, canonical_json(PolicySection)) -> tag
```

### HMAC File Format

The HMAC file is stored as JSON at `~/.config/xkey/xkey_policy.hmac`:

```json
{
  "version": 1,
  "algorithm": "HMAC-SHA256",
  "salt": "<base64-encoded 16-byte random salt>",
  "hmac": "<base64-encoded 32-byte HMAC tag>",
  "tpm_nv_index": 0
}
```

A fresh random salt is generated on each write. The file uses 0600 permissions and atomic write (temp file + rename).

### Tamper Response

When the SO logs in and HMAC verification fails:

1. `tamperDetected` flag is set for the session
2. Application locks to SO-only mode
3. The SO is presented with the changed fields
4. The SO can re-sign the policy to acknowledge changes or revert

Tamper detection is deferred until SO login. The application loads and runs normally before that point because the SO PIN is required to derive the verification key.

## Authentication Gate

### AuthMode States

```
locked -> user      (User PIN verified)
locked -> so_admin  (SO PIN verified)
so_admin -> locked  (logout)
user -> locked      (logout)
```

### Personal Mode (No HMAC File)

1. User starts application
2. Barrier unseal prompt (if barrier storage is configured)
3. After unseal, `SetModeUser()` is called automatically
4. No login gate is shown; the user proceeds to the main app

### Enterprise Mode (HMAC File Exists)

1. User starts application
2. Login gate is shown (SO PIN or User PIN)
3. **User login**: verifies User PIN, sets mode to `user`
4. **SO login**: verifies SO PIN, triggers HMAC verification, sets mode to `so_admin`
5. HMAC verification result is cached for the session (`policyVerified` atomic bool)

### LoginResult

Both `LoginUser()` and `LoginSO()` return a `LoginResult`:

```go
type LoginResult struct {
    Success        bool   `json:"success"`
    Mode           string `json:"mode"`            // "locked", "user", "so_admin"
    PolicyVerified bool   `json:"policy_verified"`
    TamperDetected bool   `json:"tamper_detected"`
    Error          string `json:"error,omitempty"`
}
```

## Admin vs User UI

### SO Admin App Shell

When authenticated as `so_admin`, the GUI shows the admin app shell with:

- Policy editor (read/write access to all 24 policy fields)
- PIN management (set/change SO PIN, set/reset User PIN)
- Hardware management (TPM provisioning, platform policy)
- Policy re-signing (recompute HMAC after policy changes)
- Ability to switch to user mode for testing

### User App

When authenticated as `user`, the GUI shows the standard app with navigation filtered by policy permissions:

- Theme settings (if `user_can_configure_theme`)
- Trust store management (if `user_can_manage_trust_store`)
- Audit log viewer (if `user_can_view_audit_log`)
- Sealed data management (if `user_can_manage_sealed_data`)
- PIN change (if `user_can_change_own_pin`)
- Auto-unseal configuration (if `user_can_configure_auto_unseal`)

Navigation items for disabled permissions are hidden from the UI.

## SO Provisioning Flow

The SO provisions a device before handing it to the end user. This is a 7-step process:

| Step | Action | Description |
|------|--------|-------------|
| 1 | Initialize barrier | Create encrypted storage with a barrier password |
| 2 | Initialize data directory | Create the xkey data directory structure |
| 3 | Configure SO PIN | Set the Security Officer PIN |
| 4 | Provision TPM keys | Create EK, SRK, IAK, IDevID (when TPM available) |
| 5 | Initialize platform key store | Create platform SRK with SO/User auth |
| 6 | Write security policy | Set policy fields in unified config and save |
| 7 | Compute policy HMAC | Derive key from SO PIN, write HMAC file |

After SO provisioning, `setup_complete` remains `false`. The HMAC file existence triggers enterprise mode detection. User onboarding must complete before the device is operational.

## User Onboarding Flow

After the SO provisions the device, the end user completes a 4-step onboarding:

| Step | Action | Description |
|------|--------|-------------|
| 1 | Verify SO PIN | User enters the SO PIN provided by the SO |
| 2 | Set User PIN | User creates their own PIN (must meet `min_pin_length`) |
| 3 | Initialize/unseal barrier | Unseal existing barrier or create new one |
| 4 | Save configuration | Set `setup_complete=true` in both GUI and unified config |

The SO PIN verification in step 1 ensures only authorized users can onboard. After step 4, the application shows the login gate on subsequent launches.

## Startup State Detection

`GetStartupState()` inspects the filesystem and config to determine the initial view:

| setup_complete | HMAC exists | User PIN set | Result |
|---------------|-------------|--------------|--------|
| true | true | true | Show login gate (enterprise) |
| true | false | - | Show barrier unseal (personal) |
| false | true | false | Show user onboarding wizard |
| false | false | - | Show SO provisioning wizard |

## Programmatic Usage

```go
import "github.com/jeremyhahn/go-xkms/xkey/pkg/config"

// Check enterprise mode
isEnterprise := config.IsEnterpriseMode(config.ConfigDir())

// Compute HMAC for a policy
salt := make([]byte, 16)
io.ReadFull(rand.Reader, salt)
tag, err := config.ComputePolicyHMAC(&policy, soPIN, salt)

// Write HMAC file
err := config.WritePolicyHMAC(&policy, soPIN, hmacPath)

// Verify policy integrity
ok, err := config.VerifyPolicyHMAC(&policy, hmacPath, soPIN)
```
