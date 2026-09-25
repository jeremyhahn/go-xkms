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

The `policy:` section of the unified config holds 37 SO-controlled fields that govern security requirements, backend selection, and user permissions. These fields are covered by the HMAC integrity tag.

Every field below is either enforced at a specific service-layer call (a typed
`*PolicyDeniedError` or `*PolicyPreconditionError`, refusing the operation and
emitting an `audit.OpPolicyDenied` event) or is a plain configuration value a
non-gated consumer reads. None is inert: a field that reached this state
without an enforcement point was deleted (#668, and see the **BREAKING**
change note below).

**BREAKING**: `platform_pcrs`, `require_password_protection`,
`password_protection_mode` and `fido2_require_resident_key` were removed.
They were parsed and signed into the sealed policy but nothing read them.
Deploying a build with this change re-seals the policy (the field set
changed, so the HMAC changes); an enterprise config that sets any of these
four keys is now rejected the way any unrecognized YAML key is. Delete them
from the config file before upgrading.

### Security Requirements

Since #668, `require_so_pin`, `require_user_pin`, `require_encrypted_storage`
and `require_tpm` are checked once, right after the SO PIN verifies the
sealed policy (`checkStartupPreconditions` in `pkg/gui/enterprise_policy.go`).
If the host does not meet a requirement the policy declares, the verified
section is **not** applied -- the secure `DefaultPolicy()` values already in
effect for every other consumer stay in effect, and `LoginResult.Error`
carries the unmet field list -- rather than refusing the SO's login itself,
since that would lock out the one person who could fix the deployment.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_pin_length` | int | 6 | Minimum PIN length for SO and User PINs |
| `require_so_pin` | bool | true | SO PIN must be configured on this host |
| `require_user_pin` | bool | true | User PIN must be configured on this host |
| `require_encrypted_storage` | bool | true | Storage backend must be `barrier` |
| `storage_type` | string | "barrier" | Storage type: barrier, luks |
| `require_tpm` | bool | false | TPM must be available on this host |
| `platform_pcr_bank` | string | "" | PCR hash bank (sha256, sha384) used by TPM enrollment |

### Backend Control

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_backends` | []string | nil | Whitelist of permitted backends |
| `default_backend` | string | "" | Default backend for new keys |

### FIDO2 Policy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fido2_always_uv` | bool | false | Force user verification on all FIDO2 ops |
| `fido2_require_user_presence` | bool | true | Require user presence even when PIN auth succeeds |
| `fido2_user_intent_check` | bool | true | Show a presence dialog before `StatusPINRequired` |
| `attestation_mode` | string | "" | Attestation enforcement mode |

### Auto-Unseal Policy

Both fields gate `AppService.ToggleBarrierAutoUnseal` (#668): `allow_auto_unseal`
is the organization-wide kill switch (off unless the SO opts in explicitly),
`user_can_configure_auto_unseal` is the per-user deny switch. Both must be
true to enable auto-unseal; either alone is enough to keep it off.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_auto_unseal` | bool | false | Organization permits TPM-based auto-unseal at all |
| `user_can_configure_auto_unseal` | bool | true | User can toggle auto-unseal in Settings |

### User Permissions

Each `user_can_*` field below is a deny switch: false refuses the
corresponding service call with a typed `*PolicyDeniedError` and logs an
`audit.OpPolicyDenied` event, rather than merely hiding the control in the
GUI (#668).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `user_can_configure_theme` | bool | true | User can change UI theme (`AppService.SetTheme`) |
| `user_can_manage_trust_store` | bool | true | User can add/remove/import trust roots (`TrustService`) |
| `user_can_view_audit_log` | bool | true | User can view or export the audit log (`AuditService`) |
| `user_can_manage_sealed_data` | bool | true | User can seal or delete sealed data (`SealService`) |
| `user_can_change_own_pin` | bool | true | User can change their own PIN (`PINService.ChangeUserPIN`) |
| `user_can_toggle_dev_tools` | bool | true | User can toggle the Developer Tools panel |
| `user_can_configure_extension` | bool | true | User can change browser-extension settings |

### Developer Surface

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_explorer_enabled` | bool | true | API Explorer subsystem is enabled at all (`APIExplorerService.Execute`) |
| `api_explorer_sandbox_policy` | string | "" | User-configurable API Explorer sandbox policy value |
| `developer_tools_enabled` | bool | true | Developer Tools subsystem is enabled at all |

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

Tamper detection in the GUI is deferred until SO login. The application loads and runs normally before that point because the SO PIN is required to derive the verification key.

### Verification on the CLI path

A CLI command never reads the `policy:` section straight from the loaded config. It goes through `config.LoadVerifiedPolicy(cfg, configDir, soPIN)`, which returns the section together with its verification state and fails closed whenever the section is sealed but cannot be authenticated:

| Config directory | SO PIN | Result |
|---|---|---|
| No HMAC file (personal mode) | ignored | `PolicyUnsealed`: the section is the user's own file |
| HMAC file present, section verifies | supplied | `PolicySealedVerified`: authenticated enterprise policy, honoured in both directions |
| HMAC file present, anything else | empty, wrong, file unreadable, HMAC mismatch | `ErrPolicyUnverifiable` joined with the cause; **no policy is returned** |

The third case is an error rather than a state, so an unverified sealed section cannot be consumed by accident. Commands that consult the policy accept the SO PIN through `--so-pin-stdin` (preferred), `XKEY_SO_PIN` or `--so-pin`, and never demand it:

| Command | No SO PIN supplied | SO PIN supplied, verifies | SO PIN supplied, does not verify |
|---|---|---|---|
| `xkey device pair` | sealed policy not consulted; an unattestable device is refused whatever `devices.yaml` says | policy honoured in both directions, including `pairing_allow_unattestable_devices` locked open | pairing refused (`ErrPairingPolicyRefused`) |
| `xkey extension serve` | sealed policy not consulted; `DefaultPolicy()` applied for the extension gates (`--no-auth` and `--no-pairing` are overridden) | policy honoured in both directions | server does not start (`ErrServePolicyRefused`) |

The GUI follows the same rule. At startup, before any SO login, it resolves the section through `LoadVerifiedPolicy` with no SO PIN: in personal mode there is no enterprise policy and the GUI's own settings stand; in enterprise mode the sealed section cannot yet be authenticated, so `DefaultPolicy()` is applied to the FIDO2 authenticator (`fido2_require_user_presence`, `fido2_user_intent_check`) and to the browser-extension gates, never the file's relaxations. When the SO logs in and the HMAC verifies, the verified section replaces those defaults on both consumers for the rest of the session. A section that fails verification leaves the defaults in place.

The authenticator core enforces its own lock independently of the GUI. When the authenticator opens with a policy integrity provider and the stored HMAC fails to verify, `Authenticator.TamperDetected` is set and every user-mode CTAP command and Go API registration or assertion is refused with `CTAP2_ERR_INTEGRITY_FAILURE` until the SO re-signs the policy and the authenticator is re-opened. `getInfo` and `selection` still answer so the device stays discoverable. See [Tamper Lock](../fido2/engineering.md#tamper-lock).

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

- Policy editor (read/write access to all 37 policy fields)
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
- Auto-unseal configuration (if `user_can_configure_auto_unseal` and `allow_auto_unseal`)
- Developer Tools toggle (if `user_can_toggle_dev_tools` and `developer_tools_enabled`)
- Browser-extension settings (if `user_can_configure_extension`)
- API Explorer (if `api_explorer_enabled`)

Navigation items for disabled permissions are hidden from the UI, and the
underlying service call refuses even if reached directly -- hiding the
control is presentation, not the enforcement point (#668).

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
