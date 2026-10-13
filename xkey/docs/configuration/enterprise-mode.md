# xKey Enterprise Mode

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `policy:` section, its HMAC seal and the SO/User login gate; the provisioning and onboarding wizards are in [setup-wizard](../setup-wizard/).

Enterprise mode adds an organization-managed security policy with tamper detection, an SO/User login gate, and SO/User separation. It is designed for deployments where a Security Officer (SO) provisions devices before handing them to end users.

## Mode Detection

Enterprise mode is detected by the existence of the HMAC file
(`IsEnterpriseMode`, `xkey/pkg/config/policy_integrity.go:72`):

```
~/.config/xkey/xkey_policy.hmac
```

No config flag is needed. The application infers the mode from filesystem state:

| HMAC File Exists | Mode | Auth Gate |
|------------------|------|-----------|
| No | Personal | None (barrier unseal is sufficient) |
| Yes | Enterprise | SO PIN or User PIN required at login |

## Policy Section

The `policy:` section of the unified config (`PolicySection`,
`xkey/pkg/config/policy.go:26-124`) holds 42 SO-controlled fields. Every field
is covered by the HMAC integrity tag. Defaults are `DefaultPolicy()`
(`policy.go:128`).

Where a field is gated in a GUI service, a denied call returns a typed
`*PolicyDeniedError` and the precondition check returns
`*PolicyPreconditionError` (`xkey/pkg/gui/enterprise_policy.go:155-189`).
Fields marked *provisioning only* are written by SO provisioning
(`xkey/pkg/gui/services/setup_wizard_service.go:1344-1400`) and shown in the
GUI, but no runtime enforcement point reads them.

### Security Requirements

`require_so_pin`, `require_user_pin`, `require_encrypted_storage` and
`require_tpm` are checked once, right after the SO PIN verifies the sealed
policy (`checkStartupPreconditions`, `enterprise_policy.go:155`). If the host
does not meet a requirement, the verified section is **not** applied: the
`DefaultPolicy()` values already in effect stay in effect, and
`LoginResult.Error` carries the unmet field list. The SO login itself still
succeeds (`xkey/pkg/gui/services/auth_service.go:205-219`), since refusing it
would lock out the one person who could fix the deployment.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_pin_length` | int | 6 | Minimum PIN length (provisioning only) |
| `pin_max_attempts` | int | 5 | PIN retry limit; when > 0 the GUI locks the user's own retry setting |
| `require_so_pin` | bool | true | SO PIN must be configured on this host |
| `require_user_pin` | bool | true | User PIN must be configured on this host |
| `require_encrypted_storage` | bool | true | GUI `storage_type` must be `barrier` (`enterprise_policy.go:171`) |
| `storage_type` | string | "barrier" | Storage type chosen at provisioning (provisioning only) |
| `require_tpm` | bool | false | TPM must be available on this host |
| `platform_pcr_bank` | string | "" | PCR bank; SO provisioning sets `sha256` (provisioning only) |

### Backend Control

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_backends` | []string | nil | Permitted backends (provisioning only) |
| `default_backend` | string | "" | Default backend for new keys (provisioning only) |

### FIDO2 Policy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fido2_always_uv` | bool | false | Force user verification on all FIDO2 ops (`enterprise_policy.go:66`) |
| `fido2_require_user_presence` | bool | true | Require user presence even when PIN auth succeeds |
| `fido2_user_intent_check` | bool | true | Show a presence dialog before `StatusPINRequired` |
| `attestation_mode` | string | "" | Attestation mode (provisioning only) |

### Auto-Unseal Policy

Both fields gate `AppService.ToggleBarrierAutoUnseal`
(`xkey/pkg/gui/services/app_service.go:616-621`):
`user_can_configure_auto_unseal` false refuses any change, and
`allow_auto_unseal` false refuses enabling it.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_auto_unseal` | bool | false | Organization permits TPM-based auto-unseal at all |
| `user_can_configure_auto_unseal` | bool | true | User can toggle auto-unseal in Settings |

### User Permissions

Each `user_can_*` field is a deny switch enforced in the service, not only
by hiding the control in the GUI:

| Field | Type | Default | Enforced in |
|-------|------|---------|-------------|
| `user_can_configure_theme` | bool | true | `AppService.SetTheme` (`app_service.go:594`) |
| `user_can_manage_trust_store` | bool | true | `TrustService` (`trust_service.go:162`) |
| `user_can_view_audit_log` | bool | true | `AuditService` (`audit_service.go:101`) |
| `user_can_manage_sealed_data` | bool | true | `SealService` (`seal_service.go:424`) |
| `user_can_change_own_pin` | bool | true | `PINService` (`pin_service.go:359`) |
| `user_can_toggle_dev_tools` | bool | true | `AppService` dev-tools toggle (`app_service.go:645`) |
| `user_can_configure_extension` | bool | true | Browser-extension settings (`enterprise_policy.go:83`) |

### Developer Surface

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_explorer_enabled` | bool | true | API Explorer is enabled at all (`api_explorer_service.go:211`) |
| `api_explorer_sandbox_policy` | string | "" | API Explorer sandbox policy; validated on load (`config.go:568`) |
| `developer_tools_enabled` | bool | true | Developer Tools can be turned on at all (`app_service.go:648`) |

### Browser Extension

`policy.go:53-61`; applied to the extension gates by `enterprise_policy.go`.

| Field | Type | Default |
|-------|------|---------|
| `extension_enabled` | bool | true |
| `extension_require_authentication` | bool | true |
| `extension_require_pairing` | bool | true |
| `extension_force_audit` | bool | true |
| `extension_allowed_domains` | []string | nil |
| `extension_blocked_domains` | []string | nil |
| `extension_max_fills_per_minute` | int | 0 |

### Phone Pairing and Sync

Each pair is an answer plus a lock: while the `lock_*` field is false the
user's own setting governs (`devices.yaml`, or `--allow-sync` for sync); while
it is true the sealed policy does. All default to false, the safe value
(`policy.go:63-120`).

| Field | Answer to |
|-------|-----------|
| `pairing_allow_unattestable_devices` / `lock_pairing_attestation_policy` | May `xkey device pair` accept a phone whose hardware attestation cannot be verified? |
| `pairing_allowed_applications`, `pairing_allow_unpinned_signatures` / `lock_pairing_application_policy` | Which xkey-android builds attested pairing accepts; when locked, the policy list is used in full, never merged with `devices.yaml` |
| `phone_sync_allow_secret_export` / `lock_phone_sync_policy` | May `xkey device listen`/`relay` export password-vault or OATH secrets to the phone? |

### Organization

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `organization_name` | string | "" | Organization name for display (provisioning only) |
| `policy_version` | int | 1 | Policy schema version |

## Policy Integrity (HMAC Tamper Detection)

### Key Derivation

The HMAC key is derived from the SO PIN in two stages
(`deriveHMACKey`, `policy_integrity.go:215-237`):

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

HKDF provides domain separation, so the policy integrity key is independent of other keys derived from the same SO PIN.

### Canonical JSON

The section is serialized with `encoding/json`, which marshals struct fields
in declaration order (`PolicyCanonicalJSON`, `policy.go:166`):

```
HMAC-SHA256(key, canonical_json(PolicySection)) -> tag
```

Adding, removing or reordering a field changes this encoding, so an
enterprise deployment must re-seal its policy after upgrading to a build with
a different field set; until then it reads as tampered (`policy.go:161-165`).

### HMAC File Format

The HMAC file is JSON at `~/.config/xkey/xkey_policy.hmac`
(`PolicyHMAC`, `policy_integrity.go:60-66`):

```json
{
  "version": 1,
  "algorithm": "HMAC-SHA256",
  "salt": "<base64-encoded 16-byte random salt>",
  "hmac": "<base64-encoded 32-byte HMAC tag>"
}
```

`tpm_nv_index` is also part of the format, omitted when zero.
`WritePolicyHMAC` generates a fresh random salt on each write and writes the
file with 0600 permissions through the atomic writer (`policy_integrity.go:146-185`).

### Tamper Response

When the SO logs in and HMAC verification fails, the SO is still logged in
as `so_admin`, the session's `tamperDetected` flag is set, and the
`LoginResult` reports `tamper_detected: true` with `policy_verified: false`
(`auth_service.go:184-201`). The verified section is not applied, so the
`DefaultPolicy()` values stay in effect.

Tamper detection in the GUI is deferred until SO login, because the SO PIN is required to derive the verification key.

### Verification on the CLI path

A CLI command never reads the `policy:` section straight from the loaded config. It goes through `config.LoadVerifiedPolicy(cfg, configDir, soPIN)` (`xkey/pkg/config/policy_verified.go:76`), which returns the section together with its verification state and fails closed whenever the section is sealed but cannot be authenticated:

| Config directory | SO PIN | Result |
|---|---|---|
| No HMAC file (personal mode) | ignored | `PolicyUnsealed`: the section is the user's own file |
| HMAC file present, section verifies | supplied | `PolicySealedVerified`: authenticated enterprise policy, honoured in both directions |
| HMAC file present, anything else | empty, wrong, file unreadable, HMAC mismatch | `ErrPolicyUnverifiable` joined with the cause; **no policy is returned** |

The third case is an error rather than a state, so an unverified sealed section cannot be consumed by accident. Commands that consult the policy accept the SO PIN through `--so-pin-stdin` or `XKEY_SO_PIN` (`xkey/cmd/xkey/cmd/pin_input.go:72-73`), and never demand it:

| Command | No SO PIN supplied | SO PIN supplied, verifies | SO PIN supplied, does not verify |
|---|---|---|---|
| `xkey device pair` | sealed policy not consulted for the unattestable-device decision, so such a device is refused; the attested-application allow-list cannot be resolved, so attested pairing refuses (`device_pairing_policy_shared.go:88-103`) | policy honoured in both directions | pairing refused (`ErrPairingPolicyRefused`, `device_pairing_policy_shared.go:152`) |
| `xkey extension serve` | `DefaultPolicy()` applied for the extension gates (`extension_serve.go:672-676`) | policy honoured in both directions | server does not start (`ErrServePolicyRefused`, `extension_serve.go:66`) |

The application allow-list is resolved on unattended reconnects too, so there only `XKEY_SO_PIN` can supply the SO PIN (`device_pairing_policy_shared.go:52-53`).

The GUI follows the same rule. Before any SO login, an enterprise-mode GUI runs on `DefaultPolicy()`. When the SO logs in and the HMAC verifies, the verified section replaces those defaults for the rest of the session (`auth_service.go:205-206`). A section that fails verification leaves the defaults in place.

The authenticator core enforces its own lock independently of the GUI: when the stored HMAC fails to verify, user-mode CTAP commands are refused with `CTAP2_ERR_INTEGRITY_FAILURE` while `getInfo` still answers (`xkey/pkg/authenticator/authenticator.go:207`). See [Tamper Lock](../fido2/engineering.md#tamper-lock).

## Authentication Gate

### AuthMode States

`locked`, `user` and `so_admin` (`auth_service.go:28-34`):

```
locked -> user      (User PIN verified, LoginUser)
locked -> so_admin  (SO PIN verified, LoginSO)
so_admin -> locked  (Logout)
user -> locked      (Logout)
```

### Personal Mode (No HMAC File)

1. User starts application
2. Barrier unseal prompt (if barrier storage is configured)
3. After unseal, the mode is set to `user` (`SetModeUser`, `auth_service.go:242-245`)
4. No login gate is shown

### Enterprise Mode (HMAC File Exists)

1. User starts application
2. Login gate is shown (SO PIN or User PIN)
3. **User login**: verifies User PIN, sets mode to `user`
4. **SO login**: verifies SO PIN, triggers HMAC verification, sets mode to `so_admin`
5. The verification result is held for the session (`policyVerified`, an `atomic.Bool`, `auth_service.go:67`)

### LoginResult

Both `LoginUser()` and `LoginSO()` return a `LoginResult` (`auth_service.go:38-44`):

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

The SO's policy view is read-only: it loads the section through
`SetupWizardService.GetPolicy` (`xkey/frontend/src/views/PolicyEditor.svelte:65`).
The policy and its HMAC are written by SO provisioning
(`setup_wizard_service.go:1404`).

As a `user`, a control whose `user_can_*` field is false is refused by the
service layer even if reached directly (see [User Permissions](#user-permissions)).

## SO Provisioning Flow

`ApplySOProvisioning` (`setup_wizard_service.go:1268`) runs seven steps:

| Step | Action |
|------|--------|
| 1 | Configure SO PIN |
| 2 | Provision TPM keys (when a TPM service is available; failure is a warning) |
| 3 | Initialize the platform key store (when a TPM service is available) |
| 4 | Initialize barrier storage (after TPM provisioning, which the TPM2 sealer needs) |
| 5 | Initialize the data directory |
| 6 | Write the security policy to the unified config |
| 7 | Compute and write the policy HMAC |

After SO provisioning, `setup_complete` stays `false` (`setup_wizard_service.go:1410-1411`). The HMAC file puts the device in enterprise mode, and user onboarding must complete before it is operational.

## User Onboarding Flow

`ApplyUserOnboarding` (`setup_wizard_service.go:1428`) runs four steps:

| Step | Action |
|------|--------|
| 1 | Verify the SO PIN the SO provided |
| 2 | Set the User PIN |
| 3 | Initialize or unseal barrier storage |
| 4 | Set `setup_complete=true` in both the GUI and the unified config, and save |

## Startup State Detection

`GetStartupState()` (`setup_wizard_service.go:1214`) reports
`setup_complete`, whether the HMAC file exists, and whether the SO and User
PINs are set, plus an `enterprise_wizard_mode`:

| setup_complete | HMAC exists | User PIN set | `enterprise_wizard_mode` |
|---------------|-------------|--------------|--------------------------|
| false | true | false | `user_onboarding` |
| false | false | - | `so_provisioning` (when a config directory is configured) |
| any other combination | | | `""` |

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
