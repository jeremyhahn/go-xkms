# Setup Wizard - Seal Integration

The `SetupWizardService` orchestrates xKey's first-run setup, configuring encrypted storage, TPM provisioning, platform policy, password protection, and auto-unseal in a single workflow. This document covers the seal-related integration points.

## Overview

```
  SetupWizardService
       |
  +----+----+----+----+----+----+----+----+
  |    |    |    |    |    |    |    |    |
Storage TPM  Platform PIN  Barrier Password AutoUnseal Config
Service Svc  PolicySvc Svc  Svc    PPSvc    Svc        Save
                 |           |       |         |
                 +--------  SealService  -----+
                              |
                         Sealer Registry
```

The wizard receives a `SetupChoices` struct from the frontend and applies each choice by delegating to the appropriate service. Progress events are emitted before each step so the frontend can display a live progress indicator.

## Setup Steps

| Step | Label | Service | Description |
|---|---|---|---|
| 1 | Creating encrypted storage | StorageService | Create LUKS volume (if LUKS storage type) |
| 2 | Configuring PINs | PINService | Set SO PIN and User PIN |
| 3 | Provisioning TPM keys | TPMService | Provision EK, Shared SRK, IAK, IDevID |
| 4 | Initializing platform key store | TPMService | Create Platform SRK with userPIN auth |
| 5 | Creating platform policy | PlatformPolicyService | Capture PCRs [0, 7, 9] with sha256 bank |
| 6 | Initializing built-in encryption | BarrierService | Initialize barrier (AES-256-GCM) with best strategy |
| 7 | Initializing data directory | initDataDirFunc | Create `~/.xkey/data/`, init PINManager, retry PINs from Step 2 |
| 8 | Configuring password protection | PasswordProtectionService | Configure tpm_sealed / aes_software / none |
| 9 | Configuring auto-unseal | AutoUnsealService | Seal storage passphrase for auto-unlock |
| 10 | Saving configuration | configSave | Persist all settings, mark SetupComplete=true |

Each step emits a `setup:progress` event:

```go
events.SetupProgressPayload{
    Step:      stepNumber,    // 1-10
    TotalStep: 10,
    Label:     "step label",
}
```

## SetupChoices

```go
type SetupChoices struct {
    Mode                 string `json:"mode"`                  // "standalone", "server", "both"
    ServerAddress        string `json:"server_address"`
    ServerProtocol       string `json:"server_protocol"`
    EnableStorage        bool   `json:"enable_storage"`
    StorageSizeGB        int    `json:"storage_size_gb"`
    StoragePass          string `json:"storage_passphrase"`
    EnableMasterPW       bool   `json:"enable_master_password"`
    MasterPassword       string `json:"master_password"`
    TPMSealPasswords     bool   `json:"tpm_seal_passwords"`
    PasswordStoreMode    string `json:"password_store_mode"`   // "tpm_sealed", "aes_software", "none"
    SOPin                string `json:"so_pin"`                // SO PIN for TPM hierarchy (empty valid)
    UserPin              string `json:"user_pin"`              // Initial user PIN
    UseUserPinAsMaster   bool   `json:"use_user_pin_as_master"`
    SetHierarchyAuth     bool   `json:"set_hierarchy_auth"`    // Use SO PIN to set TPM hierarchy passwords
    EnableAutoUnseal     bool   `json:"enable_auto_unseal"`
    StorageType          string `json:"storage_type"`          // "luks" or "barrier"
    BarrierPassword      string `json:"barrier_password"`      // For barrier software strategy
    SealerBackend        string `json:"sealer_backend"`        // "tpm2", "software", "" (auto)
}
```

| Field | Type | Description |
|---|---|---|
| `Mode` | string | Operating mode: `standalone` (local only), `server` (remote), `both` |
| `EnableStorage` | bool | Create an encrypted volume |
| `StorageSizeGB` | int | LUKS volume size in gigabytes |
| `StoragePass` | string | Passphrase for the LUKS volume |
| `StorageType` | string | Storage backend: `luks` (LUKS volume) or `barrier` (built-in encryption) |
| `BarrierPassword` | string | Password for barrier software strategy |
| `SealerBackend` | string | Sealer backend override: `tpm2`, `software`, or `""` (auto-select) |
| `PasswordStoreMode` | string | Password encryption: `tpm_sealed`, `aes_software`, `none` |
| `SOPin` | string | Security Officer PIN for TPM hierarchy |
| `UserPin` | string | User PIN for daily authentication and Platform SRK auth |
| `SetHierarchyAuth` | bool | Apply SO PIN to TPM hierarchy passwords during Install (Step 3) |
| `EnableAutoUnseal` | bool | Seal storage passphrase for automatic unlock |
| `EnableMasterPW` | bool | Enable master password protection |
| `MasterPassword` | string | Master password (for `aes_software` mode) |
| `UseUserPinAsMaster` | bool | Use User PIN as master password and barrier password |
| `TPMSealPasswords` | bool | Seal passwords to TPM (for `tpm_sealed` mode) |

## Seal-Related Steps in Detail

### Step 4: Platform Key Store Initialization

When `choices.UserPin != ""`, the wizard ALWAYS calls `InitializePlatformKeyStore(soPIN, userPIN)` to create the Platform SRK with userPIN as its auth value. The `soPIN` parameter is only passed when `SetHierarchyAuth` is true (it controls TPM hierarchy passwords set during Install at Step 3), and does NOT set the SRK auth. When no User PIN is provided, `InitializePlatformKeyStoreWithDefaults()` is called instead (empty auth).

If the SRK already exists, `ensureSRKAuth` handles re-provisioning: verify auth match, then evict + recreate. If eviction fails (e.g., wrong hierarchy auth), the method returns `ErrPlatformKeyStoreEvictSRK`. There is no fallback to the Shared SRK.

### Step 5: Platform Policy Creation

The wizard always attempts platform policy creation:

```
  PlatformPolicyService.CreatePolicy(
      pcrs: [0, 7, 9],
      bank: "sha256",
  )
```

This captures the current PCR values from the TPM. If this step succeeds, the `platformPolicyCreated` flag is set to true, which affects Step 9.

Failure at this step produces a warning but does not fail the entire setup.

### Step 6: Barrier Initialization

The barrier provides built-in AES-256-GCM encryption that always wraps the base backend (filesystem or LUKS). This step must run AFTER TPM provisioning (Steps 3-4) because the TPM2 sealing strategy requires a provisioned SRK.

When `UseUserPinAsMaster` is true and a User PIN is configured, the User PIN is used as the barrier password. The barrier selects the best available strategy automatically (TPM2-backed or software-backed).

Failure at this step is a hard error that sets `result.Success = false`.

### Step 7: Data Directory Initialization

Creates `~/.xkey/data/`, initializes the PINManager, and starts the FIDO2 device via `postDataDirStartup()`. This step must run AFTER barrier init (Step 6) so the static password store can use the barrier as its encrypted backend.

PINs set at Step 2 may have failed because the PINManager did not exist yet. This step retries both SO PIN and User PIN setup. The retry logic includes fallback through `ChangeSOPIN` and `VerifySOPIN` to handle cases where the TPM was provisioned with or without hierarchy auth.

### Step 8: Password Protection

When the barrier is initialized (Step 6), it handles encryption transparently and no separate PasswordProtectionService is needed. The static password store uses the barrier backend directly.

When the barrier is NOT active but the data directory is ready, the `PasswordStoreMode` choice determines how passwords are encrypted:

| Mode | Service Method | Description |
|---|---|---|
| `tpm_sealed` | `SetModeTPMSealed()` | Seal password master key to TPM |
| `aes_software` | `SetModeAESSoftwareUserPassword(pw)` | AES encryption with user-derived key |
| `none` | (no-op) | No password encryption |

If no mode is explicitly chosen and the barrier is inactive, the wizard defaults to `aes_software` as a defensive measure to prevent storing passwords unprotected.

### Step 9: Auto-Unseal Configuration

**LUKS auto-unseal:** When `EnableAutoUnseal`, `StorageType == "luks"`, `EnableStorage`, and `StoragePass` are all set:

```
  AutoUnsealService.Enable(
      passphrase:  choices.StoragePass,
      pcrs:        [0, 7, 9],
      pcrBank:     "sha256",
      policyType:  policyType,     // "platform_policy" or "none"
      policyName:  policyName,     // "Platform Policy" or ""
      backend:     "tpm2",
  )
```

**Barrier auto-unseal:** When the barrier uses the `software` strategy, the barrier password is sealed to the TPM so it can auto-unseal on restart. The TPM2 strategy auto-unseals inherently (no password needed).

The policy type depends on Step 5:

| Step 5 Result | Policy Type | Policy Name |
|---|---|---|
| Platform policy created | `platform_policy` | `"Platform Policy"` |
| Platform policy skipped/failed | `none` | `""` |

Auto-unseal gets PCR binding for free when platform policy succeeds. Without platform policy, the passphrase is still sealed to the TPM but without PCR binding.

### Step 10: Save Configuration

The wizard saves the updated `GUIConfigData` with:
- `SetupComplete = true`
- Server settings (if mode is `server` or `both`)

Then emits `setup:completed` with the outcome:

```go
events.SetupCompletedPayload{
    Mode:                  choices.Mode,
    StorageCreated:        choices.EnableStorage && result.Success,
    MasterPWSet:           choices.EnableMasterPW && ... && result.Success,
    PlatformPolicyCreated: platformPolicyCreated && result.Success,
    TPMSealedPasswords:    tpmSealedPasswords && result.Success,
}
```

## SkipSetup

`SkipSetup()` marks setup as complete without configuring any services:

1. Call `initDataDirFunc()` to create a plain data directory (no LUKS).
2. Set `SetupComplete = true` in config.
3. Emit `setup:skipped` event with reason `"user skipped setup wizard"`.

No storage, TPM, seal, or auto-unseal configuration is performed. The user can configure these individually through the settings UI later.

## Progress Events

| Event | Payload | Emitted When |
|---|---|---|
| `setup:progress` | `{step, total_steps, label}` | Before each of the 10 steps |
| `setup:completed` | `{mode, storage_created, ...}` | After successful setup |
| `setup:skipped` | `{reason}` | After SkipSetup |

The frontend subscribes to these events to display a progress bar and final status.

## Error Handling

The wizard uses a soft-failure model: most step failures produce warnings, not hard errors. Only critical failures (storage creation, barrier initialization, data directory initialization, config save) set `result.Success = false`.

| Error | Condition |
|---|---|
| `ErrSetupAlreadyComplete` | `SetupComplete` is already true in config |
| `ErrSetupInvalidMode` | Mode is not `standalone`, `server`, or `both` |
| `ErrSetupStorageFailed` | Config functions nil, config nil, or data dir init failed |
| `ErrSetupPasswordFailed` | Master password setup failed |
| `ErrPlatformKeyStoreEvictSRK` | SRK eviction failed during Platform Key Store init (Step 4) |

## Service Dependencies

The wizard requires these services to be set before `ApplySetup`:

| Setter | Service | Required For |
|---|---|---|
| `SetStorageService()` | StorageService | Step 1: LUKS volume |
| `SetPINService()` | PINService | Step 2: SO/User PIN |
| `SetTPMService()` | TPMService | Steps 3-4: TPM provisioning, Platform Key Store |
| `SetPlatformPolicyService()` | PlatformPolicyService | Step 5: PCR capture |
| `SetBarrierService()` | BarrierService | Step 6: Barrier initialization |
| `SetInitDataDirFunc()` | data dir init | Step 7: Data directory + PIN retry |
| `SetPasswordProtectionService()` | PasswordProtectionService | Step 8: Password mode |
| `SetSealService()` | SealService | Steps 8-9: Seal operations |
| `SetAutoUnsealService()` | AutoUnsealService | Step 9: Auto-unseal |
| `SetConfigFunc()` | config reader | All steps |
| `SetConfigSaveFunc()` | config writer | Step 10 |
| `SetEventEmitter()` | event emitter | Progress events |
| `SetTPMStatusFunc()` | TPM probe | `ProbeEnvironment()` |

Missing services produce warnings rather than errors (except config functions which are required).

## Environment Probe

Before the wizard starts, the frontend calls `ProbeEnvironment()` to detect system capabilities:

```go
type EnvironmentProbe struct {
    TPMAvailable    bool   `json:"tpm_available"`
    LUKSAvailable   bool   `json:"luks_available"`
    ServerReachable bool   `json:"server_reachable"`
    ServerAddress   string `json:"server_address"`
    Platform        string `json:"platform"`      // e.g., "linux/amd64"
    SetupComplete   bool   `json:"setup_complete"`
    StorageExists   bool   `json:"storage_exists"`
    StorageMounted  bool   `json:"storage_mounted"`
}
```

The frontend uses this to:
- Show/hide TPM-related options based on `TPMAvailable`.
- Show/hide LUKS options based on `LUKSAvailable`.
- Pre-fill server address from existing config.
- Redirect to main UI if `SetupComplete` is true.

## See Also

- [Setup and Unlock Flow](../../architecture/setup-and-unlock-flow.md) -- Detailed backend execution flow with Mermaid diagrams
- [xKey Seal/Unseal Architecture](README.md) -- SealService core documentation
- [Auto-Unseal Architecture](auto-unseal.md) -- Auto-unseal enable/disable/reseal
- [Platform Policy Service](platform-policy.md) -- PCR-based platform policy
- [Barrier Encryption Architecture](../../seal/README.md) -- go-xkms core barrier seal subsystem
