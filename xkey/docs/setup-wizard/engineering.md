# Setup Wizard — Engineering

> **Status: NORMATIVE** · Feature: `setup-wizard` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

Package: `xkey/pkg/gui/services`, file `setup_wizard_service.go`. Errors in
`errors.go`. Frontend contract in `xkey/frontend/src/lib/types/setup.ts`.

## Exported surface

| Method | Purpose |
|---|---|
| `NewSetupWizardService()` | Constructor; dependencies arrive through `Set*` setters |
| `ProbeEnvironment()` | `EnvironmentProbe`: TPM, LUKS, platform, existing storage, barrier strategies, sealers, backends |
| `GenerateSetupPINs()` | Random SO PIN (16 chars) and User PIN (12 chars), full character-class complexity |
| `ApplySetup(*SetupChoices)` | Personal setup, ten steps; returns `*SetupResult` |
| `ApplySOProvisioning(*SetupChoices)` | Enterprise phase one, seven steps; leaves setup incomplete |
| `ApplyUserOnboarding(*UserOnboardingChoices)` | Enterprise phase two, four steps; completes setup |
| `GetStartupState()` | Which view the frontend shows first |
| `SkipSetup()` | Plain data directory, `setup_complete = true`, nothing else |
| `IsSetupComplete()` | Reads the flag from config |
| `GetPolicy()` | The written enterprise policy as a map |
| `FactoryReset(soPin)` | Full wipe, SO-PIN-authorized |

Setters: `SetContext`, `SetStorageService`, `SetPasswordProtectionService`,
`SetTPMService`, `SetPINService`, `SetSealService`,
`SetPlatformPolicyService`, `SetAutoUnsealService`, `SetBarrierService`,
`SetStaticPasswordService`, `SetAdminService`, `SetTPMStatusFunc`,
`SetConfigFunc`, `SetConfigSaveFunc`, `SetEventEmitter`,
`SetInitDataDirFunc`, `SetPostApplyFunc`, `SetConfigDir`.

## Types that carry the credential contract

```go
type GeneratedPINs struct {
    SOPin   string `json:"so_pin"`
    UserPin string `json:"user_pin"`
}

// SetupChoices, the fields that matter here (the full struct is in the source):
SOPin           string `json:"so_pin"`
UserPin         string `json:"user_pin"`
QuickSetup      bool   `json:"quick_setup"`        // PINs came from GenerateSetupPINs
DeploymentMode  string `json:"deployment_mode"`    // "personal" | "enterprise"
SavePinsToStore bool   `json:"save_pins_to_store"` // manual setup: save the User PIN; never the SO PIN
SOPINRecorded   bool   `json:"so_pin_recorded"`    // quick setup: operator recorded the SO PIN out of band
```

## Invariants

1. **The SO PIN value is never written to the device.** `ApplySetup`
   persists it only through `PINService.SetSOPIN` (the backend's verifier).
   No `StaticPasswordService` entry, no config field, no event payload
   carries the value. `SetupCompletedPayload.SOPINSet` is a boolean.
2. **Quick setup requires the acknowledgement.** `ApplySetup` returns
   `ErrSetupSOPINNotRecorded` when `QuickSetup` is true and `SOPINRecorded`
   is false, before any step runs: no progress event, no PIN call, no
   config write. Manual setup (`QuickSetup` false) is not gated, because the
   operator typed and confirmed the SO PIN themselves.
3. **The acknowledgement is not persisted.** It is a property of one
   `ApplySetup` call. A regenerated PIN needs a fresh acknowledgement; the
   frontend clears `so_pin_recorded` whenever it calls `GenerateSetupPINs`.
4. **The User PIN copy is a convenience, not recovery.** Quick-setup personal
   mode, and manual setup with `SavePinsToStore`, write the User PIN to the
   `xKey` folder of the password store. That store is unlocked by the same
   User PIN.
5. **Validation order** is mode, SO PIN present, User PIN present, then the
   acknowledgement gate. A missing SO PIN reports `ErrSetupSOPINRequired`,
   never `ErrSetupSOPINNotRecorded`.
6. Steps 6 → 7 → 8 are ordered: barrier, then data directory, then password
   store. PIN calls that fail at step 2 because the PIN manager does not
   exist yet are retried at step 7.
7. **A failed barrier attempt never persists `barrier_strategy: tpm2` on a
   build/host with no usable TPM sealer.** When `ApplySetup`'s barrier step
   fails, the config-commit switch persists `choices.SealerBackend` so the
   operator can retry -- except that `refuseUnavailableStrategyPersist`
   refuses the write specifically for `tpm2` when
   `BarrierService.ProbeStrategies` reports it unavailable
   (`tpmSealerFn == nil`, or the sealer's `CanSeal()` is false). The prior
   config value, if any, is left untouched; `ErrSetupSealStrategyUnavailable`
   is reported instead. Every other strategy, a barrier service that is not
   wired at all (test-only path), and a hardware/credential failure against
   an *available* tpm2 strategy (`CanSeal()` true but `Unseal` still fails)
   are unaffected and still persist the requested strategy for retry
   (go-xkms#510 item 1). This closes the setup-time half of #510; the
   runtime re-unseal-in-place path is `BarrierService.Unseal`'s own guard via
   `assembleStrategy`, already in place.

## Errors

All declared in `errors.go`, all typed values, all prefixed `setup_wizard:`.

| Error | When |
|---|---|
| `ErrSetupAlreadyComplete` | `setup_complete` already true |
| `ErrSetupInvalidMode` | mode not `standalone`, `server`, `both` |
| `ErrSetupStorageFailed` | config functions missing, or config nil |
| `ErrSetupSOPINRequired` | empty SO PIN |
| `ErrSetupUserPINRequired` | empty User PIN |
| `ErrSetupSOPINNotRecorded` | quick setup without `so_pin_recorded` |
| `ErrSetupPINGenerationFailed` | `crypto/rand` failure in `GenerateSetupPINs` |
| `ErrSetupInvalidDeploymentMode` | enterprise flow with an unknown mode |
| `ErrSetupSOPINVerifyFailed` | user onboarding presented the wrong SO PIN |
| `ErrSetupPINServiceUnavailable` | an SO-PIN-authorized operation reached without a PIN service; refused, never assumed |
| `ErrSetupNotSOProvisioned` | user onboarding before SO provisioning |
| `ErrSetupSealStrategyUnavailable` | a failed barrier attempt requested `tpm2` and no usable TPM sealer is wired in on this build/host; the config write for `barrier_strategy` is skipped |

Step failures inside `ApplySetup` are soft: they land in
`SetupResult.Warnings` or `SetupResult.Errors` with `Success` false, and
the method still returns the result. Only the pre-flight checks above
return an error.

## Configuration

`setup_complete` in the GUI config file (`~/.xkey/gui.json`). `false` shows
the wizard; `true` bypasses it. Nothing about PINs is written there.

## Events

| Event | Payload | When |
|---|---|---|
| `setup:progress` | `{step, total_steps, label}` | before each step; totals are 10 / 7 / 4 for the three apply methods |
| `setup:completed` | `{mode, storage_created, master_password_set, platform_policy_created, tpm_sealed_passwords, user_pin_set, so_pin_set, barrier_initialized, barrier_strategy}` | end of `ApplySetup` |
| `setup:skipped` | `{reason}` | `SkipSetup` |

## Tests

Suite: `make test-gui` from `xkey/` (runs `./pkg/gui/...` with `-race`;
allow several minutes). The #290 contract lives in
`setup_wizard_so_pin_test.go`, built on a real in-memory
`StaticPasswordService`, a software mock PIN backend and a real
`BarrierService`, so `ApplySetup` reaches step 8 for real:

| Test | Proves |
|---|---|
| `TestApplySetup_QuickSetupPersonal_NeverStoresSOPIN` | no entry named `SO PIN`, no entry holding the value, name lookup fails, value search is empty; the User PIN entry is the positive control that step 8 ran; the PIN backend holds the verifier |
| `TestApplySetup_ManualSaveToStore_NeverStoresSOPIN` | the manual opt-in saves the User PIN only |
| `TestApplySetup_QuickSetup_RefusesUnacknowledgedSOPIN` | `ErrSetupSOPINNotRecorded`; zero PIN calls, no events, empty store, setup not complete |
| `TestApplySetup_QuickSetup_AcknowledgedSOPINApplies` | the same choices with the flag set run the flow |
| `TestApplySetup_ManualSetup_NeedsNoSOPINAcknowledgement` | manual setup is not gated |
| `TestApplySetup_SOPINRequiredBeforeAcknowledgementGate` | validation order |
| `TestApplySetup_TPM2Unavailable_RefusesToPersistStrategy` | a failed `tpm2` attempt with no TPM sealer wired writes no `barrier_strategy` and reports `ErrSetupSealStrategyUnavailable` |
| `TestApplySetup_TPM2Unavailable_PreservesPriorBarrierStrategy` | the refused write leaves a pre-existing config value untouched |
| `TestApplySetup_TPM2Available_PersistsStrategyOnSealedShutFailure` | a hardware failure against an *available* `tpm2` strategy still persists it for retry |
| `TestApplySetup_PassphraseStrategy_UnaffectedByTPM2Guard` | the guard is scoped to `tpm2`; passphrase failures persist as before |
| `TestRefuseUnavailableStrategyPersist_*` (`setup_wizard_tpm2_guard_test.go`) | the guard function in isolation: no sealer, `CanSeal()` false, a working sealer, passphrase never blocked, no barrier service wired |

Mutation checks recorded on go-xkms#290: reinstating the `SO PIN` store
write fails the first two tests at the name, value and lookup assertions;
deleting the gate fails the third.

The frontend type-checks with `npm run check` in `xkey/frontend`. The
pre-existing `pin_max_attempts` errors there are unrelated to this feature
and present on `main`.
