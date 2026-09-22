# Setup Wizard — Engineering

> **Status: NORMATIVE** · Feature: `setup-wizard` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

Package: `xkey/pkg/gui/services`, file `setup_wizard_service.go`. Errors in
`errors.go`. Frontend contract in `xkey/frontend/src/lib/types/setup.ts`.

## Exported surface

| Method | Purpose |
|---|---|
| `NewSetupWizardService(pinSvc *PINService) (*SetupWizardService, error)` | Constructor; `pinSvc` is required, everything else arrives through `Set*` setters |
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

Setters: `SetContext`, `SetStorageService`, `SetTPMService`, `SetPINService`
(re-wires the collaborator the constructor already required, e.g. to swap in
a test double), `SetSealService`, `SetPlatformPolicyService`,
`SetAutoUnsealService`, `SetBarrierService`, `SetStaticPasswordService`,
`SetAdminService`, `SetTPMStatusFunc`, `SetConfigFunc`, `SetConfigSaveFunc`,
`SetEventEmitter`, `SetInitDataDirFunc`, `SetConfigDir`.

### Required vs. optional collaborators (#313)

`pinSvc` is the only constructor argument. It is the SO/User PIN credential
gate that every wizard phase authorizes against: `ApplySetup` and
`ApplySOProvisioning` configure the SO and User PINs, `ApplyUserOnboarding`
and `FactoryReset` verify the SO PIN before a destructive operation proceeds.
Earlier revisions accepted it through `SetPINService` and guarded each use
with `if s.pinSvc != nil`, so a caller that forgot the setter got a wizard
whose credential checks silently passed instead of refusing to run —
observed for `FactoryReset`, a full device wipe. `NewSetupWizardService`
refuses a nil `pinSvc` with `ErrSetupWizardPINServiceRequired`, so that
construction is no longer possible through the public constructor.

Every other collaborator stays a setter because each may legitimately be
absent on a given build or host — e.g. a device with no TPM (#510) — and the
step that needs it already degrades to a warning (`platform policy service
unavailable`, `barrier service unavailable`, ...) or a soft `SetupResult`
failure rather than fabricating success. `SetPasswordProtectionService` and
`SetPostApplyFunc` were removed as part of this audit: the former set a
field (`ppSvc`) no code in the package ever read, and the latter wired a
callback `app.go` never called; both were exercised only by coverage-only
tests, not by anything reachable from the GUI.

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
8. **The wizard does not touch the app lock's unlock-attempt budget
   (go-xkms#272).** That budget (`AppLockPINMaxAttempts`,
   `xkey/pkg/gui/services/app_lock_attempts.go`) is a property of
   `AppLockService`, not of the PIN the wizard establishes, and starts at
   its full value for a fresh data directory with no wizard involvement
   needed. `ApplySetup` neither reads nor resets it; only a Security
   Officer, after setup, clears an exhausted one
   (`PINService.ResetLockout` / `PINService.SetUserPIN`, both of which
   reset it as a side effect when an `AppLockService` is wired — see
   [`../agent-automation/engineering.md`](../agent-automation/engineering.md)).

## Errors

All declared in `errors.go`, all typed values, all prefixed `setup_wizard:`.

| Error | When |
|---|---|
| `ErrSetupWizardPINServiceRequired` | `NewSetupWizardService` called with a nil `pinSvc` |
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

## Shared governing PIN strategy (go-xkms#307)

The wizard sets `SOPin`/`UserPin` through whichever `qrdbsdk.PINBackend`
`App.initPINService` wired into the `PINService` setter before `ApplySetup`
runs — software, or TPM2 when a Platform SRK is enrolled. That backend
choice is what governs, and it must be the *same* choice `xkey pin` and the
headless daemon see, or a PIN the wizard just set fails to verify through
the other entry point. Before this fix the GUI alone persisted its choice,
in `GUIConfig.PINStrategy` (`~/.config/xkey/gui.json`); `xkey pin` and the
daemon always hard-coded software, so a PIN enrolled through a TPM2 wizard
run authenticated through the GUI but not through either of them.

The choice now lives at `<dataDir>/pin/strategy`, beside the PIN state
itself, written and read by `xkey/pkg/pinstrategy` — a plain package with
no cgo or Wails dependency, so the GUI, `xkey pin` and `xkey extension
serve` all resolve it the same way (`pinstrategy.Resolve`,
`services.ResolvePINBackend` on the GUI side). `App.initPINService`
migrates an older install's `GUIConfig.PINStrategy` into that file once,
the first time it runs against a data directory with no strategy record of
its own yet; `GUIConfig.PINStrategy` is otherwise read-only from then on.

A consequence for this package: `ApplySetup`'s TPM2 path (`SetTPMService`,
`ApplySOProvisioning`'s hierarchy-auth step) must run after
`initPINService` has resolved and persisted a strategy, or the wizard would
enroll a PIN against a backend that has not yet been recorded as
governing. The existing step ordering (barrier, then data directory
initialization, then PIN calls) already satisfies this — `initPINService`
runs once per app startup, well before the wizard's PIN steps.

### `require_platform_policy` removed (#313, BREAKING)

The enterprise wizard no longer offers a "Require platform policy" choice.
The field previously had two write paths and no reader: `SetupChoices`
carried a `require_platform_policy` value the frontend checkbox set, which
nothing ever consulted, while `ApplySOProvisioning` separately wrote
`policy.RequirePlatformPolicy = true` into the persisted config
unconditionally — regardless of what the checkbox held. Both write paths
and the field itself (`PolicySection.RequirePlatformPolicy`,
`xkey/pkg/config/policy.go`) are removed outright: a stale
`require_platform_policy` key in an existing `config.yaml` is now ignored
by the lenient YAML loader rather than round-tripped. Removing the field
changes `PolicyCanonicalJSON`'s byte output, so a sealed enterprise policy
must be re-sealed (`ComputePolicyHMAC`) after upgrading to a build with
this change — an unsealed upgrade reads as tampered, which is the correct
failure direction. Wiring an actual PCR-policy precondition remains
tracked as #313 (A)/(B), along with the other 20 inert `PolicySection`
fields the same audit found.

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
| `TestNewSetupWizardService_NilPINService_ReturnsError` | the constructor refuses a nil `pinSvc` with `ErrSetupWizardPINServiceRequired` |
| `TestNewSetupWizardService_WithPINService_Succeeds` | the constructor wires a non-nil `pinSvc` through |
| `TestFactoryReset_RefusesWhenPINServiceUnwired` (`setup_wizard_factory_reset_test.go`) | `FactoryReset`'s own guard still fails closed on a struct-literal-constructed service (the only way to reach a nil `pinSvc` now), independent of the constructor check |

Mutation checks recorded on go-xkms#290: reinstating the `SO PIN` store
write fails the first two tests at the name, value and lookup assertions;
deleting the gate fails the third.

The frontend type-checks with `npm run check` in `xkey/frontend`. The
pre-existing `pin_max_attempts` errors there are unrelated to this feature
and present on `main`.
