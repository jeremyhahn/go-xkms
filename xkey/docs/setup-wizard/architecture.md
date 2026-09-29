# Setup Wizard — Architecture

> **Status: NORMATIVE** · Feature: `setup-wizard` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

## The problem

A fresh xKey install has no PINs, no barrier, no data directory and no
policy. Every one of those is owned by an existing service, and each has
ordering constraints on the others: the barrier must exist before the
password store can use it, the PIN manager does not exist until the data
directory does, TPM sealing needs a provisioned SRK. A first-run flow has to
sequence all of that, survive partial failure, and hand the operator the
credentials the device will demand from them later.

## Shape

`SetupWizardService` (`xkey/pkg/gui/services/setup_wizard_service.go`) is an
orchestrator in the GUI services layer. It owns no state of its own beyond
the `setup_complete` flag in the GUI config; every step delegates to the
service that owns the capability (`PINService`, `BarrierService`,
`TPMService`, `StaticPasswordService`, `TPMPolicyService`,
`BarrierAutoUnsealService`, `AutoUnsealService`, `StorageService`). Dependencies are injected by setters
during Wails startup (`xkey/pkg/gui/app.go`), which is what lets the tests
wire an in-memory password store and a mock PIN backend around the real
orchestration.

The frontend (`xkey/frontend/src/views/SetupWizard.svelte`, state in
`lib/stores/wizard.ts`) collects choices and calls the service over Wails
bindings. It holds no business logic: validation that matters is repeated in
Go, and the Go side is the one that refuses.

## Flows

| Flow | Entry method | What it establishes |
|---|---|---|
| Personal, quick | `GenerateSetupPINs` then `ApplySetup` with `quick_setup: true` | Generated SO PIN and User PIN, barrier, data directory, password store |
| Personal, manual | `ApplySetup` | Operator-chosen PINs, plus storage, sealing, policy and auto-unseal choices |
| Enterprise, SO provisioning | `ApplySOProvisioning` | SO PIN, barrier, TPM keys, signed security policy; setup left incomplete |
| Enterprise, user onboarding | `ApplyUserOnboarding` | Verifies the SO PIN, sets the User PIN, completes setup |
| Skip | `SkipSetup` | Marks setup complete with a plain data directory and nothing else |

`GetStartupState` tells the frontend which of these to show.

### `ApplySetup` step order

| Step | Label | Delegate |
|---|---|---|
| 1 | Creating encrypted storage | `StorageService` (LUKS only) |
| 2 | Configuring PINs | `PINService` (may fail here; retried at 7) |
| 3 | Provisioning TPM keys | `TPMService` |
| 4 | Initializing platform key store | `TPMService` |
| 5 | Initializing built-in encryption | `BarrierService` |
| 6 | Initializing data directory | `initDataDirFunc`, then PIN retry |
| 7 | Configuring password protection | `StaticPasswordService`, `PasswordProtectionService` |
| 8 | Configuring auto-unseal | `AutoUnsealService` (LUKS), `TPMPolicyService` + `BarrierAutoUnsealService` (barrier) |
| 9 | Saving configuration | config save, `setup:completed` |

Step 5 must precede step 6 so the password store can sit on the barrier.
Step 6 must precede step 7 because the store does not exist before it.

There is no platform-policy step: the built-in `platform` TPM policy always
exists. When the operator asks for auto-unseal, step 8 creates the named TPM
policy `auto-unseal` over the live values of PCRs 0, 7 and 9 (SHA-256) on
xKey's own TPM — or reuses it on a re-run — and seals the barrier password
under it (`BarrierAutoUnsealService.EnableAutoUnseal`); the LUKS passphrase
is sealed under the built-in `platform` policy. When the TPM owner hierarchy
was given the SO PIN as its password, the SO PIN authorizes the policy's NV
index. A failure is a warning: setup completes and the barrier needs its
password on restart. See [../seal/](../seal/architecture.md) and
[docs/tpm-policies](../../../docs/tpm-policies/architecture.md).

## Credential placement

The wizard establishes two credentials with different jobs:

- The **User PIN** unlocks the app, the FIDO2 authenticator, PKCS#11 and the
  password store. It is the everyday credential.
- The **SO PIN** is the administrative and recovery credential. Its jobs are
  the ones PKCS#11 gives the Security Officer: initialize the token, reset a
  User PIN the user has lost, and authorize destructive operations such as
  factory reset.

The password store is unlocked by the User PIN. That fixes where the SO PIN
may live:

> **A recovery credential must not live inside the thing it recovers.**

So the wizard persists the SO PIN **only as the PIN service's verifier**,
the same form the User PIN takes. The value is returned once from
`GenerateSetupPINs`, shown once on the Generated Credentials step, and never
written to the device. Quick setup refuses to apply until the operator
acknowledges recording it out of band (`so_pin_recorded`), because a device
initialized with a recovery credential nobody holds is a device with no
recovery.

The User PIN, by contrast, is still saved to the `xKey` folder of the
password store in quick setup (and in manual setup when the operator opts
in). It is not a recovery credential, and the store it lands in is the store
it unlocks: the copy is a convenience for the first lock, not a recovery
path.

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Store the SO PIN in the device's own password store (the behaviour before #290) | Unreachable in every situation the SO role exists for: a forgotten User PIN after a lock or restart, a sealed barrier, a wiped or corrupt store. And readable by anything that can drive the IPC socket once the store is open, including the auto-unlock and open-access-mode paths. Unavailable when needed, or reachable by everything. |
| Keep the store copy and document the loop | Implies a recovery story that does not exist. Strictly worse than not storing it. |
| Escrow the SO PIN somewhere the User PIN does not gate (platform keychain, printed recovery sheet, separate sealed blob) | Not built. It is a design of its own and stays open as an owner decision on go-xkms#290. Nothing in this folder precludes it; a future escrow would be an explicit export at generation time, never silent on-device storage. |

## Boundaries

- The wizard never talks to the FIDO2 authenticator's own SO PIN
  (`AuthenticatorState.SOPINManager`). That credential is established over
  CTAP (go-xkms#233, #306) and is a different subject from the qrdb PIN
  service SO PIN this wizard configures.
- The wizard does not implement PIN storage, sealing or policy. It calls the
  owners. A behaviour change in one of those belongs in that feature's
  folder, not here.
