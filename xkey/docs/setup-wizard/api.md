# Setup Wizard — API

> **Status: NORMATIVE** · Feature: `setup-wizard` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

One transport: Wails bindings, called from the frontend as
`window.go.services.SetupWizardService.<Method>(...)` through
`callBackend` / `callBackendWithError` in `lib/api/backend.ts`. Not exposed
over the IPC socket, REST, gRPC or the CLI. Requests and responses are the
JSON forms of the Go types in `setup_wizard_service.go`.

## Methods

| Method | Request | Response |
|---|---|---|
| `ProbeEnvironment()` | — | `EnvironmentProbe` |
| `GenerateSetupPINs()` | — | `{so_pin, user_pin}` |
| `ApplySetup(choices)` | `SetupChoices` | `SetupResult` |
| `ApplySOProvisioning(choices)` | `SetupChoices` (enterprise fields) | `SetupResult` |
| `ApplyUserOnboarding(choices)` | `{so_pin, user_pin, barrier_password}` | `SetupResult` |
| `GetStartupState()` | — | `{setup_complete, enterprise_mode, enterprise_wizard_mode, so_pin_set, user_pin_set, policy_verified}` |
| `SkipSetup()` | — | — |
| `IsSetupComplete()` | — | `bool` |
| `GetPolicy()` | — | policy object |
| `FactoryReset(so_pin)` | `string` | — |

`SetupResult` is `{success, errors[], warnings[], setup_complete}`. A
rejected pre-flight check (see errors in [engineering.md](engineering.md))
arrives as the binding's error, not as a result.

## The generated-credential contract

`GenerateSetupPINs` is the **only** time the SO PIN value crosses the
boundary. The frontend shows it once on the Generated Credentials step and
must send back, in `ApplySetup`:

| Field | Type | Meaning |
|---|---|---|
| `so_pin` | string | the value shown, unchanged |
| `user_pin` | string | the value shown, unchanged |
| `quick_setup` | bool | `true` when the PINs came from `GenerateSetupPINs` |
| `deployment_mode` | string | `"personal"` |
| `so_pin_recorded` | bool | the operator's acknowledgement that the SO PIN is recorded outside this device |

With `quick_setup: true` and `so_pin_recorded: false` the binding returns
the error `setup_wizard: generated SO PIN must be acknowledged as recorded
out of band before setup can apply` and nothing has happened on the device.

`save_pins_to_store` (manual setup) saves the **User PIN** to the `xKey`
folder of the password store. It has never had a way to save the SO PIN
since go-xkms#290; sending it with quick setup is harmless and redundant,
because quick-setup personal mode saves the User PIN regardless.

No method returns the SO PIN after `GenerateSetupPINs`. `GetStartupState`
and the `setup:completed` event carry `so_pin_set` booleans only.

## Events (frontend subscribes)

| Event | Payload |
|---|---|
| `setup:progress` | `{step, total_steps, label}` |
| `setup:completed` | `{mode, storage_created, master_password_set, tpm_sealed_passwords, user_pin_set, so_pin_set, barrier_initialized, barrier_strategy}` |
| `setup:skipped` | `{reason}` |

## Frontend elements the contract depends on

In `views/SetupWizard.svelte`, quick-setup step 4:

| Element | `data-testid` | Role |
|---|---|---|
| SO PIN display | `wizard-generated-so-pin` | masked by default; reveal and copy buttons; copy clears the clipboard after 30 s |
| User PIN display | `wizard-generated-user-pin` | same shape |
| Acknowledgement checkbox | `wizard-so-pin-recorded` | bound to `choices.so_pin_recorded`; Continue is disabled until it is checked |

Calling `GenerateSetupPINs` again (re-entering Quick Setup) resets
`so_pin_recorded` to `false` and re-masks both values.
