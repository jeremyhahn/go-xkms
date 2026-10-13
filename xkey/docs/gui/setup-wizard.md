<!-- Copyright (c) 2025 Jeremy Hahn -->
<!-- Copyright (c) 2025 Automate The Things, LLC -->

# xKey Setup Wizard

> **Status: REFERENCE** · Last verified: 2026-10-13
> Superseded background: the GUI feature folder ([architecture.md](architecture.md)) and the [Setup Wizard feature folder](../setup-wizard/architecture.md) are normative.

## Overview

The xKey GUI includes a first-run Setup Wizard that detects the user's environment and guides them through essential configuration choices. The wizard appears when `setup_complete` is `false` in the GUI config (`gui.json` under the OS user config dir, see [README](README.md#configuration)), which is the default for new installations.

After completion (or skip), the wizard sets `setup_complete` to `true` and never appears again unless reset.

## Flows

The frontend wizard store (`xkey/frontend/src/lib/stores/wizard.ts:11`) has
two flows, with step bounds set by `wizardMaxStep` (`wizard.ts:89`):

| Flow | Steps |
|------|-------|
| `setup` | 6 once a deployment mode (`personal` or `enterprise`) is chosen; 2 before that |
| `user_onboarding` | 3 |

The backend reports apply progress over 9 steps (`setupTotalSteps`,
`xkey/pkg/gui/services/setup_wizard_service.go:465`). The step-by-step
content of each flow, including PINs, the barrier, sealing and enterprise
policy, is described in the
[Setup Wizard feature folder](../setup-wizard/architecture.md).

### Environment probe

`ProbeEnvironment()` returns an `EnvironmentProbe`
(`setup_wizard_service.go:49`): TPM availability and device path, LUKS
availability (`exec.LookPath("cryptsetup")`, `:429`), server reachability,
platform, setup and storage state, and the available barrier strategies,
sealers and backends.

### Operating mode

`SetupChoices.Mode` is `standalone`, `server` or `both`
(`validSetupModes`, `setup_wizard_service.go:37`). Server or Both also takes
a server address (for example `kms.example.com:8443`) and protocol.

### Storage

`SetupChoices.StorageType` is `barrier` or `luks`. The barrier is the
application-level encryption layer; LUKS is offered as an optional base layer
when `cryptsetup` is available.

## Architecture

### Backend

**SetupWizardService** (`xkey/pkg/gui/services/setup_wizard_service.go`) is the Go backend orchestrator. Its dependencies are injected with setters during the Wails startup lifecycle (`SetContext`, `SetStorageService`, `SetTPMService`, `SetPINService`, `SetSealService`, `SetBarrierService`, `SetStaticPasswordService`, `SetAdminService`, `SetTPMStatusFunc`, `SetConfigFunc`, `SetConfigSaveFunc`, `SetEventEmitter`, and others).

Key methods:

| Method | Description |
|--------|-------------|
| `ProbeEnvironment()` | Returns `EnvironmentProbe` with detected capabilities |
| `ApplySetup(choices)` | Applies the setup-flow choices, returns `SetupResult` |
| `ApplySOProvisioning(...)` | Applies enterprise SO provisioning |
| `ApplyUserOnboarding(...)` | Applies the user-onboarding flow |
| `SkipSetup()` | Marks setup complete without changes |
| `IsSetupComplete()` | Returns current setup status from config |
| `GetStartupState()` | Returns the state the frontend uses to pick a flow |

For the backend execution flow (including TPM provisioning, Platform SRK initialization, barrier setup, and auto-unseal), see [Setup and Unlock Flow](../architecture/setup-and-unlock-flow.md).

### Frontend

- **SetupWizard.svelte** (`xkey/frontend/src/views/SetupWizard.svelte`) -- full-screen overlay component rendered when setup is incomplete
- **Wizard store** (`xkey/frontend/src/lib/stores/wizard.ts`) -- Svelte writable store managing `WizardState` with flow, step navigation, choices, and result tracking

### Events

Defined in `xkey/pkg/gui/events/events.go:94-96`:

| Event | Payload | Trigger |
|-------|---------|---------|
| `setup:progress` | `SetupProgressPayload` | Each apply step |
| `setup:completed` | `mode`, `storage_created`, `master_password_set`, `tpm_sealed_passwords`, `user_pin_set`, `so_pin_set`, `barrier_initialized`, `barrier_strategy` | After a successful apply |
| `setup:skipped` | `reason` | After `SkipSetup` |

## Configuration

The wizard reads and writes `gui.json`. The relevant field:

```json
{
  "setup_complete": false
}
```

| Value | Behavior |
|-------|----------|
| `false` (default) | Wizard appears on launch |
| `true` | Wizard is bypassed |

## Resetting the Wizard

To re-run the wizard, edit `gui.json` and set `setup_complete` back to `false`. On the next application launch, the wizard will appear again.

## Adding New Steps

1. Update the step bounds in the wizard store (`wizardMaxStep` and `navigateStep()` in `wizard.ts`, which both hard-code the per-flow maximum)
2. Add the step UI in `SetupWizard.svelte`
3. Add any new backend methods to `SetupWizardService` in Go
4. Extend the `SetupChoices` struct in both Go (`setup_wizard_service.go:73`) and TypeScript (`$lib/types/setup.ts`)
5. Wire new service calls into the matching `Apply*` method following the existing delegation pattern

## See Also

- [Setup and Unlock Flow](../architecture/setup-and-unlock-flow.md) -- Backend execution flow with Mermaid diagrams
- [Setup Wizard — Architecture](../setup-wizard/architecture.md) -- Full step-by-step orchestration, including seal-related steps
- [Seal & Auto-Unseal — Architecture](../seal/architecture.md) -- The Barrier, barrier PCR-policy auto-unseal, and the legacy sealed-blob store the wizard configures
