<!-- Copyright (c) 2025 Jeremy Hahn -->
<!-- Copyright (c) 2025 Automate The Things, LLC -->

# xKey Setup Wizard

## Overview

The xKey GUI includes a first-run Setup Wizard that detects the user's environment and guides them through essential configuration choices. The wizard appears automatically when `setup_complete` is `false` in `~/.xkey/gui.json`, which is the default for new installations.

After completion (or skip), the wizard sets `setup_complete` to `true` and never appears again unless manually reset.

## Wizard Steps

The wizard consists of five sequential steps with a progress indicator.

### Step 1: Welcome

Probes the system for available capabilities:

| Capability | Detection Method |
|------------|-----------------|
| TPM 2.0 | TPM status callback |
| LUKS tools | `exec.LookPath("cryptsetup")` |
| Platform | `runtime.GOOS/GOARCH` |
| Existing storage | StorageService status check |

Two shortcuts are available:

- **Skip Setup** -- marks setup complete without changes, emits `setup:skipped`
- **Quick Setup** -- applies sensible defaults for detected capabilities

### Step 2: Operating Mode

Choose how xKey operates:

| Mode | Description |
|------|-------------|
| **Standalone** | Local-only operation, no server connection |
| **Server** | Connect to a remote xkmsd instance |
| **Both** | Local xkms plus server connection |

When Server or Both is selected, the user provides:

- Server address (e.g., `xkms.example.com:8443`)
- Protocol (gRPC, REST, QUIC)

Server mode also enables `server_auto_connect` in the config.

### Step 3: Encrypted Storage

Configures the layered encryption architecture. The barrier (AES-256-GCM application-level encryption) is always initialized. LUKS (kernel-level full-volume encryption) is offered as an optional base layer when `cryptsetup` is available.

| Storage Type | Base Backend | Barrier | Encryption Layers |
|-------------|-------------|---------|-------------------|
| `barrier` | filestorage.Backend | Always active | 1 (barrier AES-256-GCM) |
| `luks` | luks.Backend | Always active | 2 (barrier AES-256-GCM + LUKS AES-256-XTS) |

When LUKS is selected:

| Parameter | Range | Default |
|-----------|-------|---------|
| Volume size | 1--100 GB | 2 GB |
| Passphrase | User-provided | (none) |

Delegates LUKS creation to `StorageService.CreateVolume()` and `StorageService.UnlockVolume()`. Barrier initialization is handled by `BarrierService`. When the software sealing strategy is used and TPM2 is available, the barrier password is TPM-sealed for automatic unlock on subsequent boots (stored as `BarrierAutoUnsealBlobID`).

### Step 4: Master Password

Optional master password that encrypts static passwords at rest using AES software encryption.

Delegates to `PasswordProtectionService.SetModeAESSoftwareUserPassword()`.

### Step 5: Summary

Displays all selections with inline edit links to jump back to any step. Clicking **Apply** executes all choices atomically through `SetupWizardService.ApplySetup()`. The result screen shows success confirmation or detailed error messages.

## Architecture

### Backend

**SetupWizardService** (`xkey/pkg/gui/services/setup_wizard_service.go`) is the Go backend orchestrator. It uses a setter injection pattern so dependencies are wired up during the Wails application startup lifecycle:

```
SetContext()                    -- Wails context
SetStorageService()             -- LUKS volume operations
SetPasswordProtectionService()  -- Master password encryption
SetTPMStatusFunc()              -- TPM availability check
SetConfigFunc()                 -- Read current GUIConfigData
SetConfigSaveFunc()             -- Persist GUIConfigData
SetEventEmitter()               -- Emit events to frontend
```

Key methods:

| Method | Description |
|--------|-------------|
| `ProbeEnvironment()` | Returns `EnvironmentProbe` with detected capabilities |
| `ApplySetup(choices)` | Applies all wizard choices, returns `SetupResult` |
| `SkipSetup()` | Marks setup complete without changes |
| `IsSetupComplete()` | Returns current setup status from config |

For the full 10-step backend execution flow (including TPM provisioning, Platform SRK initialization, barrier setup, and auto-unseal), see [Setup and Unlock Flow](../architecture/setup-and-unlock-flow.md).

### Frontend

- **SetupWizard.svelte** (`xkey/frontend/src/views/SetupWizard.svelte`) -- full-screen overlay component rendered when setup is incomplete
- **Wizard store** (`xkey/frontend/src/lib/stores/wizard.ts`) -- Svelte writable store managing `WizardState` with step navigation, choices, and result tracking

### Events

| Event | Payload | Trigger |
|-------|---------|---------|
| `setup:completed` | `mode`, `storage_created`, `master_pw_set` | After successful `ApplySetup` |
| `setup:skipped` | `reason` | After `SkipSetup` |

## Configuration

The wizard reads and writes `~/.xkey/gui.json`. The relevant field:

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

To re-run the wizard, edit `~/.xkey/gui.json` and set `setup_complete` back to `false`:

```json
{
  "setup_complete": false
}
```

On the next application launch, the wizard will appear again. Previous configuration choices (server address, storage volume, etc.) remain intact; the wizard allows overriding them.

## Adding New Steps

1. Add a new step number constant to the wizard store (`wizard.ts`), updating the max step bound in `navigateStep()`
2. Add an `{#if step === N}` block in `SetupWizard.svelte` with the step UI
3. Update the progress steps array in the wizard component
4. Add any new backend methods to `SetupWizardService` in Go
5. Extend the `SetupChoices` struct in both Go (`setup_wizard_service.go`) and TypeScript (`$lib/types/setup.ts`)
6. Wire new service calls into `ApplySetup()` following the existing delegation pattern

## See Also

- [Setup and Unlock Flow](../architecture/setup-and-unlock-flow.md) -- Backend execution flow with Mermaid diagrams
- [Setup Wizard Seal Integration](../seal/setup-wizard.md) -- Seal-related integration points
