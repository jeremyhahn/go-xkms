# xKey Desktop GUI — Architecture

> **Status: NORMATIVE** · Feature: `gui` · Module: `go-xkms/xkey` · Last verified: 2026-09-30

This file replaces the pre-convention `gui/architecture.md`. The other files
in this folder — `README.md`, `features.md`, `design-system.md`,
`setup-wizard.md`, `api-explorer.md`, `browser-settings.md`, `ROADMAP.md` —
predate the five-file convention and are superseded where they disagree with
this folder; see the "Disagreements" note at the end.

## What it is

The desktop GUI is a [Wails v2](https://wails.io) application: a Go backend
(`xkey/pkg/gui`) driving native OS windowing, paired with a Svelte/TypeScript
frontend (`xkey/frontend`) rendered in a native WebView. `xkey/wails.json`
configures the build (`build:dir: cmd/xkey`, frontend build via `npm run
build`, tags `ble,production,codec_json`).

```
Frontend (Svelte, xkey/frontend/src)
    views/*.svelte  --calls-->  wailsjs/go/services/<Service>  (generated)
                                        |
                                        v
Go backend (xkey/pkg/gui)
    App (app.go)  --binds-->  ~44 *Service structs (xkey/pkg/gui/services)
                                        |
                                        v
                    xkey/pkg/*  (phone, authenticator, ssh, pkcs11, ...)
                    go-xkms sdk/go  (xkmsd, backends)
```

## Entry point and the App type

`App` (`xkey/pkg/gui/app.go`) is the central orchestrator: it owns every
backend service as a struct field (`app.go:100-146`), wires cross-service
dependencies during startup (for example
`phoneService.SetBarrierService(barrierService)`, `app.go:755`), and starts
the Wails runtime in `Run()`. `Run()` builds the `Bind` slice — every backend
type the Wails runtime exposes to the frontend — and passes it to
`wails.Run` via `options.App{Bind: bindings, ...}` (`app.go:2578-2650`).

`App` itself is also in the `Bind` slice (`app.go:2579`), so a handful of
top-level methods on `*App` are frontend-callable in addition to the ~43
service types.

## The backend-service surface

Every struct in `xkey/pkg/gui/services` that `Run()` binds becomes a
frontend-callable object at `wailsjs/go/services/<TypeName>`. The set is
large — see [api.md](api.md) for the full inventory with citations — and
groups naturally by domain:

| Domain | Representative services |
|---|---|
| Credentials & backends | `FIDO2Service`, `FIDO2DeviceService`, `OATHService`, `PIVService`, `StaticPasswordService`, `SSHService`/`SSHProfileService`/`SSHConnectService`/`SSHConsoleService`/`SSHLocalService`, `PKCS11Service`, `TPMService`, `TPMPolicyService`, `KeyService`, `CertificateService` |
| Phone | `PhoneService` — see [../phone/](../phone/architecture.md) |
| Barrier / seal / lock | `SealService`, `SealProtectionService`, `BarrierService`, `BarrierAutoUnsealService`, `AutoUnsealService`, `AppLockService`, `PasswordProtectionService`, `PINService` |
| Identity & auth | `AuthService`, `SecurityFactorService`, `OIDCService` (local providers), `OIDCServerService` (the connected xkmsd's server-side OIDC credentials, shown beside the local providers only while connected), `PairingService` (extension pairing) |
| Admin & multi-tenant | `AdminService`, `TrustService`, `TenantService`, `TeamService`, `AgentService`, `ConnectionService` |
| Browser | `BrowserService`, `SecureBrowserService`, `AutoFillService` (all three appended only when non-nil, `app.go:2650-2659`) |
| Storage, audit, misc | `StorageService`, `AuditService`, `NotificationService`, `ClipboardService`, `SetupWizardService`, `ShareService`, `CustodianService`, `APIExplorerService`, `AppService` |

## Two IPC surfaces, not one

The GUI is reachable two ways, and they are architecturally distinct:

1. **Wails bindings** — in-process, generated at build time, the frontend's
   only channel to the Go backend. This is what [api.md](api.md) documents.
2. **A Unix-domain-socket IPC server** (`ipc.Server`, field
   `ipcServer *ipc.Server` at `app.go:196`) that lets *other processes*
   running as the same user reach the live GUI: the CLI's `xkey touch`,
   `xkey pin status`, `xkey barrier status`, and the browser extension's
   native-messaging host. `guiIPCHandler` implements four separate
   interfaces for this — `ipc.Handler` (touch/password/status),
   `ipc.AutofillHandler`, `ipc.PairingHandler`, and `ipc.StateHandler`
   (`app.go:3159-3164`, `xkey/pkg/gui/ipc_state.go:32-33`). The state
   queries exist specifically so `xkey pin status`/`xkey barrier status`
   report this process's live (possibly unsealed) state instead of a fresh
   process's false-negative read of the sealed on-disk data directory
   (comment at `ipc_state.go:22-30`). No PIN, password value, or key
   material is ever returned over it; the socket's only authentication is
   filesystem permission — a `0700` directory the server refuses to reuse
   if it is a symlink or another user's. On startup a socket already held by
   a live listener is taken over only when `ipc.ReclaimSocket` confirms the
   directory and the socket are this user's (`app.go:3330-3337`,
   `xkey/pkg/ipc/socketdir.go:135`); see
   [agent-automation/engineering.md](../agent-automation/engineering.md).

## Systray

`TrayManager` (`xkey/pkg/gui/systray.go`) is optional tray integration built
on `fyne.io/systray`. Its menu is a live status/shortcut surface, not a
duplicate of the window: status line, a Phone submenu (connection status,
Connect/Disconnect, Attest Device), a managed-key counter, storage status, an
FIDO2 submenu (Start/Stop Bridge, Credentials), OATH/PIV/TPM entries,
Settings, Audit Log, and Quit (`systray.go:65-121`). Phone connection status
reaches the tray through the same `PhoneStatusChangeFunc` hook `PhoneService`
uses to notify the rest of the app (`app.go:2376-2383`).

## Events

`xkey/pkg/gui/events` defines the typed event vocabulary the Go backend
pushes to the frontend over the Wails runtime event system — phone
(`phone:connected`, `phone:disconnected`, `phone:scan_result`,
`phone:pairing_request`), key, OATH, FIDO2 (bridge lifecycle, touch
required/resolved, credential created), attestation, and policy-violation
events (`xkey/pkg/gui/events/events.go:24-58`). Each domain service emits
its own subset; there is no central event bus beyond the shared `EventType`
vocabulary and the Wails runtime's own dispatch.

## Configuration

`xkey/pkg/gui/config.go` defines the GUI's local config (theme constants
`ThemeLight`/`ThemeDark`/`ThemeSystem`, window geometry, start-minimized,
etc.), loaded through the same `viper`-backed precedence (flags > env >
config file) the CLI uses. `xkey/pkg/gui/enterprise_policy.go`'s
`startupEnterprisePolicy` resolves an enterprise policy the GUI may need to
apply before the Security Officer has logged in — see
[setup-wizard](../setup-wizard/architecture.md) for what that policy governs.

## Frontend

`xkey/frontend` is Svelte 4 + Vite + TypeScript + Tailwind (`package.json`).
Structure: `src/views` (one `.svelte` per screen — Dashboard, Pairing,
PairingDetail, FIDO2, FIDO2Credential, OATH, PIV, PIVSlot, TPM, TPMInfo, SSH,
Passwords, Certificates, Keys, IdentityKeys, PlatformKeys, Seal,
SecurityFactors, OIDC, Browser, APIExplorer, TrustStore, AuditLog, Admin and
its sub-views, Settings and its sub-views, SetupWizard, FactoryReset,
PolicyEditor, UserPINManagement — `xkey/frontend/src/views/`), `src/lib/
stores` (Svelte stores per domain: `app`, `auth`, `auth-factors`, `backends`,
`connection`, `events`, `fido2`, `keys`, `notifications`, `oath`, `oidc`,
`pairing`, `ssh`, `theme`, `touch`, `wizard`), `src/lib/components`,
`src/lib/api`, `src/lib/actions`, `src/lib/types`, and the generated
`src/wailsjs`/`wailsjs` bindings directories.

## Security architecture, briefly

The GUI carries no separate custody model of its own: it drives the same
barrier, PIN, TPM, and backend-registry primitives the CLI uses, through the
service layer above rather than by re-implementing key handling. Where a
service must hold sensitive material at rest before a barrier exists (for
example `PhoneService`'s local Noise private key), it follows the same
fail-closed rule documented in [../phone-hsm/engineering.md](../phone-hsm/engineering.md)
(#42): sealed when a barrier is open, refused when one is initialized but
not open, and unsealed-with-a-warning only when no barrier exists.

## Disagreements with the superseded `gui/` files

Verified against the code as of this revision:

- **`gui/architecture.md`'s "Backend Services" section listed six services**
  (`AppService`, `PhoneService`, `FIDO2Service`, `OATHService`,
  `TPMService`, `AdminService`). The actual `Run()` binding list is
  ~44 services (`app.go:2578-2650`) — see [api.md](api.md).
- **Its "Directory Structure" showed `pkg/gui/bindings/bindings.go`.** No
  such file or package exists; the `Bind` slice is built inline in
  `App.Run()`.
- **Its frontend view list included `Devices.svelte`.** The actual view is
  `Pairing.svelte`/`PairingDetail.svelte`
  (`xkey/frontend/src/views/Pairing.svelte`); there is no `Devices.svelte`.
  Its view list is also missing the large majority of the ~30 views that
  exist today (SSH, PIV, TPM detail, Seal, SecurityFactors, OIDC, Browser,
  APIExplorer, TrustStore, Admin sub-views, Settings sub-views,
  SetupWizard, and more).
- **Its System Architecture diagram's Go-backend box names a "Crypto
  Backend" service.** No service by that name exists; cryptographic backend
  selection is a `go-xkms` SDK concept the individual credential services
  (FIDO2, PIV, SSH, ...) each configure, not a single GUI service.
