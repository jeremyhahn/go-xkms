# xKey Desktop GUI — Engineering Contract

> **Status: NORMATIVE** · Feature: `gui` · Module: `go-xkms/xkey` · Last verified: 2026-09-30

## Exported surface — `*App` itself

`App` is bound alongside its services (`xkey/pkg/gui/app.go:2579`), so these
top-level methods are also frontend-callable:

| Method | Purpose |
|---|---|
| `InitializeDataDir() error` | `app.go:1607` |
| `PostUnlockInitialize() error` | Runs after the app-lock / barrier unlocks (`app.go:1620`) |
| `PostBarrierUnseal() error` | `app.go:1636` |
| `ToggleFIDO2Authenticator(enabled bool) error` | `app.go:3133` |
| `EmitEvent(event events.Event)` | `app.go:3498` |
| `GetStatus() *services.AppStatus` | `app.go:3507` |
| `GetConfig() *services.GUIConfigData` / `UpdateConfig(cfg) error` | `app.go:3512-3521` |
| `GetTheme() string` / `SetTheme(theme string) error` | `app.go:3522-3541` |
| `Quit()` / `ShowWindow()` / `HideWindow()` | `app.go:3542, 3588, 3607` |
| `BackendRegistry() backendregistry.Registry` | `app.go:339` |

`Run() error` (`app.go:2573`) is the process entry point, not a frontend
call — it blocks until the application exits.

## Exported surface — backend services

~44 `*services.XxxService` types, each a struct field on `App`
(`app.go:100-146`) and bound in `Run()`'s `bindings` slice
(`app.go:2578-2660`). The service inventory with one-line descriptions:

| Service | Struct field | Description (from its doc comment) |
|---|---|---|
| `AppService` | `appService` | Application-level state & config, `services/app_service.go` |
| `PhoneService` | `phoneService` | Phone backend operations — see [../phone/engineering.md](../phone/engineering.md) |
| `FIDO2Service` | `fido2Service` | FIDO2/WebAuthn operations |
| `FIDO2DeviceService` | `fido2DeviceService` | FIDO2 device/service host (concurrency-safe) |
| `OATHService` | `oathService` | TOTP/HOTP operations |
| `StaticPasswordService` | `staticPWService` | Static password store, access modes, locking |
| `PIVService` | `pivService` | PIV certificate/key operations; delegates to a remote transport client when one is set, else a local file-backed manager |
| `TPMService` | `tpmService` | TPM2 device operations |
| `TPMPolicyService` | `tpmPolicyService` | Named TPM policies: the connected server's, else in-process over xKey's own TPM (`LocalTPMPolicies`, opened by `ensureLocalTPMPolicies`); follows the server connection through `applyConnectionEvent` |
| `AuditService` | `auditService` | Audit log operations |
| `AdminService` | `adminService` | Server administration; hidden by default, privilege-gated |
| `ConnectionService` | `connectionService` | — |
| `KeyService` | `keyService` | — |
| `SSHService` | `sshService` | SSH key/backend operations across software/tpm2/pkcs11/cloud/remote backends |
| `SSHProfileService` | `sshProfileService` | Folder-organized SSH connection profiles referencing xkey-managed keys |
| `SSHConnectService` | `sshConnectService` | Launches `ssh` in the system terminal over an in-process agent |
| `SSHConsoleService` | `sshConsoleService` | Loopback WebSocket bridge for an xterm.js console to SSH |
| `SSHLocalService` | `sshLocalService` | Read-only discovery of local `ssh_config`/agent identities |
| `StorageService` | `storageService` | — |
| `NotificationService` | `notificationService` | — |
| `SealService` | `sealService` | Barrier-backed encrypted storage, auto-selected backend |
| `SealProtectionService` | `sealProtectionSvc` | UI-level access gating for seal operations |
| `AutoUnsealService` | `autoUnsealService` | Orchestrates sealed auto-unseal, coordinating `SealService` + `StorageService` |
| `BarrierAutoUnsealService` | `barrierAutoUnsealService` | Barrier auto-unseal through a named TPM policy the TPM enforces |
| `OIDCService` | `oidcService` | xKey's local OIDC providers, browser logins and refresh loops; unaffected by a server connection |
| `OIDCServerService` | `oidcServerService` | The connected xkmsd's server-side OIDC credentials; follows the server connection through `applyConnectionEvent` and copies access tokens through `ClipboardService` |
| `ClipboardService` | `clipboardService` | — |
| `TrustService` | `trustService` | Trust store operations |
| `SetupWizardService` | `setupWizardService` | First-run setup, composing `StorageService`/`TPMService`/`PINService`/etc. |
| `PINService` | `pinService` | — |
| `BarrierService` | `barrierService` | Cross-platform encrypted storage, automatic strategy selection |
| `AuthService` | `authService` | App-lock / SO-PIN gate |
| `BrowserService` | `browserService` | Optional; appended only if non-nil |
| `SecureBrowserService` | `secureBrowserService` | Optional; browser profile configuration |
| `APIExplorerService` | `apiExplorerService` | Optional; authenticated HTTP client via ServerRegistry/TrustStore |
| `ShareService` | `shareService` | Shamir share import/export/submission |
| `CustodianService` | `custodianService` | Frontend-safe custodian types + events |
| `TenantService` | `tenantService` | Tenant operations + events |
| `AgentService` | `agentService` | Concurrent-safe agent operations |
| `AutoFillService` | `autofillService` | AutoFill extension policy |
| `PairingService` | `pairingService` | Browser-extension pairing (distinct from phone pairing) |
| `AppLockService` | `appLockService` | App-lock for installations with no barrier at all |
| `PKCS11Service` | `pkcs11Service` | — |
| `PasswordProtectionService` | `passwordProtectionSvc` | UI-level access gating (same pattern as `SealProtectionService`) |
| `TeamService` | `teamService` | Team management |
| `CertificateService` | `certificateService` | — |
| `SecurityFactorService` | `securityFactorService` | Proxies to the connected platform server's REST API |

(Descriptions are each service's own doc comment, condensed; see the cited
file for the full comment. "—" means the doc comment did not add detail
beyond the type name.)

## Invariants

- **Every service in the `Bind` slice must be non-nil**, or Wails panics at
  startup — which is why `browserService`, `secureBrowserService`, and
  `apiExplorerService` are only appended when non-nil rather than always
  included (`app.go:2650-2660`): those three can fail to initialize on some
  platforms.
- **Local and server OIDC never mix.** `OIDCService` keeps xKey's local
  providers exactly as without a server; `OIDCServerService` reaches only the
  connected xkmsd (`SetClient` on `server:connected`, `SetClient(nil)` on
  disconnect or error) and holds no token: `CopyServerAccessToken` fetches a
  current access token and writes it straight to the clipboard, and
  `ImportCodexAuth` parses the pasted auth.json with `xkms.ParseCodexAuth`
  and never logs it. Its sentinels are `ErrOIDCServerNotConnected`,
  `ErrOIDCServerNameRequired`, `ErrOIDCServerScopeInvalid`,
  `ErrOIDCServerAccessTokenRequired`, `ErrOIDCServerExpiryInvalid`,
  `ErrOIDCServerCodexAuthRequired` and `ErrOIDCServerClipboardUnavailable`.
- **`App` is a composition root, not a place for business logic.** Its job
  is wiring (`SetXxx` calls during startup) and the thin top-level methods
  above; feature behavior lives in the service the method delegates to.
- **The Wails IPC and the Unix-socket IPC (`ipc.Server`) are separate
  authorization surfaces.** A method reachable over one is not automatically
  reachable over the other — `guiIPCHandler`'s state methods
  (`ipc_state.go`) are deliberately read-only and return no secret material,
  because that socket's only access control is filesystem permission (see
  [architecture.md](architecture.md)).
- **A GUI settings save can never silently wipe a `GUIConfig` field the
  frontend does not edit.** `services.GUIConfigData` (`services/app_service.go:81`)
  is a DTO carrying only the GUI-editable subset of `GUIConfig`
  (`config.go:52`); `configToData` (`app.go:235`) builds it from the loaded
  config at startup, and the `AppService.ConfigUpdater` callback wired in
  `NewApp` (`app.go:2401`) persists edits by calling `applyDataToConfig`
  (`app.go:281`), which merges the DTO onto a **copy of the existing**
  `GUIConfig` rather than rebuilding one from scratch. Any `GUIConfig` field
  the DTO does not carry — currently `ServerSPKIPin` and
  `FIDO2FirmwareVersion`, neither of which has a Settings UI control — is
  therefore always preserved from the pre-existing config instead of being
  zeroed. `TestConfigDataRoundTrip` (`config_data_roundtrip_test.go`) walks
  every exported `GUIConfig` field via reflection and fails if a new field
  is added without either an entry in `configToData`/`applyDataToConfig` or
  a documented reason in `unmappedGUIConfigDataFields`. This is the fix for
  go-xkms#1122, where the predecessor `dataToConfig` rebuilt `GUIConfig`
  from the DTO alone and silently zeroed both fields on every save.

## Errors — `xkey/pkg/gui/errors.go`

GUI-lifecycle sentinels: `ErrWindowCreate`, `ErrWindowShow`, `ErrWindowHide`,
`ErrConfigLoad`, `ErrConfigSave`, `ErrServiceStart`, `ErrServiceStop`,
`ErrTraySetup`, `ErrTrayIconLoad`, `ErrEventEmit`, `ErrNotInitialized`,
`ErrInvalidTheme`, `ErrAlreadyRunning` (`errors.go`). Each backend service
additionally defines its own error sentinels in its own file (for example
`PhoneService`'s, documented in [../phone/engineering.md](../phone/engineering.md));
there is no shared error type across services beyond Go's `error` interface.

## Configuration

`xkey/pkg/gui/config.go` — theme (`ThemeLight`/`ThemeDark`/`ThemeSystem`),
window geometry, start-minimized, and other GUI-local settings, loaded
through the same config precedence the CLI uses (flags > env > config file).
`xkey/pkg/gui/enterprise_policy.go`'s `startupEnterprisePolicy` resolves an
enterprise policy that can apply before the Security Officer has logged in —
see [../setup-wizard/](../setup-wizard/engineering.md).

## Tests

`xkey/pkg/gui` and `xkey/pkg/gui/services` are two of the largest test
surfaces in the module — each backend service file above has a matching
`_test.go`, and `services/` additionally carries dozens of
`coverage_*_test.go`/`final_*_test.go`/`surgical_*_test.go` files targeting
specific branches (barrier strategies, TPM reunseal paths, setup-wizard
factory reset, PKCS#11 slot registries, and more). Run a single package's
tests rather than the whole module during development:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' ./pkg/gui/services/... -run TestPhoneService
```
