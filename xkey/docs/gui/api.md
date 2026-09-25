# xKey Desktop GUI — API

> **Status: NORMATIVE** · Feature: `gui` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

The GUI's API is the set of Go types Wails binds to the frontend — there is
no separate network protocol for it (the Unix-socket IPC server is a
different, non-Wails surface; see [architecture.md](architecture.md)). Every
method listed below is generated into
`xkey/frontend/wailsjs/go/services/<Service>` and callable as
`await window.go.services.<Service>.<Method>(...)` from Svelte.

Method lists are the exported (capitalized) methods on each service type as
of this revision, grouped by what they do; `SetXxx`/wiring methods (called
by `App` during startup, not by the frontend in normal use) are grouped
separately from the operations a view actually calls. Where a service
already has its own five-file feature folder, this table points there for
full method-by-method detail instead of repeating it.

## Services with their own feature folder

| Service | Folder |
|---|---|
| `PhoneService` | [../phone/api.md](../phone/api.md) |
| `SSHService`, `SSHProfileService`, `SSHConnectService`, `SSHConsoleService`, `SSHLocalService` | [../ssh/api.md](../ssh/api.md) |
| `OATHService` | [../oath/api.md](../oath/api.md) |
| `StaticPasswordService` | [../password/api.md](../password/api.md) |
| `PKCS11Service` | [../pkcs11/api.md](../pkcs11/api.md) |
| `AgentService` | [../agent/api.md](../agent/api.md) |
| `AutoFillService` | [../autofill/api.md](../autofill/api.md) |
| `SealService` | [../seal/api.md](../seal/api.md) |
| `SetupWizardService` | [../setup-wizard/](../setup-wizard/) |

## Remaining services, by method group

`xkey/pkg/gui/services/<file>.go`, each type's exported methods:

| Service | Method groups | File |
|---|---|---|
| `AppService` | Status/config/theme (`GetStatus`, `GetConfig`, `UpdateConfig`, `GetTheme`, `SetTheme`); identity (`GetIdentity`, `UpdateIdentity`); window (`MinimizeToTray`, `ToggleFIDO2Authenticator`); file save (`SaveTextFile`, `SavePEMFile`); ~15 `SetXxxFunc` wiring hooks other services report status through | `app_service.go` |
| `TPMService` | Device/EK/IAK/IDevID/SRK info and cert import/export; PCR read/quote/event-log; key provisioning, listing, certify; NV index define/read/write/extend/delete; policy CRUD (PCR, password, composite) and assignment; lockout; factory/force clear — the largest single service (~90 methods) | `tpm_service.go` |
| `AuditService` | `GetEntries`, `ExportEntries` | `audit_service.go` |
| `AdminService` | Server status; backend list/rename/info/default/configure/test-connection; audit-log export | `admin_service.go` |
| `ConnectionService` | `GetConnectionInfo`, `IsConnected`, `GetClient`, `Connect`, `Disconnect`, `HealthCheck` | `connection_service.go` |
| `KeyService` | Backend/provider listing; key CRUD, sign/verify, encrypt/decrypt, import/export, rotate, attest; file-based sign/verify/encrypt/decrypt helpers | `key_service.go` |
| `StorageService` | `GetStatus`, `CreateVolume`, `UnlockVolume`, `LockVolume`, `MigrateToEncrypted`, `WipeVolume`, `RequireUnlocked` | `storage_service.go` |
| `NotificationService` | `SendNotification`, `NotifyTouchRequired`, enable/availability checks | `notification_service.go` |
| `SealProtectionService` | `GetStatus` (UI access gating for seal operations) | `seal_protection_service.go` |
| `PlatformPolicyService` | Policy CRUD, verify, export, PCR refresh (local and `...Remote` variants for a connected server) | `platform_policy_service.go` |
| `AutoUnsealService` | `GetStatus`, `Enable`, `Disable`, `TryAutoUnseal`, `Reseal` | `auto_unseal_service.go` |
| `BarrierAutoUnsealService` | `TryAutoUnseal`, `CaptureCurrentPCRs`, auto-unseal policy get/set/clear | `barrier_auto_unseal.go` |
| `OIDCService` | Provider CRUD/discovery; login/logout, token info/refresh/auto-refresh; script-based token post-processing (execute/save/list/delete) | `oidc_service.go` |
| `ClipboardService` | `Copy`, `CopyWithClear`, `ClearClipboard`, timeout get/set | `clipboard_service.go` |
| `TrustService` | Certificate list/add/remove/import/export (PEM/DER); browser trust bundle export; system install/remove | `trust_service.go` |
| `PINService` | PIN status, set/change/verify SO and user PIN, lockout status/reset, FIDO2 hash verify | `pin_service.go` |
| `BarrierService` | Strategy probing/selection, initialize, unseal, seal, change password, status | `barrier_service.go` |
| `AuthService` | `LoginUser`, `LoginSO`, `Logout`, mode/policy/tamper queries | `auth_service.go` |
| `BrowserService` | Trust bundle path, browser detection/config, `OpenURL` | `browser_service.go` |
| `SecureBrowserService` | `LaunchBrowser`, `LaunchBrowserWithOptions`, `DetectBrowsers`, `Rebuild` | `secure_browser_service.go` |
| `APIExplorerService` | `Execute` (authenticated HTTP call), token/history listing | `api_explorer_service.go` |
| `ShareService` | Shamir share list/import/delete/receive/submit/status | `share_service.go` |
| `CustodianService` | Custodian group CRUD, member add/remove, share distribution | `custodian_service.go` |
| `TenantService` | Tenant CRUD, barrier init/unseal | `tenant_service.go` |
| `PairingService` | Browser-extension pairing: request/verify/unpair, manifest install/uninstall — distinct from phone pairing | `pairing_service.go` |
| `AppLockService` | Lock/unlock/auto-unlock, activity recording, status — for installations with no barrier at all | `app_lock_service.go` |
| `PasswordProtectionService` | `GetStatus`, `ExportPasswordsDecrypted` | `password_protection_service.go` |
| `TeamService` | Team CRUD, member add/remove | `team_service.go` |
| `CertificateService` | `ListCertificates`, `ListAllCertificates` | `certificate_service.go` |
| `SecurityFactorService` | Factor list/add/remove/rotate/relabel; MFA policy; mTLS/FIDO2/PIV login flows; PIV card enumeration — proxies a connected platform server's REST API | `security_factor_service.go` |
| `FIDO2Service` | Credential list/get/delete; relying-party policy CRUD; phone-bridge start/stop/status/request handling; stored auth-response retrieval | `fido2_service.go` |
| `FIDO2DeviceService` | Daemon start/stop/status; touch approve/deny/pending; user-presence/intent policy get/set | `fido2_device_service.go` |

## What is not part of this API

- The Unix-domain-socket IPC server (`guiIPCHandler`) — a separate,
  non-Wails transport for the CLI and browser extension; see
  [architecture.md](architecture.md).
- `xkey/pkg/backend/phone` and other `go-xkms` SDK-level backend
  implementations — the GUI reaches them through the services above, not
  directly.
