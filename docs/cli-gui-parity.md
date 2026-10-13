# CLI ↔ GUI Feature Parity Audit

> **Status: REFERENCE** · Last verified: 2026-10-12
> A parity snapshot generated on 2026-04-16. The approximate counts and "examples" lists are not re-derived. The corrections below were checked against the tree on 2026-10-12.

**Generated:** 2026-04-16
**Scope:** `xkey` desktop CLI + `xkmsctl` admin CLI vs. xkey desktop (Wails) GUI

## Method

- CLI surface enumerated from `cobra.Command` declarations and `AddCommand` calls in `xkey/cmd/xkey/cmd/*.go` and `cmd/xkmsctl/*.go`.
- GUI surface enumerated from:
  - Route tables in `xkey/frontend/src/App.svelte:395-435` and `xkey/frontend/src/views/AdminApp.svelte:14-39`
  - `callBackend(...Service...)` invocations across `xkey/frontend/src/views/*.svelte`
  - Wails bindings in `xkey/pkg/gui/services/*.go`
- Playwright coverage from `xkey/frontend/tests/e2e/*.spec.ts` (33 spec files at generation; 38 on 2026-10-12, plus `live/`).

## Summary

### xkey CLI vs xkey GUI (user-facing)

| Status | Count | Percent |
|---|---|---|
| ✅ Full parity | ~42 | 38% |
| ⚠️ Partial / diverges | ~28 | 25% |
| ❌ Missing in GUI | ~24 | 22% |
| 🚫 CLI-only by design | ~16 | 15% |
| **Total** | **~110** | |

### xkmsctl CLI vs xkey GUI (server admin)

| Status | Count | Percent |
|---|---|---|
| ✅ Full parity | ~8 | 8% |
| ⚠️ Partial / via API Explorer | ~20 | 21% |
| ❌ Missing in GUI | ~60 | 63% |
| 🚫 CLI-only by design | ~7 | 8% |
| **Total** | **~95** | |

## Critical Gaps

### 1. Tenant Management
`xkey/pkg/gui/services/tenant_service.go` covers Create/List/Delete. Phase 6 of the xkey plan added per-tenant DEKs and backend-registry tenant context. No Svelte view — multi-tenant architecture is only reachable via `xkmsctl`.
- Entry point: `Tenants.svelte` inside `AdminApp.svelte`.
- Effort: Large.

### 2. CA Operations (Issue / Sign-CSR / Revoke / CRL)
`xkey/pkg/gui/services/ca_service.go` has all 7 CA operations wired. `xkey ca *` and `xkmsctl ca *` expose them. Certificates view is read-only; Keys view only signs with existing keys. No way to request/revoke/CRL via GUI.
- Entry point: expand `Certificates.svelte` with Request/Sign/Revoke/CRL actions + a CA info card.
- Effort: Medium.

### 3. SSH Key + Agent Management (closed since generation)
There is now an SSH view (`xkey/frontend/src/views/SSH.svelte`), bound to `SSHService` (`xkey/pkg/gui/services/ssh_service.go`), with key list, generate, export and delete. Keys also appear in `Keys.svelte`. Coverage is in `tests/e2e/ssh.spec.ts`.

## xkey CLI → GUI Detail (abridged — see audit transcript for full tables)

### Full parity (✅ examples)
- **piv**: list, show, delete, generate, status, backend-switch — `PIV.svelte` + `GeneratePIVKeyDialog` + `PIVSlot.svelte`
- **oath**: add, list, generate, remove — `OATH.svelte`
- **oidc**: providers add/list/remove, login, logout, token, refresh, status, stop — `OIDC.svelte`
- **password**: add, list, get, remove — `Passwords.svelte` + `PasswordAddEditDialog.svelte`
- **pin**: set-so, set-user, change-so, change-user, verify, reset-lockout, status — `UserPINManagement.svelte` + `PINDialog.svelte`
- **tpm**: info, install, provision, status, pcrs — `TPM.svelte` + `TPMInfo.svelte`
- **platform-store (seal)**: put, get, delete, list, status — Seal view
- **policy**: create, list, get, delete, set-auto-unseal, clear-auto-unseal — `PolicyEditor.svelte` + `TPM.svelte`
- **luks2**: seal, unseal, lock, wipe — Settings → Storage
- **barrier**: init, unseal, status — `SetupWizard.svelte` + `UnsealDialog.svelte` + Dashboard card
- **extension**: install, uninstall, status, unpair, pair-status — Settings → Browser
- **browser**: launch — Settings → Secure Browser

### Missing in GUI (❌ examples)
- **piv**: store (import cert), export, import (key), csr
- **oath**: scan (QR screen scan), phone sync commands
- **oidc**: aws STS credential provisioning
- **cert**: request, export
- **tpm**: quote, iak (all subcommands), idevid (all subcommands), idevid-cert
- **policy**: verify, export
- **ssh**: commands beyond key list/generate/export/delete (see `SSH.svelte`)
- **usb**: entire command group (gadget mode)
- **backup**: to-device, from-device
- **auth**: register, token, status (GUI only has enterprise login via `AuthLoginGate`)
- **device**: enroll, connect, share, import, sync/*, piv-device/*, oath phone-sync

### CLI-only by design (🚫)
- `xkey fido2` (start virtual authenticator; the GUI app itself is the authenticator)
- `xkey extension host` (Chrome native-messaging stdio launcher)
- `xkey extension serve` (headless IPC server)
- `xkey device listen` / `device relay` (daemon processes)
- `xkey uhid setup` (sudo-time command)
- `xkmsctl bootstrap auto` / `noise` / `dane` / `spki` (pre-GUI provisioning)
- `xkey completion` (shell integration)

## xkmsctl CLI → GUI Detail (abridged)

### Full parity (✅)
- **backends**: list, info — `Admin.svelte` / `AdminBackends.svelte`
- **key**: generate, list, delete, sign, verify, encrypt, decrypt, encrypt-asym — `Keys.svelte`
- **seal / unseal-data / can-seal** — Seal view
- **pkcs11**: probe, register, list-modules, connect, disconnect — `Admin.svelte`

### Missing in GUI (❌ broad strokes)
- **ca** (7 subcommands), **ca tcg** (enroll, issue-ek/ak, sign-csr)
- **cert**: save/save-chain/get/get-chain/delete/generate-ca/issue
- **tls**: get
- **admin**: create/list/get/delete/disable/enable/status
- **user**: register/login/list/get/delete/disable/enable/status/credential-config
- **credential**: submit, strategy
- **tenant**: entire group (see Gap 1 above)
- **frost**: entire group (threshold signatures)
- **key**: rotate, import, export, copy, wrap, unwrap, get-import-params

## Undertested GUI Operations (missing Playwright coverage)

- **OIDC**: no `oidc.spec.ts`. 16 `callBackend` invocations in `OIDC.svelte` untested at e2e.
- **FIDO2**: `fido2_service.StartPhoneBridge/StopPhoneBridge/GetBridgeStatus` — bound services with no UI button and no spec.
- **Keys**: `keys.spec.ts` doesn't exercise sign/verify/encrypt/decrypt round-trip or file ops.
- **Settings**: `NotificationService.SetEnabled`, `AutoFillService.SetEnabled/SetRequireAuthentication`, `BarrierAutoUnsealService.ClearAutoUnsealPolicy` — no e2e spec.
- **Pairing**: `PhoneService.SetAttestationPolicy/ClearAttestationPolicy`, `AgentService.ApproveEnrollment/RejectEnrollment` — no UI or spec.
- **TPM**: 75 `callBackend` calls; `tpm.spec.ts` covers nav only, not policy CRUD or handle editing.
- **Admin**: `RenameBackend`, `SetDefaultBackend`, cloud KMS connection testers (AWS/GCP/Azure/Vault) — no specs.

## Multi-Protocol CLI Coverage (xkmsctl)

**Existing infrastructure** (already solid — `test/integration/api/`):
- Protocols supported: Unix, REST, gRPC, QUIC, MCP, Embedded (all 6 per `test/integration/CLAUDE.md`)
- Test harness: `commands.CommandDefinition` + `commands.TestRunner` with table-driven protocol loops
- Helpers: `execCLIWithProtocol`, `execCLIWithServer`, `execCLIWithLocal`
- ~109 protocol tests across `cli_multiprotocol_test.go` (670L), `cli_complete_test.go` (1058L), `cli_comprehensive_test.go` (836L), plus `protocol_parity_test.go`, `ca_parity_test.go`, `frost_parity_test.go`, `sealing_parity_test.go`

**Covered command groups** (in `commands.AllCommands()`):
- ✅ Version, Backends, Key (full lifecycle + algorithm matrix), Cert, TLS, Frost, FIDO2, Sealing, CA

**Gaps — xkmsctl command groups with no multi-protocol parity coverage yet:**
- ❌ admin (user accounts)
- ❌ bootstrap (auto, noise, dane, spki) — though these are pre-server provisioning
- ❌ credential (submit, strategy)
- ❌ pkcs11 (probe, register, list-modules, list-tokens, init-token, connect, disconnect)
- ❌ piv (server-side PIV cert store — separate from local-xkey PIV)
- ❌ tenant (create/list/show/delete/update-entitlements/update-quotas, `cmd/xkmsctl/tenant.go`)
- ❌ user (register/login/list/get/delete/disable/enable/status/credential-config)

Adding these is mechanical: extend `commands.CommandDefinition` lists in `test/integration/api/commands/commands.go` and the table-driven framework picks them up automatically across all 6 protocols.

## Relevant Paths

- CLI entry: `xkey/cmd/xkey/cmd/root.go`, `cmd/xkmsctl/root.go`
- GUI nav: `xkey/frontend/src/App.svelte:65-82,395-435`, `xkey/frontend/src/views/AdminApp.svelte:14-39`
- Unused service bindings (bound to Wails, no Svelte consumer):
  - `xkey/pkg/gui/services/tenant_service.go`
  - `xkey/pkg/gui/services/ca_service.go`
  - `xkey/pkg/gui/services/agent_service.go` (partial — `PairAgentDialog` consumes some methods)
- Playwright suite: `xkey/frontend/tests/e2e/` (38 spec files on 2026-10-12)
