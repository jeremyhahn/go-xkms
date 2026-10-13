# Enterprise Setup Architecture

> **Status: REFERENCE** · Last verified: 2026-10-13
> How personal and enterprise deployments differ; the wizard flows are normative in [setup-wizard](../setup-wizard/architecture.md), the policy fields and HMAC in [enterprise-mode.md](enterprise-mode.md).

## Deployment Modes

- **Personal**: single user, no authentication gate. Barrier unseal is
  sufficient for daily use.
- **Enterprise**: a Security Officer (SO) provisions the device and seals a
  security policy, then a user onboards with the SO's authorization.

Enterprise mode is detected by the existence of the HMAC file
`~/.config/xkey/xkey_policy.hmac`, not by a config flag
(`IsEnterpriseMode`, `xkey/pkg/config/policy_integrity.go:72`). A CLI command
that acts on the policy consults it only through `config.LoadVerifiedPolicy`,
which fails closed in enterprise mode until the SO PIN is supplied (see
[enterprise-mode.md](enterprise-mode.md#verification-on-the-cli-path)).

## Unified Config

All settings live in one YAML file. `Load` reads the first one found; the
system file is a fallback, not a merge (`xkey/pkg/config/load.go:82-95`):

| Path | Role |
|------|------|
| `~/.config/xkey/xkey.yaml` | Per-user config, read first |
| `/etc/xkey/xkey.yaml` | Read only when there is no user config (`load.go:34`, `:77`) |

`XKEY_`-prefixed environment variables override the file (`XKEY_LOG_LEVEL=debug`).
The top-level sections are those of `Config` (`xkey/pkg/config/config.go:28-48`):
`policy`, `backend`, `backends`, `fido2`, `piv`, `oath`, `phone`, `xkmsd`,
`oidc`, `agent`, `tpm`, `password_protection`, `trust`, `attestation`, `log`,
`gui`, `state`, `barrier` and `device`. Their keys are in
[app-configuration.md](app-configuration.md).

Only `policy:` is covered by the HMAC. Every other section can be changed
freely by the user.

## Tamper Scenarios

| Scenario | Result |
|----------|--------|
| Policy section modified | HMAC mismatch at SO login; the SO is logged in with `tamper_detected` set and `DefaultPolicy()` stays in effect (`xkey/pkg/gui/services/auth_service.go:184-201`) |
| HMAC file deleted | Enterprise mode is no longer detected; the device runs in personal mode |
| Both intact | Policy verified at SO login and applied for the session |

The HMAC file has a `tpm_nv_index` field (`policy_integrity.go:65`), but
nothing reads or writes it, so verification always needs the SO PIN.

## Setup Flows

`GetStartupState` tells the frontend which flow to show; SO provisioning
(`ApplySOProvisioning`) and user onboarding (`ApplyUserOnboarding`) are
described step by step in
[setup-wizard/architecture.md](../setup-wizard/architecture.md#flows) and
[enterprise-mode.md](enterprise-mode.md#so-provisioning-flow).

## Auth Gate

In enterprise mode the login gate (`AuthLoginGate.svelte`) takes the SO PIN
or the User PIN. The SO lands in the admin shell (`AdminApp.svelte`), which
can switch to the user app or log out (`AdminApp.svelte:21`); a user lands in
the user app. In personal mode the gate is skipped. The `locked`, `user` and
`so_admin` modes are in [enterprise-mode.md](enterprise-mode.md#authmode-states).

## Policy Permissions

Each `user_can_*` field is a deny switch enforced at the service call it
governs, not only a UI hint. Setting it to `false` makes the call return a
typed `*PolicyDeniedError`:

| Field | Controls |
|-------|----------|
| `user_can_configure_auto_unseal` | `AppService.ToggleBarrierAutoUnseal` (also requires `allow_auto_unseal`) |
| `user_can_configure_theme` | `AppService.SetTheme` (`app_service.go:593`) |
| `user_can_manage_trust_store` | Mutating `TrustService` calls |
| `user_can_view_audit_log` | `AuditService.GetEntries` / `ExportEntries` (`audit_service.go:120`, `:169`) |
| `user_can_manage_sealed_data` | `SealService.SealData` / `DeleteBlob` (`seal_service.go:739`, `:993`) |
| `user_can_change_own_pin` | `PINService.ChangeUserPIN` (`pin_service.go:351`) |
| `user_can_toggle_dev_tools` | `AppService.SetDeveloperTools` (`app_service.go:643`; also requires `developer_tools_enabled`) |
| `user_can_configure_extension` | `AutoFillService.SetEnabled` / `SetPolicy` / `SetRequireAuthentication` (`autofill_service.go:173`, `:245`, `:280`) |

The full field list, defaults and the requirement checks are in
[enterprise-mode.md](enterprise-mode.md#policy-section).

## Factory Reset

The confirmation screen (`xkey/frontend/src/views/FactoryReset.svelte:10`)
asks for the phrase `FACTORY RESET` and the SO PIN.
`SetupWizardService.FactoryReset`
(`xkey/pkg/gui/services/setup_wizard_service.go:1630`) refuses without a
verified SO PIN, then:

1. Resets the TPM (`TPMService.FactoryReset`, `tpm_service.go:1398`)
2. Removes the policy HMAC file, leaving enterprise mode
3. Removes the unified config file
4. Resets the GUI config, so setup runs on next launch

Step failures are collected and reported together rather than stopping the reset.

## Key Files

| File | Purpose |
|------|---------|
| `xkey/pkg/config/config.go` | `Config` struct and validation |
| `xkey/pkg/config/load.go` | Path resolution, Viper loading |
| `xkey/pkg/config/save.go` | Atomic config persistence |
| `xkey/pkg/config/policy.go` | `PolicySection`, canonical JSON, defaults |
| `xkey/pkg/config/policy_integrity.go` | HMAC compute, verify, write, key derivation |
| `xkey/pkg/gui/services/setup_wizard_service.go` | `ApplySetup`, `ApplySOProvisioning`, `ApplyUserOnboarding`, `FactoryReset` |
| `xkey/pkg/gui/services/auth_service.go` | `LoginSO`, `LoginUser`, mode management |
| `xkey/frontend/src/views/SetupWizard.svelte` | Setup wizard UI |
| `xkey/frontend/src/views/AdminApp.svelte` | SO admin shell |
| `xkey/frontend/src/views/FactoryReset.svelte` | Factory reset confirmation |
| `xkey/frontend/src/lib/components/AuthLoginGate.svelte` | Enterprise login overlay |
| `xkey/frontend/src/lib/stores/auth.ts` | Auth state store |
| `xkey/frontend/src/lib/stores/wizard.ts` | Wizard state store |
