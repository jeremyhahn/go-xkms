# FIDO2/WebAuthn Security Key

> **Status: REFERENCE** · Last verified: 2026-10-13
> Orientation for `xkey fido2`; the [fido2](architecture.md) and [virtual-authenticator](../virtual-authenticator/architecture.md) feature folders are normative.

`xkey fido2` runs a FIDO2/WebAuthn authenticator that appears to the browser
as a USB HID security key through Linux UHID. Keys are held by the software
backend, a TPM 2.0, or a paired phone. `getInfo` advertises
`pinUvAuthProtocols: [2, 1]`, and the client picks the protocol per request
(see [engineering.md](engineering.md#pin-protocol-v1-and-v2)).

## Quick Start

```bash
# Software backend (the default, fido2.go:190)
sudo xkey fido2

# TPM-backed keys
sudo xkey fido2 --backend tpm2

# Keys on a paired phone
sudo xkey fido2 --backend phone

# Establish the initial PIN from stdin and prompt in the terminal for presence
echo 123456 | sudo xkey fido2 --set-pin-stdin --interactive
```

`--backend` accepts only `software`, `tpm2` and `phone`; anything else fails
with `ErrFIDO2InvalidBackend` (`xkey/cmd/xkey/cmd/fido2.go:59`, `:277`).
Credentials are kept in memory unless `--storage file` or `--storage barrier`
is given (`fido2.go:377`). Every flag, its environment variable and its
config-file key are in
[virtual-authenticator/cli.md](../virtual-authenticator/cli.md#xkey-fido2--run-the-authenticator).

## Commands

`xkey fido2` (alias `xkey fido`, `fido2.go:306-307`) and its subcommands:

| Command | Source | Documented in |
|---------|--------|---------------|
| `xkey fido2`, `xkey fido2 start` | `fido2.go`, `fido2_status.go:48` | [virtual-authenticator/cli.md](../virtual-authenticator/cli.md) |
| `xkey fido2 status` | `fido2_status.go:63` | [cli.md](cli.md#xkey-fido2-status) |
| `xkey fido2 policy`, `profile` | `fido2_policy.go:62`, `:123` | [virtual-authenticator/cli.md](../virtual-authenticator/cli.md) |
| `xkey fido2 init-token`, `change-so-pin` | `fido2_init_token.go:90`, `:125` | [virtual-authenticator/cli.md](../virtual-authenticator/cli.md) |
| `xkey fido2 provision-attestation` | `fido2_provision_attestation.go:137` | [cli.md](cli.md#xkey-fido2-provision-attestation) |
| `xkey touch` | `touch.go:32` | [cli.md](cli.md#xkey-touch) |
| `xkey unlock` | `unlock.go` | [cli.md](cli.md#xkey-unlock) |

## User Presence

`--require-touch` defaults to `true`, so every ceremony waits for presence
(`fido2.go:399`). Presence is answered in the terminal with `--interactive`
(`:397`), or through a desktop notification (`--notify`, default `dialog`,
`:425`) followed by `xkey touch`. A script can approve with `xkey touch`
against the daemon's IPC socket. See [user.md](user.md).

## Security Officer PIN

`xkey fido2` registers no SO PIN flags. The host PIN service's SO and User
PINs are managed by `xkey pin`: `set-so`, `set-user` (`pin_set.go:32`, `:61`),
`change-so`, `change-user` (`pin_change.go:23`, `:41`), `verify`
(`pin_verify.go:30`), `status` (`pin_status.go:54`) and `reset-lockout`
(`pin_reset.go:25`).

The authenticator's own CTAP2 SO PIN is a separate credential, set with
`xkey fido2 init-token` and changed with `change-so-pin`. Over CTAP it is
reached through the `authenticatorConfig` vendor subcommand
(`AuthConfigCmdVendorPrototype`, `0x80`), which carries vendor command IDs
`0x01`-`0x0B` (`xkey/pkg/authenticator/cmd_config.go:38-75`). See
[virtual-authenticator/cli.md](../virtual-authenticator/cli.md#the-token-lifecycle--init-token-change-so-pin-and-provision-attestation).

## Where to Go Next

| Topic | Page |
|-------|------|
| Daemon and GUI process design | [architecture.md](architecture.md) |
| PIN protocols, tokens, hmac-secret, credProtect, tamper lock | [engineering.md](engineering.md) |
| Approving, unlocking, attestation, troubleshooting | [user.md](user.md) |
| The CTAP2 engine and its storage | [virtual-authenticator](../virtual-authenticator/architecture.md) |
