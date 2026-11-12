# ACME Client Namespace

> **Status: PARTIAL** · Feature: `acme` · Module: `go-xkms/xkey` · Built: `account`, `endorse`, `enroll`, `renew`, `revoke` (CLI), GUI Go service (`account`, `renew`, `revoke`); planned: the GUI view, GUI `enroll`/`endorse`
> Scope: the `xkey acme` namespace; the ACME client itself is [acme-issuance](../../../docs/acme-issuance/).

## Purpose

`xkey acme` will put ACME certificate issuance beside xkey's TPM, seal,
platform-trust and device verbs, in the CLI and the GUI alike. It is a front
end only: the ACME client is one library, `pkg/acme/client`, and xkey carries
no client logic of its own.

## Verbs

| Verb | Purpose | State |
|---|---|---|
| `account register\|update\|deactivate` | Create and manage the ACME account | Implemented (CLI) |
| `enroll` | Enroll the local TPM through `enroll-01`, `endorse-01` or `device-attest-01`; writes the IDevID, IAK and chain as PEM | Implemented |
| `endorse` | Obtain an EK certificate for the local TPM through `endorse-01` (`--ip` required); writes the PEM certificate only, to `--out` or stdout | Implemented |
| `renew` | Renew an issued certificate (`--cert`, `--domain`); writes the PEM certificate only | Implemented |
| `revoke` | Revoke an issued certificate (`--cert`, `--reason` RFC 5280 name or number) | Implemented (CLI) |

Shared flags: `--directory` (ACME directory URL), `--account-key` (PEM
account key; never printed), `--trusted-root` (repeatable) and
`--system-roots`. `account deactivate` is irreversible and needs `--yes`.
The server finds the account from the account key (RFC 8555 7.3.1), so the
verbs keep no local account state.

Code: `xkey/cmd/xkey/cmd/acme.go`, `acme_account.go`, `acme_revoke.go`, `acme_endorse.go`.

## Call path

```
xkey acme (CLI and GUI) -> go-xkms/sdk/go -> go-xkms/pkg/acme/client
```

xkey reaches the client only through `sdk/go`, as every xkey feature does.
The dedicated `cmd/acme-client` binary is the other front end over the same
library, for installers, the initrd and hosts without xkey.

## Status

`account`, `endorse`, `enroll`, `renew` and `revoke` are implemented in the
CLI. The GUI's Go side is implemented: the Wails-bound `services.ACMEService`
(`xkey/pkg/gui/services/acme_service.go`) serves account register, update and
deactivate, revoke and renew, on the client factory the CLI shares
(`xkey/pkg/gui/services/acme_client.go`). The Svelte view and GUI `enroll`
and `endorse` (through the GUI's TPM) are planned. See the `acme` row in [docs/SPEC.md](../../../docs/SPEC.md#xkey).
