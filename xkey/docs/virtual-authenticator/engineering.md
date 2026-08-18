# Virtual FIDO2 Authenticator — Engineering Contract

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## Exported surface

### `xkey/pkg/uhid`

Linux UHID device creation and the HID report wire format:
`uhid_linux.go` (real), `uhid_stub.go` (non-Linux builds), `types.go`,
`serialize.go`, `errors.go`.

### `xkey/pkg/authenticator`

The CTAP2 implementation. One file per command:

| Command | File |
|---|---|
| `authenticatorMakeCredential` | `cmd_makecredential.go` |
| `authenticatorGetAssertion` | `cmd_getassertion.go` |
| `authenticatorGetInfo` | `cmd_getinfo.go` |
| `authenticatorClientPIN` | `cmd_clientpin.go` |
| `authenticatorCredentialManagement` | `cmd_credmgmt.go` |
| `authenticatorConfig` | `cmd_config.go` |
| `authenticatorReset` | `cmd_reset.go` |

Supporting: `authenticator.go`, `authdata.go`, `crypto.go`, `config.go`,
`entity.go`, `errors.go`, `hid_adapter.go`, `pin_protocol.go`,
`pin_protocol_v1.go`, `migration.go`.

Extensions: `ext_hmac_secret.go`, `ext_deviceconfig.go`.

Storage seams: `dao_credential_store.go`, `dao_rp_policy_store.go`.

Key material: `key_manager.go`, `key_wrapper.go`, `keybackend/`.

PIN state lives on the authenticator as `state.PINHash` with a fixed
`PINHashSize` (`cmd_config.go:474`), and `key_manager.go:253` carries a
`PINSyncPending` path that re-initializes the user PIN when a sync was deferred.

## Configuration — `xkey fido2` flags

Defaults are constants at `xkey/cmd/xkey/cmd/fido2.go:164-170`.

| Flag | Default | Meaning |
|---|---|---|
| `--storage` | `memory` | `memory`, `file`, or `barrier` |
| `--storage-path` | `./data` | path for file storage |
| `--barrier-password` | `""` | barrier password for encrypted storage |
| `--barrier-password-file` | `""` | read it from a file's first line |
| `--name` | `xKey (go-xkms)` | device name the OS sees |
| `--serial` | `""` | device serial; generated when empty |
| `--pin` | `true` | require a PIN |
| `--set-pin` | `""` | set the initial PIN (needs `--pin`) |
| `--interactive` | `false` | interactive setup |
| `--require-touch` | `true` | require user presence |
| `--timeout` | `30s` | operation timeout |
| `--backend` | `software` | `software`, `tpm2`, or `phone` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path |
| `--attestation` | `none` | `none`, `packed`, or `tpm` |
| `--phone-device` | `""` | specific paired phone; default is the default phone |
| `--password-store` | `./data/staticpw` | static password store path |
| `--socket` | `$XDG_RUNTIME_DIR/xkey/xkey.sock` | IPC socket |
| `--default-password` | `""` | password name typed on a bare touch |
| `--notify-command` | `""` | custom notification command |
| `--notify` | `dialog` | `dialog`, `passive`, `log`, or `none` |
| `--unified-pin` | `true` | share one PIN across xkey subsystems |
| `--auto-uv` | `false` | satisfy user verification without a human |
| `--cdp` | `false` | Chrome DevTools virtual-authenticator bridge |
| `--cdp-host` | `localhost` | DevTools host |
| `--cdp-port` | `9222` | DevTools debugging port |

**`--storage memory` is the default**, which means credentials do not survive a
restart unless you choose `file` or `barrier`. That is a safe default for a
first run and the wrong one for daily use.

## Invariants

- **The device is a real CTAP2 authenticator**, not an emulation of a specific
  vendor's. `--attestation` reports what it is.
- **User presence is required unless explicitly disabled.** `--require-touch`
  defaults true and `--auto-uv` defaults false. Both are deliberate defaults;
  changing either removes a human from the loop.
- **The relying party cannot distinguish backends.** `software`, `tpm2` and
  `phone` present identically over CTAP2, so the strength claim is the
  operator's to make honestly.
- **Credential storage and key material are separate seams.** The DAO stores
  hold credential records; `keybackend` holds key material. Do not merge them.
- **`--storage memory` loses credentials on exit.** No warning is emitted; it is
  the documented default.
- **CTAP2 is one command at a time per channel.** The HID adapter serialises.
- **PIN state is `state.PINHash` with a fixed size** — treat it as the
  authenticator's own credential, distinct from the barrier or the OS.

## Error semantics

`xkey/pkg/authenticator/errors.go` and `xkey/pkg/uhid/errors.go`. CTAP2 status
codes are returned to the consumer, so failures surface as `CTAP2_ERR_*` in a
browser's console rather than as Go errors.

**Fail closed:** no user presence within `--timeout`, wrong PIN, PIN retries
exhausted, an unavailable backend (TPM absent, phone unpaired), or a credential
not present. None of them fall back to a weaker path — in particular, a `tpm2`
backend that cannot reach its TPM does not silently become `software`.

## Persistence

- **`memory`** — nothing survives the process.
- **`file`** — under `--storage-path` (default `./data`).
- **`barrier`** — encrypted, keyed by the barrier password.

Credential records go through the DAO stores; key material through
`keybackend` to software, TPM or phone. RP policies are
`dao_rp_policy_store.go`.

`migration.go` handles moving between earlier PIN-state layouts —
`xkey/pkg/gui/migration.go` documents the historical paths
(`<dataDir>/pin-state.json` for the CLI path, `<dataDir>/tpm/pin_state.json`
for the GUI/TPM path) and the deprecated `FilePINManager` they came from.

## Test strategy

- **Unit** — per-command suites in `xkey/pkg/authenticator`, plus PIN protocol,
  extensions, key wrapping and the DAO stores.
- **UHID** — `xkey/pkg/uhid` serialization and device tests; the stub build is
  compiled on non-Linux.
- **Browser end to end** — Playwright specs against the CDP bridge, and
  `go-xkms/test/integration/webauthn-browser`.
- **Cross-module** — `go-xkms/test/integration/logins` drives xkey against a
  real relying party.

## Observability

`--notify` selects how the user-presence prompt reaches a human: `dialog`
(interactive), `passive` (desktop notification), `log`, or `none`.
**`--notify none` combined with `--require-touch true` produces an
authenticator that waits silently for a touch nobody was asked for** — the
symptom is a browser that hangs until the timeout. `--notify-command` overrides
with a custom command.
