# PIV Certificate Management — Architecture

> **Status: NORMATIVE** · Feature: `piv` · Module: `go-xkms/xkey` · Last verified: 2026-10-12

## Scope: the xkey CLI/GUI surface, not the PIV storage implementation

This folder documents `cmd/xkey/cmd/piv*.go` and
`pkg/gui/services/piv_service.go` — the CLI and GUI surface that lets an
operator store, generate, show, export, delete and CSR a certificate in a
PIV slot, across three key/storage backends.

The slot semantics, the certificate storage backends themselves (file,
TPM2 NV, PKCS#11), and their wire-level detail are owned by the go-xkms SDK
and documented in the root module: **[docs/piv-smartcard](../../../docs/piv-smartcard/)**
is the normative feature folder for that layer, including the TPM2 NV and
PKCS#11 storage detail. This folder links there rather than re-describing slot
NV offsets, file layout, or PKCS#11 object attributes.

## Shape chosen: a thin cobra layer over the SDK's PIV manager

`cmd/xkey/cmd/piv.go` defines a `PIVConfig` (backend, storage type, storage
path, TPM device, PKCS#11 library/token/PIN/SO-PIN) that
`createPIVStorage` turns into an `xkms.PIVCertificateStorage`
(`sdk/go/pivcert.go`, re-exporting `pkg/pivcert`), which it then registers
with the SDK's process-wide PIV manager (`xkms.InitializePIV`,
`xkms.RegisterPIVStore`). Every `piv` subcommand — `store`, `show`, `list`,
`export`, `delete`, `status`, `csr`, `generate`, `import` — operates through
that manager and SDK types (`xkms.PIVSlot`, `xkms.PIVSlotName`,
`xkms.PIVPrimarySlots`, `xkms.PIVCertFormat`, `xkms.ValidatePIVSlot`). xkey
owns none of the slot or storage logic itself; it owns flag parsing, output
formatting, and CSR/self-signed-certificate construction
(`piv_csr.go`, `piv_generate.go`).

**`cmd/xkey/cmd/piv.go`'s own `PIVSlot`/`CertFormat` types are a second,
local set of constants** (`PIVSlotAuthentication = "9a"`, etc.,
`CertFormatPEM`/`CertFormatDER`) used only for the CLI's own validation and
output; the SDK's `xkms.PIVSlot`/`xkms.PIVCertFormat` are the types the
storage layer actually operates on. `validatePIVSlot` converts between the
two. Do not confuse the two `PIVSlot` types when reading the code.

## Build-tag-gated backends

`--backend tpm2` and `--piv-storage pkcs11`/`tpm2` only work in a binary
built with the matching tag:

| Backend | Build tag | Production file | Stub file (opposite tag) |
|---|---|---|---|
| PKCS#11 | `pkcs11` | `cmd/xkey/cmd/piv_pkcs11.go` | `piv_pkcs11_stub.go` → `ErrPIVPKCS11BuildTagRequired` |
| TPM2 | `tpm2` | `cmd/xkey/cmd/piv_tpm2.go` | `piv_tpm2_stub.go` → `ErrPIVTPM2BuildTagRequired` |

The `software`/file backend has no build tag and is always available. Its
keys live in xKey's barrier-protected key store (`keys/`), reached through
the same `localKeyBackends` the vault key factors use and handed to the PIV
manager by `InitPIVBackendResolver`, exactly as the PKCS#11 backend hands
over its token (`ensureSoftwarePIVKeyStore`, `piv_software.go`). This
mirrors the pattern [device](../device/) uses for its `ble` tag and
[phone-hsm](../phone-hsm/) documents in more depth — a compile-time
capability split with an identical `--help` surface, not a runtime flag.

## GUI: a local/remote split mirroring the CLI's backend/storage split

`pkg/gui/services/piv_service.go`'s `PIVService` is the Wails-bound
counterpart to the CLI. It picks between two code paths per call:

- **Local** — direct SDK calls, used when `SetLocalEnabled(true)` and the
  configured local backend supports it (`getLocalSlots`,
  `getLocalCertificate`, `generateLocalKey`).
- **Remote** — a `transport.Client` call to xkmsd (`getRemoteSlots`,
  `getRemoteCertificate`, `generateRemoteKey`), used for backends the local
  process cannot reach directly (hardware HSMs behind xkmsd, for example).

`GetCAAvailability()` reports, per registered backend, whether a CA is
configured to sign PIV keys — the GUI surfaces this so `GenerateKeyAdvanced`
can offer a CA-signed output format only where one exists, the same
distinction `piv generate --output-format ca-signed` makes on the CLI.

## Corrections to the legacy `piv/README.md`

The superseded `xkey/docs/piv/README.md` documented `store`, `show`, `list`,
`export`, `delete`, `status` and a Configuration table, but:

- **It omitted `piv csr` and `piv generate` entirely** — two fully
  implemented subcommands (`cmd/xkey/cmd/piv_csr.go`,
  `cmd/xkey/cmd/piv_generate.go`) that generate a CSR for an existing slot
  key, or generate a new key pair with a self-signed, CA-signed, CSR-only,
  or bare-public-key output.
- **It omitted the PKCS#11 Security Officer PIN entirely**, a real
  persistent input alongside the user PIN
  (`pivPKCS11SOPINSource`, `cmd/xkey/cmd/piv.go:479`; neither has taken a
  value flag since go-xkms#871 replaced `--pkcs11-pin`/`--pkcs11-so-pin`
  with `--pkcs11-pin-stdin`/`--pkcs11-so-pin-stdin`, matching the rest of
  this CLI's PIN inputs).
- **Its Configuration table claimed YAML config file and environment
  variable support** (`piv.backend` / `PIV_BACKEND`, etc.) that, at the time,
  did not exist: `PIVCmd`'s flags were viper-bound with no config file or
  `AutomaticEnv` behind them. go-xkms#871 made that claim true for
  `--backend`, `--piv-storage`, `--storage-path`, `--tpm-device`,
  `--pkcs11-library` and `--pkcs11-token` (the `piv:` config section plus
  matching `XKEY_PIV_*` variables) while keeping the PKCS#11 PIN/SO-PIN on
  their own dedicated stdin/environment path, never the config file. See
  [engineering.md](engineering.md#configuration) for the current, accurate
  picture.

## What this feature deliberately does not do

- **It does not implement PIV slot or card semantics.** That is
  [docs/piv-smartcard](../../../docs/piv-smartcard/), consumed through the SDK.
- **It does not maintain its own certificate store.** `createPIVStorage`
  only selects and configures one of the SDK's existing storage
  implementations; there is no xkey-specific persistence format.
- **Phone-held PIV slots are a different feature's verbs.** `device
  phone-list`/`phone-generate`/`phone-push-cert`/`phone-pull-cert`/`piv-sync`
  operate on a paired phone's PIV material over the pairing protocol; they
  are documented in [phone-hsm/cli.md](../phone-hsm/cli.md#piv-on-the-phone),
  not here.
