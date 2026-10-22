# OATH TOTP/HOTP — Architecture

> **Status: NORMATIVE** · Feature: `oath` · Module: `go-xkms/xkey` · Last verified: 2026-10-21

## Scope

RFC 4226 (HOTP) and RFC 6238 (TOTP) credential management for `xkey`: the
credential model and in-memory secret protection (`xkey/pkg/oath`), the CLI
(`xkey oath`), the screen-based QR enrollment path (`xkey/pkg/qrscan`), and
the GUI's `OATHService` (`xkey/pkg/gui/services/oath_service.go`). At-rest
storage location and encryption (the barrier vs. the plain JSON file) is a
`seal`-feature decision this document only summarizes; see
[seal/architecture.md](../seal/architecture.md) for the full mechanism.

Out of scope: `xkey oath sync`/`push`/`pull` (phone-backed
OATH sync, owned by the `device`/`phone` feature folders), and
`AutoFillService.GetTOTPForDomain`/`GetTOTPByID` (browser-extension TOTP
autofill, documented in [autofill/](../autofill/) — that service calls
`OATHService.GenerateTOTP` but the fill decision and policy belong there).

## Components

### Credential model (`xkey/pkg/oath/credential.go`)

`Credential` holds a TOTP or HOTP definition: `ID`, `Name`, `Issuer`,
`AccountName`, `Type` (`totp`/`hotp`), `Algorithm` (`SHA1`/`SHA256`/`SHA512`),
`Digits` (6/7/8), `Period` (TOTP step, seconds), `Counter` (HOTP), `CreatedAt`,
and `BackendID` (which store manages the credential; empty means the default
store). The shared secret is never a plain Go field: it lives in an unexported
`*secure.Buffer` (mlocked, guard-paged memory), set through `SetSecret` and
read back only through `Secret`, which returns a caller-owned `[]byte` copy
the caller wipes (go-xkms#210, go-xkms#1398). `MarshalJSON`/`UnmarshalJSON` round-trip the secret through the
historical `"secret"` JSON key without ever materializing it as a
long-lived string.

Three construction paths converge on the same validated `Credential`:
`ParseURI` (an `otpauth://` URI, from a QR code or manual paste),
`NewCredentialFromManualEntry` (name/issuer/secret typed by hand), and
`NewCredential` (programmatic, secret supplied separately). `GenerateSecret`
produces a random Base32 secret for a new enrollment.

### Generator (`xkey/pkg/oath/generator.go`)

`Generator` wraps a `Credential` and implements the RFC 4226/6238 HMAC
computation: `Generate`/`GenerateAt` (TOTP, current or given time),
`GenerateCounter` (HOTP, explicit counter), `Validate`/`ValidateWithSkew`
(TOTP with an allowed clock-skew window), `TimeRemaining`, `Counter`, and
`IncrementCounter`.

### Stores (`xkey/pkg/oath/store.go`, `backend_store.go`, `composite_store.go`)

Three implementations of the `Store` interface (`Add`, `Get`, `List`,
`Update`, `Delete`, `Close`):

- `FileStore` — plain JSON file, used when no barrier protects the resolved
  store path (or an explicit `--store` path was given).
- `BackendStore` — wraps any `xkms.StorageBackend` (the barrier, when one is
  unsealed) with the `oath/` key prefix; every credential is opaque
  ciphertext on disk once the barrier wraps it.
- `CompositeStore` — routes `Add`/`Get`/`Update`/`Delete` to one of several
  registered per-backend `Store`s by `Credential.BackendID`, and merges
  `List` across all of them. `Add` refuses an unregistered backend with a
  `*BackendError` naming it (`ErrStoreNotFound`) and refuses an ID or name
  another backend already holds (`checkDuplicate`,
  `pkg/oath/composite_store.go:225`), because `Get`/`Delete` look a
  credential up across every backend.

### Multi-backend partitions (`xkey/pkg/oath/backends.go`)

Both surfaces open OATH as a `CompositeStore` with one partition per
OATH-capable backend. `backendregistry.ConfiguredFor`
(`pkg/backendregistry/capabilities.go:32`) lists them from the unified
config: `software`, then every `backends.local` entry whose category offers
`oath` (`software`, `pkcs11`; `DefaultCapabilities`). The default backend,
used by an `Add` that names none, is `backends.defaults.oath`, else
`software`.

`OpenStores` (`pkg/oath/backends.go:53`) is the one constructor; the CLI,
the GUI, `xkey extension serve` and `xkey backup` all call it:

- with the unsealed barrier — one `BackendStore` per backend: `software`
  under `oath/`, any other backend under `oath@<id>/`;
- without one — one `FileStore` per backend: `software` at the store path,
  any other backend beside it as `<stem>@<id><ext>`
  (`FilePartitionPath`, `pkg/oath/backends.go:75`). `oath.json` gets
  `oath@token1.json`; `--store /tmp/a.json` gets `/tmp/a@token1.json`, so two
  stores in one directory never share a partition. A store path whose file
  name contains `@` is refused with `ErrInvalidStorePath`, so a store file
  can never be another store's partition.

The `software` partition is the historical location, so credentials stored
before multi-backend routing (no `BackendID`) are still listed, generated
and removed. A backend ID that cannot name a key prefix or file is refused
with `ErrInvalidBackendID`; a partition that fails to open is
`ErrBackendStoreOpen`, both wrapped in a `*BackendError` naming the backend
(`newPartitionedStore`, `pkg/oath/backends.go:98`). Partitions share the
one store (barrier or files): a backend partition records where a
credential belongs; the secret is protected by the barrier, not by the
named backend's hardware. `CompositeStore.Add`
(`pkg/oath/composite_store.go:70`) holds the write lock across the
duplicate check and the insertion, so two concurrent adds of one name to
different backends cannot both succeed: one gets `ErrCredentialExists`.

`openOATHStore` (`cmd/xkey/cmd/oath.go:263`) is the CLI's own decision: an
explicit `--store` always wins and selects file partitions at that path;
otherwise it defers to `resolveSecretStoreBackend` (shared with
`xkey backup` and `xkey oath sync`, see
[seal/architecture.md](../seal/architecture.md)) to decide barrier vs. plain
file; both paths go through `openOATHStores` (`cmd/xkey/cmd/oath.go:294`),
which supplies the configured backend list. `xkey oath add --backend <id>`
(`cmd/xkey/cmd/oath.go:779`) sets `Credential.BackendID`.
`xkey/pkg/gui/services/oath_service.go`'s `OATHService` takes an
already-constructed `oath.Store` (via `NewOATHService`/`SetStore`); the GUI
builds the same composite at startup (`pkg/gui/app.go:817`), and
`xkey extension serve` does too (`initPlainStores`/`initBarrierStores`,
`cmd/xkey/cmd/extension_serve.go:746`), so the browser extension sees every
partition.

`xkey backup` reads every partition (`resolveOATHBackupStore`,
`cmd/xkey/cmd/backup.go:897`; the default source counts as missing only
when no partition file exists, `oathPartitionsMissing`, `backup.go:941`).
The archive records each credential's `backend_id`, and restore adds it back
to that backend; a backend not configured on the restoring host fails that
credential with `ErrStoreNotFound` in the restore errors.

### QR scanning (`xkey/pkg/qrscan`)

`Scanner.ScanScreen`/`ScanAllScreens` capture the desktop display(s) and
decode QR codes with `gozxing`; `ScanScreenForOTP` is the convenience entry
point `xkey oath scan` uses. Scanning is local (X11/framebuffer screen
capture), not a camera or file-based QR reader.

## Data flow: `xkey oath scan`

1. `Scanner.ScanScreen`/`ScanAllScreens` capture the requested display(s).
2. Each detected QR payload is handed to `oath.ParseURI`, which validates and
   builds a `Credential`.
3. The user confirms (or `--yes` skips confirmation).
4. `openOATHStore` resolves the destination store (barrier-backed or plain
   file) and `Store.Add` persists the credential.

## At-rest encryption

Summarized from [seal/architecture.md](../seal/architecture.md), which is
normative: `xkey oath`'s default store location (no explicit `--store`) goes
through the unsealed barrier when one is initialized (`oath.OpenStores`
over the barrier backend), falls back to the plain `FileStore` with a logged
warning when no barrier exists, and refuses outright (never falling back to
plaintext) when a barrier exists but cannot be opened. An explicit `--store`
path always selects the plain file, bypassing the barrier decision.

## See also

- [engineering.md](engineering.md) — exported surface, invariants, errors, tests
- [cli.md](cli.md) — every `xkey oath` verb and flag
- [api.md](api.md) — GUI/SDK surface (no network transport)
- [user.md](user.md) — task-oriented usage
- [seal/architecture.md](../seal/architecture.md) — the barrier decision `xkey oath` defers to
