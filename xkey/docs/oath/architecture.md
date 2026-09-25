# OATH TOTP/HOTP — Architecture

> **Status: NORMATIVE** · Feature: `oath` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

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
read back only through `SecretString` at a serialization boundary
(go-xkms#210). `MarshalJSON`/`UnmarshalJSON` round-trip the secret through the
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
  `List` across all of them. **Not currently constructed by the CLI or the
  GUI** (`grep` finds no `NewCompositeStore` call site outside
  `pkg/oath` itself) — the multi-backend routing it implements is not yet
  reachable from either surface. See engineering.md's Tests section.

`openOATHStore` (`cmd/xkey/cmd/oath.go`) is the CLI's own decision: an
explicit `--store` always wins and selects `FileStore` at that path;
otherwise it defers entirely to `resolveSecretStoreBackend` (shared with
`xkey backup` and `xkey oath sync`, see
[seal/architecture.md](../seal/architecture.md)) to decide barrier vs. plain
file. `xkey/pkg/gui/services/oath_service.go`'s `OATHService` takes an
already-constructed `oath.Store` (via `NewOATHService`/`SetStore`) — the GUI
wires the same barrier-or-file decision at startup, not inside the service.

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
through the unsealed barrier when one is initialized (`oath.NewBackendStore`
over the barrier backend), falls back to the plain `FileStore` with a logged
warning when no barrier exists, and refuses outright (never falling back to
plaintext) when a barrier exists but cannot be opened. An explicit `--store`
path always selects the plain file, bypassing the barrier decision.

## Rejected alternatives

- **Wiring `CompositeStore` into the CLI now.** It is fully implemented and
  tested (`composite_store_test.go`) but nothing in `cmd/xkey/cmd` or
  `pkg/gui` constructs one yet; multi-backend OATH credential routing (e.g.
  "this credential's secret is sealed by the phone backend, that one by the
  barrier") is not a requirement any current command has. Left in the
  package rather than deleted — see engineering.md — because it is exactly
  the shape a genuine multi-backend need would reuse.

## See also

- [engineering.md](engineering.md) — exported surface, invariants, errors, tests
- [cli.md](cli.md) — every `xkey oath` verb and flag
- [api.md](api.md) — GUI/SDK surface (no network transport)
- [user.md](user.md) — task-oriented usage
- [seal/architecture.md](../seal/architecture.md) — the barrier decision `xkey oath` defers to
