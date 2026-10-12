# Init Ceremony — Engineering

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-11

## Exported surface (`pkg/init`)

- `CeremonyCA`, `CAAdapter`, `NewCAAdapter(xkmsCA, trustDomain)` —
  `ca_adapter.go`; implements go-qrdb's `CertProvider` / `CertSigner` seams.
- `SPKIPin(cert)` — `ceremony.go`; the SPKI SHA-256 pin written to
  `spki-pin.txt`.
- `AdminEnrollmentConfig`, `NewAdminFactorRegistry`, `PreflightAdminFactors`,
  `EnrollAdminFactors` — `admin_enrollment.go`.
- `AdminEnrollmentContext`, `NewAdminEnrollmentParams` — `admin_factors.go`.
- `ThresholdInitializer`, `ThresholdOptions`, `ThresholdStatus`,
  `ThresholdRegistry`, `NoopThresholdInitializer` — aliases of the go-qrdb
  types.

## Invariants

- A planned factor that cannot succeed (no security key attached) fails in
  preflight, before any state changes, with go-qrdb's
  `*AdminFactorUnavailableError`. This covers a planned `fido2` factor with
  no `FIDO2Handler` (reason `fido2.NoHandlerReason`): the init ceremony has
  no browser, so the registry always wires the local CTAP2 ceremony, never
  the browser-path factor that reports itself available. A planned `piv`
  factor with no generator and no `AllowSoftwarePIV` fails the same way
  (`piv.NoGeneratorReason`).
- First boot is idempotent: `xkmsd run`'s own first boot is a no-op afterwards.
- The node is always closed before `xkmsd init` returns.
- Holder certificates carry the registered subject only, no SAN, never the
  CSR's names.

## Errors

Typed, in `pkg/init/errors.go`: `ErrNoLocalFIDO2Ceremony`,
`ErrPasskeyRPIDRequired`, `ErrAdminCertRequired`, `RandomSourceError`,
`AdminKeyGenerationError`, `ErrNilSignOptions`, plus the threshold sentinels
re-exported from go-qrdb. The driver wraps its failures in
`cmd/xkmsd` `WrappedError` with `ErrFirstBootFailed`,
`ErrAdminCredentialPersistFailed`, `ErrAdminUserResolveFailed`,
`ErrUserAuthFactorsUnavailable`.

## Configuration

`xkmsd init` reads the daemon config (`--config`) for storage, seal and
relying-party settings, and `XKMS_SO_PIN`, `XKMS_BARRIER_STRATEGY`,
`XKMS_HOSTNAME`, `XKMS_SANS`, `XKMS_PASSKEY_PIN`. See [cli.md](cli.md).

## Tests

`go test ./pkg/init/ ./cmd/xkmsd/` covers the CA adapter, SPKI pin, factor
enrollment, the bootstrap driver and flag validation. The persistence across a
restart is covered by `test/integration/initceremony`.
