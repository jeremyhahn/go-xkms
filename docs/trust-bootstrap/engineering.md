# Trust Bootstrap — Engineering Contract

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-08-19

## Exported surface — `pkg/trust/bootstrap`

```go
type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeDANE   Mode = "dane"
	ModeNoise  Mode = "noise"
	ModeSPKI   Mode = "spki"
	ModeDirect Mode = "direct"
	ModeTOFU   Mode = "tofu"
)

const DefaultNoisePort = "8445"

func Fetch(ctx context.Context, cfg Config) (*CABundle, error)
```

`Mode` values **match the canonical CLI verb and the SDK accessor name** by
design (`bootstrap.go:57-59`). Renaming one without the others is a defect.

### `Config`

| Field | Type | Meaning |
|---|---|---|
| `Mode` | `Mode` | **Required.** Dispatch strategy. |
| `ServerURL` | `string` | Canonical xkms server URL, e.g. `https://kms.example.com:8443`. Needed by every mode except pure Noise — and Noise reads it to derive an address when `NoiseConfig.ServerAddr` is empty. |
| `BundlePath` | `string` | Overrides the CA-bundle path. Empty = the canonical unauthenticated route `/v1/ca/bootstrap`. |
| `PerMethodTimeout` | `time.Duration` | Caps each mode attempt, and each `ModeAuto` fallback. Zero = go-truststrap's default. |
| `Logger` | `*slog.Logger` | Nil disables per-call logging. Set it — bootstrap audit trails are otherwise incomplete. |
| `DANE` | `*DANEConfig` | Required for `ModeDANE`; optional knob under `ModeAuto`. |
| `Noise` | `*NoiseConfig` | Required for `ModeNoise`; optional under `ModeAuto`. |
| `SPKI` | `*SPKIConfig` | Required for `ModeSPKI`; optional under `ModeAuto`. |
| `Direct` | `*DirectConfig` | Required for `ModeDirect`; optional under `ModeAuto`. |
| `TOFU` | `*TOFUConfig` | Required for `ModeTOFU`. Under `ModeAuto`, used only when non-nil **and** `TOFUMethodOrder` contains `ModeTOFU`. |
| `TOFUMethodOrder` | `[]truststrap.Method` | Overrides the auto order to include TOFU. Nil = truststrap's `DefaultMethodOrder`, which does not include TOFU. Consulted only when `Mode == ModeAuto && TOFU != nil`. |

### `CABundle`

```go
type CABundle struct {
	PEM          []byte     // PEM-encoded chain
	Certificates [][]byte   // individual DER certificates
	ContentType  string     // what truststrap reported, e.g. "application/pem-certificate-chain"
}
```

### Errors

```go
var ErrInvalidMode       = errors.New("trust bootstrap: invalid mode")
var ErrModeNotConfigured = errors.New("trust bootstrap: mode not configured")
var ErrServerURLRequired = errors.New("trust bootstrap: server URL required")
var ErrFetch             = errors.New("trust bootstrap: fetch failed")

type FetchError struct {
	Mode  Mode
	Cause error
}
func (e *FetchError) Error() string
func (e *FetchError) Is(target error) bool   // matches ErrFetch
func (e *FetchError) Unwrap() error          // the truststrap-typed cause
```

Use `errors.Is(err, ErrFetch)` for "any fetch-level failure" and
`errors.As`/`errors.Unwrap` to recover the truststrap cause for finer dispatch.
`FetchError.Mode` tells you which anchor was being attempted, which is the field
that makes an `ModeAuto` failure diagnosable.

## Invariants

- **`Fetch` is stateless.** Each call constructs a fresh bootstrapper, runs,
  closes, returns. **There is no caching between calls.** A caller wanting a
  cached bundle owns the cache and its invalidation.
- **A nil sub-config means "not configured".** `ModeAuto` skips it silently; a
  single-mode `Fetch` returns `ErrModeNotConfigured`. Do not "helpfully" make
  single-mode fall back.
- **TOFU is never in the auto chain by accident.** Two explicit acts are needed
  — set `Config.TOFU` and list `ModeTOFU` in `TOFUMethodOrder`. The code comment
  states the reason: a TOFU fallback in a pinned environment is a security
  hazard. Do not add it to the default order.
- **The bundle is returned, never installed.** This package does not write to a
  trust store.
- **`DeriveNoiseAddr` appends `DefaultNoisePort` ("8445") when no explicit
  address is given.** See the port conflict below.
- **Concurrency.** `Fetch` is safe to call concurrently; it shares no state.

**Fail closed:** an unverifiable anchor, an unresolvable TLSA, a Noise key
mismatch, an SPKI pin mismatch, or a changed TOFU pin all return an error. None
of them degrade to an unverified fetch.

## Configuration

Server side — the ports the bootstrap channel uses:

```yaml
server:
  noise_port: 8447        # configs/xkmsd-local.yaml
```

**Known conflict, as shipped:** `DefaultNoisePort` is `"8445"`
(`pkg/trust/bootstrap/bootstrap.go:98`), which is the same value the shipped
configs use for `mcp_port`. `configs/xkmsd-local.yaml` sets `noise_port: 8447`
precisely to avoid the collision, so the library default and the shipped
configuration disagree. Set the port explicitly on both sides. Full table:
[`../key-management/api.md`](../key-management/api.md) §Port conflicts.

**Second known disagreement:** `Config.BundlePath`'s doc comment says empty
means `/v1/ca/bootstrap` (the canonical unauthenticated route), while the CLI's
`--bundle-path` help text (`cmd/xkmsctl/bootstrap.go:243`) says the default is
`/api/v1/ca/bundle` — the *authenticated* route. Both routes exist and serve a
bundle, but only the first works before the client has credentials. Documented
as shipped; reconciling the two is an owner decision.

TOFU pin persistence is `pkg/trust/bootstrap/pinstore_qrdb.go`, backed by
`go-qrdb/sdk/go`. The pin store is a security boundary — treat write access to
it as equivalent to the ability to re-anchor trust.

## Persistence

Only TOFU persists anything: the captured SPKI pin, through the qrdb pin store.
Every other mode is stateless. There is no bundle cache and no pin cache for the
non-TOFU modes.

## Test strategy

- **Unit** — `bootstrap_test.go`, `bootstrap_fetch_test.go`,
  `bootstrap_tofu_test.go`, `bootstrap_auto_tofu_gaps_test.go` (the auto-chain
  TOFU-exclusion behaviour has its own suite, because that is the rule most
  likely to be "simplified" by a later change), `tlsconfig_test.go`,
  `pinstore_qrdb_test.go`, `pinstore_errors_gaps_test.go`.
- **CLI** — `cmd/xkmsctl/bootstrap_{auto,dane,noise,spki,run}_test.go`.
- **Integration** — `test/integration/bootstrap`.
- **Fault injection** — the pin-store tests cover a changed pin, which is the
  case that must fail rather than re-pin.

Note that the DANE path needs a resolver; suites that exercise it require DNS
infrastructure and are gated accordingly.

## Observability

Set `Config.Logger`. Under `ModeAuto` each attempted mode logs its outcome,
which is the only way to tell "DANE was skipped because unconfigured" from
"DANE was tried and failed" — and those have completely different remediations.
`FetchError.Mode` carries the same information programmatically.
