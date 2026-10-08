# Canonical Trust-Bootstrap Library

`pkg/trust/bootstrap` is the single, canonical dispatch layer in the xkms
stack for fetching a server's CA bundle over an untrusted network. It wraps
[`go-truststrap`](https://github.com/jeremyhahn/go-truststrap) with a typed
`Mode` enum and a single `Fetch(ctx, cfg)` entry point. Every consumer that
performs trust bootstrap routes through this package — there is exactly one
implementation of "select mode, build truststrap config, FetchCABundle,
return PEM" in the whole stack, and it lives here.

This document describes the canonical surface, the supported modes, the four
consumers that depend on it, and the Phase 7 unification that eliminated
three near-duplicate dispatchers in favor of this library.

## Why a single dispatcher exists

Before Phase 7 each consumer (`xkmsctl`, `xkey/pkg/gui/services`, and
`go-trusted-platform/pkg/bootstrap/client.go`) maintained its own
"if mode == dane { … } else if mode == noise { … }" branch on top of
`go-truststrap`. Each branch built a slightly different `truststrap.*Config`
shape, applied a slightly different timeout policy, derived the Noise port
slightly differently, and surfaced errors with a slightly different
wrapping. Three near-duplicate dispatchers meant three places to fix a
mode-selection bug and three places to add a new mode.

The canonical library replaces all three with:

```go
import "github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"

cfg := bootstrap.Config{
    Mode:             bootstrap.ModeAuto,
    ServerURL:        "https://kms.example.com:8443",
    PerMethodTimeout: 10 * time.Second,
    Logger:           slog.Default(),
    DANE:             &bootstrap.DANEConfig{Hostname: "kms.example.com"},
    Noise:            &bootstrap.NoiseConfig{ServerStaticKey: hexKey},
    SPKI:             &bootstrap.SPKIConfig{Pin: hexPin},
}
bundle, err := bootstrap.Fetch(ctx, cfg)
```

The package is stateless: each `Fetch` call constructs a fresh truststrap
bootstrapper, runs the fetch, closes it, and returns. No caching, no
package-level mutable state.

Source: `pkg/trust/bootstrap/bootstrap.go:251`.

## Surface

### Mode enum

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
```

Mode values match both the canonical CLI verb (`quicbaas bootstrap <mode>`,
`xkmsctl bootstrap <mode>`) and the SDK accessor name
(`Security().Trust().Bootstrap().<mode>`).

| Mode | Verifies server via | When to use |
|------|---------------------|-------------|
| `ModeAuto` | Whichever sub-config is populated, in DANE → Noise → SPKI → Direct order | Default. Configure every method you have, take the first success. |
| `ModeDANE` | DNSSEC-validated TLSA records | Production with a DNSSEC-signed zone. |
| `ModeNoise` | Server's pre-shared Curve25519 static key over a Noise_NK channel | Operator distributes the Noise pubkey out-of-band. |
| `ModeSPKI` | SHA-256 pin of the server certificate's SubjectPublicKeyInfo | Trust-on-first-use after the server prints its pin. |
| `ModeDirect` | System trust store | Last-resort fallback for servers that already have a publicly-trusted certificate. |
| `ModeTOFU` | Captured SPKI pin (trust-on-first-use) | No pre-shared anchor available; first contact is unauthenticated. Requires `TOFUConfig.PinStore`. |

Source: `pkg/trust/bootstrap/bootstrap.go:62`.

### Config

`Config` is the input to a single `Fetch` invocation. Populate `Mode`, plus
whichever sub-configs the mode (or, for `ModeAuto`, the ordering) needs.
Sub-configs left nil mean "this mode is not configured" — `ModeAuto` skips
them silently; single-mode fetches return `ErrModeNotConfigured`.

```go
type Config struct {
    Mode             Mode
    ServerURL        string
    BundlePath       string         // overrides default "/api/v1/ca/bundle"
    PerMethodTimeout time.Duration
    Logger           *slog.Logger
    DANE             *DANEConfig
    Noise            *NoiseConfig
    SPKI             *SPKIConfig
    Direct           *DirectConfig
    TOFU             *TOFUConfig
    TOFUMethodOrder  []truststrap.Method  // only for ModeAuto; see TOFUConfig
}
```

| Sub-config | Required fields |
|------------|-----------------|
| `DANEConfig` | `Hostname`. Optional: `DNSServer`, `DNSOverTLS`, `DNSTLSServerName`. |
| `NoiseConfig` | `ServerStaticKey` (hex-encoded 32-byte Curve25519 pubkey). Optional: `ServerAddr` — derived from `Config.ServerURL` via `DeriveNoiseAddr` when empty. |
| `SPKIConfig` | `Pin` (64-character hex-encoded SHA-256 SPKI pin). |
| `DirectConfig` | No fields. Empty struct flags "direct mode is enabled" so `ModeAuto` can include it. |
| `TOFUConfig` | `PinStore` (required). Optional: `ConfirmFunc`. Explicit-config-only — set `TOFUMethodOrder` to include `ModeTOFU` in `ModeAuto`; absent by default. |

Source: `pkg/trust/bootstrap/bootstrap.go:96`.

### CABundle (return type)

```go
type CABundle struct {
    PEM          []byte    // PEM-encoded certificate chain
    Certificates [][]byte  // individual DER-encoded certificates
    ContentType  string    // server-reported, e.g. "application/pem-certificate-chain"
}
```

Source: `pkg/trust/bootstrap/bootstrap.go:182`.

### StoragePinStore (TOFU pin persistence)

`StoragePinStore` implements the `truststrap.PinStore` interface over any
xkms `storage.Backend`. It persists TOFU pins at the key prefix
`trust/tofu/pins/<host>:<port>` using JSON encoding. IPv6 hosts are
unambiguous because `net.JoinHostPort` brackets them.

```go
// Backed by any storage.Backend — memory, file, PebbleDB, or qrdb cluster.
backend := storage.NewMemory() // or OpenEngine(cfg) for durable backends
pinStore, err := bootstrap.NewStoragePinStore(backend)

bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
    Mode:      bootstrap.ModeTOFU,
    ServerURL: "https://kms.example.com:8443",
    TOFU:      &bootstrap.TOFUConfig{PinStore: pinStore},
})
```

When the backend is a Raft-replicated qrdb cluster, every `Put` replicates
through the Raft log, providing cluster-wide pin consistency.

**Security caveat**: the first connection to a new server is unauthenticated.
No pre-existing trust anchor validates the server certificate. All subsequent
connections verify the captured SPKI pin with the same strictness as
`ModeSPKI`. Use DANE, Noise, or SPKI when a pre-shared anchor is available.

Source: `pkg/trust/bootstrap/pinstore_qrdb.go`.

### DeriveNoiseAddr

Helper that extracts the host portion of `serverURL` and appends the default
Noise bootstrap port (`DefaultNoisePort = "8445"`). Accepts either a full URL
(`"https://kms.example.com:8443"`) or a bare host. Returns an empty string
on empty input.

```go
addr := bootstrap.DeriveNoiseAddr("https://kms.example.com:8443")
// addr == "kms.example.com:8445"
```

Source: `pkg/trust/bootstrap/bootstrap.go:272`.

### Trust-verified tls.Config constructors

For callers that need an ongoing TLS connection verified by the same
bootstrap trust strategies (rather than a one-shot CA-bundle fetch), the
package exposes two `*tls.Config` constructors built on the documented
custom-verifier pattern — WebPKI verification is disabled and a
`VerifyConnection` / `VerifyPeerCertificate` callback is the sole verifier:

```go
// DANE: TLSA records resolved eagerly for "_<port>._tcp.<hostname>.";
// the presented chain is verified per RFC 7671. cfg supplies resolver
// knobs (DNSServer, DNSOverTLS, DNSTLSServerName); nil cfg or empty
// DNSServer uses the system resolver with DNSSEC AD enforcement.
// cfg.Hostname takes precedence over the hostname parameter.
tlsCfg, err := bootstrap.NewDANETLSConfig(ctx, cfg.DANE, "kms.example.com", 8443)

// SPKI: presented chain must contain a certificate whose SHA-256
// SubjectPublicKeyInfo digest matches the hex-encoded pin.
tlsCfg, err := bootstrap.NewSPKIPinTLSConfig(cfg.SPKI.Pin)
```

`NewDANETLSConfig` resolves TLSA records at construction time so callers
can fall back to another strategy before dialing; build a fresh config
per connection attempt to honor DNS TTLs. It returns
`ErrHostnameRequired` when neither `cfg.Hostname` nor the hostname
parameter is set.

Both constructors are re-exported through `sdk/go/bootstrap` and the
QuicBaaS `sdk/go/xkms/trust/bootstrap` package.

Source: `pkg/trust/bootstrap/tlsconfig.go`.

### Errors

```go
var (
    ErrInvalidMode       = errors.New("trust bootstrap: invalid mode")
    ErrModeNotConfigured = errors.New("trust bootstrap: mode not configured")
    ErrServerURLRequired = errors.New("trust bootstrap: server URL required")
    ErrFetch             = errors.New("trust bootstrap: fetch failed")
    ErrHostnameRequired  = errors.New("trust bootstrap: hostname required")
)

type FetchError struct {
    Mode  Mode
    Cause error
}
```

`FetchError` implements `Is(ErrFetch)` and `Unwrap()`. Use
`errors.Is(err, bootstrap.ErrFetch)` to detect any fetch-level failure; use
`errors.As(err, &fetchErr)` to recover the attempted mode and the underlying
truststrap-typed cause for finer dispatch.

Source: `pkg/trust/bootstrap/bootstrap.go:201`.

## Architecture

```
                +-----------------------------+
                |   bootstrap.Fetch(ctx, cfg) |
                +--------------+--------------+
                               |
              +---------+------+-------+----------+----------+----------+
              v         v              v          v          v          v
          fetchAuto fetchDANE     fetchNoise  fetchSPKI  fetchDirect fetchTOFU
              |         |              |          |          |          |
              v         v              v          v          v          v
        AutoBootstrapper        NoiseBootstrapper         DirectBootstrapper
                          DANEBootstrapper      SPKIBootstrapper  TOFUBootstrapper
                                  (go-truststrap)
                                  |
                                  v
                              CA bundle PEM
```

Every per-mode function is a thin adapter:

1. Validate the matching sub-config is present (`ErrModeNotConfigured`).
2. Validate `ServerURL` (`ErrServerURLRequired`) — Noise tolerates absence
   when `NoiseConfig.ServerAddr` is explicit.
3. Translate this package's typed config into the truststrap-typed config.
4. Construct the bootstrapper, defer its `Close`, call `FetchCABundle`.
5. Wrap any error in `FetchError{Mode, Cause}` so callers can recover the
   mode that failed.

`ModeAuto` populates every truststrap sub-config that has the minimum
required inputs (`ServerURL` + the mode-specific identifier) and hands the
whole bundle to `truststrap.AutoFetch`, which tries each in the canonical
DANE → Noise → SPKI → Direct order until one succeeds.

```mermaid
flowchart LR
    Caller -->|Config{Mode, ServerURL, sub-configs}| Fetch
    Fetch -->|ModeAuto| fetchAuto
    Fetch -->|ModeDANE| fetchDANE
    Fetch -->|ModeNoise| fetchNoise
    Fetch -->|ModeSPKI| fetchSPKI
    Fetch -->|ModeDirect| fetchDirect
    Fetch -->|ModeTOFU| fetchTOFU
    fetchAuto -->|truststrap.AutoFetch| truststrap
    fetchDANE -->|NewDANEBootstrapper| truststrap
    fetchNoise -->|NewNoiseBootstrapper| truststrap
    fetchSPKI -->|NewSPKIBootstrapper| truststrap
    fetchDirect -->|NewDirectBootstrapper| truststrap
    fetchTOFU -->|NewTOFUBootstrapper| truststrap
    truststrap -->|FetchCABundle| Server[xkms server :8443]
```

## Consumers

There are exactly four consumers of this library. Every other process that
needs a CA bundle goes through one of these four entry points; no other
package may dispatch trust modes directly against `go-truststrap`.

### 1. `xkmsctl bootstrap` (xkms CLI)

`cmd/xkmsctl/bootstrap.go` builds a `bootstrap.Config` from cobra flags and
calls `bootstrap.Fetch`. The CLI subcommands `auto`, `dane`, `noise`, `spki`
are all thin flag-parsing wrappers around the same library call.

```go
// cmd/xkmsctl/bootstrap.go:89
func runAutoBootstrap(params *autoBootstrapParams) error {
    cfg := buildAutoConfig(params)
    bundle, err := bootstrap.Fetch(context.Background(), *cfg)
    if err != nil {
        return fmt.Errorf("%w: %w", ErrAllBootstrapMethodsFailed, err)
    }
    return writeCABundle(bundle.PEM, params.bundleOutput)
}
```

Source: `cmd/xkmsctl/bootstrap.go:14`.

### 2. xkey GUI (`xkey/pkg/gui/services/trust_service.go`)

The xkey desktop application's trust service builds a `bootstrap.Config`
from the user's GUI inputs and dispatches via the canonical library.
Previously the xkey GUI maintained its own DANE/Noise/SPKI selector; that
selector is now a `Mode` value passed to `bootstrap.Fetch`.

```go
// xkey/pkg/gui/services/trust_service.go (excerpt)
// Dispatch goes through xkms/pkg/trust/bootstrap — the single
// canonical entry point for every consumer.
bundle, err := bootstrap.Fetch(ctx, cfg)
```

### 3. QuicBaaS SDK (`sdk/go/xkms/trust/bootstrap`)

The QuicBaaS Go SDK re-exports the canonical types via a pure-alias
package so downstream callers can import bootstrap through the SDK path:

```go
// quicbaas/sdk/go/xkms/trust/bootstrap/bootstrap.go
package bootstrap

import xkmsbootstrap "github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"

type (
    Config       = xkmsbootstrap.Config
    DANEConfig   = xkmsbootstrap.DANEConfig
    NoiseConfig  = xkmsbootstrap.NoiseConfig
    SPKIConfig   = xkmsbootstrap.SPKIConfig
    DirectConfig = xkmsbootstrap.DirectConfig
    CABundle     = xkmsbootstrap.CABundle
)
```

The SDK Trust accessor (`Security().Trust().Bootstrap()`) is wired to this
re-export so applications calling
`client.Security().Trust().Bootstrap().Fetch(ctx, cfg)` ultimately invoke
the same `Fetch` function as `xkmsctl`.

### 4. go-trusted-platform (via the SDK)

`go-trusted-platform/pkg/bootstrap/client.go` no longer imports
`go-xkms` directly. Its bootstrap client is a thin adapter over the QuicBaaS
SDK's `Security().Trust().Bootstrap()` accessor, which transitively reaches
the canonical library. This is the SDK Consumption Invariant documented in
`platform/CLAUDE.md`.

## Phase 7 unification

Before Phase 7 there were three independent dispatchers. After Phase 7 the
state is:

| Component | Before Phase 7 | After Phase 7 |
|-----------|---------------|---------------|
| `cmd/xkmsctl/bootstrap.go` | Inline branches over `truststrap.NewDANEBootstrapper` / `NewNoiseBootstrapper` / `NewSPKIBootstrapper` | Calls `bootstrap.Fetch` |
| `xkey/pkg/gui/services/trust_service.go` | Inline branches with its own timeout policy | Calls `bootstrap.Fetch` |
| `platform/pkg/bootstrap/client.go` | Inline branches over `truststrap` | Calls `Security().Trust().Bootstrap().Fetch` via the SDK |
| `pkg/trust/bootstrap/bootstrap.go` | did not exist | Canonical library |
| `sdk/go/xkms/trust/bootstrap` | did not exist | Pure-alias re-export |

The unification was completed across sub-phases 7a–7f. See the project
roadmap for the per-sub-phase commit history.

## Operational notes

- **Timeouts**: `PerMethodTimeout` applies to each individual mode attempt.
  In `ModeAuto` it caps each fallback independently, so the total wall clock
  for an auto fetch is bounded by `PerMethodTimeout × number-of-modes`.
- **Logging**: `Config.Logger` is passed straight through to `go-truststrap`.
  Pass a `slog.Logger` configured with the audit handler if bootstrap
  attempts need to land in the audit trail.
- **Network**: every mode that talks HTTPS uses
  `Config.BundlePath` to override the REST API path; leave empty for the
  go-truststrap default of `/api/v1/ca/bundle`.
- **Noise port**: when `NoiseConfig.ServerAddr` is empty, the library
  derives it from `Config.ServerURL` by stripping the scheme/path and
  appending `:8445`. Pass `NoiseConfig.ServerAddr` explicitly if the server
  uses a non-default Noise port.

## See also

- [Bootstrap (server-side)](../bootstrap/README.md) — how the xkms server
  exposes the bootstrap endpoints.
- [Init ceremony](../init-ceremony/architecture.md) — the `xkmsd init` ceremony that
  produces the CA bundle the trust library fetches.
- [QuicBaaS SDK — Trust accessor](https://github.com/jeremyhahn/go-quicbaas/tree/master/sdk/go/xkms/trust/bootstrap) — SDK re-export
  package.
- `go-truststrap` upstream library — implements the per-mode wire protocols
  this library dispatches over.
