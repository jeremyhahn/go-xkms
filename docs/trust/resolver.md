# Trust Resolver

`pkg/trust/resolver` is the generic, scope-keyed trust resolver for the xkms
stack. It maps an arbitrary scope name and a peer endpoint onto a verified
`*tls.Config`, `*x509.CertPool`, or raw CA bundle PEM by executing an ordered
list of trust-bootstrap strategies and returning the first success.

This package owns: scope scoping, the ordered fallback chain, pool caching, and
the local strategies (embedded OS trust, ca-file, provider-ca). Strategy
_dispatch_ (DANE, Noise_NK, SPKI pin, TOFU) is delegated entirely to
`pkg/trust/bootstrap`, so there is exactly one implementation of each
wire-protocol fetch in the stack.

The SDK re-export lives at `sdk/go/trust/resolver` (per-package re-export
style) and as `TrustResolver*` prefixed names in the flat `sdk/go` package
(`sdk/go/trust.go`).

## Scope model

Scopes are arbitrary string keys configured under `trust.scopes` in the
xkmsd config file (or wired directly in code). Platform layers that want
named constants (e.g. `default`, `bmc`, `internal`) define those constants
in their own layer and pass them as scope strings. The resolver imposes no
fixed scope names.

## Strategies

| Strategy | Description |
|----------|-------------|
| `dane` | DNSSEC-validated TLSA records (RFC 7671) via `pkg/trust/bootstrap.ModeDANE` |
| `noise` | Noise_NK channel pinned by the server's static Curve25519 key via `ModeNoise` |
| `spki` | SHA-256 SPKI pin of the server leaf certificate via `ModeSPKI` |
| `tofu` | Trust-on-first-use; first connection is unauthenticated, pin captured and reused via `ModeTOFU` |
| `embedded` | OS system trust store — no network fetch; returns `(nil, nil)` PEM |
| `ca-file` | PEM file on local disk |
| `provider-ca` | CA bundle from an injected `CABundleProvider` interface |

Strategies are tried in the order listed in `ScopeConfig.Strategies`. The first
success is returned; all failures are recorded as `Attempt` entries in
`ErrNoStrategySucceeded`.

## `trust:` config section (xkmsd)

Add a `trust:` section to any xkmsd config YAML:

```yaml
trust:
  scopes:
    default:
      strategies: [dane, noise, spki, embedded]
      server-url: "https://kms.example.com:8443"
      hostname: "kms.example.com"
      per-method-timeout: 10s
      install-to-system-trust: false
      dane:
        dns-server: "8.8.8.8:53"
        dns-over-tls: false
      noise:
        server-addr: "kms.example.com:8445"
        server-static-key: "<64-hex-chars>"          # Noise_NK; not runnable under FIPS
        server-p256-static-key: "<130-hex-chars>"    # approved suite; required under FIPS
      spki:
        pin: "<64-hex-chars>"
        # -or- pin-file: /etc/xkms/bootstrap-spki-pin
    bmc:
      strategies: [spki, ca-file]
      ca-file: "/etc/xkms/bmc-ca.pem"
      spki:
        pin: "<64-hex-chars>"
    internal:
      strategies: [provider-ca]
```

All scope fields are optional. An unconfigured scope fails resolution with
`ErrScopeNotConfigured`. A scope whose strategy list is empty fails
`Validate()` with `ErrInvalidConfig`.

### `pin-file` resolution

When `spki.pin-file` is set and `spki.pin` is empty, `Validate()` reads the
file and resolves the pin in-place. The autoinstall flow writes
`/etc/xkms/bootstrap-spki-pin` during first boot; operators can point
`pin-file` at that path instead of duplicating the value.

### `tofu` strategy

The `tofu` strategy requires a `TOFUPinStore` injected at construction time via
`WithTOFUPinStore`. Because the pin store carries runtime state it is never
serialised into the config file; `TOFUScopeConfig` is an empty struct
placeholder. Constructing a resolver with `tofu` in any scope's strategy list
without calling `WithTOFUPinStore` returns `ErrTOFUPinStoreRequired`.

**Security caveat**: the first connection to a new server under TOFU is
unauthenticated. Use DANE, Noise, or SPKI when a pre-shared trust anchor is
available.

## Constructor

```go
import "github.com/jeremyhahn/go-xkms/pkg/trust/resolver"

r, err := resolver.New(cfg,
    resolver.WithLogger(slog.Default()),
    resolver.WithPinStore(myPinStore),         // optional, for spki
    resolver.WithCABundleProvider(myProvider), // optional, for provider-ca
    resolver.WithTOFUPinStore(myTOFUStore),    // required when tofu listed
    resolver.WithTOFUConfirmFunc(myConfirm),   // optional
)
```

## Public API

```go
// Resolver interface
TLSConfig(ctx context.Context, scope string, endpoint string) (*tls.Config, error)
CAPool(ctx context.Context, scope string, endpoint string) (*x509.CertPool, error)
CABundlePEM(ctx context.Context, scope string) ([]byte, error)

// Interfaces
type PinStore interface {
    SPKIPin(ctx context.Context, endpoint string) (string, error)
}
type CABundleProvider interface {
    CABundle(ctx context.Context) ([]byte, error)
}

// Install
InstallToSystemTrust(bundlePEM []byte, certPath string) error
```

### Caching

`CAPool` caches successful pools in a `sync.Map` keyed by `(scope, endpoint)`.
The first call that builds a pool for a given pair persists it; subsequent calls
return the cached pointer. `CABundlePEM` and `TLSConfig` are not cached.

### Attempt recording

When every strategy in a scope fails, `ErrNoStrategySucceeded` is returned.
It carries an `Attempts` slice in chain order. Each `Attempt` holds the
`Strategy` name and the `error` produced. `Unwrap() []error` enables
`errors.Is`/`errors.As` traversal over all failure causes.

## xkmsctl config-file binding

`xkmsctl bootstrap auto` reads the `trust:` section from an xkmsd config file
when `--config` (local flag) or the root `--config` flag is provided. Config
file values are used as defaults; CLI flags always override them.

```sh
# Derive server-url, dane-hostname, noise-key from the config file's
# trust.scopes.default section; override spki-pin on the command line.
xkmsctl bootstrap auto \
  --config /etc/xkms/xkms.yaml \
  --spki-pin <pin>
```

## SDK re-exports

### `sdk/go/trust/resolver` (per-package path)

```go
import resolver "github.com/jeremyhahn/go-xkms/sdk/go/trust/resolver"

r, err := resolver.New(cfg, resolver.WithLogger(slog.Default()))
```

All types, constants, options, and errors from `pkg/trust/resolver` are
re-exported with identical names.

### `sdk/go` (flat namespace, `TrustResolver*` prefix)

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

r, err := xkms.TrustResolverNew(cfg, xkms.TrustResolverWithLogger(slog.Default()))
pool, err := r.CAPool(ctx, "default", "kms.example.com:8443")
```

All public identifiers are re-exported with a `TrustResolver` prefix to avoid
collision with the existing `TrustBootstrap*` surface in the same flat package.

## Typed errors

| Error | Meaning |
|-------|---------|
| `ErrNilConfig{}` | Nil `*Config` passed to `New` |
| `*ErrScopeNotConfigured` | Scope not present in `Config.Scopes` |
| `*ErrInvalidConfig` | Configuration field missing or malformed |
| `*ErrFetchFailed` | A specific strategy's fetch call failed |
| `ErrCABundleEmpty{}` | Fetched or provided bundle had zero bytes |
| `ErrCABundleParse{}` | Bundle had bytes but no parseable PEM |
| `*ErrWriteFailed` | `InstallToSystemTrust` write failed |
| `ErrProviderCAUnavailable{}` | `provider-ca` without an injected provider |
| `*ErrPinNotFound` | No SPKI pin in PinStore or static config |
| `*ErrCAFileRead` | ca-file strategy could not read the file |
| `*ErrEndpointInvalid` | endpoint / server-url could not be parsed |
| `ErrTOFUPinStoreRequired{}` | `tofu` strategy without `WithTOFUPinStore` |
| `*ErrNoStrategySucceeded` | All strategies in the chain failed |

## See also

- [Trust bootstrap](bootstrap.md) — the `pkg/trust/bootstrap` dispatch library
  that each strategy delegates to for wire-protocol fetches.
- [Init ceremony](../init-ceremony/architecture.md) — `xkmsd init` ceremony produces the CA
  bundle that the resolver fetches.
- `pkg/trust/resolver` source — `config.go`, `resolver.go`, `errors.go`,
  `install.go`.
