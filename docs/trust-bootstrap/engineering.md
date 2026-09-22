# Trust Bootstrap — Engineering Contract

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-09-22

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

// Trust-verified client *tls.Config constructors (custom-verifier pattern).
func NewDANETLSConfig(ctx context.Context, cfg *DANEConfig, hostname string, port uint16) (*tls.Config, error)
func NewSPKIPinTLSConfig(pin string) (*tls.Config, error)
func NewTOFUTLSConfig(ctx context.Context, pinStore truststrap.PinStore, endpoint string,
	confirm func(ctx context.Context, pin *truststrap.Pin) error) (*tls.Config, error)
```

`NewTOFUTLSConfig` (#139) is the endpoint-level TOFU verifier, keyed by
`"host:port"`: the first connection captures the leaf's SHA-256 SPKI pin,
offers it to `confirm` (an error refuses the connection and persists
nothing), and persists it through `pinStore`; every later connection must
present that pin. The verifier runs in `VerifyConnection` with session
tickets disabled, so a resumed session cannot bypass it, and a pin store
that fails for any reason other than "no pin recorded" is an error, never a
fresh capture. The `Pin` record it writes is the one truststrap's
bundle-fetching TOFU bootstrapper writes (`Source: "tofu"`), so the TLS
path and the bundle path share one store.

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

### `NoiseConfig`

```go
type NoiseConfig struct {
	ServerAddr          string // "host:port"; derived from ServerURL via DeriveNoiseAddr when empty
	ServerStaticKey     string // hex 32-byte Curve25519 point: offers Noise_NK (SuiteNoiseNK)
	ServerP256StaticKey string // hex uncompressed P-256 point (130 chars): offers TSBOOT1_P256_AESGCM_SHA256
	Suite               byte   // 0 = by policy; SuiteNoiseNK or SuiteP256AESGCM pins one
}
```

At least one key is required. The client offers every suite it holds a key for
**and** this build can run; `Suite` pins one. The zero value selects by policy:
the approved suite whenever FIPS is enforced, otherwise Noise_NK when its key
is configured, else P-256. A FIPS client needs `ServerP256StaticKey` to use
this transport at all — the value `xkmsctl bootstrap noise show-p256-key`
prints for the server's key.

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

Client-side suite resolution for `ModeNoise` has its own, all reached through
`errors.Is` on the `FetchError`:

```go
var ErrSuiteKeyMissing = errors.New("trust bootstrap: no server static key configured for suite")
var ErrSuiteKeyInvalid = errors.New("trust bootstrap: server static key invalid for suite")
var ErrNoSuite         = errors.New("trust bootstrap: no bootstrap suite can be offered")
var ErrBundleMalformed = errors.New("trust bootstrap: malformed certificate in CA bundle response")

type SuiteError struct{ Suite byte; Cause error }   // Cause: ErrSuiteKeyMissing | ErrSuiteKeyInvalid | ErrSuiteUnavailable
type NoSuiteError struct{ Noise, P256 error }       // Is(ErrNoSuite); Unwrap() []error exposes both reasons
type BundleCertificateError struct{ Index int; Cause error }
```

`ErrSuiteUnavailable` (from `suite.go`) is the reason a `NoSuiteError` carries
when the build cannot run the only configured suite — a FIPS client holding a
Curve25519 key and nothing else. Handshake and transport failures keep wrapping
go-truststrap's `ErrFetchFailed`, exactly as the facade this composition
replaced did.

The TOFU TLS verifier has its own typed errors:

```go
var ErrTOFUPinStoreRequired = errors.New("trust bootstrap: tofu requires a pin store")

type TOFUEndpointError struct{ Endpoint, Reason string }              // not a "host:port"
type TOFUPinStoreError struct{ Op, Host string; Port int; Err error }  // Get/Put failed, NOT first use
type TOFUPinMismatchError struct{ Host string; Port int; Stored, Presented string; Err error }
```

`TOFUPinMismatchError` unwraps to `spkipin.ErrSPKIPinMismatch`; a refused
confirmation surfaces as truststrap's `TOFURejectedError` carrying the pin
that was offered; no certificates presented is `spkipin.ErrNoCertificates`.

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
- **`DeriveNoiseAddr` joins the server URL's host with `DefaultNoisePort`
  ("8445") when no explicit address is given.** It parses the URL, so the
  URL's own port, path and userinfo are dropped and an IPv6 literal stays
  bracketed (`https://[fd00::1]` and the bare `fd00::1` both derive
  `[fd00::1]:8445`); a URL with no
  host derives nothing, which `fetchNoise` reports as `ErrServerURLRequired`.
  See the port conflict below.
- **Client suite resolution fails closed.** An unavailable suite is skipped; a
  configured key that will not decode is a `SuiteError`, never a fall-through
  to the other suite; a pinned suite reads only its own key, so the other
  suite's key, stale or malformed, is never consulted; a pinned suite the
  build cannot run is a `SuiteError`
  checked before any key is read; nothing left is a `NoSuiteError`.
  Availability comes from `EnsureSuiteAvailable`, the same probe the listener
  uses — never from a build tag, because the released FIPS artifact is built
  with `GOFIPS140` and no tag.
- **`ModeAuto` runs the same arms the single modes run.** The Auto walk is
  this package's: it steps through go-truststrap's `DefaultMethodOrder` (or
  `TOFUMethodOrder` when TOFU is armed), runs each armed method's own
  single-mode fetcher under `PerMethodTimeout`, and reports failure as
  `FetchError{Mode: auto}` wrapping go-truststrap's `AggregateError`, one
  `AttemptError` per method tried. The Noise arm is therefore the
  suite-negotiating client above, so a P-256-only configuration bootstraps
  under `ModeAuto` exactly as under `ModeNoise`. It moved here because
  go-truststrap's own dispatcher builds its Noise arm from its facade config,
  which cannot carry the P-256 key (go-truststrap#51); under it a P-256-only
  client had no Noise arm and died with a misleading `ErrModeNotConfigured`.
  An arm is skipped, not failed, when its sub-config is present but empty
  (`Noise` with neither key, `SPKI` with no pin); nothing armed at all is
  `ErrModeNotConfigured`.
- **Concurrency.** `Fetch` is safe to call concurrently; it shares no state.
- **`NoiseServer.Stop`'s nil is authoritative.** The re-exported server
  (go-truststrap v0.4.0-alpha) returns nil from `Stop` only after every
  handshake worker has exited, `ErrShutdownIncomplete` when the *caller's*
  context expires first, and `ErrServerNotStarted` before `Start`. Concurrent
  callers each wait under their own deadline and may see different outcomes,
  but none receives a nil unbacked by a real drain, and once drained every
  later `Stop` returns nil stably. A `NoiseServer` is single-use: `Start`
  succeeds once and every later call returns `ErrServerAlreadyStarted`. The
  only condition under which material the workers read — the static keys'
  protected pages — may be destroyed is that nil; xkmsd's `noiseStopDrained`
  reads nothing else. It used to also require the caller's deadline to be
  unexpired, which was the only signal under the previous pin (`Stop` then
  returned nil on its own timeout path); against the current contract that
  conjunct retained a key that was safe to wipe whenever the drain completed
  as the deadline expired, and reported a shutdown incomplete that was not
  (go-xkms#83). `TestNoiseStop_NilIsAuthoritative` holds the contract against
  the pinned server, with a live worker and concurrent callers, under
  `-race -count=200`.
- **The lifecycle sentinels are re-exported.** `ErrNoiseShutdownIncomplete`,
  `ErrNoiseServerNotStarted` and `ErrNoiseServerAlreadyStarted` are the
  upstream values (`TestNoiseServerSentinels_AreTheUpstreamValues`), and
  `sdk/go/bootstrap` aliases them, so a consumer orchestrating `Stop` matches
  them with `errors.Is` without importing go-truststrap, which only this
  package composes. `TestSDKNoiseServerLifecycleSentinels` reaches all three
  through the SDK surface alone (go-xkms#498).

**Fail closed:** an unverifiable anchor, an unresolvable TLSA, a Noise key
mismatch, an SPKI pin mismatch, or a changed TOFU pin all return an error. None
of them degrade to an unverified fetch.

## Configuration

Server side — the ports the bootstrap channel uses:

```yaml
server:
  noise_port: 8447        # configs/xkmsd-local.yaml
```

Server side — custody of the static keys the listener serves each suite with
(`config.NoiseBootstrapConfig`, YAML key `bootstrap.noise`; go-xkms#35,
go-xkms#436) is now the barrier, not config:

```yaml
bootstrap:
  noise:
    enabled: true
```

`pkg/server/bootstrap_key_custody.go` resolves each suite's key on every boot,
in this order:

1. **Barrier configured** (`s.barrier != nil`, adopted from the embedded qrdb
   node or built by `initializeBarrier` — either way the same `*seal.Barrier`):
   load the hex-encoded key already sealed under `bootstrap-noise/x25519-static-key`
   / `bootstrap-noise/p256-static-key` in the barrier's own key-value store
   (`seal.Barrier.Get`/`Put`, the same mechanism `pkg/server/credentials`
   uses for operator-owned credentials). If nothing is sealed yet
   (`isBarrierKeyNotFound`: `storage.ErrNotFound` from an xkms-backed barrier,
   `seal.ErrSecretNotFound` from a node-adopted one — the same `*seal.Barrier`
   type surfaces either sentinel depending on the storage backend underneath
   it), fall back to the **deprecated** `static_key_hex` / `static_key_file` /
   `p256_static_key_hex` / `p256_static_key_file` fields, read exactly once;
   present, that key is sealed into the barrier and a `deprecated` warning is
   logged. Present nowhere, a fresh key is generated and sealed. Every path
   after the first leaves a sealed key in place, so the next boot always takes
   the first branch — the config fields are read at most once per key, ever.
2. **No barrier** (`barrier.enabled: false`): the deprecated config fields, if
   set, are still honored exactly as before. Otherwise a key persisted in
   plaintext hex at `<storage.path>/bootstrap-noise-x25519.key` (and
   `bootstrap-noise-p256.key`) is loaded, or generated and written there
   (0600, atomic temp-file-then-rename) with **one** warning that it is
   unprotected without a barrier. A missing `storage.path` (no data directory
   configured at all) has nowhere durable to persist to and falls back to the
   pre-#35 ephemeral-with-warning behavior rather than writing to an
   unpredictable location such as the process's working directory.

Either way, a key is never silently regenerated once one exists: an ephemeral
key that changes on every restart invalidates every client provisioned with
the old public key, which was the defect #35 closes.

The four `static_key_*` / `p256_static_key_*` fields are `Deprecated` in
`config.NoiseBootstrapConfig`'s doc comments. They still parse — the one-time
migration above depends on it — but nothing reads them again once the sealed
(or, without a barrier, the persisted-file) form exists. Remove them from your
configuration once you have confirmed the key survives a restart (`xkmsctl
bootstrap noise show-p256-key`, or compare the Noise public key a client has
pinned against what the listener now serves).

The struct is still named `NoiseBootstrapConfig` and still lives under the
`bootstrap.noise` YAML key. That is historical — it predates the second suite —
and is kept so existing configs keep parsing.

**Sequencing (Ruling 1, go-xkms#35):** the bootstrap listener is a network
service and so must not bind before the barrier is unsealed. This already
holds by construction and needs no extra gating here: `s.barrier` is set
inside `initEmbeddedQRDBNode` (`pkg/server/qrdb_node.go`), which blocks on
`serveSealedWindow` until the node reports unsealed before `New` can return
(`TestServeSealedWindow_SealedNodeProceedsAfterUnseal`,
`pkg/server/sealed_window_test.go`); `Start` — the only caller of
`startNoiseBootstrap`, which is what calls `loadNoiseStaticKey` — is never
reachable until `New` has returned. There is no path from a sealed barrier to
a bound Noise listener.

**Key-loading failures are not interchangeable.** A suite that is *unavailable
in this build* is skipped, which is the normal state of Noise_NK under FIPS. A
suite that is *configured but whose key will not load* fails the whole listener,
deliberately: falling through to the other suite would leave an operator looking
at a healthy port while every client provisioned for the broken suite failed to
connect. When no suite survives at all, construction fails with
`*server.ErrNoBootstrapSuite`, which carries the rejection reason for each suite
and unwraps to `bootstrap.ErrSuiteUnavailable`.

Client side — the resolver's `noise:` scope
(`resolver.NoiseConfig`, `trust.scopes.<name>.noise`):

```yaml
noise:
  server-addr: "kms.example.com:8447"
  server-static-key: "<64-hex-chars>"          # Noise_NK; skipped where the build cannot run it
  server-p256-static-key: "<130-hex-chars>"    # approved suite; required under FIPS
```

Validation requires at least one of the two keys. `xkmsctl bootstrap auto`
takes the same pair as `--noise-key` and `--p256-key`.

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

Client side, only TOFU persists anything: the captured SPKI pin, through the
qrdb pin store. Every other mode is stateless. There is no bundle cache and no
pin cache for the non-TOFU modes.

Server side, the listener's own static keys persist (go-xkms#35): barrier-
sealed key-value storage when a barrier is configured, a fixed plaintext hex
file in the data directory otherwise. See Configuration above.

## Test strategy

- **Listener key custody (go-xkms#35)** — `pkg/server/bootstrap_key_custody_test.go`:
  sealed persist/load round trip across two `*Server`s sharing a barrier
  (`TestNoiseKeyCustody_SealedRoundTrip`, `TestP256KeyCustody_SealedRoundTrip`);
  legacy hex/file config migrates into the barrier with the deprecation
  warning logged exactly once, and a later boot with no legacy config finds
  the sealed key (`TestNoiseKeyCustody_MigratesLegacyHexAndDeprecates`,
  `TestP256KeyCustody_MigratesLegacyFileAndDeprecates`); a barrier failure
  that is not "nothing sealed yet" surfaces as `*server.ErrBarrierKeyLoad`
  rather than silently falling through
  (`TestNoiseKeyCustody_BarrierGetErrorWraps`,
  `TestP256KeyCustody_BarrierGetErrorWraps`); the no-barrier floor persists to
  a fixed 0600 file and does not re-warn on a later boot
  (`TestNoiseKeyCustody_NoBarrierPersistsToFileAndReloads`,
  `TestP256KeyCustody_NoBarrierPersistsToFileAndReloads`), and falls back to
  the pre-#35 ephemeral behavior only when there is no data directory either
  (`TestNoiseKeyCustody_NoBarrierNoDataDirStaysEphemeral`,
  `TestP256KeyCustody_NoBarrierNoDataDirStaysEphemeral`);
  `TestNoiseKeyCustody_ThroughNodeAdoptedBarrier` repeats the round trip
  through the SAME `*seal.Barrier` the embedded qrdb node hands back
  (`node.BarrierRegistry().SystemBarrier()`), which is where the two
  "not found" sentinels (`storage.ErrNotFound` vs `seal.ErrSecretNotFound`)
  this package's `isBarrierKeyNotFound` handles actually diverge. Sequencing
  (no listener before unseal) is proved separately by
  `TestServeSealedWindow_SealedNodeProceedsAfterUnseal` in
  `pkg/server/sealed_window_test.go`, cited rather than re-proved here.
- **Suite availability and the listener's keys** —
  `pkg/server/bootstrap_suite_test.go`, plus `pkg/trust/bootstrap/suite_test.go`
  and its `suite_fips_test.go` / `suite_nofips_test.go` pair. These run under
  **both** sets of build tags and assert the same invariants in each, because
  the property under test is "the listener offers whatever suite this binary can
  run" — a test that only held in one build could not distinguish that from
  "the listener offers Noise". `make test-server` and `make test-server-fips`
  are the two lanes; the FIPS one is the only target that compiles
  go-truststrap's X25519 refusal, and it runs a real P-256 handshake end to end
  rather than merely asserting the package builds.
- **Client suite resolution and real handshakes** —
  `pkg/trust/bootstrap/noise_client_test.go` runs in every build and keys its
  expectations on what the binary can run: a P-256-only bootstrap completes
  everywhere, both-keys completes everywhere, and the Curve25519-only
  configuration completes where Noise is runnable and is the typed `NoSuite`
  refusal where it is not. The fail-closed branches a fixed build cannot
  reach are driven by injecting the probe's answer. `noise_client_fips_test.go`
  (`//go:build fips`) asserts the FIPS claims with the real probe:
  `make test-trust-bootstrap-fips` is the lane, and it executes a real P-256
  handshake against a real listener. The package also passes under
  `GOFIPS140=v1.0.0 GODEBUG=fips140=only`, the mechanism the release
  artifact actually uses.
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
