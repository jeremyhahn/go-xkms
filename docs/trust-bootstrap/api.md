# Trust Bootstrap — API

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-09-22

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

This feature has an unusual API shape and the reason is structural: **the client
half is a library, not a wire call.** `Fetch` runs on the client and speaks
DNS, Noise or TLS to reach an anchor. Only the *serving* half — handing out the
bundle — is an endpoint.

## Capability matrix

| Capability | REST | gRPC / Unix | QUIC (HTTP/3) | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Fetch CA bundle (bootstrap route) | `GET /v1/ca/bootstrap` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `bootstrap.Fetch(ctx, cfg)` | **public** |
| Fetch CA bundle (authenticated route) | `GET /api/v1/ca/bundle` | `GetCABundle` | same as REST | `xkms.ca.bundle` | `CAService.GetCABundle` | session |
| Noise bootstrap channel | — | — | — | — | `pkg/trust/bootstrap/noise_server.go` | pinned static key |
| Bootstrap listener's own public keys (go-xkms#632) | `GET /api/v1/bootstrap/keys` | `BootstrapListenerKeys` | same as REST | `bootstrap.showKeys` | `XKMSService.BootstrapListenerKeys` | `bootstrap:read`, admin-only |
| Client-side dispatch (`auto`/`dane`/`noise`/`spki`/`direct`/`tofu`) | n/a — client-side | n/a | n/a | n/a | `bootstrap.Fetch` | anchor-dependent |
| Endpoint TLS verifiers (`dane`/`spki`/`tofu`) | n/a — client-side | n/a | n/a | n/a | `NewDANETLSConfig`, `NewSPKIPinTLSConfig`, `NewTOFUTLSConfig`; `resolver.TLSConfig` | anchor-dependent |

### Why the gaps are gaps and not omissions

`GET /v1/ca/bootstrap` has no gRPC, Unix or MCP equivalent. The route exists
precisely for a client that has nothing — no trust store entry, no credentials,
no negotiated transport — and an HTTP GET is the lowest common denominator such
a client has. A gRPC bootstrap endpoint would need a TLS trust decision to
connect, which is the circularity this feature exists to break.

That is a defensible design, but it is written here as a tracked row rather than
left out, so the next reader sees a decision rather than an oversight.

## The serving side

`GET /v1/ca/bootstrap` is registered in `pkg/api/rest/routes.go` under
`GroupRoot` with `RouteAuthPublic` — no authentication, no tenant middleware, no
RBAC. Its handler is `GetCABundleHandler`.

Response: the PEM-encoded CA chain, `Content-Type:
application/pem-certificate-chain`. `CABundle.ContentType` records what the
server actually reported so a client can detect a proxy that rewrote it.

**Nothing private may ever be added to this route.** It is unauthenticated by
design and by necessity.

The Noise serving side is `pkg/trust/bootstrap/noise_server.go`, listening on
the configured `noise_port`. It is not an HTTP endpoint: the client completes a
handshake pinned to the server's static public key, and the bundle is delivered
in-band on that channel.

### Two handshake suites on one port

The listener speaks two suites and selects **per connection**, from the suite
byte in the client's first frame. There is no separate port and no separate
listener:

| Suite | Wire byte | Handshake | FIPS |
|---|---|---|---|
| `SuiteNoiseNK` | `0x01` | `Noise_NK_25519_ChaChaPoly_SHA256` | **no** — mandates X25519, which SP 800-56A Rev. 3 does not approve |
| `SuiteP256AESGCM` | `0x02` | `TSBOOT1_P256_AESGCM_SHA256` | yes |

A suite whose static key is not configured is simply not offered, and a
connection selecting it is refused with go-truststrap's `ErrUnsupportedSuite`.
A FIPS build cannot run Noise_NK at all, so there the P-256 suite is the only
one the listener serves.

Which suites a binary *can* run is resolved while the listener is being
configured, not at key generation — see
[`architecture.md`](architecture.md) §Suite availability is resolved at
construction.

**Wire compatibility:** the two-byte `version || suite` header arrived with
go-truststrap v0.4.0-alpha. Peers older than that sent a bare Noise message 1
with no header and no prologue, and are refused by design — upstream lists
"strip the header and speak the old wire" among the downgrade attacks it
defends against. Both ends of a bootstrap pair move together.

## Reporting the listener's own public keys (go-xkms#632)

`GET /api/v1/bootstrap/keys` (REST; the same call over gRPC/Unix as
`BootstrapListenerKeys`, over QUIC as the same JSON route, over MCP as
`bootstrap.showKeys`, and in-process as `XKMSService.BootstrapListenerKeys`)
answers a different question from everything else on this page: not "give me
the CA bundle" but "what public key is this listener's Noise/P-256 channel
using right now, so I can hand it to a first-contact client." It requires an
authenticated administrator holding `bootstrap:read` — the opposite trust
direction from the bundle routes above, which are deliberately public because
the client asking has nothing yet. This route is for the operator who already
has credentials and needs the value to distribute, not for the client doing
the bootstrapping.

Response (`BootstrapListenerKeysResponse`):

```json
{
  "noise_public_key": "<64 hex chars>",
  "p256_public_key":  "<130 hex chars>"
}
```

Both fields are hex-encoded in **exactly** the form
[`NoiseConfig`](engineering.md) already accepts: `noise_public_key` is the
value for `NoiseConfig.ServerStaticKey` / `xkmsctl bootstrap auto --noise-key`
/ `xkmsctl bootstrap show-keys`'s own `--noise-key`-labeled line, and
`p256_public_key` is the value for `NoiseConfig.ServerP256StaticKey` /
`--p256-key`. **There is no separate SPKI pin for this transport.** No
consumer anywhere hashes the Noise/P-256 responder key into a pin before
comparing it — go-truststrap's suite-negotiating client pins the listener by
this raw public key directly (`decodeSuiteKey`: hex-decode, then a
suite-specific length check), the same way `xkmsctl bootstrap noise show-key`
/ `show-p256-key` already print it for a locally-held private key. Inventing
an SPKI-style hash here would be a format nothing in the stack could consume.

A field is omitted when that suite is not offered (a FIPS build never
populates `noise_public_key`; a build with no P-256 key configured omits
`p256_public_key`).

**Only public material is ever returned.** The private scalars stay in
`pkg/server/bootstrap_key_custody.go`'s protected memory and are never
serialized. Before the listener has finished starting (or when none is
configured at all), the call returns
`xkms.ErrBootstrapListenerNotEnabled` — 503 over REST/QUIC,
`codes.Unavailable` over gRPC/Unix — rather than a response with empty
fields, so a caller can distinguish "ask again once it's up" from "this suite
isn't offered."

## The client side

```go
bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
	Mode:      bootstrap.ModeAuto,
	ServerURL: "https://kms.example.com:8443",
	Logger:    logger,
	DANE:      &bootstrap.DANEConfig{ /* ... */ },
	SPKI:      &bootstrap.SPKIConfig{ /* ... */ },
})
```

Four consumers call it: `xkmsctl`, the xkey GUI, the QuicBaaS SDK, and
go-trusted-platform through the SDK. `Mode` string values are pinned to the CLI
verb and the SDK accessor name so those four never diverge.

### The Noise transport, client side

`ModeNoise` composes go-truststrap's suite-negotiating bootstrap client
(`pkg/trust/bootstrap/noise_client.go`) and offers whichever of the two suites
above it holds a server key for and this build can run:

```go
bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
	Mode: bootstrap.ModeNoise,
	Noise: &bootstrap.NoiseConfig{
		ServerAddr:          "kms.example.com:8447",
		ServerStaticKey:     "<64 hex>",   // Noise_NK; skipped where the build cannot run it
		ServerP256StaticKey: "<130 hex>",  // the approved suite; what a FIPS client needs
	},
})
```

A FIPS client holding only a Curve25519 key gets `ErrNoSuite` carrying
`ErrSuiteUnavailable` before it opens a connection. `NoiseConfig.Suite` pins a
suite; a pinned suite the build cannot run is refused rather than replaced.
Under `ModeAuto` the Noise arm is the same suite-negotiating client, so a
P-256-only configuration bootstraps there too; a failed arm is one
`AttemptError` in the `AggregateError` a `FetchError{Mode: auto}` wraps.

## Status and error mapping

The serving route:

| Condition | REST |
|---|---|
| bundle served | 200, `application/pem-certificate-chain` |
| no CA configured | 501 |
| CA not initialized | 409 |

`GET /api/v1/bootstrap/keys`:

| Condition | REST | gRPC / Unix |
|---|---|---|
| keys published | 200, JSON | `OK` |
| no identity, or lacking `bootstrap:read` | 401 / 403 | `Unauthenticated` / `PermissionDenied` |
| listener not yet started, or not configured | 503 | `Unavailable` |

The client library returns typed errors rather than status codes —
`ErrInvalidMode`, `ErrModeNotConfigured`, `ErrServerURLRequired`, and
`ErrFetch`/`*FetchError` carrying the attempted `Mode` and the truststrap cause.
`ModeNoise` adds `ErrSuiteKeyMissing`, `ErrSuiteKeyInvalid`, `ErrNoSuite` and
`ErrBundleMalformed`, with `*SuiteError` / `*NoSuiteError` /
`*BundleCertificateError` carrying the detail.
See [`engineering.md`](engineering.md) §Errors.

## Pagination

Not applicable. A bundle is returned whole; a partial trust chain is a security
defect, not a page.

## Versioning and deprecation

The bootstrap route is `/v1/ca/bootstrap` — a **different prefix** from the
authenticated `/api/v1` surface, deliberately. It is the one route a client
hard-codes, so it is versioned independently of the API it precedes.
`Config.BundlePath` exists to override it for deployments that mount it
elsewhere.

Nothing here is deprecated. Adding a `Mode` is additive; removing one is
breaking for every consumer that names it in configuration.
