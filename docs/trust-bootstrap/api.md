# Trust Bootstrap — API

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-08-19

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
| Client-side dispatch (`auto`/`dane`/`noise`/`spki`/`direct`/`tofu`) | n/a — client-side | n/a | n/a | n/a | `bootstrap.Fetch` | anchor-dependent |

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
Noise_NK handshake pinned to the server's static public key, and the bundle is
delivered in-band on that channel.

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

## Status and error mapping

The serving route:

| Condition | REST |
|---|---|
| bundle served | 200, `application/pem-certificate-chain` |
| no CA configured | 501 |
| CA not initialized | 409 |

The client library returns typed errors rather than status codes —
`ErrInvalidMode`, `ErrModeNotConfigured`, `ErrServerURLRequired`, and
`ErrFetch`/`*FetchError` carrying the attempted `Mode` and the truststrap cause.
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
