# Trust Bootstrap — Architecture

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

A client that has never spoken to a server needs that server's CA bundle before
it can verify anything. Fetching the bundle over a connection you cannot verify,
and then trusting it, is circular — it is trust-on-first-use with extra steps,
and it is how fleets get silently mis-enrolled.

This feature is the set of ways to break the circle: each one anchors trust in
something the client already has, out of band.

## Shape chosen: one `Fetch`, five anchors, an explicit mode

`pkg/trust/bootstrap` is a **dispatch library**, not a protocol implementation.
The protocols live in go-truststrap; this package chooses among them, supplies
xkms-specific configuration, and returns a bundle.

```go
func Fetch(ctx context.Context, cfg Config) (*CABundle, error)
```

Stateless by construction: each call builds a fresh truststrap bootstrapper,
runs the fetch, closes it, returns. **There is no caching between calls** — so a
caller that wants a cached bundle must own the cache, and a caller that wants a
fresh one always gets it.

The modes (`Mode`, a string, deliberately matching the CLI verb and the SDK
accessor name so the three never drift):

| Mode | Anchor | What the client must already have |
|---|---|---|
| `dane` | DNSSEC-validated TLSA records | a validating resolver and DNSSEC trust |
| `noise` | the server's Noise static public key | that public key, out of band |
| `spki` | SHA-256 pin of the server's SubjectPublicKeyInfo | that pin, out of band |
| `direct` | the system trust store | a publicly trusted server certificate |
| `tofu` | the first connection seen | nothing — and that is the problem |
| `auto` | tries the configured modes in order | whichever of the above are configured |

`ModeAuto` runs `DefaultMethodOrder` and returns the first success. A mode whose
sub-config is nil means "not configured": `ModeAuto` skips it silently, while a
single-mode `Fetch` returns `ErrModeNotConfigured`. That asymmetry is
deliberate — auto is a best-effort chain, an explicit mode is an assertion.

**`tofu` is not in the default auto chain**, and the code says why: "a TOFU
fallback in a strictly pinned environment is a security hazard". Including it
would mean an attacker who breaks DANE and Noise gets silently promoted to
trust-on-first-use. To use TOFU under auto you must set both `Config.TOFU` and
list `ModeTOFU` in `Config.TOFUMethodOrder` — two explicit acts.

Rejected alternatives:

- **Ship the CA bundle in the client image.** Rejected: it makes CA rotation a
  redeploy of every client, and a stale image trusts a retired root.
- **TOFU as the default.** Rejected for the reason above.
- **A single anchor.** Rejected because the anchors are not interchangeable —
  DANE needs DNSSEC you may not have, SPKI needs a pin distributed somehow,
  Noise needs a key distributed somehow. Different deployments have different
  things already.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Mode dispatch, config, errors | `pkg/trust/bootstrap/bootstrap.go` | go-xkms |
| Noise bootstrap server (the serving side) | `pkg/trust/bootstrap/noise_server.go` | go-xkms |
| TLS config construction for pinned modes | `pkg/trust/bootstrap/tlsconfig.go` | go-xkms |
| TOFU pin persistence | `pkg/trust/bootstrap/pinstore_qrdb.go` — through `go-qrdb/sdk/go` | go-xkms (store is qrdb's) |
| DANE, Noise_NK, SPKI-pinned TLS protocols | **go-truststrap** | go-truststrap |
| The bundle being served | `GET /v1/ca/bootstrap` — [`../certificate-authority/`](../certificate-authority/architecture.md) | go-xkms |
| Client-side platform CA import | `xkey trust import-platform` — [`../../xkey/docs/platform-trust/`](../../xkey/docs/platform-trust/architecture.md) | go-xkms (xkey surface) |

This is capability row **"Trust bootstrap dispatch" (tier 1)**.

Four consumers use this library: `xkmsctl`, the xkey GUI, the QuicBaaS SDK, and
go-trusted-platform through the SDK. That is why `Mode`'s string values are
pinned to the CLI verb and SDK accessor names — five spellings of the same
concept across four consumers is how they drift apart.

## Data flow

```
client                                              server
  │
  ├─ dane:   resolve TLSA via DNSSEC ──────────────► DNS
  │          verify server cert against TLSA
  │          GET /v1/ca/bootstrap over HTTPS ──────► xkmsd (public route)
  │
  ├─ spki:   TLS handshake, compare SPKI SHA-256 to the pre-shared pin
  │          GET /v1/ca/bootstrap ─────────────────► xkmsd
  │
  ├─ noise:  Noise_NK handshake pinned to the server's static key
  │          fetch the bundle in-band ─────────────► noise_server.go
  │
  ├─ direct: ordinary system-trust HTTPS ──────────► xkmsd
  │
  └─ tofu:   first connection captures the SPKI pin into PinStore;
             every later connection verifies it exactly like spki
```

`GET /v1/ca/bootstrap` is public and unauthenticated by design — a client with
no trust cannot authenticate. It is safe because the client verifies the bundle
through the anchor, not through the connection.

`Config.BundlePath` overrides the path; empty means the canonical
`/v1/ca/bootstrap`.

## Trust boundaries

- **The anchor is the trust boundary, not the transport.** Every mode except
  `direct` and `tofu` verifies the server *before* believing the bundle.
- **`direct` trusts the public web PKI.** Use it only when the server genuinely
  has a publicly trusted certificate; it is documented in the code as
  "last-resort fallback only".
- **`tofu` trusts whoever answers first.** Its pin store is the security
  boundary; a writable pin store is a trust-rewrite primitive.
- **The Noise static key and the SPKI pin are secrets in the integrity sense,
  not the confidentiality sense.** Publishing them is fine; letting an attacker
  substitute them is total compromise.
- **Nothing is cached inside the library.** A caller that caches a bundle owns
  the staleness and the revocation problem.

## What this feature deliberately does not do

- **It does not implement DANE, Noise or SPKI pinning.** go-truststrap does;
  this is dispatch. Bugs in the protocols belong there.
- **It does not authenticate the client.** Bootstrap is one-way: the client
  learns to trust the server. Client enrollment is
  [`../init-ceremony/`](../init-ceremony/architecture.md) and ACME.
- **It does not manage the lifetime of what it returns.** No refresh, no
  expiry tracking, no rotation.
- **It does not decide the mode for you.** `ModeAuto` is a convenience over
  what you configured, not a recommendation engine.
