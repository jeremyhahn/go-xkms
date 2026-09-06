# Trust Bootstrap — Architecture

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-09-06

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

## Suite availability is resolved at construction

The bootstrap listener speaks two handshake suites (see
[`api.md`](api.md) §Two handshake suites on one port). Which ones a given binary
*can* run is a property of the build, so it is resolved while the listener is
being configured rather than at key generation inside the accept loop. An
operator whose build can serve nothing learns it once, at startup, with a typed
error naming both suites — not from every client that later fails to connect.

**Availability is asked of the library, not of a FIPS predicate.** The obvious
`if fips.Compiled()` is wrong for the reason already recorded on the certstore
thumbprint: `GODEBUG=fips140=off` turns that predicate false on a
GOFIPS140-built binary, so the guard fails *open* for exactly the artifacts the
policy most cares about. `EnsureSuiteAvailable` instead attempts the key
generation and classifies the result, caching it per process. That reads the
build's real behaviour, cannot disagree with the code that will run the
handshake, and tracks upstream if go-truststrap's FIPS support later changes.
It is also why both FIPS mechanisms are covered by one implementation: the
`fips` build tag, which compiles go-truststrap's X25519 out, and
`GODEBUG=fips140=only`, where `crypto/ecdh` refuses X25519 at run time, produce
different errors but the same answer.

**A rejected suite and a broken key are not the same failure.** A suite this
build cannot run is skipped silently; a suite that is configured but whose key
will not load fails the whole listener. Falling through in the second case would
leave an operator looking at a healthy port while every client provisioned for
the broken suite failed to connect — a silent downgrade presented as success.

### Rejected: a compatibility shim for the old wire

go-truststrap v0.4.0-alpha's first frame carries a `version || suite` header;
before it, the Noise bootstrap sent a bare Noise message 1. Upstream lists
"strip the header and speak the old wire" among the downgrade attacks it
deliberately defends against, so there is no silent fallback and an
un-upgraded peer is refused. Adding a shim here to accept the old wire would
reintroduce exactly the downgrade upstream closed. Owner-ruled: clean
integration, both bootstrap ends move together.

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
