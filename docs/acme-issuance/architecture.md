# ACME Issuance — Architecture

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-10-08

## The problem

Certificates that humans issue by hand expire on a weekend. RFC 8555 (ACME) is
the standard answer, and every TLS client already speaks it. But the public
ACME profile assumes the internet's identifier model: you prove control of a
DNS name over HTTP or DNS. Inside a trusted-computing fleet the interesting
identifier is not a name at all — it is *a TPM*. A node should be able to prove
"I am this specific piece of hardware, and this key was made inside it", and
receive a certificate for that.

So this feature is RFC 8555 as specified, plus challenge types that prove
hardware identity.

## Shape chosen: a standards CA server over `TrustedCA`, with extra challenges

`pkg/acme` implements the RFC 8555 server (accounts, nonces, orders,
authorizations, challenges, finalization, revocation, key change) and issues
through [`TrustedCA`](../certificate-authority/architecture.md). It does not
have a key of its own.

Five challenge types are implemented (`pkg/acme/challenges/`):

| Challenge | Proves | Standard |
|---|---|---|
| `http-01` | control of a DNS name, over HTTP | RFC 8555 |
| `dns-01` | control of a DNS name, via a TXT record | RFC 8555 |
| `device-attest-01` | possession of an attested device key | draft |
| `enroll-01` | TPM identity, via TCG-CSR-IDEVID + `TPM2_MakeCredential`/`ActivateCredential` | **go-xkms** |
| `endorse-01` | endorsement of the requester by an existing trusted party | **go-xkms** |

`enroll-01` is the one that matters for the platform: a joining node presents a
TCG CSR carrying its IDevID, the server issues a `MakeCredential` challenge that
only the real TPM can activate, and the node's certificate is bound to hardware
that was verified, not asserted.

`device-attest-01` follows draft-ietf-acme-device-attest: the client POSTs its
attestation (`{"attObj": base64url(CBOR)}`) as the challenge response and the
server verifies it from that payload, contacting nothing. It attests a key and an identity: the
key it attests is only compared with the certificate's key at finalization
(the evidence arrives at the challenge and the CSR one request later), and the
device identity the evidence carries is compared against the order's
authorized identifier at the challenge itself, before the exchange is allowed
to validate at all. Its verification is therefore two phases for both formats
it accepts — `VerifyAttestation` and the identity check at the challenge,
`VerifiedAttestation.BindCSRKey` at finalization — and the one-shot `Verify`
refuses both formats with `ErrKeyBindingRequired`
(`pkg/acme/challenges/device-attest-01/deviceattest01.go`), so the ACME
server (`pkg/acme/server/handlers`) is what drives both phases rather than
that one-shot verifier. It does so through the attesting-verifier interface
(`common.AttestingVerifier`), which every attestation challenge type
(`enroll-01`, `endorse-01`, `device-attest-01`) must implement and which sits
beside the unchanged `ChallengeVerifierFunc` that serves `http-01`, `dns-01`
and `tls-alpn-01`: the verifier returns the attested identity and the evidence
to bind, and `ChallengeHandler` is what compares the identity against the order
and persists the evidence (see
[engineering.md](engineering.md#device-attest-01-key-binding)
for the exact contract). For the `tpm` format the evidence is the WebAuthn
Level 2 §8.3 TPM2_Certify of `pubArea` by the AIK in `x5c[0]`; the binding
requires the CSR's key to be `pubArea`'s key, and the identity is the AIK
certificate's RFC 4043 `permanentIdentifier` otherName. Both key-binding
phases go through the one binding gate, `attestation.VerifyInvariants`, that
the TCG-CSR and SignCSR carriers use. See
[engineering.md](engineering.md#device-attest-01-key-binding).

The evidence being verifiable says nothing about which device produced it,
since attestation evidence is not secret: without the identity check, a
genuine attestation captured from device X could be replayed beside an order
for an identifier device X was never assigned. `VerifiedAttestation.DeviceIdentity`
closes that read the same permanent-identifier convention
`matchesPermanentIdentifierOrder` already enforces on a CSR, so the CSR-side
and evidence-side checks cannot drift into two different ideas of what a
permanent identifier is.

Rejected for `tpm`: verifying the statement as a TPM2_Quote over the key
authorization. That was the previous verifier, and a quote attests platform
state, not a key — it never read `pubArea`, so any genuine device's evidence
authorized a certificate for any key.

Rejected alternatives:

- **Boulder or step-ca as the ACME server.** Rejected because neither can issue
  from a key that lives in our keystore, and neither has a place to put
  `enroll-01`. The comparison is retained as
  `docs/acme/boulder-comparison-enhancements.md` in the legacy tree and remains
  the reference for what a hardened public CA does that this one does not.
- **A bespoke enrollment protocol instead of ACME.** Rejected: then every client
  needs custom code. ACME means `certbot`, `lego`, `caddy` and everything else
  already work, and the hardware challenges are an extension a normal client
  simply does not select.
- **A separate ACME service process.** Rejected for the default deployment —
  see the same reasoning in
  [`../certificate-authority/architecture.md`](../certificate-authority/architecture.md).
  The ACME server can still be run on its own listener.

## Component boundaries

| Piece | Package |
|---|---|
| Protocol entities (account, order, authz, challenge, cert) | `pkg/acme/entities` |
| Server handlers | `pkg/acme/server/handlers` |
| Nonce service | `pkg/acme/nonce` |
| Challenge implementations | `pkg/acme/challenges/{http-01,dns-01,device-attest-01,enroll-01,endorse-01}` |
| Issuance | `pkg/acme/server/handlers.OrderFinalizeHandler` calls `s.ca` (`pkg/ca`) directly; `pkg/acme/issuance` is not on this path — see Data flow below |
| Storage | `pkg/acme/storage` — `objstore.NewFactory` over the server datastore's go-qrdb DAO factory (`pkg/datastore` `DAOFactory`) |
| Identifier policy, CAA | `pkg/acme/policy`, `pkg/acme/server/caa.go` — both wired, see Trust boundaries |
| Rate limits, request body cap | `pkg/acme/server/rate_limiter.go`'s `NewClientRateLimiterMiddleware` — wired into both xkmsd (`cmd/xkmsd/acme.go`) and the standalone `TrustedCA` (`pkg/acme/client/trustedca.go`), keyed per client IP; the tenant and per-category limiters (`tenant_rate_limiter.go`) keyed on verified accounts; `pkg/acme/server/request_body.go`'s `RequestBodyMiddleware` reads every body once, capped at 256 KiB, ahead of all of them; see Trust boundaries |
| Circuit breakers, degradation cache | `pkg/acme/server/circuitbreaker` (breakers, `Manager`, the bounded per-target groups in `target.go`, the HTTP middleware, and the `WrapChallengeVerifier`/`WrapChallengeVerifierPerTarget`/`WrapLogSubmitter`/`WrapKMSService` decorators), `pkg/acme/server/resilience.go`'s `WrapChallengeVerifiers` (the shared challenge-verifier wrapping helper), `pkg/acme/server/degradation` (the cache `GET /acme/directory` and `GET /acme/ca-bundle` fall back to) — wired into both xkmsd and the standalone `TrustedCA`; see Trust boundaries |
| Certificate Transparency | `pkg/acme/ct` |
| Admin plane | `pkg/acme/admin` |
| Multi-transport adapters | `pkg/acme/api/{rest,grpc,quic,mcp}` + `pkg/acme/api/adapter.go` |
| Client library | `pkg/acme/client`, `sdk/go/acme` |
| Client binary | `cmd/acme-client` (`trusted-acme-client`) |
| KMS binding | `pkg/acme/kms` |
| Web/GUI | `pkg/acme/web`, `pkg/acme/gui` |

## Data flow

Standard order, `http-01`:

```
client → GET  /acme/directory              (URLs for everything else)
       → HEAD /acme/new-nonce              (a nonce; every POST needs one)
       → POST /acme/new-account            (JWS-signed; account key established)
       → POST /acme/new-order              (identifiers requested)
       → GET  /acme/authz/{id}             (challenges offered)
       → POST /acme/challenge/{id}         (client says "ready")
         ← server validates out of band (HTTP fetch / DNS lookup)
       → POST /acme/order/{id}/finalize    (CSR submitted)
         → OrderFinalizeHandler → s.ca.SignCSR (pkg/ca) → keystore signer
       → GET  /acme/cert/{id}              (certificate chain, PEM)
```

`enroll-01`, the hardware path:

```
joining node → POST /acme/new-order with a TCG-CSR-IDEVID identifier
  → server: CATCGEnrollment.VerifyTCG_CSR_IDevIDBytes → (blob, secret, plain)
  → server issues a TPM2_MakeCredential challenge carrying the blob
  → node: TPM2_ActivateCredential — only the TPM holding the EK can recover the secret
  → node returns the secret; server finalizes and issues
```

The node's certificate is therefore evidence that the private key is inside a
TPM whose endorsement key the CA verified. A cluster configured with
`raft_enrollment.acme.enabled` uses exactly this to admit new Raft nodes; the
first node issues in-process from the local `TrustedCA` and joining nodes go
through ACME against an existing node's directory.

## Trust boundaries

- **Account keys are the client's identity.** Every POST is JWS-signed by the
  account key; the server binds orders to the account, not to a session.
- **Nonces are single-use and server-issued.** Replay protection is the nonce
  service, `pkg/acme/nonce`: an AES-GCM-encrypted, monotonic counter validated
  by decryption rather than by a lookup table, with a `NonceMaxUsed`-bounded
  redeemed-set and a `NonceLifetime`-bounded signing epoch — see
  [`engineering.md`](engineering.md) Configuration and Persistence. Nonce
  validity across nodes in a load-balanced deployment requires every node to
  share the same encryption key (`handlers.Params.NonceKey`); absent that,
  each node mints from its own key and a request that lands on a different
  node than the one that issued the nonce gets `badNonce`, which RFC 8555
  clients already retry.
- **Challenge validation happens server-side, out of band.** Nothing the client
  asserts about itself is trusted; the server fetches, resolves, or activates.
- **The validation target is client-chosen, so the server's reach is
  bounded.** Every fetch from a client-named host goes through one
  SSRF-safe client (`pkg/acme/challenges/validation`): bare host only, no
  loopback/private/link-local/metadata address after DNS resolution, capped
  responses, and client-facing errors reduced to a fixed category. Reaching a
  private target is an explicit, default-off switch,
  `acme.challenges.allow_private_targets` (go-xkms#1172; see
  [`engineering.md`](engineering.md) "Challenge validation client").
- **`enroll-01` trusts the TPM manufacturer chain**, not the requester. If the
  EK certificate does not chain to a trusted manufacturer root, activation
  cannot succeed.
- **Identifier policy and CAA are enforcement, not advice, and both are live.**
  `NewOrderHandler` runs every identifier through `pkg/acme/policy` before an
  authorization is created (`checkIdentifierPolicy`,
  `pkg/acme/server/handlers/identifier_policy.go:56`, called from
  `new_order.go:108`; go-xkms#770). `pkg/acme/server/caa.go` checks CAA
  (RFC 8659, plus RFC 8657's `accounturi`/`validationmethods` parameters)
  before issuing, wired through `Params.CAAValidator` and
  constructed from the required `acme.caa_identities` config in both xkmsd
  (`cmd/xkmsd/acme.go:245`, `order_finalize.go:523,539`) and the standalone
  `TrustedCA` (`pkg/acme/client/trustedca.go`); go-xkms#788. An ACME server
  cannot start enabled without naming the issuer identity a CAA record must
  list, and a DNS failure that leaves the CAA RRset undetermined denies
  issuance rather than proceeding regardless. Order finalize supplies the
  requesting account's URI and the challenge type that actually validated
  each identifier, so a record's `accounturi`/`validationmethods` parameters
  are enforced against reality, not merely parsed.
- **The admin plane's tenant boundary is enforced by its service, not its
  permission gate.** qrdb's gate binds the caller's own tenant as the
  target, so it admits a tenant administrator's request whichever tenant it
  names. The admin service therefore binds every tenant, role, user,
  account and certificate a request names to the caller's tenant, answers a
  foreign one exactly as a missing one, reserves tenant creation and the
  (tenant-less) audit trail to the platform, and binds the caller's tenant
  into every qrdb call so qrdb enforces it too (go-xkms#1225; see
  [`engineering.md`](engineering.md#invariants)).
- **Rate limits are enforcement, not advice, per client.**
  `pkg/acme/server/rate_limiter.go`'s `NewClientRateLimiterMiddleware` is
  mounted on the whole ACME surface by both ACME server compositions
  (xkmsd's `cmd/xkmsd/acme.go`, the standalone `TrustedCA`), keying each
  client by IP — never by an unverified JWS `kid`, which a client could vary
  per request. Its lock covers only the token arithmetic, and its state is
  bounded by a TTL and an entry cap. Ahead of it, `RequestBodyMiddleware`
  reads each request body once, capped at 256 KiB, so no limiter or
  handler ever reads the connection while holding shared state
  (go-xkms#1171). The per-tenant overall quota and the RFC 8555
  Section 6.6 per-category limits (`tenant_rate_limiter.go`,
  `rate_limiter.go`) are wired into both compositions, keyed exclusively on
  a tenant `handlers.RestService.TenantAuthMiddleware` resolves from a fully
  verified JWS `kid` — never from a client-asserted header, host, or path —
  see [`engineering.md`](engineering.md) §Rate limiting and §Tenant
  admission control (go-xkms#886).
- **Circuit breakers guard individual outbound dependencies, not order
  creation, and now run on both ACME server compositions.**
  `pkg/acme/server/circuitbreaker` guards five dependencies: three named,
  single breakers (CT log submission via `circuitbreaker.WrapLogSubmitter`,
  available wherever a CT submitter is constructed — see "What this feature
  deliberately does not do"; the tenant KMS signer, `Params.KMSService`,
  wrapped automatically by `NewRestService` when both it and
  `Params.Breakers` are set; and the CA/keystore-backed certificate storage
  `GET /acme/ca-bundle` reads from), and two **per-target breaker groups**
  — the `http-01` and `dns-01` challenge verifiers, one breaker per
  validation target (the domain http-01 dials, or the zone dns-01 queries)
  rather than one breaker shared by every account's validation
  (go-xkms#1189, #1190). A target that never responds trips only its own
  breaker; every other target's admission is decided independently, and the
  per-group table is bounded (LRU plus idle-TTL eviction, see
  [`engineering.md`](engineering.md) "Circuit breakers and degradation") so
  a flood of distinct hosts cannot grow it without limit.
  `cmd/xkmsd/acme.go` and the standalone `TrustedCA`
  (`pkg/acme/client/trustedca.go`, go-xkms#820) both build their breaker
  `Manager` and wrap their challenge verifiers through the same
  `server.WrapChallengeVerifiers` helper (`pkg/acme/server/resilience.go`),
  so a breaker group named `http01` or `dns01` means the same thing in
  either composition's `/health` output; `xkmsd`'s `buildChallengeMap` calls
  it after selecting verifiers from `acme.challenges`, `TrustedCA.Serve`
  calls it on the map a caller supplied through `WithChallengeMap`.
  `TrustedCA` reuses `pkg/config`'s `ACMEResilienceConfig` directly as
  `TCAACMEConfig.Resilience` rather than a parallel type, so the same
  `storage`/`kms`/`http01`/`dns01` breaker sections and defaults — including
  each per-target group's capacity and idle timeout — apply to both
  compositions' configuration.
  A challenge the validation client refuses before contacting the target
  (an invalid target, or a reserved address) does not count toward that
  target's breaker (go-xkms#1181): the target is client-chosen, so counting
  refusals would let an account open a breaker for free, though per-target
  isolation already limits the damage to that account's own target. See
  [`engineering.md`](engineering.md) "Circuit breakers and degradation".
  An open breaker fails only the call it guards — a challenge validation
  attempt returns an `incorrectResponse` problem instead of hanging on a dead
  verifier target, a KMS-backed finalize fails instead of blocking — it does
  not intercept `POST /acme/new-order`, which calls none of these five.
  `GET /acme/directory` and `GET /acme/ca-bundle` degrade rather than fail:
  while the storage breaker is open they serve their last computed response
  from a `pkg/acme/server/degradation` cache (falling back to a *stale*
  cache entry only past its TTL; a still-fresh one is served as a normal,
  non-degraded response). `GET /acme/health` reports every named breaker's
  state and counters, a bounded summary of each per-target group, and
  whether the directory/CA-bundle endpoints are currently degraded.
  The ACME protocol state itself — accounts, orders, authorizations,
  challenges, nonces (`pkg/acme/storage` → `go-qrdb/sdk/go`) — is not wrapped
  in a circuit breaker: go-qrdb owns that storage's consistency and retry
  semantics, and a breaker's goroutine-plus-timeout can abandon a call
  without waiting for it, which is safe for an idempotent read or a network
  probe but not for a durable write whose caller must not believe it failed
  while it is still committing. Lower layers win.

## What this feature deliberately does not do

- **It does not run a public web PKI.** OCSP stapling, CRL distribution-point
  automation, CT log submission and cross-signing automation are on the roadmap,
  not in the tree; `pkg/acme/ct` and `pkg/acme/issuance` (the bridge that would
  call it) are present but neither is wired into `OrderFinalizeHandler`, which
  issues through `TrustedCA.SignCSR` directly. `circuitbreaker.WrapLogSubmitter`
  exists so whatever wires CT submission in does not have to build its own
  resilience layer, but there is no production call site to wrap yet; SCT
  handling at issuance is tracked separately as go-xkms#745.
- **It does not own the CA.** Issuance is `TrustedCA`'s; ACME is the protocol in
  front of it.
- **It does not define identity.** Accounts are ACME accounts. Platform users,
  RBAC and tenancy are go-qrdb's.
- **`cactl` is not part of this repo, and no longer part of anything.** It was
  the CLI of a separate standalone CA project, which was decommissioned in
  August 2026 when its CA work was folded into go-xkms as `TrustedCA` plus this
  ACME implementation. The integration compose file still points
  `CACTL_BINARY` at a checkout of that retired project. See this feature
  folder's `cli.md`.
