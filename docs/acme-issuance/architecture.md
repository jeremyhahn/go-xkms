# ACME Issuance — Architecture

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-23

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
| Issuance | `pkg/acme/issuance` → `pkg/ca` |
| Storage | `pkg/acme/storage`, `pkg/acme/qrdb` (through `go-qrdb/sdk/go`) |
| Policy, CAA, rate limits, circuit breaker, degradation | `pkg/acme/policy`, `pkg/acme/server/caa.go`, `pkg/acme/server/rate_limiter.go`, `pkg/acme/server/{circuitbreaker,degradation}` |
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
         → pkg/acme/issuance → TrustedCA.SignCSR → keystore signer
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
- **`enroll-01` trusts the TPM manufacturer chain**, not the requester. If the
  EK certificate does not chain to a trusted manufacturer root, activation
  cannot succeed.
- **Rate limits and CAA are enforcement, not advice.** `pkg/acme/server/caa.go`
  checks CAA before issuing; `pkg/acme/server/rate_limiter.go` and the tenant
  rate limiter bound per-account and per-tenant issuance.
- **The circuit breaker and degradation paths fail closed** — under pressure the
  server refuses new orders rather than issuing unvalidated ones.

## What this feature deliberately does not do

- **It does not run a public web PKI.** OCSP stapling, CRL distribution-point
  automation, CT log submission and cross-signing automation are on the roadmap,
  not in the tree; `pkg/acme/ct` is present but the surrounding automation is
  not.
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
