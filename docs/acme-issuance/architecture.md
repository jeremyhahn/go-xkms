# ACME Issuance — Architecture

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-27

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
| Issuance | `pkg/acme/server/handlers.OrderFinalizeHandler` calls `s.ca` (`pkg/ca`) directly; `pkg/acme/issuance` is not on this path — see Data flow below |
| Storage | `pkg/acme/storage`, `pkg/acme/qrdb` (through `go-qrdb/sdk/go`) |
| Identifier policy, CAA | `pkg/acme/policy`, `pkg/acme/server/caa.go` — both wired, see Trust boundaries |
| Rate limits, circuit breaker, degradation | `pkg/acme/server/rate_limiter.go`, `tenant_rate_limiter.go`, `pkg/acme/server/{circuitbreaker,degradation}` — not wired into xkmsd; see Trust boundaries |
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
  service, `pkg/acme/nonce`.
- **Challenge validation happens server-side, out of band.** Nothing the client
  asserts about itself is trusted; the server fetches, resolves, or activates.
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
- **Rate limits are not enforced in xkmsd today.** `pkg/acme/server/rate_limiter.go`
  exists and is wired as request middleware in the standalone `TrustedCA`
  (`pkg/acme/client/trustedca.go:381-383`, per-client-ID only), but xkmsd's
  production ACME router (`buildACMERouter`, `cmd/xkmsd/acme.go:466-483`)
  never applies it — no rate-limit middleware is registered there. The tenant
  rate limiter (`pkg/acme/server/tenant_rate_limiter.go`) is unwired
  everywhere: nothing outside its own file constructs one. A production
  xkmsd ACME listener currently accepts orders at whatever rate a client
  sends them. Wiring is tracked in go-xkms#882.
- **The circuit breaker and degradation paths are unwired designs, not live
  enforcement.** Two independent circuit-breaker implementations exist
  (`pkg/acme/server/circuit_breaker.go` and the separate
  `pkg/acme/server/circuitbreaker` package) plus
  `pkg/acme/server/degradation`, but neither xkmsd (`cmd/xkmsd/acme.go`) nor
  the standalone `TrustedCA` (`pkg/acme/client/trustedca.go`) constructs or
  mounts either one; nothing outside their own packages and tests references
  them. Under load today the server issues (or rejects per the checks above)
  every order it receives — there is no admission-control layer in front of
  it. Wiring is tracked in go-xkms#820 (open, not on main); a separate
  circuit-breaker change, go-xkms#819, is in an open merge train and also
  not on `main` as of this writing.

## What this feature deliberately does not do

- **It does not run a public web PKI.** OCSP stapling, CRL distribution-point
  automation, CT log submission and cross-signing automation are on the roadmap,
  not in the tree; `pkg/acme/ct` is present but the surrounding automation is
  not — only `pkg/acme/issuance` (itself unwired, see above) references it.
  CT log submission is tracked with the standalone circuit breaker under
  go-xkms#820; SCT handling at issuance is go-xkms#745.
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
