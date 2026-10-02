# Init Ceremony — API

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-02 (#1226)

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Init routes are registered under `/api/v1/init` with `RouteAuthSession`, gated
on the `hasInit` predicate — when no ceremony is configured they are not
registered at all.

There is a second, deliberate wrinkle: `pkg/api/rest/middleware_init_public.go`
and `pkg/api/initgate` exist because parts of the init surface must answer
**before** normal authentication is possible. A ceremony's whole purpose is to
create the first credentials, so it cannot require one. `initgate` is what
bounds that exception, and `pkg/api/{grpc,unix}/initgate_guard_test.go` is what
keeps it bounded.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`InitCeremonyService.`) | Auth |
|---|---|---|---|---|---|---|
| Ceremony status | `GET /api/v1/init/status` | **MISSING — docs/13** | same as REST | `init.getStatus` | `GetInitStatus` | session |
| Claim cert — begin | `POST /api/v1/init/claim-cert/begin` | **MISSING — docs/13** | same as REST | `init.claimCertBegin` | `ClaimCertBegin` | session |
| Claim cert — complete | `POST /api/v1/init/claim-cert/complete` | **MISSING — docs/13** | same as REST | `init.claimCertComplete` | `ClaimCertComplete` | session |
| Claim share — begin | `POST /api/v1/init/claim-share/begin` | **MISSING — docs/13** | same as REST | `init.claimShareBegin` | `ClaimShareBegin` | session |
| Claim share — complete | `POST /api/v1/init/claim-share/complete` | **MISSING — docs/13** | same as REST | `init.claimShareComplete` | `ClaimShareComplete` | session |
| Officer status | `GET /api/v1/init/officer/status` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — | session |
| Sign CSR (init) | via the CA surface | **MISSING — docs/13** | via the CA surface | `init.signCSR` | `SignCSRInit` | session |

**The init ceremony has no gRPC or Unix surface at all.** Six rows of
`MISSING`. The client that needs these is a remote officer with a pinned
connection and no credentials, and HTTP is what such a client reliably has — the
same argument that justifies the public bootstrap route. But this is a tier-2
capability with a full REST, QUIC and MCP surface and nothing on two of the six
transports, so it is recorded as tracked debt rather than left implicit.

## Credential management

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded (`CredentialManagementService.`) | Auth |
|---|---|---|---|---|---|---|
| Submit credential | `POST /api/v1/credentials/submit` | **MISSING — docs/13** | same as REST | `credentials.submit` | `SubmitCredential` | `credentials:submit` |
| Credential strategy | `GET /api/v1/credentials/strategy` | **MISSING — docs/13** | same as REST | `credentials.strategy` | `GetCredentialStrategy` | `credentials:strategy` |
| List credentials | `GET /api/v1/credentials/` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `ListCredentials` | session |

Submit and strategy demand the `credentials:*` pair the MCP methods are gated
with; neither is on the pre-operational `initgate` allowlist, so the gate never
blocks an account-less officer. Admin and Owner hold both by default. Listing
credentials has no counterpart on any other transport, so it has no canonical
permission to adopt and stays session-authenticated.

**Submit and list are platform-scoped** (go-xkms#1226). Submitted credentials
are the platform's backend credentials, sealed into the platform store under
`credentials/<name>`, so `XKMSService.SubmitCredential` and `ListCredentials`
refuse every tenant-scoped caller -- a tenant-local Admin included -- before
the credential service is touched (`pkg/xkms/servicer_credentials.go:32,73`).
The REST handlers reach the credential service only through those methods
(`pkg/api/rest/handlers_credentials.go`). The refusal reads as a missing
tenant: REST `404` (`pkg/api/rest/handlers_credentials.go:90`), MCP
`JSONRPCCodeNotFound` (`pkg/api/mcp/handlers_init_credentials.go:124`).
`GetCredentialStrategy` is not scoped: it reports the strategy name and
whether auto-unseal is available, nothing tenant-sensitive.

The ceremony status and claim routes above stay `RouteAuthSession` rather than
carrying MCP's `ceremony:*` pairs: the REST permission decorator has no
pre-operational exemption, so gating them would refuse the credential-less
officer that `initgate` exists for.

## The two-phase claim protocol

Both claims are begin/complete, and the split is load-bearing:

```
POST /api/v1/init/claim-cert/begin
  request:  username
  response: a server-generated challenge
            ← the server has now bound this challenge to this claim

POST /api/v1/init/claim-cert/complete
  request:  the challenge response, signed by the officer's private key
  response: ClaimCertResult — the issued certificate and the CA bundle
```

Nothing is released until the officer proves possession of the key matching the
CSR that was submitted. A single-phase claim would hand a certificate to whoever
knew a username.

`claim-share` is the same shape, authenticated with the certificate obtained
from `claim-cert`.

## The client verifies by SPKI pin, not by bundle

An officer claiming a credential has no CA bundle — that is what
`claim-cert` returns. The connection is therefore verified by a pre-shared SPKI
pin, which is why `--spki-pin` is a required flag on both claim verbs. See
[`../trust-bootstrap/api.md`](../trust-bootstrap/api.md).

## Request and response schemas

Go types in `pkg/api/transport/types_init.go`, mirroring go-qrdb's ceremony
types (aliased in `pkg/init/ceremony.go`): `ClaimCertBeginRequest`/`Response`,
`ClaimCertCompleteRequest`/`Response`, `ClaimShareBeginRequest`/`Response`,
`ClaimShareCompleteRequest`/`Response`, `InitStatusResponse`,
`SignCSRInitRequest`/`Response`.

**A share appears in exactly one response — `claim-share/complete` — and is
never retrievable again.** There is no endpoint that returns an already-claimed
share, and there must not be.

The SO/bootstrap certificate the CA issues carries `tenant=system` and, when a
SPIFFE trust domain is configured, a `spiffe://<td>/tenant/system/user/<CN>`
SAN. A certificate signed from a CSR (officer claim, `SignCSRInit`) is
`CN=<username>, OU=system, OU=<role>` with no SAN: the CSR's subject and names
are never copied, only its key.

## Status and error mapping

| Condition | REST | MCP |
|---|---|---|
| success | 200 | `result` |
| ceremony not configured | route absent (404) | error object |
| ceremony in the wrong state | 409 | error object |
| credential already claimed | 409 | error object |
| challenge response invalid / key mismatch | 401 | error object |
| unparseable CSR | 400 | JSON-RPC `-32602` |
| Shamir split failed | 500 | error object |
| random source failed | 500 | error object |

`RandomSourceError` and `ShamirSplitError` are 500s that mean **abort the
ceremony**, not retry: a ceremony that continued past bad randomness would
produce material nobody can trust.

## Pagination

Not applicable — officer and credential lists are bounded by the ceremony's own
configuration.

## Versioning and deprecation

`/api/v1/init/*` and `/api/v1/credentials/*`; gRPC package `xkmsv1` (which does
not carry this feature). Nothing deprecated.

The stable contract for external tooling is the two-phase claim shape and the
SPKI-pin requirement; both are relied on by every officer workflow.
