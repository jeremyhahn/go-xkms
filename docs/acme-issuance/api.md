# ACME Issuance — API

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-09

ACME is different from every other feature in this repo: **its wire format is
defined by RFC 8555, not by us.** The six-transport rule applies to go-xkms's
own control surfaces; the ACME protocol itself is HTTPS + JWS because that is
what the standard says and what every existing client speaks. The other
transports carry it as adapters, which is what `pkg/acme/api/adapter.go` and
`pkg/acme/api/{rest,grpc,quic,mcp}` are for.

## The RFC 8555 surface (REST / HTTPS)

Served under a configured base URI. The directory advertises the rest, so
clients only ever hard-code the directory URL.

| Object | Method + path | Auth |
|---|---|---|
| Directory | `GET /acme/directory` | public |
| New nonce | `HEAD /acme/new-nonce` (also `GET`) | public |
| New account | `POST /acme/new-account` | JWS, embedded JWK |
| Account | `POST /acme/account/{id}` | JWS, account key |
| Account orders | `POST /acme/account/{id}/orders` | JWS, account key |
| Key change | `POST /acme/key-change` | JWS, both keys |
| New order | `POST /acme/new-order` | JWS, account key |
| Order | `POST /acme/order/{id}` | JWS, account key |
| Finalize | `POST /acme/order/{id}/finalize` | JWS, account key |
| New authorization | `POST /acme/new-authz` | JWS, account key |
| Authorization | `POST /acme/authz/{id}` | JWS, account key |
| Challenge | `POST /acme/challenge/{id}` | JWS, account key |
| Certificate | `POST /acme/cert/{id}` | JWS, account key |
| Revoke certificate | `POST /acme/revoke-cert` | JWS, account or certificate key |
| CA bundle | `GET /acme/ca-bundle` | public |

The directory document is built in
`pkg/acme/server/handlers/directory.go` from the configured `baseRESTURI`. When
ACME is mounted inside the unified API server, the externally visible directory
URL is `https://<host>:<rest_port>/api/v1/acme/directory` — that is the form the
cluster enrollment config uses (`pkg/config/config.go:710`). Setting
`baseRESTURI` wrong yields doubled prefixes such as
`https://host/api/v1/api/v1/acme/new-account`; the code comments this at
`pkg/acme/server/handlers/service.go:581`. The standalone `TrustedCA` takes
`baseRESTURI` from `acme.external_url`, and derives it from the listen address
when that is empty (`acmeclient.AdvertisedURL`): a wildcard bind advertises
`https://localhost:<port>`, a named bind advertises its name.

`POST-as-GET` is used throughout, per RFC 8555 §6.3: reads are POSTs with an
empty payload, signed by the account key. There are no unauthenticated reads of
account-scoped objects.

## Challenge types

| `type` | Validation the server performs | Source |
|---|---|---|
| `http-01` | fetches `http://<identifier>/.well-known/acme-challenge/<token>` | `pkg/acme/challenges/http-01` |
| `dns-01` | resolves `_acme-challenge.<identifier>` TXT | `pkg/acme/challenges/dns-01` |
| `device-attest-01` | verifies an attestation object over the key | `pkg/acme/challenges/device-attest-01` |
| `enroll-01` | `TPM2_MakeCredential` / `ActivateCredential` against a verified EK, from a TCG-CSR-IDEVID | `pkg/acme/challenges/enroll-01` |
| `endorse-01` | endorsement by an existing trusted party, with EAB | `pkg/acme/challenges/endorse-01`, `handlers/endorse_eab.go` |

`enroll-01` and `endorse-01` are go-xkms extensions. A standard client never
selects them and is unaffected by their presence.

## Transport adapters

| Transport | What it carries | Package |
|---|---|---|
| **rest** | the full RFC 8555 surface above | `pkg/acme/api/rest` |
| **quic** | the same surface over HTTP/3; `DefaultQUICPort = 9444` (`pkg/acme/api/server/server.go:49`) | `pkg/acme/api/quic` |
| **grpc** | adapter surface | `pkg/acme/api/grpc` |
| **mcp** | adapter surface | `pkg/acme/api/mcp` |
| **unix** | **MISSING — docs/13** | — |
| **embedded** | `pkg/acme/client` in-process; first-node issuance goes straight to `TrustedCA` without ACME at all | `pkg/acme/client` |

OpenAPI/Swagger definitions live in `pkg/acme/api/swagger`.

**Recorded gap:** there is no Unix-socket adapter for ACME. This is a defensible
absence — ACME is a network enrollment protocol and a local socket has no
identifiers to validate — but it is written as a gap rather than omitted so the
decision is visible.

## The xkms control-plane view of ACME

Separately from the RFC surface, the ACME server's **administration** is
reachable through `pkg/acme/admin` (accounts, policy, barrier). That plane is
not RFC 8555 and is not documented as if it were; it follows the repo's normal
authenticated-API conventions.

## Response schemas

RFC 8555 defines every protocol object; the Go types are `pkg/acme/entities`.
Errors are RFC 7807 problem documents with `urn:ietf:params:acme:error:*` types
— the mapping table is in [`engineering.md`](engineering.md) §Error semantics.

## Status codes

| Situation | Status |
|---|---|
| object returned | 200 |
| object created (account, order) | 201 |
| nonce issued (`HEAD /acme/new-nonce`) | 200 with `Replay-Nonce` |
| order still processing | 200 with `Retry-After` |
| problem document | 4xx/5xx per the error table |
| rate limited | 429 with `Retry-After` |

Every response carries a fresh `Replay-Nonce` header — a client that does not
read it will fail its next POST with `badNonce`.

## Pagination

`POST /acme/account/{id}/orders` returns an orders list with RFC 8555 `Link:
rel="next"` pagination. No ACME collection is returned unbounded.

## Versioning and deprecation

RFC 8555 has no protocol version negotiation; the directory *is* the version
contract. Adding a challenge type is additive and safe — clients select only
what they understand. Removing one is breaking.

The go-xkms extensions (`enroll-01`, `endorse-01`) are advertised in the
directory's metadata alongside the standard types and are ignored by
standard clients.
