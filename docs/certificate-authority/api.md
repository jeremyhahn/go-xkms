# Certificate Authority — API

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes are described once in
[`../key-management/api.md`](../key-management/api.md) §"How the six transports
are shaped".

Every `/api/v1/ca/*` route is registered only when a CA is configured — the
`hasCA` predicate in `pkg/api/rest/routes.go`. When none is, a single fallback
`GET /api/v1/ca/bundle` (`noCA`) is registered instead, so trust distribution
never disappears. All CA routes are `RouteAuthSession`: an authenticated
identity, no specific RBAC permission.

`GET /v1/ca/bootstrap` is the exception — `GroupRoot`, `RouteAuthPublic`,
unauthenticated by design.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`CAService.`) | Auth |
|---|---|---|---|---|---|---|
| CA bundle | `GET /api/v1/ca/bundle` | `GetCABundle` | same as REST | `xkms.ca.bundle` | `GetCABundle` | session |
| CA bundle (bootstrap) | `GET /v1/ca/bootstrap` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — | **public** |
| CA certificate | `GET /api/v1/ca/certificate` | `GetCACertificate` | same as REST | `xkms.ca.certificate` | `GetCACertificate` | session |
| Sign CSR | `POST /api/v1/ca/sign-csr` | `SignCSR` | same as REST | **MISSING — docs/13** | `SignCSR` | session |
| Issue certificate | `POST /api/v1/ca/issue` | `IssueCertificate` | same as REST | `xkms.ca.issue` | `IssueCertificate` | session |
| Revoke | `POST /api/v1/ca/revoke` | `RevokeCertificate` | same as REST | `xkms.ca.revoke` | `RevokeCertificate` | session |
| Generate CRL | `POST /api/v1/ca/crl` | `GenerateCRL` | same as REST | `xkms.ca.crl` | `GenerateCRL` | session |
| Revocation status | `GET /api/v1/ca/revoked/{serial}` | `IsRevoked` | same as REST | **MISSING — docs/13** | `IsRevoked` | session |

### TCG enrollment (`TCGCAService`)

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Issue EK certificate | `POST /api/v1/ca/tcg/ek` | `IssueEKCertificate` | same as REST | **MISSING — docs/13** | `IssueEKCertificate` | session |
| Issue AK certificate | `POST /api/v1/ca/tcg/ak` | `IssueAKCertificate` | same as REST | **MISSING — docs/13** | `IssueAKCertificate` | session |
| Sign TCG CSR | `POST /api/v1/ca/tcg/sign-csr` | `SignTCGCSR` | same as REST | **MISSING — docs/13** | `SignTCGCSR` | session |
| Enroll device | `POST /api/v1/ca/tcg/enroll` | `EnrollDevice` | same as REST | `xkms.ca.tcg.enroll` | `EnrollDevice` | session |

### Certificate storage (`CertService`)

Storage of a certificate against a keystore key — distinct from issuance.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Permission |
|---|---|---|---|---|---|---|
| Save certificate | `POST /api/v1/certs` | `SaveCert` | same as REST | `xkms.saveCert` | `SaveCertificate` | `certs:generate` |
| List certificates | `GET /api/v1/certs` | `ListCerts` | same as REST | `xkms.listCerts` | `ListCertificates` | `certs:list` |
| Get certificate | `GET /api/v1/certs/{id}` | `GetCert` | same as REST | `xkms.getCert` | `GetCertificate` | `certs:read` |
| Certificate exists | `HEAD /api/v1/certs/{id}` | `CertExists` | same as REST | `xkms.certExists` | `CertificateExists` | `certs:read` |
| Delete certificate | `DELETE /api/v1/certs/{id}` | `DeleteCert` | same as REST | `xkms.deleteCert` | `DeleteCertificate` | `certs:revoke` |
| Save chain | `POST /api/v1/certs/{id}/chain` | `SaveCertChain` | same as REST | `xkms.saveCertChain` | `SaveCertificateChain` | `certs:generate` |
| Get chain | `GET /api/v1/certs/{id}/chain` | `GetCertChain` | same as REST | `xkms.getCertChain` | `GetCertificateChain` | `certs:read` |
| TLS certificate | `GET /api/v1/tls/{id}` | `GetTLSCertificate` | same as REST | `xkms.getTLSCertificate` | `GetTLSCertificate` | `certs:read` |

## Missing coverage, recorded

MCP is the weak transport for this feature: it carries the bundle, certificate,
issue, revoke, CRL and TCG-enroll methods but not `SignCSR`, `IsRevoked`, or
three of the four TCG methods. Every gap above is written as a row rather than
omitted, per the convention, so it is tracked debt with an owner rather than an
invisible hole.

The public bootstrap route has no non-HTTP equivalent, which is defensible —
its whole purpose is to be reachable by a client that has nothing yet, and HTTP
is what such a client has. Recorded as a gap so the decision is visible rather
than assumed.

## Request and response schemas

Go types in `pkg/api/transport/types.go` (re-exported by `sdk/go/transport`),
protobuf in `pkg/api/grpc/proto/xkmsv1/xkms.proto`. Certificates are carried as
PEM; CRLs as PEM; serials as hex strings on the wire and `*big.Int` in Go.

`SignOptions` and `CertificateRequest` (`pkg/ca`) carry profile, validity, SANs
and algorithm. A request that omits validity gets `DefaultValidityPeriod()`;
one that omits algorithm gets `DefaultKeyAlgorithm()`.

## Status and error mapping

Standard mapping ([`../key-management/api.md`](../key-management/api.md));
CA-specific cases:

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| CA not configured | 501 | `Unimplemented` | error object |
| CA not initialized | 409 | `FailedPrecondition` | error object |
| CSR fails policy | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| serial not found | 404 | `NotFound` | error object |
| already revoked | 409 | `AlreadyExists` | error object |
| TCG CSR signature invalid | 400 | `InvalidArgument` | error object |
| attestation quote fails verification | 400 | `InvalidArgument` | error object |

Handlers: `pkg/api/rest/handlers_ca.go`, `handlers_ca_bundle.go`,
`handlers_ca_tcg.go`; `pkg/api/grpc/service_ca_bundle.go`;
`pkg/api/mcp/handlers_ca.go`, `handlers_ca_tcg.go`.

## Pagination

`ListCertificates` takes `ListOption` values and pages. `GenerateCRL` returns
the whole current CRL and is deliberately not paged — a partial CRL is a
security defect, not a convenience.

## Versioning and deprecation

CA routes are `/api/v1/ca/*`; the bootstrap route is `/v1/ca/bootstrap` — a
different prefix, deliberately, because it predates and outlives the
authenticated API's versioning. gRPC package `xkmsv1`. Nothing here is
deprecated.
