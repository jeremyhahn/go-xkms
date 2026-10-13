# Certificate Authority — API

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-10-12

Transport shapes are described once in
[`../key-management/api.md`](../key-management/api.md) §"How the six transports
are shaped".

Every `/api/v1/ca/*` route is registered only when a CA is configured — the
`hasCA` predicate in `pkg/api/rest/routes.go`. When none is, a single fallback
`GET /api/v1/ca/bundle` (`noCA`) is registered instead, so trust distribution
never disappears. Every CA route with a gRPC counterpart is
`RouteAuthPermission` and demands the `certs:*` pair gRPC and MCP enforce for
the same operation (the **Auth / permission** column); both variants of
`GET /api/v1/ca/bundle` carry `certs:read`. Admin and Owner hold every one of
them by default. `GET /api/v1/ca/crl` is the one CA route still served to any
authenticated session (`RouteAuthSession`): it has no counterpart on any other
transport (#275), so there is no canonical permission for it to adopt yet.

`GET /v1/ca/bootstrap` is the exception — `GroupRoot`, `RouteAuthPublic`,
unauthenticated by design.

The gRPC/Unix column below reflects the wiring fixed in go-xkms#951: the
CA servicer these RPCs delegate to is per-`Service` state
(`(*Service).SetCA`/`SetCABundler`, `pkg/api/grpc/service_ca.go`), set by
each composition root (`pkg/server`'s Unix listener, `pkg/apimodule`'s
unified-server module) the same way `pkg/api/rest`'s `Config.CA` is. See
[engineering.md](engineering.md#grpcunix-ca-wiring-is-per-service-not-a-package-global-go-xkms951).

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded (`CAService.`) | Auth / permission |
|---|---|---|---|---|---|---|
| CA bundle | `GET /api/v1/ca/bundle` | `GetCABundle` | same as REST | `xkms.ca.bundle` | `GetCABundle` | `certs:read` |
| CA bundle (bootstrap) | `GET /v1/ca/bootstrap` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — | **public** |
| CA certificate | `GET /api/v1/ca/certificate` | `GetCACertificate` | same as REST | `xkms.ca.certificate` | `GetCACertificate` | `certs:read` |
| Sign CSR | `POST /api/v1/ca/sign-csr` | `SignCSR` | same as REST | **MISSING — docs/13** | `SignCSR` | `certs:generate` |
| Issue certificate | `POST /api/v1/ca/issue` | `IssueCertificate` | same as REST | `xkms.ca.issue` | `IssueCertificate` | `certs:generate` |
| Revoke | `POST /api/v1/ca/revoke` | `RevokeCertificate` | same as REST | `xkms.ca.revoke` | `RevokeCertificate` | `certs:revoke` |
| Generate CRL (force-regenerate) | `POST /api/v1/ca/crl` | `GenerateCRL` | same as REST | `xkms.ca.crl` | `GenerateCRL` | `certs:read` |
| Get CRL (read, regenerates only if stale/missing) | `GET /api/v1/ca/crl` | **MISSING — #275** | **MISSING — #275** | **MISSING — #275** | **MISSING — #275** | session |
| Revocation status | `GET /api/v1/ca/revoked/{serial}` | `IsRevoked` | same as REST | **MISSING — docs/13** | `IsRevoked` | `certs:read` |

The `reason` field takes an RFC 5280 CRLReason code. Embedded Go callers name
them with the `sdk/go` constants `CARevocationReason…` (for example
`CARevocationReasonSuperseded` = 4).

### Revoke is confined to the certificate's issuing tenant (go-xkms#1229)

`certs:revoke` — the same permission on REST, gRPC, MCP and the embedded
transport — is necessary but not sufficient: it says a caller's role may
revoke *some* certificate, not *which one*. `XKMSService.RevokeCertificate`
(`pkg/xkms/servicer_ca.go`) makes that second decision by reading the
certificate's issuing tenant back with `CertificateTenant` (`pkg/ca`,
recorded at issuance by `signCSR` into `cert-tenant/<serial>.json`) and
running it through the same tenant-binding check (`bindTenantTarget`) every
other tenant-scoped operation in this service uses:

- A tenant-scoped caller may revoke only a certificate whose recorded
  issuing tenant is its own; a foreign tenant's certificate answers exactly
  like an unknown serial (`*TenantBindingError`, the same not-found shape
  `docs/tenancy` documents elsewhere in this service).
- A system-tenant caller is bound the same way (go-xkms#1406): it may revoke
  only a certificate recorded for the system/platform scope (`""`) — the
  server's own certificates and certificates issued through a path that
  records no tenant at all (TCG EK/AK/IDevID, the CA's own
  root/intermediate chain). A tenant's certificate answers it exactly like
  an unknown serial.
- `IssueCertificate` binds `req.TenantID` against the caller's own tenant
  before forwarding it to `IssueCertificateRaw`, exactly as `SignCSR`
  already did for `SignCSRWithSPIFFE`'s tenant, so a tenant-scoped caller
  cannot mint a certificate attributed to a different tenant either.

Both built-in roles that carry `certs:revoke` by default — go-qrdb's Admin
role, seeded into every tenant including the system tenant — get the
permission from go-qrdb's own registry (`registerAdminGrants`,
`pkg/permission/builtin_role_grants.go` in go-qrdb); xkms registers no
grant of its own for it.

### TCG enrollment (`TCGCAService`)

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth / permission |
|---|---|---|---|---|---|---|
| Issue EK certificate | `POST /api/v1/ca/tcg/ek` | `IssueEKCertificate` | same as REST | **MISSING — docs/13** | `IssueEKCertificate` | `certs:generate` |
| Issue AK certificate | `POST /api/v1/ca/tcg/ak` | `IssueAKCertificate` | same as REST | **MISSING — docs/13** | `IssueAKCertificate` | `certs:generate` |
| Sign TCG CSR | `POST /api/v1/ca/tcg/sign-csr` | `SignTCGCSR` | same as REST | **MISSING — docs/13** | `SignTCGCSR` | `certs:generate` |
| Enroll device | `POST /api/v1/ca/tcg/enroll` | `EnrollDevice` | same as REST | `xkms.ca.tcg.enroll` | `EnrollDevice` | `certs:generate` |
| Issue LAK certificate (go-xkms#715) | **MISSING** | **MISSING** | **MISSING** | **MISSING** | **MISSING** | `certs:generate` (planned) |

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

#### Certificate storage is tenant-scoped (go-xkms#1228)

Every transport is a thin adapter over the `XKMSService` certificate methods
(`pkg/xkms/servicer_cert.go:29-284`): REST `SaveCertHandler` through
`GetTLSCertificateHandler` (`pkg/api/rest/handlers.go:772-1003`), gRPC
`SaveCert` through `GetTLSCertificate` (`pkg/api/grpc/service.go:751-962`), and
MCP `handleSaveCert` through `handleGetTLSCertificate`
(`pkg/api/mcp/handlers.go:766-958`). The service resolves the backend through
the caller's tenant (`resolveTenantBackend`,
`pkg/xkms/servicer_helpers.go:98`), which stores a tenant's certificates under
`{tenant}/{keyID}` (`scopeCertKeyID`, `pkg/xkms/backend_tenant.go:58`). Save
and SaveChain take the tenant from the request's `TenantID`, which each
transport fills from the authenticated identity; the other methods read it
from the identity on the context (`scopedTenantIDFromContext`,
`pkg/xkms/servicer_password.go:93`).

- A tenant reads, writes, lists and deletes only its own certificates. The
  platform's certificates (stored unprefixed) and another tenant's are exactly
  as absent as a certificate nobody stored: the same status and the same
  body. A save under an ID another owner uses lands in the caller's own
  namespace and leaves the other certificate untouched.
- A key ID is validated before use, and validation refuses `/`
  (`simpleKeyIDPattern`, `pkg/validation/validation.go:48`), so `tenant-b/web`
  is a malformed ID (`400` / `InvalidArgument` / Invalid params), never a path
  into tenant B's namespace.
- `ListCerts` returns the caller's certificates under the IDs it used, sorted,
  and pages them in the service (`pkg/xkms/servicer_cert.go:156`).
- A platform-scoped caller (no identity, or the system tenant) operates on
  the unscoped store and sees every entry, including `tenant/id` ones.
- `GetTLSCertificate` reads the leaf and the chain from the caller's
  namespace. It no longer loads the private key to build a bundle that never
  carries it, and `chain_pem` omits the leaf when the stored chain opens with
  it (`pkg/xkms/servicer_cert.go:284`).

Wire changes: REST `ListCerts` fills `subject`, `issuer`, `not_before`,
`not_after`, `serial_number` and `certificate_pem`; a missing certificate is
`404` / `NotFound` / Not found on every transport, and a malformed PEM is
`400` / `InvalidArgument` / Invalid params with the service's message
(`keystore: invalid PEM encoding`, `keystore: invalid certificate: ...`).
gRPC's certificate RPCs use the default backend rather than whichever
backend the registry listed first, and report `Unavailable` when no service is
wired. Verified by `pkg/api/rest/handlers_certseal_crosstenant_test.go`,
`pkg/api/grpc/service_certseal_crosstenant_test.go`,
`pkg/api/mcp/handlers_certseal_crosstenant_test.go` and
`pkg/xkms/servicer_certseal_tenant_test.go`.

## SPIFFE identities

`pkg/spiffe` has no network surface. It is reachable in process through
`sdk/go/spiffe`: `TrustDomain`, `WorkloadID`, `InvalidIDError`, `ID`,
`ParseTrustDomain`, `ParseWorkloadID`, `WorkloadIDFromURL`, `ValidatePath`,
`ValidatePathPrefix`, `BuildURI`, `ParseID`, `TenantFromURIs`, `KindUser`,
`KindService`, and every `Err*` sentinel of the package.

## Missing coverage, recorded

MCP is the weak transport for this feature: it carries the bundle, certificate,
issue, revoke, CRL and TCG-enroll methods but not `SignCSR`, `IsRevoked`, or
three of the four TCG methods. Every gap above is written as a row rather than
omitted, per the convention, so it is tracked debt with an owner rather than an
invisible hole.

**`IssueLAKCertificate` has no transport wiring yet (go-xkms#715).**
`ca.TCGCA.IssueLAKCertificate` (`pkg/ca/tcg_lak.go`) and the device-side
`pkg/tpm2.(*TPM2).CreateLAK`/`CertifyLAK`/`CertifyKeyWithLAK` primitives are
implemented and tested (`pkg/ca/tcg_lak_test.go`,
`pkg/tpm2/local_attestation_key_simulator_test.go`), and xkey's TPM-backed
WebAuthn/FIDO2 authenticator already attests with the LAK
(`xkey/pkg/authenticator/keybackend/tpm_attestation.go`). No REST, gRPC/Unix,
QUIC, MCP or embedded verb submits `LAKCertificationEvidence` to a running
`xkmsd` yet; a device today reaches `IssueLAKCertificate` only by embedding
the CA in-process. Recorded as a gap rather than a row with a made-up
endpoint.

**Get CRL is REST-only (#275).** `CA.CRL(ctx)` — the read that only
regenerates when the persisted artifact is missing or stale — is reachable
today solely through `GET /api/v1/ca/crl`. gRPC, the Unix socket transport,
QUIC, MCP, and the embedded transport carry only the force-regenerate verb
(`GenerateCRL`); none of them gained a new verb for the replicated read.
Since `CA.CRL` and `CA.GenerateCRL` differ only in *when* they sign — never
in the shape of what they return — a client on any of those transports gets
an equivalent artifact by calling the existing generate verb; it simply pays
for a signing operation on every call instead of only when necessary.

The public bootstrap route has no non-HTTP equivalent, which is defensible —
its whole purpose is to be reachable by a client that has nothing yet, and HTTP
is what such a client has. Recorded as a gap so the decision is visible rather
than assumed.

### Caller-named profiles are in-process only

`ipsec-vtep` and `x509-svid` take their names from the issuing caller
(`SignOptions.SANS`). The wire `SignCSR` request on every transport carries a
profile name but no caller names. Over the wire, these profiles are therefore
refused, with `ErrCallerSANsRequired`, or with `ErrTenantSPIFFEWithCallerSANs`
when the server stamps a tenant SPIFFE identity. They are never issued from
the CSR's names. They are reached in-process, through the SDK's `TrustedCA`:

- `sdk/go` `ProfileNameIPsecVTEP` and `ProfileNameX509SVID`;
- `SubordinateIssuer.IssueSubordinateCA`;
- `TrustedCASignOptions.SANS` and `TrustedCASignOptions.Validity`;
- `CreateAttestationEvidenceExtension`.

### Key binding is in-process only

The `code-signing` profile is issuable on every transport: its CSR checks
(`ErrSubjectNotCommonNameOnly`, `ErrSubjectAltNameNotPermitted`,
`ErrCARequestNotPermitted`, `ErrKeyUsageNotPermitted`,
`ErrExtKeyUsageNotPermitted`) run on the CSR alone. Binding the certificate to
a keystore key (`TrustedCASignOptions.BoundKey`, refused with
`ErrCABoundKeyNotFound` or `ErrCABoundKeyMismatch`) has no wire field and is
reached through the SDK's `TrustedCA` only. See
[engineering.md](engineering.md#built-in-profiles).

## Request and response schemas

Go types in `pkg/api/transport/types.go` (re-exported by `sdk/go/transport`),
protobuf in `pkg/api/grpc/proto/xkmsv1/xkms.proto`. Certificates are carried as
PEM; CRLs as PEM (`POST /api/v1/ca/crl`'s JSON response) or raw DER with
`Content-Type: application/pkix-crl` (`GET /api/v1/ca/crl`'s body — no JSON
envelope, since the payload *is* the CRL); serials as hex strings on the wire
and `*big.Int` in Go.

`SignOptions` and `CertificateRequest` (`pkg/ca`) carry profile, validity, SANs
and algorithm. A request that omits validity gets `DefaultValidityPeriod()`;
one that omits algorithm gets `DefaultKeyAlgorithm()`.

## Status and error mapping

Standard mapping ([`../key-management/api.md`](../key-management/api.md));
CA-specific cases:

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| caller lacks the route's `certs:*` permission | 403 | `PermissionDenied` | error object |
| CA not configured | 501 (route not registered — `hasCA`, `pkg/api/rest/routes.go`) | `Unavailable` (`ErrCANotConfigured`, `pkg/api/grpc/service_ca.go`) | error object |
| CA not initialized | 409 | `FailedPrecondition` | error object |
| CSR fails policy | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| serial not found | 404 | `NotFound` | error object |
| already revoked | 409 | `AlreadyExists` | error object |
| `GET /api/v1/ca/crl`, no CA configured | 404 (route not registered — the `hasCA` predicate) | n/a — not exposed on this transport | n/a — not exposed on this transport |
| `GET /api/v1/ca/crl`, `ca.ErrCRLNotFound` mapped | 404 | n/a — not exposed on this transport | n/a — not exposed on this transport |
| TCG CSR signature invalid | 400 | `InvalidArgument` | error object |
| attestation quote fails verification | 400 | `InvalidArgument` | error object |

Handlers: `pkg/api/rest/handlers_ca.go`, `handlers_ca_bundle.go`,
`handlers_ca_tcg.go`; `pkg/api/grpc/service_ca_bundle.go`;
`pkg/api/mcp/handlers_ca.go`, `handlers_ca_tcg.go`.

`GET /api/v1/ca/crl` self-heals a missing artifact rather than reporting it
missing: `CA.CRL` regenerates and persists a CRL the first time it is called
for an issuer that has never published one, so `ca.ErrCRLNotFound` reaching
the transport layer (and the 404 mapping above) requires a CA configured
with no issuing certificate at all — a misconfiguration the not-initialized
and not-configured cases above already cover in practice. The mapping exists
for completeness and for any future caller that reads the persisted artifact
directly rather than through `CA.CRL`.

## Pagination

`ListCertificates` (`GET /api/v1/certs`) takes `ListOption` values and pages
through the same shared `transport.PageRequestFromQuery` implementation
every REST list endpoint uses; see
[`../key-management/api.md`](../key-management/api.md) §"Pagination" for the
`page` / `page_size` / `sort_field` / `sort_order` query parameters and the
**400** an invalid one gets. With no `page` parameter every matching
certificate is returned. `GenerateCRL` and `CA.CRL` both return the whole
current CRL and are deliberately not paged — a partial CRL is a security
defect, not a convenience.

## Versioning and deprecation

CA routes are `/api/v1/ca/*`; the bootstrap route is `/v1/ca/bootstrap` — a
different prefix, deliberately, because it predates and outlives the
authenticated API's versioning. gRPC package `xkmsv1`. Nothing here is
deprecated.
