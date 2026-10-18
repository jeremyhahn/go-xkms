# ACME Issuance — API

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-10-15

ACME is different from every other feature in this repo: **its wire format is
defined by RFC 8555, not by us.** The six-transport rule applies to go-xkms's
own control surfaces; the ACME protocol itself is HTTPS + JWS because that is
what the standard says and what every existing client speaks. Only the ACME
**admin** plane has other transports (see
[Transport adapters](#transport-adapters)).

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
| Health | `GET /acme/health` | public |

`GET /acme/health` (non-RFC 8555) reports datastore readiness, circuit
breaker and graceful-degradation status.

- `checks` — the readiness checks run through the go-qrdb SDK health
  checker. xkmsd registers one, named `datastore`, for the datastore ACME
  state persists in. Each entry carries `name`, `status` (`healthy`,
  `unhealthy`, `degraded`), `message`, `latency` and, on failure, `error`.

The response then has two breaker sections:

- `breakers` — every *named* breaker registered on the server's
  `circuitbreaker.Manager` (`storage`, `kms`, `ct_submitter` when wired),
  keyed by name, each with state and failure/success counts. This is a
  small, fixed, operator-configured set.
- `target_groups` — a bounded summary per per-target breaker group
  (`http01`, `dns01`: one breaker per validation target, see
  go-xkms#1189/#1190), keyed by group name: `capacity`, `tracked`, `closed`,
  `half_open`, `open`, and `top_open` (at most 10 currently open target
  names). This never grows with the number of distinct validation targets a
  group has tracked, unlike `breakers`.

`healthy` (and the 200/503 status) reflects only `checks` and `breakers`: an
unhealthy datastore check or an open named breaker answers 503. An open
per-target breaker in `target_groups` means one validation target is
failing, which is expected, isolated behavior, not evidence the server
itself is unhealthy. `degradation` additionally reports whether `GET
/acme/directory`/`GET /acme/ca-bundle` are currently serving cached
responses because CA-bundle storage access is unavailable. See
[`../acme-issuance/engineering.md`](engineering.md)#circuit-breakers-and-degradation
for what each breaker and group guards. A degraded `GET /acme/directory` or
`GET /acme/ca-bundle` response carries `Warning: 110 - "Response is stale"`.

The directory document is built in
`pkg/acme/server/handlers/directory.go` from the configured `baseRESTURI`. When
ACME is mounted inside the unified API server, the externally visible directory
URL is `https://<host>:<rest_port>/api/v1/acme/directory` — that is the form the
cluster enrollment config uses (`pkg/config/config.go:711`). Setting
`baseRESTURI` wrong yields doubled prefixes such as
`https://host/api/v1/api/v1/acme/new-account`; the code comments this at
`pkg/acme/server/handlers/service.go:581`. The standalone `TrustedCA` takes
`baseRESTURI` from `acme.external_url`, and derives it from the listen address
when that is empty (`acmeclient.AdvertisedURL`): a wildcard bind advertises
`https://localhost:<port>`, a named bind advertises its name.

### JWS algorithms

Every signed request must use one of `AllowedJOSEAlgorithms`
(`pkg/acme/server/types.go:25-36`): `RS256`, `RS384`, `RS512`, `PS256`,
`PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA`. Anything else fails to
parse. The list is enforced on every signed request
(`pkg/acme/server/handlers/service.go:1139`), on the key-change inner JWS
(`key_change.go:100`) and on tenant-scoped requests (`tenant_auth.go:70`).

`POST-as-GET` is used throughout, per RFC 8555 §6.3: reads are POSTs with an
empty payload, signed by the account key. There are no unauthenticated reads of
account-scoped objects.

## Challenge types

| `type` | Validation the server performs | Source |
|---|---|---|
| `http-01` | fetches `http://<identifier>/.well-known/acme-challenge/<token>` | `pkg/acme/challenges/http-01` |
| `dns-01` | resolves `_acme-challenge.<identifier>` TXT | `pkg/acme/challenges/dns-01` |
| `device-attest-01` | verifies the attestation object the client POSTs to the challenge URL (`{"attObj": base64url(CBOR)}`); contacts nothing | `pkg/acme/challenges/device-attest-01` |
| `enroll-01` | `TPM2_MakeCredential` / `ActivateCredential` against a verified EK, from a TCG-CSR-IDEVID | `pkg/acme/challenges/enroll-01` |
| `endorse-01` | endorsement by an existing trusted party, with EAB | `pkg/acme/challenges/endorse-01`, `handlers/endorse_eab.go` |

`enroll-01` and `endorse-01` are go-xkms extensions. A standard client never
selects them and is unaffected by their presence.

The server contacts `http-01` and `enroll-01` targets (and `endorse-01`'s)
only at a bare hostname or IP that does not resolve to a reserved address
(loopback, private, link-local, metadata), unless the operator set
`acme.challenges.allow_private_targets`. A failed challenge's `error` is a
fixed category -- `connection` with `detail` `"Challenge validation failed:
connection failed"`, `"... unexpected HTTP status"`, `"... response too
large"` or `"... redirect not permitted"`, or `incorrectResponse` with
`"Challenge validation failed"` / `"... invalid validation target"` -- never
the server's dial error, resolved address or the target's status code
(go-xkms#1172).

### endorse-01 finalize

An endorse-01 order's finalize CSR MUST carry the TPM's TCG manufacturer code
as tcg-at-tpmManufacturer (2.23.133.2.1) in a subjectAltName directoryName, in
the form `id:` and eight uppercase hexadecimal digits — the TPM's
`TPM_PT_MANUFACTURER` value. The CA records it in the issued EK certificate,
because a later `enroll-01` names the TPM by it (TCG DevID v1 r12 §8.1) and a
TPM that needs endorse-01 has no manufacturer EK certificate to supply it.
`acmeclient.RequestEndorsementKeyCertificate` reads it through
`TPMModule.TPMManufacturer` and fails before opening an order when the TPM
cannot report it.

| Condition | Problem |
|---|---|
| no manufacturer code in the CSR, or one not in the `id:XXXXXXXX` form | `badCSR` (400) |
| the account's external account binding names a different `deviceInfo.tpmManufacturer` | `unauthorized` (401) |
| the account names a binding that does not exist or belongs to another account | `unauthorized` (401) |

Each is refused before the order moves to `processing`, so the order stays
`ready` and a corrected request can finalize it.

The code is the device's own assertion, carrying the same assurance as the EK
public key the order asserts. An operator who registers the device through an
EAB with `deviceInfo.tpmManufacturer` bounds it: the device may assert only
that code, whether or not EAB is required for endorse-01.

endorse-01 itself proves nothing about the key, so the External Account Binding
is its only control:

| Condition | Problem |
|---|---|
| the account has no EAB of purpose `endorse-01` (EAB is required unless `acme.endorse_eab_required: false`) | `unauthorized` (401) at the challenge |
| the EAB names no EK (`deviceInfo.ekPublicKeyHash`, or the `endorse_device_id_meta_key` metadata) | `unauthorized` (401) at the challenge |
| the order's EK is not the one the EAB names | `unauthorized` (401) at the challenge |
| the order was validated by any attestation challenge but endorse-01 | `badCSR` (400) at finalize |

An endorse-01 authorization finalizes only as an EK certificate: a TCG-CSR-IDEVID
for such an order is `badCSR` (400). A TCG-CSR-IDEVID is likewise refused unless
enroll-01 validated the order and the CSR's endorsement key and IAK are the ones
that passed credential activation.

The EK certificate endorse-01 issues uses the `tcg-ek` profile: extended key
usage tcg-kp-EKCertificate (2.23.133.8.1) (`pkg/ca/profiles.go:510,590`), and
the TPM's permanent identifier as an otherName in the subjectAltName
(`pkg/ca/tcg.go:140`).

### enroll-01 finalize

An enroll-01 order finalized with a TCG-CSR-IDEVID is signed by
`SignTCGCSRIDevID`, which issues two certificates
(`pkg/acme/server/handlers/order_finalize.go:1576-1604`). The certificate the
order then serves is one PEM bundle, in this order:

1. the IAK certificate, Common Name `ca.IAKCommonName` (`iak-` prefix,
   `pkg/ca/tcg.go:284,297`);
2. the IDevID certificate, Common Name `<model>-<serial>` from the CSR's
   `ProdModel` and `ProdSerial` (`order_finalize.go:1448`);
3. the issuing chain (`appendIssuingChain`).

The parsed enrollment data goes to any `OrderFinalizeHooks` as
`TCGEnrollmentData`.

### device-attest-01 / permanent-identifier finalize

A `permanent-identifier` order finalized with a standard x509 CSR (rather
than a TCG-CSR-IDEVID) — `device-attest-01`, or `enroll-01` when the client
sends a standard CSR instead of a TCG-CSR-IDEVID — is matched against the
CSR's RFC 4043 `permanentIdentifier` otherName (OID `1.3.6.1.5.5.7.8.3`)
inside its `subjectAltName` extension. The Common Name is never consulted for
this identifier.

| Condition | Problem |
|---|---|
| the CSR has no `permanentIdentifier` otherName | `badCSR` (400) |
| the CSR carries more than one `permanentIdentifier` otherName, or an otherName of any other type | `badCSR` (400) |
| the otherName's value does not equal an identifier the order authorizes | `badCSR` (400) |
| the CSR carries a DNS or IP SAN, or an email/URI SAN | `badCSR` (400) / `malformed` (400) unless that exact name is one of the order's authorized `dns`/`ip` identifiers |
| (device-attest-01 only) no validated `device-attest-01` challenge left an attestation record to bind against | `badCSR` (400) |
| (device-attest-01 only) the CSR's key is not the attested key | `badCSR` (400) |
| (device-attest-01 `dice` only) the CSR is not the device's possession request: not the template, a signature that does not verify, another key, another order's nonce, or identifiers other than exactly the order's | `badCSR` (400) |
| (device-attest-01 `dice` only) the attestation record carries no attested SPKI, or the CSR's SubjectPublicKeyInfo is not byte-equal to it | `badCSR` (400) |
| (device-attest-01 `dice` only) the device registry, queried again, no longer holds the device's record, or holds another key | `unauthorized` (401) |
| an authorization the order references is missing from storage | `serverInternal` (500) |

As with endorse-01, each is refused before the order moves to `processing`.

A `device-attest-01` finalize is refused unless the CSR's key is the key the
challenge attested: for the `tpm` format, the key in the statement's
`pubArea`, which the AIK in `x5c[0]` certified with TPM2_Certify over the key
authorization (WebAuthn Level 2 §8.3); for `dice`, the attested SPKI — the
DeviceID key the device's provisioning record vouched for at the challenge,
which the alias leaf must also carry. The attestation object is unchanged on the wire —
`fmt: "tpm"`, `attStmt: {ver, alg, x5c, sig, certInfo, pubArea}` — but
`certInfo` must be a TPM2_Certify, not a TPM2_Quote, and `extraData` must be
`TPMExtraData(alg, keyAuthorization)`. The check runs against the attestation
record `ChallengeHandler` persisted on the authorization's `device-attest-01`
challenge when it validated; a
permanent-identifier order with no such record is refused outright rather
than signed as an ordinary CSR. See
[engineering.md](engineering.md#device-attest-01-key-binding).

For `dice` the CSR must also be the device's **possession request**: the
fixed template (empty subject, P-256 key, one `extensionRequest` with a
critical `subjectAltName` naming `permanentIdentifier` = `hex(ueid)` and a
critical `tcg-dice-UCCS-evidence` carrying the alias certificate's claims
`{10: SHA-256(keyAuthorization), 256: ueid, 273: measurements}`), signed by
the attested key (`pkg/acme/challenges/device-attest-01/possession.go:38-77`,
checked by `VerifyPossessionCSR` at `possession.go:370`). A `dice` order therefore names
exactly one `permanent-identifier` and nothing else. The UCCS extension is
never copied onto the certificate (`order_finalize.go:851`). The request's key must also be the key the device
registry vouched for at the challenge, and finalize asks the registry again, so
a device withdrawn or re-keyed since its challenge is `unauthorized`.

The challenge itself also refuses to validate unless the device identity the
evidence carries — the RFC 4043 `permanentIdentifier` otherName on the AIK
certificate for `tpm`, the hex-encoded TCG DICE `tcg-dice-Ueid` extension for
`dice` — equals the authorization's `permanent-identifier` value;
a mismatch is `unauthorized` (401) at the challenge, before
finalize is ever reached. A `dice` challenge is also `unauthorized` unless the
server's device registry holds a provisioning record for the device's UEID that
vouches for the alias certificate's key; a server with no registry, which
includes a stock `xkmsd`, refuses every `dice` attestation. See
[engineering.md](engineering.md#device-attest-01-key-binding).

`endorse-01` is the one exception: its permanent identifier is the EK public
key being certified, authorized when the endorse-01 challenge itself was
validated, so its finalize CSR is never checked against the order's
permanent identifier — only its DNS/IP SANs are.

## Transport adapters

xkmsd serves the RFC 8555 surface on its own ACME listener
(`acme.https_addr`, `pkg/config/acme.go:106`; `cmd/xkmsd/acme.go:409`). No
other transport carries the ACME protocol: `ACMEAdapter`
(`pkg/acme/api/adapter.go:184-198`) is an interface with no implementation.
The transports below carry the **admin** plane only.

| Transport | Admin plane in xkmsd | Admin plane in `MultiProtocolServer` | Client adapter |
|---|---|---|---|
| **rest** | `/admin` and `/api/v1/tenants` on the unified mTLS listener (`cmd/xkmsd/admin.go:71`, `:91-106`) | `:8443` (`pkg/acme/api/server/server.go:49`) | `pkg/acme/api/rest` |
| **grpc** | not served | `:9443` (`server.go:50`), plus the Unix socket `/run/trusted-ca-grpc.sock`, mode 0660 (`server.go:53`, `:55`) | `pkg/acme/api/grpc` |
| **quic** | not served | `:9444` over HTTP/3, disabled without TLS (`server.go:51`, `:713-723`) | `pkg/acme/api/quic` |
| **mcp** | not served | `:9445`, plus `POST /mcp` on the REST router (`server.go:52`, `:650-655`) | `pkg/acme/api/mcp` |
| **unix** | not served | HTTP over `/run/trusted-ca-rest.sock`, mode 0660, with no TLS: access is controlled only by filesystem permissions (`server.go:54`, `:56`, `:905-942`) | — |
| **embedded** | `pkg/acme/client` in-process; first-node issuance goes straight to `TrustedCA` without ACME | — | `pkg/acme/client` |

The client adapters implement `AdminAdapter` (`adapter.go:164-179`).
`MultiProtocolServer` (`pkg/acme/api/server`) is a library server. xkmsd does
not start it; only the multi-protocol integration tests import it. REST, QUIC,
MCP and HTTP-over-Unix all serve the single router that `buildRouter` builds
(`server.go:620-673`). It holds:

- the admin and tenant routes;
- `GET /health`, unauthenticated, answering `{"status":"healthy"}`
  (`:640-646`);
- `POST /mcp`;
- Swagger;
- the admin web UI.

### Authorization on the library server

Callers must always authenticate. Permissions are checked only when
`ServerConfig.Authorizer` is set; with it nil, every authenticated caller is
allowed (`server.go:96-106`, `pkg/acme/admin/authz.go:47-57`).

- **gRPC over TCP** chains three interceptors: peer credentials, mTLS
  identity and authorization (`server.go:807-811`). Each `AdminService`
  RPC declares its qrdb permission with the `(qrdb.v1.permission)` method
  option in `api/proto/admin.proto`; `adminRPCPermissions`
  (`pkg/acme/api/server/interceptor_authz.go:43`) reads them from the
  generated descriptor. A method that declares none is refused with
  `PermissionDenied` (`ErrOperationUnmapped`, `:95-130`).
- **gRPC over the Unix socket** has no TLS. The caller is identified by
  `SO_PEERCRED`, and on platforms without it the socket refuses to start
  (`server.go:839-897`). `RoleMapping` turns the peer's credentials into qrdb
  roles (`role_mapper.go:47-65`). `DefaultRoleMapping` grants `admin` to UID 0
  and GID 0, and `operator` to GIDs 10 and 80 (`:73-79`). A peer that matches
  no rule gets no role and is denied (`:42-46`).
- **MCP** has 27 methods, such as `admin.getStatus` and
  `admin.listCertificates` (`server.go:219`). Each names the `AdminService`
  RPC it mirrors and requires that RPC's permission, so gRPC and MCP need the
  same grant; `MCPToolPermissions` (`mcp_authz.go:34-42`) reports them in
  go-qrdb's `ModuleMCPToolPermissioner` contract. A method that can be
  dispatched but whose RPC declares no permission is denied
  (`mcp_authz.go:53-67`).

MCP answers with these JSON-RPC error codes (`server.go:1087-1143`):

| Code | Meaning |
|---|---|
| `-32700` | parse error |
| `-32600` | invalid request |
| `-32002` | unauthorized |
| `-32003` | forbidden |
| `-32001` | not found |
| `-32603` | internal error; the detail is withheld |

The gRPC service is `trustedca.admin.v1.AdminService` (`api/proto/admin.proto`),
with unary RPCs only.

### Interactive documentation (Swagger UI)

`pkg/acme/api/swagger` embeds both OpenAPI specs (`acme-api.yaml`,
`admin-api.yaml`) and a vendored copy of `swagger-ui-dist`, with no CDN and no
external fetch at runtime. Only `MultiProtocolServer` mounts it
(`server.go:662-667`, default spec `admin-api`). xkmsd does not serve it.

| Path | Serves |
|---|---|
| `GET /docs` | Swagger UI; `?spec=acme-api` or `?spec=admin-api` selects which spec renders |
| `GET /openapi/acme-api.yaml` | the RFC 8555 surface documented above |
| `GET /openapi/admin-api.yaml` | the `pkg/acme/admin` control-plane surface |

`/docs` and `/openapi/*` are **not public**. They require the same admin
authentication and `admin:capabilities` qrdb grant as `GET /admin/algorithms`.
The specs list every admin route, parameter and permission, so serving them to
unauthenticated callers would hand out a list of targets.

The Swagger UI page sets a strict `Content-Security-Policy` (`script-src
'self'`, no `unsafe-eval`, no `unsafe-inline` scripts). Every script it loads
is same-origin and vendored at build time.

## The xkms control-plane view of ACME

Separately from the RFC surface, the ACME server's **administration** is
reachable through `pkg/acme/admin` (accounts, certificates, orders, EAB,
tenants, roles, users, CA status/stats, audit, algorithms). That plane is not
RFC 8555 and is not documented as if it were; it follows the repo's normal
authenticated-API conventions. The SDK surface is `sdk/go/acme/client/admin`;
the CLI surface is `xkmsctl acme` ([`cli.md`](cli.md#xkmsctl-acme-admin)).

Authorization is qrdb RBAC, resolved per route by `PermissionGate`. On
xkmsd's unified mTLS listener the caller is the qrdb user its client
certificate is bound to (SPKI thumbprint), looked up in the tenant the
certificate names (its tenant SPIFFE SAN in the deployment's trust domain,
else its first OU, else the system tenant), with that user's roles. The OU
names only the tenant and never grants a role. A missing certificate, a
certificate bound to no user in that tenant, a user of another tenant, or a
SPIFFE SAN from another trust domain is answered `401`; a user holding no
role that carries the route's permission is answered `403`. The admin gRPC
service resolves the caller the same way, through the same handler
(`cmd/xkmsd/admin.go:152-157`, `pkg/acme/admin/auth_mtls.go:137-155`; see
[`engineering.md`](engineering.md#invariants)).

### Admin API response contract

Every admin operation — tenants, tenant CA hierarchy, EAB, roles, users,
certificates, accounts, orders, status/stats, audit, algorithms —
follows one contract, with no success/error envelope: a single-resource
operation's success body is the resource itself; a paginated list operation's
success body is `{items, total, page, per_page}`; a mutation with nothing
else to report succeeds with `{message}`. Every error, on every operation and
at every layer (handler validation, service errors, and `PermissionGate`'s
own 401/403), is an RFC 7807 `application/problem+json` body
(`{type, title, detail, status}`). `admin-api.yaml`
(`pkg/acme/api/swagger/openapi/admin-api.yaml`) documents exactly this for
every operation — there is no second copy of this document anywhere in the
tree to drift from it.

### Admin API routes

`admin.Routes()` (`pkg/acme/admin/routes.go:97-126`) declares these routes
under `/admin`, each with its own qrdb permission. The unified server mounts
each through qrdb's `Handle` (`pkg/apimodule/admin_module.go:147`); a
standalone host gates each with `PermissionGate` (`Handlers.RegisterRoutes`,
`pkg/acme/admin/handlers.go:100`):

| Route | Method | Permission |
|---|---|---|
| `/admin/certificates` | `GET` | `certs:list` |
| `/admin/certificates/expiring` | `GET` | `certs:list` |
| `/admin/certificates/{serial}` | `GET` | `certs:read` |
| `/admin/certificates/{serial}/revoke` | `POST` | `certs:revoke` |
| `/admin/accounts` | `GET` | `acme_accounts:list` |
| `/admin/accounts/{id}` | `GET` / `DELETE` | `acme_accounts:read` / `acme_accounts:disable` |
| `/admin/orders` | `GET` | `acme_orders:list` |
| `/admin/orders/{id}` | `GET` | `acme_orders:read` |
| `/admin/audit` | `GET` | `audit:read` |
| `/admin/status`, `/admin/stats` | `GET` | `admin:status` |
| `/admin/algorithms` | `GET` | `admin:capabilities` |

Query parameters, with defaults in parentheses:

| Route | Parameters | Source |
|---|---|---|
| `/admin/certificates` | `page` (1), `per_page` (20), `status`, `subject` | `handlers.go:153-156` |
| `/admin/certificates/expiring` | `days` (30), `page`, `per_page` | `handlers.go:232-234` |
| `/admin/accounts` | `page`, `per_page`, `status` | `handlers.go:259-261` |
| `/admin/orders` | `page`, `per_page`, `status`, `account_id` | `handlers.go:340-345` |
| `/admin/orders/{id}` | `account_id`, required; `400` without it | `handlers.go:379-383` |
| `/admin/audit` | see [audit-log/api.md](../audit-log/api.md#acme-audit-trail) | `handlers.go:500-516` |
| `/api/v1/tenants` | `page`, `per_page`, `status` | `tenant_handlers.go:344-346` |
| `/api/v1/tenants/{id}/eab` | `page`, `per_page`, `status`, `purpose` | `tenant_handlers.go:753-756` |
| `/api/v1/tenants/{id}/roles`, `/users` | `page`, `page_size` (20) | `parsePagination`, `tenant_handlers.go:1062-1076` |

The service caps `per_page` at 100 (`pkg/acme/admin/service.go:68-71`,
`tenant_service.go:521-524`). A tenant created without an `id` is given
`tenant-<unixnano>` (`tenant_handlers.go:198`). `POST .../eab` returns the
`mac_key` once (`CreateEABResponse`, `types.go:507-512`). Later reads never
include it (`EABInfo`, `types.go:470-483`).

xkmsd builds its admin handlers without an audit querier
(`cmd/xkmsd/admin.go:143`), so on xkmsd `GET /admin/audit` answers `501`
(`handlers.go:446-488`).

### Admin API tenant binding responses

Passing `PermissionGate` is not enough to act on a tenant, role, user,
account or certificate a request names (go-xkms#1225; the contract is in
[`engineering.md`](engineering.md#invariants)). A tenant-scoped caller gets
**the answer a missing resource gets**, never a denial that confirms the
resource exists; a platform (system-tenant) caller keeps its cross-tenant
reach.

| Request by a tenant-scoped caller | REST | gRPC | Site |
|---|---|---|---|
| any `/api/v1/tenants/{id}/...` route naming another tenant | `404`, detail `Tenant not found` — the body a missing tenant gets | `NotFound` | `checkTenantAccess`, `pkg/acme/admin/tenant_handlers.go:72`; service `admitTenant`, `pkg/acme/admin/tenant_binding.go:105` |
| a role or user of another tenant under its own `{id}` (every caller, the platform included) | `404`, `Role not found` / `User not found` | `NotFound` | `tenantRole` / `tenantUser`, `pkg/acme/admin/tenant_service.go:1598`, `:1705` |
| `GET /api/v1/tenants` | `200`, its own tenant only | same | `pkg/acme/admin/tenant_service.go:547` |
| `POST /api/v1/tenants` | `403`, detail `Creating a tenant requires a platform identity` | `PermissionDenied` | `qrdbsdk.IdentityIsSystemTenant`, `pkg/acme/admin/tenant_service.go:195`; `pkg/acme/admin/tenant_handlers.go:143-144` |
| `GET /admin/audit` | `403`, the gate's own `Access denied: insufficient permissions` body | `PermissionDenied` | `qrdbsdk.IdentityIsSystemTenant`, `pkg/acme/admin/handlers.go:416` |
| `/admin/certificates*`, `/admin/accounts*`, `/admin/orders*`, `/admin/stats` | only its tenant's accounts and the certificates their orders were issued; anything else is `404` on get/revoke/disable, absent from lists | `NotFound` / absent | `pkg/acme/admin/service.go:551-694` |

gRPC maps these through `convertAdminErrorToGRPC`
(`pkg/acme/api/server/grpc_service.go:563`): the refusals unwrap to
`ErrTenantNotFound`, `ErrRoleNotFound`, `ErrUserNotFound`,
`ErrAccountNotFound`, `ErrOrderNotFound`, `ErrCertificateNotFound`
(`IsNotFoundError`, `pkg/acme/admin/types.go:64`) or `ErrForbidden`
(`IsUnauthorizedError`).

### Admin API tenant routes

The ACME admin plane's tenant routes (`tenantRoutes`,
`pkg/acme/admin/routes.go:183`, part of `admin.Routes()`) are distinct from the key-management
tenant routes in [`../multi-tenancy/api.md`](../multi-tenancy/api.md): these
carry the ACME tenant's CA hierarchy, settings and EABs
([`engineering.md`](engineering.md#acme-tenant-ca-hierarchy)). Each route is
declared with its own qrdb permission. The tenant lifecycle rows
are gated by the reach of the call (`gate.WrapTenant`, `gate.WrapTenantList`,
`pkg/acme/admin/authz.go`): within the caller's own tenant the self-scoped
`tenants:*` grant, beyond it qrdb's cross-scope `qrdbsdk.PermissionTenants*Cross`
grant, which only a system-tenant caller (the platform Admin) can exercise. A
tenant-scoped caller lists only its own tenant, and naming any other tenant is
answered `404 Tenant not found`, exactly as a missing tenant is (go-xkms#1225).
Creating a tenant always reaches beyond the caller's own, so the handler carries
no platform-scope check of its own. On the unified server the tenant lifecycle
rows are mounted identity-gated (`Route.SelfPermission`) and the admin router
applies the reach gate (`RegisterAuthorizedRoutes`); a standalone host applies
it route by route (`RegisterRoutes`):

| Route | Method | Permission (own tenant / other tenant) |
|---|---|---|
| `/api/v1/tenants` | `GET` | `tenants:list` (tenant-scoped caller) / `tenants:list:cross` (system-tenant caller) |
| `/api/v1/tenants` | `POST` | `tenants:create:cross` |
| `/api/v1/tenants/{id}` | `GET` / `PUT` / `DELETE` | `tenants:read` / `tenants:update` / `tenants:delete`, or the `:cross` grant |
| `/api/v1/tenants/{id}/status` | `PUT` | `tenants:update`, or `tenants:update:cross` |
| `/api/v1/tenants/{id}/root-ca` | `POST` | `ca:create` |
| `/api/v1/tenants/{id}/intermediate-cas` | `GET` / `POST` | `ca:list` / `ca:create` |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}` | `GET` | `ca:read` |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}/status` | `PUT` | `ca:update` |
| `/api/v1/tenants/{id}/default-intermediate-ca` | `PUT` | `ca:update` |
| `/api/v1/tenants/{id}/ca-status` | `GET` | `ca:read` |
| `/api/v1/tenants/{id}/eab` | `GET` / `POST` | `acme_eab:list` / `acme_eab:create` |
| `/api/v1/tenants/{id}/eab/{kid}` | `GET` / `DELETE` | `acme_eab:read` / `acme_eab:delete` |
| `/api/v1/tenants/{id}/roles`, `/roles/{roleID}` | CRUD | `roles:*` |
| `/api/v1/tenants/{id}/users`, `/users/{userID}` | CRUD | `users:*` |

Resource names are `pkg/auth/permissions.go:45,109,116`. `acme_eab:create` is
the endorser authority: a deployment that wants an endorse-only principal
creates a qrdb role holding just that permission (the comment above the EAB
routes in `RegisterRoutes`).

Request bodies (`pkg/acme/admin/types.go`):

| Request | Fields |
|---|---|
| `CreateTenantRequest` (`:408`) | `id`, `name`, `settings` (`TenantSettingsInfo`, `:368`: `max_certificates`, `max_accounts`, `allowed_key_algorithms`, `allowed_challenge_types`, `certificate_validity_days`, `require_eab`, `allow_endorse_01`, `allow_enroll_01`, `compliance_config`) |
| `UpdateTenantStatusRequest` (`:421`) | `status` |
| `CreateTenantRootCARequest` (`:426`) | `common_name`, `key_algorithm`, `validity_years` |
| `CreateTenantIntermediateCARequest` (`:433`) | `common_name`, `parent_type` (`global` or `tenant`), `purpose`, `key_algorithm`, `validity_years`, `set_as_default` |
| `CreateEABRequest` | `purpose` — `account-binding` (the default), `endorse-01` or `enroll-01`; anything else is `400` (`tenant_handlers.go:649-658`). An `endorse-01` EAB without `device_info` is accepted with a logged warning (`:661-663`), but endorse-01 then refuses it at the challenge because it names no EK (see [endorse-01 finalize](#endorse-01-finalize)). |

```bash
curl --cert admin.pem --key admin.key \
  -H "Content-Type: application/json" \
  -d '{"common_name": "Example Corp TPM Endorsement CA",
       "parent_type": "global", "key_algorithm": "ECDSA",
       "validity_years": 10, "purpose": "tpm-endorsement"}' \
  https://kms.example.com/api/v1/tenants/example-corp/intermediate-cas
```

`key_algorithm` names an algorithm family, not a curve or size: `RSA` (also
the empty default), `ECDSA`/`EC` or `Ed25519`, in the case variants
`parseKeyAlgorithm` lists; anything else, `EC-P384` included, is refused as
malformed (`pkg/acme/admin/tenant_service.go:1744-1754`).

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
| rate limited (xkmsd whenever `acme.rate_limit` is enabled, via `acmeserver.NewClientRateLimiterMiddleware` at `cmd/xkmsd/acme.go:281`; the standalone `TrustedCA` too; see [engineering.md](engineering.md) §Invariants) | 429 with `Retry-After` |
| request body larger than 256 KiB (`server.MaxRequestBodySize`, `pkg/acme/server/request_body.go:38`) | 413, `malformed` problem |
| new-order with more than 100 identifiers (`pkg/acme/server/handlers/new_order.go:36`) | 400, `malformed` problem |

Every response carries a fresh `Replay-Nonce` header — a client that does not
read it will fail its next POST with `badNonce`.

## Pagination

`POST /acme/account/{id}/orders` returns an orders list with RFC 8555 `Link:
rel="next"` pagination. No ACME collection is returned unbounded. Admin-plane
list pagination is under [Admin API routes](#admin-api-routes).

## Versioning and deprecation

RFC 8555 has no protocol version negotiation; the directory *is* the version
contract. Adding a challenge type is additive and safe — clients select only
what they understand. Removing one is breaking.

The go-xkms extensions (`enroll-01`, `endorse-01`) are advertised in the
directory's metadata alongside the standard types and are ignored by
standard clients.
