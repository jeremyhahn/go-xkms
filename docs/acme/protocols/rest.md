# REST API Protocol

HTTP/HTTPS REST API for the ACME admin plane.

## Overview

xkmsd serves the ACME admin surface over REST only, mounted on its own
unified mTLS listener alongside the crypto-plane API (`Server.RESTPort`,
default `8443` — `configs/xkmsd.yaml:6`). There is no separate
`--admin-enabled` flag and no standalone admin binary: `cmd/xkmsd/admin.go`
constructs the admin `ServiceModule` (`newAdminModule`,
`cmd/xkmsd/admin.go:101`) ahead of `server.New` and publishes its router once
the embedded qrdb node, the ACME CA, and ACME storage are all ready
(`finalizeAdminModule`, `cmd/xkmsd/admin.go:130`).

The route table is split across two handler sets, both registered on that
one listener:

- `Handlers` (`pkg/acme/admin/handlers.go:98`) mounts under `/admin`:
  certificates, accounts, orders, audit, status/stats, and algorithm
  discovery.
- `TenantHandlers` (`pkg/acme/admin/tenant_handlers.go:53`) mounts under
  `/api/v1/tenants`: tenant lifecycle, tenant CA management, EAB, roles, and
  users.

The admin single-page app is served separately, at `/admin-ui`
(`adminUIPrefix`, `cmd/xkmsd/admin.go:73`), not under either API prefix.

## Connection

| Property | Value |
|----------|-------|
| Protocol | HTTP/1.1, HTTP/2 |
| Default Port | 8443 (`Server.RESTPort`, `configs/xkmsd.yaml:6`) |
| Transport | TCP with TLS |
| Content-Type | `application/json` |

## Authentication

Every admin route is wrapped in `PermissionGate.Wrap` at registration time
(`pkg/acme/admin/handlers.go:108-143`,
`pkg/acme/admin/tenant_handlers.go:61-127`); there is no undecorated route to
reach. `xkmsd` wires exactly one `AuthHandler` in production:
`admin.NewMTLSAuthHandler` (`cmd/xkmsd/admin.go:153`). A client authenticates
with a TLS client certificate; the package also has a JWT-based
`AuthMiddleware` (`pkg/acme/admin/auth.go:93`), but nothing in `cmd/xkmsd`
wires it, so it is not part of the served surface today.

Once authenticated, the gate authorizes every request against the embedded
qrdb node's RBAC service (`auth.NewAuthorizer(qrdbClient.RBAC())`,
`cmd/xkmsd/admin.go:157`). A request that carries no identity is refused
with `401`; an authenticated identity without the route's declared
resource:action grant is refused with `403`.

```bash
xkmsctl acme --acme-server https://localhost:8443 --acme-transport rest status
```

## Request/Response Format

### Success Response

Every handler writes the resource directly, with `writeJSON`
(`pkg/acme/admin/handlers.go:518`) — there is no `data`/`meta` envelope.
List endpoints wrap results in `ListResponse`
(`pkg/acme/admin/types.go:100`):

```json
{
  "items": [ ... ],
  "total": 150,
  "page": 1,
  "per_page": 20
}
```

### Error Response

Errors are RFC 7807 Problem Details, written by `writeProblem`
(`pkg/acme/admin/handlers.go:529`):

```json
{
  "type": "urn:trusted-ca:error:not-found",
  "title": "Not Found",
  "detail": "Certificate not found",
  "status": 404
}
```

### Pagination

List endpoints accept `page` (default 1) and `per_page` (default 20) query
parameters (`parseInt`, `pkg/acme/admin/handlers.go:543`); the response's
`ListResponse.total`/`page`/`per_page` fields report the server's view.

## Certificate Endpoints (`/admin`)

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/admin/certificates` | `ListCertificates` | List certificates; `page`, `per_page`, `status`, `subject` query params |
| GET | `/admin/certificates/expiring` | `ListExpiringCertificates` | List certificates expiring soon; `days` (default 30), `page`, `per_page` |
| GET | `/admin/certificates/{serial}` | `GetCertificate` | Get a certificate by serial |
| POST | `/admin/certificates/{serial}/revoke` | `RevokeCertificate` | Revoke a certificate |

`/admin/certificates/expiring` is registered before
`/admin/certificates/{serial}` so gorilla/mux does not match `expiring` as a
serial number (`pkg/acme/admin/handlers.go:106-111`).

A `CertificateInfo` (`pkg/acme/admin/types.go:115`) looks like:

```json
{
  "id": 42,
  "serial_number": "01:02:03:04",
  "subject": "CN=host.kms.example.com",
  "issuer": "CN=Example Intermediate CA",
  "not_before": "2026-01-01T00:00:00Z",
  "not_after": "2026-04-01T00:00:00Z",
  "status": "valid",
  "issued_at": "2026-01-01T00:00:05Z",
  "cert_url": "https://ca.kms.example.com/admin/certificates/01:02:03:04"
}
```

Revocation request body (`RevokeRequest`, `pkg/acme/admin/types.go:247`):

```json
{ "reason": "keyCompromise" }
```

## Account Endpoints (`/admin`)

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/admin/accounts` | `ListAccounts` | List ACME accounts; `page`, `per_page`, `status` |
| GET | `/admin/accounts/{id}` | `GetAccount` | Get an account by numeric ID |
| DELETE | `/admin/accounts/{id}` | `DisableAccount` | Disable an account |

`AccountInfo` (`pkg/acme/admin/types.go:128`):

```json
{
  "id": 7,
  "status": "valid",
  "contact": ["mailto:ops@kms.example.com"],
  "created_at": "2026-01-01T00:00:00Z",
  "terms_of_service_agreed": true,
  "orders_url": "/admin/orders?account_id=7",
  "order_count": 3
}
```

## Order Endpoints (`/admin`)

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/admin/orders` | `ListOrders` | List orders; `page`, `per_page`, `status`, `account_id` |
| GET | `/admin/orders/{id}` | `GetOrder` | Get an order; requires `account_id` query param |

## Audit, Status, and Capability Endpoints (`/admin`)

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/admin/audit` | `ListAuditLogs` | Query the audit trail; `501` if no audit querier is configured |
| GET | `/admin/status` | `GetStatus` | CA status (`CAStatus`, `pkg/acme/admin/types.go:210`) |
| GET | `/admin/stats` | `GetStats` | CA statistics (`CAStats`, `pkg/acme/admin/types.go:223`) |
| GET | `/admin/algorithms` | `GetAlgorithms` | Algorithms this deployment can execute (`AlgorithmsResponse`, `pkg/types/algorithm_discovery.go:38`) |

`GET /admin/audit` accepts `page`, `per_page`, `event_type`, `actor`,
`action`, `resource`, `result`, `request_id`, `start_time`, and `end_time`
(RFC 3339) query parameters (`parseListAuditLogsRequest`,
`pkg/acme/admin/handlers.go:449`).

## Tenant Endpoints (`/api/v1/tenants`)

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/api/v1/tenants` | `ListTenants` | List tenants |
| POST | `/api/v1/tenants` | `CreateTenant` | Create a tenant |
| GET | `/api/v1/tenants/{id}` | `GetTenant` | Get a tenant |
| PUT | `/api/v1/tenants/{id}` | `UpdateTenant` | Update a tenant |
| DELETE | `/api/v1/tenants/{id}` | `DeleteTenant` | Delete a tenant |
| PUT | `/api/v1/tenants/{id}/status` | `UpdateTenantStatus` | Update tenant status |

`CreateTenantRequest` (`pkg/acme/admin/types.go:388`) auto-generates `id` as
`tenant-<unix-nano>` when omitted
(`pkg/acme/admin/tenant_handlers.go:163`):

```json
{ "name": "Example Tenant", "settings": { "require_eab": true } }
```

A `TenantInfo` response (`pkg/acme/admin/types.go:306`):

```json
{
  "id": "tenant-1234567890",
  "name": "Example Tenant",
  "status": "active",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

### Tenant CA Endpoints

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| POST | `/api/v1/tenants/{id}/root-ca` | `CreateTenantRootCA` | Create the tenant's root CA |
| GET | `/api/v1/tenants/{id}/intermediate-cas` | `ListTenantIntermediateCAs` | List intermediate CAs |
| POST | `/api/v1/tenants/{id}/intermediate-cas` | `CreateTenantIntermediateCA` | Create an intermediate CA |
| GET | `/api/v1/tenants/{id}/intermediate-cas/{caid}` | `GetTenantIntermediateCA` | Get an intermediate CA |
| PUT | `/api/v1/tenants/{id}/intermediate-cas/{caid}/status` | `UpdateTenantIntermediateCAStatus` | Update an intermediate CA's status |
| PUT | `/api/v1/tenants/{id}/default-intermediate-ca` | `SetTenantDefaultIntermediateCA` | Set the tenant's default intermediate CA |
| GET | `/api/v1/tenants/{id}/ca-status` | `GetTenantCAStatus` | Tenant CA status summary |

`CreateTenantRootCARequest` (`pkg/acme/admin/types.go:406`) requires
`common_name`, `key_algorithm`, and a positive `validity_years`
(`pkg/acme/admin/tenant_handlers.go:361-374`).
`CreateTenantIntermediateCARequest` (`pkg/acme/admin/types.go:413`) adds
`parent_type` (`"global"` or `"tenant"`, defaulting to `"global"`) and an
optional `purpose`.

### EAB Endpoints

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/api/v1/tenants/{id}/eab` | `ListTenantEABs` | List EABs |
| POST | `/api/v1/tenants/{id}/eab` | `CreateTenantEAB` | Create an EAB |
| GET | `/api/v1/tenants/{id}/eab/{kid}` | `GetTenantEAB` | Get an EAB |
| DELETE | `/api/v1/tenants/{id}/eab/{kid}` | `DeleteTenantEAB` | Delete an EAB |

`CreateEABResponse` (`pkg/acme/admin/types.go:487`) reveals `mac_key` exactly
once — it is not retrievable again after this response.

### Role and User Endpoints

| Method | Endpoint | Handler | Description |
|--------|----------|---------|-------------|
| GET | `/api/v1/tenants/{id}/roles` | `ListTenantRoles` | List RBAC roles |
| POST | `/api/v1/tenants/{id}/roles` | `CreateTenantRole` | Create a role |
| GET | `/api/v1/tenants/{id}/roles/{roleID}` | `GetTenantRole` | Get a role |
| PUT | `/api/v1/tenants/{id}/roles/{roleID}` | `UpdateTenantRole` | Update a role |
| DELETE | `/api/v1/tenants/{id}/roles/{roleID}` | `DeleteTenantRole` | Delete a role |
| GET | `/api/v1/tenants/{id}/users` | `ListTenantUsers` | List users |
| POST | `/api/v1/tenants/{id}/users` | `CreateTenantUser` | Create a user |
| GET | `/api/v1/tenants/{id}/users/{userID}` | `GetTenantUser` | Get a user |
| PUT | `/api/v1/tenants/{id}/users/{userID}` | `UpdateTenantUser` | Update a user |
| DELETE | `/api/v1/tenants/{id}/users/{userID}` | `DeleteTenantUser` | Delete a user |

Role and user request/response bodies are the canonical go-qrdb types
(`db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"`,
`pkg/acme/admin/tenant_handlers.go:27`: `CreateRoleRequest`, `Role`,
`CreateUserRequest`, `User`, and their `List*`/`Update*` counterparts).

## Examples

### Get CA Status

```bash
curl -X GET https://localhost:8443/admin/status \
  --cert client.crt --key client.key --cacert ca.crt
```

### List Certificates

```bash
curl -X GET "https://localhost:8443/admin/certificates?per_page=10" \
  --cert client.crt --key client.key --cacert ca.crt
```

### Create Tenant

```bash
curl -X POST https://localhost:8443/api/v1/tenants \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"name": "Example Tenant"}'
```

### Revoke Certificate

```bash
curl -X POST https://localhost:8443/admin/certificates/01:02:03:04/revoke \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"reason": "keyCompromise"}'
```

## Error Codes

| HTTP Status | `type` | Description |
|-------------|--------|-------------|
| 400 | `urn:trusted-ca:error:bad-request` | Invalid request format |
| 401 | `urn:trusted-ca:error:unauthorized` | Authentication required |
| 403 | `urn:trusted-ca:error:forbidden` | Insufficient permissions |
| 404 | `urn:trusted-ca:error:not-found` | Resource not found |
| 409 | `urn:trusted-ca:error:conflict` | Resource already exists |
| 501 | `urn:trusted-ca:error:not-implemented` | Audit trail not configured |
| 500 | `urn:trusted-ca:error:internal` | Server error |

(`pkg/acme/admin/handlers.go` and `pkg/acme/admin/tenant_handlers.go`; the
`type` strings are literal, taken directly from the `writeProblem` call
sites.)

## See Also

- [Protocol Overview](README.md)
- [gRPC Protocol](grpc.md)
- [QUIC Protocol](quic.md)
- [MCP Protocol](mcp.md)
- [Unix Socket Protocol](unix-socket.md)
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
