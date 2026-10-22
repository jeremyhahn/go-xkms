# Admin API Reference

> **Status: REFERENCE** · Last verified: 2026-10-21
> Reference for the desktop admin router in `pkg/acme/gui/admin/api/router.go`.

`adminapi.NewRouter(client trustedca.Client, logger, opts...)`
(`pkg/acme/gui/admin/api/router.go:39`) builds a `gorilla/mux` router behind
the `pkg/acme/gui/guard` middleware. The Wails admin host
(`xkmsctl acme gui`, `gui` tag) mounts it as its AssetServer handler.

The router serves the ACME admin API's own paths (`pkg/acme/admin/routes.go`):
the CA-wide views under `/admin` and tenant management under
`/api/v1/tenants`. The admin SPA's client
(`pkg/acme/web/packages/admin/src/lib/api/admin-api.ts`) calls exactly these
paths, so one bundle runs against this router and against xkmsd's `/admin-ui`.
`pkg/acme/gui/admin/spa_routes_test.go` reads the SPA client and fails if a
call is not served, if a route is served that the SPA never calls, or if a
route is not an ACME admin API route.

Two SPA calls are not served yet, because the SDK (`trustedca.Client`) has no
operation for them: `GET /admin/audit` (Audit Log view) and
`PUT /api/v1/tenants/{id}/default-intermediate-ca`. On the desktop they answer
404; xkmsd serves both.

## Endpoints

Routes are registered at `pkg/acme/gui/admin/api/router.go:45-100`.

### Status

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/status` | CA server status |
| GET | `/admin/stats` | Certificate, account and order statistics |

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/certificates` | List certificates (paginated) |
| GET | `/admin/certificates/{serial}` | Get certificate by serial number |
| POST | `/admin/certificates/{serial}/revoke` | Revoke a certificate |

**List query params** (certificates, accounts, orders): `page` (default 1),
`per_page` (default 20), `status`. Certificates also take `expires_days`, a
positive day count that keeps only certificates expiring within it; any other
value is a 400 (`pkg/acme/gui/admin/api/cert_handlers.go:41`).

**Revoke request** (`pkg/acme/gui/admin/api/cert_handlers.go:28`):
```json
{ "reason": "keyCompromise" }
```

### Orders

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/orders` | List orders (paginated) |
| GET | `/admin/orders/{id}` | Get order by ID |

### Accounts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/accounts` | List ACME accounts (paginated) |
| GET | `/admin/accounts/{id}` | Get account by ID |
| DELETE | `/admin/accounts/{id}` | Disable an account |

### Tenants

Tenant paths below are relative to `/api/v1`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants` | List tenants |
| POST | `/tenants` | Create a tenant |
| GET | `/tenants/{id}` | Get tenant by ID |
| PUT | `/tenants/{id}` | Update a tenant |
| DELETE | `/tenants/{id}` | Delete a tenant |
| PUT | `/tenants/{id}/status` | Change tenant status |

**Create tenant request** (`CreateTenantRequest`,
`sdk/go/acme/client/admin/types.go:113`; settings fields from
`TenantSettingsInfo`):
```json
{
  "id": "acme-corp",
  "name": "ACME Corporation",
  "settings": {
    "max_certificates": 1000,
    "require_eab": true,
    "allowed_challenge_types": ["http-01", "dns-01", "device-attest-01"]
  }
}
```

### Tenant CAs

| Method | Path | Description |
|--------|------|-------------|
| POST | `/tenants/{id}/root-ca` | Create the tenant root CA |
| GET | `/tenants/{id}/ca-status` | Tenant CA status |
| POST | `/tenants/{id}/intermediate-cas` | Create an intermediate CA |
| PUT | `/tenants/{id}/intermediate-cas/{caId}/status` | Change an intermediate CA's status |

### Tenant EAB

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{id}/eab` | List EAB credentials |
| POST | `/tenants/{id}/eab` | Create EAB credential |
| DELETE | `/tenants/{id}/eab/{eabId}` | Delete EAB credential |

### Tenant roles

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{id}/roles` | List roles |
| POST | `/tenants/{id}/roles` | Create role |
| GET | `/tenants/{id}/roles/{roleId}` | Get role |
| PUT | `/tenants/{id}/roles/{roleId}` | Update role |
| DELETE | `/tenants/{id}/roles/{roleId}` | Delete role |

### Tenant users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{id}/users` | List users |
| POST | `/tenants/{id}/users` | Create user |
| GET | `/tenants/{id}/users/{userId}` | Get user |
| PUT | `/tenants/{id}/users/{userId}` | Update user |
| DELETE | `/tenants/{id}/users/{userId}` | Delete user |

## Response envelope

`pkg/acme/gui/admin/api/handlers.go:40-48`. `data`, `error` and `pagination`
are omitted when empty:

```json
{ "success": true, "data": { }, "pagination": { } }
{ "success": false, "error": { "code": "...", "message": "..." } }
```

A list answers `{ "data": [ ... ], "pagination": { } }`. The shared SPA client
(`pkg/acme/web/packages/shared/src/api/client.ts`) hands a list to its caller
with that envelope intact, so the stores read `data` and `pagination`; it
unwraps `data` only for a single object. `spa_envelope_test.go` checks the
embedded bundle keeps the envelope.

## Origin check and CORS

The `guard` middleware (`pkg/acme/gui/guard/guard.go:101`) works as follows:

- It rejects a request whose `Origin` host differs from the request `Host`.
- In the in-process (Wails) transport it answers with `Access-Control-Allow-Origin: *`.
- It answers `OPTIONS` with 204.
- It allows methods `GET, POST, PUT, DELETE, OPTIONS` and headers
  `Content-Type, Authorization` (`guard.go:42`, `:45`).

The router itself reads no auth or tenant headers.
