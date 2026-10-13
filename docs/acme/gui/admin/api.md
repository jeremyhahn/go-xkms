# Admin API Reference

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed reference for the desktop admin router in `pkg/acme/gui/admin/api/router.go`.

`adminapi.NewRouter(client trustedca.Client, logger, opts...)`
(`pkg/acme/gui/admin/api/router.go:32`) builds a `gorilla/mux` router. It
serves the paths below under `/api/v1`, behind the `pkg/acme/gui/guard`
middleware. Only the Wails admin host mounts it, and no binary builds that
host. xkmsd's `/admin-ui` uses xkmsd's own admin endpoints instead; see
[README.md](README.md).

## Endpoints

Routes are registered at `pkg/acme/gui/admin/api/router.go:42-94`.

### Status

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | CA server status |
| GET | `/stats` | Certificate, account and order statistics |

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/certificates` | List certificates (paginated) |
| GET | `/certificates/expiring` | Certificates nearing expiry |
| GET | `/certificates/{serial}` | Get certificate by serial number |
| POST | `/certificates/{serial}/revoke` | Revoke a certificate |

**List query params** (certificates, accounts, orders): `page` (default 1),
`per_page` (default 20), `status`.

**Revoke request** (`pkg/acme/gui/admin/api/cert_handlers.go:29`):
```json
{ "reason": "keyCompromise" }
```

### Orders

| Method | Path | Description |
|--------|------|-------------|
| GET | `/orders` | List orders (paginated) |
| GET | `/orders/{id}` | Get order by ID |

### Accounts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/accounts` | List ACME accounts (paginated) |
| GET | `/accounts/{id}` | Get account by ID |
| DELETE | `/accounts/{id}` | Disable an account |

### Tenants

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
| GET | `/tenants/{id}/intermediate-cas` | List intermediate CAs |
| POST | `/tenants/{id}/intermediate-cas` | Create an intermediate CA |
| GET | `/tenants/{id}/intermediate-cas/{caId}` | Get an intermediate CA |
| PUT | `/tenants/{id}/intermediate-cas/{caId}` | Update an intermediate CA |

### Tenant EAB

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{id}/eab` | List EAB credentials |
| POST | `/tenants/{id}/eab` | Create EAB credential |
| GET | `/tenants/{id}/eab/{eabId}` | Get EAB by ID |
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

## Origin check and CORS

The `guard` middleware (`pkg/acme/gui/guard/guard.go:101`) works as follows:

- It rejects a request whose `Origin` host differs from the request `Host`.
- In the in-process (Wails) transport it answers with `Access-Control-Allow-Origin: *`.
- It answers `OPTIONS` with 204.
- It allows methods `GET, POST, PUT, DELETE, OPTIONS` and headers
  `Content-Type, Authorization` (`guard.go:42`, `:45`).

The router itself reads no auth or tenant headers.
