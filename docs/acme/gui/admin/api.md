# Admin API Reference

The admin API is served at `/api/v1` by both the embedded desktop server and the ACME server (web mode).

## Endpoints

### Status

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | CA server status (identity, version, algorithms) |
| GET | `/stats` | Certificate and account statistics |

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/certificates` | List certificates (paginated) |
| GET | `/certificates/{serial}` | Get certificate by serial number |
| POST | `/certificates/{serial}/revoke` | Revoke a certificate |

**List query params:** `page`, `per_page`, `status`, `subject`, `expires_days`

**Revoke request:**
```json
{ "reason": "keyCompromise" }
```

### Accounts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/accounts` | List ACME accounts (paginated) |
| GET | `/accounts/{id}` | Get account by ID |
| DELETE | `/accounts/{id}` | Disable an account |

### Tenants

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants` | List all tenants |
| POST | `/tenants` | Create a tenant |
| GET | `/tenants/{id}` | Get tenant by ID |
| PUT | `/tenants/{id}` | Update a tenant |
| DELETE | `/tenants/{id}` | Delete a tenant |

**Create tenant request:**
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

### Tenant EAB

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{id}/eab` | List EAB credentials |
| POST | `/tenants/{id}/eab` | Create EAB credential |
| GET | `/tenants/{id}/eab/{eabId}` | Get EAB by ID |
| DELETE | `/tenants/{id}/eab/{eabId}` | Delete EAB credential |

### Tenant Roles

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{id}/roles` | List roles |
| POST | `/tenants/{id}/roles` | Create role |
| GET | `/tenants/{id}/roles/{roleId}` | Get role |
| PUT | `/tenants/{id}/roles/{roleId}` | Update role |
| DELETE | `/tenants/{id}/roles/{roleId}` | Delete role |

### Tenant Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants/{id}/users` | List users |
| POST | `/tenants/{id}/users` | Create user |
| GET | `/tenants/{id}/users/{userId}` | Get user |
| PUT | `/tenants/{id}/users/{userId}` | Update user |
| DELETE | `/tenants/{id}/users/{userId}` | Delete user |

## Response Envelope

```json
{
  "success": true,
  "data": { ... },
  "pagination": { "page": 1, "per_page": 20, "total": 142 },
  "error": null
}
```

## Headers

| Header | Purpose |
|--------|---------|
| `Authorization` | `Bearer {token}` for authenticated requests |
| `X-Tenant-ID` | Tenant context for multi-tenant operations |
| `Content-Type` | `application/json` |

## CORS

All endpoints accept `OPTIONS` preflight requests. The CORS middleware allows all origins, methods `GET/POST/PUT/DELETE/OPTIONS`, and headers `Content-Type`, `Authorization`, `X-Tenant-ID`.
