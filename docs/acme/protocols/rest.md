# REST API Protocol

HTTP/HTTPS REST API for Admin operations.

> **Correction (go-xkms#942):** there is no `trusted-acme-server` binary,
> no `cactl` binary, and no `TRUSTEDCA_` environment prefix. The ACME
> admin REST surface is `pkg/acme/admin` (`RegisterRoutes`,
> `pkg/acme/admin/handlers.go:97`), mounted under `/admin` (not
> `/api/v1` as the examples below show) on `xkmsd`'s own unified
> listener by `cmd/xkmsd/admin.go:finalizeAdminModule` — not a
> standalone `--admin-enabled` flag. The real CLI is `xkmsctl acme`
> (`docs/acme-issuance/cli.md`). This page's other REST examples are
> otherwise unverified against the current route table.

## Overview

The REST API provides standard HTTP-based access to all Admin operations. It's the most universally compatible protocol, supporting web browsers, curl, and any HTTP client.

## Connection

| Property | Value |
|----------|-------|
| Protocol | HTTP/1.1, HTTP/2 |
| Default Port | 8443 |
| Transport | TCP with TLS |
| Content-Type | `application/json` |

## Configuration

### Server

Unverified — see the correction above.

### Client (`xkmsctl acme`)

```bash
xkmsctl acme --acme-server https://localhost:8443 status
```

## Authentication

### Authorization

Every request is authenticated (JWT or mTLS client certificate) and then
authorized against the hosted go-qrdb node's RBAC service. There is no
development bypass: a request with no identity is refused with 401.

### mTLS (Production)

Configure client certificates for passwordless authentication:

```bash
# Server-side mTLS setup is unverified — see the correction above.

# Client with certificate
curl --cert client.crt --key client.key --cacert ca.crt \
  https://localhost:8443/api/v1/status
```

## API Endpoints

### Base URL

```
https://{host}:{port}/api/v1
```

### Status Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Get CA status |
| GET | `/stats` | Get CA statistics |

### Certificate Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/certificates` | List certificates |
| GET | `/certificates/{serial}` | Get certificate by serial |
| POST | `/certificates/{serial}/revoke` | Revoke certificate |

### Account Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts` | List accounts |
| GET | `/accounts/{id}` | Get account by ID |
| POST | `/accounts/{id}/disable` | Disable account |

### Tenant Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants` | Create tenant |
| GET | `/tenants` | List tenants |
| GET | `/tenants/{id}` | Get tenant |
| PUT | `/tenants/{id}` | Update tenant |
| DELETE | `/tenants/{id}` | Delete tenant |

### EAB Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants/{id}/eab` | Create EAB |
| GET | `/tenants/{id}/eab` | List EABs |
| GET | `/tenants/{id}/eab/{eabId}` | Get EAB |
| DELETE | `/tenants/{id}/eab/{eabId}` | Delete EAB |

### Policy Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants/{id}/policies` | Create policy |
| GET | `/tenants/{id}/policies` | List policies |
| GET | `/tenants/{id}/policies/{policyId}` | Get policy |
| PUT | `/tenants/{id}/policies/{policyId}` | Update policy |
| DELETE | `/tenants/{id}/policies/{policyId}` | Delete policy |

## Request/Response Format

### Request Headers

```http
Content-Type: application/json
Accept: application/json
```

### Success Response

```json
{
  "data": { ... },
  "meta": {
    "requestId": "uuid",
    "timestamp": "2025-01-12T12:00:00Z"
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Certificate not found",
    "details": { ... }
  },
  "meta": {
    "requestId": "uuid",
    "timestamp": "2025-01-12T12:00:00Z"
  }
}
```

### Pagination

List endpoints support pagination:

```bash
GET /api/v1/certificates?limit=50&offset=0
```

Response includes pagination metadata:

```json
{
  "data": [ ... ],
  "pagination": {
    "total": 150,
    "limit": 50,
    "offset": 0,
    "hasMore": true
  }
}
```

## Examples

### Get CA Status

```bash
curl -X GET https://localhost:8443/api/v1/status \
  --cert client.crt --key client.key --cacert ca.crt
```

Response:

```json
{
  "data": {
    "status": "running",
    "version": "0.1.0",
    "uptime": "24h15m30s",
    "certificatesIssued": 1234,
    "certificatesRevoked": 12
  }
}
```

### List Certificates

```bash
curl -X GET "https://localhost:8443/api/v1/certificates?limit=10" \
  --cert client.crt --key client.key --cacert ca.crt
```

### Create Tenant

```bash
curl -X POST https://localhost:8443/api/v1/tenants \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example-tenant",
    "displayName": "Example Tenant",
    "contactEmail": "admin@example.com"
  }'
```

### Revoke Certificate

```bash
curl -X POST https://localhost:8443/api/v1/certificates/ABC123/revoke \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"reason": 1}'
```

## OpenAPI Specification

The REST API is documented with OpenAPI 3.0. Access the specification at:

- **Swagger UI**: `https://localhost:8443/docs`
- **OpenAPI JSON**: `https://localhost:8443/openapi/admin-api`

## Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `BAD_REQUEST` | Invalid request format |
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Insufficient permissions |
| 404 | `NOT_FOUND` | Resource not found |
| 409 | `CONFLICT` | Resource already exists |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error |

## Rate Limiting

The REST API enforces rate limiting per client IP. When exceeded:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

## See Also

- [Protocol Overview](README.md)
- [gRPC Protocol](grpc.md)
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
