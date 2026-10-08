# Admin API

REST API for administrative operations on the ACME Certificate Authority.

## Overview

The Admin API provides comprehensive management capabilities for the go-xkms Certificate Authority. It enables enterprise administrators to manage certificates, accounts, orders, tenants, External Account Bindings (EAB), and RBAC policies through a secure, role-based interface.

The Admin API is separate from the RFC 8555 ACME API and is designed for human operators and administrative automation systems rather than ACME clients.

## Key Features

| Feature | Description |
|---------|-------------|
| **Certificate Management** | List, view, revoke, and monitor certificate expiration |
| **Account Management** | List, view, and disable ACME accounts |
| **Order Management** | List and view certificate orders with filtering |
| **Multi-Tenancy** | Complete tenant isolation with per-tenant CAs and policies |
| **EAB Management** | External Account Binding for TPM device enrollment |
| **RBAC Policies** | Role-Based Access Control via QRDB IAM PolicyEngine |
| **Role-Based Access** | 5-level hierarchical RBAC with fine-grained permissions |
| **JWT Authentication** | QRDB Auth integration with bearer tokens |
| **CA Monitoring** | Real-time status and statistics endpoints |

## Storage and Auth Integration

The Admin API uses QRDB for KV storage and RBAC/auth services. QRDB runs embedded (in-process) with go-xkms.

```
+-----------------------------------------------------------------------+
|                         Admin API                                      |
|                                                                       |
|  +---------------------------+  +---------------------------+         |
|  |     HTTP Handlers         |  |     Middleware            |         |
|  |  - Tenant Handlers        |  |  - AuthMiddleware         |         |
|  |  - Policy Handlers        |  |  - AuthzMiddleware        |         |
|  |  - Admin Handlers         |  |  - RequireRole            |         |
|  +-------------+-------------+  +-------------+-------------+         |
|                |                              |                       |
|                v                              v                       |
|  +----------------------------------------------------------------+   |
|  |                                                                |   |
|  |  +-----------------+  +-----------------+  +--------------+    |   |
|  |  | QRDB KV Storage |  | QRDB RBAC/IAM  |  | QRDB Auth    |    |   |
|  |  |                 |  |   PolicyEngine  |  |              |    |   |
|  |  | - Tenants       |  |                 |  |              |    |   |
|  |  | - EAB tokens    |  | - RBAC roles    |  | - JWT valid  |    |   |
|  |  | - Accounts      |  | - RBAC policies |  | - Token mgmt |    |   |
|  |  | - Orders        |  | - CEL rules     |  |              |    |   |
|  |  +-----------------+  +-----------------+  +--------------+    |   |
|  |                                                                |   |
|  +----------------------------------------------------------------+   |
|                                                                       |
+-----------------------------------------------------------------------+
```

### Storage Layer

The Admin API uses the QRDB DAO (Data Access Object) layer for persistent storage and QRDB RBAC for IAM:

| Entity | Storage Backend | Description |
|--------|-----------------|-------------|
| **Tenants** | QRDB KV | Tenant metadata, settings, and configuration |
| **EAB Tokens** | QRDB KV | External Account Binding credentials |
| **ACME Accounts** | QRDB KV | ACME client account data |
| **Orders** | QRDB KV | Certificate order state and metadata |
| **RBAC Policies** | QRDB IAM | Policy definitions |

### Authentication

JWT tokens are validated via the QRDB Auth client:

```go
// QRDB Auth integration
type AuthMiddleware struct {
    client auth.Client
}

func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := extractBearerToken(r)

        // Validate token via QRDB Auth
        claims, err := am.client.ValidateToken(r.Context(), token)
        if err != nil {
            writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid token")
            return
        }

        // Extract user context from claims
        user := &User{
            UserID:   claims.Subject,
            TenantID: claims.TenantID,
            Roles:    claims.Roles,
            Groups:   claims.Groups,
        }

        ctx := context.WithValue(r.Context(), ContextKeyUser, user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### Authorization (PolicyEngine)

The Admin API uses QRDB's IAM PolicyEngine for RBAC authorization:

```go
// QRDB IAM PolicyEngine integration
type AuthorizationMiddleware struct {
    policyEngine *iam.PolicyEngine
}

func (am *AuthorizationMiddleware) Authorize(action, resource string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := GetUserFromContext(r.Context())

            // Build IAM check request
            checkReq := &iam.CheckRequest{
                Subject: iam.Subject{
                    ID:       user.UserID,
                    TenantID: user.TenantID,
                    Roles:    user.Roles,
                    Groups:   user.Groups,
                },
                Resource: resource,
                Action:   action,
                Context:  buildRequestContext(r),
            }

            // Evaluate against QRDB PolicyEngine
            response, err := am.policyEngine.Evaluate(r.Context(), checkReq)
            if err != nil || !response.Allowed {
                writeError(w, http.StatusForbidden, "FORBIDDEN", response.Reason)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

## Authorization

The Admin API delegates every authorization decision to the hosted go-qrdb
node's RBAC service through the xkms `auth.Authorizer` — the same seam the xkms
REST, gRPC, QUIC, and MCP transports use. It defines no roles and no permissions
of its own, so a grant means the same thing here as it does everywhere else in
the stack.

The canonical roles are go-qrdb's six FIPS 140-3 / PCI-DSS v4 system roles:
`so`, `admin`, `operator`, `user`, `auditor`, `custodian`. The previous
ACME-local hierarchy (`super-admin` / `admin` / `endorser` / `operator` /
`viewer`) was removed; it shared no members with the qrdb roles, so granting or
revoking `admin` in qrdb had no effect on the Admin API.

| Role | ACME admin reach |
|---|---|
| `so` | Full: CA hierarchy, ACME accounts / orders / EABs, barrier governance, role management |
| `admin` | Full ACME administration; CA hierarchy; tenant, user, certificate, and EAB lifecycle |
| `operator` | Read-only ACME registration data and CA hierarchy; barrier seal/unseal/status |
| `user` | None |
| `auditor` | Read-only registration metadata, CA hierarchy, certificates, tenants, audit trail |
| `custodian` | `barrier:unseal-share` only |

Cross-tenant reach follows qrdb's system-tenant rule: an identity rooted in the
reserved system tenant, or one carrying no tenant at all (empty `TenantID` --
the bootstrap case), is platform-scoped; any other identity is confined to its
own tenant (`auth.IsCrossTenant`). That is the authority the deleted
`super-admin` role used to carry.

The `endorser` role expressed exactly one authority — minting External Account
Bindings. A deployment that needs an endorse-only principal creates a qrdb role
holding `acme_eab:create` and nothing else.

See [authorization.md](authorization.md) for the complete
operation-to-permission mapping across REST, gRPC, and MCP.

## Quick Start

### Authentication

All Admin API requests require a JWT token from QRDB Auth:

```bash
# Obtain a token from QRDB Auth
TOKEN=$(curl -s -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=admin-client" \
  -d "client_secret=secret" | jq -r '.access_token')
```

### List Certificates

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://ca.example.com/admin/certificates
```

### Get Certificate Details

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://ca.example.com/admin/certificates/123456789
```

### Revoke Certificate (Admin Required)

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}' \
  https://ca.example.com/admin/certificates/123456789/revoke
```

### List Expiring Certificates

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/certificates/expiring?days=30"
```

### Get CA Statistics

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://ca.example.com/admin/stats
```

### Create Tenant (Super-Admin Required)

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "acme-corp",
    "name": "ACME Corporation",
    "settings": {
      "max_certificates": 1000,
      "require_eab": true,
      "allow_endorse_01": true
    }
  }' \
  https://ca.example.com/api/v1/tenants
```

### Create EAB for Device Enrollment (Endorser Required)

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "endorse-01",
    "device_info": {
      "device_id": "DEV-001",
      "manufacturer": "ACME Inc",
      "model": "SecureDevice-2000"
    },
    "expires_in_days": 30
  }' \
  https://ca.example.com/api/v1/tenants/acme-corp/eab
```

### Create RBAC Policy (Admin Required)

```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "rbac.qrdb.io/v1",
    "kind": "Policy",
    "metadata": {
      "name": "business-hours-restriction",
      "description": "Restrict sensitive ops to business hours"
    },
    "spec": {
      "subjects": {
        "roles": ["operator"]
      },
      "rules": [
        {
          "name": "deny-outside-hours",
          "effect": "deny",
          "actions": ["create", "delete"],
          "resources": ["acme/tenants/acme-corp/**"],
          "when": [
            {"expression": "time.hour < 9 || time.hour >= 17"}
          ]
        }
      ]
    }
  }' \
  https://ca.example.com/api/v1/tenants/acme-corp/policies
```

## Response Format

### Success Response

```json
{
  "success": true,
  "data": {...},
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 100
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "Certificate not found"
  }
}
```

## Pagination

List endpoints support pagination via query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `page` | 1 | Page number (1-indexed) |
| `per_page` | 20 | Results per page (max: 100) |

Example:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/certificates?page=2&per_page=50"
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Admin API architecture and components |
| [Authorization](authorization.md) | RBAC hierarchy and policy system |
| [Configuration](configuration.md) | Complete configuration reference |
| [API Reference](api-reference.md) | Complete endpoint documentation |

## API Endpoints Summary

### Core Admin Endpoints (`/admin`)

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/admin/certificates` | GET | `certs:list` | List all certificates |
| `/admin/certificates/expiring` | GET | viewer | List expiring certificates |
| `/admin/certificates/{serial}` | GET | viewer | Get certificate by serial |
| `/admin/certificates/{serial}/revoke` | POST | admin | Revoke certificate |
| `/admin/accounts` | GET | viewer | List all accounts |
| `/admin/accounts/{id}` | GET | viewer | Get account details |
| `/admin/accounts/{id}` | DELETE | admin | Disable account |
| `/admin/orders` | GET | `acme_orders:list` | List all orders |
| `/admin/orders/{id}` | GET | `acme_orders:read` | Get order details |
| `/admin/status` | GET | `admin:status` | CA status |
| `/admin/stats` | GET | `admin:status` | CA statistics |

### Tenant Management (`/api/v1/tenants`)

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/tenants` | GET | `tenants:list` | List tenants |
| `/api/v1/tenants` | POST | `tenants:create` | Create tenant |
| `/api/v1/tenants/{id}` | GET | `tenants:read` | Get tenant |
| `/api/v1/tenants/{id}` | PUT | `tenants:update` | Update tenant |
| `/api/v1/tenants/{id}` | DELETE | `tenants:delete` | Delete tenant |
| `/api/v1/tenants/{id}/status` | PUT | `tenants:update` | Update status |

### Tenant CA Management

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/tenants/{id}/root-ca` | POST | `ca:create` | Create root CA |
| `/api/v1/tenants/{id}/intermediate-cas` | GET | `ca:list` | List intermediate CAs |
| `/api/v1/tenants/{id}/intermediate-cas` | POST | `ca:create` | Create intermediate CA |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}` | GET | `ca:read` | Get intermediate CA |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}/status` | PUT | `ca:update` | Update CA status |
| `/api/v1/tenants/{id}/default-intermediate-ca` | PUT | `ca:update` | Set default CA |
| `/api/v1/tenants/{id}/ca-status` | GET | `ca:read` | Get CA status |

### EAB Management (QRDB Storage)

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/tenants/{id}/eab` | GET | `acme_eab:list` | List EABs |
| `/api/v1/tenants/{id}/eab` | POST | `acme_eab:create` | Create EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | GET | `acme_eab:read` | Get EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | DELETE | `acme_eab:delete` | Delete EAB |

EAB tokens are stored in QRDB using the KV storage layer with the key pattern: `tenants/{tenant_id}/eab/{kid}`.

### Policy Management (QRDB RBAC)

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/tenants/{id}/policies` | GET | admin | List policies |
| `/api/v1/tenants/{id}/policies` | POST | admin | Create policy |
| `/api/v1/tenants/{id}/policies/{name}` | GET | admin | Get policy |
| `/api/v1/tenants/{id}/policies/{name}` | PUT | admin | Update policy |
| `/api/v1/tenants/{id}/policies/{name}` | DELETE | admin | Delete policy |

Policy operations delegate directly to the QRDB RBAC PolicyEngine.

## Service Interfaces

The Admin API accesses QRDB for storage and RBAC/auth:

```go
// QRDB provides KV storage operations
type QRDBService interface {
    // KV returns the key-value client for storage operations.
    KV() KVClient

    // Healthy returns true if the service is healthy.
    Healthy() bool
}

// QRDB provides IAM and auth services
type QRDBAuthService interface {
    // Auth returns the authentication client for token validation.
    Auth() auth.Client

    // IAM returns the policy engine for RBAC policy management.
    IAM() *iam.PolicyEngine
}
```

## Security Considerations

- Always use TLS in production to protect tokens in transit
- Rotate JWT tokens regularly (configure short expiration times)
- Use separate service accounts for different applications
- Follow the principle of least privilege when assigning roles
- Monitor API access logs for suspicious activity
- Enable audit logging for compliance requirements
- Use QRDB's RBAC policies for fine-grained access control
- System-managed policies (tenant isolation) are immutable

## Related Documentation

- [ACME API Documentation](../README.md) - RFC 8555 ACME protocol
- [Datastore](../../datastore/architecture.md) - KV storage and RBAC backend
- [OpenAPI Specification](../../acme-issuance/api.md#interactive-documentation-swagger-ui) - `GET /openapi/admin-api.yaml` on a running deployment, or `pkg/acme/api/swagger/openapi/admin-api.yaml` in the source tree
