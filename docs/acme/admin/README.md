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

## Roles

The Admin API implements a 5-level hierarchical RBAC system. Higher-level roles inherit all permissions from lower levels.

| Role | Level | Description |
|------|-------|-------------|
| **super-admin** | 100 | Global access: manage all tenants, root CA, system configuration |
| **admin** | 80 | Tenant-level full access: manage tenant CA, users, certificates |
| **endorser** | 60 | Operator permissions plus endorse-01 EAB operations |
| **operator** | 40 | Read and write access, no destructive operations |
| **viewer** | 20 | Read-only access to all resources |

### Role Hierarchy

```
+----------------+
|  super-admin   |  Level: 100 - Global system administrator
|  (Global)      |
+-------+--------+
        |
        v
+----------------+
|     admin      |  Level: 80 - Tenant administrator
|   (Tenant)     |
+-------+--------+
        |
        v
+----------------+
|   endorser     |  Level: 60 - Device provisioning
|   (Device)     |
+-------+--------+
        |
        v
+----------------+
|   operator     |  Level: 40 - Standard operations
|  (Read/Write)  |
+-------+--------+
        |
        v
+----------------+
|    viewer      |  Level: 20 - Read-only access
|  (Read-Only)   |
+----------------+
```

### Permission Matrix

| Operation | super-admin | admin | endorser | operator | viewer |
|-----------|:-----------:|:-----:|:--------:|:--------:|:------:|
| Manage tenants | X | - | - | - | - |
| Manage root CA | X | - | - | - | - |
| System configuration | X | - | - | - | - |
| Manage tenant CA | X | X | - | - | - |
| Create intermediate CA | X | X | - | - | - |
| Manage RBAC policies | X | X | - | - | - |
| Create EAB (all types) | X | X | X | - | - |
| Revoke certificates | X | X | - | - | - |
| Disable accounts | X | X | - | - | - |
| Create/update resources | X | X | X | X | - |
| Read/list resources | X | X | X | X | X |

## RBAC Policies (CEL)

RBAC policies are defined using the Common Expression Language (CEL) and stored in QRDB IAM. Policies provide fine-grained access control beyond the hierarchical RBAC roles.

### Policy Structure

```yaml
apiVersion: rbac.qrdb.io/v1
kind: Policy
metadata:
  name: policy-name
  tenant: tenant-id
  description: "Policy description"
  priority: 100
  labels:
    purpose: access-control
    managed: system
spec:
  subjects:
    authenticated: true
    roles: ["admin", "endorser"]
    groups: ["engineering"]
  rules:
    - name: rule-name
      effect: allow
      priority: 100
      actions: ["create", "read"]
      resources: ["acme/tenants/{tenant}/**"]
      when:
        - expression: "time.hour >= 9 && time.hour < 17"
      unless:
        - expression: "subject.roles.exists(r, r == 'super-admin')"
```

### CEL Expression Examples

| Expression | Description |
|------------|-------------|
| `subject.tenant_id == 'acme-corp'` | Match specific tenant |
| `subject.roles.exists(r, r == 'admin')` | Check for role membership |
| `request.ip.startsWith('10.0.')` | IP prefix matching |
| `time.hour >= 9 && time.hour < 17` | Business hours restriction |
| `resource.path.matches('/api/v1/tenants/.*')` | Resource path matching |
| `subject.groups.size() > 0` | Check group membership |

### Default Policies

When a tenant is created, QRDB automatically provisions default policies:

1. **Tenant Isolation Policy** (priority: 9999)
   - Allows access to own tenant resources
   - Denies cross-tenant access except for super-admin

2. **EAB Creation Policy** (priority: 100)
   - Allows super-admin, admin, and endorser to create EAB tokens

3. **Endorse-01 Policy** (priority: 150)
   - Allows endorser role to create endorse-01 EAB tokens for TPM enrollment

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

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/admin/certificates` | GET | viewer | List all certificates |
| `/admin/certificates/expiring` | GET | viewer | List expiring certificates |
| `/admin/certificates/{serial}` | GET | viewer | Get certificate by serial |
| `/admin/certificates/{serial}/revoke` | POST | admin | Revoke certificate |
| `/admin/accounts` | GET | viewer | List all accounts |
| `/admin/accounts/{id}` | GET | viewer | Get account details |
| `/admin/accounts/{id}` | DELETE | admin | Disable account |
| `/admin/orders` | GET | viewer | List all orders |
| `/admin/orders/{id}` | GET | viewer | Get order details |
| `/admin/status` | GET | viewer | CA status |
| `/admin/stats` | GET | viewer | CA statistics |

### Tenant Management (`/api/v1/tenants`)

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/tenants` | GET | super-admin | List tenants |
| `/api/v1/tenants` | POST | super-admin | Create tenant |
| `/api/v1/tenants/{id}` | GET | admin | Get tenant |
| `/api/v1/tenants/{id}` | PUT | admin | Update tenant |
| `/api/v1/tenants/{id}` | DELETE | super-admin | Delete tenant |
| `/api/v1/tenants/{id}/status` | PUT | super-admin | Update status |

### Tenant CA Management

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/tenants/{id}/root-ca` | POST | admin | Create root CA |
| `/api/v1/tenants/{id}/intermediate-cas` | GET | admin | List intermediate CAs |
| `/api/v1/tenants/{id}/intermediate-cas` | POST | admin | Create intermediate CA |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}` | GET | admin | Get intermediate CA |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}/status` | PUT | admin | Update CA status |
| `/api/v1/tenants/{id}/default-intermediate-ca` | PUT | admin | Set default CA |
| `/api/v1/tenants/{id}/ca-status` | GET | admin | Get CA status |

### EAB Management (QRDB Storage)

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/tenants/{id}/eab` | GET | endorser | List EABs |
| `/api/v1/tenants/{id}/eab` | POST | endorser | Create EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | GET | endorser | Get EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | DELETE | admin | Delete EAB |

EAB tokens are stored in QRDB using the KV storage layer with the key pattern: `tenants/{tenant_id}/eab/{kid}`.

### Policy Management (QRDB RBAC)

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
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

- [ACME API Documentation](../acme/README.md) - RFC 8555 ACME protocol
- [QRDB Storage](../qrdb/) - KV storage and RBAC backend
- [OpenAPI Specification](../api/openapi.yaml) - Complete API specification
