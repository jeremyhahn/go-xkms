# Admin API Reference

Complete REST API reference for the go-xkms Admin API. For the full OpenAPI specification, see [openapi.yaml](../api/openapi.yaml).

## Overview

**Base URLs:**
- Production: `https://ca.example.com`
- Staging: `https://ca-staging.example.com`
- Development: `http://localhost:8443`

**Authentication:**
All endpoints require Bearer token authentication:
```
Authorization: Bearer <jwt_token>
```

**Content Type:**
All requests and responses use JSON:
```
Content-Type: application/json
```

---

## Certificate Management

### List Certificates

Retrieves a paginated list of certificates.

```
GET /admin/certificates
```

**Required Role:** viewer

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page (max: 100) |
| `status` | string | - | Filter: valid, revoked, expired |
| `subject` | string | - | Filter by subject (partial match) |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/certificates?status=valid&page=1&per_page=20"
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "serial_number": "123456789012345678901234567890",
      "subject": "CN=example.com,O=Example Corp",
      "issuer": "CN=Intermediate CA,O=Trusted CA",
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2026-01-01T00:00:00Z",
      "status": "valid",
      "issued_at": "2025-01-01T00:00:00Z",
      "cert_url": "https://ca.example.com/certs/123456789012345678901234567890"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 150
  }
}
```

---

### List Expiring Certificates

Retrieves certificates expiring within the specified number of days.

```
GET /admin/certificates/expiring
```

**Required Role:** viewer

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Days until expiration (1-365) |
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/certificates/expiring?days=30"
```

---

### Get Certificate

Retrieves a certificate by serial number.

```
GET /admin/certificates/{serial}
```

**Required Role:** viewer

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `serial` | string | Certificate serial number |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/certificates/123456789012345678901234567890"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "serial_number": "123456789012345678901234567890",
    "subject": "CN=example.com,O=Example Corp",
    "issuer": "CN=Intermediate CA,O=Trusted CA",
    "not_before": "2025-01-01T00:00:00Z",
    "not_after": "2026-01-01T00:00:00Z",
    "status": "valid",
    "issued_at": "2025-01-01T00:00:00Z",
    "cert_url": "https://ca.example.com/certs/123456789012345678901234567890"
  }
}
```

**Error Response (404):**
```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "Certificate not found"
  }
}
```

---

### Revoke Certificate

Revokes a certificate by serial number.

```
POST /admin/certificates/{serial}/revoke
```

**Required Role:** admin

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `serial` | string | Certificate serial number |

**Request Body:**
```json
{
  "reason": "keyCompromise"
}
```

**Revocation Reasons (RFC 5280):**

| Reason | Description |
|--------|-------------|
| `unspecified` | No specific reason |
| `keyCompromise` | Private key compromised |
| `caCompromise` | CA private key compromised |
| `affiliationChanged` | Subject affiliation changed |
| `superseded` | Certificate superseded |
| `cessationOfOperation` | Subject no longer needs certificate |
| `certificateHold` | Certificate temporarily suspended |
| `removeFromCRL` | Remove from CRL (delta CRLs only) |
| `privilegeWithdrawn` | Privileges withdrawn |
| `aaCompromise` | Attribute authority compromised |

**Example Request:**
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}' \
  "https://ca.example.com/admin/certificates/123456789/revoke"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Certificate revoked successfully"
  }
}
```

---

## Account Management

### List Accounts

Retrieves a paginated list of ACME accounts.

```
GET /admin/accounts
```

**Required Role:** viewer

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |
| `status` | string | - | Filter: valid, deactivated, revoked |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/accounts?status=valid"
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "status": "valid",
      "contact": ["mailto:admin@example.com"],
      "created_at": "2025-01-01T00:00:00Z",
      "terms_of_service_agreed": true,
      "orders_url": "https://ca.example.com/acme/accounts/1/orders",
      "order_count": 5
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 100
  }
}
```

---

### Get Account

Retrieves an ACME account by ID.

```
GET /admin/accounts/{id}
```

**Required Role:** viewer

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | integer | Account ID |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/accounts/1"
```

---

### Disable Account

Disables an ACME account.

```
DELETE /admin/accounts/{id}
```

**Required Role:** admin

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | integer | Account ID |

**Example Request:**
```bash
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/accounts/1"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Account disabled successfully"
  }
}
```

---

## Order Management

### List Orders

Retrieves a paginated list of ACME orders.

```
GET /admin/orders
```

**Required Role:** viewer

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |
| `status` | string | - | Filter: pending, ready, processing, valid, invalid |
| `account_id` | integer | - | Filter by account ID |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/orders?status=valid&account_id=1"
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "account_id": 1,
      "status": "valid",
      "identifiers": ["example.com", "www.example.com"],
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2025-04-01T00:00:00Z",
      "expires": "2025-01-08T00:00:00Z",
      "certificate": "https://ca.example.com/acme/certs/123",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 50
  }
}
```

---

### Get Order

Retrieves an ACME order by ID.

```
GET /admin/orders/{id}
```

**Required Role:** viewer

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `account_id` | integer | Yes | Account ID that owns the order |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/orders/1?account_id=1"
```

---

## Status and Statistics

### Get CA Status

Retrieves the current CA operational status.

```
GET /admin/status
```

**Required Role:** viewer

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/status"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "identity": "Trusted CA Root",
    "initialized": true,
    "version": "1.0.0",
    "started_at": "2025-01-01T00:00:00Z",
    "key_algorithm": "ECDSA-P384",
    "signature_algorithm": "SHA384-ECDSA",
    "root_ca": "CN=Trusted CA Root,O=Trusted CA",
    "intermediate_ca": "CN=Trusted CA Intermediate,O=Trusted CA"
  }
}
```

---

### Get CA Statistics

Retrieves aggregate statistics about the CA.

```
GET /admin/stats
```

**Required Role:** viewer

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/admin/stats"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "total_certificates": 1500,
    "valid_certificates": 1200,
    "revoked_certificates": 100,
    "expired_certificates": 200,
    "total_accounts": 500,
    "active_accounts": 450,
    "total_orders": 2000,
    "pending_orders": 10,
    "completed_orders": 1990
  }
}
```

---

## Tenant Management

### List Tenants

Retrieves a paginated list of tenants.

```
GET /api/v1/tenants
```

**Required Role:** super-admin

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |
| `status` | string | - | Filter: active, suspended, deleted |

**Example Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://ca.example.com/api/v1/tenants?status=active"
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "acme-corp",
      "name": "ACME Corporation",
      "status": "active",
      "root_ca": {
        "common_name": "ACME Corp Root CA",
        "serial_number": "123456",
        "key_algorithm": "ECDSA",
        "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2035-01-01T00:00:00Z",
        "status": "active",
        "created_at": "2025-01-01T00:00:00Z"
      },
      "intermediate_cas": [],
      "default_intermediate_ca_id": "ca-abc123",
      "settings": {
        "max_certificates": 1000,
        "max_accounts": 100,
        "allowed_key_algorithms": ["RSA", "ECDSA", "Ed25519"],
        "allowed_challenge_types": ["http-01", "dns-01", "device-attest-01"],
        "certificate_validity_days": 90,
        "require_eab": true,
        "allow_endorse_01": true,
        "allow_enroll_01": false
      },
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-01T00:00:00Z",
      "created_by": "admin@example.com"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 10
  }
}
```

---

### Create Tenant

Creates a new tenant.

```
POST /api/v1/tenants
```

**Required Role:** super-admin

**Request Body:**
```json
{
  "id": "acme-corp",
  "name": "ACME Corporation",
  "settings": {
    "max_certificates": 1000,
    "max_accounts": 100,
    "require_eab": true,
    "allow_endorse_01": true,
    "allowed_key_algorithms": ["RSA", "ECDSA"],
    "certificate_validity_days": 90
  }
}
```

**Example Request:**
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "acme-corp",
    "name": "ACME Corporation",
    "settings": {
      "max_certificates": 1000,
      "require_eab": true
    }
  }' \
  "https://ca.example.com/api/v1/tenants"
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "acme-corp",
    "name": "ACME Corporation",
    "status": "active",
    "settings": {
      "max_certificates": 1000,
      "require_eab": true
    },
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
}
```

---

### Get Tenant

Retrieves a tenant by ID.

```
GET /api/v1/tenants/{id}
```

**Required Role:** admin (own tenant) or super-admin (any tenant)

---

### Update Tenant

Updates a tenant.

```
PUT /api/v1/tenants/{id}
```

**Required Role:** admin

**Request Body:**
```json
{
  "name": "ACME Corporation (Updated)",
  "settings": {
    "max_certificates": 2000
  }
}
```

---

### Delete Tenant

Deletes a tenant and all associated resources.

```
DELETE /api/v1/tenants/{id}
```

**Required Role:** super-admin

---

### Update Tenant Status

Updates the status of a tenant.

```
PUT /api/v1/tenants/{id}/status
```

**Required Role:** super-admin

**Request Body:**
```json
{
  "status": "suspended"
}
```

**Valid Statuses:** `active`, `suspended`, `deleted`

---

## Tenant CA Management

### Create Tenant Root CA

Creates a root CA for a tenant.

```
POST /api/v1/tenants/{id}/root-ca
```

**Required Role:** admin

**Request Body:**
```json
{
  "common_name": "ACME Corp Root CA",
  "key_algorithm": "ECDSA",
  "validity_years": 10
}
```

**Key Algorithms:** `RSA`, `ECDSA`, `Ed25519`

---

### List Tenant Intermediate CAs

Lists all intermediate CAs for a tenant.

```
GET /api/v1/tenants/{id}/intermediate-cas
```

**Required Role:** admin

---

### Create Tenant Intermediate CA

Creates an intermediate CA for a tenant.

```
POST /api/v1/tenants/{id}/intermediate-cas
```

**Required Role:** admin

**Request Body:**
```json
{
  "common_name": "ACME Corp Intermediate CA",
  "parent_type": "global",
  "purpose": "server-auth",
  "key_algorithm": "ECDSA",
  "validity_years": 5,
  "set_as_default": true
}
```

**Parent Types:**
- `global`: Signed by the global root CA
- `tenant`: Signed by the tenant's root CA

**CA Purposes:**
- `general`: Default purpose
- `server-auth`: Server authentication certificates
- `client-auth`: Client authentication certificates
- `code-signing`: Code signing certificates
- `tpm-endorsement`: TPM EK certificates

---

### Get Tenant Intermediate CA

Retrieves details of a specific intermediate CA.

```
GET /api/v1/tenants/{id}/intermediate-cas/{caid}
```

**Required Role:** admin

---

### Update Intermediate CA Status

Updates the status of an intermediate CA.

```
PUT /api/v1/tenants/{id}/intermediate-cas/{caid}/status
```

**Required Role:** admin

**Request Body:**
```json
{
  "status": "pending-rotation"
}
```

**Valid Statuses:** `active`, `pending-rotation`, `revoked`

---

### Set Default Intermediate CA

Sets the default intermediate CA for certificate signing.

```
PUT /api/v1/tenants/{id}/default-intermediate-ca
```

**Required Role:** admin

**Request Body:**
```json
{
  "intermediate_ca_id": "ca-abc123"
}
```

---

### Get Tenant CA Status

Retrieves the overall CA status for a tenant.

```
GET /api/v1/tenants/{id}/ca-status
```

**Required Role:** admin

**Response:**
```json
{
  "success": true,
  "data": {
    "tenant_id": "acme-corp",
    "root_ca": {
      "common_name": "ACME Corp Root CA",
      "status": "active"
    },
    "intermediate_cas": [
      {
        "id": "ca-abc123",
        "common_name": "ACME Corp Intermediate CA",
        "status": "active"
      }
    ],
    "default_intermediate_ca_id": "ca-abc123",
    "active_ca_count": 2,
    "can_issue_certificates": true
  }
}
```

---

## EAB Management

### List Tenant EABs

Lists External Account Binding tokens for a tenant.

```
GET /api/v1/tenants/{id}/eab
```

**Required Role:** endorser

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |
| `status` | string | - | Filter: active, used, revoked, expired |
| `purpose` | string | - | Filter: account-binding, endorse-01, enroll-01 |

---

### Create Tenant EAB

Creates an EAB token.

```
POST /api/v1/tenants/{id}/eab
```

**Required Role:** endorser

**Request Body:**
```json
{
  "purpose": "endorse-01",
  "external_account_id": "device-001",
  "device_info": {
    "device_id": "DEV-001",
    "manufacturer": "ACME Inc",
    "model": "SecureDevice-2000",
    "ek_public_key_hash": "sha256:abc123...",
    "tpm_manufacturer": "Infineon",
    "tpm_firmware_version": "7.85"
  },
  "contact": ["mailto:admin@example.com"],
  "expires_in_days": 30,
  "metadata": {
    "department": "Engineering",
    "location": "Building A"
  }
}
```

**EAB Purposes:**

| Purpose | Description |
|---------|-------------|
| `account-binding` | Standard RFC 8555 account binding |
| `endorse-01` | TPM device endorsement (TCG) |
| `enroll-01` | TPM enrollment (TCG) |

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "eab_abc123xyz",
    "mac_key": "dGVzdC1tYWMta2V5LWJhc2U2NA...",
    "algorithm": "HS256",
    "expires_at": "2025-01-31T00:00:00Z"
  }
}
```

**Important:** The `mac_key` is only returned once at creation time. Store it securely.

---

### Get Tenant EAB

Retrieves an EAB token by key ID.

```
GET /api/v1/tenants/{id}/eab/{kid}
```

**Required Role:** endorser

**Note:** The MAC key is not returned (it was only shown at creation).

---

### Delete Tenant EAB

Deletes an EAB token.

```
DELETE /api/v1/tenants/{id}/eab/{kid}
```

**Required Role:** admin

---

## Policy Management

### List Tenant Policies

Lists ABAC policies for a tenant.

```
GET /api/v1/tenants/{id}/policies
```

**Required Role:** admin

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |
| `purpose` | string | - | Filter by policy purpose label |

---

### Create Tenant Policy

Creates an ABAC policy.

```
POST /api/v1/tenants/{id}/policies
```

**Required Role:** admin

**Request Body (RBAC role format):**
```json
{
  "apiVersion": "rbac.trustedca.io/v1",
  "kind": "Policy",
  "metadata": {
    "name": "custom-access-policy",
    "labels": {
      "purpose": "access-control",
      "managed-by": "admin"
    }
  },
  "spec": {
    "subjects": {
      "roles": ["operator"],
      "authenticated": true
    },
    "rules": [
      {
        "name": "allow-read-certificates",
        "effect": "allow",
        "priority": 100,
        "actions": ["read", "list"],
        "resources": ["acme/certificates/**"]
      }
    ]
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "apiVersion": "rbac.trustedca.io/v1",
    "kind": "Policy",
    "metadata": {
      "name": "custom-access-policy",
      "tenant": "acme-corp",
      "created": "2025-01-01T00:00:00Z",
      "updated": "2025-01-01T00:00:00Z"
    },
    "spec": {
      "subjects": {
        "roles": ["operator"],
        "authenticated": true
      },
      "rules": [...]
    }
  }
}
```

---

### Get Tenant Policy

Retrieves a policy by name.

```
GET /api/v1/tenants/{id}/policies/{name}
```

**Required Role:** admin

---

### Update Tenant Policy

Updates an existing policy.

```
PUT /api/v1/tenants/{id}/policies/{name}
```

**Required Role:** admin

**Note:** System-managed (immutable) policies cannot be modified.

---

### Delete Tenant Policy

Deletes a policy.

```
DELETE /api/v1/tenants/{id}/policies/{name}
```

**Required Role:** admin

**Note:** System-managed (immutable) policies cannot be deleted.

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient privileges |
| `NOT_FOUND` | 404 | Resource not found |
| `INVALID_REQUEST` | 400 | Invalid request parameters |
| `INVALID_ID` | 400 | Invalid resource ID format |
| `MISSING_ID` | 400 | Required ID parameter missing |
| `MISSING_NAME` | 400 | Required name parameter missing |
| `MISSING_STATUS` | 400 | Required status parameter missing |
| `MISSING_ACCOUNT_ID` | 400 | Account ID required for order lookup |
| `INVALID_STATUS` | 400 | Invalid status value |
| `INVALID_PURPOSE` | 400 | Invalid EAB purpose |
| `INVALID_PARENT_TYPE` | 400 | Invalid CA parent type |
| `INVALID_VALIDITY` | 400 | Invalid validity period |
| `ALREADY_EXISTS` | 409 | Resource already exists |
| `TENANT_NOT_FOUND` | 404 | Tenant not found |
| `CA_NOT_FOUND` | 404 | CA not found |
| `EAB_NOT_FOUND` | 404 | EAB not found |
| `POLICY_NOT_FOUND` | 404 | Policy not found |
| `POLICY_EXISTS` | 409 | Policy already exists |
| `POLICY_IMMUTABLE` | 403 | Cannot modify system-managed policy |
| `INTERNAL_ERROR` | 500 | Internal server error |

---

## Rate Limits

Default rate limits apply to all endpoints:

| Limit | Value |
|-------|-------|
| Requests per minute | 100 |
| Burst | 20 |

Rate limit headers are included in responses:
```
X-Rate-Limit-Limit: 100
X-Rate-Limit-Remaining: 95
X-Rate-Limit-Reset: 1704067200
```

---

## Pagination

List endpoints support pagination:

| Parameter | Type | Default | Max |
|-----------|------|---------|-----|
| `page` | integer | 1 | - |
| `per_page` | integer | 20 | 100 |

Response includes pagination info:
```json
{
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 150
  }
}
```
