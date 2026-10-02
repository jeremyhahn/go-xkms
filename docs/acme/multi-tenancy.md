# Multi-Tenancy

go-xkms supports multi-tenant deployments where each tenant has isolated data, dedicated CA hierarchy, and independent configuration.

## Overview

Multi-tenancy enables:
- **Data isolation**: Each tenant's accounts, orders, and certificates are segregated
- **CA isolation**: Per-tenant intermediate CAs under global or tenant root CA
- **Cryptographic isolation**: Tenant-specific Data Encryption Keys (DEKs)
- **Configuration isolation**: Per-tenant settings and rate limits
- **User isolation**: Tenant-scoped RBAC with QRDB IAM (policy engine)

## Tenant Model

### Tenant Structure

```go
type Tenant struct {
    ID                      string
    Name                    string
    Status                  string  // active, suspended, deleted
    DEKKeyID                string  // XKMS key ID for tenant data encryption
    RootCA                  *TenantRootCA        // optional
    IntermediateCAs         []*TenantIntermediateCA
    DefaultIntermediateCAID string
    Settings                *TenantSettings
    CreatedAt               time.Time
    UpdatedAt               time.Time
}
```

### Tenant Status

| Status | Description |
|--------|-------------|
| `active` | Tenant is operational, can issue certificates |
| `suspended` | Tenant is suspended, cannot issue new certificates |
| `deleted` | Tenant is soft-deleted, data retained for audit |

## CA Hierarchy

Tenants can operate with two CA hierarchy models:

### Model 1: Global Root CA (Default)

```
Global Root CA (managed by a system-tenant `so` / `admin`)
+-- Tenant A Intermediate CA
+-- Tenant B Intermediate CA
+-- Tenant C Intermediate CA
```

Use case: Simplified management, single trust anchor.

### Model 2: Tenant Root CA

```
Global Root CA
+-- (unused by tenant)

Tenant B Root CA (tenant-managed)
+-- Tenant B Intermediate CA
```

Use case: Full CA independence, tenant-controlled trust anchor.

## Multiple Intermediate CAs

Each tenant can have multiple intermediate CAs for:
- **Key rotation**: Smooth transition to new keys
- **Purpose separation**: Different CAs for different certificate types
- **Compliance**: Separate CAs for regulatory requirements

### CA Purposes

| Purpose | Description | Use Case |
|---------|-------------|----------|
| `general` | Default purpose | Standard TLS certificates |
| `server-auth` | Server authentication | Web servers, APIs |
| `client-auth` | Client authentication | mTLS, device identity |
| `code-signing` | Code signing | Software distribution |
| `tpm-endorsement` | TPM EK certificates | endorse-01 challenge |

### Default CA Selection

When issuing certificates, the CA is selected:
1. If `DefaultIntermediateCAID` is set, use that CA
2. Otherwise, use the first `active` CA in the list

## API Endpoints

### Tenant Management

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/tenants` | POST | `tenants:create` | Create tenant |
| `/api/v1/tenants` | GET | `tenants:list` | List tenants |
| `/api/v1/tenants/{id}` | GET | `tenants:read` | Get tenant |
| `/api/v1/tenants/{id}` | PUT | `tenants:update` | Update tenant |
| `/api/v1/tenants/{id}` | DELETE | `tenants:delete` | Delete tenant |
| `/api/v1/tenants/{id}/status` | PUT | `tenants:update` | Update status |

### Tenant CA Management

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/tenants/{id}/root-ca` | POST | `ca:create` | Create tenant root CA |
| `/api/v1/tenants/{id}/intermediate-cas` | GET | `ca:list` | List intermediate CAs |
| `/api/v1/tenants/{id}/intermediate-cas` | POST | `ca:create` | Create intermediate CA |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}` | GET | `ca:read` | Get CA details |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}/status` | PUT | `ca:update` | Update CA status |
| `/api/v1/tenants/{id}/default-intermediate-ca` | PUT | `ca:update` | Set default CA |
| `/api/v1/tenants/{id}/ca-status` | GET | `ca:read` | Get CA status |

### Tenant EAB Management

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/api/v1/tenants/{id}/eab` | GET | `acme_eab:list` | List EABs |
| `/api/v1/tenants/{id}/eab` | POST | `acme_eab:create` | Create EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | GET | `acme_eab:read` | Get EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | DELETE | `acme_eab:delete` | Delete EAB |

## Tenant Settings

```go
type TenantSettings struct {
    MaxCertificates         int       // 0 = unlimited
    MaxAccounts             int       // 0 = unlimited
    AllowedKeyAlgorithms    []string  // empty = all allowed
    AllowedChallengeTypes   []string  // empty = all allowed
    CertificateValidityDays int
    RequireEAB              bool
    AllowEndorse01          bool
    AllowEnroll01           bool
    CustomMetadata          map[string]string
}
```

## Examples

### Create Tenant

```bash
curl -X POST \
  -H "Authorization: Bearer ${SUPER_ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "acme-corp",
    "name": "ACME Corporation",
    "settings": {
      "max_certificates": 10000,
      "require_eab": true,
      "allow_endorse_01": true,
      "allowed_key_algorithms": ["EC-P384", "RSA-4096"]
    }
  }' \
  https://ca.example.com/api/v1/tenants
```

### Create Tenant Intermediate CA

```bash
# Create general-purpose CA
curl -X POST \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "ACME Corp Intermediate CA",
    "parent_type": "global",
    "key_algorithm": "EC-P384",
    "validity_years": 10,
    "purpose": "general",
    "set_as_default": true
  }' \
  https://ca.example.com/api/v1/tenants/acme-corp/intermediate-cas

# Create TPM endorsement CA
curl -X POST \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "ACME Corp TPM Endorsement CA",
    "parent_type": "global",
    "key_algorithm": "EC-P384",
    "validity_years": 10,
    "purpose": "tpm-endorsement"
  }' \
  https://ca.example.com/api/v1/tenants/acme-corp/intermediate-cas
```

### Create EAB for endorse-01

```bash
curl -X POST \
  -H "Authorization: Bearer ${ENDORSEMENT_ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "endorse-01",
    "device_info": {
      "device_id": "device-001",
      "manufacturer": "ACME Devices",
      "model": "SecureModule-X",
      "ek_public_key_hash": "<hex SHA-256 of the device EK public key, PKIX DER>"
    },
    "expires_in_days": 30
  }' \
  https://ca.example.com/api/v1/tenants/acme-corp/eab
```

`ek_public_key_hash` names the EK the binding authorizes. endorse-01 requires
EAB by default and refuses a binding that names no EK, because endorse-01
holds no proof that the account holds the key it asks to have certified.
See [challenges.md](challenges.md#endorse-01-challenge).

## Data Encryption

### Tenant DEK Isolation

Each tenant has a dedicated Data Encryption Key (DEK) managed by go-xkms:

```
Cluster Master Key (Shamir's Secret Sharing)
+-- Cluster DEK
    +-- Tenant A DEK -> encrypts Tenant A data
    +-- Tenant B DEK -> encrypts Tenant B data
    +-- Tenant C DEK -> encrypts Tenant C data
```

Benefits:
- Cryptographic isolation between tenants
- Per-tenant key rotation
- Secure multi-tenant storage

### Storage Key Patterns

```
tenants/{tenant_id}/acme/accounts/{account_id}
tenants/{tenant_id}/acme/orders/{order_id}
tenants/{tenant_id}/acme/authorizations/{authz_id}
tenants/{tenant_id}/acme/challenges/{challenge_id}
tenants/{tenant_id}/acme/certificates/{cert_serial}
tenants/{tenant_id}/acme/eab/{kid}
tenants/{tenant_id}/ca/root
tenants/{tenant_id}/ca/intermediate/{ca_id}
```

## RBAC

Authorization is delegated to the hosted go-qrdb node's RBAC service; the ACME
Admin API defines no roles or permissions of its own. The canonical roles are
go-qrdb's six system roles.

| Role | Tenant scope | ACME admin reach |
|------|--------------|------------------|
| `so` | Own tenant (all tenants from the system tenant) | CA hierarchy, ACME accounts / orders / EABs, barrier governance, role management |
| `admin` | Own tenant (all tenants from the system tenant) | Tenant, CA hierarchy, user, certificate, and EAB lifecycle |
| `operator` | Own tenant | Read-only registration data and CA hierarchy |
| `user` | Own tenant | None |
| `auditor` | Own tenant | Read-only metadata plus the audit trail |
| `custodian` | Own tenant | `barrier:unseal-share` only |

Cross-tenant reach is not a role: it follows qrdb's system-tenant rule. An
identity rooted in the reserved system tenant, or one carrying no tenant at
all (empty `TenantID` -- the bootstrap case), is platform-scoped and reaches
every tenant; any other identity is confined to its own (`auth.IsCrossTenant`).
That is the authority the deleted `super-admin` role used to carry.

### Capabilities by permission

| Capability | Permission | Held by |
|------------|------------|---------|
| Create / delete tenant | `tenants:create`, `tenants:delete` | `so`, `admin` |
| Manage tenant CA | `ca:create`, `ca:update` | `so`, `admin` |
| Create EAB (incl. endorse-01) | `acme_eab:create` | `so`, `admin`, or a custom endorse-only role |
| Revoke certificates | `certs:revoke` | `so`, `admin` |
| View resources | `*:read`, `*:list` | `so`, `admin`, `operator`, `auditor` |

See [admin/authorization.md](admin/authorization.md) for the complete
operation-to-permission mapping.

## Best Practices

1. **Use tenant-specific intermediate CAs** - Never share CAs between tenants
2. **Enable EAB for device enrollment** - Prevent unauthorized TPM enrollment
3. **Rotate DEKs periodically** - Use XKMS DEK rotation feature
4. **Set resource limits** - Configure `max_certificates` and `max_accounts`
5. **Use purpose-specific CAs** - Separate CAs for different certificate types
6. **Monitor tenant status** - Watch for suspended or inactive tenants
7. **Audit EAB usage** - Track which EABs are used and by which devices
