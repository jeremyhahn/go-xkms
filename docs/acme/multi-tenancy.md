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
Global Root CA (managed by super-admin)
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

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/tenants` | POST | super-admin | Create tenant |
| `/api/v1/tenants` | GET | super-admin | List tenants |
| `/api/v1/tenants/{id}` | GET | admin | Get tenant |
| `/api/v1/tenants/{id}` | PUT | admin | Update tenant |
| `/api/v1/tenants/{id}` | DELETE | super-admin | Delete tenant |
| `/api/v1/tenants/{id}/status` | PUT | super-admin | Update status |

### Tenant CA Management

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/tenants/{id}/root-ca` | POST | admin | Create tenant root CA |
| `/api/v1/tenants/{id}/intermediate-cas` | GET | admin | List intermediate CAs |
| `/api/v1/tenants/{id}/intermediate-cas` | POST | admin | Create intermediate CA |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}` | GET | admin | Get CA details |
| `/api/v1/tenants/{id}/intermediate-cas/{caid}/status` | PUT | admin | Update CA status |
| `/api/v1/tenants/{id}/default-intermediate-ca` | PUT | admin | Set default CA |
| `/api/v1/tenants/{id}/ca-status` | GET | admin | Get CA status |

### Tenant EAB Management

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/tenants/{id}/eab` | GET | endorser | List EABs |
| `/api/v1/tenants/{id}/eab` | POST | endorser | Create EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | GET | endorser | Get EAB |
| `/api/v1/tenants/{id}/eab/{kid}` | DELETE | admin | Delete EAB |

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
      "model": "SecureModule-X"
    },
    "expires_in_days": 30
  }' \
  https://ca.example.com/api/v1/tenants/acme-corp/eab
```

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

### Role Hierarchy

| Role | Level | Tenant Scope |
|------|-------|--------------|
| super-admin | 100 | All tenants |
| admin | 80 | Assigned tenant |
| endorser | 60 | Assigned tenant |
| operator | 40 | Assigned tenant |
| viewer | 20 | Assigned tenant |

### Role Capabilities

| Capability | super-admin | admin | endorser | operator | viewer |
|------------|:-----------:|:-----:|:-----------------:|:--------:|:------:|
| Create tenant | X | - | - | - | - |
| Delete tenant | X | - | - | - | - |
| Manage tenant CA | X | X | - | - | - |
| Create EAB (endorse-01) | X | X | X | - | - |
| Revoke certificates | X | X | - | - | - |
| View resources | X | X | X | X | X |

## Best Practices

1. **Use tenant-specific intermediate CAs** - Never share CAs between tenants
2. **Enable EAB for device enrollment** - Prevent unauthorized TPM enrollment
3. **Rotate DEKs periodically** - Use XKMS DEK rotation feature
4. **Set resource limits** - Configure `max_certificates` and `max_accounts`
5. **Use purpose-specific CAs** - Separate CAs for different certificate types
6. **Monitor tenant status** - Watch for suspended or inactive tenants
7. **Audit EAB usage** - Track which EABs are used and by which devices
