# FIPS 140-2/3 Role Model

Role definitions and operation matrix for the go-xkms init system, aligned with FIPS 140-2 AS10.03 (Roles, Services, and Authentication).

## Overview

go-xkms implements a six-role model that enforces separation of duties between module initialization, key management, cryptographic operations, and auditing. The critical design constraint is that the Security Officer (SO) role **cannot** perform cryptographic operations (sign, encrypt, decrypt). This prevents a single compromised identity from both managing the module and using it.

## Roles

| Role | Abbreviation | Description |
|------|-------------|-------------|
| Security Officer | SO | Module initialization, PIN management, CA operations. Cannot sign/encrypt/decrypt. |
| Admin | Admin | Day-to-day key lifecycle management. Cannot initialize modules or manage SO PINs. |
| Operator | Operator | Operational key use and routine maintenance. |
| User | User | Cryptographic operations only (sign, encrypt, decrypt, verify). |
| Auditor | Auditor | Read-only access to audit logs and system state. |
| Custodian | Custodian | Shamir share holder. Can only submit barrier unseal shares. |

## Role Details

### Security Officer (SO)

The SO performs all module initialization and administrative operations. Per FIPS 140-2 separation of duties, the SO is **explicitly excluded** from cryptographic operations.

**Authentication:** Dual-factor -- mTLS certificate (something you have) + SO PIN (something you know).

**Assigned during:** `xkmsd init` (single admin or M-of-N ceremony).

**Key constraint:** The SO role CANNOT call Sign, Encrypt, or Decrypt. This is enforced at the RBAC layer.

### Admin

Admins manage operational keys and certificates but cannot initialize or re-initialize the module. This role is appropriate for team leads or senior engineers who provision keys for applications.

**Authentication:** mTLS certificate or JWT.

### Operator

Operators perform routine key operations and maintenance. They can generate operational keys and perform cryptographic operations but cannot delete keys created by other roles or manage infrastructure keys.

**Authentication:** mTLS certificate or JWT.

### User

Users perform cryptographic operations (sign, verify, encrypt, decrypt) using existing keys. They cannot create, delete, or modify keys.

**Authentication:** mTLS certificate, JWT, or API key.

### Auditor

Auditors have read-only access to audit logs, system state, and configuration. They cannot modify any state.

**Authentication:** mTLS certificate or JWT.

### Custodian

Custodians hold Shamir shares of the barrier root key. Their only operational capability is submitting their share during barrier unseal. They have no access to keys, certificates, or system configuration.

**Authentication:** mTLS certificate (issued during M-of-N init ceremony).

## FIPS Role-to-Operation Matrix

The following matrix defines which roles can perform each operation. This is enforced by the RBAC middleware on all API endpoints.

```
                                          SO    Admin  Operator  User  Auditor  Custodian
MODULE INITIALIZATION
  xkmsd init                             YES    --     --        --    --       --
  claim-cert                             YES    --     --        --    --       --
  claim-share                            YES    --     --        --    --       --
  sign-csr                               YES    --     --        --    --       --

PIN MANAGEMENT
  Set/reset SO PIN                       YES    --     --        --    --       --
  Set/reset User PIN                     YES    --     --        --    --       --
  Change own PIN                         --     YES    YES       YES   --       --

KEY LIFECYCLE
  Generate infrastructure keys           YES    --     --        --    --       --
  Generate operational keys              --     YES    YES       --    --       --
  Delete any key                         YES    --     --        --    --       --
  Delete own keys                        --     YES    YES       --    --       --
  Rotate keys                            --     YES    YES       --    --       --
  List keys                              --     YES    YES       YES   YES      --
  Get key metadata                       --     YES    YES       YES   YES      --

CRYPTO OPERATIONS (SO excluded per FIPS 140-2)
  Sign data                              --     --     YES       YES   --       --
  Verify signature                       --     --     YES       YES   --       --
  Encrypt data                           --     --     YES       YES   --       --
  Decrypt data                           --     --     YES       YES   --       --
  Wrap/unwrap keys                       --     YES    YES       --    --       --

CERTIFICATE MANAGEMENT
  Create CA                              YES    --     --        --    --       --
  Issue certificates                     YES    --     --        --    --       --
  Revoke certificates                    YES    YES    --        --    --       --
  Store/delete certificates              YES    YES    YES       --    --       --
  List certificates                      --     YES    YES       YES   YES      --

BARRIER LIFECYCLE
  Initialize barrier                     YES    --     --        --    --       --
  Seal barrier                           YES    YES    --        --    --       --
  Unseal barrier (root key)              YES    YES    --        --    --       --
  Unseal with share                      --     --     --        --    --       YES
  Initialize Shamir shares               YES    --     --        --    --       --
  Rotate barrier root key                YES    --     --        --    --       --

TENANT MANAGEMENT
  Create/delete tenants                  YES    YES    --        --    --       --
  List tenants                           YES    YES    YES       --    YES      --
  Assign backend to tenant               YES    YES    --        --    --       --

AUDIT & MONITORING
  View audit logs                        --     --     --        --    YES      --
  View system health                     YES    YES    YES       YES   YES      --
  View metrics                           YES    YES    YES       --    YES      --

CREDENTIAL MANAGEMENT
  Submit credential                      YES    YES    --        --    --       --
  Delete credential                      YES    --     --        --    --       --
  List credentials (names only)          YES    YES    --        --    YES      --
```

## Authentication Requirements

### Dual Authentication (SO)

The SO role requires two-factor authentication for all operations:

1. **mTLS client certificate** -- proves possession of the SO private key
2. **SO PIN** -- proves knowledge of the PIN set during `xkmsd init`

Both factors must be present on every SO-authenticated request. The mTLS certificate is verified at the TLS layer. The SO PIN is verified against the PKCS#11 backend (not a stored hash).

```bash
# SO operation requires both cert and PIN
xkmsctl key delete --backend hsm --key-id old-infra-key \
  --tls-cert so.pem --tls-key so-key.pem --tls-ca ca.pem \
  --so-pin <PIN>
```

### Standard Authentication (Other Roles)

Non-SO roles authenticate via mTLS, JWT, or API key depending on deployment configuration. See [Authentication Adapters](../architecture/adapter-framework.md).

## Separation of Duties

The role model enforces several separation-of-duties constraints required by FIPS 140-2/3:

### SO Cannot Sign/Encrypt/Decrypt

This is the fundamental constraint. The SO manages the module lifecycle and key infrastructure but cannot use keys for cryptographic operations. This prevents:

- An SO from signing arbitrary data with production keys
- An SO from decrypting sensitive data
- A compromised SO credential from being used for data exfiltration

### Custodians Have Minimal Access

Custodians can only submit Shamir shares. They cannot view keys, certificates, audit logs, or perform any other operation. This limits the attack surface of compromised custodian credentials.

### Auditors Are Read-Only

Auditors can observe but not modify. This ensures audit trail integrity -- an auditor cannot cover their tracks by deleting logs.

### Key Deletion Requires SO

Only the SO can delete arbitrary keys. Admins and Operators can delete keys they created. This prevents accidental or malicious destruction of infrastructure keys.

## Mapping to PKCS#11 Roles

The go-xkms role model extends the PKCS#11 two-role model (SO + User):

| PKCS#11 Role | go-xkms Roles | Notes |
|--------------|---------------|-------|
| SO | SO | Module initialization, PIN management |
| User | Admin, Operator, User | Subdivided for finer-grained access control |
| N/A | Auditor | go-xkms extension for compliance |
| N/A | Custodian | go-xkms extension for M-of-N operations |

## Mapping to Existing RBAC

The init system roles map to the RBAC permission model documented in [RBAC](../architecture/rbac.md):

| Init Role | RBAC Role | Key Differences |
|-----------|-----------|-----------------|
| SO | (custom) | Has `system:*`, `certificates:*`, `barrier:*`; explicitly **denied** `keys:sign`, `keys:encrypt`, `keys:decrypt` |
| Admin | `admin` | Has `keys:*` except `keys:sign`, `keys:decrypt`; adds `keys:wrap` |
| Operator | `operator` | Has `keys:*` including crypto operations |
| User | `user` | Has `keys:sign`, `keys:verify`, `keys:encrypt`, `keys:decrypt` |
| Auditor | `auditor` | Has `audit:*`, plus read/list on keys, certs, tenants |
| Custodian | (custom) | Has only `barrier:unseal-share` |

## Related Documentation

- [Init System Overview](README.md)
- [Init Ceremony](ceremony.md)
- [Threshold Architecture](threshold.md)
- [Credential Seal Strategies](credentials.md)
- [RBAC](../architecture/rbac.md)
- [Authentication Adapters](../architecture/adapter-framework.md)
