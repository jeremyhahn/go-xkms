# ACME Server

RFC 8555 compliant Automatic Certificate Management Environment (ACME) server with TPM attestation support.

## Overview

The ACME package (`pkg/acme`) provides a complete implementation of the ACME protocol for automated certificate management. It extends the standard RFC 8555 specification with support for TPM-based device attestation and enrollment challenges, enabling secure device identity provisioning aligned with TCG (Trusted Computing Group) specifications.

> This was formerly the standalone `go-trusted-ca` project. It is now decommissioned and absorbed into go-xkms: the CA lives in `pkg/ca` and the ACME server in `pkg/acme`.

## Key Features

| Feature | Description |
|---------|-------------|
| **RFC 8555 Compliance** | Full implementation of ACME protocol specification |
| **RFC 9773 ARI Support** | ACME Renewal Information for smart certificate renewal |
| **TPM Attestation** | `device-attest-01` challenge for hardware-bound keys |
| **TPM Enrollment** | `enroll-01` challenge for TCG-CSR-IDevID enrollment |
| **EK Certificate Issuance** | `endorse-01` challenge for TPM EK certificates |
| **HTTP-01/DNS-01** | Standard domain validation challenges |
| **DNS-01 Providers** | Cloudflare, Route53, Azure DNS, Google Cloud DNS |
| **Challenge Resolver** | Pluggable solver framework with preference ordering |
| **Pre-Authorization** | Batch authorization before order creation |
| **External Account Binding** | EAB support for pre-authorized accounts |
| **Multi-Tenant Support** | Tenant-specific CA signing via go-xkms KMS |
| **QRDB Storage** | Distributed KV storage with tenant isolation |
| **CAA Validation** | Certificate Authority Authorization per RFC 8659 |
| **Rate Limiting** | Configurable rate limits per account and IP |
| **Nonce Management** | Replay protection with configurable expiration |

## Architecture

```
+---------------------------------------------------------------+
|                        ACME Server                             |
+---------------------------------------------------------------+
|  Handlers (HTTP endpoints)                                     |
|    +-- Directory, NewNonce, NewAccount                         |
|    +-- NewOrder, Authorization, Challenge                      |
|    +-- Finalize, Certificate, RevokeCert                       |
|    +-- KeyChange, OrdersList                                   |
+---------------------------------------------------------------+
|  Middleware                                                    |
|    +-- Tenant Extraction (header, subdomain, path)             |
|    +-- Tenant Validation                                       |
|    +-- Tenant-Scoped Storage Factory                           |
+---------------------------------------------------------------+
|  Challenges                                                    |
|    +-- http-01         (HTTP domain validation)                |
|    +-- dns-01          (DNS domain validation)                 |
|    +-- device-attest-01 (TPM attestation)                      |
|    +-- enroll-01       (TPM enrollment - TCG IDevID)           |
|    +-- endorse-01      (EK certificate issuance)               |
+---------------------------------------------------------------+
|  Storage (QRDB DAO Layer)                                      |
|    +-- Accounts, Orders, Authorizations, Certificates          |
|    +-- Nonces, External Account Bindings, Tenants              |
|    +-- Tenant-scoped key prefixes for isolation                |
+---------------------------------------------------------------+
|  Integration                                                   |
|    +-- Certificate Authority (go-xkms)                         |
|    +-- Key Management (go-xkms KMS)                            |
|    +-- Multi-tenant CA Signing                                 |
+---------------------------------------------------------------+
```

## Quick Start

### Server Configuration

```yaml
acme:
  server:
    listen_addr: ":8443"
    external_url: "https://acme.example.com"
    terms_of_service: "https://example.com/tos"
    tls:
      enabled: true
      cert_file: "/etc/acme/server.crt"
      key_file: "/etc/acme/server.key"

  challenges:
    http01:
      enabled: true
      port: "80"
    dns01:
      enabled: true
    device_attest_01:
      enabled: true
    enroll_01:
      enabled: true
    endorse_01:
      enabled: true

  storage:
    backend: "qrdb"
    qrdb:
      mode: standalone
      data_dir: /var/lib/xkms/data

  multi_tenancy:
    enabled: true
    require_tenant: true
    validate_tenant: true
    default_tenant: ""
    extraction_method: "header"  # header, subdomain, or path

  external_account_binding:
    required: false
```

### Client Usage

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/client"

// Create ACME client
cfg := &client.Config{
    DirectoryURL: "https://acme.example.com/directory",
    AccountKey:   privateKey,
}
acmeClient, err := client.New(cfg)

// RequestCertificate registers the account on its first call for this
// client — there is no separate registration step. See docs/acme/client.md
// for the full account-registration and certificate-request API.

// Request certificate
cert, err := acmeClient.RequestCertificate(ctx, &client.CertificateRequest{
    Domains: []string{"example.com", "www.example.com"},
})
```

## QRDB Storage Integration

The ACME server uses QRDB as its primary storage backend, providing distributed, consistent storage for all ACME entities with native multi-tenancy support.

### Storage Architecture

All ACME entities are stored in QRDB's distributed key-value store with tenant-scoped key prefixes that ensure complete data isolation between tenants.

#### Key Structure

```
# Single-tenant (no tenant ID)
acme/accounts/{account_id}
acme/accounts/{account_id}/orders/{order_id}
acme/accounts/{account_id}/authorizations/{authz_id}
acme/accounts/{account_id}/challenges/{challenge_id}
acme/certificates/{cert_id}
acme/nonces/{nonce_id}
acme/eab/{kid}

# Multi-tenant (with tenant ID)
tenants/{tenant_id}/acme/accounts/{account_id}
tenants/{tenant_id}/acme/accounts/{account_id}/orders/{order_id}
tenants/{tenant_id}/acme/accounts/{account_id}/authorizations/{authz_id}
tenants/{tenant_id}/acme/accounts/{account_id}/challenges/{challenge_id}
tenants/{tenant_id}/acme/certificates/{cert_id}
tenants/{tenant_id}/acme/nonces/{nonce_id}
tenants/{tenant_id}/acme/eab/{kid}
tenants/{tenant_id}/counters/{entity_type}
```

#### DAO Layer

The `pkg/acme/storage/objstore/` package provides Data Access Objects for each ACME entity:

| DAO | Entity | Description |
|-----|--------|-------------|
| `AccountDAO` | ACMEAccount | Account registration and management |
| `OrderDAO` | ACMEOrder | Certificate order lifecycle |
| `AuthorizationDAO` | ACMEAuthorization | Domain/identifier authorizations |
| `ChallengeDAO` | ACMEChallenge | Challenge validation state |
| `CertificateDAO` | ACMECertificate | Issued certificate storage |
| `NonceDAO` | ACMENonce | Replay protection nonces |
| `ExternalAccountBindingDAO` | ExternalAccountBinding | EAB tokens and bindings |
| `TenantDAO` | Tenant | Tenant configuration and status |

#### Factory Pattern

The storage factory implements the `TenantAwareFactory` interface, enabling tenant-scoped DAO creation:

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
)

// Create factory from a go-qrdb KVStore
factory, err := objstore.NewTenantAwareFactoryFromKVStore(kvStore)

// Get tenant-scoped factory
tenantFactory, err := factory.ForTenant("tenant-123")

// All DAOs from tenantFactory operate within tenant-123's namespace
accountDAO, err := tenantFactory.AccountDAO()
orderDAO, err := tenantFactory.OrderDAO(accountID)
```

#### Serialization

The DAO layer supports multiple serialization formats via the `Codec` interface:

| Format | Use Case |
|--------|----------|
| JSON | Human-readable, debugging |
| CBOR | Compact binary, embedded systems |
| MessagePack | High-performance binary serialization |

## Multi-Tenancy

The ACME server provides complete multi-tenancy support with tenant isolation at the storage layer and configurable tenant extraction from requests.

### Tenant Middleware

The tenant middleware (`pkg/acme/server/handlers/middleware.go`) intercepts requests, extracts tenant context, and provides tenant-scoped storage factories.

#### Configuration

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"

middleware := handlers.NewTenantMiddleware(&handlers.TenantMiddlewareConfig{
    StorageFactory:  qrdbFactory,
    Logger:          logger,
    TenantExtractor: handlers.DefaultTenantExtractor,
    DefaultTenant:   "",
    RequireTenant:   true,
    ValidateTenant:  true,
})
```

### Tenant Extraction Methods

The server supports three methods for extracting tenant ID from incoming requests:

| Method | Extractor Function | Example |
|--------|-------------------|---------|
| **Header** | `DefaultTenantExtractor` | `X-Tenant-ID: tenant-123` |
| **Subdomain** | `SubdomainTenantExtractor` | `tenant-123.acme.example.com` |
| **Path Prefix** | `PathTenantExtractor` | `/tenant-123/acme/directory` |

#### Header-Based (Default)

```http
POST /acme/new-account HTTP/1.1
Host: acme.example.com
X-Tenant-ID: tenant-123
Content-Type: application/jose+json
```

#### Subdomain-Based

```http
POST /acme/new-account HTTP/1.1
Host: tenant-123.acme.example.com
Content-Type: application/jose+json
```

The subdomain extractor parses the first subdomain component as the tenant ID.

#### Path-Based

```http
POST /tenant-123/acme/new-account HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json
```

The path extractor uses the first path segment (before `/acme/`) as the tenant ID.

### Tenant Validation

When `ValidateTenant` is enabled, the middleware verifies:

1. Tenant exists in QRDB via TenantDAO
2. Tenant status is "active"
3. Returns appropriate error responses for invalid/inactive tenants

### Accessing Tenant Context

Handlers can access the tenant ID from the request context:

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    tenantID := handlers.TenantFromContext(r.Context())

    // Get tenant-scoped storage factory
    factory, err := handlers.GetTenantScopedFactory(r.Context(), h.storageFactory)

    // All DAO operations are now scoped to the tenant
    accountDAO, _ := factory.AccountDAO()
}
```

## ACME Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/acme/directory` | GET | ACME directory with endpoint URLs |
| `/acme/new-nonce` | HEAD/GET | Get fresh anti-replay nonce |
| `/acme/new-account` | POST | Register new account |
| `/acme/new-order` | POST | Create certificate order |
| `/acme/authz/{id}` | POST | Get authorization details |
| `/acme/challenge/{id}` | POST | Respond to challenge |
| `/acme/order/{id}/finalize` | POST | Finalize order with CSR |
| `/acme/order/{id}` | POST | Get order status |
| `/acme/cert/{id}` | POST | Download certificate |
| `/acme/revoke-cert` | POST | Revoke certificate |
| `/acme/key-change` | POST | Rotate account key |
| `/acme/account/{id}/orders` | POST | List account orders |

## Challenge Types Overview

### Standard Challenges

| Challenge | Identifier Type | Use Case |
|-----------|-----------------|----------|
| **http-01** | DNS | Domain validation via HTTP well-known path |
| **dns-01** | DNS | Domain validation via DNS TXT record |

### TPM Challenges

| Challenge | Identifier Type | Use Case |
|-----------|-----------------|----------|
| **device-attest-01** | IP/Permanent-ID | TPM attestation with quote verification |
| **enroll-01** | IP/Permanent-ID | TCG-CSR-IDevID enrollment with credential activation |
| **endorse-01** | Permanent-ID | EK certificate issuance for TPMs without manufacturer certs |

### Challenge Selection Matrix

| Identifier Type | Wildcard | Available Challenges |
|-----------------|----------|----------------------|
| `dns` | No | http-01, dns-01 |
| `dns` | Yes | dns-01 only (per RFC 8555) |
| `ip` | N/A | enroll-01, endorse-01, device-attest-01 |
| `permanent-identifier` | N/A | enroll-01, endorse-01, device-attest-01 |

## Supported Signature Algorithms

The ACME server supports the following JWS signature algorithms for account keys:

| Algorithm | Type | Description |
|-----------|------|-------------|
| RS256 | RSA | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | RSA | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | RSA | RSASSA-PKCS1-v1_5 with SHA-512 |
| PS256 | RSA-PSS | RSASSA-PSS with SHA-256 |
| PS384 | RSA-PSS | RSASSA-PSS with SHA-384 |
| PS512 | RSA-PSS | RSASSA-PSS with SHA-512 |
| ES256 | ECDSA | ECDSA with P-256 and SHA-256 |
| ES384 | ECDSA | ECDSA with P-384 and SHA-384 |
| ES512 | ECDSA | ECDSA with P-521 and SHA-512 |
| EdDSA | EdDSA | Ed25519 signature algorithm |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System architecture and component design |
| [Configuration](../acme-issuance/engineering.md) | Complete server configuration reference — `acme/configuration.md` was deleted by go-xkms#942 (pre-merge go-trusted-ca documentation for a nonexistent config shape); see `../acme-issuance/engineering.md` §Configuration |
| [Challenges](challenges.md) | Challenge types and validation flows |
| [DNS-01 Providers](dns-01/) | DNS-01 challenge provider configuration |
| [API Reference](api-reference.md) | HTTP API endpoints and responses |
| [ACME Client](client.md) | Client configuration, account management, and certificate operations |
| [Challenge Resolver](challenge-resolver.md) | Pluggable challenge solving framework |

## Integration Points

| Component | Integration |
|-----------|-------------|
| **go-xkms** | Key storage and certificate operations |
| **QRDB** | Distributed KV storage for ACME entities |
| **go-xkms** | Multi-tenant key management |
| **TPM 2.0** | Hardware-backed attestation and enrollment |
| **DNS Service** | DNS-01 challenge TXT record provisioning |

## Security Model

### Authentication

- **JWS Signatures**: All ACME requests (except directory and newNonce) require JWS-signed payloads
- **Account Keys**: Public key bound to account identity
- **Nonce Protection**: Replay attack prevention via nonce validation
- **External Account Binding**: Optional pre-authorization for account creation

### Challenge Security

- **http-01**: Validates domain control via HTTP endpoint
- **dns-01**: Validates domain control via DNS TXT record
- **device-attest-01**: TPM quote verification with AK certificate chain validation
- **enroll-01**: TPM credential activation (MakeCredential/ActivateCredential)
- **endorse-01**: EAB-based authorization for EK certificate issuance

### Multi-Tenant Security

- Tenant isolation via QRDB key prefixes (`tenants/{tenant_id}/...`)
- Tenant-scoped storage factories prevent cross-tenant data access
- Tenant validation ensures only active tenants can access the API
- Tenant-specific CA signing keys via go-xkms KMS
- EAB-based tenant assignment during account creation

## Order Finalization Hooks

The ACME server supports extensible order finalization hooks for custom post-issuance processing:

```go
// Register a hook for device enrollment
registry := handlers.NewOrderFinalizeHookRegistry()
registry.Register("inventory-update", func(ctx *OrderFinalizeHookContext) error {
    if ctx.IsTCGCSR {
        // Process TCG enrollment data
        model := ctx.TCGData.ProductModel
        serial := ctx.TCGData.ProductSerial
        // Update device inventory...
    }
    return nil
})
```

Hook context provides:
- Certificate and CSR data
- TCG enrollment metadata (for enroll-01)
- Client IP address
- Request context for cancellation

## See Also

- [go-xkms Documentation](https://github.com/jeremyhahn/go-xkms)
- [QRDB Documentation](qrdb/README.md)
- [RFC 8555 - ACME Protocol](https://tools.ietf.org/html/rfc8555)
- [TCG TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/resource/tcg-tpm-2-0-keys-for-device-identity-and-attestation/)
