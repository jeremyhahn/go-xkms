# Certificate Authority Module

RFC 5280 compliant Certificate Authority with multi-backend key storage, TPM attestation, and ACME server integration.

## Overview

The CA module provides enterprise-grade certificate lifecycle management with hardware security integration. It implements the core X.509 PKI operations required by the ACME server while leveraging go-xkms for secure key storage across multiple backends.

## Key Features

| Feature | Description |
|---------|-------------|
| **X.509 Certificate Issuance** | RFC 5280 compliant certificate signing with configurable validity |
| **CA Hierarchy** | Root and Intermediate CA support with automatic chain building |
| **Multi-Backend Key Storage** | TPM2, PKCS#11/HSM, and software (PKCS#8) via go-xkms |
| **TPM 2.0 Attestation** | TCG-CSR-IDEVID support for device identity enrollment |
| **Certificate Revocation** | CRL generation (RFC 5280) and OCSP responder (RFC 6960) |
| **Cross-Signing** | Multiple trust anchor support for chain migration |
| **TLS Integration** | Ready-to-use tls.Config and certificate bundles |
| **Post-Quantum Cryptography** | ML-DSA/ML-KEM (FIPS 203/204) via quantum backend |
| **Multi-Tenant Support** | Per-tenant intermediate CAs with isolated key material |
| **QRDB Integration** | Blob storage via QRDB objstore adapter |

## Supported Key Algorithms

| Algorithm | Key Sizes/Curves | TPM Support | Use Case |
|-----------|-----------------|-------------|----------|
| RSA | 2048, 3072, 4096 bits | Yes | Legacy compatibility, broad support |
| ECDSA | P-256, P-384, P-521 | Yes (P-256, P-384) | Modern deployments, smaller keys |
| Ed25519 | Curve25519 | Software only | High-performance signing |

### Post-Quantum Algorithms

The CA supports NIST-standardized post-quantum cryptographic algorithms via go-xkms's quantum backend. Build with `-tags quantum_safe` to enable quantum certificate extensions.

| Algorithm | Variants | Type | Standard | Use Case |
|-----------|----------|------|----------|----------|
| ML-DSA (Dilithium) | 44, 65, 87 | Signature | FIPS 204 | Quantum-resistant signing |
| ML-KEM (Kyber) | 512, 768, 1024 | KEM | FIPS 203 | Quantum-resistant key encapsulation |

**ML-DSA Security Levels:**
- ML-DSA-44: ~128-bit security (Level 2)
- ML-DSA-65: ~192-bit security (Level 3)
- ML-KEM-87: ~256-bit security (Level 5)

**ML-KEM Security Levels:**
- ML-KEM-512: ~128-bit security (Level 1)
- ML-KEM-768: ~192-bit security (Level 3)
- ML-KEM-1024: ~256-bit security (Level 5)

## Storage Integration

The CA uses three storage abstractions from the go-xkms and go-objstore ecosystems:

```
+-----------------+     +------------------+     +------------------+
|   KeyStore      |     |    CertStore     |     |   ObjectStore    |
| (go-xkms)      |     |  (go-xkms)       |     |  (go-objstore)   |
+-----------------+     +------------------+     +------------------+
| Private Keys    |     | X.509 Certs      |     | Revocation Data  |
| Signers         |     | Cert Chains      |     | Cross-Signed     |
| Key Generation  |     | Trust Stores     |     | Attestation      |
+-----------------+     +------------------+     +------------------+
        |                       |                        |
        v                       v                        v
+---------------------------------------------------------------+
|                     Storage Backends                           |
| TPM2 | PKCS#11 | PKCS#8 | File | S3 | Azure | GCP | QRDB    |
+---------------------------------------------------------------+
```

### QRDB Object Storage

The CA can use QRDB as a backend for blob storage via the objstore package (`pkg/acme/storage/objstore`). This adapter implements the go-objstore `Storage` interface, providing:

- **Attestation storage**: TPM quotes, endorsement credentials, device manifests
- **Signature storage**: Detached signatures, signing metadata
- **Certificate bundles**: CA chains, cross-signed certificates
- **Revocation data**: CRL snapshots, OCSP response caches

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
    "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
)

// Create QRDB-backed object store
kvClient := qrdbService.KV()
blobStore := objstore.NewAdapter(kvClient)

// Use with CA
authority, err := ca.New(config, certStore, blobStore)
```

The adapter stores blobs with entity type prefixes (`blob/`, `blob_meta/`) and supports:
- Full CRUD operations with context support
- Metadata management (ETag, size, timestamps)
- Prefix-based listing with pagination
- Lifecycle policy management
- Archive operations

## Storage and Service Integration

### Current Integration

| Component | Backend | Description |
|-----------|---------|-------------|
| **KV Storage** | QRDB | ACME entities, certificates, configuration |
| **Object Store Adapter** | QRDB | Blob storage for attestations and signatures |
| **Key Management** | go-xkms | TPM2, PKCS#11, PKCS#8 key storage |
| **IAM/RBAC** | QRDB | Policy-based access control |
| **Auth** | QRDB Auth | JWT token validation and sessions |
| **Seal/Unseal** | QRDB | Shamir's Secret Sharing for master key |

## Multi-Tenancy

The CA supports multi-tenant deployments where each tenant has isolated data, dedicated CA hierarchy, and independent configuration.

### Per-Tenant Intermediate CAs

Each tenant can have their own intermediate CA(s) under a global or tenant-specific root:

```
Global Root CA (managed by a system-tenant `so` / `admin`)
+-- Tenant A Intermediate CA
|   +-- General Purpose (default)
|   +-- TPM Endorsement
+-- Tenant B Intermediate CA
+-- Tenant C Intermediate CA
    +-- Server Auth
    +-- Client Auth
```

### Multi-Tenant Architecture

```
+-------------------------------------------+
|              ACME Server                   |
|         (tenant-aware routing)            |
+-------------------------------------------+
                    |
                    v
+-------------------------------------------+
|        Certificate Authority (CA)          |
|  - Per-tenant intermediate CAs             |
|  - Tenant-scoped certificate issuance      |
|  - Isolated revocation lists               |
+-------------------------------------------+
          |                    |
          v                    v
+------------------+  +------------------+
|    KeyStore      |  |   ObjectStore    |
|  (go-xkms)      |  |  (QRDB/other)    |
+------------------+  +------------------+
          |                    |
          v                    v
+-------------------------------------------+
|              QRDB (Embedded KV)           |
|  - Tenant data isolation (key prefixes)    |
|  - Blob storage for attestations           |
+-------------------------------------------+
|           QRDB (RBAC + Auth)              |
|  - RBAC policy enforcement                 |
|  - JWT token validation                    |
+-------------------------------------------+
```

### Tenant CA Configuration

```go
// Create tenant-specific intermediate CA
tenantCA := &ca.TenantIntermediateCA{
    TenantID:     "acme-corp",
    CommonName:   "ACME Corp Intermediate CA",
    KeyAlgorithm: "EC-P384",
    ValidityYears: 10,
    Purpose:      "general",
}

// Sign certificate using tenant's CA
cert, err := authority.SignCSRForTenant(tenantID, csrPEM, &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "app.acme-corp.example.com",
    },
    Valid: 365,
})
```

### Tenant Storage Isolation

Data is stored with tenant-prefixed keys:

```
tenants/{tenant_id}/ca/intermediate/{ca_id}
tenants/{tenant_id}/ca/certificates/{serial}
tenants/{tenant_id}/ca/crl/{crl_number}
tenants/{tenant_id}/ca/ocsp/{serial}
```

See [Multi-Tenancy Documentation](../acme/multi-tenancy.md) for complete details.

## Quick Start

```go
import (
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
    "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// Initialize xkms backends (see go-xkms documentation)
xkmssdk.ServiceInitialize(xkmsConfig)
defer xkmssdk.ServiceClose()

// Create CA with default configuration
config := ca.DefaultConfig()
authority, err := ca.New(config, certStore, objectStore)
if err != nil {
    log.Fatal(err)
}

// Sign a CSR
cert, err := authority.SignCSR(csrPEM, &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "example.com",
        Organization: "Example Inc",
    },
    Valid: 365,
    SANS: &ca.SubjectAlternativeNames{
        DNS: []string{"example.com", "www.example.com"},
    },
})

// Get CA bundle for client trust
bundle, err := authority.CABundle(types.StoreTypeSoftware, x509.ECDSA)
```

### With QRDB Backend

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
    "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
    "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// Initialize QRDB
dbConfig := &qrdb.Config{
    Mode:    qrdb.ModeStandalone,
    DataDir: "/var/lib/xkms/data",
}
db, err := qrdb.New(dbConfig)
if err != nil {
    log.Fatal(err)
}

// Create QRDB-backed object store for attestations
blobStore := objstore.NewAdapter(db.KV())

// Create CA with QRDB storage
authority, err := ca.New(config, certStore, blobStore)
```

## TPM Device Enrollment

```go
// Sign TCG-CSR-IDEVID for TPM-based device identity
iakDER, idevidDER, err := authority.SignTCGCSRIDevID(tcgCSR, &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-12345",
    },
})

// Issue EK certificate
ekCert, err := authority.IssueEKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-ek",
    },
    ProdModel:  "TPM-Model-X",
    ProdSerial: "SN12345",
}, ekPublicKey)

// Issue AK certificate
akCert, err := authority.IssueAKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-ak",
    },
}, akPublicKey)
```

## Post-Quantum Cryptography

The CA supports quantum-resistant cryptography through go-xkms's quantum backend. ML-DSA keys can be used for CA signing operations, and ML-KEM keys for secure key encapsulation.

### Hybrid Certificates

When the CA signer is an ML-DSA key, certificates are automatically created as **hybrid certificates** containing:

1. **Classical signature** (ECDSA/RSA) in the standard X.509 signature field for backward compatibility
2. **Quantum signature** (ML-DSA) as a certificate extension for post-quantum security

This hybrid approach ensures:
- **Backward compatibility**: Classical verifiers can validate certificates normally
- **Quantum resistance**: Quantum-aware verifiers can validate the ML-DSA signature
- **Automatic detection**: No code changes required - quantum signing is automatic when using ML-DSA CA keys

The quantum signature is stored in certificate extensions:
- `OIDQuantumAlgorithm` (1.3.6.1.4.1.29377.101.10) - Algorithm identifier
- `OIDQuantumSignature` (1.3.6.1.4.1.29377.101.11) - Signature bytes

Build with `-tags quantum_safe` to enable quantum certificate extensions.

### Usage Examples

```go
import xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

// Generate ML-DSA signing key via xkms
attrs := &xkmssdk.KeyAttributes{
    CN:        "quantum-ca-key",
    KeyType:   xkmssdk.KeyTypeCA,
    StoreType: xkmssdk.StoreQuantum,
    QuantumAttributes: &xkmssdk.QuantumAttributes{
        Algorithm: xkmssdk.QuantumAlgorithmMLDSA65,
    },
}
privateKey, err := xkms.GenerateKey(attrs)

// Issue certificate - quantum signature automatically added
// when CA uses an ML-DSA key
cert, err := authority.IssueCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{CommonName: "example.com"},
    Valid:   365,
})

// Generate ML-KEM key for encapsulation
kemAttrs := &types.KeyAttributes{
    CN:        "quantum-kem-key",
    KeyType:   types.KeyTypeEncryption,
    StoreType: types.StoreQuantum,
    QuantumAttributes: &types.QuantumAttributes{
        Algorithm: types.QuantumAlgorithmMLKEM768,
    },
}
kemKey, err := xkms.GenerateKey(kemAttrs)

// Encapsulate a shared secret
ciphertext, sharedSecret, err := kemKey.Encapsulate(recipientPublicKey)

// Decapsulate to recover the shared secret
recoveredSecret, err := kemKey.Decapsulate(ciphertext)
```

## Architecture

The CA follows a layered architecture with clear separation of concerns:

```
+-------------------------------------------+
|              ACME Server                   |
+-------------------------------------------+
                    |
                    v
+-------------------------------------------+
|        Certificate Authority (CA)          |
|  - CSR Signing      - TPM Enrollment       |
|  - Revocation       - OCSP Responder       |
|  - Chain Building   - Cross-Signing        |
|  - Multi-Tenancy    - Per-Tenant CAs       |
+-------------------------------------------+
          |                    |
          v                    v
+------------------+  +------------------+
|    KeyStore      |  |   ObjectStore    |
|  (go-xkms)      |  |  (go-objstore)   |
+------------------+  +------------------+
          |                    |
          v                    v
+-------------------------------------------+
|              Backend Layer                 |
|  TPM 2.0 | PKCS#11/HSM | Software | QRDB |
+-------------------------------------------+
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | CA hierarchy, key storage design, certificate lifecycle |
| [Configuration](configuration.md) | Complete configuration reference with examples |
| [Certificate Types](certificate-types.md) | Root, Intermediate, End-Entity, and TPM certificates |
| [API Reference](api-reference.md) | Go API documentation for all CA operations |

## Security Considerations

- **Root CA Protection**: Root CA keys should be stored in hardware (TPM/HSM) and used only for intermediate CA signing
- **Key Algorithm Selection**: Use ECDSA P-256 or RSA-2048 minimum; Ed25519 for high-performance scenarios
- **Quantum-Safe Migration**: For long-lived secrets, consider ML-KEM-768 or higher; ML-DSA-65 provides balanced security/performance
- **Certificate Validity**: Follow CA/Browser Forum guidelines (398 days for end-entity, longer for CA certificates)
- **Revocation**: Always configure CRL distribution points and OCSP responders for production deployments
- **Serial Numbers**: 128-bit cryptographically random serial numbers per RFC 5280
- **Tenant Isolation**: Use per-tenant intermediate CAs and DEKs for cryptographic isolation
- **QRDB Seal**: Enable Shamir's Secret Sharing for master key protection in production

## Standards Compliance

| Standard | Description |
|----------|-------------|
| RFC 5280 | Internet X.509 PKI Certificate and CRL Profile |
| RFC 6960 | Online Certificate Status Protocol (OCSP) |
| RFC 8555 | Automatic Certificate Management Environment (ACME) |
| TCG TPM 2.0 | Keys for Device Identity and Attestation |
| TCG EK Credential Profile | Endorsement Key Certificate Requirements |
| NIST FIPS 203 | ML-KEM (Kyber) Key Encapsulation Mechanism |
| NIST FIPS 204 | ML-DSA (Dilithium) Digital Signature Algorithm |

## Related Documentation

- [ACME Server Documentation](../acme/README.md)
- [QRDB Documentation](../acme/qrdb/README.md)
- [Multi-Tenancy](../acme/multi-tenancy.md)
- [go-xkms Documentation](https://github.com/jeremyhahn/go-xkms)
- [go-objstore Documentation](https://github.com/jeremyhahn/go-objstore)
- [go-trusted-platform TPM Documentation](https://github.com/jeremyhahn/go-trusted-platform/tree/main/docs)
