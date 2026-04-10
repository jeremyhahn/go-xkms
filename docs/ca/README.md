# Certificate Authority (CA) Package Documentation

The CA package in go-xkms provides a complete certificate authority implementation with certificate lifecycle management including CSR signing, certificate issuance, revocation, CRL generation, and TLS configuration helpers.

## Architecture

```
+------------------+     +------------------+     +------------------+
|   go-trusted-ca  |     |   go-dragondb    |     |   Application    |
|   (ACME Server)  |     | (Distributed DB) |     |     (Custom)     |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         +------------------------+------------------------+
                                  |
                          +-------v-------+
                          |      CA       |
                          | (Certificate  |
                          |   Authority)  |
                          +-------+-------+
                                  |
              +-------------------+-------------------+
              |                                       |
      +-------v-------+                       +-------v-------+
      |   KeyStore    |                       |   CertStore   |
      | (go-xkms) |                       | (go-xkms) |
      +-------+-------+                       +-------+-------+
              |                                       |
    +---------+---------+                   +---------+---------+
    |    |    |    |    |                   |    |    |    |    |
  +--+ +--+ +--+ +--+ +--+                +--+ +--+ +--+ +--+ +--+
  |SW| |TPM| |PIV| |HSM| |KMS|            |File| |S3| |DB| |Raft|
  +--+ +--+ +--+ +--+ +--+                +--+ +--+ +--+ +--+
```

**Key Features:**
- CSR signing and certificate issuance with configurable profiles
- Certificate revocation and CRL generation
- Trust chain management and verification
- TLS configuration helpers for server/client/mTLS
- Thread-safe operations with atomic state management
- Multiple keystore backend support (Software, TPM, PKCS#11, Cloud KMS)
- Multiple certificate storage backends via go-objstore

## Quick Start

### Installation

```bash
go get github.com/jeremyhahn/go-xkms/pkg/ca
```

### Basic Usage

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/ca"
    "github.com/jeremyhahn/go-xkms/pkg/certstore"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // 1. Set up keystore and certificate store
    ks, _ := xkms.New(&xkms.Config{
        StoreType: "software",
        HomeDir:   "/var/lib/ca",
    })
    cs := certstore.New(certstore.Config{
        Backend: "file",
        Path:    "/var/lib/ca/certs",
    })

    // 2. Create CA configuration
    config := ca.DefaultCAConfigWithIntermediate()
    config.Identity[0].Subject.CommonName = "My Root CA"
    config.Identity[1].Subject.CommonName = "My Intermediate CA"

    // 3. Initialize the CA
    params := &ca.Params{
        Config:    config,
        KeyStore:  ks,
        CertStore: cs,
    }
    caInstance, err := ca.New(params)
    if err != nil {
        log.Fatal(err)
    }

    // 4. Initialize (generates root and intermediate certificates)
    if err := caInstance.Init(); err != nil {
        log.Fatal(err)
    }

    // 5. Issue a certificate
    issued, err := caInstance.IssueCertificate(&ca.CertificateRequest{
        Subject: ca.Subject{
            CommonName:   "server.example.com",
            Organization: "Example Corp",
        },
        SANS: &ca.SubjectAlternativeNames{
            DNS: []string{"server.example.com", "www.example.com"},
            IPs: []string{"192.168.1.100"},
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Issued certificate: %s (expires: %s)",
        issued.Certificate.Subject.CommonName,
        issued.NotAfter)
}
```

### Creating a CSR

```go
// Create a CSR for an existing key
csrPEM, err := caInstance.CreateCSR(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "client.example.com",
        Organization: "Example Corp",
    },
    SANS: &ca.SubjectAlternativeNames{
        Email: []string{"admin@example.com"},
    },
})

// Or with an external signer (PIV card, HSM)
csrPEM, err := ca.CreateCSRWithKey(request, pivCardSigner)
```

### Signing a CSR

```go
cert, err := caInstance.SignCSR(csrPEM, &ca.SignOptions{
    Profile:      "server",
    ValidityDays: 365,
})
```

## Configuration

### CAConfig

The primary configuration structure supports hierarchical CA deployments:

```go
type CAConfig struct {
    // Identity contains all CA identities (root and intermediates)
    // Index 0 must be the root CA (IsRoot=true)
    Identity []Identity

    // SelectedCA specifies which identity to use for issuing certificates
    // 0 = root CA, 1+ = intermediate CAs
    SelectedCA int

    // DefaultValidityDays for issued certificates (default: 365)
    DefaultValidityDays int

    // IncludeLocalhostSANS adds localhost and 127.0.0.1 to all certificates
    IncludeLocalhostSANS bool

    // HomeDir is the base directory for CA storage
    HomeDir string
}
```

### Identity Configuration

```go
type Identity struct {
    // Subject contains X.509 distinguished name fields
    Subject Subject

    // Valid specifies certificate validity in years
    Valid int

    // Keys contains key configurations (algorithm, curve/size)
    Keys []*types.KeyConfig

    // KeystoreType: "software", "tpm2", "pkcs11"
    KeystoreType string

    // SANS for this CA identity
    SANS *SubjectAlternativeNames

    // IsRoot indicates this is a root CA (self-signed)
    IsRoot bool

    // ParentCA specifies the parent CA's CN for intermediates
    ParentCA string
}
```

### Environment Variable Overrides

| Variable | Description |
|----------|-------------|
| `CA_SUBJECT_CN` | Override Common Name |
| `CA_SUBJECT_O` | Override Organization |
| `CA_SUBJECT_OU` | Override Organizational Unit |
| `CA_SUBJECT_C` | Override Country |
| `CA_SUBJECT_ST` | Override State/Province |
| `CA_SUBJECT_L` | Override Locality |

### Example YAML Configuration

```yaml
identity:
  - subject:
      cn: "Example Root CA"
      organization: "Example Corp"
      country: "US"
    valid: 10
    keys:
      - algorithm: "ECDSA"
        ecc-curve: "P-384"
        hash: "SHA-384"
    keystore-type: "software"
    is-root: true

  - subject:
      cn: "Example Intermediate CA"
      organization: "Example Corp"
      country: "US"
    valid: 5
    keys:
      - algorithm: "ECDSA"
        ecc-curve: "P-256"
        hash: "SHA-256"
    keystore-type: "software"
    is-root: false
    parent-ca: "Example Root CA"

selected-ca: 1
default-validity-days: 365
include-localhost-sans: false
```

### ConfigBuilder Pattern

```go
config, err := ca.NewConfigBuilder().
    WithRootCA(
        ca.Subject{CommonName: "Root CA", Organization: "Org"},
        10, // validity years
        nil, // use default keys
        "software",
    ).
    WithIntermediateCA(
        ca.Subject{CommonName: "Intermediate CA", Organization: "Org"},
        5,
        nil,
        "tpm2",
        "Root CA",
    ).
    WithSelectedCA(1).
    WithDefaultValidityDays(365).
    Build()
```

## Certificate Profiles

Profiles define standard configurations for different certificate types.

### Built-in Profiles

| Profile | Key Usage | Extended Key Usage | Default Validity |
|---------|-----------|-------------------|------------------|
| `server` | DigitalSignature, KeyEncipherment | ServerAuth | 365 days |
| `client` | DigitalSignature, KeyEncipherment | ClientAuth | 365 days |
| `code-signing` | DigitalSignature | CodeSigning | 365 days |
| `email` | DigitalSignature, ContentCommitment, KeyEncipherment | EmailProtection | 365 days |
| `ocsp-responder` | DigitalSignature | OCSPSigning | 90 days |
| `timestamping` | DigitalSignature, ContentCommitment | TimeStamping | 365 days |
| `ca` | DigitalSignature, CertSign, CRLSign | - | 1825 days |

### PIV Profiles (NIST SP 800-73-4)

| Profile | Slot | Purpose | Key Usage |
|---------|------|---------|-----------|
| `piv-authentication` | 9A | User authentication | DigitalSignature |
| `piv-signature` | 9C | Document signing | DigitalSignature, ContentCommitment |
| `piv-key-management` | 9D | Encryption/key agreement | KeyEncipherment, KeyAgreement |
| `piv-card-auth` | 9E | Card authentication | DigitalSignature |

```go
import "github.com/jeremyhahn/go-xkms/pkg/ca/profiles"

// Get profile for a specific slot
profile, err := profiles.PIVProfileForSlot(profiles.SlotAuthentication)

// Register all PIV profiles
profiles.RegisterPIVProfiles(registry)
```

### mTLS Profiles

| Profile | Purpose | Extended Key Usage |
|---------|---------|-------------------|
| `mtls-client` | Client authentication | ClientAuth |
| `mtls-server` | Server authentication | ServerAuth |
| `mtls-dual` | Bidirectional auth | ClientAuth, ServerAuth |

```go
import "github.com/jeremyhahn/go-xkms/pkg/ca/profiles"

// Issue mTLS certificate
cert, err := caInstance.IssueCertificateWithProfile(request, "mtls-dual")

// Register mTLS profiles
profiles.RegisterMTLSProfiles(registry)
```

### TCG Profiles (Trusted Computing Group)

TCG profiles are used for TPM device identity and attestation certificates per TCG TPM 2.0 Keys for Device Identity and Attestation. All TCG certificates use indefinite validity (`99991231235959Z` NotAfter).

| Profile | Key Usage | Extended Key Usage | Validity |
|---------|-----------|-------------------|----------|
| `tcg-ek` | KeyEncipherment | ClientAuth, ServerAuth | Indefinite |
| `tcg-ak` | DigitalSignature | ClientAuth, ServerAuth | Indefinite |
| `tcg-idevid` | DigitalSignature, KeyEncipherment | ClientAuth, ServerAuth | Indefinite |

```go
import "github.com/jeremyhahn/go-xkms/pkg/ca/profiles"

// Register all TCG profiles
profiles.RegisterTCGProfiles(registry)

// Or create individual profiles
ekProfile := profiles.NewTCGEKProfile()
akProfile := profiles.NewTCGAKProfile()
idevidProfile := profiles.NewTCGIDevIDProfile()
```

### Creating Custom Profiles

```go
import "github.com/jeremyhahn/go-xkms/pkg/ca/profiles"

profile := profiles.NewBaseProfile("api-gateway",
    profiles.WithDescription("API Gateway mTLS certificate"),
    profiles.WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
    profiles.WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
    profiles.WithValidity(180),
)

registry := profiles.NewRegistry()
registry.Register(profile)
```

## TCG Trusted Computing Certificates

The CA supports issuing TCG-compliant certificates for TPM device identity and attestation per the TCG TPM 2.0 Keys for Device Identity and Attestation specification. This is exposed through the `TCGCA` interface, which extends `XKMSCA`.

### Layer Model

```
Layer 3: Transport Bindings (go-trusted-ca)
  ACME enroll-01 / endorse-01 / device-attest-01
  |
Layer 2: TCG Enrollment Protocol (go-xkms)
  pkg/ca/tcg_enrollment.go - EnrollDevice()
  |
Layer 1: Cryptographic Primitives (go-xkms)
  pkg/tpm2/ - MakeCredentialWithExternalEK, ActivateCredential
  pkg/ca/  - XKMSCA (SignCSR, IssueCertificate, etc.)
```

### TCGCA Interface

```go
type TCGCA interface {
    XKMSCA  // Embeds all standard CA operations

    // Issue an EK certificate per TCG EK Credential Profile
    IssueEKCertificate(request *CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error)

    // Issue an Attestation Key certificate
    IssueAKCertificate(request *CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error)

    // Verify and sign a TCG-CSR-IDEVID, returning IAK and IDevID certs (DER)
    SignTCGCSRIDevID(tcgCSR *tpm2.TCG_CSR_IDEVID, request *CertificateRequest) (iakDER, idevidDER []byte, err error)

    // Complete enrollment: verify CSR, MakeCredential challenge, issue certs
    EnrollDevice(packedCSR []byte, request *CertificateRequest) (*TCGEnrollmentResult, error)

    // Configure TPM for enrollment operations
    SetTPM(tpm tpm2.TrustedPlatformModule)
}
```

### CertificateRequest TCG Fields

The `CertificateRequest` includes fields specific to TCG certificate operations:

```go
type CertificateRequest struct {
    // ... standard fields ...

    ProdModel          string  // TPM product model for TCG extensions
    ProdSerial         string  // TPM product serial for TCG extensions
    PermanentID        string  // Optional permanent identifier (RFC 4043)
    IssuerKeyStoreType string  // CA keystore type ("TPM2", "PKCS8", "PKCS11")
}
```

### Issuing an EK Certificate

```go
// Cast to TCGCA for TCG operations
tcgCA := caInstance.(ca.TCGCA)

ekCert, err := tcgCA.IssueEKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "Device-EK-001",
        Organization: "Example Corp",
    },
    ProdModel:  "TPM-Model-X",
    ProdSerial: "SN-12345",
}, ekPublicKey)
```

The issued EK certificate includes:
- `tcg-kp-EKCertificate` (2.23.133.8.1) marker extension
- TPM specification extension (Family 2.0)
- TPM model and version extensions (when ProdModel/ProdSerial are set)
- `tp-keyStore: TPM2` extension
- Indefinite validity (`99991231235959Z`)
- KeyEncipherment key usage

### Issuing an AK Certificate

```go
akCert, err := tcgCA.IssueAKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "Device-AK-001",
        Organization: "Example Corp",
    },
}, akPublicKey)
```

The issued AK certificate includes:
- `tcg-kp-AIKCertificate` (2.23.133.8.3) marker extension
- TCG policy OIDs for TPM residency and fixed attributes
- DigitalSignature key usage (attestation, quotes)
- Indefinite validity

### TCG Device Enrollment Protocol

The enrollment flow implements TCG TPM 2.0 Keys for Device Identity and Attestation Section 6.2.2:

```
Device                           CA (EnrollDevice)
  |                                |
  |-- TCG-CSR-IDEVID (packed) --> |
  |                                | 1. Unmarshal CSR
  |                                | 2. Parse EK cert from CSR
  |                                | 3. MakeCredentialWithExternalEK
  |                                | 4. Sign CSR -> IAK + IDevID certs
  |                                |
  | <-- CredentialBlob ---------- |
  | <-- EncryptedSecret --------- |
  |                                |
  | TPM2_ActivateCredential        |
  |                                |
  |-- Decrypted Secret ---------> |
  |                                | Compare with PlainSecret
  |                                |
  | <-- IAK Certificate ----------|
  | <-- IDevID Certificate -------|
```

```go
tcgCA := caInstance.(ca.TCGCA)
tcgCA.SetTPM(tpmInstance)

// Step 1: Enroll device (server-side)
result, err := tcgCA.EnrollDevice(packedCSR, &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "device-001.factory.example.com",
        Organization: "Example Corp",
    },
})

// Step 2: Send challenge to device
// Send result.CredentialBlob and result.EncryptedSecret to device

// Step 3: Device calls TPM2_ActivateCredential, returns decrypted secret

// Step 4: Verify secret and deliver certificates
if bytes.Equal(deviceSecret, result.PlainSecret) {
    // Deliver result.IAKCertDER and result.IDevIDCertDER to device
}
```

### TCGEnrollmentResult

```go
type TCGEnrollmentResult struct {
    IAKCertDER      []byte  // DER-encoded IAK certificate
    IDevIDCertDER   []byte  // DER-encoded IDevID certificate
    CredentialBlob  []byte  // TPM2B_ID_OBJECT for ActivateCredential
    EncryptedSecret []byte  // TPM2B_ENCRYPTED_SECRET for ActivateCredential
    PlainSecret     []byte  // Original secret for verification
}
```

### Multi-Tenant Signing

TCG certificate operations support multi-tenant mode by providing an external signer and issuer certificate in the request:

```go
ekCert, err := tcgCA.IssueEKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{CommonName: "Tenant-Device-EK"},
    Signer:     tenantCASigner,    // External crypto.Signer
    IssuerCert: tenantCACert,      // Issuing CA certificate
}, ekPublicKey)
```

### TCG OIDs

TCG-specific OIDs used in certificate extensions:

| OID | Name | Purpose |
|-----|------|---------|
| 2.23.133.8.1 | `tcg-kp-EKCertificate` | EK certificate policy marker |
| 2.23.133.8.3 | `tcg-kp-AIKCertificate` | AIK/AK certificate policy marker |
| 2.23.133.2.16 | `tcg-at-tpmSpecification` | TPM specification version |
| 2.23.133.11.1.1 | `tcg-vt-tpmResidency` | Key resides in TPM |
| 2.23.133.11.1.2 | `tcg-vt-tpmFixed` | Key is non-migratable |
| 1.3.6.1.5.5.7.8.4 | `id-on-hardwareModuleName` | Hardware module SAN (RFC 4108) |
| 1.3.6.1.5.5.7.8.3 | `id-on-permanentIdentifier` | Permanent identifier (RFC 4043) |

**Trusted Platform extensions** (Private Enterprise 29377):

| OID | Name | Purpose |
|-----|------|---------|
| 1.3.6.1.4.1.29377.101.1 | `tp-issuerKeyStore` | CA keystore backend type |
| 1.3.6.1.4.1.29377.101.2 | `tp-keyStore` | Subject keystore backend type |
| 1.3.6.1.4.1.29377.101.20 | `tp-tenantID` | Multi-tenant binding |

### TCG Extension Helpers

Functions for creating and parsing TCG certificate extensions:

```go
import "github.com/jeremyhahn/go-xkms/pkg/ca"

// Create extensions
ext, err := ca.CreateTPMSpecificationExtension(ca.TCGTPMSpecification{
    Family: "2.0", Level: 0, Revision: 0,
})
ext, err = ca.CreateHardwareModuleNameExtension(hwTypeOID, serialBytes)
ext, err = ca.CreatePermanentIdentifierExtension("device-001", assignerOID)
ext, err = ca.CreateTenantIDExtension("tenant-abc")

// Parse extensions from a certificate
for _, ext := range cert.Extensions {
    if ext.Id.Equal(ca.OIDTCGAttributeTPMSpecification) {
        spec, err := ca.ParseTPMSpecificationExtension(ext.Value)
    }
    if ext.Id.Equal(ca.OIDHardwareModuleName) {
        hwName, err := ca.ParseHardwareModuleNameExtension(ext.Value)
    }
    if ext.Id.Equal(ca.OIDPermanentIdentifier) {
        permID, err := ca.ParsePermanentIdentifierExtension(ext.Value)
    }
}
```

## API Reference

### CA Interface

```go
type CA interface {
    crypto.Signer  // Implements Sign(rand, digest, opts)

    // Lifecycle
    Init() error
    Load() error
    IsInitialized() bool

    // CSR Operations
    CreateCSR(request *CertificateRequest) ([]byte, error)
    SignCSR(csrPEM []byte, opts *SignOptions) (*x509.Certificate, error)

    // Certificate Issuance
    IssueCertificate(request *CertificateRequest) (*IssuedCertificate, error)
    IssueCertificateWithProfile(request *CertificateRequest, profile string) (*IssuedCertificate, error)

    // Trust Chain
    CACertificate() (*x509.Certificate, error)
    CABundle() ([]byte, error)
    Verify(cert *x509.Certificate) ([][]*x509.Certificate, error)

    // Revocation
    Revoke(serial *big.Int, reason int) error
    GenerateCRL() ([]byte, error)
    IsRevoked(serial *big.Int) (bool, error)

    // TLS Helpers
    TLSCertificate(attrs *types.KeyAttributes) (tls.Certificate, error)
    TLSConfig(attrs *types.KeyAttributes) (*tls.Config, error)

    // Storage Access
    XKMS() xkms.KeyStore
    CertStore() certstore.CertStore
    Config() *Identity
    Identity() string
}
```

### ProfileProvider Interface

```go
type ProfileProvider interface {
    Name() string
    Apply(template *x509.Certificate, request *CertificateRequest) error
    KeyUsage() x509.KeyUsage
    ExtKeyUsage() []x509.ExtKeyUsage
    DefaultValidity() int
}
```

### Key Types

**CertificateRequest:**
```go
type CertificateRequest struct {
    Subject       Subject
    SANS          *SubjectAlternativeNames
    Valid         int  // validity in days
    KeyUsage      x509.KeyUsage
    ExtKeyUsage   []x509.ExtKeyUsage
    IsCA          bool
    MaxPathLen    int
    KeyAttributes *types.KeyAttributes
    Signer        crypto.Signer  // external signer
}
```

**SignOptions:**
```go
type SignOptions struct {
    Profile      string
    ValidityDays int
    NotBefore    time.Time
    KeyUsage     x509.KeyUsage
    ExtKeyUsage  []x509.ExtKeyUsage
    Subject      *Subject
    SANS         *SubjectAlternativeNames
}
```

**IssuedCertificate:**
```go
type IssuedCertificate struct {
    Certificate      *x509.Certificate
    CertificatePEM   []byte
    PrivateKey       crypto.PrivateKey
    PrivateKeyPEM    []byte
    CACertificatePEM []byte
    ChainPEM         []byte
    SerialNumber     *big.Int
    NotBefore        time.Time
    NotAfter         time.Time
}
```

## Integration Examples

### Using with go-dragondb

```go
// go-dragondb uses the CA for node-to-node mTLS
import (
    "github.com/jeremyhahn/go-xkms/pkg/ca"
    "github.com/jeremyhahn/go-dragondb/pkg/cluster"
)

// Issue node certificate
cert, err := caInstance.IssueCertificateWithProfile(
    &ca.CertificateRequest{
        Subject: ca.Subject{CommonName: "node-1.cluster.local"},
        SANS: &ca.SubjectAlternativeNames{
            DNS: []string{"node-1.cluster.local"},
            IPs: []string{"10.0.0.1"},
        },
    },
    "mtls-dual",
)

// Configure cluster TLS
tlsConfig, err := caInstance.MutualTLSConfig(nodeKeyAttrs)
```

### Using with go-trusted-ca (ACME)

```go
// go-trusted-ca embeds the CA for ACME certificate operations
import "github.com/jeremyhahn/go-trusted-ca/pkg/acme"

// The CA handles the underlying certificate operations
// ACME layer provides RFC 8555 protocol handling
acmeCA := acme.NewCA(acme.Config{
    CA:      caInstance,
    Domains: []string{"example.com"},
})
```

### xKey PIV Commands

```go
// Generate key in PIV slot
xkey piv generate --slot 9a --algorithm ECCP256 --pin-policy once

// Create CSR for PIV key
csrPEM, err := ca.CreateCSRWithKey(
    &ca.CertificateRequest{
        Subject: ca.Subject{CommonName: "user@example.com"},
    },
    pivSigner,
)

// Import signed certificate to PIV slot
xkey piv import --slot 9a --cert certificate.pem
```

## Security Considerations

### Serial Number Generation (RFC 5280)

The CA generates 128-bit serial numbers using `crypto/rand`:

- Complies with RFC 5280 Section 4.1.2.2 (20-octet maximum)
- Exceeds CAB Forum requirement of 64 bits of entropy
- MSB cleared to ensure positive integer encoding
- Collision detection with persistent storage

```go
// Custom persistent storage for production
type PersistentStorage struct {
    db *sql.DB
}

func (s *PersistentStorage) SerialExists(serial *big.Int) (bool, error) {
    // Query database
}

func (s *PersistentStorage) StoreSerial(serial *big.Int) error {
    // Insert into database
}

generator := ca.NewSerialGenerator(&PersistentStorage{db: db})
```

### Key Storage Backend Selection

| Backend | Use Case | Security Level |
|---------|----------|----------------|
| Software (PKCS#8) | Development, testing | Medium |
| TPM 2.0 | Production servers | High (hardware-bound) |
| PKCS#11 (HSM) | Enterprise/compliance | Very High |
| Cloud KMS | Cloud-native | High (managed) |

### CRL Generation and Distribution

```go
// Generate CRL
crlDER, err := caInstance.GenerateCRL()

// CRL validity and distribution points configured per Identity
config := ca.DefaultCAConfig()
config.Identity[0].CRLValidityDays = 7
config.Identity[0].CRLDistributionPoints = []string{
    "http://crl.example.com/ca.crl",
}
```

### TLS Configuration Best Practices

```go
// Secure TLS defaults provided
tlsConfig, err := caInstance.TLSConfigWithOptions(keyAttrs, &ca.TLSConfigOptions{
    IsServer:                 true,
    RequireClientCert:        true,
    MinVersion:               tls.VersionTLS12,
    MaxVersion:               tls.VersionTLS13,
    PreferServerCipherSuites: true,
})

// Custom peer verification with revocation checking
tlsConfig.VerifyPeerCertificate = caInstance.VerifyPeerCertificate

// Secure cipher suites
cipherSuites := ca.SecureCipherSuites()
// Returns: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
//          TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
//          TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ...
```

## Error Handling

The CA uses typed errors for consistent error handling:

```go
import "errors"

// Check specific error types
if errors.Is(err, ca.ErrNotInitialized) {
    // CA needs Init() or Load()
}

if errors.Is(err, ca.ErrCertificateRevoked) {
    // Certificate has been revoked
}

if errors.Is(err, ca.ErrProfileNotFound) {
    // Unknown profile name
}
```

Error categories:
- **Lifecycle:** `ErrNotInitialized`, `ErrAlreadyInitialized`
- **CSR:** `ErrInvalidCSR`, `ErrCSRGenerationFailed`
- **Certificate:** `ErrCertificateNotFound`, `ErrCertificateExpired`, `ErrCertificateRevoked`
- **Signing:** `ErrSigningFailed`, `ErrInvalidSignature`
- **Config:** `ErrInvalidConfig`, `ErrInvalidKeyAlgorithm`
- **Storage:** `ErrKeyStoreRequired`, `ErrCertStoreRequired`
- **TLS:** `ErrTLSConfigFailed`, `ErrKeyCertMismatch`
- **TCG Enrollment:** `ErrTPMNotConfigured`, `ErrTCGCSRVerificationFailed`, `ErrTCGMakeCredentialFailed`, `ErrTCGMissingEKCert`, `ErrTCGInvalidEKCert`, `ErrTCGInvalidPublicKey`, `ErrTCGInvalidIssuer`, `ErrTCGCertIssuanceFailed`, `ErrTCGIAKKeyExtraction`, `ErrTCGCSRUnmarshalFailed`
- **TCG Extensions:** `ErrTCGExtensionEncoding`, `ErrTCGExtensionParsing`, `ErrTCGTenantIDEmpty`

## Related Documentation

- [Full-Stack Protocol Parity](./protocol-parity.md)
- [CA CLI Reference](../usage/cli/ca.md)
- [Secure CA Bundle Bootstrap](./bootstrap.md)
- [go-xkms Backends](../backends/)
- [PIV Smart Card Support](../piv/)
- [PKCS#11 Integration](../pkcs11/)
- [FIDO2/WebAuthn](../fido2/)
