# CA API Reference

## Overview

This document provides comprehensive API documentation for the Certificate Authority module.

## Initialization

### New

```go
func New(config Config, certStore certstore.CertStore, objectStore common.Storage) (*CA, error)
```

Creates a new Certificate Authority instance with legacy single-store configuration.

**Parameters:**
- `config` - CA configuration including root and intermediate CA settings
- `certStore` - go-xkms CertStore for certificate management
- `objectStore` - go-objstore Storage for revocation data and attestation

**Returns:**
- Fully initialized CA ready to sign certificates
- Error if initialization fails

**Example:**
```go
config := ca.DefaultConfig()
authority, err := ca.New(config, certStore, objectStore)
if err != nil {
    log.Fatal(err)
}
```

### NewWithParams

```go
func NewWithParams(params Params) (*CA, error)
```

Creates a new CA instance using the Params struct. This is the preferred constructor for per-CA store configurations.

**Params struct:**
```go
type Params struct {
    Config             Config
    KeyStoreFactory    KeyStoreFactory
    CertStoreFactory   CertStoreFactory
    ObjectStoreFactory ObjectStoreFactory
    // BackendForStore, when set, enables per-key keystore routing.
    // The CA calls it once per unique StoreType found in the CA identity's
    // Keys slice and caches the result. See BackendForStoreFunc for details.
    BackendForStore    BackendForStoreFunc
    // Legacy fields
    KeyStore    xkms.Backend
    CertStore   certstore.CertStore
    ObjectStore common.Storage
}
```

**Example:**
```go
authority, err := ca.NewWithParams(ca.Params{
    Config:             config,
    KeyStoreFactory:    myKeyStoreFactory,
    CertStoreFactory:   myCertStoreFactory,
    ObjectStoreFactory: myObjectStoreFactory,
})
```

### Init

```go
func (ca *CA) Init() error
```

Explicitly initializes the CA by creating root and intermediate certificates. Use with `LazyInitialization: true`.

**Returns:**
- `nil` on success
- `ErrAlreadyInitialized` if CA is already initialized

### Load

```go
func (ca *CA) Load() error
```

Loads an existing CA from storage without creating new keys or certificates.

**Returns:**
- `nil` on success
- `ErrNotInitialized` if CA hasn't been initialized

### IsInitialized

```go
func (ca *CA) IsInitialized() bool
```

Returns true if the CA has been initialized and is ready to use.

---

## CSR Operations

### SignCSR

```go
func (ca *CA) SignCSR(csrPEM []byte, request *CertificateRequest) (*x509.Certificate, error)
```

Signs a PEM-encoded Certificate Signing Request.

**Parameters:**
- `csrPEM` - PEM-encoded CSR bytes
- `request` - Certificate request parameters

**CertificateRequest struct:**
```go
type CertificateRequest struct {
    SANS        *SubjectAlternativeNames
    Subject     Subject
    Valid       int  // Validity in days
    PermanentID string
    ProdModel   string
    ProdSerial  string
    KeyUsage    x509.KeyUsage
    ExtKeyUsage []x509.ExtKeyUsage
    IsCA        bool
    MaxPathLen  int
    KeyAttributes *types.KeyAttributes

    // Multi-tenant support
    Signer      crypto.Signer
    IssuerCert  *x509.Certificate
}
```

**Example:**
```go
cert, err := authority.SignCSR(csrPEM, &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "example.com",
        Organization: "Example Inc",
    },
    Valid: 365,
    SANS: &ca.SubjectAlternativeNames{
        DNS: []string{"example.com", "www.example.com"},
    },
    KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
    ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
})
```

**Quantum Signing:** When the CA signer is an ML-DSA key, hybrid certificates are automatically created with both classical and quantum signatures. Build with `-tags quantum_safe` to enable.

### CreateCSR

```go
func (ca *CA) CreateCSR(request *CertificateRequest) ([]byte, error)
```

Generates a PEM-encoded Certificate Signing Request.

**Parameters:**
- `request` - Certificate request with KeyAttributes specifying the signing key

**Returns:**
- PEM-encoded CSR bytes

**Example:**
```go
csrPEM, err := authority.CreateCSR(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "my-service",
    },
    KeyAttributes: &types.KeyAttributes{
        CN:           "my-service",
        KeyAlgorithm: x509.ECDSA,
    },
    SANS: &ca.SubjectAlternativeNames{
        DNS: []string{"my-service.internal"},
    },
})
```

---

## Certificate Lifecycle

### IssueCertificate

```go
func (ca *CA) IssueCertificate(request *CertificateRequest) (*x509.Certificate, error)
```

Issues a new certificate by generating a key pair and signing the certificate. The key is stored in the CA's keystore.

**Parameters:**
- `request` - Certificate request parameters including subject, validity, and key attributes

**Returns:**
- Signed X.509 certificate
- Error if key generation or signing fails

**Example:**
```go
cert, err := authority.IssueCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "my-service",
        Organization: "Example Inc",
    },
    Valid: 365,
    SANS: &ca.SubjectAlternativeNames{
        DNS: []string{"my-service.example.com"},
    },
    KeyAttributes: &types.KeyAttributes{
        KeyAlgorithm: x509.ECDSA,
    },
})
```

**Quantum Signing:** When the CA signer is an ML-DSA key, hybrid certificates are automatically created with both classical and quantum signatures. Quantum signing can also be explicitly requested via `request.KeyAttributes.QuantumAttributes`. Build with `-tags quantum_safe` to enable.

---

## TPM Certificate Operations

### SignTCGCSRIDevID

```go
func (ca *CA) SignTCGCSRIDevID(
    tcgCSRIDevID *tpm2.TCG_CSR_IDEVID,
    request *CertificateRequest,
) (iakDER []byte, idevidDER []byte, err error)
```

Signs a TCG-CSR-IDEVID per the TPM 2.0 Keys for Device Identity specification.

**Parameters:**
- `tcgCSRIDevID` - TCG-CSR-IDEVID structure from TPM client
- `request` - Certificate request parameters. `request.Subject` is the IDevID
  subject; it is used unchanged.

**Returns:**
- `iakDER` - DER-encoded IAK certificate, subject CN
  `IAKCommonName(model, serial)` = `iak-<model>-<serial>` (model and serial
  read from the CSR's `ProdModel` / `ProdSerial`), the rest of the subject
  copied from `request.Subject`
- `idevidDER` - DER-encoded IDevID certificate, subject `request.Subject`

Both certificates are persisted to the certificate store, which keys records
by subject common name. The two names differ, so both records survive:
`ListCertificates` returns both, either can be revoked, and the IAK can be
read back with `IAKCertificate`. Stores written before this behavior held only
the IDevID record (the IAK had been overwritten); re-enrollment or a re-issue
repopulates the IAK record, no migration fabricates one.

**Example:**
```go
iakDER, idevidDER, err := authority.SignTCGCSRIDevID(tcgCSR, &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-12345",
    },
})
```

### IAKCommonName

```go
func IAKCommonName(model, serial string) string
```

Returns `iak-<model>-<serial>`, the subject common name under which
`SignTCGCSRIDevID` issues and stores a device's IAK certificate. It is the
single definition of that name: issuance and lookup both go through it.
Re-exported by `sdk/go/acme` as `CAIAKCommonName`.

### IAKCertificate

```go
func (ca *CA) IAKCertificate(
    ctx context.Context,
    model, serial string,
) (*x509.Certificate, error)
```

Returns the IAK certificate recorded for the device identified by product
model and serial number. Exposed through the `IAKCertificateReader` interface
(re-exported as `sdk/go/acme.CAIAKCertificateReader`), which sits beside
`TCGCA` rather than inside it so existing `TCGCA` implementations keep
compiling; a caller holding a `TCGCA` type-asserts to it.

**Errors:**
- `ErrNotInitialized` - the CA has not been initialized
- `ErrCertificateNotFound` - no IAK record for the device; the detail names
  the looked-up common name

### IssueEKCertificate

```go
func (ca *CA) IssueEKCertificate(
    request *CertificateRequest,
    ekPubKey crypto.PublicKey,
) (*x509.Certificate, error)
```

Issues an Endorsement Key certificate per TCG EK Credential Profile.

**Parameters:**
- `request` - Certificate request with device information
- `ekPubKey` - EK public key (RSA or ECDSA)

**Example:**
```go
ekCert, err := authority.IssueEKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-ek",
    },
    ProdModel:   "TPM-Model-X",
    ProdSerial:  "SN12345",
    PermanentID: "device-12345",
}, ekPublicKey)
```

### IssueAKCertificate

```go
func (ca *CA) IssueAKCertificate(
    request *CertificateRequest,
    pubKey crypto.PublicKey,
) (*x509.Certificate, error)
```

Issues an Attestation Key certificate per TCG specifications.

**Parameters:**
- `request` - Certificate request
- `pubKey` - AK public key (RSA, ECDSA, or Ed25519)

**Example:**
```go
akCert, err := authority.IssueAKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-ak",
    },
}, akPublicKey)
```

### SetTPM

```go
func (ca *CA) SetTPM(tpm xkmstpm2.TrustedPlatformModule)
```

Sets the TPM instance for enrollment operations. Required before using `VerifyTCG_CSR_IDevIDBytes`.

### VerifyTCG_CSR_IDevIDBytes

```go
func (ca *CA) VerifyTCG_CSR_IDevIDBytes(
    packedCSR []byte,
    sigAlg interface{},
) (credentialBlob, encryptedSecret, secret []byte, err error)
```

Verifies a packed TCG-CSR-IDEVID and generates credential components for TPM-based device enrollment.

---

## Certificate Retrieval

### Certificate

```go
func (ca *CA) Certificate(attrs *types.KeyAttributes) (*x509.Certificate, error)
```

Retrieves a certificate by key attributes.

### CertificatePEM

```go
func (ca *CA) CertificatePEM(cn string) ([]byte, error)
```

Retrieves a PEM-encoded certificate by common name.

### TrustedRoot

```go
func (ca *CA) TrustedRoot() (*x509.Certificate, error)
```

Returns the root CA certificate.

### TrustedIntermediate

```go
func (ca *CA) TrustedIntermediate() (*x509.Certificate, error)
```

Returns the intermediate CA certificate, or nil if no intermediate is configured.

### CABundle

```go
func (ca *CA) CABundle(
    storeType types.StoreType,
    keyAlgorithm x509.PublicKeyAlgorithm,
) ([]byte, error)
```

Returns the PEM-encoded CA certificate bundle (intermediate + root).

**Example:**
```go
bundle, err := authority.CABundle(types.StoreTypeSoftware, x509.ECDSA)
```

### ImportCertificate

```go
func (ca *CA) ImportCertificate(certificate *x509.Certificate) error
```

Imports a certificate into the CA's certificate store.

---

## Revocation

### Revoke

```go
func (ca *CA) Revoke(
    certificate *x509.Certificate,
    keyAttrs *types.KeyAttributes,
) error
```

Revokes a certificate. If keyAttrs is provided, also deletes the private key.

**Example:**
```go
err := authority.Revoke(cert, &types.KeyAttributes{
    CN:           "my-service",
    KeyAlgorithm: x509.ECDSA,
    StoreType:    types.StoreTypeSoftware,
})
```

### GenerateCRL

```go
func (ca *CA) GenerateCRL() ([]byte, error)
```

Generates a DER-encoded Certificate Revocation List (RFC 5280).

**Example:**
```go
crlDER, err := authority.GenerateCRL()
```

### VerifyAgainstCRL

```go
func (ca *CA) VerifyAgainstCRL(cert *x509.Certificate, crlDER []byte) error
```

Checks if a certificate has been revoked according to a CRL.

**Returns:**
- `nil` if certificate is valid
- `ErrCertificateRevoked` if revoked

### ImportDistributionCRLs

```go
func (ca *CA) ImportDistributionCRLs(cert *x509.Certificate) error
```

Downloads and imports CRLs from a certificate's CRL distribution points.

---

## OCSP

### NewOCSPResponder

```go
func NewOCSPResponder(ca *CA, config OCSPResponderConfig) *OCSPResponder
```

Creates a new OCSP responder for the CA.

**OCSPResponderConfig:**
```go
type OCSPResponderConfig struct {
    CacheTTL   time.Duration  // Default: 1 hour
    NextUpdate time.Duration  // Default: 7 days
}
```

### HandleRequest

```go
func (o *OCSPResponder) HandleRequest(requestBytes []byte) ([]byte, error)
```

Processes an OCSP request and returns a signed OCSP response (RFC 6960).

**Example:**
```go
responder := ca.NewOCSPResponder(authority, ca.DefaultOCSPResponderConfig())
response, err := responder.HandleRequest(ocspRequest)
```

### CreateOCSPRequest

```go
func CreateOCSPRequest(
    cert *x509.Certificate,
    issuer *x509.Certificate,
    opts *ocsp.RequestOptions,
) ([]byte, error)
```

Creates an OCSP request for a certificate (primarily for testing).

### ClearCache

```go
func (o *OCSPResponder) ClearCache()
```

Removes all cached OCSP responses.

---

## Verification

### Verify

```go
func (ca *CA) Verify(
    certificate *x509.Certificate,
    xsigner crypto.Signer,
) ([][]*x509.Certificate, error)
```

Verifies a certificate against the CA's trust chain.

**Parameters:**
- `certificate` - Certificate to verify
- `xsigner` - Optional cross-signer for additional trust chains

**Returns:**
- All valid certificate chains

---

## Cross-Signing

### ImportXSignedCertificate

```go
func (ca *CA) ImportXSignedCertificate(
    issuerCN string,
    cert *x509.Certificate,
) error
```

Imports a cross-signed certificate into the CA's store.

### XSignedCertificate

```go
func (ca *CA) XSignedCertificate(
    attrs *types.KeyAttributes,
    issuerCN string,
) (*x509.Certificate, error)
```

Retrieves a cross-signed certificate by key attributes and issuer.

### XSignedRootCertificate

```go
func (ca *CA) XSignedRootCertificate(
    issuerCN string,
    cert *x509.Certificate,
) (*x509.Certificate, error)
```

Retrieves the cross-signed root certificate for a given issuer.

### XSignedIntermediateCertificates

```go
func (ca *CA) XSignedIntermediateCertificates(
    issuerCN string,
    cert *x509.Certificate,
) ([]*x509.Certificate, error)
```

Retrieves all intermediate certificates in a cross-signed chain.

### CrossSignedPEM

```go
func (ca *CA) CrossSignedPEM(attrs *types.KeyAttributes) ([]byte, error)
```

Returns the complete cross-signed certificate chain in PEM format.

---

## TLS Integration

### TLSCertificate

```go
func (ca *CA) TLSCertificate(attrs *types.KeyAttributes) (tls.Certificate, error)
```

Creates a tls.Certificate bundle from key attributes.

**Example:**
```go
tlsCert, err := authority.TLSCertificate(&types.KeyAttributes{
    CN:           "my-service",
    KeyAlgorithm: x509.ECDSA,
})
```

### TLSBundle

```go
func (ca *CA) TLSBundle(attrs *types.KeyAttributes) ([]byte, error)
```

Creates a PEM-encoded bundle with certificates and private key.

**Note:** Only works with software-backed keys; hardware keys cannot be exported.

### TLSConfig

```go
func (ca *CA) TLSConfig(attrs *types.KeyAttributes) (*tls.Config, error)
```

Creates a complete tls.Config with secure defaults.

**Features:**
- TLS 1.2 minimum, TLS 1.3 maximum
- Strong cipher suites only
- Automatic certificate chain
- CA bundle for client verification

### TLSConfigWithXSigner

```go
func (ca *CA) TLSConfigWithXSigner(
    attrs *types.KeyAttributes,
    xsigner interface{},
) (*tls.Config, error)
```

Creates a TLS configuration with cross-signer support.

### QuantumSafeTLSConfig

```go
func (ca *CA) QuantumSafeTLSConfig(attrs *types.KeyAttributes) (*tls.Config, error)
```

Creates a TLS configuration optimized for post-quantum algorithms.

### TLSBundleWithCrossSigner

```go
func (ca *CA) TLSBundleWithCrossSigner(
    attrs *types.KeyAttributes,
    issuerCN string,
) ([][]byte, *x509.Certificate, error)
```

Creates a TLS certificate bundle with cross-signed certificates.

---

## Trust Chain

### TrustedRootCertPool

```go
func (ca *CA) TrustedRootCertPool(
    cert *x509.Certificate,
    xsigner crypto.Signer,
) (*x509.CertPool, error)
```

Creates a cert pool with trusted root certificates.

### TrustedIntermediateCertPool

```go
func (ca *CA) TrustedIntermediateCertPool(
    cert *x509.Certificate,
    xsigner crypto.Signer,
) (*x509.CertPool, error)
```

Creates a cert pool with trusted intermediate certificates.

### CABundleCertPool

```go
func (ca *CA) CABundleCertPool(
    storeType types.StoreType,
    keyAlgorithm x509.PublicKeyAlgorithm,
) (*x509.CertPool, error)
```

Creates a cert pool from the CA bundle.

### RootCertificate

```go
func (ca *CA) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error)
```

Traverses the chain to find the root CA certificate.

### ImportIssuingCAs

```go
func (ca *CA) ImportIssuingCAs(cert *x509.Certificate) error
```

Auto-imports issuing CA certificates from AIA extension.

### ParseBundle

```go
func (ca *CA) ParseBundle(bundle []byte) ([]*x509.Certificate, error)
```

Parses a PEM-encoded certificate bundle.

---

## Accessors

### Signer

```go
func (ca *CA) Signer() (crypto.Signer, error)
```

Returns the CA's signing key as a crypto.Signer.

### CAConfig

```go
func (ca *CA) CAConfig() Config
```

Returns the CA configuration.

---

## Error Types

```go
var (
    ErrInvalidConfig           = errors.New("ca: invalid configuration")
    ErrInvalidCSR              = errors.New("ca: invalid certificate signing request")
    ErrInvalidCertificate      = errors.New("ca: invalid certificate")
    ErrCertificateNotFound     = errors.New("ca: certificate not found")
    ErrNotInitialized          = errors.New("ca: not initialized")
    ErrAlreadyInitialized      = errors.New("ca: already initialized")
    ErrInvalidKeyAlgorithm     = errors.New("ca: invalid key algorithm")
    ErrSigningFailed           = errors.New("ca: signing operation failed")
    ErrStorageError            = errors.New("ca: certificate storage error")
    ErrVerificationFailed      = errors.New("ca: certificate verification failed")

    // Revocation errors
    ErrCertificateRevoked      = errors.New("ca: certificate has been revoked")
    ErrCRLNotFound             = errors.New("ca: certificate revocation list not found")
    ErrCRLGenerationFailed     = errors.New("ca: CRL generation failed")

    // Cross-signing errors
    ErrCrossSignedNotFound     = errors.New("ca: cross-signed certificate not found")
    ErrInvalidIssuerCN         = errors.New("ca: invalid issuer common name")

    // Trust chain errors
    ErrInvalidIssuer           = errors.New("ca: invalid certificate issuer")
    ErrRootNotFound            = errors.New("ca: root certificate not found")
    ErrInvalidBundle           = errors.New("ca: invalid certificate bundle")

    // TPM errors
    ErrTPMNotConfigured        = errors.New("ca: TPM not configured")

    // OCSP errors
    ErrOCSPInvalidRequest      = errors.New("ca: invalid OCSP request")
    ErrOCSPResponseFailed      = errors.New("ca: failed to create OCSP response")
)
```

---

## Factory Interfaces

### KeyStoreFactory

```go
type KeyStoreFactory interface {
    CreateKeyStore(cn string) (interface{}, error)
}
```

Creates key stores for each CA identity.

### CertStoreFactory

```go
type CertStoreFactory interface {
    CreateCertStore(cn string) (interface{}, error)
}
```

Creates certificate stores for each CA identity.

### ObjectStoreFactory

```go
type ObjectStoreFactory interface {
    CreateObjectStore(cn string) (interface{}, error)
}
```

Creates object stores for each CA identity.

### BackendForStoreFunc

```go
type BackendForStoreFunc func(cn string, storeType types.StoreType) (xkms.Backend, error)
```

Resolves an `xkms.Backend` for a given CA common name and `StoreType`.
Set `Params.BackendForStore` (or `MultiIdentityParams.BackendForStore`) to
enable per-key keystore routing.

**Behavior:**

- Called **once per unique `StoreType`** found in the CA identity's `Keys`
  slice, not once per key.
- Must return a usable, non-nil `Backend`, or an error. Returning `(nil, nil)`
  is not permitted.
- The CA caches returned backends in a per-instance `keystoreMap`; the func
  is invoked at most once per `(cn, storeType)` pair.
- When nil, every key falls back to `Params.KeyStore` — legacy single-keystore
  behavior, zero behavior change.

**Example:**

```go
backendForStore := func(cn string, storeType types.StoreType) (xkms.Backend, error) {
    switch storeType {
    case types.StoreSoftware:
        return newSoftwareBackend(cn)
    case types.StoreTPM2:
        return newTPM2Backend(cn)
    default:
        return nil, fmt.Errorf("unsupported store type: %v", storeType)
    }
}

authority, err := ca.NewWithParams(ca.Params{
    Config:          config,
    BackendForStore: backendForStore,
})
```

---

## See Also

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Certificate Types](certificate-types.md)
