// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package ca provides a TrustedCA implementation for certificate authority operations.
//
// TrustedCA is the foundation library that the go-xkms ACME server embeds for ACME/TCG operations,
// and that go-qrdb uses for certificate management. It provides a complete
// certificate authority implementation with support for:
//
//   - Certificate signing request (CSR) handling
//   - Certificate issuance with configurable profiles
//   - Certificate revocation and CRL generation
//   - Trust chain management and verification
//   - TLS configuration helpers
//   - Multiple keystore backend support via go-xkms
//
// # Thread Safety
//
// All TrustedCA implementations must be thread-safe. Concurrent certificate issuance,
// signing, and revocation operations are supported. The underlying keystore and
// certificate store handle their own synchronization.
//
// # Key Storage
//
// TrustedCA delegates all key storage operations to go-xkms's KeyStore interface,
// enabling support for multiple backend types:
//
//   - Software (PKCS#8): File-based encrypted keys
//   - Hardware (PKCS#11): HSM-backed keys
//   - TPM 2.0: Platform-bound keys with attestation
//   - Cloud KMS: AWS KMS, Azure Key Vault, GCP KMS
//   - Quantum-safe: ML-DSA, ML-KEM algorithms
//
// # Certificate Storage
//
// Certificate storage is handled by go-xkms's CertStore interface, supporting:
//
//   - Local file storage
//   - Object storage (S3, GCS, Azure Blob)
//   - Database backends
//   - Distributed storage (Raft-based)
//
// # Usage Example
//
//	config := ca.DefaultMultiIdentityCAConfig()
//	config.Identity[0].Subject.CommonName = "My Root CA"
//
//	params := &ca.Params{
//	    Config:    config,
//	    KeyStore:  keystore,
//	    CertStore: certStore,
//	}
//	trustedCA, err := ca.New(params)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := trustedCA.Init(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	issued, err := trustedCA.IssueCertificate(ctx, &ca.CertificateRequest{
//	    Subject: ca.Subject{CommonName: "server.example.com"},
//	})
package ca

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TrustedCA defines the interface for a Certificate Authority.
//
// TrustedCA embeds crypto.Signer to provide direct signing operations using the
// CA's private key. This allows the CA to be used directly in contexts that
// require a crypto.Signer, such as certificate signing or TLS configuration.
//
// TrustedCA is composed of a set of smaller, cohesive sub-interfaces (CALifecycle,
// CAIssuer, CATrustChain, CARevoker, CATLSConfig, CATrustPools, CAStores,
// CAIdentityInfo, CASigningIdentity, CACertificateAccessor, CAObjectStore,
// CAChainImporter, CACrossSigner, CAAttestation, CATCGEnrollment). Consumers
// that only need one slice of CA behavior should depend on the narrower
// sub-interface instead of the full TrustedCA surface; this composition is
// purely organizational and does not change TrustedCA's method set.
//
// All methods are thread-safe and can be called concurrently from multiple
// goroutines. The implementation uses the underlying keystore's synchronization
// mechanisms to ensure safe concurrent access.
type TrustedCA interface {
	crypto.Signer

	CALifecycle
	CAIssuer
	CATrustChain
	CARevoker
	CATLSConfig
	CATrustPools
	CAStores
	CAIdentityInfo
	CASigningIdentity
	CACertificateAccessor
	CAObjectStore
	CAChainImporter
	CACrossSigner
	CAAttestation
	CATCGEnrollment
}

// CALifecycle initializes and reports on the CA's on-disk/keystore-backed
// operational state, the prerequisite for every other CA operation.
type CALifecycle interface {
	// Init initializes a new Certificate Authority by generating the root
	// and/or intermediate certificates based on the CA configuration.
	//
	// For a root CA, this generates a self-signed root certificate.
	// For an intermediate CA, this generates a CSR that must be signed by
	// the parent CA, then generates the intermediate certificate.
	//
	// Init stores the generated certificates and keys using the configured
	// keystore and certificate store backends.
	//
	// Returns ErrAlreadyInitialized if the CA has already been initialized.
	// Returns ErrInvalidConfig if the configuration is invalid.
	// Returns errors from the underlying keystore if key generation fails.
	//
	// Thread-safe: Yes, but should typically be called once during startup.
	Init(ctx context.Context) error

	// Load loads an existing Certificate Authority from storage.
	//
	// This retrieves the CA's private key from the keystore and the CA
	// certificate chain from the certificate store. After successful loading,
	// the CA is ready for signing operations.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrKeyStoreRequired if the keystore is not accessible.
	// Returns ErrCertStoreRequired if the certificate store is not accessible.
	// Returns storage errors if the key or certificates cannot be retrieved.
	//
	// Thread-safe: Yes, but should typically be called once during startup.
	Load(ctx context.Context) error

	// IsInitialized returns true if the CA has been initialized.
	//
	// A CA is considered initialized if both the CA private key exists in
	// the keystore and the CA certificate exists in the certificate store.
	//
	// This method does not verify the validity of the key or certificate,
	// only their presence in storage.
	//
	// Thread-safe: Yes
	IsInitialized() bool
}

// CAIssuer creates CSRs and turns them into issued certificates, either
// directly or via a named profile; it is the CA's certificate-minting surface.
type CAIssuer interface {
	// SignCSR signs a certificate signing request and returns the issued certificate.
	//
	// The CSR must be provided in PEM-encoded format. The SignOptions parameter
	// allows customization of the issued certificate's validity period, key usage,
	// and other attributes.
	//
	// If opts is nil, default options are applied based on the CA configuration.
	//
	// The issued certificate is automatically stored in the certificate store
	// using the certificate's Common Name as the identifier.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidCSR if the CSR is malformed or has an invalid signature.
	// Returns ErrSigningFailed if the signing operation fails.
	// Returns storage errors if the certificate cannot be stored.
	//
	// Thread-safe: Yes
	SignCSR(ctx context.Context, csrPEM []byte, opts *SignOptions) (*x509.Certificate, error)

	// CreateCSR creates a new certificate signing request for the given request.
	//
	// The CSR is generated using a newly created private key based on the
	// key attributes in the CertificateRequest. The private key is stored
	// in the keystore using the request's CommonName as the identifier.
	//
	// Returns the CSR in PEM-encoded format suitable for submission to a CA.
	//
	// Returns ErrCSRGenerationFailed if CSR creation fails.
	// Returns errors from the keystore if key generation fails.
	//
	// Thread-safe: Yes
	CreateCSR(ctx context.Context, request *CertificateRequest) ([]byte, error)

	// IssueCertificate generates a new key pair and issues a certificate.
	//
	// This is a convenience method that combines key generation, CSR creation,
	// and certificate signing into a single operation. The generated private
	// key is stored in the keystore and the certificate is stored in the
	// certificate store.
	//
	// The certificate profile is determined automatically based on the request
	// attributes (e.g., server certificate for DNS names, client certificate
	// for email addresses).
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrCertificateAlreadyExists if a certificate with the same
	// Common Name already exists.
	// Returns errors from key generation or signing operations.
	//
	// Thread-safe: Yes
	IssueCertificate(ctx context.Context, request *CertificateRequest) (*IssuedCertificate, error)

	// IssueCertificateWithProfile issues a certificate using a named profile.
	//
	// Profiles define standard configurations for different certificate types
	// such as "server", "client", "code-signing", "ocsp-responder", etc.
	// The profile specifies key usage, extended key usage, validity periods,
	// and other certificate attributes.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrProfileNotFound if the specified profile does not exist.
	// Returns ErrCertificateAlreadyExists if a certificate with the same
	// Common Name already exists.
	//
	// Thread-safe: Yes
	IssueCertificateWithProfile(ctx context.Context, request *CertificateRequest, profile string) (*IssuedCertificate, error)
}

// CATrustChain retrieves and verifies the CA's own certificate chain: the
// CA's certificate, its PEM bundle (whole or filtered), chain-walking
// helpers, and full certificate verification against that chain.
type CATrustChain interface {
	// CACertificate returns the CA's certificate.
	//
	// For a root CA, this returns the self-signed root certificate.
	// For an intermediate CA, this returns the intermediate certificate.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	//
	// Thread-safe: Yes
	CACertificate() (*x509.Certificate, error)

	// CABundle returns the CA certificate chain in PEM format.
	//
	// The bundle contains all certificates in the trust chain from the
	// issuing CA to the root CA, ordered from leaf to root. This format
	// is suitable for inclusion in TLS configurations and certificate
	// bundles.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidCertificateChain if the chain is incomplete.
	//
	// Thread-safe: Yes
	CABundle() ([]byte, error)

	// CABundleFiltered returns a CA bundle filtered by store type and algorithm.
	CABundleFiltered(storeType types.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error)

	// Verify verifies a certificate against the CA's trust chain.
	//
	// This performs full certificate validation including:
	//   - Signature verification
	//   - Validity period checking (not before, not after)
	//   - Chain of trust verification
	//   - Revocation checking (if CRLs are available)
	//
	// Returns the verified certificate chains on success.
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidCertificate if the certificate is malformed.
	// Returns ErrCertificateExpired if the certificate has expired.
	// Returns ErrCertificateRevoked if the certificate has been revoked.
	// Returns ErrInvalidCertificateChain if chain validation fails.
	//
	// When an optional cross-signing crypto.Signer is provided, Verify
	// augments the root and intermediate pools with the cross-signed
	// chain so certificates anchored by a cross-signed root are accepted.
	// Passing no xsigner preserves the standard single-root behaviour.
	//
	// Thread-safe: Yes
	Verify(cert *x509.Certificate, xsigner ...crypto.Signer) ([][]*x509.Certificate, error)

	// TrustedRoot returns the root CA certificate.
	TrustedRoot() (*x509.Certificate, error)

	// TrustedIntermediate returns the intermediate CA certificate, if any.
	TrustedIntermediate() (*x509.Certificate, error)

	// RootCertificate walks the chain from childCert to find the root CA.
	RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error)

	// ParseBundle parses a PEM-encoded certificate bundle.
	ParseBundle(bundle []byte) ([]*x509.Certificate, error)
}

// CARevoker marks certificates revoked, reports revocation status, and
// generates CRLs.
type CARevoker interface {
	// Revoke marks a certificate as revoked.
	//
	// The serial number identifies the certificate to revoke. The reason
	// code should be one of the RFC 5280 CRLReason values:
	//   - 0: Unspecified
	//   - 1: KeyCompromise
	//   - 2: CACompromise
	//   - 3: AffiliationChanged
	//   - 4: Superseded
	//   - 5: CessationOfOperation
	//   - 6: CertificateHold
	//   - 8: RemoveFromCRL
	//   - 9: PrivilegeWithdrawn
	//   - 10: AACompromise
	//
	// The revocation is recorded in the CA's revocation list and will be
	// included in subsequently generated CRLs.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrCertificateNotFound if no certificate with the given serial exists.
	// Returns ErrAlreadyRevoked if the certificate is already revoked.
	//
	// Thread-safe: Yes
	Revoke(ctx context.Context, serial *big.Int, reason int) error

	// RevokeCert revokes a certificate and optionally deletes its signing key.
	RevokeCert(ctx context.Context, cert *x509.Certificate, opts RevokeOptions) error

	// GenerateCRL generates a Certificate Revocation List.
	//
	// The CRL contains all certificates that have been revoked by this CA.
	// The CRL is signed by the CA's private key and includes the next update
	// time based on the CA configuration.
	//
	// Returns the CRL in DER-encoded format.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrCRLGenerationFailed if CRL generation fails.
	//
	// Thread-safe: Yes
	GenerateCRL(ctx context.Context) ([]byte, error)

	// IsRevoked checks if a certificate serial number is revoked.
	//
	// Returns true if the certificate with the given serial number has been
	// revoked, false otherwise.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	//
	// Thread-safe: Yes
	IsRevoked(serial *big.Int) (bool, error)
}

// CATLSConfig builds tls.Certificate/tls.Config/PEM-bundle values for the
// CA's own keys, covering client, server, quantum-safe and cross-signed
// variants.
type CATLSConfig interface {
	// TLSCertificate returns a TLS certificate for the given key attributes.
	//
	// This retrieves the private key and certificate for the specified key
	// and combines them into a tls.Certificate suitable for use with Go's
	// TLS implementation. The certificate chain is included if available.
	//
	// Returns ErrCertificateNotFound if no certificate exists for the key.
	// Returns keystore errors if the private key cannot be retrieved.
	//
	// Thread-safe: Yes
	TLSCertificate(ctx context.Context, attrs *types.KeyAttributes) (tls.Certificate, error)

	// TLSConfig returns a TLS configuration for the given key attributes.
	//
	// This creates a complete tls.Config with:
	//   - The certificate and private key loaded
	//   - The CA certificate pool configured for client verification
	//   - Secure cipher suites and TLS versions enabled
	//   - Optional client authentication based on configuration
	//
	// Note: TLSConfig defaults to client semantics (IsServer:false). For
	// listener configurations, use ServerTLSConfig to make the intent
	// explicit and avoid the SNI-not-set client-config WARN.
	//
	// Returns ErrTLSConfigFailed if the configuration cannot be created.
	// Returns ErrCertificateNotFound if the certificate does not exist.
	//
	// Thread-safe: Yes
	TLSConfig(ctx context.Context, attrs *types.KeyAttributes) (*tls.Config, error)

	// ServerTLSConfig returns a TLS configuration suitable for server
	// listeners. requireClientCert=true enables mutual TLS.
	//
	// Use this in preference to bare TLSConfig for tls.Listen / http.Server
	// callers — it makes server intent explicit, builds a config with
	// IsServer:true, and avoids the "ServerName not specified for client
	// connection" WARN that bare TLSConfig emits at startup.
	//
	// Returns ErrTLSConfigFailed if the configuration cannot be created.
	// Returns ErrCertificateNotFound if the certificate does not exist.
	//
	// Thread-safe: Yes
	ServerTLSConfig(ctx context.Context, attrs *types.KeyAttributes, requireClientCert bool) (*tls.Config, error)

	// ClientTLSConfig returns a TLS configuration suitable for clients
	// dialing TLS endpoints. serverName is required for proper SNI and
	// certificate verification.
	//
	// Returns ErrTLSConfigFailed if the configuration cannot be created.
	// Returns ErrCertificateNotFound if the certificate does not exist.
	//
	// Thread-safe: Yes
	ClientTLSConfig(ctx context.Context, attrs *types.KeyAttributes, serverName string) (*tls.Config, error)

	// QuantumSafeTLSConfig creates a TLS configuration optimized for post-quantum
	// cryptographic algorithms. This configuration enables hybrid key exchange
	// using both classical and post-quantum algorithms where supported.
	//
	// Currently clears CurvePreferences to allow the TLS runtime to negotiate
	// the best available option. When Go's crypto/tls natively supports hybrid
	// key exchange (X25519Kyber768), this method will enable it automatically.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrTLSConfigFailed if the configuration cannot be created.
	//
	// Thread-safe: Yes
	QuantumSafeTLSConfig(ctx context.Context, attrs *types.KeyAttributes) (*tls.Config, error)

	// TLSBundle returns a PEM bundle (chain + private key).
	TLSBundle(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error)

	// TLSBundleWithCrossSigner prepends cross-signed certificates.
	TLSBundleWithCrossSigner(ctx context.Context, attrs *types.KeyAttributes, xsigner crypto.Signer) ([]byte, error)

	// TLSConfigWithXSigner augments RootCAs with cross-signed certificates.
	TLSConfigWithXSigner(ctx context.Context, attrs *types.KeyAttributes, xsigner crypto.Signer) (*tls.Config, error)
}

// CATrustPools builds x509.CertPool values (root, intermediate, full bundle,
// OS trust store, and their cross-sign-aware variants) for use as
// tls.Config.RootCAs/ClientCAs.
type CATrustPools interface {
	// TrustedRootCertPool returns a certificate pool containing the root CA
	// certificate that anchors the given certificate's trust chain.
	//
	// This is useful when constructing tls.Config.RootCAs or ClientCAs pools
	// scoped to a specific root rather than the full CA bundle.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrRootNotFound if the root certificate cannot be determined.
	//
	// Thread-safe: Yes
	TrustedRootCertPool(cert *x509.Certificate) (*x509.CertPool, error)

	// TrustedIntermediateCertPool returns a certificate pool containing the
	// intermediate CA certificate(s) for the given leaf certificate's chain.
	// Returns an empty pool when the certificate is directly issued by the root.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	//
	// Thread-safe: Yes
	TrustedIntermediateCertPool(cert *x509.Certificate) (*x509.CertPool, error)

	// CABundleCertPool returns a certificate pool populated from the CA bundle.
	//
	// The pool contains all CA certificates in the trust chain (root and
	// intermediate). This is the standard pool for most TLS configurations.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidCertificateChain if the bundle cannot be built.
	//
	// Thread-safe: Yes
	CABundleCertPool() (*x509.CertPool, error)

	// OSTrustStore returns the operating system's trusted certificate pool.
	//
	// The returned pool includes all certificates in the platform trust store:
	//   - Linux: /etc/ssl/certs, /etc/pki/tls/certs, etc.
	//   - macOS: Keychain Access (System Roots)
	//   - Windows: Certificate Store (Trusted Root Certification Authorities)
	//
	// Returns an error if the OS trust store is inaccessible.
	//
	// Thread-safe: Yes
	OSTrustStore() (*x509.CertPool, error)

	// TrustedRootCertPoolWithXSigner is the cross-sign-aware variant of
	// TrustedRootCertPool.
	TrustedRootCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error)

	// TrustedIntermediateCertPoolWithXSigner is the cross-sign-aware variant
	// of TrustedIntermediateCertPool.
	TrustedIntermediateCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error)
}

// CAStores exposes the CA's underlying keystore and certificate store for
// advanced operations not covered by the rest of TrustedCA.
type CAStores interface {
	// KeyStore returns the underlying keystore.
	//
	// This provides direct access to the keystore for advanced operations
	// not exposed through the TrustedCA interface, such as key rotation,
	// backend-specific features, or direct key management.
	//
	// The returned KeyStore should not be closed directly; use the CA's
	// lifecycle methods instead.
	//
	// Thread-safe: Yes (the KeyStore itself is thread-safe)
	KeyStore() xkms.Backend

	// CertStore returns the certificate store.
	//
	// This provides direct access to the certificate store for advanced
	// operations such as bulk certificate queries, direct storage access,
	// or certificate store maintenance.
	//
	// The returned CertStore should not be closed directly; use the CA's
	// lifecycle methods instead.
	//
	// Thread-safe: Yes (the CertStore itself is thread-safe)
	CertStore() certstore.CertStore
}

// CAIdentityInfo reports the CA's static and derived configuration: its
// identity, default algorithms and validity periods, and per-store key
// attributes, without touching key material.
type CAIdentityInfo interface {
	// Config returns the issuing CA identity configuration.
	//
	// Returns the Identity of the CA that is configured for issuing
	// certificates (determined by SelectedCA in the CA configuration).
	// Returns nil if no issuing identity is configured.
	//
	// Thread-safe: Yes
	Config() *Identity

	// Identity returns the CA's identity string.
	//
	// This is typically the Common Name (CN) of the CA certificate and is
	// used to identify the CA in logs, error messages, and certificate
	// subject fields.
	//
	// Thread-safe: Yes
	Identity() string

	// IssuingIdentity returns a value copy of the Identity this CA uses
	// to sign certificates (the intermediate identity when configured,
	// otherwise the root identity). Returns a zero-value Identity when
	// no identity has been configured so callers can safely read fields
	// such as Keys without a nil check.
	IssuingIdentity() Identity

	// CAKeyAttributes returns the KeyAttributes for the CA's signing key.
	CAKeyAttributes(storeType types.StoreType) (*types.KeyAttributes, error)

	// DefaultKeyAlgorithm returns the CA's default public-key algorithm.
	DefaultKeyAlgorithm() x509.PublicKeyAlgorithm

	// DefaultSignatureAlgorithm returns the CA's default signature algorithm.
	DefaultSignatureAlgorithm() x509.SignatureAlgorithm

	// DefaultValidityPeriod returns the default validity in days.
	DefaultValidityPeriod() int

	// Hash returns the CA's signing hash function.
	Hash() crypto.Hash

	// IsAutoImportingIssuerCAs reports whether AIA auto-import is enabled.
	IsAutoImportingIssuerCAs() bool
}

// CASigningIdentity retrieves the CA's signing key material and performs raw
// signing operations against it, independent of certificate issuance.
type CASigningIdentity interface {
	// Signer returns a crypto.Signer backed by the CA's issuing identity key.
	Signer(ctx context.Context) (crypto.Signer, error)

	// PrivateKey retrieves a private key handle from the CA's keystore.
	// Hardware-bound keys are returned as opaque crypto.PrivateKey values.
	PrivateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// PubKey returns the public key half of the key identified by attrs.
	PubKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PublicKey, error)

	// SignedBlob signs arbitrary data using the CA's signing key.
	SignedBlob(ctx context.Context, data []byte) ([]byte, error)

	// CASigner returns a crypto.Signer filtered by storeType/algorithm.
	CASigner(ctx context.Context, storeType types.StoreType, algo x509.PublicKeyAlgorithm) (crypto.Signer, error)
}

// CACertificateAccessor reads and writes individual issued certificates by
// Common Name or KeyAttributes.
type CACertificateAccessor interface {
	// Exists reports whether a certificate for cn exists with the specified
	// public-key algorithm. This is the single existence check: an
	// algorithm-agnostic variant (Issued) previously sat alongside it, which
	// meant two ways to ask the same question and no reason to prefer either.
	Exists(ctx context.Context, cn string, algo x509.PublicKeyAlgorithm) (bool, error)

	// Certificate retrieves a certificate using its KeyAttributes.
	Certificate(ctx context.Context, attrs *types.KeyAttributes) (*x509.Certificate, error)

	// CertificatePEM returns the certificate identified by cn in PEM form.
	CertificatePEM(ctx context.Context, cn string) ([]byte, error)

	// ImportCertificate stores an externally-issued certificate in the CA.
	ImportCertificate(ctx context.Context, cert *x509.Certificate) error

	// ImportCertificatePEM parses a PEM-encoded certificate and imports it.
	ImportCertificatePEM(ctx context.Context, cn string, pemBytes []byte) error

	// PEM is a KeyAttributes-keyed alias for CertificatePEM.
	PEM(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error)
}

// CAObjectStore is a raw key/value passthrough to the CA's underlying object
// store, for blob data that does not fit the certificate/key model.
type CAObjectStore interface {
	// Blob returns raw blob data stored in the CA's object store.
	Blob(key []byte) ([]byte, error)

	// ImportBlob stores raw blob data in the CA's object store.
	ImportBlob(key, data []byte) error
}

// CAChainImporter fetches and imports issuer certificates and CRLs
// discovered via a certificate's AIA/CDP extensions, implementing xkms's
// AIA-driven root import capability.
type CAChainImporter interface {
	// ImportDistributionCRLs downloads and imports CRLs listed in the
	// certificate's CRLDistributionPoints extension.
	ImportDistributionCRLs(cert *x509.Certificate) error

	// ImportIssuingCAs recursively imports issuing CA certificates from the
	// certificate's AuthorityInformationAccess (AIA) extension.
	ImportIssuingCAs(ctx context.Context, cert *x509.Certificate) error
}

// CACrossSigner stores and retrieves cross-signed certificates, implementing
// xkms's cross-signed root pool capability.
type CACrossSigner interface {
	// ImportXSignedCertificate persists a cross-signed certificate.
	ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error

	// XSignedCertificate retrieves a cross-signed certificate.
	XSignedCertificate(issuerCN string, attrs *types.KeyAttributes) (*x509.Certificate, error)

	// XSignedRootCertificate walks the cross-signed chain to the root.
	XSignedRootCertificate(issuerCN string, cert *x509.Certificate) (*x509.Certificate, error)

	// XSignedIntermediateCertificates returns intermediates in the
	// cross-signed chain.
	XSignedIntermediateCertificates(issuerCN string, cert *x509.Certificate) ([]*x509.Certificate, error)

	// CrossSignedPEM returns every cross-signed certificate found for the
	// subject identified by attrs.CN.
	CrossSignedPEM(attrs *types.KeyAttributes) ([]byte, error)
}

// CAAttestation stores and verifies TPM attestation evidence (quotes, event
// logs, PCR snapshots, and AK certificates) tied to a key, per xkms's TPM
// 2.0 attestation ownership.
type CAAttestation interface {
	// ImportAttestation stores a TPM attestation blob (quote/event log/PCRs)
	// together with a CA-produced signature.
	ImportAttestation(ctx context.Context, akAttrs *types.KeyAttributes, blobType string, data []byte) error

	// ImportAttestationKeyCertificate stores a DER-encoded AK certificate.
	ImportAttestationKeyCertificate(ctx context.Context, attrs *types.KeyAttributes, akDER []byte) error

	// ImportAttestationEventLog stores a TPM event log blob.
	ImportAttestationEventLog(ctx context.Context, akAttrs *types.KeyAttributes, eventLog []byte) error

	// ImportAttestationPCRs stores a TPM PCR snapshot blob.
	ImportAttestationPCRs(ctx context.Context, akAttrs *types.KeyAttributes, pcrs []byte) error

	// ImportAttestationQuote stores a TPM quote blob.
	ImportAttestationQuote(ctx context.Context, akAttrs *types.KeyAttributes, quote []byte) error

	// ImportLocalAttestation imports a complete local attestation.
	ImportLocalAttestation(ctx context.Context, akAttrs *types.KeyAttributes, quote *tpm2.Quote) error

	// VerifyAttestationQuote checks a previously-stored quote blob.
	VerifyAttestationQuote(akAttrs *types.KeyAttributes, quote []byte) error

	// VerifyAttestationEventLog checks a previously-stored event log blob.
	VerifyAttestationEventLog(akAttrs *types.KeyAttributes, eventLog []byte) error

	// VerifyAttestationPCRs checks a previously-stored PCR snapshot blob.
	VerifyAttestationPCRs(akAttrs *types.KeyAttributes, pcrs []byte) error
}

// CATCGEnrollment verifies packed TCG-CSR-IDEVID blobs submitted for TPM
// device-identity enrollment.
type CATCGEnrollment interface {
	// VerifyTCG_CSR_IDevIDBytes verifies a packed TCG-CSR-IDEVID and returns
	// the MakeCredential challenge components for ActivateCredential.
	VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg x509.SignatureAlgorithm) (blob []byte, secret []byte, plain []byte, err error)
}

// Compile-time assertions that *CA satisfies TrustedCA and every
// sub-interface it composes. These pin the composition so an edit to
// TrustedCA's method set cannot silently drop a sub-interface's methods.
var (
	_ TrustedCA             = (*CA)(nil)
	_ CALifecycle           = (*CA)(nil)
	_ CAIssuer              = (*CA)(nil)
	_ CATrustChain          = (*CA)(nil)
	_ CARevoker             = (*CA)(nil)
	_ CATLSConfig           = (*CA)(nil)
	_ CATrustPools          = (*CA)(nil)
	_ CAStores              = (*CA)(nil)
	_ CAIdentityInfo        = (*CA)(nil)
	_ CASigningIdentity     = (*CA)(nil)
	_ CACertificateAccessor = (*CA)(nil)
	_ CAObjectStore         = (*CA)(nil)
	_ CAChainImporter       = (*CA)(nil)
	_ CACrossSigner         = (*CA)(nil)
	_ CAAttestation         = (*CA)(nil)
	_ CATCGEnrollment       = (*CA)(nil)
)

// ProfileProvider defines the interface for certificate profile providers.
//
// Profiles encapsulate standard certificate configurations for different use
// cases. Each profile specifies key usage, extended key usage, validity periods,
// and other certificate attributes appropriate for its intended purpose.
//
// Built-in profiles include:
//   - server: TLS server authentication
//   - client: TLS client authentication
//   - code-signing: Code signing operations
//   - email: S/MIME email protection
//   - ocsp-responder: OCSP response signing
//   - timestamping: Timestamp authority
//
// Custom profiles can be registered to support application-specific requirements.
//
// Thread-safe: Implementations must be thread-safe.
type ProfileProvider interface {
	// Name returns the profile name.
	//
	// The name is used to identify the profile when issuing certificates
	// with IssueCertificateWithProfile. Names should be lowercase and
	// use hyphens for multi-word names (e.g., "code-signing").
	//
	// Thread-safe: Yes
	Name() string

	// Apply applies the profile to a certificate template.
	//
	// This method modifies the certificate template in place, setting
	// key usage, extended key usage, validity periods, and other
	// profile-specific attributes.
	//
	// The request parameter provides information about the certificate
	// being issued, allowing profiles to make context-sensitive decisions.
	//
	// Returns ErrInvalidProfile if the profile cannot be applied to the
	// given request (e.g., incompatible key type).
	//
	// Thread-safe: Yes
	Apply(template *x509.Certificate, request *CertificateRequest) error

	// KeyUsage returns the key usage for this profile.
	//
	// This returns the x509.KeyUsage flags that should be set on
	// certificates issued with this profile.
	//
	// Thread-safe: Yes
	KeyUsage() x509.KeyUsage

	// ExtKeyUsage returns the extended key usage for this profile.
	//
	// This returns the slice of x509.ExtKeyUsage values that should be
	// set on certificates issued with this profile.
	//
	// Thread-safe: Yes
	ExtKeyUsage() []x509.ExtKeyUsage

	// DefaultValidity returns the default validity period in days.
	//
	// This is used when a certificate request does not specify a validity
	// period. Different profiles have different default validities based
	// on best practices for their use case.
	//
	// Thread-safe: Yes
	DefaultValidity() int
}

// ProfileRegistry provides access to certificate profiles.
//
// The registry maintains a collection of named profiles that can be used
// when issuing certificates. Profiles can be registered at startup or
// dynamically added during runtime.
//
// Thread-safe: All methods must be thread-safe.
type ProfileRegistry interface {
	// Register registers a profile with the given name.
	//
	// If a profile with the same name already exists, it is replaced.
	// Profile names are case-insensitive and normalized to lowercase.
	//
	// Returns ErrInvalidProfile if the profile is nil or invalid.
	//
	// Thread-safe: Yes
	Register(name string, profile ProfileProvider) error

	// Get returns a profile by name.
	//
	// Profile names are case-insensitive.
	//
	// Returns ErrProfileNotFound if no profile with the given name exists.
	//
	// Thread-safe: Yes
	Get(name string) (ProfileProvider, error)

	// List returns all registered profile names.
	//
	// The returned slice is sorted alphabetically and contains the
	// normalized (lowercase) profile names.
	//
	// Thread-safe: Yes
	List() []string
}

// TCGCA extends TrustedCA with TCG Trusted Computing certificate operations
// for TPM device identity (IDevID), attestation key (AK), and endorsement
// key (EK) per TCG TPM 2.0 Keys for Device Identity and Attestation.
//
// TCGCA embeds TrustedCA and adds methods for issuing TCG-compliant certificates
// and performing device enrollment using the TPM 2.0 credential activation
// protocol (MakeCredential/ActivateCredential).
//
// # Thread Safety
//
// All TCGCA methods are thread-safe and can be called concurrently.
//
// # Usage
//
//	// Create a CA that supports TCG operations
//	trustedCA, _ := ca.New(params)
//	trustedCA.Init(ctx)
//
//	// Cast to TCGCA for TCG operations
//	tcgCA := trustedCA.(ca.TCGCA)
//	tcgCA.SetTPM(tpmInstance)
//
//	// Enroll a device
//	result, err := tcgCA.EnrollDevice(ctx, packedCSR, &ca.CertificateRequest{
//	    Subject: ca.Subject{CommonName: "device-001"},
//	})
type TCGCA interface {
	TrustedCA

	// IssueEKCertificate issues an Endorsement Key certificate per TCG EK
	// Credential Profile. EK certs use indefinite validity (99991231235959Z)
	// and KeyEncipherment key usage.
	//
	// If request.Signer and request.IssuerCert are set, uses them for signing
	// (multi-tenant mode). Otherwise uses the CA's internal signer.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrTCGInvalidPublicKey if ekPubKey is nil or unsupported.
	// Returns ErrTCGInvalidIssuer if Signer is set without IssuerCert.
	//
	// Thread-safe: Yes
	IssueEKCertificate(ctx context.Context, request *CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error)

	// IssueAKCertificate issues an Attestation Key certificate per TCG spec.
	// AK certs use indefinite validity and DigitalSignature key usage with
	// TCG policy OIDs for TPM residency and fixed attributes.
	//
	// If request.Signer and request.IssuerCert are set, uses them for signing
	// (multi-tenant mode). Otherwise uses the CA's internal signer.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrTCGInvalidPublicKey if pubKey is nil or unsupported.
	// Returns ErrTCGInvalidIssuer if Signer is set without IssuerCert.
	//
	// Thread-safe: Yes
	IssueAKCertificate(ctx context.Context, request *CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error)

	// SignTCGCSRIDevID verifies and signs a TCG-CSR-IDEVID for device identity
	// enrollment. Verifies the CSR signature, extracts IAK/IDevID public keys,
	// and issues both IAK and IDevID certificates.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidCSR if tcgCSR is nil.
	// Returns ErrTCGCSRVerificationFailed if signature verification fails.
	//
	// Thread-safe: Yes
	SignTCGCSRIDevID(ctx context.Context, tcgCSR *tpm2.TCG_CSR_IDEVID, request *CertificateRequest) (iakDER, idevidDER []byte, err error)

	// EnrollDevice performs complete TCG enrollment: verifies the packed CSR,
	// generates a MakeCredential challenge, and prepares certificates.
	// The caller must complete the ActivateCredential challenge/response before
	// delivering the certificates to the device.
	//
	// Requires SetTPM() to have been called with a TrustedPlatformModule.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrTPMNotConfigured if SetTPM has not been called.
	// Returns ErrTCGCSRUnmarshalFailed if the packed CSR is invalid.
	//
	// Thread-safe: Yes
	EnrollDevice(ctx context.Context, packedCSR []byte, request *CertificateRequest) (*TCGEnrollmentResult, error)

	// SetTPM configures the TPM instance for enrollment operations requiring
	// MakeCredentialWithExternalEK (server-side credential challenge).
	//
	// Thread-safe: Yes
	SetTPM(tpm tpm2.TrustedPlatformModule)

	// VerifyQuote verifies a TPM quote signature and validates the nonce.
	//
	// This is the primary method for remote attestation verification per TCG
	// specifications. The verification process:
	//  1. Validates that the returned nonce matches the expected nonce
	//  2. Computes a SHA-256 digest of the quoted data
	//  3. Verifies the signature using the AK's public key
	//
	// The AK public key is resolved from attrs.TPMAttributes.PublicKeyBytes when
	// present, falling back to the certificate stored in the certificate store.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidRequest if attrs or quote is nil.
	// Returns ErrInvalidNonce if the nonce does not match.
	// Returns ErrInvalidSignature if the quote signature verification fails.
	//
	// Thread-safe: Yes
	VerifyQuote(attrs *types.KeyAttributes, quote *tpm2.Quote, nonce []byte) error

	// ImportEndorsementKeyCertificate imports a manufacturer-provided EK certificate
	// into the CA's certificate store. The certificate is validated for the presence
	// of the TCG EK OID extension; an absent OID generates a warning but is not
	// treated as an error to accommodate non-standard manufacturer certificates.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidCertificate if cert is nil.
	// Returns ErrStorageError if the certificate cannot be stored.
	//
	// Thread-safe: Yes
	ImportEndorsementKeyCertificate(cert *x509.Certificate) error

	// EndorsementKeyCertificate retrieves an EK certificate from the certificate
	// store by Common Name.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrCertificateNotFound if no certificate with the given CN exists.
	//
	// Thread-safe: Yes
	EndorsementKeyCertificate(cn string) (*x509.Certificate, error)
}
