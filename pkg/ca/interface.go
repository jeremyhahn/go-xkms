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

// Package ca provides a XKMSCA implementation for certificate authority operations.
//
// XKMSCA is the foundation library that go-trusted-ca embeds for ACME/TCG operations,
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
// All XKMSCA implementations must be thread-safe. Concurrent certificate issuance,
// signing, and revocation operations are supported. The underlying keystore and
// certificate store handle their own synchronization.
//
// # Key Storage
//
// XKMSCA delegates all key storage operations to go-xkms's KeyStore interface,
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
//	basicCA, err := ca.New(params)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := basicCA.Init(); err != nil {
//	    log.Fatal(err)
//	}
//
//	issued, err := basicCA.IssueCertificate(&ca.CertificateRequest{
//	    Subject: ca.Subject{CommonName: "server.example.com"},
//	})
package ca

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// XKMSCA defines the interface for a Certificate Authority.
//
// XKMSCA embeds crypto.Signer to provide direct signing operations using the
// CA's private key. This allows the CA to be used directly in contexts that
// require a crypto.Signer, such as certificate signing or TLS configuration.
//
// All methods are thread-safe and can be called concurrently from multiple
// goroutines. The implementation uses the underlying keystore's synchronization
// mechanisms to ensure safe concurrent access.
type XKMSCA interface {
	crypto.Signer

	// ========================================================================
	// Lifecycle Operations
	// ========================================================================

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
	Init() error

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
	Load() error

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

	// ========================================================================
	// CSR Operations
	// ========================================================================

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
	SignCSR(csrPEM []byte, opts *SignOptions) (*x509.Certificate, error)

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
	CreateCSR(request *CertificateRequest) ([]byte, error)

	// ========================================================================
	// Certificate Issuance
	// ========================================================================

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
	IssueCertificate(request *CertificateRequest) (*IssuedCertificate, error)

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
	IssueCertificateWithProfile(request *CertificateRequest, profile string) (*IssuedCertificate, error)

	// ========================================================================
	// Trust Chain Operations
	// ========================================================================

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
	// Thread-safe: Yes
	Verify(cert *x509.Certificate) ([][]*x509.Certificate, error)

	// ========================================================================
	// Revocation Operations
	// ========================================================================

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
	Revoke(serial *big.Int, reason int) error

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
	GenerateCRL() ([]byte, error)

	// IsRevoked checks if a certificate serial number is revoked.
	//
	// Returns true if the certificate with the given serial number has been
	// revoked, false otherwise.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	//
	// Thread-safe: Yes
	IsRevoked(serial *big.Int) (bool, error)

	// ========================================================================
	// TLS Helpers
	// ========================================================================

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
	TLSCertificate(attrs *types.KeyAttributes) (tls.Certificate, error)

	// TLSConfig returns a TLS configuration for the given key attributes.
	//
	// This creates a complete tls.Config with:
	//   - The certificate and private key loaded
	//   - The CA certificate pool configured for client verification
	//   - Secure cipher suites and TLS versions enabled
	//   - Optional client authentication based on configuration
	//
	// Returns ErrTLSConfigFailed if the configuration cannot be created.
	// Returns ErrCertificateNotFound if the certificate does not exist.
	//
	// Thread-safe: Yes
	TLSConfig(attrs *types.KeyAttributes) (*tls.Config, error)

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
	QuantumSafeTLSConfig(attrs *types.KeyAttributes) (*tls.Config, error)

	// ========================================================================
	// Trust Pool Builders
	// ========================================================================

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

	// ========================================================================
	// Storage Access
	// ========================================================================

	// KeyStore returns the underlying keystore.
	//
	// This provides direct access to the keystore for advanced operations
	// not exposed through the XKMSCA interface, such as key rotation,
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

	// ========================================================================
	// Configuration
	// ========================================================================

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
}

// BasicCA is an alias for XKMSCA for backward compatibility.
// go-qrdb and other consumers reference BasicCA.
type BasicCA = XKMSCA

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

// TCGCA extends XKMSCA with TCG Trusted Computing certificate operations
// for TPM device identity (IDevID), attestation key (AK), and endorsement
// key (EK) per TCG TPM 2.0 Keys for Device Identity and Attestation.
//
// TCGCA embeds XKMSCA and adds methods for issuing TCG-compliant certificates
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
//	basicCA, _ := ca.New(params)
//	basicCA.Init()
//
//	// Cast to TCGCA for TCG operations
//	tcgCA := basicCA.(ca.TCGCA)
//	tcgCA.SetTPM(tpmInstance)
//
//	// Enroll a device
//	result, err := tcgCA.EnrollDevice(packedCSR, &ca.CertificateRequest{
//	    Subject: ca.Subject{CommonName: "device-001"},
//	})
type TCGCA interface {
	XKMSCA

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
	IssueEKCertificate(request *CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error)

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
	IssueAKCertificate(request *CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error)

	// SignTCGCSRIDevID verifies and signs a TCG-CSR-IDEVID for device identity
	// enrollment. Verifies the CSR signature, extracts IAK/IDevID public keys,
	// and issues both IAK and IDevID certificates.
	//
	// Returns ErrNotInitialized if the CA has not been initialized.
	// Returns ErrInvalidCSR if tcgCSR is nil.
	// Returns ErrTCGCSRVerificationFailed if signature verification fails.
	//
	// Thread-safe: Yes
	SignTCGCSRIDevID(tcgCSR *tpm2.TCG_CSR_IDEVID, request *CertificateRequest) (iakDER, idevidDER []byte, err error)

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
	EnrollDevice(packedCSR []byte, request *CertificateRequest) (*TCGEnrollmentResult, error)

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
