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
// # CA Lifecycle
//
// The CA struct implements the XKMSCA interface and follows a three-phase lifecycle:
//
//  1. Construction (New): Creates a CA instance with provided configuration, keystore,
//     and certificate store. The CA is not operational at this point.
//
//  2. Initialization: Choose one of:
//     - Init(): For new CAs - generates root/intermediate certificates
//     - Load(): For existing CAs - loads certificates from storage
//
//  3. Operations: Once initialized, the CA can sign CSRs, issue certificates,
//     generate CRLs, and perform other CA operations.
//
// # Thread Safety
//
// The CA implementation is fully thread-safe. All public methods use proper
// synchronization via read-write mutexes. The underlying keystore and certificate
// store also provide their own thread safety guarantees.
//
// # Example Usage
//
//	// Create configuration
//	config := ca.DefaultMultiIdentityCAConfig()
//	config.Identity[0].Subject.CommonName = "My Root CA"
//
//	// Set up storage
//	keystore, _ := xkms.New(&xkms.BackendConfig{...})
//	certStore := certstore.New(...)
//
//	// Create CA with parameters
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
//	// Initialize new CA (or use Load() for existing CA)
//	if err := basicCA.Init(); err != nil {
//	    log.Fatal(err)
//	}
//
//	// CA is now ready for operations
//	cert, err := basicCA.IssueCertificate(&ca.CertificateRequest{...})
package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Params contains the parameters for creating a new CA instance.
//
// All required fields must be non-nil. Optional fields will use sensible
// defaults if not provided.
type Params struct {
	// Config contains the per-CA configuration including identity, validity,
	// and certificate extensions.
	// Required.
	Config *CAConfig

	// KeyAttributes provides the runtime key attributes for the CA's key pair.
	// Typically derived from Identity.ToKeyAttributes() when using
	// MultiIdentityCAConfig, or constructed directly.
	// Required.
	KeyAttributes *types.KeyAttributes

	// KeyStore provides cryptographic key storage and operations.
	// All CA private keys are stored and accessed through this interface.
	// Required.
	KeyStore xkms.Backend

	// CertStore provides certificate storage and management.
	// All CA and issued certificates are stored through this interface.
	// Required.
	CertStore certstore.CertStore

	// SerialGen provides serial number generation for certificates.
	// If nil, a memory-based serial generator is used.
	// For production use, provide a persistent serial generator.
	// Optional.
	SerialGen SerialGenerator

	// Profiles provides certificate profile management.
	// If nil, default profiles (server, client, etc.) are registered.
	// Optional.
	Profiles ProfileRegistry
}

// Validate checks that all required parameters are present.
func (p *Params) Validate() error {
	if p.Config == nil {
		return ErrInvalidConfig
	}
	if err := p.Config.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if p.KeyAttributes == nil {
		return fmt.Errorf("%w: key attributes are required", ErrInvalidConfig)
	}
	if p.KeyStore == nil {
		return ErrKeyStoreRequired
	}
	if p.CertStore == nil {
		return ErrCertStoreRequired
	}
	return nil
}

// CA implements the XKMSCA interface for certificate authority operations.
//
// CA is designed to be embedded by higher-level CA implementations such as
// ACME servers or enterprise PKI systems. It provides all core CA functionality
// including certificate signing, issuance, revocation, and CRL generation.
//
// Thread-safe: All methods are safe for concurrent use.
type CA struct {
	// Configuration (multi-identity for internal hierarchy management)
	config *MultiIdentityCAConfig

	// caConfig is the flat per-CA configuration provided via Params.
	caConfig *CAConfig

	// keyAttrs holds the runtime key attributes for the CA's key pair.
	keyAttrs *types.KeyAttributes

	// Storage backends
	// keyStore backend used for CA operations
	keyStore  xkms.Backend
	certStore certstore.CertStore

	// Serial number generator
	serialGen SerialGenerator

	// Certificate profiles
	profiles ProfileRegistry

	// CA certificates (cached after initialization)
	rootCert         *x509.Certificate
	intermediateCert *x509.Certificate

	// Revocation tracking
	revocations      map[string]*RevocationInfo
	revocationsMutex sync.RWMutex

	// State management
	// Using atomic for lock-free read of initialized state
	initialized atomic.Bool

	// Mutex for write operations that modify CA state
	mu sync.RWMutex
}

// Compile-time interface compliance check
var _ XKMSCA = (*CA)(nil)

// signatureAlgorithmToName converts an x509.SignatureAlgorithm to a
// types.SignatureAlgorithmName for use in KeyConfig serialization.
func signatureAlgorithmToName(algo x509.SignatureAlgorithm) types.SignatureAlgorithmName {
	switch algo {
	case x509.MD2WithRSA:
		return types.SigMD2WithRSA
	case x509.MD5WithRSA:
		return types.SigMD5WithRSA
	case x509.SHA1WithRSA:
		return types.SigSHA1WithRSA
	case x509.SHA256WithRSA:
		return types.SigSHA256WithRSA
	case x509.SHA384WithRSA:
		return types.SigSHA384WithRSA
	case x509.SHA512WithRSA:
		return types.SigSHA512WithRSA
	case x509.SHA256WithRSAPSS:
		return types.SigSHA256WithRSAPSS
	case x509.SHA384WithRSAPSS:
		return types.SigSHA384WithRSAPSS
	case x509.SHA512WithRSAPSS:
		return types.SigSHA512WithRSAPSS
	case x509.DSAWithSHA1:
		return types.SigDSAWithSHA1
	case x509.DSAWithSHA256:
		return types.SigDSAWithSHA256
	case x509.ECDSAWithSHA1:
		return types.SigECDSAWithSHA1
	case x509.ECDSAWithSHA256:
		return types.SigECDSAWithSHA256
	case x509.ECDSAWithSHA384:
		return types.SigECDSAWithSHA384
	case x509.ECDSAWithSHA512:
		return types.SigECDSAWithSHA512
	case x509.PureEd25519:
		return types.SigEd25519
	default:
		return types.SigECDSAWithSHA256
	}
}

// caConfigToMultiIdentity converts a flat CAConfig to a MultiIdentityCAConfig
// with a single identity. This allows callers using the flat CAConfig (e.g.,
// go-dragondb) to work with the internal multi-identity CA implementation.
func caConfigToMultiIdentity(cfg *CAConfig, keyAttrs *types.KeyAttributes) *MultiIdentityCAConfig {
	// Determine the CN
	cn := cfg.Identity
	if cfg.Subject != nil && cfg.Subject.CommonName != "" {
		cn = cfg.Subject.CommonName
	}

	// Determine store type
	storeType := cfg.StoreType
	if storeType == "" {
		storeType = types.StoreSoftware
	}

	// Build key config from key attributes
	var keys []*types.KeyConfig
	if keyAttrs != nil {
		keyConfig := &types.KeyConfig{
			KeyAlgorithm:       types.ParseKeyAlgorithmString(keyAttrs.KeyAlgorithm.String()),
			Hash:               types.ParseHashName(keyAttrs.Hash.String()),
			SignatureAlgorithm: signatureAlgorithmToName(keyAttrs.SignatureAlgorithm),
			StoreType:          storeType,
			KeyType:            types.ParseKeyTypeString(keyAttrs.KeyType.String()),
		}
		if keyAttrs.ECCAttributes != nil {
			keyConfig.ECCConfig = &types.ECCConfig{
				Curve: types.EllipticCurve(types.CurveName(keyAttrs.ECCAttributes.Curve)),
			}
		}
		if keyAttrs.RSAAttributes != nil {
			keyConfig.RSAConfig = &types.RSAConfig{
				KeySize: keyAttrs.RSAAttributes.KeySize,
			}
		}
		keys = []*types.KeyConfig{keyConfig}
	} else {
		keys = DefaultKeyConfig()
	}

	// Determine validity in years (convert from days)
	validYears := cfg.ValidityDays / 365
	if validYears <= 0 {
		if cfg.IsRootCA {
			validYears = DefaultRootValidityYears
		} else {
			validYears = DefaultIntermediateValidityYears
		}
	}

	// Build the subject
	subject := Subject{CommonName: cn}
	if cfg.Subject != nil {
		subject = *cfg.Subject
	}

	identity := Identity{
		Subject:                subject,
		Valid:                  validYears,
		Keys:                   keys,
		KeystoreType:           storeType,
		IsRoot:                 cfg.IsRootCA,
		CRLDistributionPoints:  cfg.CRLDistributionPoints,
		OCSPServers:            cfg.OCSPServers,
		IssuingCertificateURLs: cfg.IssuingCertificateURLs,
		PolicyIdentifiers:      cfg.PolicyIdentifiers,
		CRLValidityDays:        cfg.CRLValidityDays,
		MaxPathLength:          cfg.MaxPathLength,
		MaxPathLengthZero:      cfg.MaxPathLengthZero,
	}

	defaultValidityDays := cfg.DefaultCertValidityDays
	if defaultValidityDays <= 0 {
		defaultValidityDays = DefaultCertValidityDays
	}

	return &MultiIdentityCAConfig{
		Identity:            []Identity{identity},
		SelectedCA:          0,
		DefaultValidityDays: defaultValidityDays,
	}
}

// New creates a new CA instance with the provided parameters.
//
// The CA is created in an uninitialized state. Call Init() to create a new CA
// with generated certificates, or Load() to load an existing CA from storage.
//
// Parameters:
//   - params: Configuration and dependencies for the CA. See Params for details.
//
// Returns an error if:
//   - Required parameters are nil (ErrKeyStoreRequired, ErrCertStoreRequired)
//   - Configuration validation fails (ErrInvalidConfig)
//
// Thread-safe: Yes
func New(params *Params) (XKMSCA, error) {
	if params == nil {
		return nil, ErrInvalidConfig
	}

	if err := params.Validate(); err != nil {
		return nil, err
	}

	// Convert the flat CAConfig to a MultiIdentityCAConfig for internal use
	multiConfig := caConfigToMultiIdentity(params.Config, params.KeyAttributes)

	ca := &CA{
		config:      multiConfig,
		caConfig:    params.Config,
		keyAttrs:    params.KeyAttributes,
		keyStore:    params.KeyStore,
		certStore:   params.CertStore,
		revocations: make(map[string]*RevocationInfo),
	}

	// Set up serial generator (use memory storage if not provided)
	if params.SerialGen != nil {
		ca.serialGen = params.SerialGen
	} else {
		ca.serialGen = NewSerialGenerator(NewMemoryStorage())
	}

	// Set up profile registry (use defaults if not provided)
	if params.Profiles != nil {
		ca.profiles = params.Profiles
	} else {
		ca.profiles = NewDefaultProfileRegistry()
	}

	return ca, nil
}

// MultiIdentityParams contains parameters for creating a CA from a
// MultiIdentityCAConfig. This is a convenience wrapper around Params
// that automatically derives the flat CAConfig and KeyAttributes from
// the multi-identity configuration.
type MultiIdentityParams struct {
	// Config contains the multi-identity CA configuration.
	// Required.
	Config *MultiIdentityCAConfig

	// KeyStore provides cryptographic key storage and operations.
	// Required.
	KeyStore xkms.Backend

	// CertStore provides certificate storage and management.
	// Required.
	CertStore certstore.CertStore

	// SerialGen provides serial number generation for certificates.
	// Optional. If nil, a memory-based serial generator is used.
	SerialGen SerialGenerator

	// Profiles provides certificate profile management.
	// Optional. If nil, default profiles are registered.
	Profiles ProfileRegistry
}

// NewFromMultiIdentityConfig creates a new CA from a MultiIdentityCAConfig.
//
// This convenience constructor derives a flat CAConfig and KeyAttributes
// from the issuing identity in the multi-identity configuration, then
// delegates to New(). This is used internally by go-xkms and by consumers
// that work with the multi-identity configuration model.
//
// Thread-safe: Yes
func NewFromMultiIdentityConfig(mp *MultiIdentityParams) (XKMSCA, error) {
	if mp == nil {
		return nil, ErrInvalidConfig
	}
	if mp.Config == nil {
		return nil, ErrInvalidConfig
	}

	// Validate the multi-identity config
	if err := mp.Config.Validate(); err != nil {
		return nil, err
	}

	// Get the issuing identity
	issuingIdentity := mp.Config.IssuingIdentity()
	if issuingIdentity == nil {
		return nil, fmt.Errorf("%w: no issuing identity found", ErrInvalidConfig)
	}

	// Derive KeyAttributes from the issuing identity
	keyAttrs, err := issuingIdentity.ToKeyAttributes()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to derive key attributes: %v", ErrInvalidConfig, err)
	}

	// Build the flat CAConfig from the issuing identity
	caConfig := &CAConfig{
		Identity:                issuingIdentity.Subject.CommonName,
		Subject:                 &issuingIdentity.Subject,
		ValidityDays:            issuingIdentity.GetValidityDays(),
		IsRootCA:                issuingIdentity.IsRoot,
		MaxPathLength:           issuingIdentity.MaxPathLength,
		MaxPathLengthZero:       issuingIdentity.MaxPathLengthZero,
		CRLDistributionPoints:   issuingIdentity.CRLDistributionPoints,
		OCSPServers:             issuingIdentity.OCSPServers,
		IssuingCertificateURLs:  issuingIdentity.IssuingCertificateURLs,
		PolicyIdentifiers:       issuingIdentity.PolicyIdentifiers,
		StoreType:               issuingIdentity.GetStoreType(),
		DefaultCertValidityDays: mp.Config.GetDefaultValidityDays(),
		CRLValidityDays:         issuingIdentity.GetCRLValidityDays(),
	}

	return New(&Params{
		Config:        caConfig,
		KeyAttributes: keyAttrs,
		KeyStore:      mp.KeyStore,
		CertStore:     mp.CertStore,
		SerialGen:     mp.SerialGen,
		Profiles:      mp.Profiles,
	})
}

// Init initializes a new Certificate Authority by generating the root
// and/or intermediate certificates based on the CA configuration.
//
// For a root CA (single identity), this generates a self-signed root certificate.
// For an intermediate CA (multiple identities), this generates the complete
// certificate hierarchy from root to the selected issuing CA.
//
// The generated certificates and keys are stored using the configured
// keystore and certificate store backends.
//
// Returns:
//   - ErrAlreadyInitialized if the CA has already been initialized
//   - ErrInvalidConfig if the configuration is invalid
//   - Storage errors if key generation or certificate storage fails
//
// Thread-safe: Yes, but should typically be called once during startup.
func (ca *CA) Init() error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.initialized.Load() {
		return ErrAlreadyInitialized
	}

	// Create root CA certificate
	if err := ca.createRootCertificate(); err != nil {
		return fmt.Errorf("failed to create root certificate: %w", err)
	}

	// Create intermediate CA certificates if configured
	if ca.config.HasIntermediate() {
		if err := ca.createIntermediateCertificates(); err != nil {
			return fmt.Errorf("failed to create intermediate certificates: %w", err)
		}
	}

	ca.initialized.Store(true)
	return nil
}

// Load loads an existing Certificate Authority from storage.
//
// This retrieves the CA's certificate chain from the certificate store and
// verifies that the corresponding private keys exist in the keystore.
// After successful loading, the CA is ready for signing operations.
//
// Returns:
//   - ErrAlreadyInitialized if the CA has already been initialized
//   - ErrCertificateNotFound if the CA certificate cannot be found
//   - ErrKeyStoreRequired if the corresponding private key is missing
//   - Storage errors if certificate retrieval fails
//
// Thread-safe: Yes, but should typically be called once during startup.
func (ca *CA) Load() error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.initialized.Load() {
		return ErrAlreadyInitialized
	}

	// Load root CA certificate
	rootIdentity := ca.config.RootIdentity()
	if rootIdentity == nil {
		return ErrInvalidConfig
	}

	rootCert, err := ca.certStore.GetCertificate(rootIdentity.Subject.CommonName)
	if err != nil {
		return fmt.Errorf("%w: root certificate: %v", ErrCertificateNotFound, err)
	}
	ca.rootCert = rootCert

	// Verify root key exists
	rootAttrs, err := rootIdentity.ToKeyAttributes()
	if err != nil {
		return fmt.Errorf("failed to get root key attributes: %w", err)
	}
	if _, err := ca.keyStore.Signer(rootAttrs); err != nil {
		return fmt.Errorf("%w: root key not found: %v", ErrKeyStoreRequired, err)
	}

	// Load intermediate certificates if configured
	if ca.config.HasIntermediate() {
		issuingIdentity := ca.config.IssuingIdentity()
		if issuingIdentity == nil {
			return ErrInvalidConfig
		}

		intermediateCert, err := ca.certStore.GetCertificate(issuingIdentity.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("%w: intermediate certificate: %v", ErrCertificateNotFound, err)
		}
		ca.intermediateCert = intermediateCert

		// Verify intermediate key exists
		intermediateAttrs, err := issuingIdentity.ToKeyAttributes()
		if err != nil {
			return fmt.Errorf("failed to get intermediate key attributes: %w", err)
		}
		if _, err := ca.keyStore.Signer(intermediateAttrs); err != nil {
			return fmt.Errorf("%w: intermediate key not found: %v", ErrKeyStoreRequired, err)
		}
	}

	ca.initialized.Store(true)
	return nil
}

// IsInitialized returns true if the CA has been initialized.
//
// A CA is considered initialized after a successful call to either Init() or Load().
// An uninitialized CA cannot perform signing operations.
//
// Thread-safe: Yes (lock-free atomic read)
func (ca *CA) IsInitialized() bool {
	return ca.initialized.Load()
}

// =============================================================================
// crypto.Signer Implementation
// =============================================================================

// Public returns the CA's public key.
//
// This returns the public key of the issuing CA certificate, which may be
// either the root CA or an intermediate CA depending on configuration.
//
// Returns nil if the CA has not been initialized.
//
// Thread-safe: Yes
func (ca *CA) Public() crypto.PublicKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	cert := ca.getIssuingCertificate()
	if cert == nil {
		return nil
	}
	return cert.PublicKey
}

// Sign signs a digest using the CA's private key.
//
// This implements the crypto.Signer interface, allowing the CA to be used
// directly in contexts that require a crypto.Signer, such as TLS configuration
// or custom signing workflows.
//
// The signing operation is delegated to the underlying keystore, which may
// use hardware-backed keys (TPM, HSM) or software keys depending on configuration.
//
// Parameters:
//   - randReader: Random source for signature generation (may be nil for deterministic algorithms)
//   - digest: The message digest to sign (pre-hashed)
//   - opts: Signature options including hash function
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrSigningFailed if the signing operation fails
//
// Thread-safe: Yes
func (ca *CA) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	signer, err := ca.getSigner()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	signature, err := signer.Sign(randReader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	return signature, nil
}

// =============================================================================
// Storage Accessors
// =============================================================================

// KeyStore returns the underlying keystore.
//
// This provides direct access to the keystore for advanced operations
// not exposed through the XKMSCA interface, such as key rotation,
// backend-specific features, or direct key management.
//
// The returned Backend should not be closed directly; the CA manages
// the lifecycle of its dependencies.
//
// Thread-safe: Yes (the Backend itself is thread-safe)
func (ca *CA) KeyStore() xkms.Backend {
	return ca.keyStore
}

// CertStore returns the certificate store.
//
// This provides direct access to the certificate store for advanced
// operations such as bulk certificate queries, direct storage access,
// or certificate store maintenance.
//
// The returned CertStore should not be closed directly; the CA manages
// the lifecycle of its dependencies.
//
// Thread-safe: Yes (the CertStore itself is thread-safe)
func (ca *CA) CertStore() certstore.CertStore {
	return ca.certStore
}

// Config returns the issuing CA identity configuration.
//
// Returns the Identity of the CA that is configured for issuing
// certificates (determined by SelectedCA in the CA configuration).
// Returns nil if no issuing identity is configured.
//
// Thread-safe: Yes
func (ca *CA) Config() *Identity {
	return ca.config.IssuingIdentity()
}

// Identity returns the CA's identity string.
//
// This is the Common Name (CN) of the issuing CA certificate and is
// used to identify the CA in logs, error messages, and certificate
// subject fields.
//
// Thread-safe: Yes
func (ca *CA) Identity() string {
	issuingIdentity := ca.config.IssuingIdentity()
	if issuingIdentity == nil {
		return ""
	}
	return issuingIdentity.Subject.CommonName
}

// =============================================================================
// Certificate Accessors
// =============================================================================

// CACertificate returns the issuing CA's certificate.
//
// For a root CA, this returns the self-signed root certificate.
// For an intermediate CA, this returns the intermediate certificate.
//
// Returns ErrNotInitialized if the CA has not been initialized.
//
// Thread-safe: Yes
func (ca *CA) CACertificate() (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	defer ca.mu.RUnlock()

	cert := ca.getIssuingCertificate()
	if cert == nil {
		return nil, ErrCertificateNotFound
	}
	return cert, nil
}

// CABundle returns the CA certificate chain in PEM format.
//
// The bundle contains all certificates in the trust chain from the
// issuing CA to the root CA, ordered from leaf to root. This format
// is suitable for inclusion in TLS configurations and certificate
// bundles.
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrInvalidCertificateChain if the chain is incomplete
//
// Thread-safe: Yes
func (ca *CA) CABundle() ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	defer ca.mu.RUnlock()

	var buf bytes.Buffer

	// Add intermediate certificate if present
	if ca.intermediateCert != nil {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.intermediateCert.Raw,
		}); err != nil {
			return nil, fmt.Errorf("%w: failed to encode intermediate certificate", ErrInvalidCertificateChain)
		}
	}

	// Add root certificate
	if ca.rootCert != nil {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.rootCert.Raw,
		}); err != nil {
			return nil, fmt.Errorf("%w: failed to encode root certificate", ErrInvalidCertificateChain)
		}
	}

	if buf.Len() == 0 {
		return nil, ErrInvalidCertificateChain
	}

	return buf.Bytes(), nil
}

// =============================================================================
// Private Helper Methods
// =============================================================================

// getIssuingCertificate returns the certificate used for signing operations.
// This is either the intermediate certificate (if configured) or the root certificate.
// Must be called with mu held (read or write).
func (ca *CA) getIssuingCertificate() *x509.Certificate {
	if ca.intermediateCert != nil {
		return ca.intermediateCert
	}
	return ca.rootCert
}

// getSigner returns the crypto.Signer for the issuing CA.
// This retrieves the signer from the keystore for the currently selected CA identity.
func (ca *CA) getSigner() (crypto.Signer, error) {
	issuingIdentity := ca.config.IssuingIdentity()
	if issuingIdentity == nil {
		return nil, ErrInvalidConfig
	}

	attrs, err := ca.getCAKeyAttributes(issuingIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer: %w", err)
	}

	return ca.keyStore.Signer(attrs)
}

// getCAKeyAttributes returns KeyAttributes for the specified identity.
// If the key type is not set, it defaults to KeyTypeCA since all CA keys
// are by definition CA keys.
func (ca *CA) getCAKeyAttributes(identity *Identity) (*types.KeyAttributes, error) {
	if identity == nil {
		return nil, ErrInvalidConfig
	}
	attrs, err := identity.ToKeyAttributes()
	if err != nil {
		return nil, err
	}
	// CA keys must always have KeyTypeCA
	if attrs.KeyType == 0 {
		attrs.KeyType = types.KeyTypeCA
	}
	return attrs, nil
}

// getOrGenerateCAKey retrieves an existing key or generates a new one if it doesn't exist.
// This makes key operations idempotent, allowing CA initialization to be retried
// without failing on "key already exists" errors.
func (ca *CA) getOrGenerateCAKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// First, try to get the existing key
	privateKey, err := ca.keyStore.GetKey(attrs)
	if err == nil {
		// Key exists, return it
		return privateKey, nil
	}

	// Key doesn't exist, generate a new one based on algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		privateKey, err = ca.keyStore.GenerateRSA(attrs)
	case x509.ECDSA:
		privateKey, err = ca.keyStore.GenerateECDSA(attrs)
	case x509.Ed25519:
		privateKey, err = ca.keyStore.GenerateEd25519(attrs)
	default:
		return nil, fmt.Errorf("%w: unsupported key algorithm: %v", ErrInvalidKeyAlgorithm, attrs.KeyAlgorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return privateKey, nil
}

// createRootCertificate generates a self-signed root CA certificate.
// Must be called with mu held (write lock).
func (ca *CA) createRootCertificate() error {
	rootIdentity := ca.config.RootIdentity()
	if rootIdentity == nil {
		return ErrInvalidConfig
	}

	// Get key attributes for the root CA
	attrs, err := ca.getCAKeyAttributes(rootIdentity)
	if err != nil {
		return fmt.Errorf("failed to get root key attributes: %w", err)
	}

	// Get existing key or generate a new one (idempotent operation)
	privateKey, err := ca.getOrGenerateCAKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to get or generate root CA key: %w", err)
	}

	// Get the signer interface
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("generated key does not implement crypto.Signer")
	}

	// Generate serial number
	serial, err := ca.serialGen.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Determine signature algorithm
	sigAlgo, err := rootIdentity.GetSignatureAlgorithm()
	if err != nil {
		return fmt.Errorf("failed to determine signature algorithm: %w", err)
	}

	// Create certificate template
	now := time.Now()
	validityDays := rootIdentity.GetValidityDays()

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               rootIdentity.Subject.ToPkixName(),
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            rootIdentity.MaxPathLength,
		MaxPathLenZero:        rootIdentity.MaxPathLengthZero,
		SignatureAlgorithm:    sigAlgo,
	}

	// Add Subject Alternative Names if configured
	if rootIdentity.SANS != nil {
		template.DNSNames = rootIdentity.SANS.DNS
		template.EmailAddresses = rootIdentity.SANS.Email
		template.IPAddresses = rootIdentity.SANS.ParseIPs()
		template.URIs = rootIdentity.SANS.ParseURIs()
	}

	// Apply CRL distribution points, OCSP servers, and issuing certificate URLs
	if len(rootIdentity.CRLDistributionPoints) > 0 {
		template.CRLDistributionPoints = rootIdentity.CRLDistributionPoints
	}
	if len(rootIdentity.OCSPServers) > 0 {
		template.OCSPServer = rootIdentity.OCSPServers
	}
	if len(rootIdentity.IssuingCertificateURLs) > 0 {
		template.IssuingCertificateURL = rootIdentity.IssuingCertificateURLs
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return fmt.Errorf("failed to create root certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %w", err)
	}

	// Store the certificate
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return fmt.Errorf("failed to store root certificate: %w", err)
	}

	ca.rootCert = cert
	return nil
}

// createIntermediateCertificates generates intermediate CA certificates.
// This creates certificates for all intermediate identities in the hierarchy.
// Must be called with mu held (write lock).
func (ca *CA) createIntermediateCertificates() error {
	intermediateIdentities := ca.config.IntermediateIdentities()
	if len(intermediateIdentities) == 0 {
		return nil
	}

	// Get root signer for signing intermediate certificates
	rootIdentity := ca.config.RootIdentity()
	if rootIdentity == nil {
		return ErrInvalidConfig
	}

	rootAttrs, err := rootIdentity.ToKeyAttributes()
	if err != nil {
		return fmt.Errorf("failed to get root key attributes: %w", err)
	}

	parentSigner, err := ca.keyStore.Signer(rootAttrs)
	if err != nil {
		return fmt.Errorf("failed to get root signer: %w", err)
	}

	parentCert := ca.rootCert

	// Create each intermediate CA in order
	for i, identity := range intermediateIdentities {
		cert, err := ca.createSingleIntermediateCertificate(&identity, parentCert, parentSigner)
		if err != nil {
			return fmt.Errorf("failed to create intermediate CA %d: %w", i+1, err)
		}

		// Store the certificate
		if err := ca.certStore.StoreCertificate(cert); err != nil {
			return fmt.Errorf("failed to store intermediate certificate: %w", err)
		}

		// If this is the selected issuing CA, store it
		if i+1 == ca.config.SelectedCA {
			ca.intermediateCert = cert
		}

		// Update parent for next intermediate in chain
		parentCert = cert

		attrs, err := identity.ToKeyAttributes()
		if err != nil {
			return fmt.Errorf("failed to get intermediate key attributes: %w", err)
		}

		parentSigner, err = ca.keyStore.Signer(attrs)
		if err != nil {
			return fmt.Errorf("failed to get intermediate signer: %w", err)
		}
	}

	// If no intermediate was selected, use the last one
	if ca.intermediateCert == nil && len(intermediateIdentities) > 0 {
		lastIdentity := &intermediateIdentities[len(intermediateIdentities)-1]
		cert, err := ca.certStore.GetCertificate(lastIdentity.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("failed to retrieve last intermediate certificate: %w", err)
		}
		ca.intermediateCert = cert
	}

	return nil
}

// createSingleIntermediateCertificate creates a single intermediate CA certificate.
func (ca *CA) createSingleIntermediateCertificate(
	identity *Identity,
	parentCert *x509.Certificate,
	parentSigner crypto.Signer,
) (*x509.Certificate, error) {
	// Get key attributes for the intermediate CA
	attrs, err := ca.getCAKeyAttributes(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to get intermediate key attributes: %w", err)
	}

	// Get existing key or generate a new one (idempotent operation)
	privateKey, err := ca.getOrGenerateCAKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get or generate intermediate CA key: %w", err)
	}

	// Get the signer interface for public key extraction
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("generated key does not implement crypto.Signer")
	}

	// Generate serial number
	serial, err := ca.serialGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Determine signature algorithm based on parent key type
	sigAlgo := determineSignatureAlgorithm(parentSigner.Public())

	// Create certificate template
	now := time.Now()
	validityDays := identity.GetValidityDays()

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               identity.Subject.ToPkixName(),
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            identity.MaxPathLength,
		MaxPathLenZero:        identity.MaxPathLengthZero,
		SignatureAlgorithm:    sigAlgo,
	}

	// Add Subject Alternative Names if configured
	if identity.SANS != nil {
		template.DNSNames = identity.SANS.DNS
		template.EmailAddresses = identity.SANS.Email
		template.IPAddresses = identity.SANS.ParseIPs()
		template.URIs = identity.SANS.ParseURIs()
	}

	// Apply CRL distribution points, OCSP servers, and issuing certificate URLs
	if len(identity.CRLDistributionPoints) > 0 {
		template.CRLDistributionPoints = identity.CRLDistributionPoints
	}
	if len(identity.OCSPServers) > 0 {
		template.OCSPServer = identity.OCSPServers
	}
	if len(identity.IssuingCertificateURLs) > 0 {
		template.IssuingCertificateURL = identity.IssuingCertificateURLs
	}

	// Sign with parent CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, signer.Public(), parentSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
	}

	return cert, nil
}

// determineSignatureAlgorithm returns the appropriate signature algorithm for the given public key.
func determineSignatureAlgorithm(pub crypto.PublicKey) x509.SignatureAlgorithm {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 224, 256:
			return x509.ECDSAWithSHA256
		case 384:
			return x509.ECDSAWithSHA384
		case 521:
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA256
		}
	case ed25519.PublicKey:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// =============================================================================
// CSR Operations
// =============================================================================

// NOTE: CreateCSR is defined in csr.go to avoid code duplication

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
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrInvalidCSR if the CSR is malformed or has an invalid signature
//   - ErrSigningFailed if the signing operation fails
//   - Storage errors if the certificate cannot be stored
//
// Thread-safe: Yes
func (ca *CA) SignCSR(csrPEM []byte, opts *SignOptions) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	// Parse the CSR
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, ErrInvalidCSR
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: invalid CSR signature: %v", ErrInvalidCSR, err)
	}

	// Get issuing CA certificate and signer
	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()

	if issuingCert == nil {
		return nil, ErrCertificateNotFound
	}

	signer, err := ca.getSigner()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	// Generate serial number
	serial, err := ca.serialGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerialGenerationFailed, err)
	}

	// Determine validity period
	validityDays := ca.config.GetDefaultValidityDays()
	if opts != nil && opts.ValidityDays > 0 {
		validityDays = opts.ValidityDays
	}

	now := time.Now()
	notBefore := now
	if opts != nil && !opts.NotBefore.IsZero() {
		notBefore = opts.NotBefore
	}

	// Build subject
	subject := csr.Subject
	if opts != nil && opts.Subject != nil {
		subject = mergeSubjects(csr.Subject, opts.Subject)
	}

	// Determine key usage
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if opts != nil && opts.KeyUsage != 0 {
		keyUsage = opts.KeyUsage
	}

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if opts != nil && opts.ExtKeyUsage != nil {
		extKeyUsage = opts.ExtKeyUsage
	}

	// Apply profile if specified
	if opts != nil && opts.Profile != "" {
		profile, err := ca.profiles.Get(opts.Profile)
		if err != nil {
			return nil, err
		}
		keyUsage = profile.KeyUsage()
		extKeyUsage = profile.ExtKeyUsage()
		if opts.ValidityDays == 0 {
			validityDays = profile.DefaultValidity()
		}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, validityDays),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		SignatureAlgorithm:    determineSignatureAlgorithm(signer.Public()),
	}

	// Add SANs from options
	if opts != nil && opts.SANS != nil {
		template.DNSNames = append(template.DNSNames, opts.SANS.DNS...)
		template.EmailAddresses = append(template.EmailAddresses, opts.SANS.Email...)
		template.IPAddresses = append(template.IPAddresses, opts.SANS.ParseIPs()...)
		template.URIs = append(template.URIs, opts.SANS.ParseURIs()...)
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuingCert, csr.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	// Store the certificate
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to store certificate: %w", err)
	}

	return cert, nil
}

// =============================================================================
// Certificate Issuance
// =============================================================================

// IssueCertificate generates a new key pair and issues a certificate.
//
// This is a convenience method that combines key generation, CSR creation,
// and certificate signing into a single operation. The generated private
// key is stored in the keystore and the certificate is stored in the
// certificate store.
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrCertificateAlreadyExists if a certificate with the same CN exists
//   - Errors from key generation or signing operations
//
// Thread-safe: Yes
func (ca *CA) IssueCertificate(request *CertificateRequest) (*IssuedCertificate, error) {
	return ca.IssueCertificateWithProfile(request, "")
}

// IssueCertificateWithProfile issues a certificate using a named profile.
//
// Profiles define standard configurations for different certificate types
// such as "server", "client", "code-signing", "ocsp-responder", etc.
// The profile specifies key usage, extended key usage, validity periods,
// and other certificate attributes.
//
// If profile is empty, the profile is determined automatically based on
// the request attributes.
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrProfileNotFound if the specified profile does not exist
//   - ErrCertificateAlreadyExists if a certificate with the same CN exists
//
// Thread-safe: Yes
func (ca *CA) IssueCertificateWithProfile(request *CertificateRequest, profile string) (*IssuedCertificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	if err := request.Validate(); err != nil {
		return nil, err
	}

	// Check if certificate already exists
	exists, err := ca.certStore.GetCertificate(request.Subject.CommonName)
	if err == nil && exists != nil {
		return nil, ErrCertificateAlreadyExists
	}

	// Create CSR using the method from csr.go
	csrPEM, err := ca.CreateCSR(request)
	if err != nil {
		return nil, err
	}

	// Build sign options
	opts := &SignOptions{
		Profile:      profile,
		ValidityDays: request.Valid,
		KeyUsage:     request.KeyUsage,
		ExtKeyUsage:  request.ExtKeyUsage,
		SANS:         request.SANS,
	}

	// Sign the CSR
	cert, err := ca.SignCSR(csrPEM, opts)
	if err != nil {
		return nil, err
	}

	// Build response
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	caCertPEM, _ := ca.CABundle()

	issued := &IssuedCertificate{
		Certificate:      cert,
		CertificatePEM:   certPEM,
		CACertificatePEM: caCertPEM,
		SerialNumber:     cert.SerialNumber,
		NotBefore:        cert.NotBefore,
		NotAfter:         cert.NotAfter,
	}

	return issued, nil
}

// =============================================================================
// Trust Chain Operations
// =============================================================================

// Verify verifies a certificate against the CA's trust chain.
//
// This performs full certificate validation including:
//   - Signature verification
//   - Validity period checking (not before, not after)
//   - Chain of trust verification
//   - Revocation checking (if CRLs are available)
//
// Returns the verified certificate chains on success.
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrInvalidCertificate if the certificate is malformed
//   - ErrCertificateExpired if the certificate has expired
//   - ErrCertificateRevoked if the certificate has been revoked
//   - ErrInvalidCertificateChain if chain validation fails
//
// Thread-safe: Yes
func (ca *CA) Verify(cert *x509.Certificate) ([][]*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	// Check if revoked
	revoked, err := ca.IsRevoked(cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrCertificateRevoked
	}

	// Build verification options
	ca.mu.RLock()
	roots := x509.NewCertPool()
	if ca.rootCert != nil {
		roots.AddCert(ca.rootCert)
	}

	intermediates := x509.NewCertPool()
	if ca.intermediateCert != nil {
		intermediates.AddCert(ca.intermediateCert)
	}
	ca.mu.RUnlock()

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificateChain, err)
	}

	return chains, nil
}

// =============================================================================
// Revocation Operations
// =============================================================================

// Revoke marks a certificate as revoked.
//
// The serial number identifies the certificate to revoke. The reason
// code should be one of the RFC 5280 CRLReason values.
//
// The revocation is recorded in the CA's revocation list and will be
// included in subsequently generated CRLs.
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrAlreadyRevoked if the certificate is already revoked
//
// Thread-safe: Yes
func (ca *CA) Revoke(serial *big.Int, reason int) error {
	if !ca.initialized.Load() {
		return ErrNotInitialized
	}

	if serial == nil {
		return ErrInvalidCertificate
	}

	key := serial.Text(10)

	ca.revocationsMutex.Lock()
	defer ca.revocationsMutex.Unlock()

	if _, exists := ca.revocations[key]; exists {
		return ErrAlreadyRevoked
	}

	ca.revocations[key] = &RevocationInfo{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
		Reason:         reason,
	}

	return nil
}

// GenerateCRL generates a Certificate Revocation List.
//
// The CRL contains all certificates that have been revoked by this CA.
// The CRL is signed by the CA's private key and includes the next update
// time based on the CA configuration.
//
// Returns the CRL in DER-encoded format.
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrCRLGenerationFailed if CRL generation fails
//
// Thread-safe: Yes
func (ca *CA) GenerateCRL() ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()

	if issuingCert == nil {
		return nil, ErrCRLGenerationFailed
	}

	signer, err := ca.getSigner()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRLGenerationFailed, err)
	}

	// Build revoked certificates list
	ca.revocationsMutex.RLock()
	revokedEntries := make([]x509.RevocationListEntry, 0, len(ca.revocations))
	for _, info := range ca.revocations {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   info.SerialNumber,
			RevocationTime: info.RevocationTime,
			ReasonCode:     info.Reason,
		})
	}
	ca.revocationsMutex.RUnlock()

	// Determine CRL validity from issuing identity
	crlValidityDays := DefaultCRLValidityDays
	if issuingIdentity := ca.config.IssuingIdentity(); issuingIdentity != nil {
		crlValidityDays = issuingIdentity.GetCRLValidityDays()
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(0, 0, crlValidityDays),
		RevokedCertificateEntries: revokedEntries,
		SignatureAlgorithm:        determineSignatureAlgorithm(signer.Public()),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuingCert, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRLGenerationFailed, err)
	}

	// Store the CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse generated CRL: %v", ErrCRLGenerationFailed, err)
	}

	if err := ca.certStore.StoreCRL(crl); err != nil {
		return nil, fmt.Errorf("failed to store CRL: %w", err)
	}

	return crlDER, nil
}

// IsRevoked checks if a certificate serial number is revoked.
//
// Returns true if the certificate with the given serial number has been
// revoked, false otherwise.
//
// Returns ErrNotInitialized if the CA has not been initialized.
//
// Thread-safe: Yes
func (ca *CA) IsRevoked(serial *big.Int) (bool, error) {
	if !ca.initialized.Load() {
		return false, ErrNotInitialized
	}

	if serial == nil {
		return false, nil
	}

	key := serial.Text(10)

	ca.revocationsMutex.RLock()
	_, revoked := ca.revocations[key]
	ca.revocationsMutex.RUnlock()

	return revoked, nil
}

// NOTE: TLS helper methods (TLSCertificate, TLSConfig, TLSConfigWithOptions,
// ServerTLSConfig, ClientTLSConfig, MutualTLSConfig, VerifyPeerCertificate)
// are defined in tls.go to keep TLS-related functionality organized.

// =============================================================================
// Helper Functions
// =============================================================================

// mergeSubjects merges CSR subject with override subject from options.
func mergeSubjects(csrSubject pkix.Name, override *Subject) pkix.Name {
	result := csrSubject

	if override.CommonName != "" {
		result.CommonName = override.CommonName
	}
	if override.Organization != "" {
		result.Organization = []string{override.Organization}
	}
	if override.OrganizationalUnit != "" {
		result.OrganizationalUnit = []string{override.OrganizationalUnit}
	}
	if override.Country != "" {
		result.Country = []string{override.Country}
	}
	if override.Province != "" {
		result.Province = []string{override.Province}
	}
	if override.Locality != "" {
		result.Locality = []string{override.Locality}
	}

	return result
}
