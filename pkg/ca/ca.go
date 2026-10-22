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
// # CA Lifecycle
//
// The CA struct implements the TrustedCA interface and follows a three-phase lifecycle:
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
//	trustedCA, err := ca.New(params)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Initialize new CA (or use Load() for existing CA)
//	if err := trustedCA.Init(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// CA is now ready for operations
//	cert, err := trustedCA.IssueCertificate(ctx, &ca.CertificateRequest{...})
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	backendpkg "github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
	// Typically derived from Identity.ToKeyAttributes(ctx) when using
	// MultiIdentityCAConfig, or constructed directly.
	// Required.
	KeyAttributes *types.KeyAttributes

	// KeyStore provides cryptographic key storage and operations for
	// non-CA-signing-key paths (TLS certificate issuance, CSR signing for
	// leaf certificates, and the certificate cache). CA signing keys
	// (Identity.Keys) are always routed through BackendForStore.
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

	// ObjectStore provides blob storage for CA-adjacent artifacts that don't
	// fit the CertStore's CN-keyed model: cross-signed certificates, AIA
	// trust-chain cache, CRL snapshots, attestation evidence, TCG-CSR-IDEVID
	// blobs. Consumed by trust_chain.go, cross_signing.go, attestation.go
	// and tpm_enrollment.go. If nil, features that require an object store
	// return ErrObjectStoreRequired when invoked.
	// Optional.
	ObjectStore qrdbsdk.Storage

	// RevocationStore durably persists certificate revocations and the
	// derived CRL artifact in the datastore so both survive restarts and
	// replicate under Raft. Required. There is no fallback to ObjectStore or
	// to in-memory-only tracking.
	RevocationStore storage.Backend

	// Identity carries one or two CA identities for the multi-identity
	// constructors NewCA, NewParentCA, and NewIntermediateCA. Identity[0]
	// is the root; Identity[1] (if present) is the intermediate. Leave empty
	// when calling the single-identity New constructor via Config /
	// KeyAttributes. Optional.
	Identity []Identity

	// KeyStoreFactory resolves a KeyStore per-CA, keyed on the CA's
	// subject CN. When set, NewCA / NewParentCA / NewIntermediateCA invoke
	// the factory for each identity instead of using the shared KeyStore
	// field. Optional.
	KeyStoreFactory KeyStoreFactoryFunc

	// CertStoreFactory resolves a CertStore per-CA CN. See
	// KeyStoreFactory for semantics. Optional.
	CertStoreFactory CertStoreFactoryFunc

	// ObjectStoreFactory resolves an object store per-CA CN. Factories
	// may return (nil, nil) to indicate the CA has no object store.
	// Optional.
	ObjectStoreFactory ObjectStoreFactoryFunc

	// BackendForStore resolves an xkms.Backend per (CA CN, StoreType). The
	// constructors call it for every unique StoreType in the CA identity's
	// Keys and build an internal keystoreMap; every CA signing key is routed
	// to the matching backend at generation and signing time.
	//
	// Required. There is no fallback to a single shared KeyStore for every
	// StoreType: a caller with a single uniform backend supplies a factory
	// that returns it for every StoreType, making that an explicit choice
	// rather than an implicit default.
	BackendForStore BackendForStoreFunc

	// RequireKeyPassword mirrors MultiIdentityCAConfig.RequireKeyPassword for
	// the single-identity (New / NewParentCA) and multi-identity (NewCA /
	// NewIntermediateCA) constructors. When true, getOrGenerateCAKey rejects
	// an empty key password with ErrKeyPasswordRequired before any key
	// generation I/O occurs. The default (false) allows plaintext PKCS#8 keys,
	// which is appropriate when the storage layer provides equivalent
	// protection. Optional.
	RequireKeyPassword bool

	// AuditLogger records CA lifecycle events (root/intermediate
	// initialization, CRL generation, cross-signing) per the go-xkms audit
	// write-failure policy (docs/audit-log/engineering.md): every CA
	// lifecycle action is SeveritySecurity, so a failed write refuses the
	// operation rather than let it complete unaudited. A nil logger disables
	// audit logging for the CA entirely (opt-in wiring) and is not itself a
	// failure. Optional.
	AuditLogger qrdbsdk.NodeAuditLogger
}

// Validate checks that all required parameters are present.
func (p *Params) Validate() error {
	if p.Config == nil {
		return ErrInvalidConfig
	}
	if err := p.Config.Validate(); err != nil {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: fmt.Sprintf("%v", err)}
	}
	if p.KeyAttributes == nil {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "key attributes are required"}
	}
	if p.KeyStore == nil {
		return ErrKeyStoreRequired
	}
	if p.CertStore == nil {
		return ErrCertStoreRequired
	}
	if p.BackendForStore == nil {
		return ErrBackendForStoreRequired
	}
	if p.RevocationStore == nil {
		return ErrRevocationStoreRequired
	}
	return nil
}

// CA implements the TrustedCA interface for certificate authority operations.
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

	// inputIdentity preserves the full Identity (including its multi-key
	// configuration) as passed to NewParentCA / NewIntermediateCA / NewCA.
	// When non-nil, IssuingIdentity() returns a copy of it verbatim so that
	// the caller's multi-key slice is not lost by the flat-CAConfig round
	// trip. nil when the CA is constructed via New(*Params) directly.
	inputIdentity *Identity

	// keyAttrs holds the runtime key attributes for the CA's key pair.
	keyAttrs *types.KeyAttributes

	// Storage backends
	// keyStore backend used for non-CA-signing-key operations (TLS
	// certificates, leaf CSR signing, certificate cache).
	keyStore  xkms.Backend
	certStore certstore.CertStore

	// keystoreMap holds one xkms.Backend per StoreType for this CA instance,
	// populated by the constructors from the required Params.BackendForStore.
	// Every CA signing key is routed through this map. Read-only after
	// construction, so concurrent reads via resolveKeyBackend need no
	// synchronization.
	keystoreMap map[types.StoreType]xkms.Backend

	// objectStore is the optional blob store for cross-signed certs, AIA
	// trust-chain cache, and attestation evidence. May be nil; features that
	// require it return ErrObjectStoreRequired in that case.
	objectStore qrdbsdk.Storage

	// revocationStore durably persists revocation records and the derived CRL
	// artifact in the datastore so both survive restarts (and replicate under
	// Raft). Always non-nil on a constructed CA: Params.Validate() rejects a
	// nil RevocationStore. There is no fallback to objectStore or to
	// in-memory-only tracking.
	revocationStore storage.Backend

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

	// clock is the time source CRL generation and staleness detection use
	// (see now() in crl_persistence.go). nil in production, which falls
	// back to time.Now(); tests inject a fixed/advancing clock to make
	// regenerate-on-read behavior deterministic instead of sleeping out a
	// real validity window.
	clock Clock

	// fetchClient downloads the PKI objects certificate extensions point at
	// (AIA caIssuers certificates, CRL distribution points). nil in
	// production, which uses the address-filtered pkiFetchClient (see
	// pki_fetch.go); tests inject a client that may reach an httptest
	// server on loopback.
	fetchClient *http.Client

	// auditLogger records CA lifecycle events (see Params.AuditLogger and
	// pkg/ca/audit.go). nil disables audit logging for this CA instance.
	auditLogger qrdbsdk.NodeAuditLogger

	// secondaryKeyErr records the error from the most recent
	// initSecondaryKeys call during Init, or nil if every secondary key
	// (Keys[1..n] of the identity) generated successfully or the identity
	// has none. Secondary-key generation is deliberately best-effort during
	// Init — the CA is usable once the primary (Keys[0]) certificate
	// exists, so a secondary-key failure must not fail Init — but the
	// failure is not discarded: it is retained here so SecondaryKeyInitError
	// lets a caller detect a partially provisioned multi-key CA instead of
	// the failure vanishing silently. Guarded by mu.
	secondaryKeyErr error

	// State management
	// Using atomic for lock-free read of initialized state
	initialized atomic.Bool

	// Mutex for write operations that modify CA state
	mu sync.RWMutex
}

// Compile-time interface compliance check
var _ TrustedCA = (*CA)(nil)

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
// go-qrdb) to work with the internal multi-identity CA implementation.
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
		TCGConfig:           cfg.TCGConfig,
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
//   - Required parameters are nil (ErrKeyStoreRequired, ErrCertStoreRequired,
//     ErrBackendForStoreRequired)
//   - Configuration validation fails (ErrInvalidConfig)
//
// Thread-safe: Yes
func New(params *Params) (TrustedCA, error) {
	if params == nil {
		return nil, ErrInvalidConfig
	}

	if err := params.Validate(); err != nil {
		return nil, err
	}

	// Convert the flat CAConfig to a MultiIdentityCAConfig for internal use
	multiConfig := caConfigToMultiIdentity(params.Config, params.KeyAttributes)
	// Propagate the caller's key-password policy into the internal config so
	// getOrGenerateCAKey can enforce it without needing a separate field on CA.
	multiConfig.RequireKeyPassword = params.RequireKeyPassword

	// Build the per-StoreType backend map. Prefer the caller-supplied
	// Identity[0] (carries the full Keys slice from NewParentCA /
	// NewIntermediateCA); fall back to the issuing identity synthesized from
	// the flat CAConfig (Keys[0] only). params.Validate() has already
	// rejected a nil params.BackendForStore, so every CA signing key is
	// routed through this map.
	cn := params.Config.Identity
	if params.Config.Subject != nil && params.Config.Subject.CommonName != "" {
		cn = params.Config.Subject.CommonName
	}
	idForMap := multiConfig.IssuingIdentity()
	if len(params.Identity) > 0 {
		idForMap = &params.Identity[0]
	}
	keystoreMap, err := buildKeystoreMap(idForMap, cn, params.BackendForStore)
	if err != nil {
		return nil, err
	}

	ca := &CA{
		config:          multiConfig,
		caConfig:        params.Config,
		keyAttrs:        params.KeyAttributes,
		keyStore:        params.KeyStore,
		certStore:       params.CertStore,
		keystoreMap:     keystoreMap,
		objectStore:     params.ObjectStore,
		revocationStore: params.RevocationStore,
		revocations:     make(map[string]*RevocationInfo),
		auditLogger:     params.AuditLogger,
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

	// ObjectStore provides blob storage for cross-signed certificates, AIA
	// trust-chain cache, and attestation evidence.
	// Optional. If nil, features that require it return ErrObjectStoreRequired.
	ObjectStore qrdbsdk.Storage

	// RevocationStore durably persists certificate revocations and the
	// derived CRL artifact in the datastore so both survive restarts.
	// Required. There is no fallback to ObjectStore or in-memory-only
	// tracking.
	RevocationStore storage.Backend

	// BackendForStore resolves an xkms.Backend per (CA CN, StoreType). It is
	// forwarded to the inner New() call (or, for NewHierarchicalCA, invoked
	// directly per identity) so the CA routes each key to the backend
	// matching its StoreType. Required.
	BackendForStore BackendForStoreFunc

	// AuditLogger records CA lifecycle events. See Params.AuditLogger.
	// Optional.
	AuditLogger qrdbsdk.NodeAuditLogger
}

// NewFromMultiIdentityConfig creates a new CA from a MultiIdentityCAConfig.
//
// This convenience constructor derives a flat CAConfig and KeyAttributes
// from the issuing identity in the multi-identity configuration, then
// delegates to New(). This is used internally by go-xkms and by consumers
// that work with the multi-identity configuration model.
//
// Thread-safe: Yes
func NewFromMultiIdentityConfig(mp *MultiIdentityParams) (TrustedCA, error) {
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
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "no issuing identity found"}
	}

	// Derive KeyAttributes from the issuing identity
	keyAttrs, err := issuingIdentity.ToKeyAttributes(context.Background())
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: fmt.Sprintf("failed to derive key attributes: %v", err)}
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
		TCGConfig:               mp.Config.TCGConfig,
	}

	return New(&Params{
		Config:             caConfig,
		KeyAttributes:      keyAttrs,
		KeyStore:           mp.KeyStore,
		CertStore:          mp.CertStore,
		SerialGen:          mp.SerialGen,
		Profiles:           mp.Profiles,
		ObjectStore:        mp.ObjectStore,
		RevocationStore:    mp.RevocationStore,
		BackendForStore:    mp.BackendForStore,
		RequireKeyPassword: mp.Config.RequireKeyPassword,
		AuditLogger:        mp.AuditLogger,
	})
}

// NewHierarchicalCA creates a CA that PRESERVES the full multi-identity
// hierarchy (root plus every configured intermediate) rather than flattening
// to the single issuing identity the way NewFromMultiIdentityConfig does.
//
// Use this when the configuration declares more than one issuing intermediate
// — for example a platform CA and a dedicated cluster CA as siblings under
// the root — so that Init creates every intermediate and IssuerForIdentity
// can resolve any of them by common name. mp.BackendForStore is required: it
// is invoked once per unique StoreType across every configured identity to
// build the per-instance keystoreMap that routes every CA signing key to its
// backend. There is no fallback to a single shared KeyStore.
//
// The behavior is identical to NewFromMultiIdentityConfig for a config with a
// single issuing identity, so callers may use it unconditionally.
//
// Returns ErrBackendForStoreRequired when mp.BackendForStore is nil.
//
// Thread-safe: Yes
func NewHierarchicalCA(mp *MultiIdentityParams) (TrustedCA, error) {
	if mp == nil || mp.Config == nil {
		return nil, ErrInvalidConfig
	}
	if err := mp.Config.Validate(); err != nil {
		return nil, err
	}
	if mp.BackendForStore == nil {
		return nil, ErrBackendForStoreRequired
	}
	if mp.RevocationStore == nil {
		return nil, ErrRevocationStoreRequired
	}

	config := mp.Config
	config.RequireKeyPassword = mp.Config.RequireKeyPassword

	keystoreMap := make(map[types.StoreType]xkms.Backend, len(config.Identity))
	for i := range config.Identity {
		id := &config.Identity[i]
		m, err := buildKeystoreMap(id, id.Subject.CommonName, mp.BackendForStore)
		if err != nil {
			return nil, err
		}
		for storeType, backend := range m {
			keystoreMap[storeType] = backend
		}
	}

	instance := &CA{
		config:          config,
		keyStore:        mp.KeyStore,
		certStore:       mp.CertStore,
		keystoreMap:     keystoreMap,
		objectStore:     mp.ObjectStore,
		revocationStore: mp.RevocationStore,
		revocations:     make(map[string]*RevocationInfo),
		auditLogger:     mp.AuditLogger,
	}
	if mp.SerialGen != nil {
		instance.serialGen = mp.SerialGen
	} else {
		instance.serialGen = NewSerialGenerator(NewMemoryStorage())
	}
	if mp.Profiles != nil {
		instance.profiles = mp.Profiles
	} else {
		instance.profiles = NewDefaultProfileRegistry()
	}
	return instance, nil
}

// ObjectStore returns the configured object store, or nil if none.
// Used by CA-adjacent features (cross-signing, AIA cache, attestation
// evidence, CRL snapshots) that need blob storage beyond the CN-keyed
// CertStore. Callers should check for nil and surface ErrObjectStoreRequired.
func (ca *CA) ObjectStore() qrdbsdk.Storage {
	return ca.objectStore
}

// SecondaryKeyInitError returns the error from the most recent
// initSecondaryKeys attempt made by Init, or nil when every secondary key
// (Keys[1..n] of the identity) generated successfully or the identity has
// none. Init never fails because of this error — the CA is usable once the
// primary (Keys[0]) certificate exists — so a caller that needs every
// configured key actually provisioned (not just the primary) should check
// this after Init and alert or retry out of band.
//
// Thread-safe: Yes
func (ca *CA) SecondaryKeyInitError() error {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.secondaryKeyErr
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
func (ca *CA) Init(ctx context.Context) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.initialized.Load() {
		return ErrAlreadyInitialized
	}

	// Create root CA certificate
	if err := ca.createRootCertificate(ctx); err != nil {
		return &errs.Wrapped{Msg: "failed to create root certificate", Err: err}
	}

	// Generate any non-primary keys (Keys[1..n]) into their resolved backends.
	// This is best-effort: the CA is functional once the primary (Keys[0])
	// certificate exists, so a secondary-key failure must not fail Init.
	// initSecondaryKeys is a no-op unless a multi-key Identity was preserved
	// (NewParentCA / NewCA path) and BackendForStore routing is in play. The
	// error is not discarded, though: it is retained on ca.secondaryKeyErr
	// (see SecondaryKeyInitError) so a caller that needs every configured
	// key provisioned can detect and act on a partial failure Init itself
	// must not fail on.
	ca.secondaryKeyErr = ca.initSecondaryKeys(ctx, ca.config.RootIdentity())

	// Create intermediate CA certificates if configured
	if ca.config.HasIntermediate() {
		if err := ca.createIntermediateCertificates(ctx); err != nil {
			return &errs.Wrapped{Msg: "failed to create intermediate certificates", Err: err}
		}
	}

	ca.initialized.Store(true)
	return nil
}

// wrapCertLookupError classifies a certStore.GetCertificate failure inside
// Load. The certificate store's DAO reporting the entity not found (no
// certificate was ever stored under this CN) becomes ErrCertificateNotFound:
// the one condition callers -- in particular pkg/server's initializeCA -- may
// treat as "never initialized" and safely retry through Init. Any other cause (a corrupt or unparseable
// persisted certificate, a backend I/O failure) is returned as a distinct
// error that does not satisfy errors.Is(_, ErrCertificateNotFound), so
// damaged existing state can never be mistaken for an empty store and
// silently papered over by minting a new CA (go-xkms#793).
func wrapCertLookupError(label string, err error) error {
	if qrdbsdk.IsDAONotFound(err) {
		return &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("%s: %v", label, err)}
	}
	return &errs.Wrapped{Msg: fmt.Sprintf("failed to load %s", label), Err: err}
}

// Load loads an existing Certificate Authority from storage.
//
// This retrieves the CA's certificate chain from the certificate store and
// verifies that the corresponding private keys exist in the keystore.
// After successful loading, the CA is ready for signing operations.
//
// Returns:
//   - ErrAlreadyInitialized if the CA has already been initialized
//   - ErrCertificateNotFound if the CA certificate genuinely does not exist
//     (the store has no record under this CN)
//   - A distinct, non-ErrCertificateNotFound error if the certificate
//     record exists but is corrupt or unreadable, or the store failed for
//     any other reason -- callers must not treat this as "not initialized"
//   - ErrKeyStoreRequired if the corresponding private key is missing
//   - Storage errors if certificate retrieval fails
//
// Thread-safe: Yes, but should typically be called once during startup.
func (ca *CA) Load(ctx context.Context) error {
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
		return wrapCertLookupError("root certificate", err)
	}
	ca.rootCert = rootCert

	// Verify root key exists. getCAKeyAttributes (not the bare
	// identity.ToKeyAttributes) so a root identity whose KeyConfig leaves
	// key-type unset resolves to the same KeyTypeCA default Init used when it
	// generated and stored this same key (go-xkms#793): Load must attempt the
	// lookup with the identical attributes Init wrote under, or the lookup
	// fails KeyAttributes.Validate() before it ever reaches the keystore.
	rootAttrs, err := ca.getCAKeyAttributes(ctx, rootIdentity)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get root key attributes", Err: err}
	}
	rootBackend, err := ca.resolveKeyBackend(rootAttrs.StoreType)
	if err != nil {
		return err
	}
	if _, err := rootBackend.Signer(ctx, rootAttrs); err != nil {
		return &errs.Detail{Err: ErrKeyStoreRequired, Detail: fmt.Sprintf("root key not found: %v", err)}
	}

	// Load intermediate certificates if configured
	if ca.config.HasIntermediate() {
		issuingIdentity := ca.config.IssuingIdentity()
		if issuingIdentity == nil {
			return ErrInvalidConfig
		}

		intermediateCert, err := ca.certStore.GetCertificate(issuingIdentity.Subject.CommonName)
		if err != nil {
			return wrapCertLookupError("intermediate certificate", err)
		}
		ca.intermediateCert = intermediateCert

		// Verify intermediate key exists. Same getCAKeyAttributes default-filling
		// as the root key above (go-xkms#793).
		intermediateAttrs, err := ca.getCAKeyAttributes(ctx, issuingIdentity)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to get intermediate key attributes", Err: err}
		}
		intermediateBackend, err := ca.resolveKeyBackend(intermediateAttrs.StoreType)
		if err != nil {
			return err
		}
		if _, err := intermediateBackend.Signer(ctx, intermediateAttrs); err != nil {
			return &errs.Detail{Err: ErrKeyStoreRequired, Detail: fmt.Sprintf("intermediate key not found: %v", err)}
		}

		// Verify EVERY other configured intermediate (certificate present and
		// key resolvable), not only the selected issuing one, so non-selected
		// identities — e.g. a dedicated cluster intermediate that signs Raft
		// transport certificates — are guaranteed usable after Load.
		for _, intermediate := range ca.config.IntermediateIdentities() {
			cn := intermediate.Subject.CommonName
			if cn == issuingIdentity.Subject.CommonName {
				continue
			}
			if _, err := ca.certStore.GetCertificate(cn); err != nil {
				return wrapCertLookupError(fmt.Sprintf("intermediate %q certificate", cn), err)
			}
			// Same getCAKeyAttributes default-filling as above (go-xkms#793).
			attrs, err := ca.getCAKeyAttributes(ctx, &intermediate)
			if err != nil {
				return &errs.Wrapped{Msg: fmt.Sprintf("failed to get intermediate %q key attributes", cn), Err: err}
			}
			backend, err := ca.resolveKeyBackend(attrs.StoreType)
			if err != nil {
				return err
			}
			if _, err := backend.Signer(ctx, attrs); err != nil {
				return &errs.Detail{Err: ErrKeyStoreRequired, Detail: fmt.Sprintf("intermediate %q key not found: %v", cn, err)}
			}
		}
	}

	// Replay the revocation records persisted to the revocation store. A
	// corrupt record fails Load with ErrRevocationRecordCorrupt: skipping it
	// would silently un-revoke the certificate it describes.
	if err := ca.loadPersistedRevocations(ctx); err != nil {
		return err
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

	signer, err := ca.getSigner(context.Background())
	if err != nil {
		return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
	}

	signature, err := signer.Sign(randReader, digest, opts)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
	}

	return signature, nil
}

// =============================================================================
// Storage Accessors
// =============================================================================

// KeyStore returns the underlying keystore.
//
// This provides direct access to the keystore for advanced operations
// not exposed through the TrustedCA interface, such as key rotation,
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
			return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: "failed to encode intermediate certificate"}
		}
	}

	// Add root certificate
	if ca.rootCert != nil {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.rootCert.Raw,
		}); err != nil {
			return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: "failed to encode root certificate"}
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
func (ca *CA) getSigner(ctx context.Context) (crypto.Signer, error) {
	issuingIdentity := ca.config.IssuingIdentity()
	if issuingIdentity == nil {
		return nil, ErrInvalidConfig
	}

	attrs, err := ca.getCAKeyAttributes(ctx, issuingIdentity)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get signer", Err: err}
	}

	backend, err := ca.resolveKeyBackend(attrs.StoreType)
	if err != nil {
		return nil, err
	}
	return backend.Signer(ctx, attrs)
}

// getCAKeyAttributes returns KeyAttributes for the specified identity.
// If the key type is not set, it defaults to KeyTypeCA since all CA keys
// are by definition CA keys.
func (ca *CA) getCAKeyAttributes(ctx context.Context, identity *Identity) (*types.KeyAttributes, error) {
	if identity == nil {
		return nil, ErrInvalidConfig
	}
	attrs, err := identity.ToKeyAttributes(ctx)
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
func (ca *CA) getOrGenerateCAKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Route to the backend configured for this key's StoreType via the
	// per-instance keystoreMap built from BackendForStore.
	backend, err := ca.resolveKeyBackend(attrs.StoreType)
	if err != nil {
		return nil, err
	}

	// First, try to get the existing key
	privateKey, err := backend.GetKey(ctx, attrs)
	if err == nil {
		// Key exists, return it
		return privateKey, nil
	}

	// Only a genuine "key does not exist" result may fall through to
	// generation. Every backend reports that as errors.Is(err,
	// backendpkg.ErrKeyNotFound); anything else -- a TPM transient fault, a
	// PKCS#11 login failure, cloud KMS throttling, an I/O error against the
	// metadata store -- means the backend could not determine whether a key
	// already exists, and generating one anyway risks silently replacing a
	// hardware-backed CA signing key the backend merely failed to reach
	// right now. Fail closed instead.
	if !errors.Is(err, backendpkg.ErrKeyNotFound) {
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("CA identity %q: %v", attrs.CN, err)}
	}

	// Enforce the optional password policy before any I/O: when RequireKeyPassword
	// is true an empty (nil) password is rejected so the key is never written as
	// plaintext PKCS#8. This check runs only on the generate path; retrieving an
	// already-existing key is always allowed.
	if ca.config.RequireKeyPassword && attrs.Password == nil {
		return nil, &errs.Detail{Err: ErrKeyPasswordRequired, Detail: fmt.Sprintf("CA identity %q must have a key password", attrs.CN)}
	}

	// Key doesn't exist, generate a new one based on algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		privateKey, err = backend.GenerateRSA(ctx, attrs)
	case x509.ECDSA:
		privateKey, err = backend.GenerateECDSA(ctx, attrs)
	case x509.Ed25519:
		privateKey, err = backend.GenerateEd25519(ctx, attrs)
	default:
		return nil, &errs.Detail{Err: ErrInvalidKeyAlgorithm, Detail: fmt.Sprintf("unsupported key algorithm: %v", attrs.KeyAlgorithm)}
	}
	if err != nil {
		// Lost get-or-generate race: on a cluster, a sibling node generated
		// this key between our not-found read and our write (or our read
		// preceded the replicated write's visibility). The winner's key is
		// the key — fetch it.
		if errors.Is(err, backendpkg.ErrKeyAlreadyExists) {
			if existing, getErr := backend.GetKey(ctx, attrs); getErr == nil {
				return existing, nil
			}
		}
		return nil, &errs.Wrapped{Msg: "failed to generate key", Err: err}
	}

	return privateKey, nil
}

// resolveKeyBackend returns the xkms.Backend for a key with the given
// StoreType from keystoreMap. keystoreMap is read-only after construction, so
// this is safe for concurrent use without locking.
//
// Returns ErrKeyStoreRequired when storeType has no entry in keystoreMap:
// every StoreType that appears in an identity's Keys is populated by
// buildKeystoreMap at construction time, so a miss here means attrs.StoreType
// names a backend the CA was never configured with.
func (ca *CA) resolveKeyBackend(storeType types.StoreType) (xkms.Backend, error) {
	if b, ok := ca.keystoreMap[storeType]; ok {
		return b, nil
	}
	return nil, &errs.Detail{Err: ErrKeyStoreRequired, Detail: fmt.Sprintf("no backend configured for store type %q", storeType)}
}

// buildKeystoreMap iterates identity.Keys, collects the unique StoreTypes, and
// invokes factory once per unique type to populate the returned map. factory
// and identity are both required: there is no fallback to a single shared
// backend for every StoreType. An empty per-key StoreType defaults to
// types.StoreSoftware so unconfigured keys land in the software backend.
func buildKeystoreMap(
	identity *Identity,
	cn string,
	factory BackendForStoreFunc,
) (map[types.StoreType]xkms.Backend, error) {
	if factory == nil {
		return nil, ErrBackendForStoreRequired
	}
	if identity == nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "buildKeystoreMap: identity is required"}
	}
	seen := make(map[types.StoreType]bool)
	m := make(map[types.StoreType]xkms.Backend)
	for _, kc := range identity.Keys {
		if kc == nil {
			continue
		}
		st := kc.StoreType
		if st == "" {
			st = types.StoreSoftware
		}
		if seen[st] {
			continue
		}
		seen[st] = true
		b, err := factory(cn, st)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("ca: backend factory for %q storeType %q", cn, st), Err: err}
		}
		if b == nil {
			return nil, &errs.Detail{Err: ErrKeyStoreRequired, Detail: fmt.Sprintf("BackendForStore returned nil for cn=%q storeType=%q", cn, st)}
		}
		m[st] = b
	}
	return m, nil
}

// initSecondaryKeys generates the non-primary keys (Keys[1..n]) of the given
// identity in their resolved backends. It is best-effort and called during
// Init() after the primary CA certificate is created: the CA certificate binds
// only the primary key (Keys[0]); secondary keys are pre-generated for backup,
// rotation, or algorithm-agile signing.
//
// The full multi-key slice is preserved on ca.inputIdentity (NewParentCA /
// NewCA path); the flat caConfig only retains Keys[0]. When no multi-key
// identity is present this is a no-op. Must be called with mu held.
func (ca *CA) initSecondaryKeys(ctx context.Context, identity *Identity) error {
	id := identity
	if ca.inputIdentity != nil {
		id = ca.inputIdentity
	}
	if id == nil || len(id.Keys) <= 1 {
		return nil
	}
	for i, kc := range id.Keys[1:] {
		attrs, err := types.KeyAttributesFromConfig(ctx, kc)
		if err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("ca: secondary key %d attributes", i+1), Err: err}
		}
		attrs.CN = id.Subject.CommonName
		if attrs.KeyType == 0 {
			attrs.KeyType = types.KeyTypeCA
		}
		if _, err := ca.getOrGenerateCAKey(ctx, attrs); err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("ca: generate secondary key %d (store=%s)", i+1, attrs.StoreType), Err: err}
		}
	}
	return nil
}

// createRootCertificate generates a self-signed root CA certificate.
// Must be called with mu held (write lock).
func (ca *CA) createRootCertificate(ctx context.Context) error {
	rootIdentity := ca.config.RootIdentity()
	if rootIdentity == nil {
		return ErrInvalidConfig
	}

	// Get key attributes for the root CA
	attrs, err := ca.getCAKeyAttributes(ctx, rootIdentity)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get root key attributes", Err: err}
	}

	// Get existing key or generate a new one (idempotent operation)
	privateKey, err := ca.getOrGenerateCAKey(ctx, attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get or generate root CA key", Err: err}
	}

	// Get the signer interface
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return &errs.Message{Msg: "generated key does not implement crypto.Signer"}
	}

	// Generate serial number
	serial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to generate serial number", Err: err}
	}

	// Determine signature algorithm
	sigAlgo, err := rootIdentity.GetSignatureAlgorithm()
	if err != nil {
		return &errs.Wrapped{Msg: "failed to determine signature algorithm", Err: err}
	}

	// A root is a self-signed CA certificate: a nil Issuer.Certificate makes
	// the template its own parent, and the CA profile supplies the key usage,
	// basic constraints and path length every CA certificate carries.
	caProfile, err := ca.Profiles().Get(ProfileNameCA)
	if err != nil {
		return err
	}

	now := time.Now()
	validityDays := rootIdentity.GetValidityDays()

	issuer := &Issuer{Signer: signer, Identity: rootIdentity}
	cert, err := issuer.Issue(rand.Reader, &CertificateSpec{
		Serial:             serial,
		Subject:            rootIdentity.Subject.ToPkixName(),
		NotBefore:          now,
		NotAfter:           now.AddDate(0, 0, validityDays),
		SignatureAlgorithm: sigAlgo,
		Profile:            caProfile,
		Request: &CertificateRequest{
			Subject:        rootIdentity.Subject,
			SANS:           rootIdentity.SANS,
			Valid:          validityDays,
			IsCA:           true,
			MaxPathLen:     rootIdentity.MaxPathLength,
			MaxPathLenZero: rootIdentity.MaxPathLengthZero,
		},
		SANS: rootIdentity.SANS,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to create root certificate", Err: err}
	}

	// CA_INITIALIZED is SeveritySecurity (docs/audit-log/engineering.md): the
	// audit record is written before the certificate is persisted, so a
	// failed write refuses initialization rather than leave an unaudited CA
	// root in the certificate store.
	if auditErr := ca.emitAudit(ctx, auditActionCAInit, auditResourceCA, rootIdentity.Subject.CommonName); auditErr != nil {
		return auditErr
	}

	// Store the certificate
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return &errs.Wrapped{Msg: "failed to store root certificate", Err: err}
	}

	ca.rootCert = cert
	return nil
}

// createIntermediateCertificates generates intermediate CA certificates.
// This creates certificates for all intermediate identities in the hierarchy.
// Must be called with mu held (write lock).
func (ca *CA) createIntermediateCertificates(ctx context.Context) error {
	intermediateIdentities := ca.config.IntermediateIdentities()
	if len(intermediateIdentities) == 0 {
		return nil
	}

	// Get root signer for signing intermediate certificates
	rootIdentity := ca.config.RootIdentity()
	if rootIdentity == nil {
		return ErrInvalidConfig
	}

	rootAttrs, err := rootIdentity.ToKeyAttributes(ctx)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get root key attributes", Err: err}
	}

	rootBackend, err := ca.resolveKeyBackend(rootAttrs.StoreType)
	if err != nil {
		return err
	}
	parentSigner, err := rootBackend.Signer(ctx, rootAttrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get root signer", Err: err}
	}

	parentCert := ca.rootCert

	// issuersByCN tracks every CA created so far (root plus each finished
	// intermediate) so an identity's ParentCA can select its issuer by common
	// name — enabling SIBLING intermediates under the root (e.g. a platform CA
	// and a cluster CA that are both direct children of the root). Identities
	// with an empty ParentCA keep the historical sequential chaining: each is
	// signed by the previous identity in the list.
	type caIssuer struct {
		cert   *x509.Certificate
		signer crypto.Signer
	}
	issuersByCN := map[string]caIssuer{
		rootIdentity.Subject.CommonName: {cert: ca.rootCert, signer: parentSigner},
	}

	// Create each intermediate CA in order
	for i, identity := range intermediateIdentities {
		issuer := caIssuer{cert: parentCert, signer: parentSigner}
		if identity.ParentCA != "" {
			named, ok := issuersByCN[identity.ParentCA]
			if !ok {
				return &ErrUnknownParentCA{
					Identity: identity.Subject.CommonName,
					ParentCA: identity.ParentCA,
				}
			}
			issuer = named
		}

		cert, err := ca.createSingleIntermediateCertificate(ctx, &identity, issuer.cert, issuer.signer)
		if err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("failed to create intermediate CA %d", i+1), Err: err}
		}

		// CA_INITIALIZED (see createRootCertificate): the audit record is
		// written before the intermediate certificate is persisted.
		if auditErr := ca.emitAudit(ctx, auditActionCAInit, auditResourceCA, identity.Subject.CommonName); auditErr != nil {
			return auditErr
		}

		// Store the certificate
		if err := ca.certStore.StoreCertificate(cert); err != nil {
			return &errs.Wrapped{Msg: "failed to store intermediate certificate", Err: err}
		}

		// If this is the selected issuing CA, store it
		if i+1 == ca.config.SelectedCA {
			ca.intermediateCert = cert
		}

		// Update parent for next intermediate in chain
		parentCert = cert

		attrs, err := identity.ToKeyAttributes(ctx)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to get intermediate key attributes", Err: err}
		}

		intermediateBackend, err := ca.resolveKeyBackend(attrs.StoreType)
		if err != nil {
			return err
		}
		parentSigner, err = intermediateBackend.Signer(ctx, attrs)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to get intermediate signer", Err: err}
		}

		issuersByCN[identity.Subject.CommonName] = caIssuer{cert: cert, signer: parentSigner}
	}

	// If no intermediate was selected, use the last one
	if ca.intermediateCert == nil && len(intermediateIdentities) > 0 {
		lastIdentity := &intermediateIdentities[len(intermediateIdentities)-1]
		cert, err := ca.certStore.GetCertificate(lastIdentity.Subject.CommonName)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to retrieve last intermediate certificate", Err: err}
		}
		ca.intermediateCert = cert
	}

	return nil
}

// createSingleIntermediateCertificate creates a single intermediate CA certificate.
func (ca *CA) createSingleIntermediateCertificate(
	ctx context.Context,
	identity *Identity,
	parentCert *x509.Certificate,
	parentSigner crypto.Signer,
) (*x509.Certificate, error) {
	// Get key attributes for the intermediate CA
	attrs, err := ca.getCAKeyAttributes(ctx, identity)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get intermediate key attributes", Err: err}
	}

	// Get existing key or generate a new one (idempotent operation)
	privateKey, err := ca.getOrGenerateCAKey(ctx, attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get or generate intermediate CA key", Err: err}
	}

	// Get the signer interface for public key extraction
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, &errs.Message{Msg: "generated key does not implement crypto.Signer"}
	}

	// Generate serial number
	serial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate serial number", Err: err}
	}

	// Determine signature algorithm based on parent key type
	sigAlgo := determineSignatureAlgorithm(parentSigner.Public())

	// An intermediate is a CA certificate signed by its parent. It is issued
	// with the same CA profile as the root, so the two cannot drift apart.
	caProfile, err := ca.Profiles().Get(ProfileNameCA)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	validityDays := identity.GetValidityDays()

	issuer := &Issuer{Signer: parentSigner, Certificate: parentCert, Identity: identity}
	cert, err := issuer.Issue(rand.Reader, &CertificateSpec{
		Serial:             serial,
		Subject:            identity.Subject.ToPkixName(),
		NotBefore:          now,
		NotAfter:           now.AddDate(0, 0, validityDays),
		PublicKey:          signer.Public(),
		SignatureAlgorithm: sigAlgo,
		Profile:            caProfile,
		Request: &CertificateRequest{
			Subject:        identity.Subject,
			SANS:           identity.SANS,
			Valid:          validityDays,
			IsCA:           true,
			MaxPathLen:     identity.MaxPathLength,
			MaxPathLenZero: identity.MaxPathLengthZero,
		},
		SANS: identity.SANS,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create intermediate certificate", Err: err}
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
func (ca *CA) SignCSR(ctx context.Context, csrPEM []byte, opts *SignOptions) (*x509.Certificate, error) {
	return ca.signCSR(ctx, csrPEM, opts, nil)
}

// signCSR is the single end-entity issuance implementation shared by SignCSR
// and IssueCertificateWithProfile.
//
// request carries the originating CertificateRequest when issuance started
// from IssueCertificateWithProfile, so the selected profile sees the caller's
// full issuance context (CA flag, path length, tenant). Direct CSR signing has
// no CertificateRequest, so one is reconstructed from the certificate spec and
// the sign options; profiles are always invoked with a non-nil request.
//
// The certificate itself is built and signed by Issuer.Issue, the single
// implementer of CA certificate creation in this project.
func (ca *CA) signCSR(ctx context.Context, csrPEM []byte, opts *SignOptions, request *CertificateRequest) (*x509.Certificate, error) {
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
		return nil, &errs.Detail{Err: ErrInvalidCSR, Detail: fmt.Sprintf("%v", err)}
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, &errs.Detail{Err: ErrInvalidCSR, Detail: fmt.Sprintf("invalid CSR signature: %v", err)}
	}

	return ca.signVerifiedCSR(ctx, csr, opts, request)
}

// signVerifiedCSR issues a certificate for a certificate request whose key
// the caller has already established: a parsed CSR whose signature
// checked, or a request IssueCertificateForKey assembled for a public key
// the caller vouches for.
func (ca *CA) signVerifiedCSR(ctx context.Context, csr *x509.CertificateRequest, opts *SignOptions, request *CertificateRequest) (*x509.Certificate, error) {
	// Determine the signing key and issuer certificate. When the caller
	// supplies an external Signer on SignOptions, we use it instead of the
	// CA's own key — this is the multi-tenant signing path where a tenant's
	// key issues under an umbrella CA's trust chain. An IssuerCert must also
	// be provided when Signer is non-nil; otherwise the caller's configuration
	// is invalid because x509.CreateCertificate needs a concrete issuer
	// whose SubjectKeyId populates the AuthorityKeyIdentifier extension.
	var (
		signer      crypto.Signer
		issuingCert *x509.Certificate
	)
	if opts != nil && opts.Signer != nil {
		if opts.IssuerCert == nil {
			return nil, ErrInvalidIssuer
		}
		signer = opts.Signer
		issuingCert = opts.IssuerCert
	} else {
		ca.mu.RLock()
		issuingCert = ca.getIssuingCertificate()
		ca.mu.RUnlock()

		if issuingCert == nil {
			return nil, ErrCertificateNotFound
		}

		var err error
		signer, err = ca.getSigner(ctx)
		if err != nil {
			return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
		}
	}

	// Generate serial number
	serial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSerialGenerationFailed, Detail: fmt.Sprintf("%v", err)}
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

	// Determine key usage
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if opts != nil && opts.KeyUsage != 0 {
		keyUsage = opts.KeyUsage
	}

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if opts != nil && opts.ExtKeyUsage != nil {
		extKeyUsage = opts.ExtKeyUsage
	}

	// Resolve the requested profile. Its key usage, extended key usage and
	// default validity seed the template here; the profile's Apply runs once
	// the template is complete so extensions it owns land on the certificate.
	var profile ProfileProvider
	if opts != nil && opts.Profile != "" {
		resolved, err := ca.Profiles().Get(opts.Profile)
		if err != nil {
			return nil, err
		}
		profile = resolved
		keyUsage = profile.KeyUsage()
		extKeyUsage = profile.ExtKeyUsage()
		if opts.ValidityDays == 0 {
			validityDays = profile.DefaultValidity()
		}
	}

	// A caller that named no profile still gets one: the CA's TLS leaf profile
	// carrying whatever key usage and extended key usage the caller asked for.
	// Expressing the "no profile" case as a profile is what lets Issuer.Issue
	// require a profile unconditionally, so no path can bypass Profile.Apply.
	if profile == nil {
		profile = newTLSLeafProfile(keyUsage, extKeyUsage, validityDays)
	}

	// A profile that constrains the request refuses it here, before anything
	// is built from it, and a caller-bound key must be the key requested.
	if validator, ok := profile.(CSRValidator); ok {
		if err := validator.ValidateCSR(csr); err != nil {
			return nil, err
		}
	}
	if opts != nil && opts.BoundKey != nil {
		if err := ca.checkBoundKey(ctx, csr, opts.BoundKey); err != nil {
			return nil, err
		}
	}

	// The lifetime: a duration, a day count, or the profile's default, and
	// never more than a lifetime-bounded profile's maximum.
	var requestedValidity time.Duration
	requestedDays := 0
	if opts != nil {
		requestedValidity = opts.Validity
		requestedDays = opts.ValidityDays
	}
	lifetime, err := resolveLifetime(profile, requestedValidity, requestedDays)
	if err != nil {
		return nil, err
	}
	notAfter := notBefore.AddDate(0, 0, validityDays)
	if lifetime > 0 {
		notAfter = notBefore.Add(lifetime)
	}

	if opts != nil && opts.RawSubject == nil && opts.RawSubjectURIs != nil {
		return nil, ErrInvalidRawSubjectURIs
	}
	if opts != nil && opts.RawSubject != nil {
		return ca.signRawSubjectCSR(ctx, csr, opts, request, profile, &signContext{
			signer:       signer,
			issuingCert:  issuingCert,
			validityDays: validityDays,
			keyUsage:     keyUsage,
			extKeyUsage:  extKeyUsage,
		}, serial, notBefore, notAfter)
	}

	if isCallerSANProfile(profile) {
		return ca.signCallerNamedCSR(ctx, csr, opts, request, &signContext{
			signer:       signer,
			issuingCert:  issuingCert,
			serial:       serial,
			notBefore:    notBefore,
			notAfter:     notAfter,
			validityDays: validityDays,
			keyUsage:     keyUsage,
			extKeyUsage:  extKeyUsage,
			profile:      profile,
		})
	}

	// Build subject
	subject := csr.Subject
	if opts != nil && opts.Subject != nil {
		subject = mergeSubjects(csr.Subject, opts.Subject)
	}

	// Assemble the subject alternative names in issuance order: the CSR's own
	// names, then the caller's additions, then the synthesized SPIFFE identity.
	dnsNames := csr.DNSNames
	emailAddresses := csr.EmailAddresses
	ipAddresses := csr.IPAddresses
	uris := csr.URIs
	if opts != nil && opts.SANS != nil {
		dnsNames = append(dnsNames, opts.SANS.DNS...)
		emailAddresses = append(emailAddresses, opts.SANS.Email...)
		ipAddresses = append(ipAddresses, opts.SANS.ParseIPs()...)
		uris = append(uris, opts.SANS.ParseURIs()...)
	}

	// Synthesize a tenant-scoped SPIFFE URI SAN when requested. This binds the
	// issued client certificate to its tenant so login can derive the tenant
	// from the verified peer certificate (SPIFFE SAN -> tenant). The format is
	// owned by pkg/spiffe; we never hand-assemble the path here.
	if opts != nil && opts.SPIFFETrustDomain != "" && opts.TenantID != "" {
		kind := opts.SPIFFEKind
		if kind == "" {
			kind = spiffe.KindUser
		}
		name := opts.SPIFFEName
		if name == "" {
			name = subject.CommonName
		}
		spiffeURI, err := spiffe.BuildURI(opts.SPIFFETrustDomain, opts.TenantID, kind, name)
		if err != nil {
			return nil, &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
		}
		uris = append(uris, spiffeURI)
	}

	spec := &CertificateSpec{
		Serial:             serial,
		Subject:            subject,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: determineSignatureAlgorithm(signer.Public()),
		Profile:            profile,
		DNSNames:           dnsNames,
		EmailAddresses:     emailAddresses,
		IPAddresses:        ipAddresses,
		URIs:               uris,
	}

	return ca.issueSignedSpec(ctx, spec, csr, opts, request, &signContext{
		signer:       signer,
		issuingCert:  issuingCert,
		validityDays: validityDays,
		keyUsage:     keyUsage,
		extKeyUsage:  extKeyUsage,
	})
}

// checkBoundKey refuses csr unless its public key is the public key of the
// keystore key attrs names, compared as marshalled SubjectPublicKeyInfo.
//
// Returns ErrBoundKeyNotFound when the keystore holds no such key and
// ErrBoundKeyMismatch when the keys differ.
func (ca *CA) checkBoundKey(ctx context.Context, csr *x509.CertificateRequest, attrs *types.KeyAttributes) error {
	if ca.keyStore == nil {
		return ErrKeyStoreRequired
	}
	key, err := ca.keyStore.GetKey(ctx, attrs)
	if errors.Is(err, backendpkg.ErrKeyNotFound) {
		return &errs.Detail{Err: ErrBoundKeyNotFound, Detail: attrs.CN}
	}
	if err != nil {
		return &errs.Wrapped{Msg: "ca: resolve bound key " + attrs.CN, Err: err}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return &errs.Detail{Err: ErrInvalidKeyAlgorithm, Detail: "bound key " + attrs.CN + " does not expose a public key"}
	}
	want, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return &errs.Detail{Err: ErrInvalidKeyAlgorithm, Detail: fmt.Sprintf("bound key %s: %v", attrs.CN, err)}
	}
	got, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(got, want) {
		return &errs.Detail{Err: ErrBoundKeyMismatch, Detail: attrs.CN}
	}
	return nil
}

// signRawSubjectCSR signs a CSR under a caller-chosen raw subject: the
// certificate carries exactly opts.RawSubject, no subject alternative name
// but opts.RawSubjectURIs, and the CSR contributes only its public key.
func (ca *CA) signRawSubjectCSR(
	ctx context.Context,
	csr *x509.CertificateRequest,
	opts *SignOptions,
	request *CertificateRequest,
	profile ProfileProvider,
	sc *signContext,
	serial *big.Int,
	notBefore, notAfter time.Time,
) (*x509.Certificate, error) {
	if opts.Subject != nil || opts.SANS != nil || len(opts.OtherNames) > 0 || opts.SPIFFETrustDomain != "" ||
		opts.SPIFFEKind != "" || opts.SPIFFEName != "" || isCallerSANProfile(profile) {
		return nil, ErrRawSubjectWithNames
	}
	uris := make([]*url.URL, 0, len(opts.RawSubjectURIs))
	for _, uri := range opts.RawSubjectURIs {
		if uri == nil {
			return nil, ErrInvalidRawSubjectURIs
		}
		clone := *uri
		uris = append(uris, &clone)
	}
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(opts.RawSubject, &rdns)
	if err != nil || len(rest) != 0 || len(rdns) == 0 {
		return nil, ErrInvalidRawSubject
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&rdns)

	spec := &CertificateSpec{
		Serial:             serial,
		Subject:            subject,
		RawSubject:         bytes.Clone(opts.RawSubject),
		URIs:               uris,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: determineSignatureAlgorithm(sc.signer.Public()),
		Profile:            profile,
	}
	return ca.issueSignedSpec(ctx, spec, csr, opts, request, sc)
}

// issueSignedSpec finishes a CSR-signed issuance: it attaches the issuance
// context the profile sees, signs through Issuer.Issue, stores the
// certificate and records its tenant. signCSR and signCallerNamedCSR both end
// here, so the two name-sourcing rules share one signing, storage and tenant
// path.
func (ca *CA) issueSignedSpec(
	ctx context.Context,
	spec *CertificateSpec,
	csr *x509.CertificateRequest,
	opts *SignOptions,
	request *CertificateRequest,
	sc *signContext,
) (*x509.Certificate, error) {
	// Profiles receive the issuance context so they can make context-sensitive
	// decisions — a CA profile reads MaxPathLen, a tenant-aware profile reads
	// TenantID.
	//
	// A caller-supplied request is copied rather than used directly, because
	// recording the CSR's requested extensions below must not mutate the value
	// the caller still holds.
	if request != nil {
		requested := *request
		spec.Request = &requested
	} else {
		spec.Request = certificateRequestFromSpec(spec, opts, sc.validityDays, sc.keyUsage, sc.extKeyUsage)
	}

	// The extensions the CSR asked for travel with the issuance context so that
	// a profile can copy the ones it understands. They are deliberately not
	// applied to the certificate here: a requester that could name its own
	// extensions would be issuing to itself. The FIDO2 attestation profile is
	// the one profile that opts in, for id-fido-gen-ce-aaguid.
	spec.Request.CSRExtensions = csr.Extensions

	tenantID := ""
	if opts != nil {
		spec.ExtraExtensions = opts.ExtraExtensions
		spec.OtherNames = opts.OtherNames
		tenantID = opts.TenantID
	}

	// The certificate carries its tenant as the subject's first
	// organizational unit, in place of any the CSR or the caller named.
	subject, rawSubject, err := StampTenant(tenantID, spec.Subject, spec.RawSubject)
	if err != nil {
		return nil, err
	}
	spec.Subject, spec.RawSubject = subject, rawSubject

	// Certificates signed with a caller-supplied Signer belong to a different
	// issuer whose CRL and OCSP services this CA cannot speak for, so that
	// path carries no identity and keeps whatever the caller or its profile
	// supplied.
	issuer := &Issuer{Signer: sc.signer, Certificate: sc.issuingCert}
	if opts == nil || opts.Signer == nil {
		issuer.Identity = ca.config.IssuingIdentity()
	}

	cert, err := issuer.Issue(rand.Reader, spec)
	if err != nil {
		return nil, err
	}

	// Store the certificate. The store is keyed by Common Name, so a
	// certificate with none cannot be stored there. Only a caller-named
	// profile issues such a certificate — an X.509-SVID needs no subject —
	// and it stays revocable: RevokeCert takes the certificate itself, and
	// its tenant is recorded below by serial.
	if cert.Subject.CommonName != "" || !isCallerSANProfile(spec.Profile) {
		if err := ca.certStore.StoreCertificate(cert); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to store certificate", Err: err}
		}
	}

	// Record the issuing tenant so a later revoke request can be refused for
	// a caller bound to a different tenant (go-xkms#1229). This is the single
	// recording site for both direct CSR signing and keypair issuance --
	// IssueCertificateWithProfile routes through this method.
	if err := ca.recordCertTenant(ctx, cert.SerialNumber, tenantID); err != nil {
		return nil, err
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
func (ca *CA) IssueCertificate(ctx context.Context, request *CertificateRequest) (*IssuedCertificate, error) {
	return ca.IssueCertificateWithProfile(ctx, request, "")
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
func (ca *CA) IssueCertificateWithProfile(ctx context.Context, request *CertificateRequest, profile string) (*IssuedCertificate, error) {
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
	csrPEM, err := ca.CreateCSR(ctx, request)
	if err != nil {
		return nil, err
	}

	// Build sign options. The SPIFFE tenant-binding fields are forwarded so the
	// keypair-issuance path stamps the same tenant-scoped SPIFFE URI SAN as the
	// CSR-sign path. SignCSR owns the single synthesis site (spiffe.BuildURI),
	// keeping both paths DRY.
	opts := &SignOptions{
		Profile:           profile,
		ValidityDays:      request.Valid,
		KeyUsage:          request.KeyUsage,
		ExtKeyUsage:       request.ExtKeyUsage,
		SANS:              request.SANS,
		SPIFFETrustDomain: request.SPIFFETrustDomain,
		TenantID:          request.TenantID,
		SPIFFEKind:        request.SPIFFEKind,
		SPIFFEName:        request.SPIFFEName,
		ExtraExtensions:   request.ExtraExtensions,
	}

	// Sign the CSR, forwarding the originating request so the profile sees the
	// caller's full issuance context.
	cert, err := ca.signCSR(ctx, csrPEM, opts, request)
	if err != nil {
		return nil, err
	}

	// Record the exact KeyAttributes the CA generated or resolved for this
	// certificate's key, keyed by its serial number, so a later
	// RevokeCert(..., RevokeOptions{DeleteKeys: true}) can delete precisely
	// this key instead of reconstructing incomplete attributes from the
	// certificate alone (go-xkms#751). Skipped when the caller supplied an
	// external Signer: CreateCSR never touched ca.keyStore for that request,
	// so there is no CA-held key to record.
	if request.Signer == nil {
		if err := ca.recordIssuedKey(ctx, cert.SerialNumber, request.KeyAttributes); err != nil {
			return nil, err
		}
	}

	// Build response
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	caCertPEM, err := ca.CABundle()
	if err != nil {
		return nil, err
	}

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

// IssueCertificateForKey issues a certificate that binds publicKey, a key the
// caller holds: the CA neither generates nor sees its private half, and no
// proof of possession is asked for, so the caller vouches that the key is the
// requester's. It honors the request's subject, SANs, key usage, validity,
// SPIFFE binding and extra extensions as IssueCertificate does, and records
// the issuance the same way.
func (ca *CA) IssueCertificateForKey(ctx context.Context, request *CertificateRequest, publicKey crypto.PublicKey) (*IssuedCertificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if publicKey == nil {
		return nil, ErrPublicKeyRequired
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}

	// The SANs travel on the sign options alone: signVerifiedCSR appends them
	// to the request's own, so naming them on both would list each twice.
	csr := &x509.CertificateRequest{
		Subject:   request.Subject.ToPkixName(),
		PublicKey: publicKey,
	}
	opts := &SignOptions{
		ValidityDays:      request.Valid,
		KeyUsage:          request.KeyUsage,
		ExtKeyUsage:       request.ExtKeyUsage,
		SANS:              request.SANS,
		SPIFFETrustDomain: request.SPIFFETrustDomain,
		TenantID:          request.TenantID,
		SPIFFEKind:        request.SPIFFEKind,
		SPIFFEName:        request.SPIFFEName,
		ExtraExtensions:   request.ExtraExtensions,
	}
	cert, err := ca.signVerifiedCSR(ctx, csr, opts, request)
	if err != nil {
		return nil, err
	}

	caCertPEM, err := ca.CABundle()
	if err != nil {
		return nil, err
	}
	return &IssuedCertificate{
		Certificate:      cert,
		CertificatePEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		CACertificatePEM: caCertPEM,
		SerialNumber:     cert.SerialNumber,
		NotBefore:        cert.NotBefore,
		NotAfter:         cert.NotAfter,
	}, nil
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
// When an optional cross-signing crypto.Signer is provided as the second
// argument, Verify routes through the cross-sign-aware pool builders so
// certificates anchored by a cross-signed root can be validated. Passing
// no xsigner (or a nil one) preserves the original single-root behaviour.
//
// Thread-safe: Yes
func (ca *CA) Verify(cert *x509.Certificate, xsigner ...crypto.Signer) ([][]*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	// Check if revoked. Applies to both the native path and the
	// cross-sign-aware path so a revoked cert is never accepted.
	revoked, err := ca.IsRevoked(cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrCertificateRevoked
	}

	// Route to the cross-sign-aware path when a non-nil signer is provided.
	// The variadic slot is optional: zero elements or a single nil element
	// falls through to the native verify below.
	if len(xsigner) > 0 && xsigner[0] != nil {
		roots, err := ca.TrustedRootCertPoolWithXSigner(cert, xsigner[0])
		if err != nil {
			return nil, err
		}
		intermediates, err := ca.TrustedIntermediateCertPoolWithXSigner(cert, xsigner[0])
		if err != nil {
			return nil, err
		}
		chains, err := cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		})
		if err != nil {
			return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: fmt.Sprintf("%v", err)}
		}
		return chains, nil
	}

	// Native path: verify against the CA's own root/intermediate pools.
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
		return nil, &errs.Detail{Err: ErrInvalidCertificateChain, Detail: fmt.Sprintf("%v", err)}
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
func (ca *CA) Revoke(ctx context.Context, serial *big.Int, reason int) error {
	if !ca.initialized.Load() {
		return ErrNotInitialized
	}

	// recordRevocation performs the serial-nil guard, the already-revoked
	// check, the in-memory insertion, and object-store persistence so
	// Revoke/RevokeCert remain consistent.
	return ca.recordRevocation(ctx, serial, reason, false)
}

// GenerateCRL forces regeneration of the Certificate Revocation List and
// persists the result, even when a still-valid CRL is already published.
// This is the explicit force-refresh verb; use CRL to read the current
// artifact without paying for a signing operation on every call.
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
func (ca *CA) GenerateCRL(ctx context.Context) ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	return ca.generateAndPersistCRL(ctx)
}

// IsRevoked checks if a certificate serial number is revoked.
//
// Returns true if the certificate with the given serial number has been
// revoked, false otherwise. A serial missing from this instance's in-memory
// map is read through to the replicated revocation store, so a revocation
// recorded by any instance in the cluster is seen (go-xkms#1116).
//
// It fails closed: the result is false only when the store definitively
// has no record for the serial. Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrStorageError if the revocation store cannot be read
//   - ErrRevocationRecordCorrupt if the serial's record cannot be decoded
//
// Thread-safe: Yes
func (ca *CA) IsRevoked(serial *big.Int) (bool, error) {
	if !ca.initialized.Load() {
		return false, ErrNotInitialized
	}

	if serial == nil {
		return false, nil
	}

	info, err := ca.lookupRevocation(context.Background(), serial)
	if err != nil {
		return false, err
	}
	return info != nil, nil
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
