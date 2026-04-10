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

package xkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// Compile-time interface compliance check: XKMSService implements
// the full XKMSServicer interface used by the embedded SDK transport.
var _ transport.XKMSServicer = (*XKMSService)(nil)

// Service singleton instance
var (
	service  *XKMSService
	initOnce sync.Once
	initMu   sync.RWMutex
)

// XKMSService provides a simplified API for xkms operations
// across multiple backends. Applications and services use this instead of managing
// Backend instances directly, preventing leaky abstractions.
//
// When optional subsystem setters are called (SetBarrier, SetWebAuthn, etc.),
// XKMSService implements the full transport.XKMSServicer interface, enabling
// direct in-process access via the SDK's embedded transport.
type XKMSService struct {
	backends       map[string]Backend // full-service backend name -> Backend
	keyProviders   map[string]Backend // partial key provider name -> Backend
	defaultBackend string             // default backend to use
	mu             sync.RWMutex

	// Optional subsystems — when set via Set* methods, XKMSService implements
	// the full transport.XKMSServicer interface. Each field starts nil (returning
	// ErrNotConfigured) until wired by the server or application.
	barrier           *seal.Barrier
	barrierRegistry   *seal.BarrierRegistry
	pinManager        pin.PINManager //nolint:staticcheck // TODO: migrate to PINBackend
	userStore         user.Store
	passwordStore     *staticpw.BackendStore
	platformStore     seal.PlatformStore
	policyManager     *policy.Manager
	webauthnService   *webauthn.Service
	custodianService  *custodian.Service
	shareStore        sharestore.ShareStore
	credentialService *credentialspkg.Service

	// passwordStoreManager manages per-tenant password stores with
	// session lock state and TenantBarrier-backed encryption.
	passwordStoreManager *staticpw.TenantPasswordStoreManager

	// ceremonyService is stored as any to break the import cycle:
	// xkms -> init -> ca -> xkms. The concrete type is *initialize.CeremonyService.
	// Callers retrieve it via CeremonyService() and type-assert as needed.
	ceremonyService any

	// ca is the Certificate Authority provider. Uses the provider.CA interface
	// from pkg/ca/provider to break the import cycle (pkg/ca imports pkg/xkms).
	// The concrete type is *ca.CA which implements provider.CA (and optionally
	// provider.TCGCA for TCG operations).
	ca provider.CA
}

// ServiceConfig configures the xkms service
type ServiceConfig struct {
	// Backends is a map of full-service backend name to Backend.
	// Full-service backends support sign, verify, encrypt, decrypt, certs, seal/unseal.
	Backends map[string]Backend

	// KeyProviders is a map of partial key provider name to Backend.
	// Key providers support key generation and limited crypto ops,
	// composed into full-service backends (e.g., pkcs8, symmetric, quantum, frost, threshold).
	KeyProviders map[string]Backend

	// DefaultBackend is the name of the default backend to use
	// when no backend is specified in the key ID
	DefaultBackend string
}

// Get returns the initialized XKMSService singleton.
// Returns ErrNotInitialized if Initialize has not been called.
func Get() (*XKMSService, error) {
	initMu.RLock()
	defer initMu.RUnlock()
	if service == nil {
		return nil, ErrNotInitialized
	}
	return service, nil
}

// SetBarrier sets the barrier subsystem for seal/unseal operations.
func (s *XKMSService) SetBarrier(b *seal.Barrier) { s.barrier = b }

// SetPINManager sets the PIN management subsystem.
func (s *XKMSService) SetPINManager(p pin.PINManager) { s.pinManager = p } //nolint:staticcheck // TODO: migrate to PINBackend

// SetUserStore sets the user management subsystem.
func (s *XKMSService) SetUserStore(u user.Store) { s.userStore = u }

// SetPasswordStore sets the static password management subsystem.
func (s *XKMSService) SetPasswordStore(p *staticpw.BackendStore) { s.passwordStore = p }

// SetPlatformStore sets the sealed platform credential store subsystem.
func (s *XKMSService) SetPlatformStore(p seal.PlatformStore) { s.platformStore = p }

// SetPolicyManager sets the PCR policy management subsystem.
func (s *XKMSService) SetPolicyManager(p *policy.Manager) { s.policyManager = p }

// SetWebAuthn sets the WebAuthn/FIDO2 subsystem.
func (s *XKMSService) SetWebAuthn(w *webauthn.Service) { s.webauthnService = w }

// SetCustodianService sets the custodian group management subsystem.
func (s *XKMSService) SetCustodianService(c *custodian.Service) { s.custodianService = c }

// SetShareStore sets the Shamir share store subsystem.
func (s *XKMSService) SetShareStore(ss sharestore.ShareStore) { s.shareStore = ss }

// SetBarrierRegistry sets the barrier registry for multi-tenant barrier management.
func (s *XKMSService) SetBarrierRegistry(r *seal.BarrierRegistry) { s.barrierRegistry = r }

// SetPasswordStoreManager sets the per-tenant password store manager.
func (s *XKMSService) SetPasswordStoreManager(m *staticpw.TenantPasswordStoreManager) {
	s.passwordStoreManager = m
}

// SetCredentialService sets the credential management subsystem.
func (s *XKMSService) SetCredentialService(svc *credentialspkg.Service) {
	s.credentialService = svc
}

// SetCeremonyService sets the init ceremony subsystem. The value is stored as
// any to break the import cycle (xkms -> init -> ca -> xkms). The concrete
// type is *initialize.CeremonyService; callers type-assert after retrieval.
func (s *XKMSService) SetCeremonyService(svc any) {
	s.ceremonyService = svc
}

// CeremonyService returns the ceremony service. Callers must type-assert
// to *initialize.CeremonyService.
func (s *XKMSService) CeremonyService() any {
	return s.ceremonyService
}

// SetCA sets the Certificate Authority provider. The concrete type is *ca.CA
// which implements provider.CA (and optionally provider.TCGCA for TCG ops).
func (s *XKMSService) SetCA(ca provider.CA) {
	s.ca = ca
}

// CA returns the Certificate Authority provider, or nil if not configured.
func (s *XKMSService) CA() provider.CA {
	return s.ca
}

// validateTenantAccess checks that the TenantID in KeyAttributes is valid.
// Returns nil when TenantID is empty (single-tenant mode).
func validateTenantAccess(attrs *types.KeyAttributes) error {
	if attrs == nil || attrs.TenantID == "" {
		return nil // single-tenant mode
	}
	return storage.ValidateTenantID(attrs.TenantID)
}

// Initialize sets up the xkms service.
// This should be called once at application startup.
// Subsequent calls are no-ops due to sync.Once semantics.
func Initialize(config *ServiceConfig) error {
	var initErr error

	initOnce.Do(func() {
		if config == nil {
			initErr = ErrNilConfig
			return
		}

		if len(config.Backends) == 0 {
			initErr = ErrNoBackendsConfigured
			return
		}

		// If no default specified, use first backend
		defaultBackend := config.DefaultBackend
		if defaultBackend == "" {
			for name := range config.Backends {
				defaultBackend = name
				break
			}
		}

		// Verify default backend exists
		if _, ok := config.Backends[defaultBackend]; !ok {
			initErr = &ErrBackendLookup{
				Sentinel: ErrDefaultBackendNotFound,
				Name:     validation.SanitizeForLog(defaultBackend),
			}
			return
		}

		service = &XKMSService{
			backends:       config.Backends,
			keyProviders:   config.KeyProviders,
			defaultBackend: defaultBackend,
		}
	})

	return initErr
}

// Reset clears the service (useful for testing)
func Reset() {
	initMu.Lock()
	defer initMu.Unlock()

	if service != nil {
		service.mu.Lock()
		for _, b := range service.backends {
			if closeErr := b.Close(); closeErr != nil {
				log.Printf("failed to close backend during reset: %v", closeErr)
			}
		}
		for _, kp := range service.keyProviders {
			if closeErr := kp.Close(); closeErr != nil {
				log.Printf("failed to close key provider during reset: %v", closeErr)
			}
		}
		service.backends = nil
		service.keyProviders = nil
		service.mu.Unlock()
	}

	service = nil
	initOnce = sync.Once{}
}

// IsInitialized returns whether the service has been initialized
func IsInitialized() bool {
	initMu.RLock()
	defer initMu.RUnlock()
	return service != nil
}

// GetBackend returns a specific backend by name
func GetBackend(name string) (Backend, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	b, ok := service.backends[name]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrBackendNotFound,
			Name:     validation.SanitizeForLog(name),
		}
	}

	return b, nil
}

// DefaultBackend returns the default backend
func DefaultBackend() (Backend, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	if service.defaultBackend == "" {
		return nil, ErrNoDefaultBackend
	}

	b, ok := service.backends[service.defaultBackend]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrBackendNotFound,
			Name:     service.defaultBackend,
		}
	}

	return b, nil
}

// BackendFor returns the appropriate backend for the given key attributes.
// If StoreType is specified in attrs, returns that backend.
// Otherwise returns the default backend.
// This centralizes backend resolution logic to avoid scattered conditionals.
func BackendFor(attrs *types.KeyAttributes) (Backend, error) {
	if attrs == nil {
		return DefaultBackend()
	}

	// Validate tenant access before resolving backend
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	// If StoreType is specified, use that backend
	if attrs.StoreType != "" {
		return GetBackend(string(attrs.StoreType))
	}

	// Fall back to default backend
	return DefaultBackend()
}

// ParseCertificateID parses a certificate ID string into KeyAttributes.
// This uses the unified 4-part Key ID format: backend:type:algo:keyname
// All segments except keyname are optional.
//
// Examples:
//   - "my-key" - shorthand for just keyname (uses defaults)
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
func ParseCertificateID(kid string) (*types.KeyAttributes, error) {
	return ParseKeyIDToAttributes(kid)
}

// RegisterServiceBackend dynamically adds a backend to the running xkms service.
// This allows backends discovered after startup (e.g., PKCS#11 tokens
// connected via the admin area) to participate in key operations and PIV.
func RegisterServiceBackend(name string, backend Backend) error {
	if !IsInitialized() {
		return ErrNotInitialized
	}
	if err := validation.ValidateBackendName(name); err != nil {
		return &ErrBackendNameValidation{Err: err}
	}

	service.mu.Lock()
	defer service.mu.Unlock()

	service.backends[name] = backend
	return nil
}

// Backends returns the names of all registered backends
func Backends() []string {
	if !IsInitialized() {
		return nil
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	backends := make([]string, 0, len(service.backends))
	for name := range service.backends {
		backends = append(backends, name)
	}

	return backends
}

// KeyProviders returns the names of all registered key providers.
// Key providers are partial implementations (key generation + limited ops)
// that are composed into full-service backends.
func KeyProviders() []string {
	if !IsInitialized() {
		return nil
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	providers := make([]string, 0, len(service.keyProviders))
	for name := range service.keyProviders {
		providers = append(providers, name)
	}

	return providers
}

// GetKeyProvider returns a specific key provider by name.
func GetKeyProvider(name string) (Backend, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, &ErrKeyProviderNameValidation{Err: err}
	}

	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	kp, ok := service.keyProviders[name]
	if !ok {
		return nil, &ErrBackendLookup{
			Sentinel: ErrKeyProviderNotFound,
			Name:     validation.SanitizeForLog(name),
		}
	}

	return kp, nil
}

// getBackendForKID determines which backend to use for a given key ID (kid).
// It parses the 4-part kid format (backend:type:algo:keyname) and returns the
// appropriate backend along with the parsed KeyAttributes.
//
// The kid format supports optional segments:
//   - "my-key" - shorthand for just keyname (uses default backend)
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
func getBackendForKID(kid string) (Backend, *types.KeyAttributes, error) {
	if !IsInitialized() {
		return nil, nil, ErrNotInitialized
	}

	attrs, err := ParseKeyIDToAttributes(kid)
	if err != nil {
		return nil, nil, err
	}

	var b Backend

	if attrs.StoreType != "" {
		// Use StoreType as the backend name
		b, err = GetBackend(string(attrs.StoreType))
	} else {
		// Use default backend
		b, err = DefaultBackend()
	}

	if err != nil {
		return nil, nil, err
	}

	return b, attrs, nil
}

// Simplified API - applications use these functions directly

// GenerateKey generates a new key with the given attributes.
// Uses BackendFor(attrs) to resolve the correct backend based on StoreType.
func GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	// Route to appropriate generation method based on algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.GenerateRSA(attrs)
	case x509.ECDSA:
		return b.GenerateECDSA(attrs)
	case x509.Ed25519:
		return b.GenerateEd25519(attrs)
	default:
		return nil, &ErrUnsupportedPublicKeyAlgorithm{Algorithm: attrs.KeyAlgorithm}
	}
}

// Key retrieves a key by its attributes.
// Uses BackendFor(attrs) to resolve the correct backend based on StoreType.
func Key(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.GetKey(attrs)
}

// Signer returns a crypto.Signer for the specified key attributes.
// This is the primary method - use SignerByID for string-based lookups.
func Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the specified key attributes.
// This is the primary method - use DecrypterByID for string-based lookups.
func Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.Decrypter(attrs)
}

// DeleteKey deletes a key by its attributes.
// This is the primary method - use DeleteKeyByID for string-based lookups.
func DeleteKey(attrs *types.KeyAttributes) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.DeleteKey(attrs)
}

// Certificate retrieves a certificate by key attributes.
// This is the primary method - use CertificateByID for string-based lookups.
func Certificate(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.GetCert(attrs.CertificateID())
}

// SaveCertificate saves a certificate using key attributes.
// This is the primary method - use SaveCertificateByID for string-based lookups.
func SaveCertificate(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.SaveCert(attrs.CertificateID(), cert)
}

// DeleteCertificate deletes a certificate by key attributes.
// This is the primary method - use DeleteCertificateByID for string-based lookups.
func DeleteCertificate(attrs *types.KeyAttributes) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.DeleteCert(attrs.CertificateID())
}

// CertificateChain retrieves a certificate chain by key attributes.
// This is the primary method - use CertificateChainByID for string-based lookups.
func CertificateChain(attrs *types.KeyAttributes) ([]*x509.Certificate, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return b.GetCertChain(attrs.CertificateID())
}

// SaveCertificateChain saves a certificate chain using key attributes.
// This is the primary method - use SaveCertificateChainByID for string-based lookups.
func SaveCertificateChain(attrs *types.KeyAttributes, chain []*x509.Certificate) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return b.SaveCertChain(attrs.CertificateID(), chain)
}

// CertificateExists checks if a certificate exists for the given key attributes.
// This is the primary method - use CertificateExistsByID for string-based lookups.
func CertificateExists(attrs *types.KeyAttributes) (bool, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return false, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return false, err
	}

	return b.CertExists(attrs.CertificateID())
}

// TLSCertificate returns a complete tls.Certificate for the given key attributes.
// This is the primary method - use TLSCertificateByID for string-based lookups.
func TLSCertificate(attrs *types.KeyAttributes) (tls.Certificate, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return tls.Certificate{}, err
	}

	b, err := BackendFor(attrs)
	if err != nil {
		return tls.Certificate{}, err
	}

	return b.GetTLSCertificate(attrs.CertificateID(), attrs)
}

// ========================================================================
// Secondary API - String-based lookups (use primary KeyAttributes methods when possible)
// ========================================================================

// KeyByID retrieves a key by its key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Key(attrs) for type-safe lookups.
func KeyByID(kid string) (crypto.PrivateKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetKeyByID(kid)
}

// SignerByID returns a signer for the specified key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Signer(attrs) for type-safe lookups.
func SignerByID(kid string) (crypto.Signer, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetSignerByID(kid)
}

// DecrypterByID returns a decrypter for the specified key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Decrypter(attrs) for type-safe lookups.
func DecrypterByID(kid string) (crypto.Decrypter, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetDecrypterByID(kid)
}

// DeleteKeyByID deletes a key by its key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer DeleteKey(attrs) for type-safe lookups.
func DeleteKeyByID(kid string) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.DeleteKey(attrs)
}

// ListKeys lists all keys across all backends or from a specific backend
func ListKeys(backendName ...string) ([]*types.KeyAttributes, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Validate backend name if provided
	if len(backendName) > 0 && backendName[0] != "" {
		if err := validation.ValidateBackendName(backendName[0]); err != nil {
			return nil, &ErrBackendNameValidation{Err: err}
		}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	var allKeys []*types.KeyAttributes

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		b, ok := service.backends[backendName[0]]
		if !ok {
			return nil, &ErrBackendLookup{
				Sentinel: ErrBackendNotFound,
				Name:     validation.SanitizeForLog(backendName[0]),
			}
		}

		return b.ListKeys()
	}

	// List from all backends
	for _, b := range service.backends {
		keys, err := b.ListKeys()
		if err != nil {
			// Log error but continue with other backends
			continue
		}
		allKeys = append(allKeys, keys...)
	}

	return allKeys, nil
}

// SaveCertificateByID saves a certificate by key ID.
// Format: "backend:key-id" or just "key-id" (uses default backend).
// Prefer SaveCertificate(attrs, cert) for type-safe lookups.
func SaveCertificateByID(kid string, cert *x509.Certificate) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.SaveCert(kid, cert)
}

// CertificateByID retrieves a certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Certificate(attrs) for type-safe lookups.
func CertificateByID(kid string) (*x509.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetCert(kid)
}

// DeleteCertificateByID deletes a certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer DeleteCertificate(attrs) for type-safe lookups.
func DeleteCertificateByID(kid string) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.DeleteCert(kid)
}

// ListCertificates lists all certificate IDs across all backends or from a specific backend
func ListCertificates(backendName ...string) ([]string, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Validate backend name if provided
	if len(backendName) > 0 && backendName[0] != "" {
		if err := validation.ValidateBackendName(backendName[0]); err != nil {
			return nil, &ErrBackendNameValidation{Err: err}
		}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	var allCerts []string

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		b, ok := service.backends[backendName[0]]
		if !ok {
			return nil, &ErrBackendLookup{
				Sentinel: ErrBackendNotFound,
				Name:     validation.SanitizeForLog(backendName[0]),
			}
		}

		return b.ListCerts()
	}

	// List from all backends
	for _, b := range service.backends {
		certs, err := b.ListCerts()
		if err != nil {
			// Log error but continue with other backends
			continue
		}
		allCerts = append(allCerts, certs...)
	}

	return allCerts, nil
}

// Close closes all backends (called at application shutdown)
func Close() error {
	if !IsInitialized() {
		return nil
	}

	service.mu.Lock()
	defer service.mu.Unlock()

	var errs []error
	for name, b := range service.backends {
		if err := b.Close(); err != nil {
			errs = append(errs, &ErrBackendCloseItem{Backend: name, Err: err})
		}
	}

	if len(errs) > 0 {
		return &ErrBackendClose{Errs: errs}
	}

	return nil
}

// ========================================================================
// Sealing Operations
// ========================================================================

// Seal encrypts/protects data using the specified backend's sealing mechanism.
// The backendName parameter specifies which backend to use for sealing.
// If backendName is empty, the default backend is used.
//
// Different backends provide different security guarantees:
//   - TPM2: PCR-bound hardware sealing (strongest)
//   - PKCS#11: HSM-backed AES-GCM encryption
//   - AWS/Azure/GCP KMS: Cloud-managed envelope encryption
//   - PKCS#8: Software-based HKDF + AES-GCM (portable but weaker)
//
// Example:
//
//	// Seal with default backend
//	sealed, err := xkms.Seal(ctx, secretData, &types.SealOptions{
//	    KeyAttributes: keyAttrs,
//	})
//
//	// Seal with specific backend
//	sealed, err := xkms.SealWithBackend(ctx, "tpm2", secretData, opts)
func Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	b, err := DefaultBackend()
	if err != nil {
		return nil, err
	}

	return b.Seal(ctx, data, opts)
}

// SealWithBackend seals data using a specific backend.
// This is useful when you need to seal with a non-default backend.
func SealWithBackend(ctx context.Context, backendName string, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	return b.Seal(ctx, data, opts)
}

// Unseal decrypts/recovers data that was previously sealed.
// The sealed data's backend type determines which backend is used for unsealing.
// The backendName is optional; if provided it must match the sealed data's backend.
//
// Example:
//
//	// Unseal - backend is determined from sealed data
//	plaintext, err := xkms.Unseal(ctx, sealed, &types.UnsealOptions{
//	    KeyAttributes: keyAttrs,
//	})
func Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrInvalidSealedData
	}

	// Find the backend that matches the sealed data's backend type
	service.mu.RLock()
	defer service.mu.RUnlock()

	for _, b := range service.backends {
		if b.KeyProvider().Type() == sealed.Backend {
			return b.Unseal(ctx, sealed, opts)
		}
	}

	return nil, &ErrUnsealBackendNotFound{BackendType: sealed.Backend}
}

// UnsealWithBackend unseals data using a specific backend.
// The backend must match the sealed data's backend type.
func UnsealWithBackend(ctx context.Context, backendName string, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	return b.Unseal(ctx, sealed, opts)
}

// CanSeal returns true if the specified backend supports sealing operations.
// If backendName is empty, checks the default backend.
func CanSeal(backendName ...string) bool {
	var b Backend
	var err error

	if len(backendName) > 0 && backendName[0] != "" {
		b, err = GetBackend(backendName[0])
	} else {
		b, err = DefaultBackend()
	}

	if err != nil {
		return false
	}

	return b.CanSeal()
}

// ========================================================================
// Backend Information
// ========================================================================

// BackendInfo contains information about a backend.
type BackendInfo struct {
	// ID is the backend's unique identifier/name
	ID string

	// Type is the backend type (e.g., "pkcs8", "pkcs11", "tpm2", etc.)
	Type types.BackendType

	// HardwareBacked indicates if keys are stored in hardware
	HardwareBacked bool

	// Capabilities describes what features the backend supports
	Capabilities types.Capabilities
}

// GetBackendInfo returns information about a specific backend.
func GetBackendInfo(name string) (*BackendInfo, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(name)
	if err != nil {
		return nil, err
	}

	kp := b.KeyProvider()
	caps := kp.Capabilities()

	return &BackendInfo{
		ID:             name,
		Type:           kp.Type(),
		HardwareBacked: caps.HardwareBacked,
		Capabilities:   caps,
	}, nil
}

// GetBackendCapabilities returns the capabilities of a specific backend.
func GetBackendCapabilities(name string) (types.Capabilities, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return types.Capabilities{}, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(name)
	if err != nil {
		return types.Capabilities{}, err
	}

	return b.KeyProvider().Capabilities(), nil
}

// ========================================================================
// Extended Key Operations
// ========================================================================

// GenerateKeyWithBackend generates a new key on a specific backend.
func GenerateKeyWithBackend(backendName string, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.GenerateRSA(attrs)
	case x509.ECDSA:
		return b.GenerateECDSA(attrs)
	case x509.Ed25519:
		return b.GenerateEd25519(attrs)
	default:
		return nil, &ErrUnsupportedPublicKeyAlgorithm{Algorithm: attrs.KeyAlgorithm}
	}
}

// RotateKey rotates (replaces) an existing key with a new one.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func RotateKey(kid string) (crypto.PrivateKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.RotateKey(attrs)
}

// ========================================================================
// Signing and Verification
// ========================================================================

// SignOptions contains options for signing operations.
type SignOptions struct {
	// Hash is the hash algorithm to use (default: SHA256)
	Hash crypto.Hash

	// PSSOptions for RSA-PSS signatures (optional)
	PSSOptions *rsa.PSSOptions
}

// Sign signs data using the specified key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Sign(kid string, data []byte, opts *SignOptions) ([]byte, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	signer, err := b.Signer(attrs)
	if err != nil {
		return nil, &ErrCryptoOperation{Operation: "signer", Err: err}
	}

	// Ed25519 uses pure signing (no prehashing) by default
	// The signer expects the raw message and crypto.Hash(0) as SignerOpts
	if attrs.KeyAlgorithm == x509.Ed25519 {
		return signer.Sign(nil, data, crypto.Hash(0))
	}

	if opts == nil {
		opts = &SignOptions{Hash: crypto.SHA256}
	}
	if opts.Hash == 0 {
		opts.Hash = crypto.SHA256
	}

	hasher := opts.Hash.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	var signerOpts crypto.SignerOpts = opts.Hash
	if opts.PSSOptions != nil {
		signerOpts = opts.PSSOptions
	}

	return signer.Sign(nil, digest, signerOpts)
}

// Verify verifies a signature against data using the specified key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Verify(kid string, data, signature []byte, opts *types.VerifyOpts) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	privKey, err := b.GetKey(attrs)
	if err != nil {
		return &ErrKeyOperation{Operation: "get key", Err: err}
	}

	var pubKey crypto.PublicKey
	if signer, ok := privKey.(crypto.Signer); ok {
		pubKey = signer.Public()
	} else {
		return ErrKeySigningNotSupported
	}

	// Ed25519 uses pure verification (no prehashing) by default
	// Verify against the raw message, not a hash
	if attrs.KeyAlgorithm == x509.Ed25519 {
		verifier := types.NewVerifier(&types.VerifyOpts{Hash: crypto.Hash(0)})
		return verifier.Verify(pubKey, data, signature)
	}

	if opts == nil {
		opts = &types.VerifyOpts{Hash: crypto.SHA256}
	}
	if opts.Hash == 0 {
		opts.Hash = crypto.SHA256
	}

	hasher := opts.Hash.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	verifier := types.NewVerifier(opts)
	return verifier.Verify(pubKey, digest, signature)
}

// ========================================================================
// Symmetric Encryption/Decryption
// ========================================================================

// Encrypt encrypts data using a symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Encrypt(kid string, data []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported}
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "failed to get symmetric encrypter", Err: err}
	}

	return encrypter.Encrypt(data, opts)
}

// Decrypt decrypts data using a symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Decrypt(kid string, data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported}
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrDecryptionFailed, Detail: "failed to get symmetric encrypter", Err: err}
	}

	return encrypter.Decrypt(data, opts)
}

// ========================================================================
// Certificate Chain Operations (String-based - prefer KeyAttributes versions)
// ========================================================================

// SaveCertificateChainByID saves a certificate chain by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer SaveCertificateChain(attrs, chain) for type-safe lookups.
func SaveCertificateChainByID(kid string, chain []*x509.Certificate) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return err
	}

	return b.SaveCertChain(kid, chain)
}

// CertificateChainByID retrieves a certificate chain by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer CertificateChain(attrs) for type-safe lookups.
func CertificateChainByID(kid string) ([]*x509.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	return b.GetCertChain(kid)
}

// CertificateExistsByID checks if a certificate exists for the given key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer CertificateExists(attrs) for type-safe lookups.
func CertificateExistsByID(kid string) (bool, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return false, &ErrKeyIDParse{Err: err}
	}

	b, _, err := getBackendForKID(kid)
	if err != nil {
		return false, err
	}

	return b.CertExists(kid)
}

// ========================================================================
// TLS Operations (String-based - prefer KeyAttributes versions)
// ========================================================================

// TLSCertificateByID returns a complete tls.Certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer TLSCertificate(attrs) for type-safe lookups.
func TLSCertificateByID(kid string) (tls.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return tls.Certificate{}, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return tls.Certificate{}, err
	}

	return b.GetTLSCertificate(kid, attrs)
}

// ========================================================================
// Import/Export Operations
// ========================================================================

// GetImportParameters retrieves parameters needed to import a key into a backend.
func GetImportParameters(backendName string, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
		}
	}

	return importExportBackend.GetImportParameters(attrs, algorithm)
}

// WrapKey wraps key material for secure transport using the specified parameters.
func WrapKey(backendName string, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
		}
	}

	return importExportBackend.WrapKey(keyMaterial, params)
}

// UnwrapKey unwraps key material that was previously wrapped.
func UnwrapKey(backendName string, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
		}
	}

	return importExportBackend.UnwrapKey(wrapped, params)
}

// ImportKey imports externally generated key material into a backend.
func ImportKey(backendName string, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if err := validateTenantAccess(attrs); err != nil {
		return err
	}

	if err := validation.ValidateBackendName(backendName); err != nil {
		return &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return err
	}

	importExportBackend, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Backend:  backendName,
		}
	}

	return importExportBackend.ImportKey(attrs, wrapped)
}

// ExportKey exports a key in wrapped form for secure transport.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func ExportKey(kid string, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrImportExportNotSupported}
	}

	return importExportBackend.ExportKey(attrs, algorithm)
}

// ========================================================================
// Cross-Backend Operations
// ========================================================================

// CopyKey copies a key from one backend to another.
// The sourceKID format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func CopyKey(sourceKID string, destBackend string, destAttrs *types.KeyAttributes) error {
	if err := validation.ValidateKeyReference(sourceKID); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	if err := validateTenantAccess(destAttrs); err != nil {
		return err
	}

	if err := validation.ValidateBackendName(destBackend); err != nil {
		return &ErrBackendNameValidation{Err: err}
	}

	sourceB, sourceAttrs, err := getBackendForKID(sourceKID)
	if err != nil {
		return &ErrCopyKeyBackend{Role: "source", Err: err}
	}

	destB, err := GetBackend(destBackend)
	if err != nil {
		return &ErrCopyKeyBackend{Role: "destination", Err: err}
	}

	sourceImportExport, ok := sourceB.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Detail:   "source backend does not support export operations",
		}
	}

	destImportExport, ok := destB.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Detail:   "destination backend does not support import operations",
		}
	}

	if destAttrs == nil {
		destAttrs = sourceAttrs
	}

	algorithm := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	importParams, err := destImportExport.GetImportParameters(destAttrs, algorithm)
	if err != nil {
		return &ErrImportExportOperation{Operation: "get import parameters", Err: err}
	}

	wrappedKey, err := sourceImportExport.ExportKey(sourceAttrs, algorithm)
	if err != nil {
		return &ErrImportExportOperation{Operation: "export key", Err: err}
	}

	wrappedKey.ImportToken = importParams.ImportToken

	return destImportExport.ImportKey(destAttrs, wrappedKey)
}

// ========================================================================
// Symmetric Key Operations
// ========================================================================

// GenerateSymmetricKey generates a new symmetric key.
func GenerateSymmetricKey(backendName string, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if err := validateTenantAccess(attrs); err != nil {
		return nil, err
	}

	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, &ErrBackendNameValidation{Err: err}
	}

	b, err := GetBackend(backendName)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrSymmetricNotSupported,
			Backend:  backendName,
		}
	}

	return symBackend.GenerateSymmetricKey(attrs)
}

// GetSymmetricKey retrieves an existing symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func GetSymmetricKey(kid string) (types.SymmetricKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	b, attrs, err := getBackendForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported}
	}

	return symBackend.GetSymmetricKey(attrs)
}
