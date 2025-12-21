// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package keychain

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/jeremyhahn/go-keychain/pkg/validation"
)

var (
	// ErrNoDefaultBackend is returned when no default backend is set
	ErrNoDefaultBackend = errors.New("no default backend configured")
)

// Service singleton instance
var (
	service  *KeychainService
	initOnce sync.Once
	initMu   sync.RWMutex
)

// KeychainService provides a simplified API for keychain operations
// across multiple backends. Applications and services use this instead of managing
// KeyStore instances directly, preventing leaky abstractions.
type KeychainService struct {
	backends       map[string]KeyStore // backend name -> KeyStore
	defaultBackend string              // default backend to use
	mu             sync.RWMutex
}

// ServiceConfig configures the keychain service
type ServiceConfig struct {
	// Backends is a map of backend name to KeyStore
	Backends map[string]KeyStore

	// DefaultBackend is the name of the default backend to use
	// when no backend is specified in the key ID
	DefaultBackend string
}

// Initialize sets up the keychain service
// This should be called once at application startup
func Initialize(config *ServiceConfig) error {
	var initErr error

	initOnce.Do(func() {
		if config == nil {
			initErr = errors.New("config cannot be nil")
			return
		}

		if len(config.Backends) == 0 {
			initErr = errors.New("at least one backend must be configured")
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
			initErr = fmt.Errorf("default backend %s not found in configured backends", defaultBackend)
			return
		}

		service = &KeychainService{
			backends:       config.Backends,
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
		for _, ks := range service.backends {
			if closeErr := ks.Close(); closeErr != nil {
				log.Printf("failed to close keystore during reset: %v", closeErr)
			}
		}
		service.backends = nil
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

// Backend returns a specific backend by name
func Backend(name string) (KeyStore, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(name); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	ks, ok := service.backends[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, validation.SanitizeForLog(name))
	}

	return ks, nil
}

// DefaultBackend returns the default backend
func DefaultBackend() (KeyStore, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	if service.defaultBackend == "" {
		return nil, ErrNoDefaultBackend
	}

	ks, ok := service.backends[service.defaultBackend]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, service.defaultBackend)
	}

	return ks, nil
}

// BackendFor returns the appropriate backend for the given key attributes.
// If StoreType is specified in attrs, returns that backend.
// Otherwise returns the default backend.
// This centralizes backend resolution logic to avoid scattered conditionals.
func BackendFor(attrs *types.KeyAttributes) (KeyStore, error) {
	if attrs == nil {
		return DefaultBackend()
	}

	// If StoreType is specified, use that backend
	if attrs.StoreType != "" {
		return Backend(string(attrs.StoreType))
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

// getKeystoreForKID determines which keystore to use for a given key ID (kid).
// It parses the 4-part kid format (backend:type:algo:keyname) and returns the
// appropriate keystore along with the parsed KeyAttributes.
//
// The kid format supports optional segments:
//   - "my-key" - shorthand for just keyname (uses default backend)
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
func getKeystoreForKID(kid string) (KeyStore, *types.KeyAttributes, error) {
	if !IsInitialized() {
		return nil, nil, ErrNotInitialized
	}

	attrs, err := ParseKeyIDToAttributes(kid)
	if err != nil {
		return nil, nil, err
	}

	var ks KeyStore

	if attrs.StoreType == "" {
		// Use default backend
		ks, err = DefaultBackend()
	} else {
		// Use specified backend
		ks, err = Backend(string(attrs.StoreType))
	}

	if err != nil {
		return nil, nil, err
	}

	return ks, attrs, nil
}

// Simplified API - applications use these functions directly

// GenerateKey generates a new key with the given attributes.
// Uses BackendFor(attrs) to resolve the correct backend based on StoreType.
func GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	// Route to appropriate generation method based on algorithm
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		return ks.GenerateEd25519(attrs)
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %v", attrs.KeyAlgorithm)
	}
}

// Key retrieves a key by its attributes.
// Uses BackendFor(attrs) to resolve the correct backend based on StoreType.
func Key(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return ks.GetKey(attrs)
}

// Signer returns a crypto.Signer for the specified key attributes.
// This is the primary method - use SignerByID for string-based lookups.
func Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return ks.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the specified key attributes.
// This is the primary method - use DecrypterByID for string-based lookups.
func Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return ks.Decrypter(attrs)
}

// DeleteKey deletes a key by its attributes.
// This is the primary method - use DeleteKeyByID for string-based lookups.
func DeleteKey(attrs *types.KeyAttributes) error {
	ks, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return ks.DeleteKey(attrs)
}

// Certificate retrieves a certificate by key attributes.
// This is the primary method - use CertificateByID for string-based lookups.
func Certificate(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return ks.GetCert(attrs.CertificateID())
}

// SaveCertificate saves a certificate using key attributes.
// This is the primary method - use SaveCertificateByID for string-based lookups.
func SaveCertificate(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	ks, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return ks.SaveCert(attrs.CertificateID(), cert)
}

// DeleteCertificate deletes a certificate by key attributes.
// This is the primary method - use DeleteCertificateByID for string-based lookups.
func DeleteCertificate(attrs *types.KeyAttributes) error {
	ks, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return ks.DeleteCert(attrs.CertificateID())
}

// CertificateChain retrieves a certificate chain by key attributes.
// This is the primary method - use CertificateChainByID for string-based lookups.
func CertificateChain(attrs *types.KeyAttributes) ([]*x509.Certificate, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return nil, err
	}

	return ks.GetCertChain(attrs.CertificateID())
}

// SaveCertificateChain saves a certificate chain using key attributes.
// This is the primary method - use SaveCertificateChainByID for string-based lookups.
func SaveCertificateChain(attrs *types.KeyAttributes, chain []*x509.Certificate) error {
	ks, err := BackendFor(attrs)
	if err != nil {
		return err
	}

	return ks.SaveCertChain(attrs.CertificateID(), chain)
}

// CertificateExists checks if a certificate exists for the given key attributes.
// This is the primary method - use CertificateExistsByID for string-based lookups.
func CertificateExists(attrs *types.KeyAttributes) (bool, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return false, err
	}

	return ks.CertExists(attrs.CertificateID())
}

// TLSCertificate returns a complete tls.Certificate for the given key attributes.
// This is the primary method - use TLSCertificateByID for string-based lookups.
func TLSCertificate(attrs *types.KeyAttributes) (tls.Certificate, error) {
	ks, err := BackendFor(attrs)
	if err != nil {
		return tls.Certificate{}, err
	}

	return ks.GetTLSCertificate(attrs.CertificateID(), attrs)
}

// ========================================================================
// Secondary API - String-based lookups (use primary KeyAttributes methods when possible)
// ========================================================================

// KeyByID retrieves a key by its key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Key(attrs) for type-safe lookups.
func KeyByID(kid string) (crypto.PrivateKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	return ks.GetKeyByID(attrs.CN)
}

// SignerByID returns a signer for the specified key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Signer(attrs) for type-safe lookups.
func SignerByID(kid string) (crypto.Signer, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	return ks.GetSignerByID(attrs.CN)
}

// DecrypterByID returns a decrypter for the specified key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Decrypter(attrs) for type-safe lookups.
func DecrypterByID(kid string) (crypto.Decrypter, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	return ks.GetDecrypterByID(attrs.CN)
}

// DeleteKeyByID deletes a key by its key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer DeleteKey(attrs) for type-safe lookups.
func DeleteKeyByID(kid string) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return err
	}

	return ks.DeleteKey(attrs)
}

// ListKeys lists all keys across all backends or from a specific backend
func ListKeys(backendName ...string) ([]*types.KeyAttributes, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Validate backend name if provided
	if len(backendName) > 0 && backendName[0] != "" {
		if err := validation.ValidateBackendName(backendName[0]); err != nil {
			return nil, fmt.Errorf("invalid backend name: %w", err)
		}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	var allKeys []*types.KeyAttributes

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		ks, ok := service.backends[backendName[0]]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, validation.SanitizeForLog(backendName[0]))
		}

		return ks.ListKeys()
	}

	// List from all backends
	for _, ks := range service.backends {
		keys, err := ks.ListKeys()
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
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return err
	}

	return ks.SaveCert(attrs.CN, cert)
}

// CertificateByID retrieves a certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer Certificate(attrs) for type-safe lookups.
func CertificateByID(kid string) (*x509.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	return ks.GetCert(attrs.CN)
}

// DeleteCertificateByID deletes a certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer DeleteCertificate(attrs) for type-safe lookups.
func DeleteCertificateByID(kid string) error {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return err
	}

	return ks.DeleteCert(attrs.CN)
}

// ListCertificates lists all certificate IDs across all backends or from a specific backend
func ListCertificates(backendName ...string) ([]string, error) {
	if !IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Validate backend name if provided
	if len(backendName) > 0 && backendName[0] != "" {
		if err := validation.ValidateBackendName(backendName[0]); err != nil {
			return nil, fmt.Errorf("invalid backend name: %w", err)
		}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	var allCerts []string

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		ks, ok := service.backends[backendName[0]]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, validation.SanitizeForLog(backendName[0]))
		}

		return ks.ListCerts()
	}

	// List from all backends
	for _, ks := range service.backends {
		certs, err := ks.ListCerts()
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
	for name, ks := range service.backends {
		if err := ks.Close(); err != nil {
			errs = append(errs, fmt.Errorf("backend %s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close %d backend(s): %v", len(errs), errs)
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
//	sealed, err := keychain.Seal(ctx, secretData, &types.SealOptions{
//	    KeyAttributes: keyAttrs,
//	})
//
//	// Seal with specific backend
//	sealed, err := keychain.SealWithBackend(ctx, "tpm2", secretData, opts)
func Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	ks, err := DefaultBackend()
	if err != nil {
		return nil, err
	}

	return ks.Seal(ctx, data, opts)
}

// SealWithBackend seals data using a specific backend.
// This is useful when you need to seal with a non-default backend.
func SealWithBackend(ctx context.Context, backendName string, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return nil, err
	}

	return ks.Seal(ctx, data, opts)
}

// Unseal decrypts/recovers data that was previously sealed.
// The sealed data's backend type determines which backend is used for unsealing.
// The backendName is optional; if provided it must match the sealed data's backend.
//
// Example:
//
//	// Unseal - backend is determined from sealed data
//	plaintext, err := keychain.Unseal(ctx, sealed, &types.UnsealOptions{
//	    KeyAttributes: keyAttrs,
//	})
func Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrInvalidSealedData
	}

	// Find the backend that matches the sealed data's backend type
	service.mu.RLock()
	defer service.mu.RUnlock()

	for _, ks := range service.backends {
		if ks.Backend().Type() == sealed.Backend {
			return ks.Unseal(ctx, sealed, opts)
		}
	}

	return nil, fmt.Errorf("%w: no backend found for type %s", ErrBackendNotFound, sealed.Backend)
}

// UnsealWithBackend unseals data using a specific backend.
// The backend must match the sealed data's backend type.
func UnsealWithBackend(ctx context.Context, backendName string, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	// Validate backend name to prevent injection attacks
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return nil, err
	}

	return ks.Unseal(ctx, sealed, opts)
}

// CanSeal returns true if the specified backend supports sealing operations.
// If backendName is empty, checks the default backend.
func CanSeal(backendName ...string) bool {
	var ks KeyStore
	var err error

	if len(backendName) > 0 && backendName[0] != "" {
		ks, err = Backend(backendName[0])
	} else {
		ks, err = DefaultBackend()
	}

	if err != nil {
		return false
	}

	return ks.CanSeal()
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
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(name)
	if err != nil {
		return nil, err
	}

	b := ks.Backend()
	caps := b.Capabilities()

	return &BackendInfo{
		ID:             name,
		Type:           b.Type(),
		HardwareBacked: caps.HardwareBacked,
		Capabilities:   caps,
	}, nil
}

// GetBackendCapabilities returns the capabilities of a specific backend.
func GetBackendCapabilities(name string) (types.Capabilities, error) {
	if err := validation.ValidateBackendName(name); err != nil {
		return types.Capabilities{}, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(name)
	if err != nil {
		return types.Capabilities{}, err
	}

	return ks.Backend().Capabilities(), nil
}

// ========================================================================
// Extended Key Operations
// ========================================================================

// GenerateKeyWithBackend generates a new key on a specific backend.
func GenerateKeyWithBackend(backendName string, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return nil, err
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		return ks.GenerateEd25519(attrs)
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %v", attrs.KeyAlgorithm)
	}
}

// RotateKey rotates (replaces) an existing key with a new one.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func RotateKey(kid string) (crypto.PrivateKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	return ks.RotateKey(attrs)
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
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer: %w", err)
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
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return err
	}

	privKey, err := ks.GetKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	var pubKey crypto.PublicKey
	if signer, ok := privKey.(crypto.Signer); ok {
		pubKey = signer.Public()
	} else {
		return fmt.Errorf("key does not support signing operations")
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
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support symmetric encryption")
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
	}

	return encrypter.Encrypt(data, opts)
}

// Decrypt decrypts data using a symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func Decrypt(kid string, data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support symmetric decryption")
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
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
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return err
	}

	return ks.SaveCertChain(attrs.CN, chain)
}

// CertificateChainByID retrieves a certificate chain by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer CertificateChain(attrs) for type-safe lookups.
func CertificateChainByID(kid string) ([]*x509.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	return ks.GetCertChain(attrs.CN)
}

// CertificateExistsByID checks if a certificate exists for the given key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer CertificateExists(attrs) for type-safe lookups.
func CertificateExistsByID(kid string) (bool, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return false, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return false, err
	}

	return ks.CertExists(attrs.CN)
}

// ========================================================================
// TLS Operations (String-based - prefer KeyAttributes versions)
// ========================================================================

// TLSCertificateByID returns a complete tls.Certificate by key ID (kid).
// Format: "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
// Prefer TLSCertificate(attrs) for type-safe lookups.
func TLSCertificateByID(kid string) (tls.Certificate, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return tls.Certificate{}, err
	}

	return ks.GetTLSCertificate(attrs.CN, attrs)
}

// ========================================================================
// Import/Export Operations
// ========================================================================

// GetImportParameters retrieves parameters needed to import a key into a backend.
func GetImportParameters(backendName string, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend %s does not support import/export operations", backendName)
	}

	return importExportBackend.GetImportParameters(attrs, algorithm)
}

// WrapKey wraps key material for secure transport using the specified parameters.
func WrapKey(backendName string, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend %s does not support import/export operations", backendName)
	}

	return importExportBackend.WrapKey(keyMaterial, params)
}

// UnwrapKey unwraps key material that was previously wrapped.
func UnwrapKey(backendName string, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend %s does not support import/export operations", backendName)
	}

	return importExportBackend.UnwrapKey(wrapped, params)
}

// ImportKey imports externally generated key material into a backend.
func ImportKey(backendName string, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return err
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return fmt.Errorf("backend %s does not support import/export operations", backendName)
	}

	return importExportBackend.ImportKey(attrs, wrapped)
}

// ExportKey exports a key in wrapped form for secure transport.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func ExportKey(kid string, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import/export operations")
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
		return fmt.Errorf("invalid source key ID: %w", err)
	}

	if err := validation.ValidateBackendName(destBackend); err != nil {
		return fmt.Errorf("invalid destination backend name: %w", err)
	}

	sourceKs, sourceAttrs, err := getKeystoreForKID(sourceKID)
	if err != nil {
		return fmt.Errorf("failed to get source keystore: %w", err)
	}

	destKs, err := Backend(destBackend)
	if err != nil {
		return fmt.Errorf("failed to get destination backend: %w", err)
	}

	sourceImportExport, ok := sourceKs.Backend().(backend.ImportExportBackend)
	if !ok {
		return fmt.Errorf("source backend does not support export operations")
	}

	destImportExport, ok := destKs.Backend().(backend.ImportExportBackend)
	if !ok {
		return fmt.Errorf("destination backend does not support import operations")
	}

	if destAttrs == nil {
		destAttrs = sourceAttrs
	}

	algorithm := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	importParams, err := destImportExport.GetImportParameters(destAttrs, algorithm)
	if err != nil {
		return fmt.Errorf("failed to get import parameters: %w", err)
	}

	wrappedKey, err := sourceImportExport.ExportKey(sourceAttrs, algorithm)
	if err != nil {
		return fmt.Errorf("failed to export key: %w", err)
	}

	wrappedKey.ImportToken = importParams.ImportToken

	return destImportExport.ImportKey(destAttrs, wrappedKey)
}

// ========================================================================
// Symmetric Key Operations
// ========================================================================

// GenerateSymmetricKey generates a new symmetric key.
func GenerateSymmetricKey(backendName string, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if err := validation.ValidateBackendName(backendName); err != nil {
		return nil, fmt.Errorf("invalid backend name: %w", err)
	}

	ks, err := Backend(backendName)
	if err != nil {
		return nil, err
	}

	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		return nil, fmt.Errorf("backend %s does not support symmetric key operations", backendName)
	}

	return symBackend.GenerateSymmetricKey(attrs)
}

// GetSymmetricKey retrieves an existing symmetric key.
// The kid format is "backend:type:algo:keyname" with optional segments, or just "keyname" (uses defaults).
func GetSymmetricKey(kid string) (types.SymmetricKey, error) {
	if err := validation.ValidateKeyReference(kid); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, attrs, err := getKeystoreForKID(kid)
	if err != nil {
		return nil, err
	}

	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support symmetric key operations")
	}

	return symBackend.GetSymmetricKey(attrs)
}
