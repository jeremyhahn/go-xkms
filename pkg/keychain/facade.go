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
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/jeremyhahn/go-keychain/pkg/validation"
)

var (
	// ErrNoDefaultBackend is returned when no default backend is set
	ErrNoDefaultBackend = errors.New("no default backend configured")
)

// Facade singleton instance
var (
	facade   *KeychainFacade
	initOnce sync.Once
	initMu   sync.RWMutex
)

// KeychainFacade provides a simplified API for keychain operations
// across multiple backends. Applications and services use this instead of managing
// KeyStore instances directly, preventing leaky abstractions.
type KeychainFacade struct {
	backends       map[string]KeyStore // backend name -> KeyStore
	defaultBackend string              // default backend to use
	mu             sync.RWMutex
}

// FacadeConfig configures the keychain facade
type FacadeConfig struct {
	// Backends is a map of backend name to KeyStore
	Backends map[string]KeyStore

	// DefaultBackend is the name of the default backend to use
	// when no backend is specified in the key ID
	DefaultBackend string
}

// Initialize sets up the keychain facade
// This should be called once at application startup
func Initialize(config *FacadeConfig) error {
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

		facade = &KeychainFacade{
			backends:       config.Backends,
			defaultBackend: defaultBackend,
		}
	})

	return initErr
}

// Reset clears the facade (useful for testing)
func Reset() {
	initMu.Lock()
	defer initMu.Unlock()

	if facade != nil {
		facade.mu.Lock()
		for _, ks := range facade.backends {
			_ = ks.Close()
		}
		facade.backends = nil
		facade.mu.Unlock()
	}

	facade = nil
	initOnce = sync.Once{}
}

// IsInitialized returns whether the facade has been initialized
func IsInitialized() bool {
	initMu.RLock()
	defer initMu.RUnlock()
	return facade != nil
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

	facade.mu.RLock()
	defer facade.mu.RUnlock()

	ks, ok := facade.backends[name]
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

	facade.mu.RLock()
	defer facade.mu.RUnlock()

	if facade.defaultBackend == "" {
		return nil, ErrNoDefaultBackend
	}

	ks, ok := facade.backends[facade.defaultBackend]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, facade.defaultBackend)
	}

	return ks, nil
}

// Backends returns the names of all registered backends
func Backends() []string {
	if !IsInitialized() {
		return nil
	}

	facade.mu.RLock()
	defer facade.mu.RUnlock()

	backends := make([]string, 0, len(facade.backends))
	for name := range facade.backends {
		backends = append(backends, name)
	}

	return backends
}

// parseKeyReference parses a key reference in the format:
// - "backend:key-id" - use specific backend
// - "key-id" - use default backend
func parseKeyReference(keyRef string) (backend, keyID string) {
	// Split on first colon only
	parts := strings.SplitN(keyRef, ":", 2)
	if len(parts) == 2 {
		// Format: "backend:key-id"
		return parts[0], parts[1]
	}
	// Format: "key-id" (use default backend)
	return "", keyRef
}

// getKeystoreForKey determines which keystore to use for a given key reference
func getKeystoreForKey(keyRef string) (KeyStore, string, error) {
	if !IsInitialized() {
		return nil, "", ErrNotInitialized
	}

	backend, keyID := parseKeyReference(keyRef)

	var ks KeyStore
	var err error

	if backend == "" {
		// Use default backend
		ks, err = DefaultBackend()
	} else {
		// Use specified backend
		ks, err = Backend(backend)
	}

	if err != nil {
		return nil, "", err
	}

	return ks, keyID, nil
}

// Simplified API - applications use these functions directly

// GenerateKey generates a new key with the given attributes
func GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks, err := DefaultBackend()
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

// Key retrieves a key by its attributes
func Key(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks, err := DefaultBackend()
	if err != nil {
		return nil, err
	}

	return ks.GetKey(attrs)
}

// KeyByID retrieves a key by its ID
// Supports format: "backend:key-id" or just "key-id" (uses default backend)
func KeyByID(keyRef string) (crypto.PrivateKey, error) {
	// Validate key reference to prevent injection attacks
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	return ks.GetKeyByID(keyID)
}

// Signer returns a signer for the specified key
func Signer(keyRef string) (crypto.Signer, error) {
	// Validate key reference to prevent injection attacks
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	return ks.GetSignerByID(keyID)
}

// Decrypter returns a decrypter for the specified key
func Decrypter(keyRef string) (crypto.Decrypter, error) {
	// Validate key reference to prevent injection attacks
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	return ks.GetDecrypterByID(keyID)
}

// DeleteKey deletes a key by its ID
func DeleteKey(keyRef string) error {
	// Validate key reference to prevent injection attacks
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return err
	}

	// Look up full key attributes from the backend
	keys, err := ks.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
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

	facade.mu.RLock()
	defer facade.mu.RUnlock()

	var allKeys []*types.KeyAttributes

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		ks, ok := facade.backends[backendName[0]]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, validation.SanitizeForLog(backendName[0]))
		}

		return ks.ListKeys()
	}

	// List from all backends
	for _, ks := range facade.backends {
		keys, err := ks.ListKeys()
		if err != nil {
			// Log error but continue with other backends
			continue
		}
		allKeys = append(allKeys, keys...)
	}

	return allKeys, nil
}

// SaveCertificate saves a certificate
func SaveCertificate(keyID string, cert *x509.Certificate) error {
	// Validate key ID to prevent injection attacks
	if err := validation.ValidateKeyReference(keyID); err != nil {
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, parsedKeyID, err := getKeystoreForKey(keyID)
	if err != nil {
		return err
	}

	return ks.SaveCert(parsedKeyID, cert)
}

// Certificate retrieves a certificate
func Certificate(keyID string) (*x509.Certificate, error) {
	// Validate key ID to prevent injection attacks
	if err := validation.ValidateKeyReference(keyID); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, parsedKeyID, err := getKeystoreForKey(keyID)
	if err != nil {
		return nil, err
	}

	return ks.GetCert(parsedKeyID)
}

// DeleteCertificate deletes a certificate
func DeleteCertificate(keyID string) error {
	// Validate key ID to prevent injection attacks
	if err := validation.ValidateKeyReference(keyID); err != nil {
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, parsedKeyID, err := getKeystoreForKey(keyID)
	if err != nil {
		return err
	}

	return ks.DeleteCert(parsedKeyID)
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

	facade.mu.RLock()
	defer facade.mu.RUnlock()

	var allCerts []string

	if len(backendName) > 0 && backendName[0] != "" {
		// List from specific backend
		ks, ok := facade.backends[backendName[0]]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, validation.SanitizeForLog(backendName[0]))
		}

		return ks.ListCerts()
	}

	// List from all backends
	for _, ks := range facade.backends {
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

	facade.mu.Lock()
	defer facade.mu.Unlock()

	var errs []error
	for name, ks := range facade.backends {
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
	facade.mu.RLock()
	defer facade.mu.RUnlock()

	for _, ks := range facade.backends {
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
// The keyRef supports format: "backend:key-id" or just "key-id" (uses default backend).
func RotateKey(keyRef string) (crypto.PrivateKey, error) {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
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
// The keyRef supports format: "backend:key-id" or just "key-id" (uses default backend).
func Sign(keyRef string, data []byte, opts *SignOptions) ([]byte, error) {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
	}

	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer: %w", err)
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
// The keyRef supports format: "backend:key-id" or just "key-id" (uses default backend).
func Verify(keyRef string, data, signature []byte, opts *types.VerifyOpts) error {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return err
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
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
// The keyRef supports format: "backend:key-id" or just "key-id" (uses default backend).
func Encrypt(keyRef string, data []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
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
// The keyRef supports format: "backend:key-id" or just "key-id" (uses default backend).
func Decrypt(keyRef string, data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
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
// Certificate Chain Operations
// ========================================================================

// SaveCertificateChain saves a certificate chain for the given key ID.
func SaveCertificateChain(keyID string, chain []*x509.Certificate) error {
	if err := validation.ValidateKeyReference(keyID); err != nil {
		return fmt.Errorf("invalid key ID: %w", err)
	}

	ks, parsedKeyID, err := getKeystoreForKey(keyID)
	if err != nil {
		return err
	}

	return ks.SaveCertChain(parsedKeyID, chain)
}

// CertificateChain retrieves a certificate chain by key ID.
func CertificateChain(keyID string) ([]*x509.Certificate, error) {
	if err := validation.ValidateKeyReference(keyID); err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, parsedKeyID, err := getKeystoreForKey(keyID)
	if err != nil {
		return nil, err
	}

	return ks.GetCertChain(parsedKeyID)
}

// CertificateExists checks if a certificate exists for the given key ID.
func CertificateExists(keyID string) (bool, error) {
	if err := validation.ValidateKeyReference(keyID); err != nil {
		return false, fmt.Errorf("invalid key ID: %w", err)
	}

	ks, parsedKeyID, err := getKeystoreForKey(keyID)
	if err != nil {
		return false, err
	}

	return ks.CertExists(parsedKeyID)
}

// ========================================================================
// TLS Operations
// ========================================================================

// GetTLSCertificate returns a complete tls.Certificate ready for use.
func GetTLSCertificate(keyRef string) (tls.Certificate, error) {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return tls.Certificate{}, err
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return tls.Certificate{}, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
	}

	return ks.GetTLSCertificate(keyID, attrs)
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
func ExportKey(keyRef string, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import/export operations")
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
	}

	return importExportBackend.ExportKey(attrs, algorithm)
}

// ========================================================================
// Cross-Backend Operations
// ========================================================================

// CopyKey copies a key from one backend to another.
func CopyKey(sourceKeyRef string, destBackend string, destAttrs *types.KeyAttributes) error {
	if err := validation.ValidateKeyReference(sourceKeyRef); err != nil {
		return fmt.Errorf("invalid source key reference: %w", err)
	}

	if err := validation.ValidateBackendName(destBackend); err != nil {
		return fmt.Errorf("invalid destination backend name: %w", err)
	}

	sourceKs, sourceKeyID, err := getKeystoreForKey(sourceKeyRef)
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

	keys, err := sourceKs.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list source keys: %w", err)
	}

	var sourceAttrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == sourceKeyID {
			sourceAttrs = k
			break
		}
	}

	if sourceAttrs == nil {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, sourceKeyID)
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
func GetSymmetricKey(keyRef string) (types.SymmetricKey, error) {
	if err := validation.ValidateKeyReference(keyRef); err != nil {
		return nil, fmt.Errorf("invalid key reference: %w", err)
	}

	ks, keyID, err := getKeystoreForKey(keyRef)
	if err != nil {
		return nil, err
	}

	keys, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var attrs *types.KeyAttributes
	for _, k := range keys {
		if k.CN == keyID {
			attrs = k
			break
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
	}

	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support symmetric key operations")
	}

	return symBackend.GetSymmetricKey(attrs)
}
