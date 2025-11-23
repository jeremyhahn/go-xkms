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
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"

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

	// Convert keyID back to attributes
	// TODO: Implement proper key ID to attributes conversion
	attrs := &types.KeyAttributes{
		CN: keyID,
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
