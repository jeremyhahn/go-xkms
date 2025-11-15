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

//go:build vault

// Package vault provides a cloud-backed keystore implementation using HashiCorp Vault Transit.
//
// This package implements the keychain.KeyStore interface for managing cryptographic
// keys in HashiCorp Vault's Transit secrets engine. Private keys never leave Vault,
// providing enhanced security for cryptographic operations.
//
// Key Features:
//   - Cloud-based key generation (RSA 2048-4096 bits, ECDSA P-256/P-384/P-521, Ed25519)
//   - Private keys never leave Vault
//   - Support for signing operations
//   - Support for encryption/decryption operations
//   - Thread-safe operations using mutex synchronization
//   - Key versioning and rotation
//
// Example Usage:
//
//	config := &vault.Config{
//	    Address:     "http://127.0.0.1:8200",
//	    Token:       "root",
//	    TransitPath: "transit",
//	}
//	backend, err := vault.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	ks, err := NewKeyStore(backend, certStorage)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer ks.Close()
//
//	attrs := &types.KeyAttributes{
//	    CN:           "my-vault-key",
//	    KeyAlgorithm: x509.ECDSA,
//	    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
//	}
//	key, err := ks.GenerateECDSA(attrs)
package vault

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	vaultbackend "github.com/jeremyhahn/go-keychain/pkg/backend/vault"
	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyStore implements the keychain.KeyStore interface for HashiCorp Vault.
// It provides secure key management with private keys that never leave Vault.
type KeyStore struct {
	backend     *vaultbackend.Backend
	certStorage certstore.CertificateStorageAdapter
	mu          sync.RWMutex
	closed      bool
}

// NewKeyStore creates a new Vault keystore instance.
//
// The keystore wraps a Vault backend and provides high-level key management
// operations that leverage Vault Transit engine security.
//
// Parameters:
//   - backend: Vault backend that has been initialized with configuration
//   - certStorage: Certificate storage backend for managing certificates
//
// Returns a new KeyStore instance or an error if the backend is invalid.
func NewKeyStore(backend *vaultbackend.Backend, certStorage certstore.CertificateStorageAdapter) (keychain.KeyStore, error) {
	if backend == nil {
		return nil, keychain.ErrBackendNotInitialized
	}
	if certStorage == nil {
		return nil, keychain.ErrCertStorageRequired
	}

	return &KeyStore{
		backend:     backend,
		certStorage: certStorage,
	}, nil
}

// Backend returns the underlying storage backend.
func (ks *KeyStore) Backend() types.Backend {
	return &backendWrapper{backend: ks.backend}
}

// Type returns the store type identifier.
func (ks *KeyStore) Type() types.StoreType {
	return types.StoreTPM2
}

// Initialize prepares the Vault keystore for use.
//
// For Vault, this is a no-op as initialization happens at the backend level
// with Vault tokens. This method is included to satisfy the KeyStore interface.
//
// Parameters:
//   - soPIN: Not used for Vault
//   - userPIN: Not used for Vault
//
// Returns nil as Vault does not require separate initialization.
func (ks *KeyStore) Initialize(soPIN, userPIN types.Password) error {
	// Vault does not require initialization like PKCS#11 tokens
	// Authentication is handled through Vault tokens
	return nil
}

// Close releases resources held by the keychain.
//
// This method closes the backend and performs any necessary cleanup.
// After calling Close, the keychain should not be used.
func (ks *KeyStore) Close() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return keychain.ErrStorageClosed
	}

	ks.closed = true
	return ks.backend.Close()
}

// GenerateKey generates a new key based on the provided attributes.
func (ks *KeyStore) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.backend.GenerateKey(attrs)
}

// GenerateRSA generates a new RSA key pair with the specified attributes.
func (ks *KeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs.KeyAlgorithm == 0 {
		attrs.KeyAlgorithm = x509.RSA
	}

	key, err := ks.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, key)
}

// GenerateECDSA generates a new ECDSA key pair with the specified attributes.
func (ks *KeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs.KeyAlgorithm == 0 {
		attrs.KeyAlgorithm = x509.ECDSA
	}

	key, err := ks.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, key)
}

// GenerateEd25519 generates a new Ed25519 key pair with the specified attributes.
func (ks *KeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs.KeyAlgorithm == 0 {
		attrs.KeyAlgorithm = x509.Ed25519
	}

	key, err := ks.GenerateKey(attrs)
	if err != nil {
		return nil, err
	}

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, key)
}

// GetKey retrieves a key by its attributes.
func (ks *KeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.backend.GetKey(attrs)
}

// GetRSAKey retrieves an RSA key by its attributes.
func (ks *KeyStore) GetRSAKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := ks.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, key)
}

// GetECDSAKey retrieves an ECDSA key by its attributes.
func (ks *KeyStore) GetECDSAKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := ks.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, key)
}

// GetEd25519Key retrieves an Ed25519 key by its attributes.
func (ks *KeyStore) GetEd25519Key(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := ks.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, key)
}

// DeleteKey removes a key identified by its attributes.
func (ks *KeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return keychain.ErrStorageClosed
	}

	return ks.backend.DeleteKey(attrs)
}

// ListKeys returns all key attributes managed by this keystore.
func (ks *KeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.backend.ListKeys()
}

// RotateKey rotates a key by creating a new version in Vault.
func (ks *KeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	// Rotate the key in Vault (creates new version)
	if err := ks.backend.RotateKey(attrs); err != nil {
		return nil, err
	}

	// Get the new key
	return ks.backend.GetKey(attrs)
}

// KeyExists checks if a key with the given attributes exists.
func (ks *KeyStore) KeyExists(attrs *types.KeyAttributes) (bool, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return false, keychain.ErrStorageClosed
	}

	_, err := ks.backend.GetKey(attrs)
	if err != nil {
		if err == vaultbackend.ErrKeyNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Signer returns a crypto.Signer for the specified key.
func (ks *KeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.backend.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the specified key.
func (ks *KeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.backend.Decrypter(attrs)
}

// GetKeyByID retrieves a key by its identifier.
//
// This method takes a key identifier (CN) and returns the key.
//
// Parameters:
//   - keyID: The key identifier (Common Name)
//
// Returns a crypto.PrivateKey or an error if the key doesn't exist.
func (ks *KeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		StoreType: backend.STORE_VAULT,
	}
	return ks.GetKey(attrs)
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
//
// This method takes a key identifier (CN) and returns a crypto.Signer
// for signing operations.
//
// Parameters:
//   - keyID: The key identifier (Common Name)
//
// Returns a crypto.Signer or an error if the key doesn't exist.
func (ks *KeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_VAULT,
	}
	return ks.Signer(attrs)
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
//
// This method takes a key identifier (CN) and returns a crypto.Decrypter
// for decryption operations.
//
// Parameters:
//   - keyID: The key identifier (Common Name)
//
// Returns a crypto.Decrypter or an error if the key doesn't exist.
func (ks *KeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_VAULT,
	}
	return ks.Decrypter(attrs)
}

// GetTLSCertificate returns a tls.Certificate for the specified key and certificate.
func (ks *KeyStore) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	return ks.TLSCertificate(attrs)
}

// TLSCertificate returns a tls.Certificate for the specified key and certificate.
func (ks *KeyStore) TLSCertificate(attrs *types.KeyAttributes) (tls.Certificate, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return tls.Certificate{}, keychain.ErrStorageClosed
	}

	// Get certificate
	cert, err := ks.certStorage.GetCert(attrs.CN)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Get certificate chain
	chain, err := ks.certStorage.GetCertChain(attrs.CN)
	if err != nil && err != storage.ErrNotFound {
		return tls.Certificate{}, fmt.Errorf("failed to get certificate chain: %w", err)
	}

	// Build tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
	}

	// Add chain certificates
	for _, chainCert := range chain {
		tlsCert.Certificate = append(tlsCert.Certificate, chainCert.Raw)
	}

	// Get signer (private key operations)
	signer, err := ks.backend.Signer(attrs)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to get signer: %w", err)
	}

	tlsCert.PrivateKey = signer
	tlsCert.Leaf = cert

	return tlsCert, nil
}

// CertStorage returns the certificate storage backend.
func (ks *KeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return ks.certStorage
}

// SaveCert stores a certificate for the given key ID.
func (ks *KeyStore) SaveCert(keyID string, cert *x509.Certificate) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return keychain.ErrStorageClosed
	}

	return ks.certStorage.SaveCert(keyID, cert)
}

// GetCert retrieves a certificate by key ID.
func (ks *KeyStore) GetCert(keyID string) (*x509.Certificate, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.certStorage.GetCert(keyID)
}

// DeleteCert removes a certificate by key ID.
func (ks *KeyStore) DeleteCert(keyID string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return keychain.ErrStorageClosed
	}

	return ks.certStorage.DeleteCert(keyID)
}

// SaveCertChain stores a certificate chain for the given key ID.
func (ks *KeyStore) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return keychain.ErrStorageClosed
	}

	return ks.certStorage.SaveCertChain(keyID, chain)
}

// GetCertChain retrieves a certificate chain by key ID.
func (ks *KeyStore) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.certStorage.GetCertChain(keyID)
}

// ListCerts returns all certificate IDs currently stored.
func (ks *KeyStore) ListCerts() ([]string, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	return ks.certStorage.ListCerts()
}

// CertExists checks if a certificate exists for the given key ID.
func (ks *KeyStore) CertExists(keyID string) (bool, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return false, keychain.ErrStorageClosed
	}

	return ks.certStorage.CertExists(keyID)
}

// backendWrapper wraps vaultbackend.Backend to implement types.Backend interface.
type backendWrapper struct {
	backend *vaultbackend.Backend
}

// Type returns the backend type identifier.
func (bw *backendWrapper) Type() types.BackendType {
	return backend.BackendTypeVault
}

// Capabilities returns what features this backend supports.
func (bw *backendWrapper) Capabilities() types.Capabilities {
	return bw.backend.Capabilities()
}

// GenerateKey generates a new private key with the given attributes.
func (bw *backendWrapper) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return bw.backend.GenerateKey(attrs)
}

// GetKey retrieves an existing private key by its attributes.
func (bw *backendWrapper) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return bw.backend.GetKey(attrs)
}

// DeleteKey removes a key identified by its attributes.
func (bw *backendWrapper) DeleteKey(attrs *types.KeyAttributes) error {
	return bw.backend.DeleteKey(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (bw *backendWrapper) ListKeys() ([]*types.KeyAttributes, error) {
	return bw.backend.ListKeys()
}

// Signer returns a crypto.Signer for the given key.
func (bw *backendWrapper) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return bw.backend.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the given key.
func (bw *backendWrapper) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return bw.backend.Decrypter(attrs)
}

// RotateKey rotates the key identified by attrs, creating a new version.
func (bw *backendWrapper) RotateKey(attrs *types.KeyAttributes) error {
	return bw.backend.RotateKey(attrs)
}

// Close releases any resources held by the backend.
func (bw *backendWrapper) Close() error {
	return bw.backend.Close()
}
