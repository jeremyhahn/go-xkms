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

//go:build pkcs11

// Package pkcs11 provides a hardware-backed keystore implementation using PKCS#11.
//
// This package implements the keychain.KeyStore interface for managing cryptographic
// keys in PKCS#11 hardware security modules (HSMs) and smart cards. Private keys
// never leave the HSM hardware, providing enhanced security for cryptographic operations.
//
// Key Features:
//   - Hardware-based key generation (RSA 2048-4096 bits, ECDSA P-256/P-384/P-521)
//   - Private keys never leave HSM
//   - Support for signing and decryption operations
//   - Thread-safe operations using mutex synchronization
//   - Context caching for efficient multi-instance usage
//   - SoftHSM support for development and testing
//
// Unsupported Features:
//   - Ed25519 keys (not supported by most PKCS#11 implementations)
//   - Direct private key export (by design - HSM security)
//
// Example Usage:
//
//	backend, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
//	    CN:         "my-keystore",
//	    Library:    "/usr/lib/softhsm/libsofthsm2.so",
//	    TokenLabel: "my-token",
//	    PIN:        "123456",
//	    SOPIN:      "12345678",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	err = backend.Login()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ks, err := NewKeyStore(backend)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer ks.Close()
//
//	attrs := &types.KeyAttributes{
//	    CN: "my-hsm-key",
//	    KeyAlgorithm: x509.RSA,
//	    KeyType: keychain.KeyTypeSigning,
//	    StoreType: keychain.StorePKCS11,
//	    RSAAttributes: &types.RSAAttributes{KeySize: 2048},
//	}
//	key, err := ks.GenerateRSA(attrs)
package pkcs11

import (
	"crypto"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	pkcs11backend "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyStore implements the keychain.KeyStore interface for PKCS#11 hardware security modules.
// It provides secure key management with private keys that never leave the HSM hardware.
type KeyStore struct {
	backend     *pkcs11backend.Backend
	certStorage *storage.CertAdapter
	mu          sync.RWMutex
	closed      bool
}

// NewKeyStore creates a new PKCS#11 keystore instance.
//
// The keystore wraps a PKCS#11 backend and provides high-level key management
// operations that leverage HSM security. The backend must be properly initialized
// and logged in before use.
//
// Parameters:
//   - backend: PKCS#11 backend that has been initialized and logged in
//   - certStorage: Certificate storage backend for managing certificates
//
// Returns a new KeyStore instance or an error if the backend is invalid.
func NewKeyStore(backend *pkcs11backend.Backend, certStorage storage.Backend) (keychain.KeyStore, error) {
	if backend == nil {
		return nil, keychain.ErrBackendNotInitialized
	}
	if certStorage == nil {
		return nil, keychain.ErrCertStorageRequired
	}

	// Wrap the certificate storage backend with an adapter that provides
	// certificate-specific operations (SaveCert, GetCert, etc.)
	certAdapter := storage.NewCertAdapter(certStorage)

	return &KeyStore{
		backend:     backend,
		certStorage: certAdapter,
	}, nil
}

// Backend returns the underlying storage backend.
func (ks *KeyStore) Backend() types.Backend {
	// Convert pkcs11backend.Backend to types.Backend wrapper
	return &backendWrapper{backend: ks.backend}
}

// Type returns the store type identifier.
func (ks *KeyStore) Type() types.StoreType {
	return types.StorePKCS11
}

// Initialize prepares the PKCS#11 token for use.
//
// For PKCS#11 tokens, this sets up the SO and user PINs and initializes
// the token. This operation is typically performed once during initial setup.
//
// Parameters:
//   - soPIN: Security Officer PIN for administrative operations
//   - userPIN: User PIN for normal operations
//
// Returns ErrAlreadyInitialized if the token is already initialized.
func (ks *KeyStore) Initialize(soPIN, userPIN types.Password) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	soPINStr, err := soPIN.String()
	if err != nil {
		return fmt.Errorf("failed to get SO PIN: %w", err)
	}

	userPINStr, err := userPIN.String()
	if err != nil {
		return fmt.Errorf("failed to get user PIN: %w", err)
	}

	return ks.backend.Initialize(soPINStr, userPINStr)
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
//
// This method delegates to the appropriate algorithm-specific generation
// method (GenerateRSA, GenerateECDSA, or GenerateEd25519) based on the
// KeyAlgorithm field in the attributes.
//
// Parameters:
//   - attrs: Key configuration including algorithm and parameters
//
// Returns an OpaqueKey wrapping the generated key, or an error if the
// algorithm is unsupported or generation fails.
func (ks *KeyStore) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		// Ed25519 is not supported by most PKCS#11 implementations
		return nil, pkcs11backend.ErrUnsupportedKeyAlgorithm
	default:
		return nil, keychain.ErrInvalidKeyAlgorithm
	}
}

// GenerateRSA generates a new RSA key pair on the HSM.
//
// The key size is specified in attrs.RSAAttributes.KeySize. If not specified
// or less than 512 bits, a default size of 2048 bits is used. Common sizes
// are 2048, 3072, and 4096 bits.
//
// The private key is generated on the HSM and never leaves the hardware.
// Only the public key is accessible outside the HSM.
//
// Parameters:
//   - attrs: Key configuration including RSA key size
//
// Returns an OpaqueKey for the generated RSA key, or an error if generation fails.
func (ks *KeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Apply default key size if not specified
	if attrs.RSAAttributes == nil {
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: 2048,
		}
	}
	if attrs.RSAAttributes.KeySize == 0 || attrs.RSAAttributes.KeySize < 512 {
		attrs.RSAAttributes.KeySize = 2048
	}

	// Generate the RSA key pair on the HSM with the specified key size
	signer, err := ks.backend.GenerateRSAWithSize(attrs, attrs.RSAAttributes.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key on HSM: %w", err)
	}

	// Extract the public key from the signer
	publicKey := signer.Public()

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, publicKey)
}

// GenerateECDSA generates a new ECDSA key pair on the HSM.
//
// The elliptic curve is specified in attrs.ECCAttributes.Curve. If not specified,
// P-256 is used as the default. Common curves include P-256, P-384, and P-521.
//
// The private key is generated on the HSM and never leaves the hardware.
// Only the public key is accessible outside the HSM.
//
// Parameters:
//   - attrs: Key configuration including ECC curve
//
// Returns an OpaqueKey for the generated ECDSA key, or an error if generation fails.
func (ks *KeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Apply default curve if not specified
	var curve elliptic.Curve
	if attrs.ECCAttributes == nil || attrs.ECCAttributes.Curve == nil {
		curve = elliptic.P256()
	} else {
		curve = attrs.ECCAttributes.Curve
	}

	// Generate the ECDSA key pair on the HSM with the specified curve
	signer, err := ks.backend.GenerateECDSAWithCurve(attrs, curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key on HSM: %w", err)
	}

	// Extract the public key from the signer
	publicKey := signer.Public()

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, publicKey)
}

// GenerateEd25519 generates a new Ed25519 key pair.
//
// Ed25519 keys are not supported by most PKCS#11 implementations.
// This method always returns ErrUnsupportedKeyAlgorithm.
//
// Parameters:
//   - attrs: Key configuration
//
// Returns ErrUnsupportedKeyAlgorithm as Ed25519 is not supported by PKCS#11.
func (ks *KeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Ed25519 is not supported by most PKCS#11 implementations
	return nil, pkcs11backend.ErrUnsupportedKeyAlgorithm
}

// GenerateSecretKey generates a new secret key for symmetric operations on the HSM.
//
// This method supports AES key generation for KeyTypeSecret and KeyTypeHMAC key types.
// The secret key is generated on the HSM and never leaves the hardware.
//
// Supported key sizes:
//   - AES-128: 128 bits (16 bytes)
//   - AES-256: 256 bits (32 bytes)
//
// Currently defaults to AES-256 (256 bits).
//
// Parameters:
//   - attrs: Key attributes specifying KeyTypeHMAC or KeyTypeSecret
//
// Returns an error if the key type is not supported or generation fails.
func (ks *KeyStore) GenerateSecretKey(attrs *types.KeyAttributes) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Validate key type
	if attrs.KeyType != backend.KEY_TYPE_ENCRYPTION && attrs.KeyType != backend.KEY_TYPE_SIGNING {
		return fmt.Errorf("unsupported key type for secret key generation: %s (only KeyTypeSecret and KeyTypeHMAC are supported)", attrs.KeyType)
	}

	// Default to AES-256
	keySize := 256

	// Generate the secret key on the HSM
	_, err := ks.backend.GenerateSecretKey(attrs, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate secret key on HSM: %w", err)
	}

	return nil
}

// RotateKey atomically replaces an existing key with a newly generated key.
//
// This method deletes the existing key from the HSM and generates a new one
// with the same attributes. If any step fails, an error is returned.
//
// Note: If deletion succeeds but generation fails, the key will be in a
// deleted state. HSM key rotation should be performed carefully.
//
// Parameters:
//   - attrs: Key attributes identifying the key to rotate
//
// Returns an OpaqueKey for the new key, or an error if rotation fails.
func (ks *KeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Verify the key exists before attempting rotation
	_, err := ks.Find(attrs)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: cannot rotate key that doesn't exist: %w", err)
	}

	// Delete the existing key
	if err := ks.Delete(attrs); err != nil {
		return nil, fmt.Errorf("pkcs11: failed to delete existing key during rotation: %w", err)
	}

	// Generate new key with same attributes
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		return nil, pkcs11backend.ErrUnsupportedKeyAlgorithm
	default:
		return nil, keychain.ErrInvalidKeyAlgorithm
	}
}

// Equal compares an opaque key with a native private key for equality.
//
// For HSM-backed keys, we can only compare the public key portions since
// the private key never leaves the HSM. This method extracts public keys
// from both parameters and performs a deep comparison.
//
// Parameters:
//   - opaque: The opaque key from the HSM
//   - x: The private key to compare against
//
// Returns true if the public keys match, indicating the same key pair.
func (ks *KeyStore) Equal(opaqueKey crypto.PrivateKey, x crypto.PrivateKey) bool {
	// Check if the key implements the opaque.OpaqueKey interface
	opaqueImpl, ok := opaqueKey.(opaque.OpaqueKey)
	if !ok {
		return false
	}
	return keychain.CompareOpaqueKeyEquality(opaqueImpl, x)
}

// Signer returns a crypto.Signer for the specified key.
//
// The returned signer delegates signing operations to the HSM without
// exposing the private key material. The signing operation is performed
// entirely within the HSM hardware.
//
// Parameters:
//   - attrs: Key attributes identifying the signing key
//
// Returns a crypto.Signer, or an error if the key doesn't exist or
// cannot be loaded.
func (ks *KeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Get the signer from the backend
	signer, err := ks.backend.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer from HSM: %w", err)
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the specified key.
//
// The returned decrypter delegates decryption operations to the HSM without
// exposing the private key material. The decryption operation is performed
// entirely within the HSM hardware.
//
// Currently only RSA keys support decryption. ECDSA keys do not support
// encryption/decryption operations.
//
// Parameters:
//   - attrs: Key attributes identifying the decryption key
//
// Returns a crypto.Decrypter, or an error if the key doesn't exist,
// cannot be loaded, or doesn't support decryption.
func (ks *KeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Get the signer (which may also be a decrypter)
	signer, err := ks.backend.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key from HSM: %w", err)
	}

	// Check if the signer also implements crypto.Decrypter
	decrypter, ok := signer.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("key type %s does not support decryption", attrs.KeyAlgorithm)
	}

	return decrypter, nil
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
		StoreType: backend.STORE_PKCS11,
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
		StoreType: backend.STORE_PKCS11,
	}
	return ks.Signer(attrs)
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
//
// This method takes a key identifier (CN) and returns a crypto.Decrypter
// for decryption operations. Only RSA keys support decryption.
//
// Parameters:
//   - keyID: The key identifier (Common Name)
//
// Returns a crypto.Decrypter or an error if the key doesn't exist or doesn't support decryption.
func (ks *KeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_PKCS11,
	}
	return ks.Decrypter(attrs)
}

// Find locates an existing key on the HSM without fully loading it.
//
// This method checks if a key exists on the HSM by attempting to find it
// by its identifier (Common Name). It's more efficient than loading the
// full key when you only need to verify existence.
//
// Parameters:
//   - attrs: Key attributes identifying the key
//
// Returns an OpaqueKey if found, or an error if the key doesn't exist.
func (ks *KeyStore) Find(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Try to find the key on the HSM
	signer, err := ks.backend.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("key not found on HSM: %w", err)
	}

	// Extract the public key
	publicKey := signer.Public()

	return opaque.NewOpaqueKey(ks, attrs, publicKey)
}

// GetKey retrieves an existing key.
//
// This is an alias for Key() to satisfy the keychain.KeyStore interface.
func (ks *KeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return ks.Key(attrs)
}

// DeleteKey removes a key.
//
// This is an alias for Delete() to satisfy the keychain.KeyStore interface.
func (ks *KeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	return ks.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this keystore.
func (ks *KeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	// Listing would require additional backend support
	return []*types.KeyAttributes{}, nil
}

// Key retrieves an existing key from the HSM.
//
// This method finds the key on the HSM by its identifier and returns an
// OpaqueKey that can be used for cryptographic operations. The private key
// material remains on the HSM and is never exposed.
//
// Parameters:
//   - attrs: Key attributes identifying the key
//
// Returns an OpaqueKey for the requested key, or an error if the key
// doesn't exist or cannot be loaded.
func (ks *KeyStore) Key(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return ks.Find(attrs)
}

// Delete removes a key from the HSM.
//
// This operation deletes both the private and public key objects from the
// HSM token. The operation is typically irreversible.
//
// Note: Some HSMs may not support key deletion or may require special
// permissions. The behavior depends on the specific HSM and its configuration.
//
// Parameters:
//   - attrs: Key attributes identifying the key to delete
//
// Returns an error if the key doesn't exist or deletion fails.
func (ks *KeyStore) Delete(attrs *types.KeyAttributes) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	return ks.backend.Delete(attrs)
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

// GetTLSCertificate returns a complete tls.Certificate ready for use.
// This combines the private key from the backend with the certificate
// from storage into a single tls.Certificate structure.
func (ks *KeyStore) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	// Get the private key (opaque key)
	key, err := ks.GetKey(attrs)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to get key: %w", err)
	}

	// Get the certificate
	cert, err := ks.GetCert(keyID)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Get the certificate chain if available
	chain, err := ks.GetCertChain(keyID)
	if err != nil && err != keychain.ErrCertNotFound {
		return tls.Certificate{}, fmt.Errorf("failed to get certificate chain: %w", err)
	}

	// Build the tls.Certificate
	tlsCert := tls.Certificate{
		PrivateKey: key,
	}

	// Add leaf certificate
	tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)

	// Add chain certificates if available
	for _, chainCert := range chain {
		tlsCert.Certificate = append(tlsCert.Certificate, chainCert.Raw)
	}

	// Parse the leaf certificate for the tls package
	tlsCert.Leaf = cert

	return tlsCert, nil
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

// CertStorage returns the certificate storage backend.
func (ks *KeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return ks.certStorage
}

// backendWrapper wraps pkcs11backend.Backend to implement types.Backend interface.
// It does not own the backend lifecycle - the keychain is responsible for closing
// the backend when appropriate.
type backendWrapper struct {
	backend *pkcs11backend.Backend
}

// Type returns the backend type identifier.
func (bw *backendWrapper) Type() types.BackendType {
	return backend.BackendTypePKCS11
}

// Capabilities returns what features this backend supports.
func (bw *backendWrapper) Capabilities() types.Capabilities {
	return types.NewHardwareCapabilities()
}

// GenerateKey generates a new private key with the given attributes.
func (bw *backendWrapper) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// PKCS#11 doesn't return private keys - they stay on the HSM
	// Use the keystore GenerateKey method instead
	return nil, fmt.Errorf("pkcs11: GenerateKey not supported on backend wrapper, use KeyStore.GenerateKey instead")
}

// GetKey retrieves an existing private key by its attributes.
func (bw *backendWrapper) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// PKCS#11 doesn't export private keys
	return nil, fmt.Errorf("pkcs11: GetKey not supported on backend wrapper, use KeyStore.GetKey instead")
}

// DeleteKey removes a key identified by its attributes.
func (bw *backendWrapper) DeleteKey(attrs *types.KeyAttributes) error {
	return bw.backend.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (bw *backendWrapper) ListKeys() ([]*types.KeyAttributes, error) {
	// PKCS#11 listing would require additional backend support
	return []*types.KeyAttributes{}, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (bw *backendWrapper) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return bw.backend.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (bw *backendWrapper) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	// Get the signer (which may also be a decrypter for RSA keys)
	signer, err := bw.backend.Signer(attrs)
	if err != nil {
		return nil, err
	}

	// Check if the signer also implements crypto.Decrypter
	decrypter, ok := signer.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("pkcs11: key type %s does not support decryption", attrs.KeyAlgorithm)
	}

	return decrypter, nil
}

// RotateKey rotates the key identified by attrs, creating a new version.
func (bw *backendWrapper) RotateKey(attrs *types.KeyAttributes) error {
	return bw.backend.RotateKey(attrs)
}

// Close is a no-op for the backend wrapper.
// The wrapper does not own the backend lifecycle - the keychain that created
// this wrapper is responsible for closing the backend when the keychain itself
// is closed. This prevents premature closure of shared contexts that may be
// cached and used by multiple keystore instances.
func (bw *backendWrapper) Close() error {
	// Do not close the backend - the keychain owns the backend lifecycle
	return nil
}
