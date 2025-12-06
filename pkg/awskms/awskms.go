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

//go:build awskms

// Package awskms provides a cloud-backed keystore implementation using AWS KMS.
//
// This package implements the keychain.KeyStore interface for managing cryptographic
// keys in AWS Key Management Service (KMS). Private keys never leave AWS KMS,
// providing enhanced security for cryptographic operations.
//
// Key Features:
//   - Cloud-based key generation (RSA 2048-4096 bits, ECDSA P-256/P-384/P-521)
//   - Symmetric key generation (AES-256-GCM)
//   - Private keys never leave AWS KMS
//   - Support for signing operations
//   - Support for symmetric encryption keys
//   - Thread-safe operations using mutex synchronization
//   - Support for IAM role-based authentication
//   - LocalStack support for development and testing
//
// Unsupported Features:
//   - Ed25519 keys (not supported by AWS KMS)
//   - Decryption operations (requires different key usage type)
//
// Example Usage:
//
//	config := &awskms.Config{
//	    Region:          "us-east-1",
//	    AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
//	    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//	}
//	backend, err := awskms.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	ks, err := NewKeyStore(backend)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer ks.Close()
//
//	attrs := &types.KeyAttributes{
//	    CN:           "my-kms-key",
//	    KeyAlgorithm: x509.RSA,
//	    KeyType:      keychain.KeyTypeSigning,
//	    StoreType:    keychain.StorePKCS11,
//	    RSAAttributes: &types.RSAAttributes{KeySize: 2048},
//	}
//	key, err := ks.GenerateRSA(attrs)
package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	awskmsbackend "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyStore implements the keychain.KeyStore interface for AWS KMS.
// It provides secure key management with private keys that never leave AWS KMS.
type KeyStore struct {
	backend     *awskmsbackend.Backend
	certStorage certstore.CertificateStorageAdapter
	mu          sync.RWMutex
	closed      bool
}

// NewKeyStore creates a new AWS KMS keystore instance.
//
// The keystore wraps an AWS KMS backend and provides high-level key management
// operations that leverage AWS KMS security. The backend must be properly initialized
// with valid AWS credentials.
//
// Parameters:
//   - backend: AWS KMS backend that has been initialized with configuration
//   - certStorage: Certificate storage backend for managing certificates
//
// Returns a new KeyStore instance or an error if the backend is invalid.
func NewKeyStore(backend *awskmsbackend.Backend, certStorage certstore.CertificateStorageAdapter) (keychain.KeyStore, error) {
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
	// Convert awskmsbackend.Backend to types.Backend wrapper
	return &backendWrapper{backend: ks.backend}
}

// Type returns the store type identifier.
func (ks *KeyStore) Type() types.StoreType {
	return types.StorePKCS11 // AWS KMS acts similar to PKCS11
}

// Initialize prepares the AWS KMS keystore for use.
//
// For AWS KMS, this is a no-op as initialization happens at the backend level
// with AWS credentials. This method is included to satisfy the KeyStore interface.
//
// Parameters:
//   - soPIN: Not used for AWS KMS
//   - userPIN: Not used for AWS KMS
//
// Returns nil as AWS KMS does not require separate initialization.
func (ks *KeyStore) Initialize(soPIN, userPIN types.Password) error {
	// AWS KMS does not require initialization like PKCS#11 tokens
	// Authentication is handled through IAM credentials
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
		// Ed25519 is not supported by AWS KMS
		return nil, backend.ErrInvalidKeyType
	default:
		return nil, keychain.ErrInvalidKeyAlgorithm
	}
}

// GenerateRSA generates a new RSA key pair in AWS KMS.
//
// The key size is specified in attrs.RSAAttributes.KeySize. If not specified
// or less than 512 bits, a default size of 2048 bits is used. AWS KMS supports
// RSA key sizes of 2048, 3072, and 4096 bits.
//
// The private key is generated in AWS KMS and never leaves the service.
// Only the public key is accessible outside KMS.
//
// Parameters:
//   - attrs: Key configuration including RSA key size
//
// Returns an OpaqueKey for the generated RSA key, or an error if generation fails.
func (ks *KeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Validate key algorithm
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm && attrs.KeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("%w: expected RSA, got %s", keychain.ErrInvalidKeyAlgorithm, attrs.KeyAlgorithm)
	}

	// Apply default key size if not specified
	if attrs.RSAAttributes == nil {
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: 2048,
		}
	}
	if attrs.RSAAttributes.KeySize == 0 || attrs.RSAAttributes.KeySize < 512 {
		attrs.RSAAttributes.KeySize = 2048
	}

	// Create the RSA key in AWS KMS
	keyID, err := ks.backend.CreateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA key in AWS KMS: %w", err)
	}

	// Get the public key from KMS
	publicKeyBytes, err := ks.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key from AWS KMS: %w", err)
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Verify it's an RSA key
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA public key, got %T", publicKey)
	}

	// Store the key ID in metadata for later retrieval
	_ = keyID // Key ID is stored in backend metadata

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, rsaPublicKey)
}

// GenerateECDSA generates a new ECDSA key pair in AWS KMS.
//
// The elliptic curve is specified in attrs.ECCAttributes.Curve. If not specified,
// P-256 is used as the default. AWS KMS supports P-256, P-384, and P-521 curves.
//
// The private key is generated in AWS KMS and never leaves the service.
// Only the public key is accessible outside KMS.
//
// Parameters:
//   - attrs: Key configuration including ECC curve
//
// Returns an OpaqueKey for the generated ECDSA key, or an error if generation fails.
func (ks *KeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Apply default curve if not specified
	if attrs.ECCAttributes == nil {
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: elliptic.P256(),
		}
	}
	if attrs.ECCAttributes.Curve == nil {
		attrs.ECCAttributes.Curve = elliptic.P256()
	}

	// Create the ECDSA key in AWS KMS
	keyID, err := ks.backend.CreateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key in AWS KMS: %w", err)
	}

	// Get the public key from KMS
	publicKeyBytes, err := ks.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key from AWS KMS: %w", err)
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Verify it's an ECDSA key
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA public key, got %T", publicKey)
	}

	// Store the key ID in metadata for later retrieval
	_ = keyID // Key ID is stored in backend metadata

	// Return an opaque key wrapping the public key
	return opaque.NewOpaqueKey(ks, attrs, ecdsaPublicKey)
}

// GenerateEd25519 generates a new Ed25519 key pair.
//
// Ed25519 keys are not supported by AWS KMS.
// This method always returns ErrUnsupportedKeyType.
//
// Parameters:
//   - attrs: Key configuration
//
// Returns ErrInvalidKeyType as Ed25519 is not supported by AWS KMS.
func (ks *KeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Ed25519 is not supported by AWS KMS
	return nil, fmt.Errorf("%w: Ed25519 not supported by AWS KMS", backend.ErrInvalidKeyType)
}

// GenerateSecretKey generates a new secret key for symmetric operations.
//
// This method creates a symmetric encryption key in AWS KMS using the
// SYMMETRIC_DEFAULT key spec, which provides AES-256-GCM encryption.
// Symmetric keys can be used for encrypt/decrypt operations but not
// for signing operations.
//
// Supported key types:
//   - KeyTypeSecret: General-purpose secret key
//   - KeyTypeEncryption: Encryption-specific key
//   - KeyTypeHMAC: HMAC key (note: AWS KMS uses ENCRYPT_DECRYPT usage for HMAC keys)
//
// Parameters:
//   - attrs: Key attributes specifying KeyTypeSecret, KeyTypeEncryption, or KeyTypeHMAC
//
// Returns an error if the key type is not supported or key generation fails.
func (ks *KeyStore) GenerateSecretKey(attrs *types.KeyAttributes) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Validate key type - only symmetric key types are supported
	switch attrs.KeyType {
	case backend.KEY_TYPE_ENCRYPTION, backend.KEY_TYPE_SIGNING:
		// These are valid symmetric key types
	default:
		return fmt.Errorf("awskms: unsupported key type for symmetric key generation: %s (use KeyTypeEncryption or KeyTypeSigning)", attrs.KeyType)
	}

	// Create the symmetric key in AWS KMS
	// This will use SYMMETRIC_DEFAULT key spec (AES-256-GCM)
	keyID, err := ks.backend.CreateKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to create symmetric key in AWS KMS: %w", err)
	}

	// Store the key ID in metadata for later retrieval
	_ = keyID // Key ID is stored in backend metadata

	return nil
}

// RotateKey atomically replaces an existing key with a newly generated key.
//
// This method deletes the existing key from AWS KMS and generates a new one
// with the same attributes. If any step fails, an error is returned.
//
// Note: If deletion succeeds but generation fails, the key will be in a
// deleted state. AWS KMS key rotation should be performed carefully.
//
// Parameters:
//   - attrs: Key attributes identifying the key to rotate
//
// Returns an OpaqueKey for the new key, or an error if rotation fails.
func (ks *KeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Verify the key exists before attempting rotation
	_, err := ks.Find(attrs)
	if err != nil {
		return nil, fmt.Errorf("awskms: cannot rotate key that doesn't exist: %w", err)
	}

	// Delete the existing key
	if err := ks.Delete(attrs); err != nil {
		return nil, fmt.Errorf("awskms: failed to delete existing key during rotation: %w", err)
	}

	// Generate new key with same attributes
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		return nil, backend.ErrInvalidKeyType
	default:
		return nil, keychain.ErrInvalidKeyAlgorithm
	}
}

// Equal compares an opaque key with a native private key for equality.
//
// For AWS KMS-backed keys, we can only compare the public key portions since
// the private key never leaves AWS KMS. This method delegates to the shared
// CompareOpaqueKeyEquality helper function for consistent comparison logic.
//
// Parameters:
//   - opaqueKey: The opaque key from AWS KMS
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
// The returned signer delegates signing operations to AWS KMS without
// exposing the private key material. The signing operation is performed
// entirely within AWS KMS.
//
// Parameters:
//   - attrs: Key attributes identifying the signing key
//
// Returns a crypto.Signer, or an error if the key doesn't exist or
// cannot be loaded.
func (ks *KeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Get the public key first to verify the key exists
	publicKeyBytes, err := ks.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, fmt.Errorf("failed to get key from AWS KMS: %w", err)
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Create a signer that wraps the AWS KMS backend
	signer := &kmsSigner{
		backend: ks.backend,
		attrs:   attrs,
		pub:     publicKey,
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the specified key.
//
// AWS KMS decryption is not supported in the current implementation.
// AWS KMS requires keys to be created with ENCRYPT_DECRYPT usage for
// decryption operations, which is incompatible with the signing keys
// this interface manages.
//
// Parameters:
//   - attrs: Key attributes identifying the decryption key
//
// Returns an error indicating the operation is not supported.
func (ks *KeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	// AWS KMS decryption requires different key usage type
	// Keys created for signing cannot be used for decryption
	return nil, fmt.Errorf("awskms: decryption not supported for asymmetric signing keys")
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
		StoreType: backend.STORE_AWSKMS,
	}
	return ks.GetKey(attrs)
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
//
// This method takes a key identifier (CN) and returns a crypto.Signer
// for signing operations. The key must exist in AWS KMS and must be
// a signing key.
//
// Parameters:
//   - keyID: The key identifier (Common Name)
//
// Returns a crypto.Signer or an error if the key doesn't exist.
func (ks *KeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_AWSKMS,
	}
	return ks.Signer(attrs)
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
//
// AWS KMS decryption is not supported in the current implementation.
// This method always returns an error.
//
// Parameters:
//   - keyID: The key identifier (Common Name)
//
// Returns an error indicating the operation is not supported.
func (ks *KeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_AWSKMS,
	}
	return ks.Decrypter(attrs)
}

// Find locates an existing key in AWS KMS without fully loading it.
//
// This method checks if a key exists in AWS KMS by attempting to retrieve
// its public key. It's more efficient than loading the full key when you
// only need to verify existence.
//
// Parameters:
//   - attrs: Key attributes identifying the key
//
// Returns an OpaqueKey if found, or an error if the key doesn't exist.
func (ks *KeyStore) Find(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Try to get the public key from AWS KMS
	publicKeyBytes, err := ks.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, fmt.Errorf("key not found in AWS KMS: %w", err)
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return opaque.NewOpaqueKey(ks, attrs, publicKey)
}

// GetKey retrieves an existing key from AWS KMS.
//
// This method finds the key in AWS KMS by its identifier and returns an
// OpaqueKey that can be used for cryptographic operations. The private key
// material remains in AWS KMS and is never exposed.
//
// Parameters:
//   - attrs: Key attributes identifying the key
//
// Returns an OpaqueKey for the requested key, or an error if the key
// doesn't exist or cannot be loaded.
func (ks *KeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return ks.Find(attrs)
}

// Key retrieves an existing key from AWS KMS.
// Alias for GetKey() for convenience.
func (ks *KeyStore) Key(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return ks.Find(attrs)
}

// Delete removes a key from AWS KMS.
//
// This operation schedules the key for deletion in AWS KMS with a 7-day
// waiting period. The operation is typically irreversible after the waiting
// period expires.
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

// DeleteKey removes a key from AWS KMS.
//
// This operation schedules the key for deletion in AWS KMS with a 7-day
// waiting period. The operation is typically irreversible after the waiting
// period expires.
//
// Parameters:
//   - attrs: Key attributes identifying the key to delete
//
// Returns an error if the key doesn't exist or deletion fails.
func (ks *KeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	return ks.Delete(attrs)
}

// ListKeys returns all key attributes for keys stored in AWS KMS.
//
// This method retrieves all keys from the AWS KMS backend by reconstructing
// KeyAttributes from stored metadata.
//
// Returns a list of key attributes or an error if listing fails.
func (ks *KeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	// Delegate to backend's ListKeys implementation
	return ks.backend.ListKeys()
}

// GetTLSCertificate returns a complete tls.Certificate ready for use.
//
// This combines the private key from AWS KMS with the certificate
// from storage into a single tls.Certificate structure.
//
// Parameters:
//   - keyID: The key identifier (typically the CN)
//   - attrs: Key attributes identifying the key
//
// Returns a tls.Certificate or an error if retrieval fails.
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

	// Build the TLS certificate
	tlsCert := tls.Certificate{
		PrivateKey: key,
	}

	// Add leaf certificate
	tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)

	// Add chain if available
	for _, c := range chain {
		tlsCert.Certificate = append(tlsCert.Certificate, c.Raw)
	}

	return tlsCert, nil
}

// CertStorage returns the certificate storage instance.
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

// backendWrapper wraps awskmsbackend.Backend to implement types.Backend interface.
// It does not own the backend lifecycle - the keychain is responsible for closing
// the backend when appropriate.
type backendWrapper struct {
	backend *awskmsbackend.Backend
}

// Type returns the backend type identifier.
func (bw *backendWrapper) Type() types.BackendType {
	return backend.BackendTypeAWSKMS
}

// Capabilities returns what features this backend supports.
func (bw *backendWrapper) Capabilities() types.Capabilities {
	return types.NewHardwareCapabilities()
}

// GenerateKey generates a new private key with the given attributes.
func (bw *backendWrapper) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// AWS KMS doesn't return private keys - they stay in KMS
	// GenerateKey should be called on KeyStore, not backend wrapper
	return nil, fmt.Errorf("awskms: GenerateKey not supported on backend wrapper, use KeyStore.GenerateKey instead")
}

// GetKey retrieves an existing private key by its attributes.
func (bw *backendWrapper) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// AWS KMS doesn't export private keys
	// Return an error indicating keys should be accessed through KeyStore
	return nil, fmt.Errorf("awskms: GetKey not supported on backend wrapper, use KeyStore.GetKey instead")
}

// DeleteKey removes a key identified by its attributes.
func (bw *backendWrapper) DeleteKey(attrs *types.KeyAttributes) error {
	return bw.backend.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (bw *backendWrapper) ListKeys() ([]*types.KeyAttributes, error) {
	// AWS KMS listing would require additional backend support
	return []*types.KeyAttributes{}, nil
}

// Signer returns a crypto.Signer for the given key.
func (bw *backendWrapper) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	// Get the public key first
	publicKeyBytes, err := bw.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &kmsSigner{
		backend: bw.backend,
		attrs:   attrs,
		pub:     publicKey,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the given key.
func (bw *backendWrapper) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, fmt.Errorf("awskms: decryption not supported")
}

// RotateKey rotates the key identified by attrs, creating a new version.
func (bw *backendWrapper) RotateKey(attrs *types.KeyAttributes) error {
	return bw.backend.RotateKey(attrs)
}

// Close is a no-op for the backend wrapper.
// The wrapper does not own the backend lifecycle - the keychain that created
// this wrapper is responsible for closing the backend when the keychain itself
// is closed.
func (bw *backendWrapper) Close() error {
	// Do not close the backend - the keychain owns the backend lifecycle
	return nil
}

// kmsSigner implements crypto.Signer for AWS KMS keys.
type kmsSigner struct {
	backend *awskmsbackend.Backend
	attrs   *types.KeyAttributes
	pub     crypto.PublicKey
}

// Public returns the public key.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the digest using AWS KMS.
func (s *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.backend.Sign(s.attrs, digest)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS signing failed: %w", err)
	}
	return signature, nil
}

// CanSeal returns true if the underlying backend supports sealing operations.
func (ks *KeyStore) CanSeal() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.closed {
		return false
	}
	return ks.backend.CanSeal()
}

// Seal encrypts data using the backend's sealing mechanism.
func (ks *KeyStore) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}
	if !ks.backend.CanSeal() {
		return nil, keychain.ErrSealingNotSupported
	}
	return ks.backend.Seal(ctx, data, opts)
}

// Unseal decrypts data using the backend's unsealing mechanism.
func (ks *KeyStore) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}
	if sealed == nil {
		return nil, keychain.ErrInvalidSealedData
	}
	return ks.backend.Unseal(ctx, sealed, opts)
}
