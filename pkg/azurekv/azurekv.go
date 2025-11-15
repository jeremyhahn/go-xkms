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

//go:build azurekv

// Package azurekv provides a cloud-backed keystore implementation using Azure Key Vault.
//
// This package implements the keychain.KeyStore interface for managing cryptographic
// keys in Azure Key Vault. Private keys never leave Azure Key Vault infrastructure,
// providing enhanced security for cryptographic operations.
//
// Key Features:
//   - Cloud-based key generation (RSA 2048-4096 bits, ECDSA P-256/P-384/P-521)
//   - Symmetric key generation (AES-128, AES-256)
//   - Private keys never leave Azure Key Vault
//   - Support for signing operations
//   - Thread-safe operations using mutex synchronization
//   - Global availability and scalability
//   - Integration with Azure RBAC and managed identities
//
// Unsupported Features:
//   - Ed25519 keys (not supported by Azure Key Vault)
//   - Decryption operations (asymmetric decryption not supported)
//   - Direct private key export (by design - cloud security)
//
// Example Usage:
//
//	config := &azurekvbackend.Config{
//	    VaultURL:    "https://my-vault.vault.azure.net",
//	    TenantID:    "tenant-id",
//	    ClientID:    "client-id",
//	    ClientSecret: "client-secret",
//	}
//
//	backend, err := azurekvbackend.NewBackend(context.Background(), config)
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
//	    CN: "my-cloud-key",
//	    KeyAlgorithm: x509.RSA,
//	    KeyType: keychain.KeyTypeSigning,
//	    StoreType: keychain.StoreAzureKV,
//	    RSAAttributes: &types.RSAAttributes{KeySize: 2048},
//	}
//	key, err := ks.GenerateRSA(attrs)
package azurekv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	azurekvbackend "github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyStore implements the keychain.KeyStore interface for Azure Key Vault.
// It provides secure key management with private keys that never leave Azure infrastructure.
type KeyStore struct {
	backend     *azurekvbackend.Backend
	certStorage certstore.CertificateStorageAdapter
	mu          sync.RWMutex
	closed      bool
}

// NewKeyStore creates a new Azure Key Vault keystore instance.
//
// The keystore wraps an Azure Key Vault backend and provides high-level key management
// operations that leverage cloud security. The backend must be properly initialized
// with valid Azure credentials before use.
//
// Parameters:
//   - backend: Azure Key Vault backend that has been initialized with configuration
//   - certStorage: Certificate storage backend for managing certificates
//
// Returns a new KeyStore instance or an error if the backend is invalid.
func NewKeyStore(backend *azurekvbackend.Backend, certStorage certstore.CertificateStorageAdapter) (keychain.KeyStore, error) {
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
	// Convert azurekvbackend.Backend to types.Backend wrapper
	return &backendWrapper{backend: ks.backend}
}

// CertStorage returns the certificate storage instance.
func (ks *KeyStore) CertStorage() certstore.CertificateStorageAdapter {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.certStorage
}

// Type returns the store type identifier.
func (ks *KeyStore) Type() types.StoreType {
	return types.StoreAzureKV
}

// Initialize prepares the Azure Key Vault keystore for use.
//
// For Azure Key Vault, initialization is not required as vaults are
// managed through the Azure portal or CLI. This method is a no-op.
//
// Parameters:
//   - soPIN: Not used for Azure Key Vault
//   - userPIN: Not used for Azure Key Vault
//
// Returns nil as Azure Key Vault doesn't require initialization.
func (ks *KeyStore) Initialize(soPIN, userPIN types.Password) error {
	// Azure Key Vault doesn't require initialization like PKCS#11
	// Vaults and authentication are managed through Azure portal/CLI
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
		// Ed25519 is not supported by Azure Key Vault
		return nil, azurekvbackend.ErrUnsupportedKeyType
	default:
		return nil, keychain.ErrInvalidKeyAlgorithm
	}
}

// GenerateRSA generates a new RSA key pair in Azure Key Vault.
//
// The key size is specified in attrs.RSAAttributes.KeySize. If not specified
// or less than 512 bits, a default size of 2048 bits is used. Azure Key Vault supports
// RSA key sizes of 2048, 3072, and 4096 bits.
//
// The private key is generated in Azure Key Vault and never leaves the cloud infrastructure.
// Only the public key is accessible outside Azure.
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

	// Create the RSA key in Azure Key Vault
	keyID, err := ks.backend.CreateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA key in Azure Key Vault: %w", err)
	}

	// Get the public key from Key Vault
	publicKeyBytes, err := ks.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key from Azure Key Vault: %w", err)
	}

	// Parse the public key (may be in PEM or raw PKIX format)
	publicKey, err := parsePublicKey(publicKeyBytes)
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

// GenerateECDSA generates a new ECDSA key pair in Azure Key Vault.
//
// The elliptic curve is specified in attrs.ECCAttributes.Curve. If not specified,
// P-256 is used as the default. Azure Key Vault supports P-256, P-384, and P-521 curves.
//
// The private key is generated in Azure Key Vault and never leaves the cloud infrastructure.
// Only the public key is accessible outside Azure.
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

	// Create the ECDSA key in Azure Key Vault
	keyID, err := ks.backend.CreateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key in Azure Key Vault: %w", err)
	}

	// Get the public key from Key Vault
	publicKeyBytes, err := ks.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key from Azure Key Vault: %w", err)
	}

	// Parse the public key (may be in PEM or raw PKIX format)
	publicKey, err := parsePublicKey(publicKeyBytes)
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
// Ed25519 keys are not supported by Azure Key Vault.
// This method always returns ErrUnsupportedKeyType.
//
// Parameters:
//   - attrs: Key configuration
//
// Returns ErrUnsupportedKeyType as Ed25519 is not supported by Azure Key Vault.
func (ks *KeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Ed25519 is not supported by Azure Key Vault
	return nil, azurekvbackend.ErrUnsupportedKeyType
}

// GenerateSecretKey generates a new symmetric secret key in Azure Key Vault.
//
// This method creates symmetric encryption keys (AES) as Azure Key Vault key objects
// with the oct (octet) key type. Supports AES-128 (16 bytes) and AES-256 (32 bytes).
//
// The key is stored securely in Azure Key Vault and never leaves the cloud infrastructure.
// Key metadata (vault URL, key ID) is stored locally for retrieval.
//
// Parameters:
//   - attrs: Key attributes specifying KeyTypeSecret or KeyTypeEncryption
//     attrs.RSAAttributes.KeySize determines the key size (128, 256, or defaults to 256)
//
// Returns an error if the key type is invalid, key size is unsupported, or creation fails.
func (ks *KeyStore) GenerateSecretKey(attrs *types.KeyAttributes) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Validate key type - only secret and encryption types are supported
	if attrs.KeyType != backend.KEY_TYPE_SECRET && attrs.KeyType != backend.KEY_TYPE_ENCRYPTION {
		return fmt.Errorf("azurekv: invalid key type for secret key generation, must be KeyTypeSecret or KeyTypeEncryption")
	}

	// Determine key size - default to AES-256 (32 bytes = 256 bits)
	keySize := 32 // Default to AES-256
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		switch attrs.RSAAttributes.KeySize {
		case 128:
			keySize = 16 // AES-128
		case 256:
			keySize = 32 // AES-256
		default:
			return fmt.Errorf("azurekv: unsupported key size %d, must be 128 or 256 bits", attrs.RSAAttributes.KeySize)
		}
	}

	// Create the symmetric key in Azure Key Vault using CreateSecretKey
	keyID, err := ks.backend.CreateSecretKey(attrs, keySize)
	if err != nil {
		return fmt.Errorf("azurekv: failed to create secret key in Azure Key Vault: %w", err)
	}

	// Store the key ID for future reference
	_ = keyID // Key ID is stored in backend metadata

	return nil
}

// RotateKey atomically replaces an existing key with a newly generated key.
//
// This method deletes the existing key from Azure Key Vault and generates a new one
// with the same attributes. If any step fails, an error is returned.
//
// Note: If deletion succeeds but generation fails, the key will be in a
// deleted state. Azure Key Vault key rotation should be performed carefully.
//
// Parameters:
//   - attrs: Key attributes identifying the key to rotate
//
// Returns an OpaqueKey for the new key, or an error if rotation fails.
func (ks *KeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Verify the key exists before attempting rotation
	_, err := ks.Find(attrs)
	if err != nil {
		return nil, fmt.Errorf("azurekv: cannot rotate key that doesn't exist: %w", err)
	}

	// Delete the existing key
	if err := ks.Delete(attrs); err != nil {
		return nil, fmt.Errorf("azurekv: failed to delete existing key during rotation: %w", err)
	}

	// Generate new key with same attributes
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		return nil, azurekvbackend.ErrUnsupportedKeyType
	default:
		return nil, keychain.ErrInvalidKeyAlgorithm
	}
}

// Equal compares an opaque key with a native private key for equality.
//
// For cloud-backed keys, we can only compare the public key portions since
// the private key never leaves Azure Key Vault. This method extracts public keys
// from both parameters and performs a deep comparison.
//
// Parameters:
//   - opaque: The opaque key from Azure Key Vault
//   - x: The private key to compare against
//
// Returns true if the public keys match, indicating the same key pair.
func (ks *KeyStore) Equal(opaqueKey crypto.PrivateKey, x crypto.PrivateKey) bool {
	// Convert to opaque.OpaqueKey if possible
	if opaque, ok := opaqueKey.(opaque.OpaqueKey); ok {
		return keychain.CompareOpaqueKeyEquality(opaque, x)
	}
	return false
}

// Signer returns a crypto.Signer for the specified key.
//
// The returned signer delegates signing operations to Azure Key Vault without
// exposing the private key material. The signing operation is performed
// entirely within Azure Key Vault infrastructure.
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
		return nil, fmt.Errorf("failed to get key from Azure Key Vault: %w", err)
	}

	// Parse the public key (may be in PEM or raw PKIX format)
	publicKey, err := parsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Create a signer that wraps the Azure Key Vault backend
	signer := &kvSigner{
		backend: ks.backend,
		attrs:   attrs,
		pub:     publicKey,
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the specified key.
//
// Azure Key Vault asymmetric keys do not support decryption operations
// in the current implementation. This method always returns an error.
//
// Parameters:
//   - attrs: Key attributes identifying the decryption key
//
// Returns an error as decryption is not supported for asymmetric keys in Azure Key Vault.
func (ks *KeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	// Azure Key Vault asymmetric keys do not support decryption
	return nil, fmt.Errorf("azurekv: decryption not supported for asymmetric signing keys")
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
		StoreType: backend.STORE_AZUREKV,
	}
	return ks.Key(attrs)
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
		StoreType: backend.STORE_AZUREKV,
	}
	return ks.Signer(attrs)
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
//
// Azure Key Vault asymmetric keys do not support decryption operations.
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
		StoreType: backend.STORE_AZUREKV,
	}
	return ks.Decrypter(attrs)
}

// Find locates an existing key in Azure Key Vault without fully loading it.
//
// This method checks if a key exists in Azure Key Vault by attempting to retrieve
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

	// Try to get the public key from Azure Key Vault
	publicKeyBytes, err := ks.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, fmt.Errorf("key not found in Azure Key Vault: %w", err)
	}

	// Parse the public key (may be in PEM or raw PKIX format)
	publicKey, err := parsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return opaque.NewOpaqueKey(ks, attrs, publicKey)
}

// GetKey retrieves an existing key from Azure Key Vault.
//
// This is an alias for Key() to satisfy the keychain.KeyStore interface.
//
// Parameters:
//   - attrs: Key attributes identifying the key
//
// Returns an OpaqueKey for the requested key, or an error if the key
// doesn't exist or cannot be loaded.
func (ks *KeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return ks.Key(attrs)
}

// Key retrieves an existing key from Azure Key Vault.
//
// This method finds the key in Azure Key Vault by its identifier and returns an
// OpaqueKey that can be used for cryptographic operations. The private key
// material remains in Azure Key Vault and is never exposed.
//
// Parameters:
//   - attrs: Key attributes identifying the key
//
// Returns an OpaqueKey for the requested key, or an error if the key
// doesn't exist or cannot be loaded.
func (ks *KeyStore) Key(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return ks.Find(attrs)
}

// Delete removes a key from Azure Key Vault.
//
// This operation soft-deletes the key. Azure Key Vault provides a retention
// period during which keys can be recovered or purged.
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

// DeleteKey removes a key from Azure Key Vault.
//
// This is an alias for Delete() to satisfy the keychain.KeyStore interface.
//
// Parameters:
//   - attrs: Key attributes identifying the key to delete
//
// Returns an error if the key doesn't exist or deletion fails.
func (ks *KeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	return ks.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this keystore.
//
// Note: Azure Key Vault listing requires additional backend support.
// This implementation returns an empty list.
//
// Returns an empty list of key attributes.
func (ks *KeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	// Azure Key Vault listing would require additional backend support
	return []*types.KeyAttributes{}, nil
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

// parsePublicKey parses a public key that may be in PEM or raw PKIX format.
func parsePublicKey(data []byte) (crypto.PublicKey, error) {
	// Try PEM decode first
	block, _ := pem.Decode(data)
	if block != nil {
		// PEM encoded
		return x509.ParsePKIXPublicKey(block.Bytes)
	}

	// Try raw PKIX
	return x509.ParsePKIXPublicKey(data)
}

// backendWrapper wraps azurekvbackend.Backend to implement types.Backend interface.
// It does not own the backend lifecycle - the keychain is responsible for closing
// the backend when appropriate.
type backendWrapper struct {
	backend *azurekvbackend.Backend
}

// Type returns the backend type identifier.
func (bw *backendWrapper) Type() types.BackendType {
	return backend.BackendTypeAzureKV
}

// Capabilities returns what features this backend supports.
func (bw *backendWrapper) Capabilities() types.Capabilities {
	return types.NewHardwareCapabilities()
}

// GenerateKey generates a new private key with the given attributes.
func (bw *backendWrapper) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Azure Key Vault doesn't return private keys - they stay in Azure infrastructure
	// Use the keystore GenerateKey method instead
	return nil, fmt.Errorf("azurekv: GenerateKey not supported on backend wrapper, use KeyStore.GenerateKey instead")
}

// GetKey retrieves an existing private key by its attributes.
func (bw *backendWrapper) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// Azure Key Vault doesn't export private keys
	return nil, fmt.Errorf("azurekv: GetKey not supported on backend wrapper, use KeyStore.GetKey instead")
}

// DeleteKey removes a key identified by its attributes.
func (bw *backendWrapper) DeleteKey(attrs *types.KeyAttributes) error {
	return bw.backend.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (bw *backendWrapper) ListKeys() ([]*types.KeyAttributes, error) {
	// Azure Key Vault listing would require additional backend support
	return []*types.KeyAttributes{}, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (bw *backendWrapper) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	// Get the public key first
	publicKeyBytes, err := bw.backend.Get(attrs, backend.FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, err
	}

	publicKey, err := parsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &kvSigner{
		backend: bw.backend,
		attrs:   attrs,
		pub:     publicKey,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (bw *backendWrapper) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, fmt.Errorf("azurekv: decryption not supported for asymmetric signing keys")
}

// RotateKey rotates the key identified by attrs, creating a new version.
func (bw *backendWrapper) RotateKey(attrs *types.KeyAttributes) error {
	return bw.backend.RotateKey(attrs)
}

// Close is a no-op for the backend wrapper.
// The wrapper does not own the backend lifecycle - the keychain that created
// this wrapper is responsible for closing the backend when the keychain itself
// is closed. This prevents premature closure of shared backends that may be
// used by multiple keystore instances.
func (bw *backendWrapper) Close() error {
	// Do not close the backend - the keychain owns the backend lifecycle
	return nil
}

// kvSigner implements crypto.Signer for Azure Key Vault keys.
type kvSigner struct {
	backend *azurekvbackend.Backend
	attrs   *types.KeyAttributes
	pub     crypto.PublicKey
}

// Public returns the public key.
func (s *kvSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the digest using Azure Key Vault.
func (s *kvSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.backend.Sign(s.attrs, digest)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault signing failed: %w", err)
	}
	return signature, nil
}
