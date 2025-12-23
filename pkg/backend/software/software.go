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

package software

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/backend/symmetric"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// SoftwareBackend provides a unified interface for both asymmetric and symmetric
// cryptographic operations using software-based implementations.
//
// This backend uses the Composite/Facade design pattern, delegating:
//   - Asymmetric operations (RSA, ECDSA, Ed25519) to PKCS8Backend
//   - Symmetric operations (AES-GCM, ChaCha20-Poly1305) to symmetric.Backend
//
// This design provides a consistent interface similar to cloud backends
// (AWS KMS, GCP KMS, Azure Key Vault) which also support both operation types.
//
// Thread-safe: Yes, uses a read-write mutex for concurrent access.
type SoftwareBackend struct {
	pkcs8Backend     *pkcs8.PKCS8Backend  // Handles asymmetric operations
	symmetricBackend *symmetric.Backend   // Handles symmetric operations
	storage          storage.Backend      // Direct access to storage for import operations
	closed           bool
	mu               sync.RWMutex

	// Import/export state
	importTokens map[string]*importTokenData // Map of import token UUID to wrapping key data
	importMu     sync.RWMutex                // Separate mutex for import token operations
}

// importTokenData holds the private key and metadata for an import operation
type importTokenData struct {
	privateKey *rsa.PrivateKey
	algorithm  backend.WrappingAlgorithm
	expiresAt  time.Time
	keySpec    string
}

// SoftwareBackendWithKeyAgreement extends the software backend with KeyAgreement capabilities.
// This interface is used internally by the Software backend to provide ECDH support.
type SoftwareBackendWithKeyAgreement interface {
	types.SymmetricBackend
	types.KeyAgreement
}

// NewBackend creates a new unified software backend with the given configuration.
//
// Example usage:
//
//	storage := storage.New()
//	config := &software.Config{
//	    KeyStorage: storage,
//	}
//	backend, err := software.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Generate an RSA key (asymmetric)
//	rsaAttrs := &types.KeyAttributes{
//	    CN:           "example.com",
//	    KeyType:      backend.KEY_TYPE_TLS,
//	    StoreType:    backend.STORE_SW,
//	    KeyAlgorithm: backend.ALG_RSA,
//	    RSAAttributes: &types.RSAAttributes{
//	        KeySize: 2048,
//	    },
//	}
//	rsaKey, err := backend.GenerateKey(rsaAttrs)
//
//	// Generate an AES key (symmetric) with AEAD safety tracking
//	aesAttrs := &types.KeyAttributes{
//	    CN:                "my-secret-key",
//	    KeyType:           backend.KEY_TYPE_SECRET,
//	    StoreType:         backend.STORE_SW,
//	    SymmetricAlgorithm: types.SymmetricAES256GCM,
//	    AEADOptions:       nil, // Use defaults (nonce tracking + bytes tracking enabled)
//	}
//	aesKey, err := backend.GenerateSymmetricKey(aesAttrs)
func NewBackend(config *Config) (types.SymmetricBackend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create PKCS8 backend for asymmetric operations
	pkcs8Config := &pkcs8.Config{
		KeyStorage: config.KeyStorage,
	}
	pkcs8Backend, err := pkcs8.NewBackend(pkcs8Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS8 backend: %w", err)
	}

	// Create AEAD tracker for symmetric operations
	// Use config tracker if provided, otherwise create default
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Create symmetric backend for symmetric operations with tracking
	symmetricConfig := &symmetric.Config{
		KeyStorage: config.KeyStorage,
		Tracker:    tracker,
	}
	symmetricBackend, err := symmetric.NewBackend(symmetricConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create symmetric backend: %w", err)
	}

	return &SoftwareBackend{
		pkcs8Backend:     pkcs8Backend.(*pkcs8.PKCS8Backend),
		symmetricBackend: symmetricBackend.(*symmetric.Backend),
		storage:          config.KeyStorage,
		closed:           false,
		importTokens:     make(map[string]*importTokenData),
	}, nil
}

// Type returns the backend type identifier.
func (b *SoftwareBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

// Capabilities returns what features this backend supports.
// The unified software backend supports BOTH asymmetric and symmetric operations.
func (b *SoftwareBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,  // Asymmetric signing via PKCS8
		Decryption:          true,  // Asymmetric decryption via PKCS8
		KeyRotation:         true,  // Supported by PKCS8
		SymmetricEncryption: true,  // Symmetric operations via AES
		Import:              true,  // Software backend supports key import
		Export:              true,  // Software backend supports key export
		KeyAgreement:        true,  // ECDH key agreement via PKCS8 (X25519, P-256, P-384, P-521)
		ECIES:               false, // Not currently supported
		Sealing:             true,  // Sealing via PKCS8 (HKDF-derived key + AES-GCM)
	}
}

// GenerateKey generates a new asymmetric private key with the given attributes.
// This operation is delegated to the PKCS8 backend.
//
// Supported algorithms:
//   - RSA: Requires RSAAttributes with KeySize (minimum 2048 bits)
//   - ECDSA: Requires ECCAttributes with Curve (P-256, P-384, P-521)
//   - Ed25519: No additional attributes required
func (b *SoftwareBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.pkcs8Backend.GenerateKey(attrs)
}

// GetKey retrieves an existing asymmetric private key by its attributes.
// This operation is delegated to the PKCS8 backend.
func (b *SoftwareBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.pkcs8Backend.GetKey(attrs)
}

// DeleteKey removes a key identified by its attributes.
// This works for both asymmetric and symmetric keys.
func (b *SoftwareBackend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Determine if this is a symmetric or asymmetric key
	if attrs.IsSymmetric() {
		return b.symmetricBackend.DeleteKey(attrs)
	}
	return b.pkcs8Backend.DeleteKey(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
// This includes both asymmetric and symmetric keys.
func (b *SoftwareBackend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Get keys from both backends
	pkcs8Keys, err := b.pkcs8Backend.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list PKCS8 keys: %w", err)
	}

	aesKeys, err := b.symmetricBackend.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list AES keys: %w", err)
	}

	// Combine results
	allKeys := make([]*types.KeyAttributes, 0, len(pkcs8Keys)+len(aesKeys))
	allKeys = append(allKeys, pkcs8Keys...)
	allKeys = append(allKeys, aesKeys...)

	return allKeys, nil
}

// Signer returns a crypto.Signer for the asymmetric key identified by attrs.
// This operation is delegated to the PKCS8 backend.
func (b *SoftwareBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.pkcs8Backend.Signer(attrs)
}

// Decrypter returns a crypto.Decrypter for the asymmetric key identified by attrs.
// This operation is delegated to the PKCS8 backend.
func (b *SoftwareBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.pkcs8Backend.Decrypter(attrs)
}

// RotateKey rotates/updates a key identified by attrs.
// For asymmetric keys, this is delegated to the PKCS8 backend.
// For symmetric keys, this is delegated to the symmetric backend.
func (b *SoftwareBackend) RotateKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if attrs.IsSymmetric() {
		return b.symmetricBackend.RotateKey(attrs)
	}
	return b.pkcs8Backend.RotateKey(attrs)
}

// Close releases any resources held by the backend.
// This closes both the PKCS8 and symmetric backends.
func (b *SoftwareBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Close both backends (but only close storage once)
	// Note: Both backends share the same storage, so we only need to close
	// one of them to close the storage. The second Close() will be a no-op.
	if err := b.pkcs8Backend.Close(); err != nil {
		return fmt.Errorf("failed to close PKCS8 backend: %w", err)
	}

	// The storage is already closed by pkcs8Backend.Close(), so this will
	// return immediately without error.
	if err := b.symmetricBackend.Close(); err != nil {
		return fmt.Errorf("failed to close symmetric backend: %w", err)
	}

	return nil
}

// GenerateSymmetricKey generates a new symmetric AES key with the given attributes.
// This operation is delegated to the symmetric backend.
//
// Supported key sizes: 128, 192, 256 bits
func (b *SoftwareBackend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.symmetricBackend.GenerateSymmetricKey(attrs)
}

// GetSymmetricKey retrieves an existing symmetric key by its attributes.
// This operation is delegated to the symmetric backend.
func (b *SoftwareBackend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.symmetricBackend.GetSymmetricKey(attrs)
}

// SymmetricEncrypter returns a SymmetricEncrypter for the key identified by attrs.
// This operation is delegated to the symmetric backend.
func (b *SoftwareBackend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	return b.symmetricBackend.SymmetricEncrypter(attrs)
}

// GetImportParameters generates a wrapping key pair and returns the public key
// along with an import token for later import operations.
//
// For the software backend, we generate a 2048-bit RSA key pair and store the
// private key in memory with a 24-hour expiration. The import token is a UUID
// that identifies this wrapping key pair.
func (b *SoftwareBackend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.importMu.Lock()
	defer b.importMu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Validate algorithm
	if !isValidWrappingAlgorithm(algorithm) {
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, algorithm)
	}

	// Generate a 2048-bit RSA key pair for wrapping
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wrapping key: %w", err)
	}

	// Generate import token (UUID)
	tokenUUID := uuid.New().String()
	importToken := []byte(tokenUUID)

	// Set expiration to 24 hours from now
	expiresAt := time.Now().Add(24 * time.Hour)

	// Determine key spec based on key attributes
	keySpec := determineKeySpec(attrs)

	// Store the private key and metadata
	b.importTokens[tokenUUID] = &importTokenData{
		privateKey: privateKey,
		algorithm:  algorithm,
		expiresAt:  expiresAt,
		keySpec:    keySpec,
	}

	return &backend.ImportParameters{
		WrappingPublicKey: &privateKey.PublicKey,
		ImportToken:       importToken,
		Algorithm:         algorithm,
		ExpiresAt:         &expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material using the specified import parameters.
// This uses the pkg/crypto/wrapping functions to wrap the key.
func (b *SoftwareBackend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, fmt.Errorf("%w: key material cannot be nil or empty", backend.ErrInvalidAttributes)
	}
	if params == nil {
		return nil, fmt.Errorf("%w: import parameters cannot be nil", backend.ErrInvalidAttributes)
	}

	// Extract the RSA public key
	publicKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: wrapping public key must be an RSA public key", backend.ErrInvalidKeyType)
	}

	var wrappedKey []byte
	var err error

	// Use the appropriate wrapping algorithm
	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1, backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		wrappedKey, err = wrapping.WrapRSAOAEP(keyMaterial, publicKey, params.Algorithm)
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		wrappedKey, err = wrapping.WrapRSAAES(keyMaterial, publicKey, params.Algorithm)
	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, params.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrappedKey,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey unwraps key material that was previously wrapped.
// For the software backend, we can perform unwrapping since we have access
// to the private key.
func (b *SoftwareBackend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if wrapped == nil {
		return nil, fmt.Errorf("%w: wrapped key material cannot be nil", backend.ErrInvalidAttributes)
	}
	if params == nil {
		return nil, fmt.Errorf("%w: import parameters cannot be nil", backend.ErrInvalidAttributes)
	}

	b.importMu.RLock()
	defer b.importMu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Get the import token UUID
	tokenUUID := string(wrapped.ImportToken)
	if tokenUUID == "" {
		return nil, fmt.Errorf("%w: import token cannot be empty", backend.ErrInvalidAttributes)
	}

	// Look up the stored private key
	tokenData, ok := b.importTokens[tokenUUID]
	if !ok {
		return nil, fmt.Errorf("%w: invalid import token", backend.ErrKeyNotFound)
	}

	// Check expiration
	if time.Now().After(tokenData.expiresAt) {
		return nil, fmt.Errorf("%w: import token has expired", backend.ErrKeyNotFound)
	}

	// Verify algorithm matches
	if wrapped.Algorithm != tokenData.algorithm {
		return nil, fmt.Errorf("%w: wrapped with %s but token expects %s",
			backend.ErrInvalidAlgorithm, wrapped.Algorithm, tokenData.algorithm)
	}

	var unwrapped []byte
	var err error

	// Unwrap using the appropriate algorithm
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1, backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		unwrapped, err = wrapping.UnwrapRSAOAEP(wrapped.WrappedKey, tokenData.privateKey, wrapped.Algorithm)
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		unwrapped, err = wrapping.UnwrapRSAAES(wrapped.WrappedKey, tokenData.privateKey, wrapped.Algorithm)
	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, wrapped.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	return unwrapped, nil
}

// ImportKey imports externally generated key material into the backend.
// The key material is unwrapped and then stored based on the key type.
func (b *SoftwareBackend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return fmt.Errorf("%w: key attributes cannot be nil", backend.ErrInvalidAttributes)
	}
	if wrapped == nil {
		return fmt.Errorf("%w: wrapped key material cannot be nil", backend.ErrInvalidAttributes)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// Get the import parameters to unwrap the key
	tokenUUID := string(wrapped.ImportToken)
	if tokenUUID == "" {
		return fmt.Errorf("%w: import token cannot be empty", backend.ErrInvalidAttributes)
	}

	// Look up the stored private key (with read lock)
	b.importMu.RLock()
	tokenData, ok := b.importTokens[tokenUUID]
	b.importMu.RUnlock()

	if !ok {
		return fmt.Errorf("%w: invalid import token", backend.ErrKeyNotFound)
	}

	// Check expiration
	if time.Now().After(tokenData.expiresAt) {
		return fmt.Errorf("%w: import token has expired", backend.ErrKeyNotFound)
	}

	// Create import parameters for unwrapping
	params := &backend.ImportParameters{
		WrappingPublicKey: &tokenData.privateKey.PublicKey,
		ImportToken:       wrapped.ImportToken,
		Algorithm:         tokenData.algorithm,
		ExpiresAt:         &tokenData.expiresAt,
		KeySpec:           tokenData.keySpec,
	}

	// Unwrap the key material
	keyMaterial, err := b.UnwrapKey(wrapped, params)
	if err != nil {
		return fmt.Errorf("failed to unwrap key material: %w", err)
	}

	// Parse and store the key based on type
	if attrs.IsSymmetric() {
		// For symmetric keys, the key material is raw bytes
		return b.importSymmetricKey(attrs, keyMaterial)
	}

	// For asymmetric keys, parse the PKCS8 private key
	return b.importAsymmetricKey(attrs, keyMaterial)
}

// ExportKey exports a key in wrapped form for secure transport.
func (b *SoftwareBackend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Check if backend supports export
	if !b.Capabilities().Export {
		return nil, backend.ErrExportNotSupported
	}

	// Check if key is marked as exportable
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Validate algorithm
	if !isValidWrappingAlgorithm(algorithm) {
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, algorithm)
	}

	// Get the key material
	var keyMaterial []byte
	var err error

	if attrs.IsSymmetric() {
		// Get symmetric key
		key, err := b.symmetricBackend.GetSymmetricKey(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to get symmetric key: %w", err)
		}
		keyMaterial, err = key.Raw()
		if err != nil {
			return nil, fmt.Errorf("failed to get raw key material: %w", err)
		}
	} else {
		// Get asymmetric key and marshal to PKCS8
		privateKey, err := b.pkcs8Backend.GetKey(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to get private key: %w", err)
		}
		keyMaterial, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
	}

	// Generate import parameters for wrapping
	params, err := b.GetImportParameters(attrs, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate import parameters: %w", err)
	}

	// Wrap the key material
	wrapped, err := b.WrapKey(keyMaterial, params)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	return wrapped, nil
}

// importSymmetricKey imports a symmetric key from raw key material
func (b *SoftwareBackend) importSymmetricKey(attrs *types.KeyAttributes, keyMaterial []byte) error {
	// Validate key size
	expectedSize := attrs.SymmetricAlgorithm.KeySize() / 8
	if len(keyMaterial) != expectedSize {
		return fmt.Errorf("%w: invalid key material size expected %d bytes, got %d", backend.ErrInvalidAttributes, expectedSize, len(keyMaterial))
	}

	// Store the raw key material directly (symmetric backend stores raw bytes)
	keyID := attrs.ID()
	if err := storage.SaveKey(b.storage, keyID, keyMaterial); err != nil {
		return fmt.Errorf("failed to store symmetric key: %w", err)
	}

	return nil
}

// importAsymmetricKey imports an asymmetric key from PKCS8-encoded key material
func (b *SoftwareBackend) importAsymmetricKey(attrs *types.KeyAttributes, keyMaterial []byte) error {
	// Parse the PKCS8 private key
	privateKey, err := x509.ParsePKCS8PrivateKey(keyMaterial)
	if err != nil {
		return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	// Validate the key type matches the attributes
	if err := validateKeyType(privateKey, attrs); err != nil {
		return fmt.Errorf("key type validation failed: %w", err)
	}

	// Store the PKCS8-encoded key material directly
	keyID := attrs.ID()
	if err := storage.SaveKey(b.storage, keyID, keyMaterial); err != nil {
		return fmt.Errorf("failed to store asymmetric key: %w", err)
	}

	return nil
}

// Helper functions

func isValidWrappingAlgorithm(algorithm backend.WrappingAlgorithm) bool {
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		return true
	default:
		return false
	}
}

func determineKeySpec(attrs *types.KeyAttributes) string {
	if attrs == nil {
		return "UNKNOWN"
	}

	if attrs.IsSymmetric() {
		keySize := attrs.SymmetricAlgorithm.KeySize()
		if keySize > 0 {
			return fmt.Sprintf("AES_%d", keySize)
		}
		return "AES_256" // default
	}

	// Asymmetric keys
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil {
			return fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		}
		return "RSA_2048" // default
	case x509.ECDSA:
		if attrs.ECCAttributes != nil {
			curveName := types.CurveName(attrs.ECCAttributes.Curve)
			switch curveName {
			case "P-256":
				return "ECC_NIST_P256"
			case "P-384":
				return "ECC_NIST_P384"
			case "P-521":
				return "ECC_NIST_P521"
			}
		}
		return "ECC_NIST_P256" // default
	case x509.Ed25519:
		return "ED25519"
	default:
		return "UNKNOWN"
	}
}

func validateKeyType(privateKey crypto.PrivateKey, attrs *types.KeyAttributes) error {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if attrs.KeyAlgorithm != x509.RSA {
			return fmt.Errorf("%w: expected RSA key but attributes specify %s", backend.ErrInvalidKeyType, attrs.KeyAlgorithm)
		}
		if attrs.RSAAttributes != nil && key.N.BitLen() != attrs.RSAAttributes.KeySize {
			return fmt.Errorf("%w: RSA key size mismatch key is %d bits but attributes specify %d",
				backend.ErrInvalidAttributes, key.N.BitLen(), attrs.RSAAttributes.KeySize)
		}
	case *rsa.PublicKey:
		return fmt.Errorf("%w: expected private key but got public key", backend.ErrInvalidKeyType)
	default:
		// For other key types (ECDSA, Ed25519), basic validation is sufficient
		// More detailed validation can be added if needed
	}
	return nil
}

// GetTracker returns the AEAD safety tracker from the underlying symmetric backend.
// This allows external code to inspect tracking state and configuration.
func (b *SoftwareBackend) GetTracker() types.AEADSafetyTracker {
	return b.symmetricBackend.GetTracker()
}

// DeriveSharedSecret performs ECDH key agreement between the private key
// identified by attrs and the provided public key.
//
// This method delegates to the underlying PKCS8Backend, which supports:
//   - X25519 keys for fast key agreement
//   - NIST curves (P-256, P-384, P-521) via ECDSA keys
//
// The shared secret is the raw output of ECDH - use a KDF to derive encryption keys.
func (b *SoftwareBackend) DeriveSharedSecret(attrs *types.KeyAttributes, publicKey crypto.PublicKey) ([]byte, error) {
	return b.pkcs8Backend.DeriveSharedSecret(attrs, publicKey)
}

// CanSeal returns true if this backend supports sealing operations.
// Software backend supports sealing via its internal PKCS#8 backend.
func (b *SoftwareBackend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return false
	}

	return b.pkcs8Backend.CanSeal()
}

// Seal encrypts/protects data using HKDF-derived key and AES-GCM.
// This operation is delegated to the PKCS8 backend.
//
// The sealing process:
//  1. Load the private key specified in opts.KeyAttributes
//  2. Derive a sealing key using HKDF from the private key material
//  3. Encrypt the data using AES-256-GCM with a random nonce
//
// Security Note: This is a software-only sealing mechanism. The private key
// is loaded into memory during the sealing process. For secrets that should
// never touch system memory, use hardware-backed backends (TPM, HSM).
func (b *SoftwareBackend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Delegate to PKCS8 backend which implements the sealing logic
	sealed, err := b.pkcs8Backend.Seal(ctx, data, opts)
	if err != nil {
		return nil, err
	}

	// Update backend type to reflect it came from software backend
	sealed.Backend = types.BackendTypeSoftware

	return sealed, nil
}

// Unseal decrypts/recovers data using HKDF-derived key and AES-GCM.
// This operation is delegated to the PKCS8 backend.
//
// This method accepts sealed data from both Software and PKCS8 backends,
// since Software backend delegates sealing to PKCS8 internally.
func (b *SoftwareBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, fmt.Errorf("sealed data is required")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Verify this is a software backend sealed data
	if sealed.Backend != types.BackendTypeSoftware {
		return nil, fmt.Errorf("sealed data was not created by software backend (got %s)", sealed.Backend)
	}

	return b.pkcs8Backend.Unseal(ctx, sealed, opts)
}

// Verify interface compliance at compile time
var _ types.Backend = (*SoftwareBackend)(nil)
var _ types.SymmetricBackend = (*SoftwareBackend)(nil)
var _ types.SymmetricBackendWithTracking = (*SoftwareBackend)(nil)
var _ types.KeyAgreement = (*SoftwareBackend)(nil)
var _ backend.ImportExportBackend = (*SoftwareBackend)(nil)
var _ types.Sealer = (*SoftwareBackend)(nil)
