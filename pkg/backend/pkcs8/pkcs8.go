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

package pkcs8

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	ecdhpkg "github.com/jeremyhahn/go-keychain/pkg/crypto/ecdh"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/youmark/pkcs8"
)

// PKCS8Backend implements the Backend interface using PKCS#8 encoding
// for key storage. Keys are stored using the provided storage Backend implementation.
//
// This backend is software-based and supports RSA, ECDSA, and Ed25519 keys.
// Keys can be optionally encrypted with a password using PKCS#8 encryption.
//
// Thread-safe: Yes, uses a read-write mutex for concurrent access.
type PKCS8Backend struct {
	storage storage.Backend
	closed  bool
	mu      sync.RWMutex
}

// Type returns the backend type identifier.
func (b *PKCS8Backend) Type() types.BackendType {
	return types.BackendTypePKCS8
}

// Capabilities returns what features this backend supports.
func (b *PKCS8Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: false,
		Import:              true, // PKCS#8 supports key import via standard encoding
		Export:              true, // PKCS#8 supports key export via standard encoding
		KeyAgreement:        true, // PKCS#8 supports ECDH key agreement (P-256, P-384, P-521, X25519)
		ECIES:               false,
	}
}

// GenerateKey generates a new private key with the given attributes.
// The key is encoded in PKCS#8 format and stored using the KeyStorage.
//
// Supported algorithms:
//   - RSA: Requires RSAAttributes with KeySize (minimum 2048 bits)
//   - ECDSA: Requires ECCAttributes with Curve (P-256, P-384, P-521)
//   - Ed25519: No additional attributes required
//
// X25519 keys are supported via CustomKeyAlgorithm when X25519Attributes are present.
//
// If attrs.Password is provided, the key will be encrypted using PKCS#8 encryption.
func (b *PKCS8Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	// Check if key already exists
	keyID := attrs.ID()
	exists, err := storage.KeyExists(b.storage, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to check key existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyAlreadyExists, keyID)
	}

	// Generate key based on algorithm
	var privateKey crypto.PrivateKey

	// Check for X25519 key agreement key
	if attrs.X25519Attributes != nil {
		privateKey, err = b.generateX25519Key()
	} else {
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			privateKey, err = b.generateRSAKey(attrs.RSAAttributes)
		case x509.ECDSA:
			privateKey, err = b.generateECDSAKey(attrs.ECCAttributes)
		case x509.Ed25519:
			privateKey, err = b.generateEd25519Key()
		default:
			return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Encode and store the key
	if err := b.storeKey(keyID, privateKey, attrs.Password); err != nil {
		return nil, err
	}

	return privateKey, nil
}

// GetKey retrieves an existing private key by its attributes.
// Returns an error if the key does not exist.
func (b *PKCS8Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	keyID := attrs.ID()
	keyData, err := storage.GetKey(b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
		}
		return nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	// Decode the key
	privateKey, err := b.decodeKey(keyData, attrs.Password)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// DeleteKey removes a key identified by its attributes.
// Returns an error if the key does not exist.
func (b *PKCS8Backend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	keyID := attrs.ID()
	if err := storage.DeleteKey(b.storage, keyID); err != nil {
		if err == storage.ErrNotFound {
			return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
		}
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
// Returns an empty slice if no keys exist.
//
// Note: This implementation returns key IDs as CommonNames.
// Full attribute reconstruction may require additional metadata storage.
func (b *PKCS8Backend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyIDs, err := storage.ListKeys(b.storage)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Parse key ID to extract attributes
	// Format: [partition:]storetype:keytype:cn:algorithm
	// Example: sw:tls:my-key:rsa or partition:sw:signing:my-key:ecdsa
	// Also supports format like: pkcs8:tls:my-key:rsa
	attrs := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, id := range keyIDs {
		parts := strings.Split(id, ":")
		var cn string
		var keyTypeStr string
		var storeTypeStr string
		var algorithmStr string

		if len(parts) >= 4 {
			// Has all required parts
			// For format without partition: storetype:keytype:cn:algorithm (4 parts)
			// For format with partition: partition:storetype:keytype:cn:algorithm (5 parts)
			if len(parts) == 4 {
				// storetype:keytype:cn:algorithm
				storeTypeStr = parts[0]
				keyTypeStr = parts[1]
				cn = parts[2]
				algorithmStr = parts[3]
			} else {
				// partition:storetype:keytype:cn:algorithm
				storeTypeStr = parts[1]
				keyTypeStr = parts[2]
				cn = parts[3]
				algorithmStr = parts[4]
			}
		} else {
			// Fallback to using the whole ID as CN
			cn = id
			keyTypeStr = "tls"     // Default to TLS
			storeTypeStr = "pkcs8" // Default to pkcs8
			algorithmStr = "rsa"   // Default to RSA
		}

		attr := &types.KeyAttributes{
			CN:        cn,
			KeyType:   types.ParseKeyType(keyTypeStr),
			StoreType: types.ParseStoreType(storeTypeStr),
		}

		// Parse key algorithm
		switch strings.ToLower(algorithmStr) {
		case "rsa":
			attr.KeyAlgorithm = x509.RSA
			attr.RSAAttributes = &types.RSAAttributes{KeySize: 2048} // Default
		case "ecdsa":
			attr.KeyAlgorithm = x509.ECDSA
			curve, _ := types.ParseCurve("P-256") // Default curve
			attr.ECCAttributes = &types.ECCAttributes{Curve: curve}
		case "ed25519":
			attr.KeyAlgorithm = x509.Ed25519
		}

		// Ensure we have valid defaults
		if attr.KeyType == 0 {
			attr.KeyType = types.KeyTypeTLS
		}
		if attr.StoreType == "" {
			attr.StoreType = types.StorePKCS8
		}
		if attr.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			attr.KeyAlgorithm = x509.RSA
			attr.RSAAttributes = &types.RSAAttributes{KeySize: 2048}
		}

		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
// This allows the key to be used for signing operations without
// exposing the private key material.
func (b *PKCS8Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrKeyNotSigner
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// This allows the key to be used for decryption operations without
// exposing the private key material.
func (b *PKCS8Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, ErrKeyNotDecrypter
	}

	return decrypter, nil
}

// Close releases any resources held by the backend.
// After calling Close, the backend should not be used.
func (b *PKCS8Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	return b.storage.Close()
}

// generateRSAKey generates a new RSA private key.
func (b *PKCS8Backend) generateRSAKey(attrs *types.RSAAttributes) (*rsa.PrivateKey, error) {
	if attrs == nil {
		return nil, fmt.Errorf("%w: RSA attributes are required", backend.ErrInvalidAttributes)
	}

	if attrs.KeySize < 2048 {
		return nil, fmt.Errorf("%w: RSA key size must be at least 2048 bits", backend.ErrInvalidAttributes)
	}

	return rsa.GenerateKey(rand.Reader, attrs.KeySize)
}

// generateECDSAKey generates a new ECDSA private key.
func (b *PKCS8Backend) generateECDSAKey(attrs *types.ECCAttributes) (*ecdsa.PrivateKey, error) {
	if attrs == nil {
		return nil, fmt.Errorf("%w: ECC attributes are required", backend.ErrInvalidAttributes)
	}

	if attrs.Curve == nil {
		return nil, fmt.Errorf("%w: curve is required", backend.ErrInvalidAttributes)
	}

	return ecdsa.GenerateKey(attrs.Curve, rand.Reader)
}

// generateEd25519Key generates a new Ed25519 private key.
func (b *PKCS8Backend) generateEd25519Key() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	return privateKey, err
}

// generateX25519Key generates a new X25519 private key for key agreement.
func (b *PKCS8Backend) generateX25519Key() (crypto.PrivateKey, error) {
	ka := x25519.New()
	keyPair, err := ka.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("X25519 key generation failed: %w", err)
	}

	// Wrap the X25519 private key to implement crypto.PrivateKey
	wrappedKey, err := x25519.NewPrivateKeyStorage(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap X25519 private key: %w", err)
	}

	return wrappedKey, nil
}

// storeKey encodes a private key in PKCS#8 format and stores it.
func (b *PKCS8Backend) storeKey(keyID string, privateKey crypto.PrivateKey, password types.Password) error {
	var keyData []byte
	var err error

	// Unwrap X25519 wrapped key if needed
	actualPrivateKey := privateKey
	if wrapped, ok := privateKey.(*x25519.PrivateKeyStorage); ok {
		// For X25519, store the raw ecdh.PrivateKey
		actualPrivateKey = wrapped.PrivateKey()
	}

	// Get password bytes if provided
	var passwordBytes []byte
	if password != nil {
		passwordBytes = password.Bytes()
	}

	// Encode the key
	if len(passwordBytes) > 0 {
		// Encrypted PKCS#8
		keyData, err = pkcs8.MarshalPrivateKey(actualPrivateKey, passwordBytes, nil)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrKeyEncodingFailed, err)
		}
	} else {
		// Unencrypted PKCS#8
		keyData, err = x509.MarshalPKCS8PrivateKey(actualPrivateKey)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrKeyEncodingFailed, err)
		}
	}

	// Store the encoded key
	if err := storage.SaveKey(b.storage, keyID, keyData); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	return nil
}

// decodeKey decodes a PKCS#8 encoded private key.
// X25519 keys are automatically wrapped in PrivateKeyStorage for consistency.
func (b *PKCS8Backend) decodeKey(keyData []byte, password types.Password) (crypto.PrivateKey, error) {
	var passwordBytes []byte
	var err error

	if password != nil {
		passwordBytes = password.Bytes()
	}

	var privateKey crypto.PrivateKey

	// Try encrypted PKCS#8 if password provided
	if len(passwordBytes) > 0 {
		privateKey, err = pkcs8.ParsePKCS8PrivateKey(keyData, passwordBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyDecodingFailed, err)
		}
	} else {
		// Try unencrypted PKCS#8
		privateKey, err = x509.ParsePKCS8PrivateKey(keyData)
		if err != nil {
			// If a password interface was provided but returned empty/nil, and
			// unencrypted parsing failed, this likely means password retrieval
			// failed (e.g., TPM unseal error) and the key is actually encrypted.
			if password != nil {
				return nil, fmt.Errorf("%w: unencrypted parsing failed and password retrieval returned empty (possible TPM unseal failure or key is encrypted): %v", ErrKeyDecodingFailed, err)
			}
			return nil, fmt.Errorf("%w: %v", ErrKeyDecodingFailed, err)
		}
	}

	// Wrap X25519 keys for consistency
	if ecdhPrivKey, ok := privateKey.(*ecdh.PrivateKey); ok {
		if ecdhPrivKey.Curve() == ecdh.X25519() {
			wrapped, err := x25519.NewPrivateKeyStorage(ecdhPrivKey)
			if err != nil {
				return nil, fmt.Errorf("failed to wrap X25519 key: %w", err)
			}
			return wrapped, nil
		}
	}

	return privateKey, nil
}

// Public returns the public key corresponding to the private key.
// This is a helper method for signing operations.
func (b *PKCS8Backend) Public(attrs *types.KeyAttributes) (crypto.PublicKey, error) {
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *x25519.PrivateKeyStorage:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("%w: %T", backend.ErrInvalidKeyType, key)
	}
}

// Sign signs digest with the private key identified by attrs.
// This is a convenience method that wraps Signer().
func (b *PKCS8Backend) Sign(attrs *types.KeyAttributes, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, err := b.Signer(attrs)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, digest, opts)
}

// RotateKey rotates/updates a key identified by attrs.
// For PKCS#8 software keys, rotation means generating a new key and replacing the old one.
func (b *PKCS8Backend) RotateKey(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	// Delete the old key
	if err := b.DeleteKey(attrs); err != nil && !errors.Is(err, backend.ErrKeyNotFound) {
		return fmt.Errorf("failed to delete old key: %w", err)
	}

	// Generate a new key with the same attributes
	_, err := b.GenerateKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	return nil
}

// DeriveSharedSecret performs ECDH key agreement between the private key
// identified by attrs and the provided public key.
//
// Supports:
//   - X25519 keys for key agreement (32 bytes)
//   - NIST curves (P-256, P-384, P-521) via ECDSA keys
//
// Both keys must be compatible (same curve).
// The shared secret is the raw output of ECDH - use a KDF to derive encryption keys.
func (b *PKCS8Backend) DeriveSharedSecret(attrs *types.KeyAttributes, publicKey crypto.PublicKey) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if attrs == nil {
		return nil, fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	// Get the private key
	privateKey, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	// Handle different key types
	switch privKey := privateKey.(type) {
	case *x25519.PrivateKeyStorage:
		// X25519 key agreement
		pubKeyStorage, ok := publicKey.(*x25519.PublicKeyStorage)
		if !ok {
			return nil, fmt.Errorf("public key must be X25519 for X25519 private key")
		}
		ka := x25519.New()
		return ka.DeriveSharedSecret(privKey.PrivateKey(), pubKeyStorage.PublicKey())

	case *ecdsa.PrivateKey:
		// NIST curve ECDH (P-256, P-384, P-521)
		pubKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key must be ECDSA for ECDSA private key")
		}
		// Use the ECDH package from pkg/crypto/ecdh
		return deriveECDHSharedSecret(privKey, pubKeyECDSA)

	default:
		return nil, fmt.Errorf("%w: %T does not support key agreement", backend.ErrInvalidKeyType, privateKey)
	}
}

// deriveECDHSharedSecret is a helper that performs ECDH with NIST curves (P-256, P-384, P-521).
func deriveECDHSharedSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Check that curves match
	if privateKey.Curve != publicKey.Curve {
		return nil, fmt.Errorf("curve mismatch: private key uses %s, public key uses %s",
			privateKey.Curve.Params().Name, publicKey.Curve.Params().Name)
	}

	// Use the ecdh package from pkg/crypto/ecdh for NIST curves
	return ecdhpkg.DeriveSharedSecret(privateKey, publicKey)
}

// Verify interface compliance at compile time.
var _ types.Backend = (*PKCS8Backend)(nil)
var _ types.KeyAgreement = (*PKCS8Backend)(nil)
