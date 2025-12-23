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

package symmetric

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	chacha20poly1305pkg "github.com/jeremyhahn/go-keychain/pkg/crypto/chacha20poly1305"
	cryptorand "github.com/jeremyhahn/go-keychain/pkg/crypto/rand"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"golang.org/x/crypto/argon2"
)

// Backend implements symmetric encryption operations for both AES-GCM and ChaCha20-Poly1305.
// This backend provides software-based symmetric key generation and encryption,
// storing raw symmetric keys (not PKCS#8 encoded).
//
// Supported algorithms:
//   - AES-128-GCM, AES-192-GCM, AES-256-GCM
//   - ChaCha20-Poly1305, XChaCha20-Poly1305
//
// Key storage format:
//   - Unencrypted: Raw key bytes (16, 24, or 32 bytes)
//   - Password-protected: [salt(32)][nonce(12)][ciphertext+tag]
//
// File naming convention: [partition:]sw:secret:cn:algorithm
//
// Thread-safe: Yes, uses a read-write mutex for concurrent access.
//
// AEAD Safety Tracking:
//   - Nonce uniqueness checking (prevents catastrophic nonce reuse)
//   - Bytes encrypted tracking (enforces NIST limits)
//   - Automatic tracking with sensible defaults
//
// RNG Configuration:
//   - Supports configurable random number generation (hardware or software)
//   - Used for nonce generation in AEAD operations
//   - Defaults to auto-detection (hardware preferred)
type Backend struct {
	storage           storage.Backend
	wrappingKeys      map[string]*rsa.PrivateKey // Maps import token (UUID) to RSA private key
	tracker           types.AEADSafetyTracker    // AEAD safety tracker for nonce/bytes tracking
	rng               cryptorand.Resolver        // Configurable RNG for nonce generation
	closed            bool
	mu                sync.RWMutex
	wrappingKeysMutex sync.RWMutex
}

// Config contains configuration for the symmetric Backend.
type Config struct {
	// KeyStorage is the underlying storage for key material.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	KeyStorage storage.Backend

	// Tracker is the AEAD safety tracker for nonce/bytes tracking.
	// If nil, a default memory-based tracker will be created.
	// For production systems, provide a persistent tracker.
	Tracker types.AEADSafetyTracker

	// RNGConfig configures the random number generator for nonce generation.
	// If nil, defaults to ModeAuto (hardware RNG preferred, falls back to software).
	// Configure this to use specific RNG sources (TPM2, PKCS11, software).
	// Example: cryptorand.ModeSoftware, cryptorand.ModeTPM2, cryptorand.ModePKCS11
	RNGConfig interface{}
}

// Validate checks if the Config is valid.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.KeyStorage == nil {
		return fmt.Errorf("KeyStorage is required")
	}
	return nil
}

// NewBackend creates a new software symmetric backend with the given configuration.
//
// Example usage:
//
//	storage := storage.New()
//	config := &symmetric.Config{
//	    KeyStorage: storage,
//	}
//	backend, err := symmetric.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Generate a new AES-256 key
//	attrs := &types.KeyAttributes{
//	    CN:                 "my-secret-key",
//	    KeyType:            backend.KEY_TYPE_SECRET,
//	    StoreType:          backend.STORE_SW,
//	    SymmetricAlgorithm: backend.SymmetricAES256GCM,
//	}
//	key, err := backend.GenerateSymmetricKey(attrs)
func NewBackend(config *Config) (types.SymmetricBackend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create default tracker if none provided
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Create RNG resolver with default auto-detection if not provided
	rng, err := cryptorand.NewResolver(config.RNGConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RNG: %w", err)
	}

	return &Backend{
		storage:      config.KeyStorage,
		tracker:      tracker,
		rng:          rng,
		wrappingKeys: make(map[string]*rsa.PrivateKey),
		closed:       false,
	}, nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return types.BackendTypeSymmetric
}

// Capabilities returns what features this backend supports.
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             false, // Symmetric backend is symmetric-only
		Decryption:          false, // No asymmetric decryption
		KeyRotation:         true,  // Supports key rotation
		SymmetricEncryption: true,
		Import:              true, // Supports key import
		Export:              true, // Supports key export
	}
}

// GenerateKey is not supported by the symmetric backend (symmetric only).
// Use GenerateSymmetricKey instead.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("%w: use GenerateSymmetricKey instead", backend.ErrOperationNotSupported)
}

// GetKey is not supported by the symmetric backend (symmetric only).
// Use GetSymmetricKey instead.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("%w: use GetSymmetricKey instead", backend.ErrOperationNotSupported)
}

// DeleteKey removes a symmetric key identified by its attributes.
// Returns an error if the key does not exist.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
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
			return backend.ErrKeyNotFound
		}
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
// Returns an empty slice if no keys exist.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyIDs, err := storage.ListKeys(b.storage)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Parse key ID format: [partition:]sw:secret:cn:algorithm
	attrs := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, id := range keyIDs {
		parts := strings.Split(id, ":")
		var cn string
		var keyTypeStr string
		var algorithmStr string
		var storeType string
		var partition string

		if len(parts) >= 4 {
			// Has all required parts
			// For format without partition: sw:secret:my-key:aes256-gcm (4 parts)
			// For format with partition: partition:sw:secret:my-key:aes256-gcm (5 parts)
			if len(parts) == 4 {
				// storetype:keytype:cn:algorithm
				storeType = parts[0]
				keyTypeStr = parts[1]
				cn = parts[2]
				algorithmStr = parts[3]
			} else {
				// partition:storetype:keytype:cn:algorithm
				partition = parts[0]
				storeType = parts[1]
				keyTypeStr = parts[2]
				cn = parts[3]
				algorithmStr = parts[4]
			}
		} else {
			// Fallback to using the whole ID as CN
			cn = id
			keyTypeStr = "secret" // Default to SECRET for symmetric keys
			storeType = "sw"
		}

		// Skip asymmetric keys - they are handled by the PKCS8 backend
		// Only process keys with keyType "secret" (symmetric keys)
		if strings.ToLower(keyTypeStr) != "secret" {
			continue
		}

		attr := &types.KeyAttributes{
			CN:                 cn,
			KeyType:            types.ParseKeyType(keyTypeStr),
			StoreType:          backend.StoreType(storeType),
			Partition:          types.Partition(partition),
			SymmetricAlgorithm: types.SymmetricAlgorithm(algorithmStr),
		}
		// Ensure we have a valid key type for symmetric keys
		if attr.KeyType == 0 {
			attr.KeyType = types.KeyTypeSecret // Default to Secret if parsing fails
		}

		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// Signer is not supported by the symmetric backend (symmetric only).
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, backend.ErrOperationNotSupported
}

// Decrypter is not supported by the symmetric backend (symmetric only).
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrOperationNotSupported
}

// RotateKey rotates/updates a symmetric key identified by attrs.
// For symmetric keys, rotation means generating a new key and replacing the old one.
//
// AEAD Safety Tracking:
//   - Tracking state is reset (nonce history cleared, byte counters reset)
//   - New key starts with fresh tracking state
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	keyID := attrs.ID()

	// Reset tracking before deleting the key
	if b.tracker != nil {
		if err := b.tracker.ResetTracking(keyID); err != nil {
			// Log but don't fail rotation
			fmt.Printf("Warning: failed to reset tracking: %v\n", err)
		}
	}

	// Delete the old key
	if err := b.DeleteKey(attrs); err != nil && err != backend.ErrKeyNotFound {
		return fmt.Errorf("failed to delete old key: %w", err)
	}

	// Generate a new key with the same attributes (tracking will be re-initialized)
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	return nil
}

// Close releases any resources held by the backend.
// After calling Close, the backend should not be used.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Close RNG resolver
	if b.rng != nil {
		if err := b.rng.Close(); err != nil {
			// Log but don't fail - storage close is more critical
			fmt.Printf("Warning: failed to close RNG: %v\n", err)
		}
	}

	return b.storage.Close()
}

// GenerateSymmetricKey generates a new symmetric key with the given attributes.
// The key is stored encrypted with Argon2id-derived key if a password is provided.
//
// AEAD Safety Tracking:
//   - If attrs.AEADOptions is nil, default safety options are applied (tracking enabled)
//   - Nonce uniqueness and bytes limits are enforced during encryption
//   - Tracking state is initialized for the new key
//
// Supported algorithms:
//   - AES-128-GCM, AES-192-GCM, AES-256-GCM (key sizes: 128, 192, 256 bits)
//   - ChaCha20-Poly1305, XChaCha20-Poly1305 (key size: 256 bits)
//
// Storage format: See design doc Appendix B for password-encrypted format
func (b *Backend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
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

	// Set up AEAD tracking with defaults if not specified
	aeadOpts := attrs.AEADOptions
	if aeadOpts == nil {
		aeadOpts = types.DefaultAEADOptions()
	}
	if err := aeadOpts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid AEAD options: %w", err)
	}

	// Initialize tracking for this key
	if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
		return nil, fmt.Errorf("failed to set AEAD options: %w", err)
	}

	// Generate random key bytes based on algorithm
	keySize := attrs.SymmetricAlgorithm.KeySize() / 8 // Convert bits to bytes

	keyData := make([]byte, keySize)
	if _, err := rand.Read(keyData); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Create appropriate symmetric key based on algorithm
	var symmetricKey types.SymmetricKey
	var keyErr error
	switch attrs.SymmetricAlgorithm {
	case types.SymmetricChaCha20Poly1305, types.SymmetricXChaCha20Poly1305:
		symmetricKey, keyErr = NewChaCha20Key(string(attrs.SymmetricAlgorithm), keyData)
		if keyErr != nil {
			return nil, fmt.Errorf("failed to create ChaCha20 key: %w", keyErr)
		}
	default:
		symmetricKey, keyErr = NewAESKey(string(attrs.SymmetricAlgorithm), keyData)
		if keyErr != nil {
			return nil, fmt.Errorf("failed to create AES key: %w", keyErr)
		}
	}

	// Encode and store the key
	if err := b.storeSymmetricKey(keyID, keyData, attrs.Password); err != nil {
		return nil, err
	}

	return symmetricKey, nil
}

// GetSymmetricKey retrieves an existing symmetric key by its attributes.
// Returns an error if the key does not exist.
func (b *Backend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	keyID := attrs.ID()
	keyData, err := storage.GetKey(b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, backend.ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	// Decode the key
	rawKey, err := b.decodeSymmetricKey(keyData, attrs.Password)
	if err != nil {
		return nil, err
	}

	// Create appropriate symmetric key based on algorithm
	switch attrs.SymmetricAlgorithm {
	case types.SymmetricChaCha20Poly1305, types.SymmetricXChaCha20Poly1305:
		return NewChaCha20Key(string(attrs.SymmetricAlgorithm), rawKey)
	default:
		return NewAESKey(string(attrs.SymmetricAlgorithm), rawKey)
	}
}

// SymmetricEncrypter returns a SymmetricEncrypter for the specified key.
// This allows the key to be used for encryption/decryption operations with AEAD safety tracking.
func (b *Backend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		return nil, err
	}

	return &softwareSymmetricEncrypter{
		key:     key,
		attrs:   attrs,
		tracker: b.tracker,
		rng:     b.rng,
	}, nil
}

// softwareSymmetricEncrypter implements types.SymmetricEncrypter for symmetric AEAD ciphers.
type softwareSymmetricEncrypter struct {
	key     types.SymmetricKey
	attrs   *types.KeyAttributes
	tracker types.AEADSafetyTracker
	rng     cryptorand.Resolver
}

// Encrypt encrypts plaintext using AES-GCM or ChaCha20-Poly1305 with the symmetric key.
// Returns EncryptedData containing ciphertext, nonce, and authentication tag.
//
// AEAD Safety Tracking:
//  1. Checks bytes limit before encryption (prevents exceeding NIST limits)
//  2. Generates a random nonce (or uses provided nonce)
//  3. Checks nonce uniqueness (prevents catastrophic nonce reuse)
//  4. Performs encryption
//  5. Records nonce after successful encryption
//
// If any safety check fails, encryption is aborted and an error is returned.
func (e *softwareSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// Get key ID for tracking
	keyID := e.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if e.tracker != nil {
		if err := e.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w (consider rotating this key)", err)
		}
	}

	// Get raw key bytes
	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	// Determine which cipher to use and perform encryption
	var encrypted *types.EncryptedData

	switch e.attrs.SymmetricAlgorithm {
	case types.SymmetricChaCha20Poly1305, types.SymmetricXChaCha20Poly1305:
		// Use ChaCha20-Poly1305
		var chacha20Cipher chacha20poly1305pkg.AEAD
		if e.attrs.SymmetricAlgorithm == types.SymmetricXChaCha20Poly1305 {
			chacha20Cipher, err = chacha20poly1305pkg.NewX(keyBytes)
		} else {
			chacha20Cipher, err = chacha20poly1305pkg.New(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
		}

		// STEP 2: Generate or use provided nonce
		var nonce []byte
		nonceSize := chacha20Cipher.NonceSize()
		if opts.Nonce != nil {
			nonce = opts.Nonce
			if len(nonce) != nonceSize {
				return nil, fmt.Errorf("invalid nonce size: %d (expected %d)", len(nonce), nonceSize)
			}
		} else {
			// Use configured RNG for nonce generation
			nonce, err = e.rng.Rand(nonceSize)
			if err != nil {
				return nil, fmt.Errorf("failed to generate nonce: %w", err)
			}
		}

		// STEP 3: Check nonce uniqueness before encryption
		if e.tracker != nil {
			if err := e.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, fmt.Errorf("AEAD safety check failed: %w (CRITICAL: rotate this key immediately)", err)
			}
		}

		// STEP 4: Perform encryption using ChaCha20 AEAD interface
		chacha20Opts := &types.EncryptOptions{
			Nonce:          nonce,
			AdditionalData: opts.AdditionalData,
		}
		encrypted, err = chacha20Cipher.Encrypt(plaintext, chacha20Opts)
		if err != nil {
			return nil, fmt.Errorf("ChaCha20 encryption failed: %w", err)
		}

	default:
		// Use AES-GCM
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %w", err)
		}

		nonceSize := gcm.NonceSize()

		// STEP 2: Generate or use provided nonce
		var nonce []byte
		if opts.Nonce != nil {
			nonce = opts.Nonce
			if len(nonce) != nonceSize {
				return nil, fmt.Errorf("invalid nonce size: %d (expected %d)", len(nonce), nonceSize)
			}
		} else {
			// Use configured RNG for nonce generation
			nonce, err = e.rng.Rand(nonceSize)
			if err != nil {
				return nil, fmt.Errorf("failed to generate nonce: %w", err)
			}
		}

		// STEP 3: Check nonce uniqueness before encryption
		if e.tracker != nil {
			if err := e.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, fmt.Errorf("AEAD safety check failed: %w (CRITICAL: rotate this key immediately)", err)
			}
		}

		// STEP 4: Perform encryption with authentication
		ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)

		// Extract tag from end of ciphertext
		tagSize := gcm.Overhead()
		if len(ciphertextWithTag) < tagSize {
			return nil, fmt.Errorf("ciphertext too short")
		}

		ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
		tag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]

		encrypted = &types.EncryptedData{
			Ciphertext: ciphertext,
			Nonce:      nonce,
			Tag:        tag,
			Algorithm:  e.key.Algorithm(),
		}
	}

	// STEP 5: Record nonce after successful encryption
	if e.tracker != nil {
		if err := e.tracker.RecordNonce(keyID, encrypted.Nonce); err != nil {
			// Log this error but don't fail the encryption since it already succeeded
			// In a production system, you might want to handle this differently
			fmt.Printf("Warning: failed to record nonce: %v\n", err)
		}
	}

	return encrypted, nil
}

// Decrypt decrypts ciphertext using AES-GCM or ChaCha20-Poly1305 with the symmetric key.
// Verifies authentication before decrypting. Returns error if authentication fails.
func (e *softwareSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	if data == nil {
		return nil, fmt.Errorf("encrypted data is nil")
	}

	// Get raw key bytes
	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	// Reconstruct ciphertext with tag (AEAD ciphers expect tag appended)
	fullCiphertext := append(data.Ciphertext, data.Tag...)

	// Determine which cipher to use
	var plaintext []byte
	switch e.attrs.SymmetricAlgorithm {
	case types.SymmetricChaCha20Poly1305, types.SymmetricXChaCha20Poly1305:
		// Use ChaCha20-Poly1305
		var chacha20Cipher chacha20poly1305pkg.AEAD
		if e.attrs.SymmetricAlgorithm == types.SymmetricXChaCha20Poly1305 {
			chacha20Cipher, err = chacha20poly1305pkg.NewX(keyBytes)
		} else {
			chacha20Cipher, err = chacha20poly1305pkg.New(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
		}

		// Decrypt and verify - use the ChaCha20 AEAD interface's Decrypt method
		plaintext, err = chacha20Cipher.Decrypt(data, &types.DecryptOptions{
			AdditionalData: opts.AdditionalData,
		})
		if err != nil {
			return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
		}

	default:
		// Use AES-GCM
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %w", err)
		}

		// Decrypt and verify
		plaintext, err = gcm.Open(nil, data.Nonce, fullCiphertext, opts.AdditionalData)
		if err != nil {
			return nil, fmt.Errorf("decryption failed (authentication error): %w", err)
		}
	}

	return plaintext, nil
}

// storeSymmetricKey stores a symmetric key, optionally encrypted with a password.
// Uses Argon2id for password-based key derivation with parameters:
// - time=1, memory=64MB, threads=4, keyLen=32
func (b *Backend) storeSymmetricKey(keyID string, keyData []byte, password types.Password) error {
	var storedData []byte

	if password != nil {
		passwordBytes := password.Bytes()
		if len(passwordBytes) > 0 {
			// Encrypt key data using AES-256-GCM with password-derived key
			var err error
			storedData, err = encryptWithPassword(keyData, passwordBytes)
			if err != nil {
				return fmt.Errorf("failed to encrypt key: %w", err)
			}
		} else {
			storedData = keyData
		}
	} else {
		storedData = keyData
	}

	if err := storage.SaveKey(b.storage, keyID, storedData); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	return nil
}

// decodeSymmetricKey decodes a stored symmetric key, decrypting if password-protected.
func (b *Backend) decodeSymmetricKey(storedData []byte, password types.Password) ([]byte, error) {
	if password != nil {
		passwordBytes := password.Bytes()
		if len(passwordBytes) > 0 {
			// Decrypt key data
			keyData, err := decryptWithPassword(storedData, passwordBytes)
			if err != nil {
				// ErrInvalidPassword is already returned by decryptWithPassword
				return nil, err
			}
			return keyData, nil
		}
	}

	return storedData, nil
}

// encryptWithPassword encrypts key data using a password-derived key.
// Uses Argon2id for key derivation with the following parameters:
// - Time cost: 1 iteration
// - Memory: 64 MB (64*1024 KB)
// - Threads: 4
// - Key length: 32 bytes (256 bits) for AES-256
//
// Format: [salt][nonce][ciphertext+tag]
// - Salt: 32 bytes
// - Nonce: 12 bytes (GCM standard)
// - Ciphertext+Tag: variable (tag is 16 bytes)
func encryptWithPassword(keyData, password []byte) ([]byte, error) {
	// Generate salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key using Argon2id
	// Parameters: time=1, memory=64MB, threads=4, keyLen=32
	derivedKey := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with salt as additional authenticated data
	ciphertext := gcm.Seal(nil, nonce, keyData, salt)

	// Format: [salt][nonce][ciphertext+tag]
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptWithPassword decrypts key data using a password-derived key.
// Expected format: [salt][nonce][ciphertext+tag]
func decryptWithPassword(encryptedData, password []byte) ([]byte, error) {
	// Minimum size: 32 (salt) + 12 (nonce) + 16 (tag) = 60 bytes
	if len(encryptedData) < 60 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes (minimum 60)", len(encryptedData))
	}

	// Extract components
	salt := encryptedData[0:32]
	nonce := encryptedData[32:44]
	ciphertext := encryptedData[44:]

	// Derive encryption key using same parameters as encryption
	derivedKey := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt with salt as additional authenticated data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, salt)
	if err != nil {
		return nil, ErrInvalidPassword
	}

	return plaintext, nil
}

// GetImportParameters generates RSA wrapping key pair for importing symmetric keys.
// The private key is stored in memory with a UUID token, and the public key
// is returned for use in wrapping operations.
func (b *Backend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrStorageClosed
	}
	b.mu.RUnlock()

	if attrs == nil {
		return nil, fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	// Validate wrapping algorithm
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported algorithms
	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, algorithm)
	}

	// Generate 2048-bit RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Generate UUID token for this import operation
	token := uuid.New().String()

	// Store the private key with the token
	b.wrappingKeysMutex.Lock()
	b.wrappingKeys[token] = privateKey
	b.wrappingKeysMutex.Unlock()

	// Set expiration to 24 hours from now
	expiresAt := time.Now().Add(24 * time.Hour)

	// Determine key spec from algorithm
	keySpec := "AES_256" // Default
	switch attrs.SymmetricAlgorithm.KeySize() {
	case 128:
		keySpec = "AES_128"
	case 192:
		keySpec = "AES_192"
	case 256:
		keySpec = "AES_256"
	}

	return &backend.ImportParameters{
		WrappingPublicKey: &privateKey.PublicKey,
		ImportToken:       []byte(token),
		Algorithm:         algorithm,
		ExpiresAt:         &expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps symmetric key material for secure transport using the specified parameters.
// Uses pkg/crypto/wrapping to wrap the key material.
func (b *Backend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, fmt.Errorf("%w: key material cannot be nil or empty", backend.ErrInvalidAttributes)
	}

	if params == nil {
		return nil, fmt.Errorf("%w: import parameters cannot be nil", backend.ErrInvalidAttributes)
	}

	// Validate key material is a valid symmetric key size
	keySize := len(keyMaterial)
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("%w: invalid symmetric key size %d bytes (must be 16, 24, or 32)", backend.ErrInvalidAttributes, keySize)
	}

	// Ensure we have an RSA public key
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: wrapping public key must be RSA", backend.ErrInvalidKeyType)
	}

	var wrapped []byte
	var err error

	// Wrap based on algorithm
	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Direct RSA-OAEP wrapping (suitable for symmetric keys which are small)
		wrapped, err = wrapping.WrapRSAOAEP(keyMaterial, rsaPubKey, params.Algorithm)

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Hybrid wrapping (RSA + AES-KWP)
		wrapped, err = wrapping.WrapRSAAES(keyMaterial, rsaPubKey, params.Algorithm)

	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, params.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to wrap key material: %w", err)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey unwraps key material using the stored RSA private key.
// The import token is used to retrieve the corresponding private key.
func (b *Backend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if wrapped == nil {
		return nil, fmt.Errorf("%w: wrapped key material cannot be nil", backend.ErrInvalidAttributes)
	}

	if params == nil {
		return nil, fmt.Errorf("%w: import parameters cannot be nil", backend.ErrInvalidAttributes)
	}

	if len(wrapped.ImportToken) == 0 {
		return nil, fmt.Errorf("%w: import token cannot be nil or empty", backend.ErrInvalidAttributes)
	}

	// Retrieve the private key using the import token
	/* Convert to string for map key */

	b.wrappingKeysMutex.RLock()
	privateKey, exists := b.wrappingKeys[string(wrapped.ImportToken)]
	b.wrappingKeysMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("%w: invalid or expired import token", backend.ErrKeyNotFound)
	}

	var unwrapped []byte
	var err error

	// Unwrap based on algorithm
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Direct RSA-OAEP unwrapping
		unwrapped, err = wrapping.UnwrapRSAOAEP(wrapped.WrappedKey, privateKey, wrapped.Algorithm)

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Hybrid unwrapping (RSA + AES-KWP)
		unwrapped, err = wrapping.UnwrapRSAAES(wrapped.WrappedKey, privateKey, wrapped.Algorithm)

	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, wrapped.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key material: %w", err)
	}

	// Validate unwrapped key is a valid symmetric key size
	keySize := len(unwrapped)
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("%w: unwrapped key has invalid size %d bytes (must be 16, 24, or 32)", backend.ErrInvalidAttributes, keySize)
	}

	return unwrapped, nil
}

// ImportKey unwraps and imports symmetric key material into the backend.
// The key material is validated and stored using the backend's storage mechanism.
func (b *Backend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if attrs == nil {
		return fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	if err := attrs.Validate(); err != nil {
		return fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	// Check if key already exists
	keyID := attrs.ID()
	exists, err := storage.KeyExists(b.storage, keyID)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if exists {
		return fmt.Errorf("%w: %s", backend.ErrKeyAlreadyExists, keyID)
	}

	// Create import parameters to pass to UnwrapKey
	// We need to retrieve the wrapping key, but we'll do it inside UnwrapKey
	params := &backend.ImportParameters{
		ImportToken: wrapped.ImportToken,
		Algorithm:   wrapped.Algorithm,
	}

	// Unwrap the key material
	keyData, err := b.UnwrapKey(wrapped, params)
	if err != nil {
		return fmt.Errorf("failed to unwrap key material: %w", err)
	}

	// Validate key size matches attributes
	expectedSize := attrs.SymmetricAlgorithm.KeySize() / 8
	if len(keyData) != expectedSize {
		return fmt.Errorf("%w: unwrapped key size (%d bytes) does not match expected size (%d bytes)",
			backend.ErrInvalidAttributes, len(keyData), expectedSize)
	}

	// Store the key using the existing storage mechanism
	if err := b.storeSymmetricKey(keyID, keyData, attrs.Password); err != nil {
		return fmt.Errorf("failed to store imported key: %w", err)
	}

	// Clean up the wrapping key after successful import
	if wrapped.ImportToken != nil {
		token := string(wrapped.ImportToken)
		b.wrappingKeysMutex.Lock()
		delete(b.wrappingKeys, token)
		b.wrappingKeysMutex.Unlock()
	}

	return nil
}

// ExportKey exports a symmetric key in wrapped form for secure transport.
// The key is retrieved and wrapped using the specified algorithm.
func (b *Backend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
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

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	// Retrieve the key
	keyID := attrs.ID()
	keyData, err := storage.GetKey(b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, backend.ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	// Decode the key (handle password protection if necessary)
	rawKey, err := b.decodeSymmetricKey(keyData, attrs.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Generate import parameters for wrapping
	params, err := b.GetImportParameters(attrs, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate import parameters: %w", err)
	}

	// Wrap the key material
	wrapped, err := b.WrapKey(rawKey, params)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key material: %w", err)
	}

	return wrapped, nil
}

// GetTracker returns the AEAD safety tracker for this backend.
// This allows external code to inspect tracking state and configuration.
func (b *Backend) GetTracker() types.AEADSafetyTracker {
	return b.tracker
}

// GetRNG returns the configured RNG resolver for this backend.
// This allows external code to use the same RNG source for consistency.
func (b *Backend) GetRNG() cryptorand.Resolver {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.rng
}

// Verify interface compliance at compile time
var _ types.Backend = (*Backend)(nil)
var _ types.SymmetricBackend = (*Backend)(nil)
var _ types.SymmetricBackendWithTracking = (*Backend)(nil)
var _ backend.ImportExportBackend = (*Backend)(nil)
var _ types.SymmetricEncrypter = (*softwareSymmetricEncrypter)(nil)
