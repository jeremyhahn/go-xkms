// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package symmetric

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	chacha20poly1305pkg "github.com/jeremyhahn/go-xkms/pkg/crypto/chacha20poly1305"
	cryptorand "github.com/jeremyhahn/go-xkms/pkg/crypto/rand"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
		return &errs.Message{Msg: "config is nil"}
	}
	if c.KeyStorage == nil {
		return &errs.Message{Msg: "KeyStorage is required"}
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
func NewBackend(config *Config) (types.SymmetricKeyProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid config", Err: err}
	}

	// Create default tracker if none provided
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Create RNG resolver with default auto-detection if not provided
	rng, err := cryptorand.NewResolver(config.RNGConfig)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to initialize RNG", Err: err}
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
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: "use GenerateSymmetricKey instead"}
}

// GetKey is not supported by the symmetric backend (symmetric only).
// Use GetSymmetricKey instead.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: "use GetSymmetricKey instead"}
}

// DeleteKey removes a symmetric key identified by its attributes.
// Returns an error if the key does not exist.
func (b *Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()
	if err := storage.DeleteKey(ctx, b.storage, keyID); err != nil {
		if err == storage.ErrNotFound {
			return backend.ErrKeyNotFound
		}
		return &errs.Wrapped{Msg: "failed to delete key", Err: err}
	}

	// Remove the metadata record so a deleted key leaves no orphaned
	// Exportable flag behind for a future key ID collision to inherit.
	if err := b.deleteKeyMetadata(ctx, keyID); err != nil {
		return err
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
// Returns an empty slice if no keys exist.
func (b *Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyIDs, err := storage.ListKeys(ctx, b.storage)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys", Err: err}
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
		if !strings.EqualFold(keyTypeStr, "secret") {
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

		// Reload the metadata record to recover attributes the key ID string
		// has no room to encode. A missing/corrupt record (a key that
		// predates metadata persistence) is not an error: loadKeyMetadata
		// returns the safe Exportable=false default and ListKeys carries on.
		metadata := b.loadKeyMetadata(ctx, id)
		attr.Exportable = metadata.Exportable
		attr.Sensitive = metadata.Sensitive

		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// Signer is not supported by the symmetric backend (symmetric only).
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, backend.ErrOperationNotSupported
}

// Decrypter is not supported by the symmetric backend (symmetric only).
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrOperationNotSupported
}

// RotateKey rotates/updates a symmetric key identified by attrs.
// For symmetric keys, rotation means generating a new key and replacing the old one.
//
// AEAD Safety Tracking:
//   - Tracking state is reset (nonce history cleared, byte counters reset)
//   - New key starts with fresh tracking state
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
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
	if err := b.DeleteKey(ctx, attrs); err != nil && err != backend.ErrKeyNotFound {
		return &errs.Wrapped{Msg: "failed to delete old key", Err: err}
	}

	// Generate a new key with the same attributes (tracking will be re-initialized)
	_, err := b.GenerateSymmetricKey(ctx, attrs)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to generate new key", Err: err}
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
func (b *Backend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: attrs.KeyAlgorithm.String()}
	}

	// Check if key already exists
	keyID := attrs.ID()
	exists, err := storage.KeyExists(ctx, b.storage, keyID)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to check key existence", Err: err}
	}
	if exists {
		return nil, &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: keyID}
	}

	// Set up AEAD tracking with defaults if not specified
	aeadOpts := attrs.AEADOptions
	if aeadOpts == nil {
		aeadOpts = types.DefaultAEADOptions()
	}
	if err := aeadOpts.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid AEAD options", Err: err}
	}

	// Initialize tracking for this key
	if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to set AEAD options", Err: err}
	}

	// Generate random key bytes based on algorithm
	keySize := attrs.SymmetricAlgorithm.KeySize() / 8 // Convert bits to bytes

	keyData := make([]byte, keySize)
	if _, err := rand.Read(keyData); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate random key", Err: err}
	}

	// Create appropriate symmetric key based on algorithm
	var symmetricKey types.SymmetricKey
	var keyErr error
	switch attrs.SymmetricAlgorithm {
	case types.SymmetricChaCha20Poly1305, types.SymmetricXChaCha20Poly1305:
		symmetricKey, keyErr = NewChaCha20Key(string(attrs.SymmetricAlgorithm), keyData)
		if keyErr != nil {
			return nil, &errs.Wrapped{Msg: "failed to create ChaCha20 key", Err: keyErr}
		}
	default:
		symmetricKey, keyErr = NewAESKey(string(attrs.SymmetricAlgorithm), keyData)
		if keyErr != nil {
			return nil, &errs.Wrapped{Msg: "failed to create AES key", Err: keyErr}
		}
	}

	// Encode and store the key
	if err := b.storeSymmetricKey(ctx, keyID, keyData, attrs.Password); err != nil {
		return nil, err
	}

	// Persist the metadata record (currently just Exportable) that the key
	// ID string has no room to encode. This is the fix for the defect where
	// Exportable was honoured at creation but never survived a reload: it
	// must be saved before returning so a caller that immediately lists or
	// exports the key sees the same value it just requested.
	if err := b.saveKeyMetadata(ctx, keyID, attrs); err != nil {
		return nil, err
	}

	return symmetricKey, nil
}

// GetSymmetricKey retrieves an existing symmetric key by its attributes.
// Returns an error if the key does not exist.
func (b *Backend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: attrs.KeyAlgorithm.String()}
	}

	keyID := attrs.ID()
	keyData, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, backend.ErrKeyNotFound
		}
		return nil, &errs.Wrapped{Msg: "failed to retrieve key", Err: err}
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
func (b *Backend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	key, err := b.GetSymmetricKey(ctx, attrs)
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

	// AES-CBC and AES-CBC-PAD are non-AEAD: they take a different code path
	// entirely (no tag, no AEAD nonce/AAD, no AEAD safety tracking -- the
	// NIST SP 800-38D nonce-reuse and byte-limit rules below are specific to
	// GCM/ChaCha20-Poly1305 and do not apply to CBC).
	switch opts.Mode {
	case "":
		// Fall through to the AEAD path below (existing default behavior).
	case types.CipherModeCBC, types.CipherModeCBCPad:
		return e.encryptCBC(plaintext, opts)
	case types.CipherModeECB:
		return e.encryptECB(plaintext, opts)
	default:
		return nil, ErrUnsupportedCipherMode
	}

	// Get key ID for tracking
	keyID := e.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if e.tracker != nil {
		if err := e.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (consider rotating this key)"}
		}
	}

	// Get raw key bytes
	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get raw key", Err: err}
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
			return nil, &errs.Wrapped{Msg: "failed to create ChaCha20 cipher", Err: err}
		}

		// Poly1305 has no truncated form; see ErrTagSizeNotSupported.
		if opts.TagSize != 0 && opts.TagSize != chacha20Cipher.Overhead() {
			return nil, ErrTagSizeNotSupported
		}

		// STEP 2: Generate or use provided nonce
		var nonce []byte
		nonceSize := chacha20Cipher.NonceSize()
		if opts.Nonce != nil {
			nonce = opts.Nonce
			if len(nonce) != nonceSize {
				return nil, &errs.Message{Msg: fmt.Sprintf("invalid nonce size: %d (expected %d)", len(nonce), nonceSize)}
			}
		} else {
			// Use configured RNG for nonce generation
			nonce, err = e.rng.Rand(nonceSize)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to generate nonce", Err: err}
			}
		}

		// STEP 3: Check nonce uniqueness before encryption
		if e.tracker != nil {
			if err := e.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (CRITICAL: rotate this key immediately)"}
			}
		}

		// STEP 4: Perform encryption using ChaCha20 AEAD interface
		chacha20Opts := &types.EncryptOptions{
			Nonce:          nonce,
			AdditionalData: opts.AdditionalData,
		}
		encrypted, err = chacha20Cipher.Encrypt(plaintext, chacha20Opts)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "ChaCha20 encryption failed", Err: err}
		}

	default:
		// Use AES-GCM
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
		}

		gcm, err := newGCMWithTagSize(block, opts.TagSize)
		if err != nil {
			return nil, err
		}

		nonceSize := gcm.NonceSize()

		// STEP 2: Generate or use provided nonce
		var nonce []byte
		if opts.Nonce != nil {
			nonce = opts.Nonce
			if len(nonce) != nonceSize {
				return nil, &errs.Message{Msg: fmt.Sprintf("invalid nonce size: %d (expected %d)", len(nonce), nonceSize)}
			}
		} else {
			// Use configured RNG for nonce generation
			nonce, err = e.rng.Rand(nonceSize)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to generate nonce", Err: err}
			}
		}

		// STEP 3: Check nonce uniqueness before encryption
		if e.tracker != nil {
			if err := e.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (CRITICAL: rotate this key immediately)"}
			}
		}

		// STEP 4: Perform encryption with authentication
		ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, opts.AdditionalData)

		// Extract tag from end of ciphertext
		tagSize := gcm.Overhead()
		if len(ciphertextWithTag) < tagSize {
			return nil, &errs.Message{Msg: "ciphertext too short"}
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
		return nil, &errs.Message{Msg: "encrypted data is nil"}
	}

	switch opts.Mode {
	case "":
		// Fall through to the AEAD path below (existing default behavior).
	case types.CipherModeCBC, types.CipherModeCBCPad:
		return e.decryptCBC(data, opts)
	case types.CipherModeECB:
		return e.decryptECB(data, opts)
	default:
		return nil, ErrUnsupportedCipherMode
	}

	// Get raw key bytes
	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get raw key", Err: err}
	}

	// Reconstruct ciphertext with tag (AEAD ciphers expect tag appended)
	fullCiphertext := slices.Concat(data.Ciphertext, data.Tag)

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
			return nil, &errs.Wrapped{Msg: "failed to create ChaCha20 cipher", Err: err}
		}

		// Poly1305 has no truncated form; see ErrTagSizeNotSupported.
		if opts.TagSize != 0 && opts.TagSize != chacha20Cipher.Overhead() {
			return nil, ErrTagSizeNotSupported
		}

		// Decrypt and verify - use the ChaCha20 AEAD interface's Decrypt method
		plaintext, err = chacha20Cipher.Decrypt(data, &types.DecryptOptions{
			AdditionalData: opts.AdditionalData,
		})
		if err != nil {
			return nil, &errs.Wrapped{Msg: "decryption failed (authentication error)", Err: err}
		}

	default:
		// Use AES-GCM
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
		}

		// The tag length has to be reconstructed here, not inferred from the
		// tag that arrived: SP 800-38D section 5.2.2 verifies a t-bit tag by
		// recomputing the tag at t bits and comparing, so decrypting a
		// truncated tag under a full-length GCM rejects it as a forgery.
		// Taking the length from data.Tag instead of from opts would let an
		// attacker choose it, which is what SP 800-38D appendix C warns
		// against.
		gcm, err := newGCMWithTagSize(block, opts.TagSize)
		if err != nil {
			return nil, err
		}

		if len(data.Tag) != gcm.Overhead() {
			return nil, &errs.Message{Msg: fmt.Sprintf(
				"symmetric: authentication tag is %d bytes, want %d", len(data.Tag), gcm.Overhead())}
		}

		// crypto/cipher panics rather than returning an error when the nonce is
		// not exactly NonceSize bytes. The nonce arrives from the caller, so
		// without this check any request carrying a short nonce takes the whole
		// daemon down.
		if len(data.Nonce) != gcm.NonceSize() {
			return nil, &errs.Message{Msg: fmt.Sprintf(
				"symmetric: nonce is %d bytes, want %d", len(data.Nonce), gcm.NonceSize())}
		}

		// Decrypt and verify
		plaintext, err = gcm.Open(nil, data.Nonce, fullCiphertext, opts.AdditionalData)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "decryption failed (authentication error)", Err: err}
		}
	}

	return plaintext, nil
}

// newGCMWithTagSize builds an AES-GCM AEAD producing a tagSize-byte
// authentication tag, with zero selecting the full 16-byte tag. The tag-length
// rules live in pkg/crypto/aead so that every AES-GCM implementation in the
// stack answers the same way; this wrapper only maps the failure onto this
// package's sentinel so callers can match on ErrInvalidTagSize.
func newGCMWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	gcm, err := aead.NewGCM(block, tagSize)
	if err != nil {
		if errors.Is(err, aead.ErrInvalidGCMTagSize) {
			return nil, &errs.Detail{Err: ErrInvalidTagSize, Detail: err.Error()}
		}
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}
	return gcm, nil
}

// isAESCipherAlgorithm reports whether alg is one of the AES-family
// SymmetricAlgorithm values. AES-CBC and AES-CBC-PAD are only defined for
// AES keys; ChaCha20-Poly1305/XChaCha20-Poly1305 have no CBC mode.
func isAESCipherAlgorithm(alg types.SymmetricAlgorithm) bool {
	switch alg {
	case types.SymmetricAES128GCM, types.SymmetricAES192GCM, types.SymmetricAES256GCM:
		return true
	default:
		return false
	}
}

// encryptCBC implements types.CipherModeCBC (unpadded, PKCS#11's
// CKM_AES_CBC) and types.CipherModeCBCPad (PKCS#7-padded, PKCS#11's
// CKM_AES_CBC_PAD). AES-CBC is not an AEAD mode: it produces no
// authentication tag and accepts no additional authenticated data.
func (e *softwareSymmetricEncrypter) encryptCBC(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if !isAESCipherAlgorithm(e.attrs.SymmetricAlgorithm) {
		return nil, ErrCBCRequiresAES
	}
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	// AES-CBC produces no authentication tag at all, so a tag length is not
	// something this mode can honour. Accepting and ignoring it would report
	// success for an operation the caller did not get.
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}

	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get raw key", Err: err}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// crypto/cipher's NewCBCEncrypter panics if the IV is not exactly
	// block.BlockSize() bytes, so validate before calling it: a caller
	// -supplied IV of the wrong length must become a typed error, not a
	// daemon crash.
	iv := opts.IV
	if len(iv) == 0 {
		iv, err = e.rng.Rand(aes.BlockSize)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to generate IV", Err: err}
		}
	} else if len(iv) != aes.BlockSize {
		return nil, &errs.Detail{Err: ErrInvalidIVSize, Detail: fmt.Sprintf("got %d bytes, want %d", len(iv), aes.BlockSize)}
	}

	var toEncrypt []byte
	if opts.Mode == types.CipherModeCBCPad {
		toEncrypt = padPKCS7(plaintext, aes.BlockSize)
	} else {
		// Unpadded CBC: crypto/cipher's BlockMode.CryptBlocks panics on a
		// non-block-aligned input, so this must be checked before calling
		// it rather than left to panic on caller-supplied plaintext.
		if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
			return nil, ErrPlaintextNotBlockAligned
		}
		toEncrypt = plaintext
	}

	ciphertext := make([]byte, len(toEncrypt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, toEncrypt)

	return &types.EncryptedData{
		Ciphertext: ciphertext,
		IV:         iv,
		Algorithm:  e.key.Algorithm(),
	}, nil
}

// encryptECB implements types.CipherModeECB (PKCS#11's CKM_AES_ECB). Each
// 16-byte block is enciphered independently under the raw block cipher: there
// is no IV, no chaining and no authentication tag.
//
// SECURITY: ECB is deterministic. Two identical plaintext blocks produce two
// identical ciphertext blocks under the same key, which is exactly the
// structure leak the mode is known for. It is implemented because PKCS#11
// v3.2 §6.10.4 defines the mechanism and this module advertises it; a
// mechanism that is advertised and then quietly served by some other mode is
// worse than either offering it or refusing it, because the ciphertext no
// peer can reproduce still looks like success.
func (e *softwareSymmetricEncrypter) encryptECB(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if !isAESCipherAlgorithm(e.attrs.SymmetricAlgorithm) {
		return nil, ErrECBRequiresAES
	}
	// ECB authenticates nothing and takes no IV, so associated data, a tag
	// length and an IV are all things this mode cannot honour. Accepting and
	// ignoring any of them would report success for an operation the caller
	// did not get -- the same reasoning as the matching checks in encryptCBC.
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}
	if len(opts.IV) > 0 {
		return nil, ErrIVNotSupported
	}

	// crypto/cipher has no ECB BlockMode -- deliberately, because the mode is
	// unsafe as a general construction -- so the blocks are driven through
	// cipher.Block directly. That is the same primitive NewCBCEncrypter would
	// use, with no chaining applied.
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, ErrPlaintextNotBlockAligned
	}

	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get raw key", Err: err}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	ciphertext := make([]byte, len(plaintext))
	for offset := 0; offset < len(plaintext); offset += aes.BlockSize {
		block.Encrypt(ciphertext[offset:offset+aes.BlockSize], plaintext[offset:offset+aes.BlockSize])
	}

	return &types.EncryptedData{
		Ciphertext: ciphertext,
		Algorithm:  e.key.Algorithm(),
	}, nil
}

// decryptECB implements types.CipherModeECB decryption, the inverse of
// encryptECB.
func (e *softwareSymmetricEncrypter) decryptECB(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if !isAESCipherAlgorithm(e.attrs.SymmetricAlgorithm) {
		return nil, ErrECBRequiresAES
	}
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	if len(data.Tag) > 0 {
		return nil, &errs.Message{Msg: "symmetric: tag is not supported for AES-ECB"}
	}
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}
	// An IV on the wire means the ciphertext was produced by some other mode,
	// or the caller believes ECB uses one. Either way, decrypting it as ECB
	// would return plausible-looking garbage rather than an error.
	if len(data.IV) > 0 {
		return nil, ErrIVNotSupported
	}

	if len(data.Ciphertext) == 0 || len(data.Ciphertext)%aes.BlockSize != 0 {
		return nil, ErrCiphertextNotBlockAligned
	}

	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get raw key", Err: err}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	plaintext := make([]byte, len(data.Ciphertext))
	for offset := 0; offset < len(data.Ciphertext); offset += aes.BlockSize {
		block.Decrypt(plaintext[offset:offset+aes.BlockSize], data.Ciphertext[offset:offset+aes.BlockSize])
	}
	return plaintext, nil
}

// decryptCBC implements types.CipherModeCBC and types.CipherModeCBCPad
// decryption, the inverse of encryptCBC.
//
// SECURITY: padding removal for CipherModeCBCPad is delegated to
// unpadPKCS7, which validates padding length and content in constant time
// and returns a single ErrInvalidPadding for every failure mode. Do not add
// any branch here (or in unpadPKCS7) whose timing or error value depends on
// *how* the padding was invalid -- that is exactly the CBC padding-oracle
// primitive (Vaudenay, 2002) this function exists to close off.
func (e *softwareSymmetricEncrypter) decryptCBC(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if !isAESCipherAlgorithm(e.attrs.SymmetricAlgorithm) {
		return nil, ErrCBCRequiresAES
	}
	if len(opts.AdditionalData) > 0 {
		return nil, ErrAdditionalDataNotSupported
	}
	if len(data.Tag) > 0 {
		return nil, &errs.Message{Msg: "symmetric: tag is not supported for AES-CBC modes"}
	}
	// AES-CBC authenticates nothing, so there is no tag length to honour.
	// See the matching check in encryptCBC.
	if opts.TagSize != 0 {
		return nil, ErrTagSizeNotSupported
	}

	// crypto/cipher's NewCBCDecrypter panics if the IV is not exactly
	// block.BlockSize() bytes; validate before calling it.
	if len(data.IV) != aes.BlockSize {
		return nil, &errs.Detail{Err: ErrInvalidIVSize, Detail: fmt.Sprintf("got %d bytes, want %d", len(data.IV), aes.BlockSize)}
	}

	// crypto/cipher's BlockMode.CryptBlocks panics if its input is not a
	// whole number of blocks; validate before calling it. This depends only
	// on the caller-supplied ciphertext length, which is public information
	// independent of the key or plaintext, so it is not part of the padding
	// oracle that ErrInvalidPadding guards against below.
	if len(data.Ciphertext) == 0 || len(data.Ciphertext)%aes.BlockSize != 0 {
		return nil, ErrCiphertextNotBlockAligned
	}

	keyBytes, err := e.key.Raw()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get raw key", Err: err}
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	decrypted := make([]byte, len(data.Ciphertext))
	cipher.NewCBCDecrypter(block, data.IV).CryptBlocks(decrypted, data.Ciphertext)

	if opts.Mode == types.CipherModeCBCPad {
		return unpadPKCS7(decrypted, aes.BlockSize)
	}
	return decrypted, nil
}

// padPKCS7 appends PKCS#7 padding (RFC 5652 section 6.3) so data becomes a
// whole number of blockSize-byte blocks. When len(data) is already
// block-aligned, a full extra block of padding is appended -- this is
// required for unambiguous unpadding, since otherwise a legitimately
// block-aligned plaintext would be indistinguishable from one with its
// trailing padding already stripped.
func padPKCS7(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// unpadPKCS7 removes PKCS#7 padding from a decrypted AES-CBC plaintext.
// data's length must already be verified as a positive multiple of
// blockSize by the caller (decryptCBC checks the ciphertext length before
// decrypting, and CBC preserves length).
//
// Both ways unpadding can fail -- a padding-length byte outside [1,
// blockSize], or padding bytes that don't match that length -- return the
// identical ErrInvalidPadding, and the check runs in constant time relative
// to the padding length: the loop always scans the full last block and
// never branches on the untrusted length byte. This is the standard
// defense against a CBC padding oracle (Vaudenay, 2002): a decryption
// service that reveals *why* (or measurably how fast) unpadding failed lets
// an attacker recover plaintext one byte at a time without the key.
func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}

	padLen := int(data[len(data)-1])

	// good is 1 only if padLen is a plausible PKCS#7 length, i.e. in
	// [1, blockSize]. Computed without branching on padLen.
	good := subtle.ConstantTimeLessOrEq(1, padLen) & subtle.ConstantTimeLessOrEq(padLen, blockSize)

	lastBlock := data[len(data)-blockSize:]
	for i := 0; i < blockSize; i++ {
		// pos is the 1-based distance of byte i from the end of the block.
		pos := blockSize - i
		// isPadByte is 1 iff position pos falls within the claimed padding.
		isPadByte := subtle.ConstantTimeLessOrEq(pos, padLen)
		eq := subtle.ConstantTimeByteEq(lastBlock[i], byte(padLen))
		// A claimed padding byte that doesn't equal padLen invalidates the
		// result, but every iteration always runs regardless of padLen.
		mismatch := isPadByte & (1 - eq)
		good &= 1 - mismatch
	}

	if good != 1 {
		return nil, ErrInvalidPadding
	}
	return data[:len(data)-padLen], nil
}

// storeSymmetricKey stores a symmetric key, optionally encrypted with a password.
// Uses Argon2id for password-based key derivation with parameters:
// - time=1, memory=64MB, threads=4, keyLen=32
func (b *Backend) storeSymmetricKey(ctx context.Context, keyID string, keyData []byte, password types.Password) error {
	var storedData []byte

	if password != nil {
		passwordBytes := password.Bytes()
		if len(passwordBytes) > 0 {
			// Encrypt key data using AES-256-GCM with password-derived key
			var err error
			storedData, err = encryptWithPassword(keyData, passwordBytes)
			if err != nil {
				return &errs.Wrapped{Msg: "failed to encrypt key", Err: err}
			}
		} else {
			storedData = keyData
		}
	} else {
		storedData = keyData
	}

	if err := storage.SaveKey(ctx, b.storage, keyID, storedData); err != nil {
		return &errs.Wrapped{Msg: "failed to save key", Err: err}
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
		return nil, &errs.Wrapped{Msg: "failed to generate salt", Err: err}
	}

	// Derive encryption key using Argon2id
	// Parameters: time=1, memory=64MB, threads=4, keyLen=32
	derivedKey := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the same 96-bit nonce this code prepended by hand and Open strips it, so
	// the stored [salt][nonce][ciphertext+tag] layout is byte-for-byte what it
	// was and blobs written by earlier builds still decrypt.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Encrypt with salt as additional authenticated data. Seal emits
	// nonce || ciphertext+tag, so prefixing the salt reproduces the existing
	// [salt][nonce][ciphertext+tag] format exactly.
	sealed := gcm.Seal(nil, nil, keyData, salt)

	result := make([]byte, 0, len(salt)+len(sealed))
	result = append(result, salt...)
	result = append(result, sealed...)

	return result, nil
}

// decryptWithPassword decrypts key data using a password-derived key.
// Expected format: [salt][nonce][ciphertext+tag]
func decryptWithPassword(encryptedData, password []byte) ([]byte, error) {
	// Minimum size: 32 (salt) + 12 (nonce) + 16 (tag) = 60 bytes
	if len(encryptedData) < 60 {
		return nil, &errs.Message{Msg: fmt.Sprintf("encrypted data too short: %d bytes (minimum 60)", len(encryptedData))}
	}

	// Extract components. The nonce stays where it always was, at offset 32;
	// Open reads it from the front of the blob handed to it rather than from a
	// separate argument.
	salt := encryptedData[0:32]
	nonceAndCiphertext := encryptedData[32:]

	// Derive encryption key using same parameters as encryption
	derivedKey := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the same 96-bit nonce this code prepended by hand and Open strips it, so
	// the stored [salt][nonce][ciphertext+tag] layout is byte-for-byte what it
	// was and blobs written by earlier builds still decrypt.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Decrypt with salt as additional authenticated data
	plaintext, err := gcm.Open(nil, nil, nonceAndCiphertext, salt)
	if err != nil {
		return nil, ErrInvalidPassword
	}

	return plaintext, nil
}

// GetImportParameters generates RSA wrapping key pair for importing symmetric keys.
// The private key is stored in memory with a UUID token, and the public key
// is returned for use in wrapping operations.
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrStorageClosed
	}
	b.mu.RUnlock()

	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	// Validate wrapping algorithm
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported algorithms
	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: algorithm.String()}
	}

	// Generate 2048-bit RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate RSA key pair", Err: err}
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
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key material cannot be nil or empty"}
	}

	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}

	// Validate key material is a valid symmetric key size
	keySize := len(keyMaterial)
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("invalid symmetric key size %d bytes (must be 16, 24, or 32)", keySize)}
	}

	// Ensure we have an RSA public key
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "wrapping public key must be RSA"}
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
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: params.Algorithm.String()}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key material", Err: err}
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
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if wrapped == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material cannot be nil"}
	}

	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}

	if len(wrapped.ImportToken) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import token cannot be nil or empty"}
	}

	// Retrieve the private key using the import token
	/* Convert to string for map key */

	b.wrappingKeysMutex.RLock()
	privateKey, exists := b.wrappingKeys[string(wrapped.ImportToken)]
	b.wrappingKeysMutex.RUnlock()

	if !exists {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: "invalid or expired import token"}
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
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: wrapped.Algorithm.String()}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unwrap key material", Err: err}
	}

	// Validate unwrapped key is a valid symmetric key size
	keySize := len(unwrapped)
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("unwrapped key has invalid size %d bytes (must be 16, 24, or 32)", keySize)}
	}

	return unwrapped, nil
}

// ImportKey unwraps and imports symmetric key material into the backend.
// The key material is validated and stored using the backend's storage mechanism.
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if attrs == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	if err := attrs.Validate(); err != nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: attrs.KeyAlgorithm.String()}
	}

	// Check if key already exists
	keyID := attrs.ID()
	exists, err := storage.KeyExists(ctx, b.storage, keyID)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to check key existence", Err: err}
	}
	if exists {
		return &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: keyID}
	}

	// Create import parameters to pass to UnwrapKey
	// We need to retrieve the wrapping key, but we'll do it inside UnwrapKey
	params := &backend.ImportParameters{
		ImportToken: wrapped.ImportToken,
		Algorithm:   wrapped.Algorithm,
	}

	// Unwrap the key material
	keyData, err := b.UnwrapKey(ctx, wrapped, params)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to unwrap key material", Err: err}
	}

	// Validate key size matches attributes
	expectedSize := attrs.SymmetricAlgorithm.KeySize() / 8
	if len(keyData) != expectedSize {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("unwrapped key size (%d bytes) does not match expected size (%d bytes)", len(keyData), expectedSize)}
	}

	// Store the key using the existing storage mechanism
	if err := b.storeSymmetricKey(ctx, keyID, keyData, attrs.Password); err != nil {
		return &errs.Wrapped{Msg: "failed to store imported key", Err: err}
	}

	// Imported keys go through the same defect as generated ones: the
	// caller's Exportable attribute has nowhere to live besides this
	// metadata record, so it must be persisted here too.
	if err := b.saveKeyMetadata(ctx, keyID, attrs); err != nil {
		return err
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
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
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
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: attrs.KeyAlgorithm.String()}
	}

	// Retrieve the key
	keyID := attrs.ID()
	keyData, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, backend.ErrKeyNotFound
		}
		return nil, &errs.Wrapped{Msg: "failed to retrieve key", Err: err}
	}

	// Decode the key (handle password protection if necessary)
	rawKey, err := b.decodeSymmetricKey(keyData, attrs.Password)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode key", Err: err}
	}

	// Generate import parameters for wrapping
	params, err := b.GetImportParameters(ctx, attrs, algorithm)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate import parameters", Err: err}
	}

	// Wrap the key material
	wrapped, err := b.WrapKey(ctx, rawKey, params)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key material", Err: err}
	}

	return wrapped, nil
}

// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
// This method provides direct access to the plaintext key bytes without wrapping.
//
// Security restrictions:
//   - ONLY works for symmetric keys (this backend only handles symmetric keys)
//   - Key must have Exportable=true (equivalent to PKCS#11 CKA_EXTRACTABLE=true)
//   - Returns ErrKeyNotExportable if the key is not marked as exportable
//
// For secure key transport between backends, prefer ExportKey which wraps the material.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// This backend only handles symmetric keys, but we still check for consistency
	if !attrs.IsSymmetric() {
		return nil, backend.ErrAsymmetricKeyExportNotAllowed
	}

	// Check if key is marked as exportable (CKA_EXTRACTABLE equivalent)
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	// Retrieve the key
	keyID := attrs.ID()
	keyData, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, backend.ErrKeyNotFound
		}
		return nil, &errs.Wrapped{Msg: "failed to retrieve key", Err: err}
	}

	// Decode the key (handle password protection if necessary)
	rawKey, err := b.decodeSymmetricKey(keyData, attrs.Password)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode key", Err: err}
	}

	return rawKey, nil
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
var _ types.KeyProvider = (*Backend)(nil)
var _ types.SymmetricKeyProvider = (*Backend)(nil)
var _ types.SymmetricKeyProviderWithTracking = (*Backend)(nil)
var _ backend.ImportExportBackend = (*Backend)(nil)
var _ types.SymmetricEncrypter = (*softwareSymmetricEncrypter)(nil)
