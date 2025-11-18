//go:build quantum

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

// Package quantum provides a quantum-safe cryptographic backend using
// post-quantum algorithms (ML-DSA for signatures, ML-KEM for key encapsulation).
// This backend integrates with the keychain interface for quantum-resistant operations.
package quantum

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// keyMetadata stores additional information about quantum keys
type keyMetadata struct {
	Algorithm string `json:"algorithm"`
	PublicKey []byte `json:"public_key"`
	SecretKey []byte `json:"secret_key"`
}

// Config holds configuration for the quantum backend
type Config struct {
	// Tracker provides AEAD safety tracking (nonce uniqueness, bytes limits)
	// If nil, a default in-memory tracker will be created
	Tracker types.AEADSafetyTracker
}

// QuantumBackend implements the Backend interface for post-quantum cryptography.
// It supports ML-DSA for digital signatures and ML-KEM for key encapsulation.
//
// AEAD Safety: ML-KEM encryption uses AES-256-GCM internally. The backend tracks
// nonces and encrypted bytes to enforce NIST SP 800-38D safety limits.
//
// Thread-safe: Yes, uses a read-write mutex for concurrent access.
type QuantumBackend struct {
	storage storage.Backend
	tracker types.AEADSafetyTracker // AEAD safety tracker for ML-KEM encryption
	closed  bool
	mu      sync.RWMutex
}

// New creates a new QuantumBackend with the given storage backend.
// The config parameter is optional; if nil, defaults will be used.
func New(store storage.Backend) (*QuantumBackend, error) {
	return NewWithConfig(store, nil)
}

// NewWithConfig creates a new QuantumBackend with the given storage and configuration.
func NewWithConfig(store storage.Backend, config *Config) (*QuantumBackend, error) {
	if store == nil {
		return nil, fmt.Errorf("storage backend cannot be nil")
	}

	// Use provided tracker or create default
	var tracker types.AEADSafetyTracker
	if config != nil && config.Tracker != nil {
		tracker = config.Tracker
	} else {
		// Create default in-memory tracker
		tracker = backend.NewMemoryAEADTracker()
	}

	return &QuantumBackend{
		storage: store,
		tracker: tracker,
	}, nil
}

// Type returns the backend type identifier.
func (b *QuantumBackend) Type() types.BackendType {
	return types.BackendTypeQuantum
}

// Capabilities returns what features this backend supports.
func (b *QuantumBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,  // ML-DSA supports signing
		Decryption:          false, // ML-KEM uses encapsulation, not direct decryption
		KeyRotation:         true,
		SymmetricEncryption: false,
		Import:              true,
		Export:              true,
		KeyAgreement:        true, // ML-KEM provides key encapsulation (similar to key agreement)
		ECIES:               false,
	}
}

// GenerateKey generates a new quantum-safe key with the given attributes.
func (b *QuantumBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	if attrs.QuantumAttributes == nil {
		return nil, ErrInvalidQuantumAttributes
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
	var metadata *keyMetadata

	algorithm := string(attrs.QuantumAttributes.Algorithm)

	switch {
	case strings.HasPrefix(algorithm, "ML-DSA"):
		privateKey, metadata, err = b.generateMLDSAKey(algorithm)
	case strings.HasPrefix(algorithm, "ML-KEM"):
		privateKey, metadata, err = b.generateMLKEMKey(algorithm, keyID)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Store the key metadata
	if err := b.storeKey(keyID, metadata); err != nil {
		return nil, err
	}

	// Initialize AEAD tracking for ML-KEM keys (they use AES-GCM internally)
	if strings.HasPrefix(algorithm, "ML-KEM") {
		aeadOpts := types.DefaultAEADOptions()
		if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
			// Log warning but don't fail - tracking is best-effort
			fmt.Printf("Warning: failed to set AEAD options for key %s: %v\n", keyID, err)
		}
	}

	return privateKey, nil
}

// generateMLDSAKey generates a ML-DSA (Dilithium) signing key
func (b *QuantumBackend) generateMLDSAKey(algorithm string) (*MLDSAPrivateKey, *keyMetadata, error) {
	signer := oqs.Signature{}
	if err := signer.Init(algorithm, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize ML-DSA: %w", err)
	}

	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		signer.Clean()
		return nil, nil, fmt.Errorf("failed to generate ML-DSA key pair: %w", err)
	}

	secretKey := signer.ExportSecretKey()

	privateKey := &MLDSAPrivateKey{
		Algorithm: algorithm,
		PublicKey: &MLDSAPublicKey{
			Algorithm: algorithm,
			Key:       pubKey,
		},
		signer: &signer,
	}

	metadata := &keyMetadata{
		Algorithm: algorithm,
		PublicKey: pubKey,
		SecretKey: secretKey,
	}

	return privateKey, metadata, nil
}

// generateMLKEMKey generates a ML-KEM (Kyber) key encapsulation key
func (b *QuantumBackend) generateMLKEMKey(algorithm, keyID string) (*MLKEMPrivateKey, *keyMetadata, error) {
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(algorithm, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize ML-KEM: %w", err)
	}

	pubKey, err := kem.GenerateKeyPair()
	if err != nil {
		kem.Clean()
		return nil, nil, fmt.Errorf("failed to generate ML-KEM key pair: %w", err)
	}

	secretKey := kem.ExportSecretKey()

	privateKey := &MLKEMPrivateKey{
		Algorithm: algorithm,
		PublicKey: &MLKEMPublicKey{
			Algorithm: algorithm,
			Key:       pubKey,
		},
		kem:     &kem,
		tracker: b.tracker, // Pass AEAD tracker for encryption safety
		keyID:   keyID,     // Pass keyID for tracking
	}

	metadata := &keyMetadata{
		Algorithm: algorithm,
		PublicKey: pubKey,
		SecretKey: secretKey,
	}

	return privateKey, metadata, nil
}

// storeKey stores key metadata using the storage backend
func (b *QuantumBackend) storeKey(keyID string, metadata *keyMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize key metadata: %w", err)
	}

	if err := storage.SaveKey(b.storage, keyID, data); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	return nil
}

// GetKey retrieves an existing quantum-safe key by its attributes.
func (b *QuantumBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
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

	// Decode the metadata
	var metadata keyMetadata
	if err := json.Unmarshal(keyData, &metadata); err != nil {
		return nil, fmt.Errorf("failed to deserialize key metadata: %w", err)
	}

	// Recreate the key
	switch {
	case strings.HasPrefix(metadata.Algorithm, "ML-DSA"):
		return b.loadMLDSAKey(&metadata)
	case strings.HasPrefix(metadata.Algorithm, "ML-KEM"):
		return b.loadMLKEMKey(&metadata, keyID)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, metadata.Algorithm)
	}
}

// loadMLDSAKey recreates a ML-DSA key from stored metadata
func (b *QuantumBackend) loadMLDSAKey(metadata *keyMetadata) (*MLDSAPrivateKey, error) {
	signer := oqs.Signature{}
	if err := signer.Init(metadata.Algorithm, metadata.SecretKey); err != nil {
		return nil, fmt.Errorf("failed to initialize ML-DSA from stored key: %w", err)
	}

	return &MLDSAPrivateKey{
		Algorithm: metadata.Algorithm,
		PublicKey: &MLDSAPublicKey{
			Algorithm: metadata.Algorithm,
			Key:       metadata.PublicKey,
		},
		signer: &signer,
	}, nil
}

// loadMLKEMKey recreates a ML-KEM key from stored metadata
func (b *QuantumBackend) loadMLKEMKey(metadata *keyMetadata, keyID string) (*MLKEMPrivateKey, error) {
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(metadata.Algorithm, metadata.SecretKey); err != nil {
		return nil, fmt.Errorf("failed to initialize ML-KEM from stored key: %w", err)
	}

	return &MLKEMPrivateKey{
		Algorithm: metadata.Algorithm,
		PublicKey: &MLKEMPublicKey{
			Algorithm: metadata.Algorithm,
			Key:       metadata.PublicKey,
		},
		kem:     &kem,
		tracker: b.tracker, // Pass AEAD tracker for encryption safety
		keyID:   keyID,     // Pass keyID for tracking
	}, nil
}

// DeleteKey removes a key identified by its attributes.
func (b *QuantumBackend) DeleteKey(attrs *types.KeyAttributes) error {
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
func (b *QuantumBackend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyIDs, err := storage.ListKeys(b.storage)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	attrs := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, id := range keyIDs {
		parts := strings.Split(id, ":")
		var cn string

		if len(parts) >= 4 {
			cn = parts[len(parts)-2]
		} else {
			cn = id
		}

		attr := &types.KeyAttributes{
			CN: cn,
		}
		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
// Only ML-DSA keys support signing.
func (b *QuantumBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
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
// ML-KEM keys use Key Encapsulation Mechanism, not direct decryption.
// This method returns an error as ML-KEM doesn't fit the crypto.Decrypter interface.
// Use the MLKEMPrivateKey directly for encapsulation/decapsulation operations.
func (b *QuantumBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrKeyNotDecrypter
}

// RotateKey rotates/updates a key identified by attrs.
func (b *QuantumBackend) RotateKey(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	keyID := attrs.ID()

	// Check if key exists
	exists, err := storage.KeyExists(b.storage, keyID)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
	}

	// Get existing key to determine algorithm
	keyData, err := storage.GetKey(b.storage, keyID)
	if err != nil {
		return fmt.Errorf("failed to retrieve key for rotation: %w", err)
	}

	var metadata keyMetadata
	if err := json.Unmarshal(keyData, &metadata); err != nil {
		return fmt.Errorf("failed to deserialize key metadata: %w", err)
	}

	// Generate new key with same algorithm
	var newMetadata *keyMetadata

	switch {
	case strings.HasPrefix(metadata.Algorithm, "ML-DSA"):
		_, newMetadata, err = b.generateMLDSAKey(metadata.Algorithm)
	case strings.HasPrefix(metadata.Algorithm, "ML-KEM"):
		_, newMetadata, err = b.generateMLKEMKey(metadata.Algorithm, keyID)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, metadata.Algorithm)
	}

	if err != nil {
		return fmt.Errorf("failed to generate new key for rotation: %w", err)
	}

	// Store the new key
	if err := b.storeKey(keyID, newMetadata); err != nil {
		return fmt.Errorf("failed to store rotated key: %w", err)
	}

	// Reset AEAD tracking for the rotated key (ML-KEM only)
	if strings.HasPrefix(metadata.Algorithm, "ML-KEM") {
		if err := b.tracker.ResetTracking(keyID); err != nil {
			// Log warning but don't fail - tracking is best-effort
			fmt.Printf("Warning: failed to reset AEAD tracking for rotated key %s: %v\n", keyID, err)
		}
		// Re-initialize AEAD options with defaults
		aeadOpts := types.DefaultAEADOptions()
		if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
			fmt.Printf("Warning: failed to set AEAD options for rotated key %s: %v\n", keyID, err)
		}
	}

	return nil
}

// Close releases any resources held by the backend.
func (b *QuantumBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	return nil
}
