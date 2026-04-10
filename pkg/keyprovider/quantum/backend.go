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

// Package quantum provides a quantum-safe cryptographic backend using
// post-quantum algorithms (ML-DSA for signatures, ML-KEM for key encapsulation).
// ML-DSA uses cloudflare/circl (FIPS 204) and ML-KEM uses Go stdlib crypto/mlkem (FIPS 203).
package quantum

import (
	"context"
	"crypto"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mldsaSeedSize is the seed size for all ML-DSA security levels (32 bytes).
const mldsaSeedSize = mldsa44.SeedSize

// keyMetadata stores information needed to reconstruct quantum keys from
// deterministic seeds. For ML-DSA the Seed is 32 bytes; for ML-KEM it is 64 bytes.
type keyMetadata struct {
	Algorithm string `json:"algorithm"`
	PublicKey []byte `json:"public_key"`
	Seed      []byte `json:"seed"`
}

// Config holds configuration for the quantum backend.
type Config struct {
	// Tracker provides AEAD safety tracking (nonce uniqueness, bytes limits).
	// If nil, a default in-memory tracker will be created.
	Tracker types.AEADSafetyTracker
}

// mldsaKeyGenerator is the function signature for ML-DSA key generation from seed.
type mldsaKeyGenerator func(seed *[mldsaSeedSize]byte) (pkBytes []byte, sk any, pk any)

// mldsaKeyGenerators maps algorithm names to their key generation functions.
var mldsaKeyGenerators = map[string]mldsaKeyGenerator{
	"ML-DSA-44": func(seed *[mldsaSeedSize]byte) ([]byte, any, any) {
		pk, sk := mldsa44.NewKeyFromSeed(seed)
		return pk.Bytes(), sk, pk
	},
	"ML-DSA-65": func(seed *[mldsaSeedSize]byte) ([]byte, any, any) {
		pk, sk := mldsa65.NewKeyFromSeed(seed)
		return pk.Bytes(), sk, pk
	},
	"ML-DSA-87": func(seed *[mldsaSeedSize]byte) ([]byte, any, any) {
		pk, sk := mldsa87.NewKeyFromSeed(seed)
		return pk.Bytes(), sk, pk
	},
}

// mlkemKeyGenerator generates an ML-KEM key pair, returning the seed bytes,
// public key bytes, and the decapsulation key (as any).
type mlkemKeyGenerator func() (seed []byte, pubKey []byte, dk any, err error)

// mlkemKeyFromSeed reconstructs an ML-KEM decapsulation key from its seed,
// returning the public key bytes and decapsulation key (as any).
type mlkemKeyFromSeed func(seed []byte) (pubKey []byte, dk any, err error)

// mlkemGenerators maps algorithm names to their key generation functions.
var mlkemGenerators = map[string]mlkemKeyGenerator{
	"ML-KEM-768": func() ([]byte, []byte, any, error) {
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, nil, nil, err
		}
		return dk.Bytes(), dk.EncapsulationKey().Bytes(), dk, nil
	},
	"ML-KEM-1024": func() ([]byte, []byte, any, error) {
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, nil, nil, err
		}
		return dk.Bytes(), dk.EncapsulationKey().Bytes(), dk, nil
	},
}

// mlkemSeedLoaders maps algorithm names to their seed reconstruction functions.
var mlkemSeedLoaders = map[string]mlkemKeyFromSeed{
	"ML-KEM-768": func(seed []byte) ([]byte, any, error) {
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk, nil
	},
	"ML-KEM-1024": func(seed []byte) ([]byte, any, error) {
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk, nil
	},
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
	tracker types.AEADSafetyTracker
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

	var tracker types.AEADSafetyTracker
	if config != nil && config.Tracker != nil {
		tracker = config.Tracker
	} else {
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
		Signing:             true,
		Decryption:          false,
		KeyRotation:         true,
		SymmetricEncryption: false,
		Import:              true,
		Export:              true,
		KeyAgreement:        true,
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

	keyID := attrs.ID()
	exists, err := storage.KeyExists(context.Background(), b.storage, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to check key existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyAlreadyExists, keyID)
	}

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

	if err := b.storeKey(keyID, metadata); err != nil {
		return nil, err
	}

	// Initialize AEAD tracking for ML-KEM keys (they use AES-GCM internally)
	if strings.HasPrefix(algorithm, "ML-KEM") {
		aeadOpts := types.DefaultAEADOptions()
		if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
			fmt.Printf("Warning: failed to set AEAD options for key %s: %v\n", keyID, err)
		}
	}

	return privateKey, nil
}

// generateMLDSAKey generates a ML-DSA signing key using circl.
// A random 32-byte seed is generated and used to deterministically derive
// the key pair via NewKeyFromSeed, enabling seed-based reconstruction.
func (b *QuantumBackend) generateMLDSAKey(algorithm string) (*MLDSAPrivateKey, *keyMetadata, error) {
	gen, ok := mldsaKeyGenerators[algorithm]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	var seed [mldsaSeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	pkBytes, sk, pk := gen(&seed)

	privateKey := &MLDSAPrivateKey{
		Algorithm: algorithm,
		PublicKey: &MLDSAPublicKey{
			Algorithm: algorithm,
			Key:       pkBytes,
		},
		sk:   sk,
		pk:   pk,
		seed: seed[:],
	}

	metadata := &keyMetadata{
		Algorithm: algorithm,
		PublicKey: pkBytes,
		Seed:      seed[:],
	}

	return privateKey, metadata, nil
}

// generateMLKEMKey generates a ML-KEM key encapsulation key using Go stdlib crypto/mlkem.
func (b *QuantumBackend) generateMLKEMKey(algorithm, keyID string) (*MLKEMPrivateKey, *keyMetadata, error) {
	gen, ok := mlkemGenerators[algorithm]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	seedBytes, pubKeyBytes, dk, err := gen()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-KEM key pair: %w", err)
	}

	privateKey := &MLKEMPrivateKey{
		Algorithm: algorithm,
		PublicKey: &MLKEMPublicKey{
			Algorithm: algorithm,
			Key:       pubKeyBytes,
		},
		dk:      dk,
		seed:    seedBytes,
		tracker: b.tracker,
		keyID:   keyID,
	}

	metadata := &keyMetadata{
		Algorithm: algorithm,
		PublicKey: pubKeyBytes,
		Seed:      seedBytes,
	}

	return privateKey, metadata, nil
}

// storeKey stores key metadata using the storage backend.
func (b *QuantumBackend) storeKey(keyID string, metadata *keyMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize key metadata: %w", err)
	}

	if err := storage.SaveKey(context.Background(), b.storage, keyID, data); err != nil {
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
	keyData, err := storage.GetKey(context.Background(), b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
		}
		return nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	var metadata keyMetadata
	if err := json.Unmarshal(keyData, &metadata); err != nil {
		return nil, fmt.Errorf("failed to deserialize key metadata: %w", err)
	}

	switch {
	case strings.HasPrefix(metadata.Algorithm, "ML-DSA"):
		return b.loadMLDSAKey(&metadata)
	case strings.HasPrefix(metadata.Algorithm, "ML-KEM"):
		return b.loadMLKEMKey(&metadata, keyID)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, metadata.Algorithm)
	}
}

// loadMLDSAKey recreates a ML-DSA key from stored seed using circl's NewKeyFromSeed.
func (b *QuantumBackend) loadMLDSAKey(metadata *keyMetadata) (*MLDSAPrivateKey, error) {
	gen, ok := mldsaKeyGenerators[metadata.Algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, metadata.Algorithm)
	}

	if len(metadata.Seed) != mldsaSeedSize {
		return nil, fmt.Errorf("invalid ML-DSA seed size: got %d, want %d", len(metadata.Seed), mldsaSeedSize)
	}

	var seed [mldsaSeedSize]byte
	copy(seed[:], metadata.Seed)

	pkBytes, sk, pk := gen(&seed)

	return &MLDSAPrivateKey{
		Algorithm: metadata.Algorithm,
		PublicKey: &MLDSAPublicKey{
			Algorithm: metadata.Algorithm,
			Key:       pkBytes,
		},
		sk:   sk,
		pk:   pk,
		seed: seed[:],
	}, nil
}

// loadMLKEMKey recreates a ML-KEM key from stored seed using stdlib NewDecapsulationKey.
func (b *QuantumBackend) loadMLKEMKey(metadata *keyMetadata, keyID string) (*MLKEMPrivateKey, error) {
	loader, ok := mlkemSeedLoaders[metadata.Algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, metadata.Algorithm)
	}

	pubKeyBytes, dk, err := loader(metadata.Seed)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct ML-KEM key from seed: %w", err)
	}

	return &MLKEMPrivateKey{
		Algorithm: metadata.Algorithm,
		PublicKey: &MLKEMPublicKey{
			Algorithm: metadata.Algorithm,
			Key:       pubKeyBytes,
		},
		dk:      dk,
		seed:    metadata.Seed,
		tracker: b.tracker,
		keyID:   keyID,
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
	if err := storage.DeleteKey(context.Background(), b.storage, keyID); err != nil {
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

	keyIDs, err := storage.ListKeys(context.Background(), b.storage)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	attrs := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, id := range keyIDs {
		parts := strings.Split(id, ":")
		if len(parts) < 4 {
			continue
		}

		// Key ID format: storetype:keytype:cn:algorithm
		// Only include quantum keys (ml-dsa-* or ml-kem-*)
		algorithmStr := parts[len(parts)-1]
		algoLower := strings.ToLower(algorithmStr)
		if !strings.HasPrefix(algoLower, "ml-dsa") && !strings.HasPrefix(algoLower, "ml-kem") {
			continue
		}

		cn := parts[len(parts)-2]
		storeTypeStr := parts[0]
		keyTypeStr := parts[1]

		// Map the algorithm string back to a QuantumAlgorithm
		algo := types.QuantumAlgorithm(strings.ToUpper(algorithmStr))

		attr := &types.KeyAttributes{
			CN:        cn,
			StoreType: types.ParseStoreType(storeTypeStr),
			KeyType:   types.ParseKeyType(keyTypeStr),
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: algo,
			},
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

	exists, err := storage.KeyExists(context.Background(), b.storage, keyID)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyID)
	}

	keyData, err := storage.GetKey(context.Background(), b.storage, keyID)
	if err != nil {
		return fmt.Errorf("failed to retrieve key for rotation: %w", err)
	}

	var metadata keyMetadata
	if err := json.Unmarshal(keyData, &metadata); err != nil {
		return fmt.Errorf("failed to deserialize key metadata: %w", err)
	}

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

	if err := b.storeKey(keyID, newMetadata); err != nil {
		return fmt.Errorf("failed to store rotated key: %w", err)
	}

	// Reset AEAD tracking for the rotated key (ML-KEM only)
	if strings.HasPrefix(metadata.Algorithm, "ML-KEM") {
		if err := b.tracker.ResetTracking(keyID); err != nil {
			fmt.Printf("Warning: failed to reset AEAD tracking for rotated key %s: %v\n", keyID, err)
		}
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
