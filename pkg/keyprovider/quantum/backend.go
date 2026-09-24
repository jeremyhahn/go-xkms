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
// Both use the Go standard library: ML-DSA via crypto/mldsa (FIPS 204) and
// ML-KEM via crypto/mlkem (FIPS 203). Neither keeps an approved-algorithm
// allowlist of its own — under a FIPS-140 build whose selected module
// version does not yet certify an algorithm, the stdlib functions this
// package calls refuse on their own (go-xkms #21).
package quantum

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// mldsaSeedSize is the seed size for all ML-DSA security levels (32 bytes).
const mldsaSeedSize = mldsa.PrivateKeySize

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
type mldsaKeyGenerator func(seed *[mldsaSeedSize]byte) (pkBytes []byte, sk any, pk any, err error)

// mldsaGenerator returns a key-generation closure for the given ML-DSA
// parameter set, sharing one seed-to-keypair path across all three security
// levels rather than repeating it per algorithm.
func mldsaGenerator(params mldsa.Parameters) mldsaKeyGenerator {
	return func(seed *[mldsaSeedSize]byte) ([]byte, any, any, error) {
		sk, err := mldsa.NewPrivateKey(params, seed[:])
		if err != nil {
			return nil, nil, nil, err
		}
		pk := sk.PublicKey()
		pkBytes := pk.Bytes()
		return pkBytes, sk, pk, nil
	}
}

// mldsaKeyGenerators maps algorithm names to their key generation functions.
var mldsaKeyGenerators = map[string]mldsaKeyGenerator{
	"ML-DSA-44": mldsaGenerator(mldsa.MLDSA44()),
	"ML-DSA-65": mldsaGenerator(mldsa.MLDSA65()),
	"ML-DSA-87": mldsaGenerator(mldsa.MLDSA87()),
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
		return nil, &errs.Message{Msg: "storage backend cannot be nil"}
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
func (b *QuantumBackend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if attrs.QuantumAttributes == nil {
		return nil, ErrInvalidQuantumAttributes
	}

	keyID := attrs.ID()
	exists, err := storage.KeyExists(ctx, b.storage, keyID)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to check key existence", Err: err}
	}
	if exists {
		return nil, &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: keyID}
	}

	var privateKey crypto.PrivateKey
	var metadata *keyMetadata

	// The generated key owns an mlocked enclave holding the reconstruction
	// seed. Until it is handed to the caller, every error path has to destroy
	// it rather than leave protected memory to the garbage collector.
	handedOff := false
	defer func() {
		if !handedOff {
			cleanPrivateKey(privateKey)
		}
	}()

	quantumAlgo := attrs.QuantumAttributes.Algorithm
	algorithm := string(quantumAlgo)

	switch {
	case quantumAlgo.IsSignature():
		privateKey, metadata, err = b.generateMLDSAKey(algorithm)
	case quantumAlgo.IsKEM():
		privateKey, metadata, err = b.generateMLKEMKey(algorithm, keyID)
	default:
		return nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: algorithm}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "key generation failed", Err: err}
	}

	if err := b.storeKey(ctx, keyID, metadata); err != nil {
		return nil, err
	}

	// Initialize AEAD tracking for ML-KEM keys (they use AES-GCM internally)
	if quantumAlgo.IsKEM() {
		aeadOpts := types.DefaultAEADOptions()
		if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
			fmt.Printf("Warning: failed to set AEAD options for key %s: %v\n", keyID, err)
		}
	}

	handedOff = true
	return privateKey, nil
}

// cleanPrivateKey destroys the enclave a generated quantum key holds. It exists
// so error paths can release protected memory without repeating the type switch,
// and it tolerates a nil or unrecognised key so a deferred call is always safe.
func cleanPrivateKey(key crypto.PrivateKey) {
	switch k := key.(type) {
	case *MLDSAPrivateKey:
		k.Clean()
	case *MLKEMPrivateKey:
		k.Clean()
	}
}

// sealSeed seals a copy of src into an enclave and leaves src to the caller.
// It copies because secure.NewSecret consumes the slice it is handed, while
// every call site here still needs src afterwards — either to build the
// metadata that gets serialized to storage, or because src belongs to the
// caller. Wiping src, where that is this package's to do, is the caller's job.
func sealSeed(src []byte) (*secure.Secret, error) {
	owned := make([]byte, len(src))
	copy(owned, src)
	sealed, err := secure.NewSecret(owned)
	if err != nil {
		secure.Wipe(owned)
		return nil, &errs.Wrapped{Msg: "failed to seal key seed", Err: err}
	}
	return sealed, nil
}

// generateMLDSAKey generates a ML-DSA signing key using crypto/mldsa.
// A random 32-byte seed is generated and used to deterministically derive
// the key pair via NewKeyFromSeed, enabling seed-based reconstruction.
func (b *QuantumBackend) generateMLDSAKey(algorithm string) (*MLDSAPrivateKey, *keyMetadata, error) {
	gen, ok := mldsaKeyGenerators[algorithm]
	if !ok {
		return nil, nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: algorithm}
	}

	var seed [mldsaSeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to generate seed", Err: err}
	}
	// Deferred, not wiped inline at the end: sealSeed can fail (protected-memory
	// allocation, mlock), and the error path is exactly where leaving 32 bytes
	// of live seed on the stack matters most. Every return from here on wipes.
	// Both consumers below copy what they need before this runs.
	defer secure.Wipe(seed[:])

	pkBytes, sk, pk, err := gen(&seed)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to derive key pair from seed", Err: err}
	}

	// The seed feeds two consumers with different lifetimes: the in-memory key,
	// which holds it enclaved, and the metadata, which is serialized to
	// storage. Both take their own copy so the stack array can be wiped as soon
	// as they have it.
	sealedSeed, sealErr := sealSeed(seed[:])
	if sealErr != nil {
		return nil, nil, sealErr
	}

	metadataSeed := make([]byte, mldsaSeedSize)
	copy(metadataSeed, seed[:])

	privateKey := &MLDSAPrivateKey{
		Algorithm: algorithm,
		PublicKey: &MLDSAPublicKey{
			Algorithm: algorithm,
			Key:       pkBytes,
		},
		sk:   sk,
		pk:   pk,
		seed: sealedSeed,
	}

	metadata := &keyMetadata{
		Algorithm: algorithm,
		PublicKey: pkBytes,
		Seed:      metadataSeed,
	}

	return privateKey, metadata, nil
}

// generateMLKEMKey generates a ML-KEM key encapsulation key using Go stdlib crypto/mlkem.
func (b *QuantumBackend) generateMLKEMKey(algorithm, keyID string) (*MLKEMPrivateKey, *keyMetadata, error) {
	gen, ok := mlkemGenerators[algorithm]
	if !ok {
		return nil, nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: algorithm}
	}

	seedBytes, pubKeyBytes, dk, err := gen()
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to generate ML-KEM key pair", Err: err}
	}
	// Deferred for the same reason as generateMLDSAKey's seed: a sealSeed
	// failure must not return with the generator's seed still live on the heap.
	defer secure.Wipe(seedBytes)

	// As in generateMLDSAKey: the enclaved key and the serialized metadata each
	// take their own copy, and seedBytes is wiped once both are served.
	sealedSeed, sealErr := sealSeed(seedBytes)
	if sealErr != nil {
		return nil, nil, sealErr
	}

	metadataSeed := make([]byte, len(seedBytes))
	copy(metadataSeed, seedBytes)

	privateKey := &MLKEMPrivateKey{
		Algorithm: algorithm,
		PublicKey: &MLKEMPublicKey{
			Algorithm: algorithm,
			Key:       pubKeyBytes,
		},
		dk:      dk,
		seed:    sealedSeed,
		tracker: b.tracker,
		keyID:   keyID,
	}

	metadata := &keyMetadata{
		Algorithm: algorithm,
		PublicKey: pubKeyBytes,
		Seed:      metadataSeed,
	}

	return privateKey, metadata, nil
}

// storeKey stores key metadata using the storage backend.
//
// It consumes metadata.Seed: the seed reconstructs the whole private key, and
// the storage format is JSON, so a plaintext slice has to exist for the moment
// encoding/json reads it. Wiping it here — on the error paths too — bounds that
// exposure to this call rather than the lifetime of the process. Anything the
// key still needs afterwards lives in the enclave the private key holds.
//
// The marshalled document is deliberately not wiped. It is handed to
// storage.Backend.Put, whose contract does not say whether an implementation
// copies the slice or retains it, so zeroing it could zero what was stored.
// Protecting the serialized form is the storage layer's problem, not this one's.
func (b *QuantumBackend) storeKey(ctx context.Context, keyID string, metadata *keyMetadata) error {
	defer secure.Wipe(metadata.Seed)

	data, err := json.Marshal(metadata)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to serialize key metadata", Err: err}
	}

	if err := storage.SaveKey(ctx, b.storage, keyID, data); err != nil {
		return &errs.Wrapped{Msg: "failed to store key", Err: err}
	}

	return nil
}

// GetKey retrieves an existing quantum-safe key by its attributes.
func (b *QuantumBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()
	keyData, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: keyID}
		}
		return nil, &errs.Wrapped{Msg: "failed to retrieve key", Err: err}
	}

	var metadata keyMetadata
	if err := json.Unmarshal(keyData, &metadata); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize key metadata", Err: err}
	}
	// The decoded seed is plaintext key material this function owns —
	// encoding/json allocates it fresh. The loaders seal their own copy, so it
	// is wiped on return rather than left for the GC. keyData is left alone: it
	// came from storage.Backend.Get, which does not say whether the slice is a
	// copy or the stored record itself.
	defer secure.Wipe(metadata.Seed)

	switch {
	case types.QuantumAlgorithm(metadata.Algorithm).IsSignature():
		return b.loadMLDSAKey(&metadata)
	case types.QuantumAlgorithm(metadata.Algorithm).IsKEM():
		return b.loadMLKEMKey(&metadata, keyID)
	default:
		return nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: metadata.Algorithm}
	}
}

// loadMLDSAKey recreates a ML-DSA key from stored seed using crypto/mldsa's
// NewPrivateKey.
func (b *QuantumBackend) loadMLDSAKey(metadata *keyMetadata) (*MLDSAPrivateKey, error) {
	gen, ok := mldsaKeyGenerators[metadata.Algorithm]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: metadata.Algorithm}
	}

	if len(metadata.Seed) != mldsaSeedSize {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid ML-DSA seed size: got %d, want %d", len(metadata.Seed), mldsaSeedSize)}
	}

	var seed [mldsaSeedSize]byte
	copy(seed[:], metadata.Seed)

	pkBytes, sk, pk, err := gen(&seed)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to derive key pair from seed", Err: err}
	}

	// seed is this function's own stack copy, so it is wiped once sealed;
	// metadata.Seed belongs to the caller and is left intact.
	sealedSeed, sealErr := sealSeed(seed[:])
	if sealErr != nil {
		return nil, sealErr
	}
	secure.Wipe(seed[:])

	return &MLDSAPrivateKey{
		Algorithm: metadata.Algorithm,
		PublicKey: &MLDSAPublicKey{
			Algorithm: metadata.Algorithm,
			Key:       pkBytes,
		},
		sk:   sk,
		pk:   pk,
		seed: sealedSeed,
	}, nil
}

// loadMLKEMKey recreates a ML-KEM key from stored seed using stdlib NewDecapsulationKey.
func (b *QuantumBackend) loadMLKEMKey(metadata *keyMetadata, keyID string) (*MLKEMPrivateKey, error) {
	loader, ok := mlkemSeedLoaders[metadata.Algorithm]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: metadata.Algorithm}
	}

	pubKeyBytes, dk, err := loader(metadata.Seed)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to reconstruct ML-KEM key from seed", Err: err}
	}

	// metadata.Seed belongs to the caller and may still be needed, so it is
	// sealed by copy and left in place.
	sealedSeed, sealErr := sealSeed(metadata.Seed)
	if sealErr != nil {
		return nil, sealErr
	}

	return &MLKEMPrivateKey{
		Algorithm: metadata.Algorithm,
		PublicKey: &MLKEMPublicKey{
			Algorithm: metadata.Algorithm,
			Key:       pubKeyBytes,
		},
		dk:      dk,
		seed:    sealedSeed,
		tracker: b.tracker,
		keyID:   keyID,
	}, nil
}

// DeleteKey removes a key identified by its attributes.
func (b *QuantumBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
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
			return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: keyID}
		}
		return &errs.Wrapped{Msg: "failed to delete key", Err: err}
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *QuantumBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyIDs, err := storage.ListKeys(ctx, b.storage)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys", Err: err}
	}

	attrs := make([]*types.KeyAttributes, 0, len(keyIDs))
	for _, id := range keyIDs {
		parts := strings.Split(id, ":")
		if len(parts) < 4 {
			continue
		}

		// Key ID format: storetype:keytype:cn:algorithm
		// Only include quantum keys (ML-DSA-* or ML-KEM-*)
		algorithmStr := parts[len(parts)-1]
		algo := types.QuantumAlgorithm(strings.ToUpper(algorithmStr))
		if !algo.IsSignature() && !algo.IsKEM() {
			continue
		}

		cn := parts[len(parts)-2]
		storeTypeStr := parts[0]
		keyTypeStr := parts[1]

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
func (b *QuantumBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := b.GetKey(ctx, attrs)
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
func (b *QuantumBackend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrKeyNotDecrypter
}

// RotateKey rotates/updates a key identified by attrs.
func (b *QuantumBackend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	keyID := attrs.ID()

	exists, err := storage.KeyExists(ctx, b.storage, keyID)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to check key existence", Err: err}
	}
	if !exists {
		return &errs.Detail{Err: backend.ErrKeyNotFound, Detail: keyID}
	}

	keyData, err := storage.GetKey(ctx, b.storage, keyID)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to retrieve key for rotation", Err: err}
	}

	var metadata keyMetadata
	if err := json.Unmarshal(keyData, &metadata); err != nil {
		return &errs.Wrapped{Msg: "failed to deserialize key metadata", Err: err}
	}
	// The seed being rotated away from is still key material until it is
	// overwritten in storage; wipe this decoded copy on the way out.
	defer secure.Wipe(metadata.Seed)

	var newMetadata *keyMetadata

	// Rotation only needs the new metadata, but generating it also produces a
	// private key holding an enclave. It is never handed anywhere, so it is
	// destroyed unconditionally rather than left to the garbage collector.
	var rotated crypto.PrivateKey
	defer func() { cleanPrivateKey(rotated) }()

	rotatedAlgo := types.QuantumAlgorithm(metadata.Algorithm)

	switch {
	case rotatedAlgo.IsSignature():
		var mldsaKey *MLDSAPrivateKey
		mldsaKey, newMetadata, err = b.generateMLDSAKey(metadata.Algorithm)
		rotated = mldsaKey
	case rotatedAlgo.IsKEM():
		var mlkemKey *MLKEMPrivateKey
		mlkemKey, newMetadata, err = b.generateMLKEMKey(metadata.Algorithm, keyID)
		rotated = mlkemKey
	default:
		return &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: metadata.Algorithm}
	}

	if err != nil {
		return &errs.Wrapped{Msg: "failed to generate new key for rotation", Err: err}
	}

	if err := b.storeKey(ctx, keyID, newMetadata); err != nil {
		return &errs.Wrapped{Msg: "failed to store rotated key", Err: err}
	}

	// Reset AEAD tracking for the rotated key (ML-KEM only)
	if rotatedAlgo.IsKEM() {
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
