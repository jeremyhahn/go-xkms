//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestNewKeyStore(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()

	ks := NewKeyStore(publicStorage, secretBackend)

	assert.NotNil(t, ks)
	assert.Equal(t, publicStorage, ks.publicStorage)
	assert.Equal(t, secretBackend, ks.secretBackend)
}

func TestKeyStore_StoreAndLoadKeyPackage(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	keyID := "test-key"
	pkg := &KeyPackage{
		ParticipantID: 1,
		SecretShare: &SecretKeyShare{
			Value: []byte{1, 2, 3, 4, 5},
		},
		GroupPublicKey: []byte{10, 20, 30, 40, 50},
		VerificationShares: map[uint32][]byte{
			1: {100, 101, 102},
			2: {200, 201, 202},
		},
		MinSigners: 2,
		MaxSigners: 2,
		Algorithm:  types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:         keyID,
		Algorithm:     types.FrostAlgorithmEd25519,
		Threshold:     2,
		Total:         2,
		ParticipantID: 1,
		CreatedAt:     1234567890,
	}

	// Store
	err := ks.StoreKeyPackage(keyID, pkg, metadata)
	require.NoError(t, err)

	// Load
	loadedPkg, loadedMeta, err := ks.LoadKeyPackage(keyID, 1)
	require.NoError(t, err)
	require.NotNil(t, loadedPkg)
	require.NotNil(t, loadedMeta)

	// Verify loaded data
	assert.Equal(t, uint32(1), loadedPkg.ParticipantID)
	assert.Equal(t, pkg.SecretShare.Value, loadedPkg.SecretShare.Value)
	assert.Equal(t, pkg.GroupPublicKey, loadedPkg.GroupPublicKey)
	assert.Equal(t, uint32(2), loadedPkg.MinSigners)
	assert.Equal(t, uint32(2), loadedPkg.MaxSigners)
	assert.Equal(t, types.FrostAlgorithmEd25519, loadedPkg.Algorithm)

	assert.Equal(t, keyID, loadedMeta.KeyID)
	assert.Equal(t, 2, loadedMeta.Threshold)
	assert.Equal(t, 2, loadedMeta.Total)
}

func TestKeyStore_LoadKeyPackage_UseMetadataParticipantID(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	keyID := "test-key"
	pkg := &KeyPackage{
		ParticipantID: 2,
		SecretShare: &SecretKeyShare{
			Value: []byte{1, 2, 3},
		},
		GroupPublicKey: []byte{10, 20, 30},
		VerificationShares: map[uint32][]byte{
			1: {100},
			2: {200},
		},
		MinSigners: 2,
		MaxSigners: 2,
		Algorithm:  types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:         keyID,
		Algorithm:     types.FrostAlgorithmEd25519,
		Threshold:     2,
		Total:         2,
		ParticipantID: 2, // Metadata stores participant ID as 2
	}

	err := ks.StoreKeyPackage(keyID, pkg, metadata)
	require.NoError(t, err)

	// Load with participantID=0 should use metadata value
	loadedPkg, _, err := ks.LoadKeyPackage(keyID, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), loadedPkg.ParticipantID)
}

func TestKeyStore_LoadKeyPackage_NotFound(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	pkg, meta, err := ks.LoadKeyPackage("nonexistent", 1)
	require.Error(t, err)
	assert.Nil(t, pkg)
	assert.Nil(t, meta)
	assert.True(t, errors.Is(err, ErrKeyNotFound))
}

func TestKeyStore_LoadPublicKeyPackage(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	keyID := "test-key"
	pkg := &KeyPackage{
		ParticipantID: 1,
		SecretShare: &SecretKeyShare{
			Value: []byte{1, 2, 3},
		},
		GroupPublicKey: []byte{10, 20, 30},
		VerificationShares: map[uint32][]byte{
			1: {100},
			2: {200},
		},
		MinSigners: 2,
		MaxSigners: 2,
		Algorithm:  types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:     keyID,
		Algorithm: types.FrostAlgorithmEd25519,
		Threshold: 2,
		Total:     2,
	}

	err := ks.StoreKeyPackage(keyID, pkg, metadata)
	require.NoError(t, err)

	// Load public package only
	pubPkg, loadedMeta, err := ks.LoadPublicKeyPackage(keyID)
	require.NoError(t, err)
	require.NotNil(t, pubPkg)
	require.NotNil(t, loadedMeta)

	assert.Equal(t, pkg.GroupPublicKey, pubPkg.GroupPublicKey)
	assert.Equal(t, uint32(2), pubPkg.MinSigners)
	assert.Equal(t, uint32(2), pubPkg.MaxSigners)
	assert.Equal(t, types.FrostAlgorithmEd25519, pubPkg.Algorithm)
}

func TestKeyStore_LoadPublicKeyPackage_NotFound(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	pkg, meta, err := ks.LoadPublicKeyPackage("nonexistent")
	require.Error(t, err)
	assert.Nil(t, pkg)
	assert.Nil(t, meta)
	assert.True(t, errors.Is(err, ErrKeyNotFound))
}

func TestKeyStore_DeleteKey(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	keyID := "test-key"
	pkg := &KeyPackage{
		ParticipantID: 1,
		SecretShare: &SecretKeyShare{
			Value: []byte{1, 2, 3},
		},
		GroupPublicKey: []byte{10, 20, 30},
		VerificationShares: map[uint32][]byte{
			1: {100},
			2: {200},
		},
		MinSigners: 2,
		MaxSigners: 2,
		Algorithm:  types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:     keyID,
		Algorithm: types.FrostAlgorithmEd25519,
		Threshold: 2,
		Total:     2,
	}

	// Store and verify exists
	err := ks.StoreKeyPackage(keyID, pkg, metadata)
	require.NoError(t, err)

	exists, err := ks.KeyExists(keyID)
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete
	err = ks.DeleteKey(keyID)
	assert.NoError(t, err)

	// Verify deleted
	exists, err = ks.KeyExists(keyID)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestKeyStore_DeleteKey_NonexistentKey(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Should not error even if key doesn't exist
	err := ks.DeleteKey("nonexistent")
	assert.NoError(t, err)
}

func TestKeyStore_KeyExists(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Should not exist initially
	exists, err := ks.KeyExists("test-key")
	require.NoError(t, err)
	assert.False(t, exists)

	// Store key
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte{1}},
		GroupPublicKey:     []byte{2},
		VerificationShares: map[uint32][]byte{1: {3}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:     "test-key",
		Threshold: 2,
		Total:     2,
	}
	err = ks.StoreKeyPackage("test-key", pkg, metadata)
	require.NoError(t, err)

	// Should exist now
	exists, err = ks.KeyExists("test-key")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestKeyStore_ListKeys(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Initially empty
	keys, err := ks.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Store some keys
	for _, keyID := range []string{"key1", "key2", "key3"} {
		pkg := &KeyPackage{
			ParticipantID:      1,
			SecretShare:        &SecretKeyShare{Value: []byte{1}},
			GroupPublicKey:     []byte{2},
			VerificationShares: map[uint32][]byte{1: {3}},
			MinSigners:         2,
			MaxSigners:         2,
			Algorithm:          types.FrostAlgorithmEd25519,
		}
		metadata := &KeyMetadata{
			KeyID:     keyID,
			Threshold: 2,
			Total:     2,
		}
		err := ks.StoreKeyPackage(keyID, pkg, metadata)
		require.NoError(t, err)
	}

	// Should list keys - verify the expected keys are present
	keys, err = ks.ListKeys()
	require.NoError(t, err)
	// The result should contain the key IDs
	assert.Contains(t, keys, "key1")
	assert.Contains(t, keys, "key2")
	assert.Contains(t, keys, "key3")
}

func TestKeyStore_ListKeysWithMetadata(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Store keys with different algorithms
	for i, algo := range []types.FrostAlgorithm{types.FrostAlgorithmEd25519, types.FrostAlgorithmP256} {
		keyID := string(rune('A' + i))
		pkg := &KeyPackage{
			ParticipantID:      1,
			SecretShare:        &SecretKeyShare{Value: []byte{1}},
			GroupPublicKey:     []byte{2},
			VerificationShares: map[uint32][]byte{1: {3}},
			MinSigners:         2,
			MaxSigners:         3,
			Algorithm:          algo,
		}
		metadata := &KeyMetadata{
			KeyID:     keyID,
			Algorithm: algo,
			Threshold: 2,
			Total:     3,
		}
		err := ks.StoreKeyPackage(keyID, pkg, metadata)
		require.NoError(t, err)
	}

	// List with metadata
	metadataList, err := ks.ListKeysWithMetadata()
	require.NoError(t, err)
	assert.Len(t, metadataList, 2)

	// Verify metadata is populated
	for _, m := range metadataList {
		assert.NotEmpty(t, m.KeyID)
		assert.NotEmpty(t, m.Algorithm)
		assert.Equal(t, 2, m.Threshold)
		assert.Equal(t, 3, m.Total)
	}
}

func TestKeyMetadata(t *testing.T) {
	metadata := &KeyMetadata{
		KeyID:             "my-key",
		Algorithm:         types.FrostAlgorithmSecp256k1,
		Threshold:         3,
		Total:             5,
		ParticipantID:     2,
		Participants:      []string{"alice", "bob", "charlie", "dave", "eve"},
		CreatedAt:         1234567890,
		SecretBackendType: types.BackendTypeSoftware,
	}

	assert.Equal(t, "my-key", metadata.KeyID)
	assert.Equal(t, types.FrostAlgorithmSecp256k1, metadata.Algorithm)
	assert.Equal(t, 3, metadata.Threshold)
	assert.Equal(t, 5, metadata.Total)
	assert.Equal(t, uint32(2), metadata.ParticipantID)
	assert.Len(t, metadata.Participants, 5)
	assert.Equal(t, int64(1234567890), metadata.CreatedAt)
}

func TestKeyPath(t *testing.T) {
	path := keyPath("my-key")
	assert.Contains(t, path, "frost/keys")
	assert.Contains(t, path, "my-key")

	path = keyPath("my-key", "metadata.json")
	assert.Contains(t, path, "metadata.json")

	path = keyPath("my-key", "dir", "file.bin")
	assert.Contains(t, path, "dir")
	assert.Contains(t, path, "file.bin")
}

func TestVerificationSharePath(t *testing.T) {
	path := verificationSharePath("my-key", 3)
	assert.Contains(t, path, "frost/keys")
	assert.Contains(t, path, "my-key")
	assert.Contains(t, path, "verification_shares")
	assert.Contains(t, path, "3.bin")
}

func TestKeyStore_ListKeysWithMetadata_CorruptMetadata(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Store a valid key
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte{1}},
		GroupPublicKey:     []byte{2},
		VerificationShares: map[uint32][]byte{1: {3}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:     "good-key",
		Algorithm: types.FrostAlgorithmEd25519,
		Threshold: 2,
		Total:     2,
	}
	err := ks.StoreKeyPackage("good-key", pkg, metadata)
	require.NoError(t, err)

	// Manually insert corrupt metadata for another key
	publicStorage.data["frost/keys/bad-key/metadata.json"] = []byte("not valid json")

	// Should return only the good key, skipping the corrupt one
	metadataList, err := ks.ListKeysWithMetadata()
	require.NoError(t, err)
	assert.Len(t, metadataList, 1)
	assert.Equal(t, "good-key", metadataList[0].KeyID)
}

func TestKeyStore_LoadKeyPackage_InsufficientVerificationShares(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Store a key package
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte{1}},
		GroupPublicKey:     []byte{2},
		VerificationShares: map[uint32][]byte{1: {3}},
		MinSigners:         2,
		MaxSigners:         3,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:     "test-key",
		Algorithm: types.FrostAlgorithmEd25519,
		Threshold: 3, // Require 3 shares
		Total:     3,
	}
	err := ks.StoreKeyPackage("test-key", pkg, metadata)
	require.NoError(t, err)

	// Delete some verification shares to create insufficient shares scenario
	delete(publicStorage.data, "frost/keys/test-key/verification_shares/1.bin")

	// Should fail because we don't have enough verification shares
	_, _, err = ks.LoadKeyPackage("test-key", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient verification shares")
}

func TestKeyStore_LoadKeyPackage_MissingGroupPublicKey(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Store a key package
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte{1}},
		GroupPublicKey:     []byte{2},
		VerificationShares: map[uint32][]byte{1: {3}, 2: {4}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:     "test-key",
		Algorithm: types.FrostAlgorithmEd25519,
		Threshold: 2,
		Total:     2,
	}
	err := ks.StoreKeyPackage("test-key", pkg, metadata)
	require.NoError(t, err)

	// Delete group public key (correct filename: group_public.bin)
	delete(publicStorage.data, "frost/keys/test-key/group_public.bin")

	// Should fail
	_, _, err = ks.LoadKeyPackage("test-key", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load group public key")
}

func TestKeyStore_LoadPublicKeyPackage_MissingGroupPublicKey(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Store a key package
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte{1}},
		GroupPublicKey:     []byte{2},
		VerificationShares: map[uint32][]byte{1: {3}, 2: {4}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:     "test-key",
		Algorithm: types.FrostAlgorithmEd25519,
		Threshold: 2,
		Total:     2,
	}
	err := ks.StoreKeyPackage("test-key", pkg, metadata)
	require.NoError(t, err)

	// Delete group public key (correct filename: group_public.bin)
	delete(publicStorage.data, "frost/keys/test-key/group_public.bin")

	// Should fail
	_, _, err = ks.LoadPublicKeyPackage("test-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load group public key")
}

func TestKeyStore_LoadKeyPackage_CorruptMetadata(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Manually insert corrupt metadata
	publicStorage.data["frost/keys/corrupt-key/metadata.json"] = []byte("not valid json")

	_, _, err := ks.LoadKeyPackage("corrupt-key", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal metadata")
}

func TestKeyStore_LoadPublicKeyPackage_CorruptMetadata(t *testing.T) {
	publicStorage := newMockStorageBackend()
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	// Manually insert corrupt metadata
	publicStorage.data["frost/keys/corrupt-key/metadata.json"] = []byte("not valid json")

	_, _, err := ks.LoadPublicKeyPackage("corrupt-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal metadata")
}

func TestKeyStore_ListKeys_Error(t *testing.T) {
	publicStorage := newFailingStorageBackend("list")
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	_, err := ks.ListKeys()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage error")
}

func TestKeyStore_ListKeysWithMetadata_ListError(t *testing.T) {
	publicStorage := newFailingStorageBackend("list")
	secretBackend := newMockSecretBackend()
	ks := NewKeyStore(publicStorage, secretBackend)

	_, err := ks.ListKeysWithMetadata()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage error")
}
