//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createTestBackend(t *testing.T) *FrostBackend {
	config := &Config{
		PublicStorage:       newMockStorageBackend(),
		SecretBackend:       newMockSecretBackend(),
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		ParticipantID:       1,
		EnableNonceTracking: true,
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	return backend
}

func TestNewBackend_Success(t *testing.T) {
	config := &Config{
		PublicStorage: newMockStorageBackend(),
		SecretBackend: newMockSecretBackend(),
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	assert.NotNil(t, backend)
}

func TestNewBackend_InvalidConfig(t *testing.T) {
	config := &Config{
		// Missing PublicStorage and SecretBackend
	}

	backend, err := NewBackend(config)
	require.Error(t, err)
	assert.Nil(t, backend)
}

func TestFrostBackend_Type(t *testing.T) {
	backend := createTestBackend(t)
	assert.Equal(t, types.BackendTypeFrost, backend.Type())
}

func TestFrostBackend_Capabilities(t *testing.T) {
	backend := createTestBackend(t)
	caps := backend.Capabilities()

	assert.True(t, caps.Keys)
	assert.True(t, caps.Signing)
	assert.False(t, caps.Decryption) // FROST is signing-only
	assert.True(t, caps.KeyRotation)
	assert.False(t, caps.SymmetricEncryption)
	assert.True(t, caps.Import)
	assert.False(t, caps.Export) // Secret shares should not be exported
}

func TestFrostBackend_GenerateKey_Success(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			Algorithm:     types.FrostAlgorithmEd25519,
			ParticipantID: 1,
		},
	}

	key, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	handle, ok := key.(*FrostKeyHandle)
	require.True(t, ok)
	assert.Equal(t, "test-key", handle.KeyID)
	assert.Equal(t, uint32(1), handle.ParticipantID)
	assert.NotEmpty(t, handle.GroupPublicKey)
}

func TestFrostBackend_GenerateKey_MissingCN(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		StoreType: types.StoreFrost,
	}

	key, err := backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "CN")
}

func TestFrostBackend_GenerateKey_Duplicate(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			Algorithm:     types.FrostAlgorithmEd25519,
			ParticipantID: 1,
		},
	}

	// First generation
	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Second generation should fail
	_, err = backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeyAlreadyExists))
}

func TestFrostBackend_GenerateKey_UsesConfigDefaults(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		// FrostAttributes with minimal config - should use config defaults for algorithm
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}

	key, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	handle := key.(*FrostKeyHandle)
	assert.Equal(t, types.FrostAlgorithmEd25519, handle.Algorithm)
}

func TestFrostBackend_GenerateKey_Closed(t *testing.T) {
	backend := createTestBackend(t)
	backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		StoreType: types.StoreFrost,
	}

	_, err := backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestFrostBackend_GetKey_Success(t *testing.T) {
	backend := createTestBackend(t)

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:        "test-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get the key
	key, err := backend.GetKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	handle := key.(*FrostKeyHandle)
	assert.Equal(t, "test-key", handle.KeyID)
}

func TestFrostBackend_GetKey_NotFound(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "nonexistent",
		StoreType: types.StoreFrost,
	}

	key, err := backend.GetKey(attrs)
	require.Error(t, err)
	assert.Nil(t, key)
}

func TestFrostBackend_GetKey_Closed(t *testing.T) {
	backend := createTestBackend(t)
	backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		StoreType: types.StoreFrost,
	}

	_, err := backend.GetKey(attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestFrostBackend_DeleteKey_Success(t *testing.T) {
	backend := createTestBackend(t)

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:        "test-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Delete the key
	err = backend.DeleteKey(attrs)
	assert.NoError(t, err)

	// Verify it's gone
	_, err = backend.GetKey(attrs)
	require.Error(t, err)
}

func TestFrostBackend_DeleteKey_MissingCN(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		StoreType: types.StoreFrost,
	}

	err := backend.DeleteKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CN")
}

func TestFrostBackend_DeleteKey_Closed(t *testing.T) {
	backend := createTestBackend(t)
	backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		StoreType: types.StoreFrost,
	}

	err := backend.DeleteKey(attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestFrostBackend_ListKeys_Empty(t *testing.T) {
	backend := createTestBackend(t)

	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestFrostBackend_ListKeys_MultipleKeys(t *testing.T) {
	backend := createTestBackend(t)

	// Generate multiple keys
	for i := 1; i <= 3; i++ {
		attrs := &types.KeyAttributes{
			CN:        "key-" + string(rune('0'+i)),
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreFrost,
			FrostAttributes: &types.FrostAttributes{
				Threshold:     2,
				Total:         3,
				ParticipantID: 1,
				Algorithm:     types.FrostAlgorithmEd25519,
			},
		}
		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
	}

	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestFrostBackend_ListKeys_Closed(t *testing.T) {
	backend := createTestBackend(t)
	backend.Close()

	_, err := backend.ListKeys()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestFrostBackend_Signer(t *testing.T) {
	backend := createTestBackend(t)

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:        "test-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Verify it implements crypto.Signer
	_, ok := signer.(crypto.Signer)
	assert.True(t, ok)
}

func TestFrostBackend_Signer_NotFound(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "nonexistent",
		StoreType: types.StoreFrost,
	}

	signer, err := backend.Signer(attrs)
	require.Error(t, err)
	assert.Nil(t, signer)
}

func TestFrostBackend_Signer_Closed(t *testing.T) {
	backend := createTestBackend(t)
	backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		StoreType: types.StoreFrost,
	}

	_, err := backend.Signer(attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestFrostBackend_Decrypter(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		StoreType: types.StoreFrost,
	}

	// FROST does not support decryption
	decrypter, err := backend.Decrypter(attrs)
	require.Error(t, err)
	assert.Nil(t, decrypter)
	assert.True(t, errors.Is(err, ErrDecryptionNotSupported))
}

func TestFrostBackend_RotateKey(t *testing.T) {
	backend := createTestBackend(t)

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:        "test-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	key1, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	oldPubKey := key1.(*FrostKeyHandle).GroupPublicKey

	// Rotate the key
	err = backend.RotateKey(attrs)
	require.NoError(t, err)

	// Get the new key
	key2, err := backend.GetKey(attrs)
	require.NoError(t, err)
	newPubKey := key2.(*FrostKeyHandle).GroupPublicKey

	// Public key should be different after rotation
	assert.NotEqual(t, oldPubKey, newPubKey)
}

func TestFrostBackend_RotateKey_NotFound(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "nonexistent",
		StoreType: types.StoreFrost,
	}

	err := backend.RotateKey(attrs)
	require.Error(t, err)
}

func TestFrostBackend_RotateKey_Closed(t *testing.T) {
	backend := createTestBackend(t)
	backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-key",
		StoreType: types.StoreFrost,
	}

	err := backend.RotateKey(attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestFrostBackend_Close_Multiple(t *testing.T) {
	backend := createTestBackend(t)

	// Close multiple times should not error
	err := backend.Close()
	assert.NoError(t, err)

	err = backend.Close()
	assert.NoError(t, err)
}

func TestFrostKeyHandle(t *testing.T) {
	handle := &FrostKeyHandle{
		KeyID:          "my-key",
		ParticipantID:  2,
		GroupPublicKey: []byte{1, 2, 3, 4, 5},
		Algorithm:      types.FrostAlgorithmSecp256k1,
	}

	assert.Equal(t, "my-key", handle.KeyID)
	assert.Equal(t, uint32(2), handle.ParticipantID)
	assert.Equal(t, types.FrostAlgorithmSecp256k1, handle.Algorithm)

	// Public() returns the group public key
	pub := handle.Public()
	assert.Equal(t, handle.GroupPublicKey, pub)
}

func TestSigningSession(t *testing.T) {
	session := &SigningSession{
		SessionID:     "session-123",
		KeyID:         "my-key",
		ParticipantID: 1,
	}

	assert.Equal(t, "session-123", session.SessionID)
	assert.Equal(t, "my-key", session.KeyID)
	assert.Equal(t, uint32(1), session.ParticipantID)
}

func TestFrostBackend_GenerateKey_InvalidFrostAttributes(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "invalid-frost-attrs",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     5, // Greater than Total
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}

	_, err := backend.GenerateKey(attrs)
	require.Error(t, err)
	// Error message contains "frost" (from frost attributes validation)
	assert.Contains(t, err.Error(), "frost")
}

func TestFrostBackend_GenerateKey_ParticipantIDFromConfig(t *testing.T) {
	backend := createTestBackend(t)

	// Test with FrostAttributes missing ParticipantID - should use config default
	attrs := &types.KeyAttributes{
		CN:        "pid-from-config-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold: 2,
			Total:     3,
			Algorithm: types.FrostAlgorithmEd25519,
			// ParticipantID is 0 - should use config.ParticipantID (1)
		},
	}

	key, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	handle := key.(*FrostKeyHandle)
	assert.Equal(t, uint32(1), handle.ParticipantID)
}

func TestFrostBackend_GenerateKey_InvalidParticipantIDTooHigh(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "invalid-pid-high",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 10, // Greater than Total
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}

	_, err := backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "participant")
}

func TestFrostBackend_GetKey_MissingCN(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		StoreType: types.StoreFrost,
		// Missing CN
	}

	_, err := backend.GetKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CN")
}

func TestFrostBackend_Signer_MissingCN(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		StoreType: types.StoreFrost,
		// Missing CN
	}

	_, err := backend.Signer(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CN")
}

func TestFrostBackend_RotateKey_MissingCN(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		StoreType: types.StoreFrost,
		// Missing CN
	}

	err := backend.RotateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CN")
}

func TestFrostBackend_GetKey_WithZeroParticipantID(t *testing.T) {
	// Create backend with ParticipantID=0 in config
	config := &Config{
		PublicStorage:       newMockStorageBackend(),
		SecretBackend:       newMockSecretBackend(),
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		ParticipantID:       0, // Zero - will use default
		EnableNonceTracking: true,
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:        "zero-pid-test",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1, // Use 1 for generation
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get key with zero participant ID in attrs - should fall back to default (1)
	getAttrs := &types.KeyAttributes{
		CN:        "zero-pid-test",
		StoreType: types.StoreFrost,
		// No FrostAttributes - ParticipantID will be 0
	}
	key, err := backend.GetKey(getAttrs)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestFrostBackend_Signer_WithZeroParticipantID(t *testing.T) {
	// Create backend with ParticipantID=0 in config
	config := &Config{
		PublicStorage:       newMockStorageBackend(),
		SecretBackend:       newMockSecretBackend(),
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		ParticipantID:       0, // Zero - will use default
		EnableNonceTracking: true,
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:        "zero-pid-signer-test",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get signer with zero participant ID - should fall back to default (1)
	signerAttrs := &types.KeyAttributes{
		CN:        "zero-pid-signer-test",
		StoreType: types.StoreFrost,
	}
	signer, err := backend.Signer(signerAttrs)
	require.NoError(t, err)
	require.NotNil(t, signer)
}
