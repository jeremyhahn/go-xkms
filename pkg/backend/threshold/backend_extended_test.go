// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Test GetKey
// ========================================================================

func TestThresholdBackend_GetKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-getkey",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	// GetKey should return ErrNotImplemented (requires distributed coordination)
	_, err = backend.GetKey(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotImplemented)
}

func TestThresholdBackend_GetKey_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err = backend.GetKey(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// ========================================================================
// Test Decrypter
// ========================================================================

func TestThresholdBackend_Decrypter(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-decrypter",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
	}

	// Decrypter should return ErrNotImplemented
	_, err = backend.Decrypter(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotImplemented)
}

func TestThresholdBackend_Decrypter_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
	}

	_, err = backend.Decrypter(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// ========================================================================
// Test RotateKey
// ========================================================================

func TestThresholdBackend_RotateKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-rotate",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	// RotateKey should return ErrNotImplemented
	err = backend.RotateKey(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotImplemented)
}

func TestThresholdBackend_RotateKey_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	err = backend.RotateKey(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// ========================================================================
// Test Error Types
// ========================================================================

func TestShareNotFoundError(t *testing.T) {
	err := &ShareNotFoundError{
		KeyID:   "test-key-123",
		ShareID: 3,
	}

	// Test Error method
	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "share 3 not found")
	assert.Contains(t, errorMsg, "test-key-123")

	// Test Unwrap method
	unwrapped := err.Unwrap()
	assert.ErrorIs(t, unwrapped, ErrShareNotFound)
	assert.True(t, errors.Is(err, ErrShareNotFound))
}

func TestInsufficientSharesError(t *testing.T) {
	err := &InsufficientSharesError{
		Have:      2,
		Threshold: 3,
	}

	// Test Error method
	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "have 2")
	assert.Contains(t, errorMsg, "need 3")

	// Test Unwrap method
	unwrapped := err.Unwrap()
	assert.ErrorIs(t, unwrapped, ErrInsufficientShares)
	assert.True(t, errors.Is(err, ErrInsufficientShares))
}

// ========================================================================
// Test additional edge cases
// ========================================================================

func TestThresholdBackend_Signer_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err = backend.Signer(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestThresholdBackend_DeleteKey_BackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	err = backend.DeleteKey(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestThresholdBackend_Close_Multiple(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// First close should succeed
	err = backend.Close()
	assert.NoError(t, err)

	// Second close should be idempotent (return nil)
	err = backend.Close()
	assert.NoError(t, err)
}

// ========================================================================
// Test RSA key generation error paths
// ========================================================================

func TestThresholdBackend_GenerateRSAKey_NoAttributes(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test with nil RSAAttributes
	attrs := &types.KeyAttributes{
		CN:           "test-rsa-no-attrs",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
		// RSAAttributes is nil
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 3,
			Total:     5,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSA attributes required")
}

func TestThresholdBackend_GenerateRSAKey_SmallKeySize(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test with key size less than 2048
	attrs := &types.KeyAttributes{
		CN:           "test-rsa-small",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 1024, // Too small
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 3,
			Total:     5,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2048 bits")
}

// ========================================================================
// Test ECDSA key generation error paths
// ========================================================================

func TestThresholdBackend_GenerateECDSAKey_NoAttributes(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test with nil ECCAttributes
	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-no-attrs",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		// ECCAttributes is nil
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 3,
			Total:     5,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ECC attributes required")
}

func TestThresholdBackend_GenerateECDSAKey_NoCurve(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test with nil Curve
	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-no-curve",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: nil, // No curve specified
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 3,
			Total:     5,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "curve is required")
}

// ========================================================================
// Test unsupported algorithm
// ========================================================================

func TestThresholdBackend_GenerateKey_UnsupportedAlgorithm(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test with an unsupported algorithm
	attrs := &types.KeyAttributes{
		CN:           "test-unsupported",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.DSA, // DSA is not supported
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 3,
			Total:     5,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key type")
}

// ========================================================================
// Test loadAnyShare error paths
// ========================================================================

func TestThresholdBackend_loadAnyShare_NoThresholdAttributes(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:                  "test",
		KeyType:             types.KeyTypeSigning,
		StoreType:           types.StoreThreshold,
		KeyAlgorithm:        x509.Ed25519,
		ThresholdAttributes: nil, // No threshold attributes
	}

	_, err = backend.loadAnyShare(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold attributes required")
}

func TestThresholdBackend_loadAnyShare_NoValidShares(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-no-shares",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Don't generate any key, so no shares exist
	_, err = backend.loadAnyShare(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid shares found")
}

func TestThresholdBackend_GenerateKey_InvalidThresholdAttributes(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-invalid-threshold",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 5,
			Total:     3, // Invalid: Total < Threshold
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid threshold attributes")
}

func TestThresholdBackend_Signer_LoadAnyShare(t *testing.T) {
	keyStorage := storage.New()
	// Create config with LocalShareID = 0 (no configured local share)
	config := &Config{
		KeyStorage:       keyStorage,
		ShareStorage:     keyStorage,
		LocalShareID:     0, // No local share configured
		DefaultThreshold: 2,
		DefaultTotal:     3,
		DefaultAlgorithm: types.ThresholdAlgorithmShamir,
		Participants:     []string{"node1", "node2", "node3"},
	}
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-any-share",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get signer - should use loadAnyShare since LocalShareID = 0
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func TestThresholdSigner_Public_InsufficientShares(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-public-fail",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 4, // Need 4 shares
			Total:     5,
		},
	}

	// Generate key first
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Delete enough shares so we only have 2 (need 4)
	keyID := backend.getKeyID(attrs)
	for i := 1; i <= 3; i++ {
		shareKey := "threshold/shares/" + keyID + "/share-1"
		_ = keyStorage.Delete(shareKey)
		shareKey = "threshold/shares/" + keyID + "/share-2"
		_ = keyStorage.Delete(shareKey)
		shareKey = "threshold/shares/" + keyID + "/share-3"
		_ = keyStorage.Delete(shareKey)
	}

	// Get signer with one of the remaining shares
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Public() should return nil when reconstruction fails (only 2 shares, need 4)
	pubKey := signer.Public()
	assert.Nil(t, pubKey)
}

func TestThresholdSigner_unmarshalPrivateKey_InvalidEd25519Size(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	signer := &ThresholdSigner{
		backend: backend,
		attrs:   attrs,
	}

	// Try to unmarshal Ed25519 key with wrong size
	invalidData := []byte("wrong size")
	_, err = signer.unmarshalPrivateKey(invalidData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Ed25519 key size")
}

func TestThresholdSigner_unmarshalPrivateKey_UnsupportedAlgorithm(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.DSA, // Unsupported
	}

	signer := &ThresholdSigner{
		backend: backend,
		attrs:   attrs,
	}

	data := []byte("some data")
	_, err = signer.unmarshalPrivateKey(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key algorithm")
}

func TestThresholdBackend_ListKeys_CorruptedMetadata(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Generate a valid key first
	attrs := &types.KeyAttributes{
		CN:           "test-valid",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Add corrupted metadata entry
	_ = keyStorage.Put("threshold/metadata/corrupted-key", []byte("invalid json"), nil)

	// ListKeys should skip the corrupted entry and return the valid one
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	// Should have at least 1 valid key (the corrupted one is skipped)
	assert.GreaterOrEqual(t, len(keys), 1)
}

func TestThresholdBackend_loadShare_CorruptedJSON(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-corrupted-share",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Store corrupted share data directly
	keyID := backend.getKeyID(attrs)
	shareKey := "threshold/shares/" + keyID + "/share-1"
	_ = keyStorage.Put(shareKey, []byte("corrupted json"), nil)

	// Try to load the corrupted share
	_, err = backend.loadShare(attrs, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal share")
}

func TestThresholdBackend_loadAnyShare_CorruptedShares(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-corrupted-any",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate key first
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Corrupt first two shares
	keyID := backend.getKeyID(attrs)
	_ = keyStorage.Put("threshold/shares/"+keyID+"/share-1", []byte("bad"), nil)
	_ = keyStorage.Put("threshold/shares/"+keyID+"/share-2", []byte("bad"), nil)

	// loadAnyShare should skip corrupted ones and find share-3
	share, err := backend.loadAnyShare(attrs)
	require.NoError(t, err)
	require.NotNil(t, share)
	assert.Equal(t, 3, share.Index)
}

func TestThresholdBackend_loadShare_CacheHit(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-cache",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate key - this caches the local share
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Load the cached share (LocalShareID is 1 by default)
	share1, err := backend.loadShare(attrs, config.LocalShareID)
	require.NoError(t, err)
	require.NotNil(t, share1)

	// Load again - should hit cache
	share2, err := backend.loadShare(attrs, config.LocalShareID)
	require.NoError(t, err)
	require.NotNil(t, share2)

	// Should be the same share object from cache
	assert.Equal(t, share1.Index, share2.Index)
}

type unsupportedKeyType struct{}

func TestThresholdBackend_marshalPrivateKey_UnsupportedType(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Try to marshal an unsupported key type
	unsupported := &unsupportedKeyType{}
	_, err = backend.marshalPrivateKey(unsupported)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestThresholdSigner_Public_RSAKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-public-rsa",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Test Public() with RSA key type
	pubKey := signer.Public()
	require.NotNil(t, pubKey)
}

func TestThresholdSigner_unmarshalPrivateKey_InvalidRSA(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
	}

	signer := &ThresholdSigner{
		backend: backend,
		attrs:   attrs,
	}

	// Try to unmarshal invalid RSA key data
	invalidData := []byte("invalid rsa key data")
	_, err = signer.unmarshalPrivateKey(invalidData)
	require.Error(t, err)
}

func TestThresholdSigner_unmarshalPrivateKey_InvalidECDSA(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
	}

	signer := &ThresholdSigner{
		backend: backend,
		attrs:   attrs,
	}

	// Try to unmarshal invalid ECDSA key data
	invalidData := []byte("invalid ecdsa key data")
	_, err = signer.unmarshalPrivateKey(invalidData)
	require.Error(t, err)
}

func TestThresholdSigner_Public_ECDSAKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-public-ecdsa",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Test Public() with ECDSA key type
	pubKey := signer.Public()
	require.NotNil(t, pubKey)
}

func TestThresholdSigner_Public_Ed25519Key(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-public-ed25519",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Test Public() with Ed25519 key type
	pubKey := signer.Public()
	require.NotNil(t, pubKey)
}

func TestThresholdSigner_Sign_ECDSAKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-sign-ecdsa",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Test Sign() with ECDSA key type
	digest := []byte("test digest")
	hash := sha256.Sum256(digest)
	sig, err := signer.Sign(nil, hash[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotNil(t, sig)
}
func TestThresholdSigner_Sign_RSAKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-sign-rsa",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Test Sign() with RSA key type (RSA requires proper hash)
	message := []byte("test message")
	hash := sha256.Sum256(message)
	sig, err := signer.Sign(nil, hash[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotNil(t, sig)
}

func TestThresholdBackend_splitAndStoreKey_Ed25519(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Generate an Ed25519 key and split/store it
	attrs := &types.KeyAttributes{
		CN:           "test-split-ed25519",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Verify shares were stored
	keyID := backend.getKeyID(attrs)
	shareKey := "threshold/shares/" + keyID + "/share-1"
	exists, err := keyStorage.Exists(shareKey)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestThresholdSigner_unmarshalPrivateKey_Ed25519(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-unmarshal-ed25519",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate and retrieve
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func TestThresholdBackend_marshalPrivateKey_ECDSA(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test ECDSA marshaling path
	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-marshal",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate key - this exercises the ECDSA marshal path in splitAndStoreKey
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)
}

func TestThresholdSigner_unmarshalPrivateKey_RSA(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test RSA unmarshal path
	attrs := &types.KeyAttributes{
		CN:           "test-rsa-unmarshal",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate and retrieve key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Verify we can get the public key (requires unmarshal)
	pubKey := signer.Public()
	require.NotNil(t, pubKey)
}

func TestThresholdSigner_unmarshalPrivateKey_ECDSA(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Test ECDSA unmarshal path
	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-unmarshal",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate and retrieve key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Verify we can get the public key (requires unmarshal)
	pubKey := signer.Public()
	require.NotNil(t, pubKey)
}

// TestThresholdBackend_ListKeys_UnreadableEntry tests ListKeys skipping unreadable entries
func TestThresholdBackend_ListKeys_UnreadableEntry(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Generate a valid key
	attrs := &types.KeyAttributes{
		CN:           "test-valid-key",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Add an entry that cannot be unmarshaled
	err = keyStorage.Put("threshold/metadata/bad-json-key", []byte("not json"), nil)
	require.NoError(t, err)

	// ListKeys should return valid keys and skip invalid ones
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(keys), 1)
}

// TestThresholdBackend_Signer_LoadShareFallback tests that Signer falls back to loadAnyShare
func TestThresholdBackend_Signer_LoadShareFallback(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-fallback-share",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Generate key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Delete the local share (share-1) from cache and storage
	keyID := backend.getKeyID(attrs)
	backend.cacheMu.Lock()
	delete(backend.shareCache, keyID)
	backend.cacheMu.Unlock()
	shareKey := "threshold/shares/" + keyID + "/share-1"
	_ = keyStorage.Delete(shareKey)

	// Get signer - local share doesn't exist, so it should fallback to loadAnyShare
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

// TestThresholdSigner_Sign_InsufficientShares tests signing with insufficient shares
func TestThresholdSigner_Sign_InsufficientShares(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-sign-insufficient",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 4, // Need 4 shares
			Total:     5,
		},
	}

	// Generate key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Delete shares to leave only 2 (need 4)
	keyID := backend.getKeyID(attrs)
	for i := 2; i <= 4; i++ {
		shareKey := "threshold/shares/" + keyID + "/share-" + string(rune('0'+i))
		_ = keyStorage.Delete(shareKey)
	}

	// Get signer with remaining share
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Sign should fail due to insufficient shares
	digest := []byte("test message")
	_, err = signer.Sign(nil, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to reconstruct key")
}

// TestThresholdBackend_loadShare_InvalidShare tests loading an invalid share
func TestThresholdBackend_loadShare_InvalidShare(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-invalid-share-validate",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     3,
		},
	}

	// Store invalid share data (valid JSON but invalid share)
	keyID := backend.getKeyID(attrs)
	shareKey := "threshold/shares/" + keyID + "/share-1"
	invalidShare := `{"index": 0, "data": ""}`
	err = keyStorage.Put(shareKey, []byte(invalidShare), nil)
	require.NoError(t, err)

	// Try to load invalid share - should fail validation
	_, err = backend.loadShare(attrs, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid share")
}

// TestThresholdSigner_reconstructKey_SkipsCorruptedShares tests that reconstruction skips corrupted shares
func TestThresholdSigner_reconstructKey_SkipsCorruptedShares(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-reconstruct-corrupt",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 2,
			Total:     5, // More shares so we can corrupt some and still have enough
		},
	}

	// Generate key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get signer before corrupting shares
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Corrupt one share - reconstructKey should skip it and use others
	keyID := backend.getKeyID(attrs)
	shareKey := "threshold/shares/" + keyID + "/share-2"
	err = keyStorage.Put(shareKey, []byte("corrupted"), nil)
	require.NoError(t, err)

	// Sign should still work - it has share-1 cached and can use share-3, 4, or 5
	// Ed25519 expects unhashed message and nil opts (or crypto.Hash(0))
	digest := []byte("test message to sign")
	sig, err := signer.Sign(nil, digest, crypto.Hash(0))
	require.NoError(t, err)
	require.NotNil(t, sig)
}
