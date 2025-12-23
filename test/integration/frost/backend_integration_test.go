//go:build integration && frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost_test

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend/frost"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFrostBackend_InterfaceCompliance verifies the backend implements types.Backend
func TestFrostBackend_InterfaceCompliance(t *testing.T) {
	publicStore, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	secretBackend := newTestSecretBackend()

	config := &frost.Config{
		PublicStorage:       publicStore,
		SecretBackend:       secretBackend,
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		ParticipantID:       1,
		EnableNonceTracking: true,
	}

	backend, err := frost.NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	// Verify interface compliance
	var _ types.Backend = backend

	// Check backend type
	assert.Equal(t, types.BackendTypeFrost, backend.Type())

	// Check capabilities
	caps := backend.Capabilities()
	assert.True(t, caps.Keys, "Should support key operations")
	assert.True(t, caps.Signing, "Should support signing")
	assert.False(t, caps.Decryption, "FROST is signing-only per RFC 9591")
	assert.True(t, caps.KeyRotation, "Should support key rotation")
	assert.False(t, caps.HardwareBacked, "Software-based implementation")
}

// TestFrostBackend_KeyLifecycle tests full FROST key lifecycle
func TestFrostBackend_KeyLifecycle(t *testing.T) {
	publicStore, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	secretBackend := newTestSecretBackend()

	config := &frost.Config{
		PublicStorage:       publicStore,
		SecretBackend:       secretBackend,
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		ParticipantID:       1,
		EnableNonceTracking: true,
	}

	backend, err := frost.NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-frost-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Algorithm:     types.FrostAlgorithmEd25519,
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
		},
	}

	// Generate key
	privateKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Verify it's a FROST key handle
	handle, ok := privateKey.(*frost.FrostKeyHandle)
	require.True(t, ok, "Should be FrostKeyHandle")

	assert.Equal(t, "test-frost-key", handle.KeyID)
	assert.Equal(t, types.FrostAlgorithmEd25519, handle.Algorithm)
	assert.Equal(t, uint32(1), handle.ParticipantID)
	assert.NotEmpty(t, handle.GroupPublicKey)
	t.Logf("Group public key size: %d bytes", len(handle.GroupPublicKey))

	// Get signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Verify it implements crypto.Signer
	var _ crypto.Signer = signer

	// List keys
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(keys), 1)

	foundKey := false
	for _, k := range keys {
		if k.CN == "test-frost-key" {
			foundKey = true
			assert.NotNil(t, k.FrostAttributes)
			assert.Equal(t, 2, k.FrostAttributes.Threshold)
			assert.Equal(t, 3, k.FrostAttributes.Total)
		}
	}
	assert.True(t, foundKey, "Should find the generated key")

	// Rotate key
	err = backend.RotateKey(attrs)
	require.NoError(t, err)

	// Get rotated key
	rotatedKey, err := backend.GetKey(attrs)
	require.NoError(t, err)

	rotatedHandle, ok := rotatedKey.(*frost.FrostKeyHandle)
	require.True(t, ok)

	// Public keys should be different after rotation
	assert.NotEqual(t, handle.GroupPublicKey, rotatedHandle.GroupPublicKey,
		"Public key should change after rotation")

	// Delete key
	err = backend.DeleteKey(attrs)
	require.NoError(t, err)

	// Verify deletion
	_, err = backend.GetKey(attrs)
	assert.Error(t, err, "Key should be deleted")
}

// TestFrostBackend_AllAlgorithms tests all supported FROST algorithms
func TestFrostBackend_AllAlgorithms(t *testing.T) {
	algorithms := []types.FrostAlgorithm{
		types.FrostAlgorithmEd25519,
		types.FrostAlgorithmRistretto255,
		types.FrostAlgorithmP256,
		types.FrostAlgorithmSecp256k1,
		// types.FrostAlgorithmEd448, // Skip Ed448 if not available
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			publicStore, err := storage.NewMemoryBackend()
			require.NoError(t, err)

			secretBackend := newTestSecretBackend()

			config := &frost.Config{
				PublicStorage:       publicStore,
				SecretBackend:       secretBackend,
				Algorithm:           algo,
				DefaultThreshold:    2,
				DefaultTotal:        3,
				ParticipantID:       1,
				EnableNonceTracking: true,
			}

			backend, err := frost.NewBackend(config)
			require.NoError(t, err)
			defer backend.Close()

			attrs := &types.KeyAttributes{
				CN:        "test-" + string(algo),
				KeyType:   types.KeyTypeSigning,
				StoreType: types.StoreFrost,
				FrostAttributes: &types.FrostAttributes{
					Algorithm:     algo,
					Threshold:     2,
					Total:         3,
					ParticipantID: 1,
				},
			}

			// Generate key
			key, err := backend.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate key with algorithm %s", algo)

			handle := key.(*frost.FrostKeyHandle)
			assert.Equal(t, algo, handle.Algorithm)
			t.Logf("%s group public key size: %d bytes", algo, len(handle.GroupPublicKey))

			// Clean up
			_ = backend.DeleteKey(attrs)
		})
	}
}

// TestFrostBackend_ThresholdVariations tests different threshold configurations
func TestFrostBackend_ThresholdVariations(t *testing.T) {
	testCases := []struct {
		name      string
		threshold int
		total     int
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"2-of-5", 2, 5},
		{"5-of-7", 5, 7},
		{"3-of-3", 3, 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			publicStore, err := storage.NewMemoryBackend()
			require.NoError(t, err)

			secretBackend := newTestSecretBackend()

			config := &frost.Config{
				PublicStorage:       publicStore,
				SecretBackend:       secretBackend,
				Algorithm:           types.FrostAlgorithmEd25519,
				DefaultThreshold:    tc.threshold,
				DefaultTotal:        tc.total,
				ParticipantID:       1,
				EnableNonceTracking: true,
			}

			backend, err := frost.NewBackend(config)
			require.NoError(t, err)
			defer backend.Close()

			attrs := &types.KeyAttributes{
				CN:        "test-" + tc.name,
				KeyType:   types.KeyTypeSigning,
				StoreType: types.StoreFrost,
				FrostAttributes: &types.FrostAttributes{
					Algorithm:     types.FrostAlgorithmEd25519,
					Threshold:     tc.threshold,
					Total:         tc.total,
					ParticipantID: 1,
				},
			}

			// Generate key
			key, err := backend.GenerateKey(attrs)
			require.NoError(t, err, "Failed to generate %s key", tc.name)

			handle := key.(*frost.FrostKeyHandle)
			t.Logf("%s: Generated key with %d byte public key", tc.name, len(handle.GroupPublicKey))

			// Clean up
			_ = backend.DeleteKey(attrs)
		})
	}
}

// TestFrostBackend_ErrorHandling tests error conditions
func TestFrostBackend_ErrorHandling(t *testing.T) {
	publicStore, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	secretBackend := newTestSecretBackend()

	config := &frost.Config{
		PublicStorage:       publicStore,
		SecretBackend:       secretBackend,
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		ParticipantID:       1,
		EnableNonceTracking: true,
	}

	backend, err := frost.NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("Missing CN", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreFrost,
			FrostAttributes: &types.FrostAttributes{
				Algorithm:     types.FrostAlgorithmEd25519,
				Threshold:     2,
				Total:         3,
				ParticipantID: 1,
			},
		}

		_, err := backend.GenerateKey(attrs)
		assert.Error(t, err, "Should fail without CN")
	})

	t.Run("Duplicate key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:        "duplicate-key",
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreFrost,
			FrostAttributes: &types.FrostAttributes{
				Algorithm:     types.FrostAlgorithmEd25519,
				Threshold:     2,
				Total:         3,
				ParticipantID: 1,
			},
		}

		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		_, err = backend.GenerateKey(attrs)
		assert.Error(t, err, "Should fail on duplicate key")

		_ = backend.DeleteKey(attrs)
	})

	t.Run("Non-existent key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:        "non-existent",
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreFrost,
		}

		_, err := backend.GetKey(attrs)
		assert.Error(t, err, "Should fail for non-existent key")
	})

	t.Run("Decrypter not supported", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:        "decrypter-test",
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreFrost,
			FrostAttributes: &types.FrostAttributes{
				Algorithm:     types.FrostAlgorithmEd25519,
				Threshold:     2,
				Total:         3,
				ParticipantID: 1,
			},
		}

		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		_, err = backend.Decrypter(attrs)
		assert.Error(t, err, "Should fail - FROST doesn't support decryption")

		_ = backend.DeleteKey(attrs)
	})
}

// testSecretBackend is a simple in-memory backend for testing
type testSecretBackend struct {
	store storage.Backend
}

func newTestSecretBackend() *testSecretBackend {
	store, _ := storage.NewMemoryBackend()
	return &testSecretBackend{store: store}
}

func (b *testSecretBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (b *testSecretBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:           true,
		Signing:        false,
		Decryption:     false,
		KeyRotation:    true,
		Import:         true,
		Export:         true,
		HardwareBacked: false,
	}
}

func (b *testSecretBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// For FROST, store the secret share data from SealData
	if attrs.SealData != nil {
		data := attrs.SealData.Bytes()
		if len(data) > 0 {
			path := "frost/secrets/" + attrs.CN + ".secret"
			if err := b.store.Put(path, data, nil); err != nil {
				return nil, fmt.Errorf("failed to store secret: %w", err)
			}
		}
	}
	return nil, nil
}

func (b *testSecretBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	path := "frost/secrets/" + attrs.CN + ".secret"
	data, err := b.store.Get(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	return data, nil
}

func (b *testSecretBackend) DeleteKey(attrs *types.KeyAttributes) error {
	path := "frost/secrets/" + attrs.CN + ".secret"
	return b.store.Delete(path)
}

func (b *testSecretBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (b *testSecretBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}

func (b *testSecretBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}

func (b *testSecretBackend) RotateKey(attrs *types.KeyAttributes) error {
	return nil
}

func (b *testSecretBackend) Close() error {
	return nil
}

// Storage returns the underlying storage backend
func (b *testSecretBackend) Storage() storage.Backend {
	return b.store
}
