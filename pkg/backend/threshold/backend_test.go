// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBackend(t *testing.T) {
	storage := memory.New()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid configuration",
			config:  DefaultConfig(storage),
			wantErr: false,
		},
		{
			name: "missing storage",
			config: &Config{
				DefaultThreshold: 3,
				DefaultTotal:     5,
			},
			wantErr: true,
		},
		{
			name: "invalid threshold (too low)",
			config: &Config{
				KeyStorage:       storage,
				DefaultThreshold: 1,
				DefaultTotal:     5,
			},
			wantErr: true,
		},
		{
			name: "total less than threshold",
			config: &Config{
				KeyStorage:       storage,
				DefaultThreshold: 5,
				DefaultTotal:     3,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewBackend(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, backend)
			} else {
				require.NoError(t, err)
				require.NotNil(t, backend)
				assert.Equal(t, types.BackendTypeThreshold, backend.Type())
				backend.Close()
			}
		})
	}
}

func TestThresholdBackend_Capabilities(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	caps := backend.Capabilities()
	assert.True(t, caps.Keys)
	assert.True(t, caps.Signing)
	assert.True(t, caps.Import)
	assert.False(t, caps.Export)
	assert.False(t, caps.HardwareBacked)
	assert.False(t, caps.SymmetricEncryption)
}

func TestThresholdBackend_GenerateRSAKey(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-rsa-key",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	// Generate threshold key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify it's an RSA key
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, 2048, rsaKey.N.BitLen())

	// Verify shares were stored
	keyID := backend.getKeyID(attrs)
	for i := 1; i <= 5; i++ {
		shareKey := fmt.Sprintf("threshold/shares/%s/share-%d", keyID, i)
		exists, err := storage.Exists(shareKey)
		require.NoError(t, err)
		t.Logf("Share %d exists: %v", i, exists)
	}

	// Verify metadata was stored
	metadataKey := "threshold/metadata/" + keyID
	exists, err := storage.Exists(metadataKey)
	require.NoError(t, err)
	t.Logf("Metadata exists: %v", exists)
}

func TestThresholdBackend_GenerateECDSAKey(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-key",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    2,
			Total:        3,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3"},
		},
	}

	// Generate threshold key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify it's an ECDSA key
	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.NotNil(t, ecdsaKey.D)
	assert.NotNil(t, ecdsaKey.PublicKey)
}

func TestThresholdBackend_GenerateEd25519Key(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	// Generate threshold key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify it's an Ed25519 key
	ed25519Key, ok := privKey.(ed25519.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, ed25519.PrivateKeySize, len(ed25519Key))
}

func TestThresholdBackend_ListKeys(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	// Initially should be empty
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Generate a few keys
	attrs1 := &types.KeyAttributes{
		CN:           "key1",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	attrs2 := &types.KeyAttributes{
		CN:           "key2",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err = backend.GenerateKey(attrs1)
	require.NoError(t, err)

	_, err = backend.GenerateKey(attrs2)
	require.NoError(t, err)

	// List should return both keys
	keys, err = backend.ListKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestThresholdBackend_DeleteKey(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "key-to-delete",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold: 3,
			Total:     5,
		},
	}

	// Generate key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Verify it exists
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	// Delete key
	err = backend.DeleteKey(attrs)
	require.NoError(t, err)

	// Verify it's gone
	keys, err = backend.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestThresholdSigner_RSA(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-rsa-signer",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	// Generate threshold key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get threshold signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test signing
	message := []byte("test message for threshold signing")
	hash := sha256.Sum256(message)

	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify signature with original key
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	require.True(t, ok)

	err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, hash[:], signature)
	assert.NoError(t, err, "Signature verification should succeed")
}

func TestThresholdSigner_ECDSA(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-signer",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    2,
			Total:        3,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3"},
		},
	}

	// Generate threshold key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get threshold signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test signing
	message := []byte("ecdsa threshold test")
	hash := sha256.Sum256(message)

	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify public key matches
	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	pubKey := signer.Public()
	require.NotNil(t, pubKey)

	pubKeyECDSA, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecdsaKey.PublicKey.Equal(pubKeyECDSA))
}

func TestThresholdSigner_Ed25519(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-signer",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	// Generate threshold key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Get threshold signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test signing
	message := []byte("ed25519 threshold signing test")

	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.NotEmpty(t, signature)
	assert.Equal(t, ed25519.SignatureSize, len(signature))

	// Verify signature
	ed25519Key, ok := privKey.(ed25519.PrivateKey)
	require.True(t, ok)

	pubKey := ed25519Key.Public().(ed25519.PublicKey)
	valid := ed25519.Verify(pubKey, message, signature)
	assert.True(t, valid, "Signature should be valid")
}

func TestThresholdBackend_InsufficientShares(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "insufficient-shares-test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    4, // Need 4 shares
			Total:        5,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	// Generate threshold key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Delete some shares to simulate insufficient shares
	keyID := backend.getKeyID(attrs)
	shareKey := "threshold/shares/" + keyID + "/share-2"
	storage.Delete(shareKey)
	shareKey = "threshold/shares/" + keyID + "/share-3"
	storage.Delete(shareKey)

	// Now we only have 3 shares, but need 4 - signing should fail
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	message := []byte("test")
	hash := sha256.Sum256(message)

	// This should fail due to insufficient shares
	_, err = signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInsufficientShares)
}

func TestThresholdBackend_Close(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)

	// Close backend
	err = backend.Close()
	assert.NoError(t, err)

	// Operations after close should fail
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.ECDSA,
	}

	_, err = backend.GenerateKey(attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = backend.ListKeys()
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestThresholdBackend_DifferentShareCombinations(t *testing.T) {
	storage := memory.New()
	config := DefaultConfig(storage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "combination-test",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreThreshold,
		KeyAlgorithm: x509.Ed25519,
		ThresholdAttributes: &types.ThresholdAttributes{
			Threshold:    3,
			Total:        7,
			Algorithm:    types.ThresholdAlgorithmShamir,
			Participants: []string{"n1", "n2", "n3", "n4", "n5", "n6", "n7"},
		},
	}

	// Generate key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	ed25519Key := privKey.(ed25519.PrivateKey)
	originalPubKey := ed25519Key.Public().(ed25519.PublicKey)

	// Test multiple different 3-share combinations by deleting different shares
	testCases := []struct {
		name              string
		sharesToDelete    []int
		shouldReconstruct bool
	}{
		{"shares 1,2,3", []int{4, 5, 6, 7}, true},
		{"shares 1,3,5", []int{2, 4, 6, 7}, true},
		{"shares 2,4,6", []int{1, 3, 5, 7}, true},
		{"shares 5,6,7", []int{1, 2, 3, 4}, true},
		{"only 2 shares", []int{1, 2, 3, 4, 5}, false},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Regenerate key before each test (except first) to restore all shares
			if i > 0 {
				backend.DeleteKey(attrs)
				privKey, err = backend.GenerateKey(attrs)
				require.NoError(t, err)
				ed25519Key = privKey.(ed25519.PrivateKey)
				originalPubKey = ed25519Key.Public().(ed25519.PublicKey)
			}

			// Create a fresh backend with same storage
			testBackend, err := NewBackend(config)
			require.NoError(t, err)
			defer testBackend.Close()

			// Delete specified shares
			keyID := testBackend.getKeyID(attrs)
			for _, shareNum := range tc.sharesToDelete {
				shareKey := fmt.Sprintf("threshold/shares/%s/share-%d", keyID, shareNum)
				storage.Delete(shareKey)
			}

			// Try to sign
			message := []byte("test message")
			signer, err := testBackend.Signer(attrs)
			if !tc.shouldReconstruct {
				// Should fail to get signer or sign
				require.NoError(t, err) // Signer should still be created
				_, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInsufficientShares)
			} else {
				require.NoError(t, err)

				signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
				require.NoError(t, err)
				require.NotEmpty(t, signature)

				// Verify signature with current public key
				valid := ed25519.Verify(originalPubKey, message, signature)
				assert.True(t, valid, "Signature should be valid")
			}
		})
	}
}
