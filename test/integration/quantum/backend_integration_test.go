//go:build integration && quantum

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package quantum_test

import (
	"crypto"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend/quantum"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQuantumSafeBackend_InterfaceCompliance verifies the backend implements types.Backend
func TestQuantumSafeBackend_InterfaceCompliance(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := quantum.New(store)
	require.NoError(t, err)
	defer backend.Close()

	// Verify interface compliance
	var _ types.Backend = backend

	// Check backend type
	assert.Equal(t, types.BackendTypeQuantum, backend.Type())

	// Check capabilities
	caps := backend.Capabilities()
	assert.True(t, caps.Keys, "Should support key operations")
	assert.True(t, caps.Signing, "Should support signing with ML-DSA")
	assert.False(t, caps.Decryption, "ML-KEM uses encapsulation, not direct decryption")
	assert.True(t, caps.KeyRotation, "Should support key rotation")
	assert.True(t, caps.KeyAgreement, "Should support key encapsulation")
	assert.False(t, caps.HardwareBacked, "Software-based implementation")
}

// TestQuantumSafeBackend_MLDSAKeyLifecycle tests full ML-DSA key lifecycle
func TestQuantumSafeBackend_MLDSAKeyLifecycle(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := quantum.New(store)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-signing-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
	}

	// Generate key
	privateKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Verify it's a ML-DSA key
	mldsaKey, ok := privateKey.(*quantum.MLDSAPrivateKey)
	require.True(t, ok, "Should be MLDSAPrivateKey")
	defer mldsaKey.Clean()

	assert.Equal(t, "ML-DSA-44", mldsaKey.Algorithm)
	assert.NotNil(t, mldsaKey.PublicKey)
	assert.Greater(t, len(mldsaKey.PublicKey.Key), 1000)

	// Get signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Sign a message
	message := []byte("Test message for quantum signing")
	signature, err := signer.Sign(nil, message, nil)
	require.NoError(t, err)
	require.NotEmpty(t, signature)
	t.Logf("ML-DSA-44 signature size: %d bytes", len(signature))

	// Verify signature using the key's Verify method
	signerKey := signer.(*quantum.MLDSAPrivateKey)
	valid, err := signerKey.Verify(message, signature)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")

	// List keys
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(keys), 1)

	// Rotate key
	err = backend.RotateKey(attrs)
	require.NoError(t, err)

	// Get rotated key
	rotatedKey, err := backend.GetKey(attrs)
	require.NoError(t, err)

	rotatedMLDSA, ok := rotatedKey.(*quantum.MLDSAPrivateKey)
	require.True(t, ok)
	defer rotatedMLDSA.Clean()

	// Public keys should be different after rotation
	assert.NotEqual(t, mldsaKey.PublicKey.Key, rotatedMLDSA.PublicKey.Key,
		"Public key should change after rotation")

	// Delete key
	err = backend.DeleteKey(attrs)
	require.NoError(t, err)

	// Verify deletion
	_, err = backend.GetKey(attrs)
	assert.Error(t, err, "Key should be deleted")
}

// TestQuantumSafeBackend_MLKEMKeyLifecycle tests full ML-KEM key lifecycle
func TestQuantumSafeBackend_MLKEMKeyLifecycle(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := quantum.New(store)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "test-kem-key",
		KeyType:   types.KeyTypeEncryption,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLKEM768,
		},
	}

	// Generate key
	privateKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Verify it's a ML-KEM key
	mlkemKey, ok := privateKey.(*quantum.MLKEMPrivateKey)
	require.True(t, ok, "Should be MLKEMPrivateKey")
	defer mlkemKey.Clean()

	assert.Equal(t, "ML-KEM-768", mlkemKey.Algorithm)
	assert.NotNil(t, mlkemKey.PublicKey)
	assert.Greater(t, len(mlkemKey.PublicKey.Key), 1000)

	t.Logf("ML-KEM-768 public key size: %d bytes", len(mlkemKey.PublicKey.Key))

	// ML-KEM doesn't support Decrypter interface
	_, err = backend.Decrypter(attrs)
	assert.Error(t, err, "ML-KEM should not support Decrypter interface")

	// Test encapsulation/decapsulation
	ciphertext, sharedSecret1, err := mlkemKey.Encapsulate(mlkemKey.PublicKey.Key)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	require.Len(t, sharedSecret1, 32, "Shared secret should be 32 bytes")

	t.Logf("ML-KEM-768 ciphertext size: %d bytes", len(ciphertext))
	t.Logf("ML-KEM-768 shared secret size: %d bytes", len(sharedSecret1))

	sharedSecret2, err := mlkemKey.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, sharedSecret1, sharedSecret2, "Shared secrets should match")

	// Retrieve key from storage
	retrievedKey, err := backend.GetKey(attrs)
	require.NoError(t, err)

	retrievedMLKEM, ok := retrievedKey.(*quantum.MLKEMPrivateKey)
	require.True(t, ok)
	defer retrievedMLKEM.Clean()

	// Retrieved key should be able to decapsulate
	sharedSecret3, err := retrievedMLKEM.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, sharedSecret1, sharedSecret3, "Retrieved key should decapsulate correctly")

	// Delete key
	err = backend.DeleteKey(attrs)
	require.NoError(t, err)
}

// TestQuantumSafeBackend_MultipleKeys tests managing multiple quantum keys
func TestQuantumSafeBackend_MultipleKeys(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := quantum.New(store)
	require.NoError(t, err)
	defer backend.Close()

	// Create multiple keys with different algorithms
	keySpecs := []struct {
		cn        string
		algorithm types.QuantumAlgorithm
		keyType   types.KeyType
	}{
		{"signing-key-1", types.QuantumAlgorithmMLDSA44, types.KeyTypeSigning},
		{"signing-key-2", types.QuantumAlgorithmMLDSA44, types.KeyTypeSigning},
		{"kem-key-1", types.QuantumAlgorithmMLKEM768, types.KeyTypeEncryption},
		{"kem-key-2", types.QuantumAlgorithmMLKEM768, types.KeyTypeEncryption},
	}

	var cleanups []func()

	for _, spec := range keySpecs {
		attrs := &types.KeyAttributes{
			CN:        spec.cn,
			KeyType:   spec.keyType,
			StoreType: types.StoreQuantum,
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: spec.algorithm,
			},
		}

		key, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, key)

		// Track cleanup
		switch k := key.(type) {
		case *quantum.MLDSAPrivateKey:
			cleanups = append(cleanups, k.Clean)
		case *quantum.MLKEMPrivateKey:
			cleanups = append(cleanups, k.Clean)
		}
	}

	// Clean up at end
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	// List all keys
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.Equal(t, 4, len(keys), "Should have 4 keys")

	// Verify each key can be retrieved
	for _, spec := range keySpecs {
		attrs := &types.KeyAttributes{
			CN:        spec.cn,
			KeyType:   spec.keyType,
			StoreType: types.StoreQuantum,
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: spec.algorithm,
			},
		}

		key, err := backend.GetKey(attrs)
		require.NoError(t, err, "Should retrieve key %s", spec.cn)
		require.NotNil(t, key)
	}
}

// TestQuantumSafeBackend_CryptoSignerInterface validates crypto.Signer compliance
func TestQuantumSafeBackend_CryptoSignerInterface(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := quantum.New(store)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "signer-interface-test",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Verify it implements crypto.Signer
	var _ crypto.Signer = signer

	// Check Public() method returns a public key
	pubKey := signer.Public()
	require.NotNil(t, pubKey)

	mldsaPubKey, ok := pubKey.(*quantum.MLDSAPublicKey)
	require.True(t, ok)
	assert.Equal(t, "ML-DSA-44", mldsaPubKey.Algorithm)
	assert.Greater(t, len(mldsaPubKey.Key), 1000)

	// Sign multiple messages
	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2 with more content"),
		[]byte("Message 3 is even longer and has more data to sign"),
	}

	for i, msg := range messages {
		sig, err := signer.Sign(nil, msg, nil)
		require.NoError(t, err, "Should sign message %d", i)
		require.NotEmpty(t, sig)
		t.Logf("Message %d: %d bytes -> signature: %d bytes", i, len(msg), len(sig))
	}

	// Clean up
	mldsaKey := signer.(*quantum.MLDSAPrivateKey)
	mldsaKey.Clean()
}

// TestQuantumSafeBackend_KeyPersistence tests key persistence across retrieval
func TestQuantumSafeBackend_KeyPersistence(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := quantum.New(store)
	require.NoError(t, err)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:        "persistence-test",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreQuantum,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
	}

	// Generate key and sign
	key1, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	mldsaKey1 := key1.(*quantum.MLDSAPrivateKey)
	defer mldsaKey1.Clean()

	message := []byte("Persistence test message")
	sig1, err := mldsaKey1.Sign(nil, message, nil)
	require.NoError(t, err)

	publicKey := mldsaKey1.PublicKey.Key

	// Retrieve key from storage
	key2, err := backend.GetKey(attrs)
	require.NoError(t, err)
	mldsaKey2 := key2.(*quantum.MLDSAPrivateKey)
	defer mldsaKey2.Clean()

	// Sign with retrieved key
	sig2, err := mldsaKey2.Sign(nil, message, nil)
	require.NoError(t, err)

	// Both signatures should verify with the same public key
	valid1, err := mldsaKey2.Verify(message, sig1)
	require.NoError(t, err)
	assert.True(t, valid1, "Signature from original key should verify")

	valid2, err := mldsaKey2.Verify(message, sig2)
	require.NoError(t, err)
	assert.True(t, valid2, "Signature from retrieved key should verify")

	// Public keys should match
	assert.Equal(t, publicKey, mldsaKey2.PublicKey.Key, "Public keys should match after retrieval")
}

// TestQuantumSafeBackend_ErrorHandling tests error conditions
func TestQuantumSafeBackend_ErrorHandling(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	backend, err := quantum.New(store)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("Missing quantum attributes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:        "invalid-key",
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreQuantum,
			// Missing QuantumAttributes
		}

		_, err := backend.GenerateKey(attrs)
		assert.Error(t, err, "Should fail without QuantumAttributes")
	})

	t.Run("Duplicate key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:        "duplicate-key",
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreQuantum,
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithmMLDSA44,
			},
		}

		key1, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		key1.(*quantum.MLDSAPrivateKey).Clean()

		_, err = backend.GenerateKey(attrs)
		assert.Error(t, err, "Should fail on duplicate key")
	})

	t.Run("Non-existent key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:        "non-existent",
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreQuantum,
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithmMLDSA44,
			},
		}

		_, err := backend.GetKey(attrs)
		assert.Error(t, err, "Should fail for non-existent key")
	})

	t.Run("Signer on KEM key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:        "kem-signer-test",
			KeyType:   types.KeyTypeEncryption,
			StoreType: types.StoreQuantum,
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithmMLKEM768,
			},
		}

		key, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		key.(*quantum.MLKEMPrivateKey).Clean()

		_, err = backend.Signer(attrs)
		assert.Error(t, err, "Should fail to get signer for KEM key")
	})
}
