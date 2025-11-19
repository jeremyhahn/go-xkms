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

package x25519

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrivateKeyStorage(t *testing.T) {
	ka := New()

	t.Run("successful creation", func(t *testing.T) {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		storage, err := NewPrivateKeyStorage(keyPair.PrivateKey)
		require.NoError(t, err)
		require.NotNil(t, storage)
		assert.Equal(t, keyPair.PrivateKey, storage.PrivateKey())
	})

	t.Run("nil private key", func(t *testing.T) {
		storage, err := NewPrivateKeyStorage(nil)
		assert.Error(t, err)
		assert.Nil(t, storage)
		assert.Contains(t, err.Error(), "private key cannot be nil")
	})

	t.Run("wrong curve type", func(t *testing.T) {
		// Create a P-256 key (wrong curve)
		p256Key, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		storage, err := NewPrivateKeyStorage(p256Key)
		assert.Error(t, err)
		assert.Nil(t, storage)
		assert.Contains(t, err.Error(), "private key must be X25519")
	})
}

func TestPrivateKeyStorage_Public(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	storage, err := NewPrivateKeyStorage(keyPair.PrivateKey)
	require.NoError(t, err)

	t.Run("returns public key", func(t *testing.T) {
		publicKey := storage.Public()
		require.NotNil(t, publicKey)

		// Should implement crypto.PublicKey

		// Should be PublicKeyStorage type
		pubStorage, ok := publicKey.(*PublicKeyStorage)
		require.True(t, ok)
		assert.Equal(t, keyPair.PublicKey.Bytes(), pubStorage.PublicKey().Bytes())
	})
}

func TestPrivateKeyStorage_PrivateKey(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	storage, err := NewPrivateKeyStorage(keyPair.PrivateKey)
	require.NoError(t, err)

	t.Run("returns underlying private key", func(t *testing.T) {
		privateKey := storage.PrivateKey()
		require.NotNil(t, privateKey)
		assert.Equal(t, keyPair.PrivateKey, privateKey)
		assert.Equal(t, keyPair.PrivateKey.Bytes(), privateKey.Bytes())
	})
}

func TestPrivateKeyStorage_Bytes(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	storage, err := NewPrivateKeyStorage(keyPair.PrivateKey)
	require.NoError(t, err)

	t.Run("returns raw key bytes", func(t *testing.T) {
		keyBytes := storage.Bytes()
		require.NotNil(t, keyBytes)
		assert.Len(t, keyBytes, 32) // X25519 keys are 32 bytes
		assert.Equal(t, keyPair.PrivateKey.Bytes(), keyBytes)
	})
}

func TestNewPublicKeyStorage(t *testing.T) {
	ka := New()

	t.Run("successful creation", func(t *testing.T) {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		storage, err := NewPublicKeyStorage(keyPair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, storage)
		assert.Equal(t, keyPair.PublicKey, storage.PublicKey())
	})

	t.Run("nil public key", func(t *testing.T) {
		storage, err := NewPublicKeyStorage(nil)
		assert.Error(t, err)
		assert.Nil(t, storage)
		assert.Contains(t, err.Error(), "public key cannot be nil")
	})

	t.Run("wrong curve type", func(t *testing.T) {
		// Create a P-256 key (wrong curve)
		p256Key, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		storage, err := NewPublicKeyStorage(p256Key.PublicKey())
		assert.Error(t, err)
		assert.Nil(t, storage)
		assert.Contains(t, err.Error(), "public key must be X25519")
	})
}

func TestPublicKeyStorage_PublicKey(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	storage, err := NewPublicKeyStorage(keyPair.PublicKey)
	require.NoError(t, err)

	t.Run("returns underlying public key", func(t *testing.T) {
		publicKey := storage.PublicKey()
		require.NotNil(t, publicKey)
		assert.Equal(t, keyPair.PublicKey, publicKey)
		assert.Equal(t, keyPair.PublicKey.Bytes(), publicKey.Bytes())
	})
}

func TestPublicKeyStorage_Bytes(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	storage, err := NewPublicKeyStorage(keyPair.PublicKey)
	require.NoError(t, err)

	t.Run("returns raw key bytes", func(t *testing.T) {
		keyBytes := storage.Bytes()
		require.NotNil(t, keyBytes)
		assert.Len(t, keyBytes, 32) // X25519 keys are 32 bytes
		assert.Equal(t, keyPair.PublicKey.Bytes(), keyBytes)
	})
}

func TestPrivateKeyStorage_CryptoInterface(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	storage, err := NewPrivateKeyStorage(keyPair.PrivateKey)
	require.NoError(t, err)

	t.Run("implements crypto.PrivateKey", func(t *testing.T) {
		// crypto.PrivateKey is a marker interface, so we just verify it compiles
		var _ crypto.PrivateKey = storage
	})

	t.Run("Public method returns crypto.PublicKey", func(t *testing.T) {
		publicKey := storage.Public()
		_ = publicKey
	})
}

func TestPublicKeyStorage_CryptoInterface(t *testing.T) {
	ka := New()
	keyPair, err := ka.GenerateKey()
	require.NoError(t, err)

	storage, err := NewPublicKeyStorage(keyPair.PublicKey)
	require.NoError(t, err)

	t.Run("implements crypto.PublicKey", func(t *testing.T) {
		// crypto.PublicKey is a marker interface, so we just verify it compiles
		var _ crypto.PublicKey = storage
	})
}

func TestStorageRoundTrip(t *testing.T) {
	ka := New()

	t.Run("private key round trip", func(t *testing.T) {
		// Generate key
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Wrap in storage
		storage, err := NewPrivateKeyStorage(keyPair.PrivateKey)
		require.NoError(t, err)

		// Extract and verify
		extractedPrivateKey := storage.PrivateKey()
		assert.Equal(t, keyPair.PrivateKey.Bytes(), extractedPrivateKey.Bytes())

		// Verify bytes method
		assert.Equal(t, keyPair.PrivateKey.Bytes(), storage.Bytes())

		// Verify public key extraction
		publicKeyStorage := storage.Public().(*PublicKeyStorage)
		assert.Equal(t, keyPair.PublicKey.Bytes(), publicKeyStorage.PublicKey().Bytes())
	})

	t.Run("public key round trip", func(t *testing.T) {
		// Generate key
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Wrap in storage
		storage, err := NewPublicKeyStorage(keyPair.PublicKey)
		require.NoError(t, err)

		// Extract and verify
		extractedPublicKey := storage.PublicKey()
		assert.Equal(t, keyPair.PublicKey.Bytes(), extractedPublicKey.Bytes())

		// Verify bytes method
		assert.Equal(t, keyPair.PublicKey.Bytes(), storage.Bytes())
	})
}

func TestStorageWithKeyAgreement(t *testing.T) {
	ka := New()

	t.Run("key agreement works with storage wrappers", func(t *testing.T) {
		// Generate Alice's key pair
		aliceKeyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Generate Bob's key pair
		bobKeyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Wrap in storage
		aliceStorage, err := NewPrivateKeyStorage(aliceKeyPair.PrivateKey)
		require.NoError(t, err)

		bobStorage, err := NewPrivateKeyStorage(bobKeyPair.PrivateKey)
		require.NoError(t, err)

		// Extract keys from storage and perform key agreement
		aliceSharedSecret, err := ka.DeriveSharedSecret(
			aliceStorage.PrivateKey(),
			bobStorage.Public().(*PublicKeyStorage).PublicKey(),
		)
		require.NoError(t, err)

		bobSharedSecret, err := ka.DeriveSharedSecret(
			bobStorage.PrivateKey(),
			aliceStorage.Public().(*PublicKeyStorage).PublicKey(),
		)
		require.NoError(t, err)

		// Both should derive the same shared secret
		assert.Equal(t, aliceSharedSecret, bobSharedSecret)
	})
}

func TestStorageEdgeCases(t *testing.T) {
	ka := New()

	t.Run("multiple wrappings of same key", func(t *testing.T) {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		// Create multiple storage wrappers for the same key
		storage1, err := NewPrivateKeyStorage(keyPair.PrivateKey)
		require.NoError(t, err)

		storage2, err := NewPrivateKeyStorage(keyPair.PrivateKey)
		require.NoError(t, err)

		// Both should produce the same bytes
		assert.Equal(t, storage1.Bytes(), storage2.Bytes())
		assert.Equal(t, storage1.PrivateKey().Bytes(), storage2.PrivateKey().Bytes())
	})

	t.Run("public key from wrapped private key", func(t *testing.T) {
		keyPair, err := ka.GenerateKey()
		require.NoError(t, err)

		privateStorage, err := NewPrivateKeyStorage(keyPair.PrivateKey)
		require.NoError(t, err)

		// Get public key from private storage
		publicFromPrivate := privateStorage.Public().(*PublicKeyStorage)

		// Create direct public key storage
		publicDirect, err := NewPublicKeyStorage(keyPair.PublicKey)
		require.NoError(t, err)

		// Both should have the same bytes
		assert.Equal(t, publicDirect.Bytes(), publicFromPrivate.Bytes())
	})
}
