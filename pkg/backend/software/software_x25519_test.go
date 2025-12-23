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

package software_test

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSoftwareBackend_X25519_GenerateKey(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:               "test.x25519",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}

	key, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Verify we got an X25519 wrapped key
	wrappedKey, ok := key.(*x25519.PrivateKeyStorage)
	require.True(t, ok, "expected X25519 wrapped key")
	assert.NotNil(t, wrappedKey.PrivateKey())
	assert.Len(t, wrappedKey.Bytes(), 32)
}

func TestSoftwareBackend_X25519_GetKey(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:               "test.x25519.get",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}

	// Generate key
	generatedKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	generatedBytes := generatedKey.(*x25519.PrivateKeyStorage).Bytes()

	// Retrieve key
	retrievedKey, err := backend.GetKey(attrs)
	require.NoError(t, err)
	retrievedBytes := retrievedKey.(*x25519.PrivateKeyStorage).Bytes()

	// Keys should match
	assert.True(t, bytes.Equal(generatedBytes, retrievedBytes))
}

func TestSoftwareBackend_X25519_DeriveSharedSecret(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Cast to concrete type to access KeyAgreement methods
	concreteBackend := backend.(*software.SoftwareBackend)

	// Generate Alice's key pair
	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.x25519",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	aliceKey, err := backend.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's key pair
	bobAttrs := &types.KeyAttributes{
		CN:               "bob.x25519",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	bobKey, err := backend.GenerateKey(bobAttrs)
	require.NoError(t, err)

	// Get Bob's public key
	bobPublicKey := bobKey.(*x25519.PrivateKeyStorage).Public().(*x25519.PublicKeyStorage)

	// Alice derives shared secret using Bob's public key
	aliceSecret, err := concreteBackend.DeriveSharedSecret(aliceAttrs, bobPublicKey)
	require.NoError(t, err)
	assert.Len(t, aliceSecret, 32)

	// Get Alice's public key
	alicePublicKey := aliceKey.(*x25519.PrivateKeyStorage).Public().(*x25519.PublicKeyStorage)

	// Bob derives shared secret using Alice's public key
	bobSecret, err := concreteBackend.DeriveSharedSecret(bobAttrs, alicePublicKey)
	require.NoError(t, err)
	assert.Len(t, bobSecret, 32)

	// Both secrets should be identical
	assert.True(t, bytes.Equal(aliceSecret, bobSecret),
		"Alice and Bob should derive the same shared secret")
}

func TestSoftwareBackend_X25519_DeriveSharedSecretDeterministic(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	concreteBackend := backend.(*software.SoftwareBackend)

	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.determ",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	_, err = backend.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobAttrs := &types.KeyAttributes{
		CN:               "bob.determ",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	bobKey, err := backend.GenerateKey(bobAttrs)
	require.NoError(t, err)

	bobPublicKey := bobKey.(*x25519.PrivateKeyStorage).Public().(*x25519.PublicKeyStorage)

	// Derive shared secret multiple times
	const numIterations = 10
	secrets := make([][]byte, numIterations)

	for i := 0; i < numIterations; i++ {
		secret, err := concreteBackend.DeriveSharedSecret(aliceAttrs, bobPublicKey)
		require.NoError(t, err)
		secrets[i] = secret
	}

	// All secrets should be identical
	for i := 1; i < numIterations; i++ {
		assert.True(t, bytes.Equal(secrets[0], secrets[i]),
			"ECDH should be deterministic")
	}
}

func TestSoftwareBackend_X25519_PublicKeyFromPrivate(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:               "test.pubkey",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}

	privateKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	wrapped := privateKey.(*x25519.PrivateKeyStorage)
	publicKey := wrapped.Public()

	assert.NotNil(t, publicKey)
	pubKeyStorage, ok := publicKey.(*x25519.PublicKeyStorage)
	require.True(t, ok)

	// Public key should be 32 bytes
	assert.Len(t, pubKeyStorage.Bytes(), 32)

	// Public key should be deterministically derived from private key
	publicKey2 := wrapped.Public()
	pubKeyStorage2 := publicKey2.(*x25519.PublicKeyStorage)
	assert.True(t, bytes.Equal(pubKeyStorage.Bytes(), pubKeyStorage2.Bytes()))
}

func TestSoftwareBackend_X25519_Capabilities(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()
	assert.True(t, caps.Keys)
	assert.True(t, caps.Signing)
	assert.True(t, caps.Decryption)
	assert.True(t, caps.KeyAgreement, "Backend should support key agreement")
	assert.True(t, caps.SymmetricEncryption)
}

func TestSoftwareBackend_X25519_DeleteKey(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:               "test.delete",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}

	// Generate key
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Verify it exists
	_, err = backend.GetKey(attrs)
	require.NoError(t, err)

	// Delete it
	err = backend.DeleteKey(attrs)
	require.NoError(t, err)

	// Verify it's gone
	_, err = backend.GetKey(attrs)
	assert.Error(t, err)
}

func TestSoftwareBackend_X25519_ListKeys(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Generate an X25519 key
	attrs := &types.KeyAttributes{
		CN:               "test.list.x25519",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// List keys
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.NotNil(t, keys)

	// Verify X25519 key is in the list by common name
	found := false
	for _, key := range keys {
		if key.CN == attrs.CN {
			found = true
			break
		}
	}
	assert.True(t, found, "X25519 key not found in list by common name")
}

func TestSoftwareBackend_X25519_DeriveWithKDF(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	concreteBackend := backend.(*software.SoftwareBackend)

	// Generate key pairs
	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.kdf",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	_, err = backend.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobAttrs := &types.KeyAttributes{
		CN:               "bob.kdf",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}
	bobKey, err := backend.GenerateKey(bobAttrs)
	require.NoError(t, err)

	bobPublicKey := bobKey.(*x25519.PrivateKeyStorage).Public().(*x25519.PublicKeyStorage)

	// Derive shared secret
	sharedSecret, err := concreteBackend.DeriveSharedSecret(aliceAttrs, bobPublicKey)
	require.NoError(t, err)

	// Derive encryption key from shared secret using HKDF
	ka := x25519.New()
	encryptionKey, err := ka.DeriveKey(sharedSecret, nil, []byte("encryption"), 32)
	require.NoError(t, err)

	assert.Len(t, encryptionKey, 32)
	assert.NotEqual(t, encryptionKey, sharedSecret,
		"derived key should be different from shared secret")
}

func TestSoftwareBackend_X25519_InterfaceCompliance(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	// Verify interface compliance
	var _ types.Backend = backend
	_ = backend

	// The concrete SoftwareBackend also implements KeyAgreement
	// But this is not exposed in the public types.SymmetricBackend interface
	// We can still call DeriveSharedSecret on backends that support it
	assert.NotNil(t, backend)
}

func TestSoftwareBackend_X25519_InvalidPublicKey(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	concreteBackend := backend.(*software.SoftwareBackend)

	attrs := &types.KeyAttributes{
		CN:               "test.invalid",
		KeyType:          types.KeyTypeEncryption,
		StoreType:        types.StoreSoftware,
		X25519Attributes: &types.X25519Attributes{},
	}

	_, err = backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Try to use a nil public key
	_, err = concreteBackend.DeriveSharedSecret(attrs, nil)
	assert.Error(t, err)
}

func TestSoftwareBackend_X25519_InvalidAttributes(t *testing.T) {
	keyStorage := storage.New()
	config := &software.Config{KeyStorage: keyStorage}
	backend, err := software.NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	concreteBackend := backend.(*software.SoftwareBackend)

	// Try to use nil attributes
	_, err = concreteBackend.DeriveSharedSecret(nil, nil)
	assert.Error(t, err)
}
