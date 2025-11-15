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

//go:build integration

package opaque

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyStore implements opaque.KeyStorer for testing
type mockKeyStore struct {
	keys       map[string]crypto.PrivateKey
	signers    map[string]crypto.Signer
	decrypters map[string]crypto.Decrypter
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{
		keys:       make(map[string]crypto.PrivateKey),
		signers:    make(map[string]crypto.Signer),
		decrypters: make(map[string]crypto.Decrypter),
	}
}

func (m *mockKeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if key, ok := m.keys[attrs.CN]; ok {
		return key, nil
	}
	return nil, opaque.ErrInvalidKeyAttributes
}

func (m *mockKeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if signer, ok := m.signers[attrs.CN]; ok {
		return signer, nil
	}
	return nil, opaque.ErrInvalidKeyAttributes
}

func (m *mockKeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if decrypter, ok := m.decrypters[attrs.CN]; ok {
		return decrypter, nil
	}
	return nil, opaque.ErrInvalidKeyAttributes
}

func (m *mockKeyStore) addKey(cn string, key crypto.PrivateKey) {
	m.keys[cn] = key
	if signer, ok := key.(crypto.Signer); ok {
		m.signers[cn] = signer
	}
	if decrypter, ok := key.(crypto.Decrypter); ok {
		m.decrypters[cn] = decrypter
	}
}

// TestOpaqueKeyRSAIntegration tests opaque key operations with RSA keys
func TestOpaqueKeyRSAIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create mock keystore
	keyStore := newMockKeyStore()
	keyStore.addKey("test-rsa", privateKey)

	// Create key attributes
	attrs := &types.KeyAttributes{
		CN:   "test-rsa",
		Hash: crypto.SHA256,
	}

	// Create opaque key
	opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
	require.NoError(t, err, "Failed to create opaque key")

	// Test Public() method
	publicKey := opaqueKey.Public()
	assert.Equal(t, &privateKey.PublicKey, publicKey, "Public key mismatch")

	// Test KeyAttributes() method
	retrievedAttrs := opaqueKey.KeyAttributes()
	assert.Equal(t, attrs, retrievedAttrs, "Key attributes mismatch")

	// Test Digest() method
	message := []byte("Test message for digest")
	digest, err := opaqueKey.Digest(message)
	require.NoError(t, err, "Failed to compute digest")
	require.NotEmpty(t, digest, "Digest should not be empty")

	// Verify digest computation
	hasher := crypto.SHA256.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to compute expected digest")
	expectedDigest := hasher.Sum(nil)
	assert.Equal(t, expectedDigest, digest, "Digest mismatch")

	// Test Sign() method
	signature, err := opaqueKey.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err, "Failed to sign with opaque key")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Verify signature
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, signature)
	assert.NoError(t, err, "Signature verification failed")

	// Test Decrypt() method
	plaintext := []byte("Secret message")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, plaintext)
	require.NoError(t, err, "Failed to encrypt test data")

	decrypted, err := opaqueKey.Decrypt(rand.Reader, ciphertext, nil)
	require.NoError(t, err, "Failed to decrypt with opaque key")
	assert.Equal(t, plaintext, decrypted, "Decrypted data mismatch")
}

// TestOpaqueKeyECDSAIntegration tests opaque key operations with ECDSA keys
func TestOpaqueKeyECDSAIntegration(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	// Create mock keystore
	keyStore := newMockKeyStore()
	keyStore.addKey("test-ecdsa", privateKey)

	// Create key attributes
	attrs := &types.KeyAttributes{
		CN:   "test-ecdsa",
		Hash: crypto.SHA256,
	}

	// Create opaque key
	opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
	require.NoError(t, err, "Failed to create opaque key")

	// Test Public() method
	publicKey := opaqueKey.Public()
	assert.Equal(t, &privateKey.PublicKey, publicKey, "Public key mismatch")

	// Test signing
	message := []byte("Test message for ECDSA")
	digest, err := opaqueKey.Digest(message)
	require.NoError(t, err, "Failed to compute digest")

	signature, err := opaqueKey.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err, "Failed to sign with opaque ECDSA key")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Verify signature
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature)
	assert.True(t, valid, "ECDSA signature verification failed")
}

// TestOpaqueKeyEd25519Integration tests opaque key operations with Ed25519 keys
func TestOpaqueKeyEd25519Integration(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "Failed to generate Ed25519 key")

	// Create mock keystore
	keyStore := newMockKeyStore()
	keyStore.addKey("test-ed25519", privateKey)

	// Create key attributes
	attrs := &types.KeyAttributes{
		CN:   "test-ed25519",
		Hash: crypto.Hash(0), // Ed25519 doesn't use hash functions
	}

	// Create opaque key
	opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, publicKey)
	require.NoError(t, err, "Failed to create opaque key")

	// Test Public() method
	retrievedPublicKey := opaqueKey.Public()
	assert.Equal(t, publicKey, retrievedPublicKey, "Public key mismatch")

	// Test signing (Ed25519 signs the message directly)
	message := []byte("Test message for Ed25519")
	signature, err := opaqueKey.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err, "Failed to sign with opaque Ed25519 key")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Verify signature
	valid := ed25519.Verify(publicKey, message, signature)
	assert.True(t, valid, "Ed25519 signature verification failed")
}

// TestOpaqueKeyEqualIntegration tests the Equal method for key comparison
func TestOpaqueKeyEqualIntegration(t *testing.T) {
	t.Run("RSA Keys Equal", func(t *testing.T) {
		// Generate RSA key pair
		privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key 1")

		privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key 2")

		// Create mock keystore
		keyStore := newMockKeyStore()
		keyStore.addKey("key1", privateKey1)

		// Create opaque key
		attrs := &types.KeyAttributes{CN: "key1", Hash: crypto.SHA256}
		opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey1.PublicKey)
		require.NoError(t, err, "Failed to create opaque key")

		// Test Equal with same key
		assert.True(t, opaqueKey.Equal(privateKey1), "Should be equal to same key")

		// Test Equal with different key
		assert.False(t, opaqueKey.Equal(privateKey2), "Should not be equal to different key")
	})

	t.Run("ECDSA Keys Equal", func(t *testing.T) {
		// Generate ECDSA key pairs
		privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate ECDSA key 1")

		privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate ECDSA key 2")

		// Create mock keystore
		keyStore := newMockKeyStore()
		keyStore.addKey("key1", privateKey1)

		// Create opaque key
		attrs := &types.KeyAttributes{CN: "key1", Hash: crypto.SHA256}
		opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey1.PublicKey)
		require.NoError(t, err, "Failed to create opaque key")

		// Test Equal
		assert.True(t, opaqueKey.Equal(privateKey1), "Should be equal to same key")
		assert.False(t, opaqueKey.Equal(privateKey2), "Should not be equal to different key")
	})

	t.Run("Ed25519 Keys Equal", func(t *testing.T) {
		// Generate Ed25519 key pairs
		pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err, "Failed to generate Ed25519 key 1")

		pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err, "Failed to generate Ed25519 key 2")

		// Create mock keystore
		keyStore := newMockKeyStore()
		keyStore.addKey("key1", priv1)

		// Create opaque key
		attrs := &types.KeyAttributes{CN: "key1", Hash: crypto.Hash(0)}
		opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, pub1)
		require.NoError(t, err, "Failed to create opaque key")

		// Test Equal
		assert.True(t, opaqueKey.Equal(priv1), "Should be equal to same key")
		assert.False(t, opaqueKey.Equal(priv2), "Should not be equal to different key")

		// Clean up
		_ = pub2
	})
}

// TestOpaqueKeyErrorHandlingIntegration tests error handling
func TestOpaqueKeyErrorHandlingIntegration(t *testing.T) {
	t.Run("NilKeyStore", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")

		attrs := &types.KeyAttributes{CN: "test", Hash: crypto.SHA256}
		opaqueKey, err := opaque.NewOpaqueKey(nil, attrs, &privateKey.PublicKey)
		assert.Error(t, err, "Should error with nil keystore")
		assert.Nil(t, opaqueKey, "Opaque key should be nil")
		assert.ErrorIs(t, err, opaque.ErrKeyStoreRequired)
	})

	t.Run("NilKeyAttributes", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")

		keyStore := newMockKeyStore()
		opaqueKey, err := opaque.NewOpaqueKey(keyStore, nil, &privateKey.PublicKey)
		assert.Error(t, err, "Should error with nil key attributes")
		assert.Nil(t, opaqueKey, "Opaque key should be nil")
		assert.ErrorIs(t, err, opaque.ErrInvalidKeyAttributes)
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		keyStore := newMockKeyStore()
		attrs := &types.KeyAttributes{CN: "test", Hash: crypto.SHA256}
		opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, nil)
		assert.Error(t, err, "Should error with nil public key")
		assert.Nil(t, opaqueKey, "Opaque key should be nil")
		assert.ErrorIs(t, err, opaque.ErrInvalidPublicKey)
	})

	t.Run("InvalidHashFunction", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")

		keyStore := newMockKeyStore()
		keyStore.addKey("test", privateKey)

		attrs := &types.KeyAttributes{
			CN:   "test",
			Hash: crypto.Hash(999), // Invalid hash
		}

		opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
		require.NoError(t, err, "Should create opaque key")

		// Digest should fail with invalid hash
		_, err = opaqueKey.Digest([]byte("test"))
		assert.Error(t, err, "Should error with invalid hash")
		assert.ErrorIs(t, err, opaque.ErrInvalidHashFunction)
	})

	t.Run("SignerNotFound", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")

		keyStore := newMockKeyStore()
		// Don't add the key to the keystore

		attrs := &types.KeyAttributes{CN: "missing", Hash: crypto.SHA256}
		opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
		require.NoError(t, err, "Should create opaque key")

		// Sign should fail because key is not in store
		_, err = opaqueKey.Sign(rand.Reader, []byte("test"), crypto.SHA256)
		assert.Error(t, err, "Should error when key not found in store")
	})

	t.Run("DecrypterNotFound", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")

		keyStore := newMockKeyStore()
		// Don't add the key to the keystore

		attrs := &types.KeyAttributes{CN: "missing", Hash: crypto.SHA256}
		opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
		require.NoError(t, err, "Should create opaque key")

		// Decrypt should fail because key is not in store
		_, err = opaqueKey.Decrypt(rand.Reader, []byte("test"), nil)
		assert.Error(t, err, "Should error when key not found in store")
	})
}

// TestOpaqueKeyRSADecryptOptionsIntegration tests RSA decryption with different options
func TestOpaqueKeyRSADecryptOptionsIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create mock keystore
	keyStore := newMockKeyStore()
	keyStore.addKey("test-rsa", privateKey)

	// Create opaque key
	attrs := &types.KeyAttributes{CN: "test-rsa", Hash: crypto.SHA256}
	opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
	require.NoError(t, err, "Failed to create opaque key")

	plaintext := []byte("Secret message for RSA decryption")

	t.Run("PKCS1v15", func(t *testing.T) {
		// Encrypt with PKCS1v15
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, plaintext)
		require.NoError(t, err, "Failed to encrypt with PKCS1v15")

		// Decrypt with opaque key
		decrypted, err := opaqueKey.Decrypt(rand.Reader, ciphertext, nil)
		require.NoError(t, err, "Failed to decrypt PKCS1v15")
		assert.Equal(t, plaintext, decrypted, "Decrypted plaintext mismatch")
	})

	t.Run("OAEP-SHA256", func(t *testing.T) {
		// Encrypt with OAEP-SHA256
		hash := sha256.New()
		ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &privateKey.PublicKey, plaintext, nil)
		require.NoError(t, err, "Failed to encrypt with OAEP-SHA256")

		// Decrypt with opaque key
		opts := &rsa.OAEPOptions{Hash: crypto.SHA256}
		decrypted, err := opaqueKey.Decrypt(rand.Reader, ciphertext, opts)
		require.NoError(t, err, "Failed to decrypt OAEP-SHA256")
		assert.Equal(t, plaintext, decrypted, "Decrypted plaintext mismatch")
	})
}

// TestOpaqueKeyConcurrentIntegration tests concurrent operations
func TestOpaqueKeyConcurrentIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create mock keystore
	keyStore := newMockKeyStore()
	keyStore.addKey("test-concurrent", privateKey)

	// Create opaque key
	attrs := &types.KeyAttributes{CN: "test-concurrent", Hash: crypto.SHA256}
	opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
	require.NoError(t, err, "Failed to create opaque key")

	// Number of concurrent operations
	numOps := 100
	done := make(chan bool, numOps)
	errors := make(chan error, numOps)

	// Test data
	message := []byte("Concurrent test message")
	digest, err := opaqueKey.Digest(message)
	require.NoError(t, err, "Failed to compute digest")

	// Launch concurrent signing operations
	for i := 0; i < numOps; i++ {
		go func() {
			signature, err := opaqueKey.Sign(rand.Reader, digest, crypto.SHA256)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			// Verify signature
			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, signature)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			done <- true
		}()
	}

	// Wait for all operations to complete
	successCount := 0
	for i := 0; i < numOps; i++ {
		select {
		case success := <-done:
			if success {
				successCount++
			}
		case err := <-errors:
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}

	assert.Equal(t, numOps, successCount, "All concurrent operations should succeed")
}

// TestOpaqueKeyDigestCompleteness tests complete digest computation
func TestOpaqueKeyDigestCompleteness(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	keyStore := newMockKeyStore()
	keyStore.addKey("test", privateKey)

	attrs := &types.KeyAttributes{CN: "test", Hash: crypto.SHA256}
	opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
	require.NoError(t, err, "Failed to create opaque key")

	// Test with various data sizes
	testCases := []int{0, 1, 16, 64, 1024, 1024 * 1024} // 0 bytes to 1MB

	for _, size := range testCases {
		t.Run(string(rune(size))+" bytes", func(t *testing.T) {
			data := make([]byte, size)
			_, err := rand.Read(data)
			require.NoError(t, err, "Failed to generate test data")

			digest, err := opaqueKey.Digest(data)
			require.NoError(t, err, "Failed to compute digest")
			assert.Equal(t, 32, len(digest), "SHA256 digest should be 32 bytes")

			// Verify digest is correct
			hasher := crypto.SHA256.New()
			n, err := hasher.Write(data)
			require.NoError(t, err, "Failed to compute expected digest")
			assert.Equal(t, len(data), n, "Should write all data")
			expectedDigest := hasher.Sum(nil)
			assert.Equal(t, expectedDigest, digest, "Digest mismatch")
		})
	}
}

// mockNonEqualKey is a key type that doesn't implement Equal
type mockNonEqualKey struct {
	crypto.Signer
}

func (m *mockNonEqualKey) Public() crypto.PublicKey {
	return "mock-public-key"
}

func (m *mockNonEqualKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte("mock-signature"), nil
}

// TestOpaqueKeyEqualWithNonEqualableKeyIntegration tests Equal with keys that don't implement Equal
func TestOpaqueKeyEqualWithNonEqualableKeyIntegration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	keyStore := newMockKeyStore()
	keyStore.addKey("test", privateKey)

	attrs := &types.KeyAttributes{CN: "test", Hash: crypto.SHA256}
	opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
	require.NoError(t, err, "Failed to create opaque key")

	// Test with non-equalable key type
	mockKey := &mockNonEqualKey{}
	assert.False(t, opaqueKey.Equal(mockKey), "Should not be equal to non-equalable key")

	// Test with non-signer type
	assert.False(t, opaqueKey.Equal("not-a-key"), "Should not be equal to non-key type")
}

// TestOpaqueKeyWithMultipleHashesIntegration tests opaque keys with different hash algorithms
func TestOpaqueKeyWithMultipleHashesIntegration(t *testing.T) {
	hashes := []crypto.Hash{
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}

	for _, hash := range hashes {
		t.Run(hash.String(), func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err, "Failed to generate RSA key")

			keyStore := newMockKeyStore()
			keyStore.addKey("test", privateKey)

			attrs := &types.KeyAttributes{CN: "test", Hash: hash}
			opaqueKey, err := opaque.NewOpaqueKey(keyStore, attrs, &privateKey.PublicKey)
			require.NoError(t, err, "Failed to create opaque key")

			// Test digest computation
			message := []byte("Test message for " + hash.String())
			digest, err := opaqueKey.Digest(message)
			require.NoError(t, err, "Failed to compute digest")
			assert.Equal(t, hash.Size(), len(digest), "Digest size mismatch")

			// Test signing
			signature, err := opaqueKey.Sign(rand.Reader, digest, hash)
			require.NoError(t, err, "Failed to sign")
			require.NotEmpty(t, signature, "Signature should not be empty")

			// Verify signature
			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature)
			assert.NoError(t, err, "Signature verification failed")
		})
	}
}
