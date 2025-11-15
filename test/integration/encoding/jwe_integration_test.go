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
// +build integration

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWEIntegration_RSAEncryption tests JWE encryption/decryption with RSA keys
func TestJWEIntegration_RSAEncryption(t *testing.T) {
	plaintext := []byte("secret message for encryption")

	t.Run("RSA_OAEP_A256GCM", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Encrypt
		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, jweString)
		assert.Contains(t, jweString, ".") // Compact serialization

		// Decrypt
		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("RSA_OAEP_256_A192GCM", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A192GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("RSA_OAEP_A128GCM", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A128GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("RSA_OAEP_A256CBC_HS512", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256CBC-HS512", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("RSA_OAEP_AutoDetectAlgorithm", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Use empty string for auto-detection
		encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestJWEIntegration_ECDHEncryption tests ECDH-based encryption
func TestJWEIntegration_ECDHEncryption(t *testing.T) {
	plaintext := []byte("ecdh encrypted message")

	t.Run("ECDH_ES_A256KW_A256GCM", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("ECDH-ES+A256KW", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("ECDH_ES_A128KW_A128GCM_P384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("ECDH-ES+A128KW", "A128GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("ECDH_ES_AutoDetect", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		// Auto-detect content encryption algorithm
		encrypter, err := jwe.NewEncrypter("ECDH-ES+A256KW", "", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestJWEIntegration_SymmetricEncryption tests symmetric key encryption
func TestJWEIntegration_SymmetricEncryption(t *testing.T) {
	plaintext := []byte("symmetric encrypted data")

	t.Run("A256KW_A256GCM", func(t *testing.T) {
		// 256-bit symmetric key
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("A256KW", "A256GCM", key)
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, key)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("A128KW_A128GCM", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := rand.Read(key)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("A128KW", "A128GCM", key)
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, key)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("DirectEncryption", func(t *testing.T) {
		// For direct encryption, key size must match content encryption
		key := make([]byte, 32) // 256-bit for A256GCM
		_, err := rand.Read(key)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("dir", "A256GCM", key)
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, key)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestJWEIntegration_KeychainIntegration tests keychain-backed JWE operations
func TestJWEIntegration_KeychainIntegration(t *testing.T) {
	plaintext := []byte("keychain encrypted data")

	t.Run("RSA_KeychainEncryption", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwe-rsa-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// Create keychain encrypter
		encrypter, err := jwe.NewKeychainEncrypter(
			"RSA-OAEP-256",
			"A256GCM",
			setup.GetPublicKeyByID,
		)
		require.NoError(t, err)

		// Encrypt with keyID
		jweString, err := encrypter.EncryptWithKeyID(plaintext, keyID)
		require.NoError(t, err)
		assert.NotEmpty(t, jweString)

		// Verify kid is in header
		kid, err := jwe.ExtractKID(jweString)
		require.NoError(t, err)
		assert.Equal(t, keyID, kid)

		// Decrypt with keychain decrypter
		decrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		decrypted, err := decrypter.DecryptWithAutoKeyID(jweString)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("ECDSA_P256_KeychainEncryption", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwe-ecdsa-p256-key"
		err := setup.GenerateECDSAKey(keyID, elliptic.P256())
		require.NoError(t, err)

		encrypter, err := jwe.NewKeychainEncrypter(
			"ECDH-ES+A256KW",
			"A256GCM",
			setup.GetPublicKeyByID,
		)
		require.NoError(t, err)

		jweString, err := encrypter.EncryptWithKeyID(plaintext, keyID)
		require.NoError(t, err)

		// For ECDSA keys, get the key directly and decrypt
		// go-jose accepts *ecdsa.PrivateKey for ECDH operations
		privateKey, err := setup.GetKeyByID(keyID)
		require.NoError(t, err)

		basicDecrypter := jwe.NewDecrypter()
		decrypted, err := basicDecrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("AutoKeyID_Detection", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwe-auto-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewKeychainEncrypter(
			"RSA-OAEP",
			"A256GCM",
			setup.GetPublicKeyByID,
		)
		require.NoError(t, err)

		jweString, err := encrypter.EncryptWithKeyID(plaintext, keyID)
		require.NoError(t, err)

		// Decrypt using auto kid extraction
		decrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		decrypted, err := decrypter.Decrypt(jweString)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("ExplicitKeyID_Override", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID1 := "pkcs8:jwe-key-1"
		keyID2 := "pkcs8:jwe-key-2"

		err := setup.GenerateRSAKey(keyID1, 2048)
		require.NoError(t, err)
		err = setup.GenerateRSAKey(keyID2, 2048)
		require.NoError(t, err)

		// Encrypt with key1
		encrypter, err := jwe.NewKeychainEncrypter(
			"RSA-OAEP-256",
			"A256GCM",
			setup.GetPublicKeyByID,
		)
		require.NoError(t, err)

		jweString, err := encrypter.EncryptWithKeyID(plaintext, keyID1)
		require.NoError(t, err)

		// Decrypt with key1 explicitly (should work)
		decrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		decrypted, err := decrypter.DecryptWithKeyID(jweString, keyID1)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// Try to decrypt with key2 (should fail - wrong key)
		_, err = decrypter.DecryptWithKeyID(jweString, keyID2)
		assert.Error(t, err)
	})
}

// TestJWEIntegration_HeaderSupport tests custom header support
func TestJWEIntegration_HeaderSupport(t *testing.T) {
	plaintext := []byte("data with headers")

	t.Run("KID_Header", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		// Encrypt with kid header
		jweString, err := encrypter.EncryptWithHeader(plaintext, map[string]interface{}{
			"kid": "my-key-123",
		})
		require.NoError(t, err)

		// Extract and verify kid
		kid, err := jwe.ExtractKID(jweString)
		require.NoError(t, err)
		assert.Equal(t, "my-key-123", kid)

		// Decrypt
		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("MultipleHeaders", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.EncryptWithHeader(plaintext, map[string]interface{}{
			"kid": "key-456",
			"typ": "JWT",
			"cty": "application/json",
		})
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// TestJWEIntegration_ErrorHandling tests error cases
func TestJWEIntegration_ErrorHandling(t *testing.T) {
	plaintext := []byte("test data")

	t.Run("WrongDecryptionKey", func(t *testing.T) {
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", key1.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		// Try to decrypt with wrong key
		decrypter := jwe.NewDecrypter()
		_, err = decrypter.Decrypt(jweString, key2)
		assert.Error(t, err)
	})

	t.Run("CorruptedCiphertext", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		// Corrupt the JWE
		corrupted := jweString[:len(jweString)-20] + "xxxxxxxxxxxxxxxxxxxx"

		decrypter := jwe.NewDecrypter()
		_, err = decrypter.Decrypt(corrupted, privateKey)
		assert.Error(t, err)
	})

	t.Run("InvalidJWEFormat", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()

		invalidJWEs := []string{
			"not.a.jwe",
			"",
			"invalid",
			"a.b.c", // Not enough parts
		}

		for _, invalid := range invalidJWEs {
			_, err := decrypter.Decrypt(invalid, privateKey)
			assert.Error(t, err)
		}
	})

	t.Run("NilKey", func(t *testing.T) {
		_, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		_, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", "invalid-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported")
	})

	t.Run("InvalidAlgorithm", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		_, err = jwe.NewEncrypter("INVALID-ALG", "A256GCM", privateKey.Public())
		assert.Error(t, err)
	})

	t.Run("KeychainKeyNotFound", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		encrypter, err := jwe.NewKeychainEncrypter(
			"RSA-OAEP",
			"A256GCM",
			setup.GetPublicKeyByID,
		)
		require.NoError(t, err)

		// Try to encrypt with non-existent key
		_, err = encrypter.EncryptWithKeyID(plaintext, "pkcs8:non-existent-key")
		assert.Error(t, err)
	})

	t.Run("EmptyKID", func(t *testing.T) {
		setup := createTestBackend(t)
		defer setup.Close()

		keyID := "pkcs8:jwe-test-key"
		err := setup.GenerateRSAKey(keyID, 2048)
		require.NoError(t, err)

		// Encrypt without kid header
		key, err := setup.GetKeyByID(keyID)
		require.NoError(t, err)

		privateKey, ok := key.(crypto.Decrypter)
		require.True(t, ok)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)

		// Try to decrypt with auto kid (should fail - no kid in header)
		decrypter := jwe.NewKeychainDecrypter(setup.GetDecrypterByID)
		_, err = decrypter.DecryptWithAutoKeyID(jweString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kid")
	})
}

// TestJWEIntegration_LargePayloads tests encryption of larger data
func TestJWEIntegration_LargePayloads(t *testing.T) {
	t.Run("1MB_Payload", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Generate 1MB of random data
		plaintext := make([]byte, 1024*1024)
		_, err = rand.Read(plaintext)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		jweString, err := encrypter.Encrypt(plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, jweString)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("MinimalPayload", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A256GCM", privateKey.Public())
		require.NoError(t, err)

		// Encrypt minimal data (1 byte)
		// Note: go-jose doesn't support zero-length payloads
		minimalData := []byte{0x00}
		jweString, err := encrypter.Encrypt(minimalData)
		require.NoError(t, err)

		decrypter := jwe.NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		require.NoError(t, err)
		assert.Equal(t, minimalData, decrypted)
	})
}
