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

//go:build vault

package vault

import (
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getTestVaultConfig returns a test configuration for Vault.
// Requires VAULT_ADDR and VAULT_TOKEN environment variables.
func getTestVaultConfig(t *testing.T) *Config {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")

	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	if token == "" {
		t.Skip("VAULT_TOKEN not set, skipping Vault integration test")
	}

	return &Config{
		Address:       addr,
		Token:         token,
		TransitPath:   "transit",
		KeyStorage:    memory.New(),
		CertStorage:   memory.New(),
		TLSSkipVerify: true,
	}
}

func TestVaultBackend_SymmetricCapabilities(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	caps := b.Capabilities()
	assert.True(t, caps.SymmetricEncryption, "Vault should support symmetric encryption")
	assert.True(t, caps.SupportsSymmetricEncryption())
}

func TestVaultBackend_GenerateSymmetricKey(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-symmetric-key-gen",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if key exists from previous test
	_ = b.DeleteKey(attrs)

	// Generate symmetric key
	symmetricKey, err := b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)
	assert.NotNil(t, symmetricKey)
	assert.Equal(t, string(types.SymmetricAES256GCM), symmetricKey.Algorithm())
	assert.Equal(t, 256, symmetricKey.KeySize())

	// Verify metadata was stored
	exists, err := config.KeyStorage.KeyExists(attrs.CN)
	require.NoError(t, err)
	assert.True(t, exists)

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

func TestVaultBackend_GenerateSymmetricKey_InvalidKeySize(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	// Try to generate with unsupported key size (128 bits)
	attrs := &types.KeyAttributes{
		CN:                 "test-symmetric-key-invalid",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES128GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   128,
			NonceSize: 12,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only supports AES-256")
}

func TestVaultBackend_GenerateSymmetricKey_AsymmetricAlgorithm(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	// Try to generate with asymmetric algorithm
	attrs := &types.KeyAttributes{
		CN:           "test-symmetric-key-asymmetric",
		KeyType:      backend.KEY_TYPE_SECRET,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA, // Wrong algorithm type
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "asymmetric algorithm")
}

func TestVaultBackend_GetSymmetricKey(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-get-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key first
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get the key
	symmetricKey, err := b.GetSymmetricKey(attrs)
	require.NoError(t, err)
	assert.NotNil(t, symmetricKey)
	assert.Equal(t, string(types.SymmetricAES256GCM), symmetricKey.Algorithm())
	assert.Equal(t, 256, symmetricKey.KeySize())

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

func TestVaultBackend_GetSymmetricKey_NotFound(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "non-existent-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	_, err = b.GetSymmetricKey(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestVaultBackend_SymmetricEncrypter_EncryptDecrypt(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-encrypt-decrypt-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	require.NoError(t, err)
	assert.NotNil(t, encrypter)

	// Test data
	plaintext := []byte("Hello, Vault Transit Engine!")

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.NotEmpty(t, encrypted.Ciphertext)
	assert.Equal(t, string(types.SymmetricAES256GCM), encrypted.Algorithm)

	// Verify ciphertext is in Vault format (starts with "vault:v")
	ciphertextStr := string(encrypted.Ciphertext)
	assert.Contains(t, ciphertextStr, "vault:v")

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

func TestVaultBackend_SymmetricEncrypter_WithAAD(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-aad-encryption-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	// Test data with AAD
	plaintext := []byte("Sensitive data with additional authenticated data")
	aad := []byte("context-information")

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	require.NoError(t, err)

	// Decrypt with correct AAD - should succeed
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Decrypt with wrong AAD - should fail
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("wrong-context"),
	})
	assert.Error(t, err, "Decryption with wrong AAD should fail")

	// Decrypt without AAD when it was used - should fail
	_, err = encrypter.Decrypt(encrypted, nil)
	assert.Error(t, err, "Decryption without AAD when it was used should fail")

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

func TestVaultBackend_SymmetricEncrypter_EmptyPlaintext(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-empty-plaintext-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	// Test empty plaintext
	plaintext := []byte{}

	encrypted, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

func TestVaultBackend_SymmetricEncrypter_LargePlaintext(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-large-plaintext-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	// Test with 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

func TestVaultBackend_SymmetricEncrypter_MultipleRoundTrips(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-multi-roundtrip-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	// Test multiple round trips with different data
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"single-char", []byte("a")},
		{"short-string", []byte("Hello, World!")},
		{"with-special-chars", []byte("Special: \n\t\r\x00\xff")},
		{"binary-data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"1kb-data", make([]byte, 1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := encrypter.Encrypt(tc.plaintext, nil)
			require.NoError(t, err)

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

func TestVaultBackend_SymmetricEncrypter_NotFound(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "non-existent-encrypter-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	_, err = b.SymmetricEncrypter(attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestVaultBackend_SymmetricKey_DuplicateGeneration(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-duplicate-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key first time - should succeed
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Try to generate same key again - should fail
	_, err = b.GenerateSymmetricKey(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

// TestVaultBackend_BytesLimit tests AEAD bytes limit enforcement.
// Vault manages nonces server-side, so only bytes tracking is tested.
func TestVaultBackend_BytesLimit(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer b.Close()

	// Generate a key with small bytes limit for testing
	smallLimit := int64(100) // 100 bytes
	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize:   256,
			NonceSize: 12,
		},
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false, // Vault manages nonces
			BytesTracking:      true,
			BytesTrackingLimit: smallLimit,
		},
	}

	// Clean up if exists
	_ = b.DeleteKey(attrs)

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	// Encrypt up to the limit
	plaintext := make([]byte, 50)

	// First 50 bytes - should succeed
	_, err = encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	// Second 50 bytes - should succeed (total 100)
	_, err = encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	// Third 50 bytes - should fail (would exceed 100 byte limit)
	_, err = encrypter.Encrypt(plaintext, nil)
	assert.Error(t, err)

	// Verify error contains bytes limit message
	assert.True(t, errors.Is(err, backend.ErrBytesLimitExceeded) ||
		containsAny(err.Error(), "bytes", "limit", "exceeded"),
		"Expected bytes limit error, got: %v", err)

	// Clean up
	err = b.DeleteKey(attrs)
	require.NoError(t, err)
}

// Helper function to check if a string contains any of the substrings
func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if len(substr) > 0 && containsSubstr(s, substr) {
			return true
		}
	}
	return false
}

func containsSubstr(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
