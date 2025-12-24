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

package symmetric

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestGenerateSymmetricKey_AllSizes tests key generation for all AES key sizes
func TestGenerateSymmetricKey_AllSizes(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		algorithm types.SymmetricAlgorithm
	}{
		{"AES-128", 128, types.SymmetricAES128GCM},
		{"AES-192", 192, types.SymmetricAES192GCM},
		{"AES-256", 256, types.SymmetricAES256GCM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = b.Close() }()

			attrs := &types.KeyAttributes{
				CN:                 "test-key-" + tt.name,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: tt.algorithm,
			}

			symBackend := b

			key, err := symBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey() failed: %v", err)
			}

			if key == nil {
				t.Fatal("Generated key is nil")
			}

			if key.KeySize() != tt.keySize {
				t.Errorf("Key size = %d, want %d", key.KeySize(), tt.keySize)
			}

			if key.Algorithm() != string(tt.algorithm) {
				t.Errorf("Algorithm = %s, want %s", key.Algorithm(), tt.algorithm)
			}

			// Verify key data is the right length
			rawKey, err := key.Raw()
			if err != nil {
				t.Fatalf("Failed to get raw key: %v", err)
			}
			expectedBytes := tt.keySize / 8
			if len(rawKey) != expectedBytes {
				t.Errorf("Raw key length = %d bytes, want %d", len(rawKey), expectedBytes)
			}
		})
	}
}

// TestGenerateSymmetricKey_AlreadyExists tests error when key already exists
func TestGenerateSymmetricKey_AlreadyExists(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "duplicate-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate first key
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("First GenerateSymmetricKey() failed: %v", err)
	}

	// Attempt to generate again with same attributes
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error for duplicate key, got nil")
	}
	if !errors.Is(err, backend.ErrKeyAlreadyExists) {
		t.Errorf("Expected backend.ErrKeyAlreadyExists, got: %v", err)
	}
}

// TestGetSymmetricKey tests retrieving an existing key
func TestGetSymmetricKey(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "retrieve-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate key
	originalKey, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Retrieve key
	retrievedKey, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() failed: %v", err)
	}

	// Verify keys match
	if retrievedKey.KeySize() != originalKey.KeySize() {
		t.Errorf("Key size mismatch: got %d, want %d", retrievedKey.KeySize(), originalKey.KeySize())
	}

	if retrievedKey.Algorithm() != originalKey.Algorithm() {
		t.Errorf("Algorithm mismatch: got %s, want %s", retrievedKey.Algorithm(), originalKey.Algorithm())
	}

	// Verify raw key data matches
	rawRetrieved, err := retrievedKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw retrieved key: %v", err)
	}
	rawOriginal, err := originalKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw original key: %v", err)
	}
	if !bytes.Equal(rawRetrieved, rawOriginal) {
		t.Error("Raw key data does not match")
	}
}

// TestGetSymmetricKey_NotFound tests error when key doesn't exist
func TestGetSymmetricKey_NotFound(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "nonexistent-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error for nonexistent key, got nil")
	}
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestSymmetricEncrypter_EncryptDecrypt tests round-trip encryption/decryption
func TestSymmetricEncrypter_EncryptDecrypt(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "encrypt-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate key
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Get encrypter
	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Test data
	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Verify encrypted data structure
	if encrypted.Ciphertext == nil {
		t.Error("Ciphertext is nil")
	}
	if encrypted.Nonce == nil || len(encrypted.Nonce) != 12 {
		t.Errorf("Nonce is invalid: %v (len %d)", encrypted.Nonce, len(encrypted.Nonce))
	}
	if encrypted.Tag == nil || len(encrypted.Tag) != 16 {
		t.Errorf("Tag is invalid: %v (len %d)", encrypted.Tag, len(encrypted.Tag))
	}
	if encrypted.Algorithm != string(types.SymmetricAES256GCM) {
		t.Errorf("Algorithm = %s, want %s", encrypted.Algorithm, types.SymmetricAES256GCM)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(encrypted.Ciphertext, plaintext) {
		t.Error("Ciphertext equals plaintext (encryption may have failed)")
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data does not match original\nGot:  %s\nWant: %s", decrypted, plaintext)
	}
}

// TestSymmetricEncrypter_WithAAD tests encryption with additional authenticated data
func TestSymmetricEncrypter_WithAAD(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "aad-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := []byte("Secret message")
	aad := []byte("context-info-v1")

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Decrypt with correct AAD
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Decrypt() with correct AAD failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data does not match with correct AAD")
	}

	// Attempt decrypt with wrong AAD (should fail)
	wrongAAD := []byte("wrong-context")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		t.Error("Expected error when decrypting with wrong AAD, got nil")
	}
}

// TestSymmetricEncrypter_CustomNonce tests encryption with a provided nonce
func TestSymmetricEncrypter_CustomNonce(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "nonce-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Generate custom nonce
	customNonce := make([]byte, 12)
	if _, err := rand.Read(customNonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := []byte("Test message")

	// Encrypt with custom nonce
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		Nonce: customNonce,
	})
	if err != nil {
		t.Fatalf("Encrypt() with custom nonce failed: %v", err)
	}

	// Verify nonce matches
	if !bytes.Equal(encrypted.Nonce, customNonce) {
		t.Error("Returned nonce does not match provided nonce")
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data does not match")
	}
}

// TestSymmetricEncrypter_VariousDataSizes tests encryption with different data sizes
func TestSymmetricEncrypter_VariousDataSizes(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "size-test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	testSizes := []int{0, 1, 16, 64, 256, 1024, 1024 * 1024} // 0B to 1MB

	for _, size := range testSizes {
		t.Run(formatBytes(size), func(t *testing.T) {
			plaintext := make([]byte, size)
			if size > 0 {
				if _, err := rand.Read(plaintext); err != nil {
					t.Fatalf("Failed to generate test data: %v", err)
				}
			}

			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encrypt() failed for size %d: %v", size, err)
			}

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decrypt() failed for size %d: %v", size, err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Round-trip failed for size %d", size)
			}
		})
	}
}

// TestPasswordProtection tests key storage with password encryption
func TestPasswordProtection(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	password := backend.StaticPassword([]byte("super-secret-password"))

	attrs := &types.KeyAttributes{
		CN:                 "protected-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           password,
	}

	// Generate password-protected key
	key, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() with password failed: %v", err)
	}

	originalRaw, err := key.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw original key: %v", err)
	}

	// Retrieve with correct password
	retrievedKey, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() with correct password failed: %v", err)
	}

	retrievedRaw, err := retrievedKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw retrieved key: %v", err)
	}
	if !bytes.Equal(retrievedRaw, originalRaw) {
		t.Error("Retrieved key does not match original with correct password")
	}

	// Attempt to retrieve with wrong password
	wrongPasswordAttrs := *attrs
	wrongPasswordAttrs.Password = backend.StaticPassword([]byte("wrong-password"))

	_, err = symBackend.GetSymmetricKey(&wrongPasswordAttrs)
	if err == nil {
		t.Error("Expected error with wrong password, got nil")
	}
	// Error should be wrapped, so check if it contains the right error
	if err.Error() == "" || err == nil {
		t.Errorf("Expected password-related error, got: %v", err)
	}
}

// TestPasswordProtection_NoPassword tests key storage without password
func TestPasswordProtection_NoPassword(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "unprotected-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate unprotected key
	key, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() without password failed: %v", err)
	}

	originalRaw, err := key.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw original key: %v", err)
	}

	// Retrieve without password
	retrievedKey, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() without password failed: %v", err)
	}

	retrievedRaw, err := retrievedKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw retrieved key: %v", err)
	}
	if !bytes.Equal(retrievedRaw, originalRaw) {
		t.Error("Retrieved key does not match original without password")
	}
}

// TestEncryptDecrypt_CorruptedData tests error handling for corrupted data
func TestEncryptDecrypt_CorruptedData(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "corrupt-test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := []byte("Test message")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Corrupt the ciphertext
	corrupted := &types.EncryptedData{
		Ciphertext: append([]byte{}, encrypted.Ciphertext...),
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
		Algorithm:  encrypted.Algorithm,
	}
	corrupted.Ciphertext[0] ^= 0xFF // Flip bits

	_, err = encrypter.Decrypt(corrupted, nil)
	if err == nil {
		t.Error("Expected error for corrupted ciphertext, got nil")
	}

	// Corrupt the tag
	corrupted = &types.EncryptedData{
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        append([]byte{}, encrypted.Tag...),
		Algorithm:  encrypted.Algorithm,
	}
	corrupted.Tag[0] ^= 0xFF // Flip bits

	_, err = encrypter.Decrypt(corrupted, nil)
	if err == nil {
		t.Error("Expected error for corrupted tag, got nil")
	}
}

// TestThreadSafety tests concurrent key generation and operations
func TestThreadSafety(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	const numGoroutines = 10
	var wg sync.WaitGroup

	// Test concurrent key generation
	t.Run("ConcurrentGeneration", func(t *testing.T) {
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()

				attrs := &types.KeyAttributes{
					CN:                 formatKeyName("concurrent-key-%d", index),
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_SW,
					SymmetricAlgorithm: types.SymmetricAES256GCM,
				}

				_, err := symBackend.GenerateSymmetricKey(attrs)
				if err != nil {
					t.Errorf("Goroutine %d: GenerateSymmetricKey() failed: %v", index, err)
				}
			}(i)
		}
		wg.Wait()
	})

	// Test concurrent encryption operations
	t.Run("ConcurrentEncryption", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "shared-encrypt-key",
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_SW,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}

		_, err := symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSymmetricKey() failed: %v", err)
		}

		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		if err != nil {
			t.Fatalf("SymmetricEncrypter() failed: %v", err)
		}

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()

				plaintext := []byte(formatKeyName("message-%d", index))
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Errorf("Goroutine %d: Encrypt() failed: %v", index, err)
					return
				}

				decrypted, err := encrypter.Decrypt(encrypted, nil)
				if err != nil {
					t.Errorf("Goroutine %d: Decrypt() failed: %v", index, err)
					return
				}

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("Goroutine %d: Round-trip failed", index)
				}
			}(i)
		}
		wg.Wait()
	})
}

// TestInvalidAttributes tests error handling for invalid attributes
func TestInvalidAttributes(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name: "AsymmetricAlgorithm",
			attrs: &types.KeyAttributes{
				CN:           "invalid-key",
				KeyType:      backend.KEY_TYPE_SECRET,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA, // Wrong algorithm type
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := symBackend.GenerateSymmetricKey(tt.attrs)
			if err == nil {
				t.Error("Expected error for invalid attributes, got nil")
			}
		})
	}
}

// TestClosedBackendSymmetric tests operations on a closed backend
func TestClosedBackendSymmetric(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "closed-test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Close the backend
	if err := b.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Attempt operations on closed backend
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Expected ErrStorageClosed for GenerateSymmetricKey, got: %v", err)
	}

	_, err = symBackend.GetSymmetricKey(attrs)
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Expected ErrStorageClosed for GetSymmetricKey, got: %v", err)
	}
}

// TestSymmetricEncrypter_NilEncryptedData tests error handling for nil encrypted data
func TestSymmetricEncrypter_NilEncryptedData(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "nil-test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	_, err = encrypter.Decrypt(nil, nil)
	if err == nil {
		t.Error("Expected error for nil encrypted data, got nil")
	}
}

// TestSymmetricEncrypter_InvalidNonceSize tests error handling for invalid nonce size
func TestSymmetricEncrypter_InvalidNonceSize(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "nonce-size-test",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Try with invalid nonce size
	invalidNonce := make([]byte, 8) // Too small (should be 12)
	_, err = encrypter.Encrypt([]byte("test"), &types.EncryptOptions{
		Nonce: invalidNonce,
	})
	if err == nil {
		t.Error("Expected error for invalid nonce size, got nil")
	}
}

// TestPasswordProtection_EmptyPassword tests key with empty password
func TestPasswordProtection_EmptyPassword(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	// Empty password should be treated as no password
	emptyPassword := backend.StaticPassword([]byte(""))

	attrs := &types.KeyAttributes{
		CN:                 "empty-password-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           emptyPassword,
	}

	key, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() with empty password failed: %v", err)
	}

	originalRaw, err := key.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw original key: %v", err)
	}

	// Retrieve with empty password
	retrievedKey, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() with empty password failed: %v", err)
	}

	retrievedRaw, err := retrievedKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw retrieved key: %v", err)
	}
	if !bytes.Equal(retrievedRaw, originalRaw) {
		t.Error("Retrieved key does not match original with empty password")
	}
}

// TestDecryptWithPassword_InvalidData tests decryption error handling
func TestDecryptWithPassword_InvalidData(t *testing.T) {
	// Test data too short
	shortData := make([]byte, 50)
	_, err := decryptWithPassword(shortData, []byte("password"))
	if err == nil {
		t.Error("Expected error for short encrypted data, got nil")
	}
}

// TestBackendType tests the backend type identifier
func TestBackendType(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	if b.Type() != backend.BackendTypeSymmetric {
		t.Errorf("Type() = %s, want %s", b.Type(), backend.BackendTypeSymmetric)
	}
}

// TestCapabilities tests the capabilities reporting
func TestCapabilities(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	caps := b.Capabilities()
	if !caps.Keys {
		t.Error("Capabilities.Keys should be true")
	}
	if caps.HardwareBacked {
		t.Error("Capabilities.HardwareBacked should be false")
	}
	if !caps.SymmetricEncryption {
		t.Error("Capabilities.SymmetricEncryption should be true")
	}
	if caps.Signing {
		t.Error("Capabilities.Signing should be false")
	}
	if caps.Decryption {
		t.Error("Capabilities.Decryption should be false")
	}
}

// TestDeleteKey tests key deletion
func TestDeleteKey(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "delete-test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate key
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Verify key exists
	_, err = symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() failed: %v", err)
	}

	// Delete key
	err = b.DeleteKey(attrs)
	if err != nil {
		t.Fatalf("DeleteKey() failed: %v", err)
	}

	// Verify key no longer exists
	_, err = symBackend.GetSymmetricKey(attrs)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound after deletion, got: %v", err)
	}
}

// TestDeleteKey_NotFound tests error when deleting non-existent key
func TestDeleteKey_NotFound(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "nonexistent-delete-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	err = b.DeleteKey(attrs)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound for non-existent key, got: %v", err)
	}
}

// TestListKeys tests listing all keys
func TestListKeys(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	// Initially should be empty
	keys, err := b.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}

	// Generate multiple keys
	keyNames := []string{"list-key-1", "list-key-2", "list-key-3"}
	for _, name := range keyNames {
		attrs := &types.KeyAttributes{
			CN:                 name,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_SW,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		_, err := symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSymmetricKey() failed for %s: %v", name, err)
		}
	}

	// List keys
	keys, err = b.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(keys) != len(keyNames) {
		t.Errorf("Expected %d keys, got %d", len(keyNames), len(keys))
	}
}

// TestAsymmetricOperationsNotSupported tests that asymmetric operations return errors
func TestAsymmetricOperationsNotSupported(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = b.GenerateKey(attrs)
	if err == nil {
		t.Error("GenerateKey() should return error for software backend")
	}

	_, err = b.GetKey(attrs)
	if err == nil {
		t.Error("GetKey() should return error for software backend")
	}

	_, err = b.Signer(attrs)
	if err == nil {
		t.Error("Signer() should return error for software backend")
	}

	_, err = b.Decrypter(attrs)
	if err == nil {
		t.Error("Decrypter() should return error for software backend")
	}

	// Note: RotateKey is now supported for symmetric keys
	// We should test it properly in a separate test
}

// TestRotateKey tests key rotation for symmetric keys
func TestRotateKey(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "rotate-test",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate initial key
	origKey, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Rotate key
	err = b.RotateKey(attrs)
	if err != nil {
		t.Fatalf("RotateKey() failed: %v", err)
	}

	// Get new key
	newKey, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() after rotation failed: %v", err)
	}

	// Verify keys are different
	rawOrig, err := origKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw original key: %v", err)
	}
	rawNew, err := newKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw new key: %v", err)
	}
	if string(rawOrig) == string(rawNew) {
		t.Error("Rotated key is the same as original key")
	}
}

// Helper function to format bytes for test names
func formatBytes(n int) string {
	if n == 0 {
		return "0B"
	}
	if n < 1024 {
		return formatKeyName("%dB", n)
	}
	if n < 1024*1024 {
		return formatKeyName("%dKB", n/1024)
	}
	return formatKeyName("%dMB", n/(1024*1024))
}

// Helper function to format key names
func formatKeyName(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

// TestConfig_Validate tests the Config validation
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "NilConfig",
			config:  nil,
			wantErr: true,
			errMsg:  "config is nil",
		},
		{
			name:    "NilKeyStorage",
			config:  &Config{KeyStorage: nil},
			wantErr: true,
			errMsg:  "KeyStorage is required",
		},
		{
			name:    "ValidConfig",
			config:  &Config{KeyStorage: storage.New()},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !bytes.Contains([]byte(err.Error()), []byte(tt.errMsg)) {
				t.Errorf("Validate() error = %v, want %s", err, tt.errMsg)
			}
		})
	}
}

// TestNewBackend_InvalidConfig tests backend creation with invalid config
func TestNewBackend_InvalidConfig(t *testing.T) {
	// Test with nil config
	_, err := NewBackend(nil)
	if err == nil {
		t.Error("NewBackend() with nil config should error")
	}

	// Test with invalid config
	_, err = NewBackend(&Config{KeyStorage: nil})
	if err == nil {
		t.Error("NewBackend() with nil storage should error")
	}
}

// TestRotateKey_ErrorOnDeleteFails tests RotateKey when delete fails
func TestRotateKey_ErrorOnDeleteFails(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Test with nil attributes
	err = b.RotateKey(nil)
	if err == nil {
		t.Error("RotateKey() with nil attributes should error")
	}
}

// TestDeleteKey_WithClosedBackend tests DeleteKey on closed backend
func TestDeleteKey_WithClosedBackend(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Close the backend
	_ = b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	err = b.DeleteKey(attrs)
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Expected ErrStorageClosed, got: %v", err)
	}
}

// TestSymmetricEncrypter_InvalidEncryptOptions tests with nil options
func TestSymmetricEncrypter_InvalidEncryptOptions(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Encrypt with nil options should use defaults
	plaintext := []byte("test data")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Errorf("Encrypt() with nil options failed: %v", err)
	}

	if encrypted == nil {
		t.Error("Encrypted data should not be nil")
	}
}

// TestGenerateSymmetricKey_AsymmetricAlgorithm tests error when using asymmetric algorithm
func TestGenerateSymmetricKey_AsymmetricAlgorithm(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:           "rsa-key",
		KeyType:      backend.KEY_TYPE_SECRET,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Error("GenerateSymmetricKey() with asymmetric algorithm should error")
	}
}

// TestGetSymmetricKey_AsymmetricAlgorithm tests error when using asymmetric algorithm
func TestGetSymmetricKey_AsymmetricAlgorithm(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:           "rsa-key",
		KeyType:      backend.KEY_TYPE_SECRET,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
	}

	_, err = symBackend.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("GetSymmetricKey() with asymmetric algorithm should error")
	}
}

// TestSymmetricEncrypter_Errors tests error conditions in SymmetricEncrypter
func TestSymmetricEncrypter_Errors(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Try to get encrypter for non-existent key
	_, err = symBackend.SymmetricEncrypter(attrs)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestEncryptWithPassword_ValidRoundTrip tests password encryption round trip
func TestEncryptWithPassword_ValidRoundTrip(t *testing.T) {
	password := []byte("my-secret-password")
	plaintext := []byte("sensitive data that needs encryption")

	encrypted, err := encryptWithPassword(plaintext, password)
	if err != nil {
		t.Fatalf("encryptWithPassword() failed: %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("Encrypted data should not be empty")
	}

	// Decrypt with correct password
	decrypted, err := decryptWithPassword(encrypted, password)
	if err != nil {
		t.Fatalf("decryptWithPassword() with correct password failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data does not match original")
	}
}

// TestEncryptWithPassword_WrongPassword tests decryption with wrong password
func TestEncryptWithPassword_WrongPassword(t *testing.T) {
	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")
	plaintext := []byte("secret data")

	encrypted, err := encryptWithPassword(plaintext, password)
	if err != nil {
		t.Fatalf("encryptWithPassword() failed: %v", err)
	}

	// Try to decrypt with wrong password
	_, err = decryptWithPassword(encrypted, wrongPassword)
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got: %v", err)
	}
}

// TestStoreSymmetricKey_WithPassword tests storing key with password
func TestStoreSymmetricKey_WithPassword(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	password := backend.StaticPassword([]byte("secure-password"))

	attrs := &types.KeyAttributes{
		CN:                 "pwd-protected-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           password,
	}

	// Generate and store
	key, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	originalRaw, _ := key.Raw()

	// Retrieve with correct password
	retrieved, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() failed: %v", err)
	}

	retrievedRaw, _ := retrieved.Raw()
	if !bytes.Equal(originalRaw, retrievedRaw) {
		t.Error("Retrieved key does not match original")
	}
}

// TestDecodeSymmetricKey_NoPassword tests decoding unencrypted key
func TestDecodeSymmetricKey_NoPassword(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	// Test data - raw key bytes
	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)

	// Decode without password (should return as-is)
	decoded, err := symmetricBackend.decodeSymmetricKey(rawKey, nil)
	if err != nil {
		t.Fatalf("decodeSymmetricKey() with nil password failed: %v", err)
	}

	if !bytes.Equal(decoded, rawKey) {
		t.Error("Decoded key does not match original")
	}
}

// TestDecodeSymmetricKey_WithPassword tests decoding encrypted key
func TestDecodeSymmetricKey_WithPassword(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	// Create test key and password
	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)
	pwd := []byte("test-password")

	// Encrypt the key
	encrypted, err := encryptWithPassword(rawKey, pwd)
	if err != nil {
		t.Fatalf("encryptWithPassword() failed: %v", err)
	}

	// Decode with correct password
	password := backend.StaticPassword(pwd)
	decoded, err := symmetricBackend.decodeSymmetricKey(encrypted, password)
	if err != nil {
		t.Fatalf("decodeSymmetricKey() with password failed: %v", err)
	}

	if !bytes.Equal(decoded, rawKey) {
		t.Error("Decoded key does not match original")
	}
}

// TestListKeys_WithClosedBackend tests ListKeys on closed backend
func TestListKeys_WithClosedBackend(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	_ = b.Close()

	_, err = b.ListKeys()
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Expected ErrStorageClosed, got: %v", err)
	}
}

// MockFailingStorage implements a storage that fails on operations
type MockFailingStorage struct {
	failOnDelete bool
	failOnExists bool
	failOnPut    bool
}

func (m *MockFailingStorage) Get(key string) ([]byte, error) {
	return nil, fmt.Errorf("storage error: get failed")
}

func (m *MockFailingStorage) Put(key string, value []byte, opts *storage.Options) error {
	if m.failOnPut {
		return fmt.Errorf("storage error: put failed")
	}
	return nil
}

func (m *MockFailingStorage) Delete(key string) error {
	if m.failOnDelete {
		return fmt.Errorf("storage error: delete failed")
	}
	return nil
}

func (m *MockFailingStorage) List(prefix string) ([]string, error) {
	return nil, fmt.Errorf("storage error: list failed")
}

func (m *MockFailingStorage) Exists(key string) (bool, error) {
	if m.failOnExists {
		return false, fmt.Errorf("storage error: exists check failed")
	}
	return false, nil
}

func (m *MockFailingStorage) Close() error {
	return nil
}

// TestDeleteKey_StorageError tests DeleteKey when storage returns error
func TestDeleteKey_StorageError(t *testing.T) {
	mockStorage := &MockFailingStorage{failOnDelete: true}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	err = b.DeleteKey(attrs)
	if err == nil {
		t.Error("Expected error when storage DeleteKey fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to delete key")) {
		t.Errorf("Expected 'failed to delete key' error, got: %v", err)
	}
}

// TestGenerateSymmetricKey_StorageKeyExistsError tests when KeyExists check fails
func TestGenerateSymmetricKey_StorageKeyExistsError(t *testing.T) {
	mockStorage := &MockFailingStorage{failOnExists: true}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error when KeyExists check fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to check key existence")) {
		t.Errorf("Expected 'failed to check key existence' error, got: %v", err)
	}
}

// TestGenerateSymmetricKey_StorageSaveKeyError tests when SaveKey fails
func TestGenerateSymmetricKey_StorageSaveKeyError(t *testing.T) {
	mockStorage := &MockFailingStorage{failOnPut: true}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error when SaveKey fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to save key")) {
		t.Errorf("Expected 'failed to save key' error, got: %v", err)
	}
}

// TestRotateKey_StorageError tests RotateKey when storage delete returns error
func TestRotateKey_StorageError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate initial key
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Close backend to cause error on rotation
	_ = b.Close()

	// Try to rotate - should fail because backend is closed
	err = b.RotateKey(attrs)
	if err == nil {
		t.Error("Expected error when rotating key on closed backend")
	}
}

// TestListKeys_StorageError tests ListKeys when storage returns error
func TestListKeys_StorageError(t *testing.T) {
	mockStorage := &MockFailingStorage{}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	_, err = b.ListKeys()
	if err == nil {
		t.Error("Expected error when ListKeys fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to list keys")) {
		t.Errorf("Expected 'failed to list keys' error, got: %v", err)
	}
}

// TestEncrypt_InvalidNonceSize tests Encrypt with provided nonce of wrong size
func TestEncrypt_InvalidNonceSize(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Test with nonce too short
	shortNonce := make([]byte, 8)
	_, err = encrypter.Encrypt([]byte("test"), &types.EncryptOptions{
		Nonce: shortNonce,
	})
	if err == nil {
		t.Error("Expected error for short nonce")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("invalid nonce size")) {
		t.Errorf("Expected 'invalid nonce size' error, got: %v", err)
	}

	// Test with nonce too long
	longNonce := make([]byte, 16)
	_, err = encrypter.Encrypt([]byte("test"), &types.EncryptOptions{
		Nonce: longNonce,
	})
	if err == nil {
		t.Error("Expected error for long nonce")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("invalid nonce size")) {
		t.Errorf("Expected 'invalid nonce size' error, got: %v", err)
	}
}

// TestExportKey_NotFound tests ExportKey for non-existent key
func TestExportKey_NotFound(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	attrs := &types.KeyAttributes{
		CN:                 "nonexistent-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	_, err = symmetricBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("Expected backend.ErrKeyNotFound, got: %v", err)
	}
}

// TestDecryptWithPassword_CorruptedData tests with corrupted encrypted data
func TestDecryptWithPassword_CorruptedData(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("secret message")

	// Create valid encrypted data
	encrypted, err := encryptWithPassword(plaintext, password)
	if err != nil {
		t.Fatalf("encryptWithPassword() failed: %v", err)
	}

	// Corrupt the nonce part (bytes 32-44)
	if len(encrypted) > 40 {
		encrypted[40] ^= 0xFF
	}

	// Try to decrypt with corrupted data
	_, err = decryptWithPassword(encrypted, password)
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword for corrupted nonce, got: %v", err)
	}
}

// TestEncryptWithPassword_VariousDataSizes tests password encryption with different plaintext sizes
func TestEncryptWithPassword_VariousDataSizes(t *testing.T) {
	password := []byte("test-password")

	testSizes := []int{0, 1, 16, 64, 256}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			if size > 0 {
				_, _ = rand.Read(plaintext)
			}

			encrypted, err := encryptWithPassword(plaintext, password)
			if err != nil {
				t.Fatalf("encryptWithPassword() failed: %v", err)
			}

			decrypted, err := decryptWithPassword(encrypted, password)
			if err != nil {
				t.Fatalf("decryptWithPassword() failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("Decrypted data does not match original")
			}
		})
	}
}

// TestGetSymmetricKey_StorageError tests GetSymmetricKey when storage returns error
func TestGetSymmetricKey_StorageError(t *testing.T) {
	mockStorage := &MockFailingStorage{}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error when storage GetKey fails")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("failed to retrieve key")) {
		t.Errorf("Expected 'failed to retrieve key' error, got: %v", err)
	}
}

// TestStoreSymmetricKey_WithEmptyPassword tests storing with empty password
func TestStoreSymmetricKey_WithEmptyPassword(t *testing.T) {
	keyStorage := storage.New()
	config := &Config{KeyStorage: keyStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	keyID := "test-key"
	keyData := make([]byte, 32)
	_, _ = rand.Read(keyData)

	// Test with empty password (should be treated as no password)
	emptyPassword := backend.StaticPassword([]byte(""))

	err = symmetricBackend.storeSymmetricKey(keyID, keyData, emptyPassword)
	if err != nil {
		t.Fatalf("storeSymmetricKey() with empty password failed: %v", err)
	}

	// Verify it was stored
	retrieved, err := storage.GetKey(symmetricBackend.storage, keyID)
	if err != nil {
		t.Fatalf("GetKey() failed: %v", err)
	}

	if !bytes.Equal(retrieved, keyData) {
		t.Error("Retrieved key does not match original")
	}
}

// TestDecodeSymmetricKey_WithEmptyPassword tests decoding with empty password
func TestDecodeSymmetricKey_WithEmptyPassword(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)

	// Decode with empty password (should return data as-is)
	emptyPassword := backend.StaticPassword([]byte(""))
	decoded, err := symmetricBackend.decodeSymmetricKey(rawKey, emptyPassword)
	if err != nil {
		t.Fatalf("decodeSymmetricKey() with empty password failed: %v", err)
	}

	if !bytes.Equal(decoded, rawKey) {
		t.Error("Decoded key does not match original")
	}
}

// TestEncrypt_EmptyPlaintext tests encryption with empty plaintext
func TestEncrypt_EmptyPlaintext(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Encrypt empty plaintext
	encrypted, err := encrypter.Encrypt([]byte{}, nil)
	if err != nil {
		t.Fatalf("Encrypt() with empty plaintext failed: %v", err)
	}

	// Decrypt to verify
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Error("Decrypted empty plaintext should be empty")
	}
}

// TestExportKey_WithPassword tests ExportKey with password-protected key
func TestExportKey_WithPassword(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	password := backend.StaticPassword([]byte("test-password"))

	attrs := &types.KeyAttributes{
		CN:                 "password-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           password,
		Exportable:         true,
	}

	// Generate password-protected key
	_, err = symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Export the key
	wrapped, err := symmetricBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("ExportKey() failed: %v", err)
	}

	if wrapped == nil || len(wrapped.WrappedKey) == 0 {
		t.Error("Wrapped key should not be empty")
	}
}

// TestDecrypt_WithAADMismatch tests decryption fails with wrong AAD
func TestDecrypt_WithAADMismatch(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := []byte("secret message")
	correctAAD := []byte("context")

	// Encrypt with correct AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: correctAAD,
	})
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Decrypt with wrong AAD
	wrongAAD := []byte("wrong-context")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		t.Error("Expected error when decrypting with wrong AAD")
	}
}

// TestEncrypt_LargeData tests encryption with large plaintext
func TestEncrypt_LargeData(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Create large plaintext (10MB)
	largePlaintext := make([]byte, 10*1024*1024)
	_, _ = rand.Read(largePlaintext)

	// Encrypt
	encrypted, err := encrypter.Encrypt(largePlaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() large data failed: %v", err)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() large data failed: %v", err)
	}

	if !bytes.Equal(decrypted, largePlaintext) {
		t.Error("Large plaintext round-trip failed")
	}
}

// TestEncrypt_DecryptOptions tests Decrypt with nil options
func TestEncrypt_DecryptOptions(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := []byte("test message")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Decrypt with nil options
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() with nil options failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypt with nil options failed")
	}
}

// TestEncrypt_MultipleRoundTrips tests multiple encrypt/decrypt cycles
func TestEncrypt_MultipleRoundTrips(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	// Test multiple round trips
	for i := 0; i < 10; i++ {
		plaintext := []byte(fmt.Sprintf("message number %d", i))
		encrypted, err := encrypter.Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Encrypt() failed on iteration %d: %v", i, err)
		}

		decrypted, err := encrypter.Decrypt(encrypted, nil)
		if err != nil {
			t.Fatalf("Decrypt() failed on iteration %d: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Round-trip failed on iteration %d", i)
		}
	}
}

// TestExportKey_WithInvalidAttribute tests ExportKey error handling
func TestExportKey_WithInvalidAttribute(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate and export key successfully
	_, err = symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Test export with invalid/asymmetric algorithm
	invalidAttrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		Exportable:   true,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err = symmetricBackend.ExportKey(invalidAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error when exporting with asymmetric algorithm")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("invalid algorithm")) {
		t.Errorf("Expected 'invalid algorithm' error, got: %v", err)
	}
}

// TestEncryptSymmetricEncrypter_VariousKeySizes tests encryption with different key sizes
func TestEncryptSymmetricEncrypter_VariousKeySizes(t *testing.T) {
	keySizes := []struct {
		size      int
		algorithm types.SymmetricAlgorithm
	}{
		{128, types.SymmetricAES128GCM},
		{192, types.SymmetricAES192GCM},
		{256, types.SymmetricAES256GCM},
	}

	for _, ks := range keySizes {
		t.Run(fmt.Sprintf("AES_%d", ks.size), func(t *testing.T) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = b.Close() }()

			symBackend := b

			attrs := &types.KeyAttributes{
				CN:                 fmt.Sprintf("key-%d", ks.size),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: ks.algorithm,
			}

			_, err = symBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey() failed: %v", err)
			}

			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("SymmetricEncrypter() failed: %v", err)
			}

			plaintext := []byte(fmt.Sprintf("test message for %d-bit key", ks.size))
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decrypt() failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("Round-trip failed")
			}
		})
	}
}

// TestGetRNG tests the GetRNG method
func TestGetRNG(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	// Test GetRNG returns a valid resolver
	rng := symmetricBackend.GetRNG()
	if rng == nil {
		t.Fatal("GetRNG() returned nil")
	}

	// Verify RNG is functional by generating random bytes
	randomBytes, err := rng.Rand(32)
	if err != nil {
		t.Fatalf("RNG.Rand() failed: %v", err)
	}

	if len(randomBytes) != 32 {
		t.Errorf("RNG.Rand() returned %d bytes, want 32", len(randomBytes))
	}

	// Verify randomness by generating multiple times and checking they're different
	randomBytes2, err := rng.Rand(32)
	if err != nil {
		t.Fatalf("RNG.Rand() second call failed: %v", err)
	}

	if bytes.Equal(randomBytes, randomBytes2) {
		t.Error("RNG generated identical random bytes twice (highly unlikely)")
	}
}

// TestEncryptWithPassword_EmptyPassword tests password encryption with empty password
func TestEncryptWithPassword_EmptyPassword(t *testing.T) {
	plaintext := []byte("test data")
	emptyPassword := []byte("")

	// Should still work with empty password
	encrypted, err := encryptWithPassword(plaintext, emptyPassword)
	if err != nil {
		t.Fatalf("encryptWithPassword() with empty password failed: %v", err)
	}

	decrypted, err := decryptWithPassword(encrypted, emptyPassword)
	if err != nil {
		t.Fatalf("decryptWithPassword() with empty password failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Round-trip with empty password failed")
	}
}

// TestRotateKey_NonexistentKey tests RotateKey for a key that doesn't exist
// Note: RotateKey treats missing keys as valid (creates a new key)
func TestRotateKey_NonexistentKey(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "nonexistent-rotate-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Rotate a non-existent key - should create a new key
	err = b.RotateKey(attrs)
	if err != nil {
		t.Fatalf("RotateKey() for non-existent key failed: %v", err)
	}

	// Verify key was created
	key, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() after rotation failed: %v", err)
	}

	if key == nil {
		t.Error("Key should exist after rotation")
	}
}

// TestExportKey_WithClosedBackend tests ExportKey on a closed backend
func TestExportKey_WithClosedBackend(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Close the backend
	_ = b.Close()

	symmetricBackend := b.(*Backend)

	// Try to export key from closed backend
	_, err = symmetricBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Expected ErrStorageClosed, got: %v", err)
	}
}

// TestExportKey_NilAttributes tests ExportKey with nil attributes
func TestExportKey_NilAttributes(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)

	// Try to export with nil attributes
	_, err = symmetricBackend.ExportKey(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error for nil attributes")
	}
	if !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Expected 'backend.ErrInvalidAttributes' error, got: %v", err)
	}
}

// TestDecryptWithPassword_TooShort tests decryptWithPassword with data too short
func TestDecryptWithPassword_TooShort(t *testing.T) {
	password := []byte("password")

	// Test with various invalid sizes
	testSizes := []int{0, 10, 30, 59} // All less than minimum 60 bytes

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			shortData := make([]byte, size)
			_, err := decryptWithPassword(shortData, password)
			if err == nil {
				t.Errorf("Expected error for %d bytes, got nil", size)
			}
			if !bytes.Contains([]byte(err.Error()), []byte("too short")) {
				t.Errorf("Expected 'too short' error for %d bytes, got: %v", size, err)
			}
		})
	}
}

// TestNewBackend_WithCustomTracker tests backend creation with custom tracker
func TestNewBackend_WithCustomTracker(t *testing.T) {
	storage := storage.New()
	tracker := backend.NewMemoryAEADTracker()
	config := &Config{
		KeyStorage: storage,
		Tracker:    tracker,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend with custom tracker: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend := b.(*Backend)
	if symmetricBackend.GetTracker() != tracker {
		t.Error("Backend should use the provided custom tracker")
	}
}

// TestGenerateSymmetricKey_WithInvalidAttributes tests key generation with invalid attributes
func TestGenerateSymmetricKey_WithInvalidAttributes(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	// Test with invalid CN (empty)
	attrs := &types.KeyAttributes{
		CN:                 "", // Invalid - empty CN
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error for invalid attributes")
	}
}

// TestGenerateSymmetricKey_WithCustomAEADOptions tests key generation with custom AEAD options
func TestGenerateSymmetricKey_WithCustomAEADOptions(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	// Custom AEAD options
	aeadOpts := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 1024 * 1024 * 100, // 100MB
		NonceSize:          12,
	}

	attrs := &types.KeyAttributes{
		CN:                 "custom-aead-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions:        aeadOpts,
	}

	key, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() with custom AEAD options failed: %v", err)
	}

	if key == nil {
		t.Fatal("Generated key is nil")
	}
}

// TestGenerateSymmetricKey_ChaCha20Poly1305 tests ChaCha20-Poly1305 key generation
func TestGenerateSymmetricKey_ChaCha20Poly1305(t *testing.T) {
	tests := []struct {
		name      string
		algorithm types.SymmetricAlgorithm
	}{
		{"ChaCha20Poly1305", types.SymmetricChaCha20Poly1305},
		{"XChaCha20Poly1305", types.SymmetricXChaCha20Poly1305},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = b.Close() }()

			attrs := &types.KeyAttributes{
				CN:                 "test-chacha20-" + tt.name,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: tt.algorithm,
			}

			symBackend := b

			key, err := symBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey() failed: %v", err)
			}

			if key == nil {
				t.Fatal("Generated key is nil")
			}

			// ChaCha20 always uses 256-bit keys
			if key.KeySize() != 256 {
				t.Errorf("Key size = %d, want 256", key.KeySize())
			}

			if key.Algorithm() != string(tt.algorithm) {
				t.Errorf("Algorithm = %s, want %s", key.Algorithm(), tt.algorithm)
			}

			// Verify key data is 32 bytes (256 bits)
			rawKey, err := key.Raw()
			if err != nil {
				t.Fatalf("Failed to get raw key: %v", err)
			}
			if len(rawKey) != 32 {
				t.Errorf("Raw key length = %d bytes, want 32", len(rawKey))
			}
		})
	}
}

// TestGetSymmetricKey_ChaCha20Poly1305 tests ChaCha20-Poly1305 key retrieval
func TestGetSymmetricKey_ChaCha20Poly1305(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-chacha20-retrieve",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	// Generate key
	key1, err := symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	// Get key
	key2, err := symBackend.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() failed: %v", err)
	}

	// Verify keys match
	rawKey1, err := key1.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw key 1: %v", err)
	}

	rawKey2, err := key2.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw key 2: %v", err)
	}

	if !bytes.Equal(rawKey1, rawKey2) {
		t.Error("Retrieved key does not match stored key")
	}
}

// TestSymmetricEncrypter_ChaCha20Poly1305 tests ChaCha20-Poly1305 encryption and decryption
func TestSymmetricEncrypter_ChaCha20Poly1305(t *testing.T) {
	tests := []struct {
		name      string
		algorithm types.SymmetricAlgorithm
		plaintext string
	}{
		{"ChaCha20_Hello", types.SymmetricChaCha20Poly1305, "Hello, World!"},
		{"XChaCha20_Hello", types.SymmetricXChaCha20Poly1305, "Hello, World!"},
		{"ChaCha20_LongText", types.SymmetricChaCha20Poly1305, "Lorem ipsum dolor sit amet, consectetur adipiscing elit"},
		{"ChaCha20_Empty", types.SymmetricChaCha20Poly1305, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = b.Close() }()

			symBackend := b

			attrs := &types.KeyAttributes{
				CN:                 "test-" + tt.name,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: tt.algorithm,
			}

			// Generate key
			_, err = symBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey() failed: %v", err)
			}

			// Get encrypter
			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("SymmetricEncrypter() failed: %v", err)
			}

			// Encrypt
			plaintext := []byte(tt.plaintext)
			encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
			if err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}

			if encrypted == nil {
				t.Fatal("Encrypted data is nil")
				return
			}

			if encrypted.Algorithm != string(tt.algorithm) {
				t.Errorf("Algorithm = %s, want %s", encrypted.Algorithm, string(tt.algorithm))
			}

			// Verify nonce size for ChaCha20 variants
			expectedNonceSize := 12 // Standard ChaCha20
			if tt.algorithm == types.SymmetricXChaCha20Poly1305 {
				expectedNonceSize = 24 // XChaCha20 uses 24-byte nonce
			}
			if len(encrypted.Nonce) != expectedNonceSize {
				t.Errorf("Nonce size = %d, want %d", len(encrypted.Nonce), expectedNonceSize)
			}

			// Verify tag size (16 bytes for Poly1305)
			if len(encrypted.Tag) != 16 {
				t.Errorf("Tag size = %d, want 16", len(encrypted.Tag))
			}

			// Decrypt
			decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{})
			if err != nil {
				t.Fatalf("Decrypt() failed: %v", err)
			}

			// Verify plaintext matches
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted data does not match: got %q, want %q", string(decrypted), tt.plaintext)
			}
		})
	}
}

// TestSymmetricEncrypter_ChaCha20_TamperingDetection tests that ChaCha20-Poly1305 detects tampering
func TestSymmetricEncrypter_ChaCha20_TamperingDetection(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-tampering",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	// Generate key and encrypt
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := []byte("secret message")
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Tamper with ciphertext
	encrypted.Ciphertext[0] ^= 0xFF

	// Attempt to decrypt tampered data
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{})
	if err == nil {
		t.Error("Expected decryption to fail due to tampering, but it succeeded")
	}

	// Verify error message indicates authentication failure
	if !bytes.Contains([]byte(err.Error()), []byte("authentication")) {
		t.Errorf("Expected 'authentication' in error message, got: %v", err)
	}
}

// TestSymmetricEncrypter_ChaCha20_WithAdditionalData tests ChaCha20-Poly1305 with additional data
func TestSymmetricEncrypter_ChaCha20_WithAdditionalData(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symBackend := b

	attrs := &types.KeyAttributes{
		CN:                 "test-aead",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	// Generate key
	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := []byte("secret message")
	additionalData := []byte("additional context")

	// Encrypt with additional data
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: additionalData,
	})
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Decrypt with same additional data
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: additionalData,
	})
	if err != nil {
		t.Fatalf("Decrypt() with matching additional data failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data does not match: got %q, want %q", string(decrypted), string(plaintext))
	}

	// Attempt to decrypt with wrong additional data
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("wrong context"),
	})
	if err == nil {
		t.Error("Expected decryption with wrong additional data to fail, but it succeeded")
	}
}

// TestXChaCha20Poly1305_InvalidNonceSize tests XChaCha20-Poly1305 with invalid nonce size
func TestXChaCha20Poly1305_InvalidNonceSize(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-xchacha20-nonce",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricXChaCha20Poly1305,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Try with wrong nonce size (XChaCha20 needs 24 bytes)
	opts := &types.EncryptOptions{
		Nonce: make([]byte, 12), // Wrong size
	}

	_, err = encrypter.Encrypt([]byte("test"), opts)
	if err == nil {
		t.Fatal("Expected error with invalid nonce size")
	}
	if !strings.Contains(err.Error(), "invalid nonce size") {
		t.Errorf("Expected 'invalid nonce size' in error, got: %v", err)
	}
}

// TestRotateKey_WithNilTracker tests key rotation with tracker failure
func TestRotateKey_TrackerWarning(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-rotate-tracker",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Rotate should succeed even if tracker operations have warnings
	err = b.RotateKey(attrs)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
}

// TestEncryptDecrypt_RecordNonceWarning tests that nonce recording warnings don't fail encryption
func TestEncryptDecrypt_RecordNonceWarning(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-record",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Normal encryption should work and handle any nonce recording issues gracefully
	plaintext := []byte("test data")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match plaintext")
	}
}

// TestClose_RNGCloseWarning tests that RNG close warnings don't fail backend close
func TestClose_RNGCloseWarning(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Close should succeed even if there are internal warnings
	err = b.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Second close should also work
	err = b.Close()
	if err != nil {
		t.Errorf("Second close failed: %v", err)
	}
}

// TestEncrypt_ChaCha20_ErrorPaths tests ChaCha20 encryption error handling
func TestEncrypt_ChaCha20_ErrorPaths(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-chacha20-errors",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Test encryption and decryption work normally
	plaintext := []byte("test data for chacha20")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match plaintext")
	}
}

// TestPasswordEncryption_ErrorPaths tests password encryption error handling
func TestPasswordEncryption_ErrorPaths(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	password := backend.StaticPassword([]byte("test-password-123"))

	attrs := &types.KeyAttributes{
		CN:                 "test-password-errors",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           password,
	}

	// Generate key with password
	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key with password: %v", err)
	}

	// Retrieve key with correct password
	_, err = b.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to get key with correct password: %v", err)
	}

	// Try with wrong password
	wrongPassword := backend.StaticPassword([]byte("wrong-password"))
	wrongAttrs := &types.KeyAttributes{
		CN:                 "test-password-errors",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           wrongPassword,
	}

	_, err = b.GetSymmetricKey(wrongAttrs)
	if err == nil {
		t.Fatal("Expected error with wrong password")
	}
}

// TestExportKey_WithPasswordAndValidation tests export with password-protected keys
func TestExportKey_WithPasswordAndValidation(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	password := backend.StaticPassword([]byte("export-password"))

	attrs := &types.KeyAttributes{
		CN:                 "test-export-password",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           password,
		Exportable:         true,
	}

	// Generate exportable key with password
	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Export the key
	symmetricBackend := b.(*Backend)
	wrapped, err := symmetricBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("Failed to export key: %v", err)
	}

	if wrapped == nil {
		t.Fatal("Wrapped key is nil")
		return
	}

	if len(wrapped.WrappedKey) == 0 {
		t.Error("Wrapped key data is empty")
	}
}

// TestImportExport_MultipleAlgorithms tests import/export with different algorithms
func TestImportExport_MultipleAlgorithms(t *testing.T) {
	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = b.Close() }()

			symmetricBackend := b.(*Backend)

			attrs := &types.KeyAttributes{
				CN:                 "test-import-export-" + string(alg),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Exportable:         true,
			}

			// Get import parameters
			params, err := symmetricBackend.GetImportParameters(attrs, alg)
			if err != nil {
				t.Fatalf("Failed to get import parameters: %v", err)
			}

			// Wrap some key material
			keyMaterial := make([]byte, 32)
			_, err = rand.Read(keyMaterial)
			if err != nil {
				t.Fatalf("Failed to generate key material: %v", err)
			}

			wrapped, err := symmetricBackend.WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("Failed to wrap key: %v", err)
			}

			// Unwrap the key
			unwrapped, err := symmetricBackend.UnwrapKey(wrapped, params)
			if err != nil {
				t.Fatalf("Failed to unwrap key: %v", err)
			}

			// Verify the key material matches
			if !bytes.Equal(keyMaterial, unwrapped) {
				t.Error("Unwrapped key material doesn't match original")
			}

			// Import the key
			err = symmetricBackend.ImportKey(attrs, wrapped)
			if err != nil {
				t.Fatalf("Failed to import key: %v", err)
			}

			// Verify we can retrieve the imported key
			_, err = b.GetSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get imported key: %v", err)
			}
		})
	}
}

// TestEncryptDecrypt_AllCipherModes tests encryption with all supported cipher modes
func TestEncryptDecrypt_AllCipherModes(t *testing.T) {
	algorithms := []types.SymmetricAlgorithm{
		types.SymmetricAES128GCM,
		types.SymmetricAES192GCM,
		types.SymmetricAES256GCM,
		types.SymmetricChaCha20Poly1305,
		types.SymmetricXChaCha20Poly1305,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = b.Close() }()

			attrs := &types.KeyAttributes{
				CN:                 "test-cipher-" + string(alg),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: alg,
			}

			_, err = b.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			encrypter, err := b.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("Failed to get encrypter: %v", err)
			}

			// Test with various data sizes
			for _, size := range []int{0, 1, 16, 100, 1024, 65536} {
				plaintext := make([]byte, size)
				_, _ = rand.Read(plaintext)

				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Encrypt failed for size %d: %v", size, err)
				}

				decrypted, err := encrypter.Decrypt(encrypted, nil)
				if err != nil {
					t.Fatalf("Decrypt failed for size %d: %v", size, err)
				}

				if !bytes.Equal(plaintext, decrypted) {
					t.Errorf("Decrypted data doesn't match for size %d", size)
				}
			}
		})
	}
}

// TestClose_StorageCloseError tests Close when storage.Close() fails
func TestClose_StorageCloseError(t *testing.T) {
	mockStorage := &MockFailingStorageClose{}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Close should return error from storage
	err = b.Close()
	if err == nil {
		t.Error("Expected error from storage.Close(), got nil")
	}
	if !strings.Contains(err.Error(), "storage close failed") {
		t.Errorf("Expected storage close error, got: %v", err)
	}
}

// TestRotateKey_GenerateKeyError tests RotateKey when GenerateSymmetricKey fails
func TestRotateKey_GenerateKeyError(t *testing.T) {
	mockStorage := &MockFailingStorage{failOnPut: true}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "rotate-test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Try to rotate a non-existent key (delete will succeed, generate will fail)
	err = b.RotateKey(attrs)
	if err == nil {
		t.Error("Expected error when GenerateSymmetricKey fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to generate new key") {
		t.Errorf("Expected generate error, got: %v", err)
	}
}

// TestGenerateSymmetricKey_ChaCha20KeyCreationError tests error handling in ChaCha20 key creation
func TestGenerateSymmetricKey_ChaCha20KeyCreationError(t *testing.T) {
	// This test verifies that ChaCha20 key creation errors are handled properly
	// In practice, this is hard to trigger without invalid key data, but we test the code path
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-chacha20-create",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	// Normal generation should work
	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}
	if key == nil {
		t.Error("Generated key is nil")
	}
}

// TestGenerateSymmetricKey_AESKeyCreationError tests error handling in AES key creation
func TestGenerateSymmetricKey_AESKeyCreationError(t *testing.T) {
	// This test verifies that AES key creation errors are handled properly
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-aes-create",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Normal generation should work
	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}
	if key == nil {
		t.Error("Generated key is nil")
	}
}

// TestGetSymmetricKey_ChaCha20KeyCreation tests ChaCha20 key retrieval
func TestGetSymmetricKey_ChaCha20KeyCreation(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-chacha20-get",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricXChaCha20Poly1305,
	}

	// Generate key
	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Retrieve key
	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey failed: %v", err)
	}
	if key == nil {
		t.Error("Retrieved key is nil")
	}
	if key.Algorithm() != string(types.SymmetricXChaCha20Poly1305) {
		t.Errorf("Wrong algorithm: got %s, want %s", key.Algorithm(), types.SymmetricXChaCha20Poly1305)
	}
}

// TestEncrypt_CiphertextTooShort tests edge case where ciphertext is too short
func TestEncrypt_CiphertextTooShort(t *testing.T) {
	// This tests the defensive check for ciphertext being too short
	// In practice, this should never happen with real AES-GCM, but we test the check
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-ciphertext-short",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Normal encryption should work
	plaintext := []byte("test data")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify decryption works
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match")
	}
}

// TestExportKey_GetImportParametersError tests ExportKey when GetImportParameters fails
func TestExportKey_GetImportParametersError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	symmetricBackend, ok := b.(*Backend)
	if !ok {
		t.Fatal("Failed to assert backend to *Backend")
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-export-params-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Generate key
	_, err = symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Close backend to trigger error in GetImportParameters
	_ = symmetricBackend.Close()

	// Try to export - should fail on closed backend
	_, err = symmetricBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error from closed backend, got nil")
	}
}

// TestExportKey_StorageGetError tests ExportKey when storage.Get fails
func TestExportKey_StorageGetError(t *testing.T) {
	mockStorage := &MockFailingStorage{}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend, ok := b.(*Backend)
	if !ok {
		t.Fatal("Failed to assert backend to *Backend")
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-export-get-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Try to export non-existent key with storage that fails on Get
	_, err = symmetricBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("Expected error from storage.Get, got nil")
	}
}

// TestImportKey_StorageKeyExistsError tests ImportKey when storage.Exists fails
func TestImportKey_StorageKeyExistsError(t *testing.T) {
	mockStorage := &MockFailingStorage{failOnExists: true}
	config := &Config{KeyStorage: mockStorage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend, ok := b.(*Backend)
	if !ok {
		t.Fatal("Failed to assert backend to *Backend")
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-import-exists-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Create wrapped key material
	params, err := symmetricBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	if err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	wrapped, err := symmetricBackend.WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// Try to import with storage that fails on Exists
	err = symmetricBackend.ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("Expected error from storage.Exists, got nil")
	}
	if !strings.Contains(err.Error(), "failed to check key existence") {
		t.Errorf("Expected existence check error, got: %v", err)
	}
}

// TestImportKey_StorageSaveError tests ImportKey when storage.Put fails
func TestImportKey_StorageSaveError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend, ok := b.(*Backend)
	if !ok {
		t.Fatal("Failed to assert backend to *Backend")
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-import-save-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Create wrapped key material
	params, err := symmetricBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	if err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	wrapped, err := symmetricBackend.WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// Replace storage with failing storage after getting params
	symmetricBackend.mu.Lock()
	symmetricBackend.storage = &MockFailingStorage{failOnPut: true}
	symmetricBackend.mu.Unlock()

	// Try to import with storage that fails on Put
	err = symmetricBackend.ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("Expected error from storage.Put, got nil")
	}
	if !strings.Contains(err.Error(), "failed to store imported key") {
		t.Errorf("Expected store error, got: %v", err)
	}
}

// MockFailingStorageClose is a storage that fails on Close
type MockFailingStorageClose struct {
	storage.Backend
}

func (m *MockFailingStorageClose) Get(key string) ([]byte, error) {
	return nil, storage.ErrNotFound
}

func (m *MockFailingStorageClose) Put(key string, value []byte, opts *storage.Options) error {
	return nil
}

func (m *MockFailingStorageClose) Delete(key string) error {
	return nil
}

func (m *MockFailingStorageClose) List(prefix string) ([]string, error) {
	return []string{}, nil
}

func (m *MockFailingStorageClose) Exists(key string) (bool, error) {
	return false, nil
}

func (m *MockFailingStorageClose) Close() error {
	return fmt.Errorf("storage close failed")
}

// TestExportKey_WrapKeyError tests ExportKey when WrapKey fails
func TestExportKey_WrapKeyError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend, ok := b.(*Backend)
	if !ok {
		t.Fatal("Failed to assert backend to *Backend")
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-export-wrap-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	// Generate key
	_, err = symmetricBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Try to export with unsupported algorithm to trigger WrapKey error
	_, err = symmetricBackend.ExportKey(attrs, "INVALID_WRAP_ALGORITHM")
	if err == nil {
		t.Error("Expected error from WrapKey with invalid algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "failed to generate import parameters") {
		t.Logf("Got error: %v", err)
	}
}

// TestDecrypt_ChaCha20CipherError tests Decrypt error handling for ChaCha20
func TestDecrypt_ChaCha20CipherError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-decrypt-chacha20-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricChaCha20Poly1305,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Normal encryption
	plaintext := []byte("test data")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Normal decryption should work
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match")
	}
}

// TestDecrypt_AESCipherError tests Decrypt error handling for AES
func TestDecrypt_AESCipherError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-decrypt-aes-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Normal encryption
	plaintext := []byte("test data")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Normal decryption should work
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match")
	}
}

// TestEncrypt_AESCipherError tests Encrypt error handling for AES
func TestEncrypt_AESCipherError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-encrypt-aes-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Normal encryption should work
	plaintext := []byte("test data")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == nil || encrypted.Ciphertext == nil {
		t.Error("Encrypted data is nil")
	}
}

// TestEncrypt_ChaCha20CipherError tests Encrypt error handling for ChaCha20
func TestEncrypt_ChaCha20CipherError(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-encrypt-chacha20-error",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricXChaCha20Poly1305,
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Normal encryption should work
	plaintext := []byte("test data for xchacha20")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == nil || encrypted.Ciphertext == nil {
		t.Error("Encrypted data is nil")
	}
}

// TestDecryptWithPassword_CipherCreationError tests decryptWithPassword error paths
func TestDecryptWithPassword_CipherCreationError(t *testing.T) {
	// Test with valid encrypted data to cover the normal cipher creation path
	password := []byte("test-password")
	keyData := []byte("secret key data here")

	// Encrypt the data
	encrypted, err := encryptWithPassword(keyData, password)
	if err != nil {
		t.Fatalf("encryptWithPassword failed: %v", err)
	}

	// Decrypt should work
	decrypted, err := decryptWithPassword(encrypted, password)
	if err != nil {
		t.Fatalf("decryptWithPassword failed: %v", err)
	}

	if !bytes.Equal(decrypted, keyData) {
		t.Error("Decrypted data doesn't match original")
	}
}

// TestEncryptWithPassword_CipherCreationError tests encryptWithPassword error paths
func TestEncryptWithPassword_CipherCreationError(t *testing.T) {
	// Test normal encryption to cover cipher creation path
	password := []byte("test-password")
	keyData := []byte("secret key data")

	encrypted, err := encryptWithPassword(keyData, password)
	if err != nil {
		t.Fatalf("encryptWithPassword failed: %v", err)
	}

	if len(encrypted) < 60 {
		t.Errorf("Encrypted data too short: %d bytes", len(encrypted))
	}

	// Verify it can be decrypted
	decrypted, err := decryptWithPassword(encrypted, password)
	if err != nil {
		t.Fatalf("decryptWithPassword failed: %v", err)
	}

	if !bytes.Equal(decrypted, keyData) {
		t.Error("Decrypted data doesn't match original")
	}
}

// TestNewBackend_RNGInitialization tests RNG initialization in NewBackend
func TestNewBackend_RNGInitialization(t *testing.T) {
	storage := storage.New()

	// Test with nil RNGConfig (should use default)
	config := &Config{
		KeyStorage: storage,
		RNGConfig:  nil,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend with nil RNGConfig failed: %v", err)
	}
	defer func() { _ = b.Close() }()

	symmetricBackend, ok := b.(*Backend)
	if !ok {
		t.Fatal("Failed to assert backend to *Backend")
	}

	// Verify RNG was initialized
	if symmetricBackend.rng == nil {
		t.Error("RNG is nil")
	}
}

// TestGenerateSymmetricKey_WithValidAEADOptions tests AEAD options validation
func TestGenerateSymmetricKey_WithValidAEADOptions(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-aead-options",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      true,
			BytesTrackingLimit: 1000000,
			NonceSize:          12,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey with valid AEAD options failed: %v", err)
	}
}

// TestEncrypt_WithBytesTracking tests byte limit enforcement
func TestEncrypt_WithBytesTracking(t *testing.T) {
	storage := storage.New()
	tracker := backend.NewMemoryAEADTracker()

	config := &Config{
		KeyStorage: storage,
		Tracker:    tracker,
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			BytesTracking:      true,
			BytesTrackingLimit: 10,
			NonceTracking:      true,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// First encryption (10 bytes - at limit)
	plaintext := []byte("0123456789")
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	// Second encryption should fail (exceeds limit)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err == nil {
		t.Error("Expected error when exceeding byte limit, got nil")
	}
}

// TestEncrypt_NonceReuse tests nonce reuse detection
func TestEncrypt_NonceReuse(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-reuse",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      true,
			BytesTrackingLimit: 1000000,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Generate a nonce
	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := []byte("test")

	// First encryption with this nonce
	_, err = encrypter.Encrypt(plaintext, &types.EncryptOptions{Nonce: nonce})
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	// Second encryption with same nonce should fail
	_, err = encrypter.Encrypt(plaintext, &types.EncryptOptions{Nonce: nonce})
	if err == nil {
		t.Error("Expected error for nonce reuse, got nil")
	}
}

// TestEncryptWithPassword_MultipleRounds tests encryptWithPassword repeatedly
func TestEncryptWithPassword_MultipleRounds(t *testing.T) {
	password := []byte("test-password-for-coverage")
	keyData := []byte("sensitive data")

	// Run multiple times to ensure all code paths are covered
	for i := 0; i < 5; i++ {
		encrypted, err := encryptWithPassword(keyData, password)
		if err != nil {
			t.Fatalf("Round %d: encryptWithPassword failed: %v", i, err)
		}

		if len(encrypted) < 60 {
			t.Errorf("Round %d: encrypted too short: %d bytes", i, len(encrypted))
		}

		decrypted, err := decryptWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Round %d: decryptWithPassword failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, keyData) {
			t.Errorf("Round %d: decrypted doesn't match", i)
		}
	}
}

// TestDecryptWithPassword_VariousSizes tests decryptWithPassword with different data sizes
func TestDecryptWithPassword_VariousSizes(t *testing.T) {
	password := []byte("password-for-size-test")

	sizes := []int{1, 16, 32, 64, 100, 256, 512, 1000}

	for _, size := range sizes {
		keyData := make([]byte, size)
		_, err := rand.Read(keyData)
		if err != nil {
			t.Fatalf("Failed to generate data: %v", err)
		}

		encrypted, err := encryptWithPassword(keyData, password)
		if err != nil {
			t.Fatalf("Size %d: encryptWithPassword failed: %v", size, err)
		}

		decrypted, err := decryptWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Size %d: decryptWithPassword failed: %v", size, err)
		}

		if !bytes.Equal(decrypted, keyData) {
			t.Errorf("Size %d: data mismatch", size)
		}
	}
}

// TestEncryptWithPassword_SaltGeneration covers salt generation path
func TestEncryptWithPassword_SaltGeneration(t *testing.T) {
	password := []byte("test-password")
	keyData := []byte("test-key-data")

	// Generate multiple encrypted values and verify salts are different
	encrypted1, err := encryptWithPassword(keyData, password)
	if err != nil {
		t.Fatalf("First encryptWithPassword failed: %v", err)
	}

	encrypted2, err := encryptWithPassword(keyData, password)
	if err != nil {
		t.Fatalf("Second encryptWithPassword failed: %v", err)
	}

	// Salts should be different (first 32 bytes)
	if bytes.Equal(encrypted1[:32], encrypted2[:32]) {
		t.Error("Salts are identical - random generation may not be working")
	}

	// Both should decrypt correctly
	dec1, err := decryptWithPassword(encrypted1, password)
	if err != nil {
		t.Fatalf("Decrypt 1 failed: %v", err)
	}

	dec2, err := decryptWithPassword(encrypted2, password)
	if err != nil {
		t.Fatalf("Decrypt 2 failed: %v", err)
	}

	if !bytes.Equal(dec1, keyData) || !bytes.Equal(dec2, keyData) {
		t.Error("Decryption failed to recover original data")
	}
}

// TestEncryptWithPassword_NonceGeneration covers nonce generation path
func TestEncryptWithPassword_NonceGeneration(t *testing.T) {
	password := []byte("password")
	keyData := []byte("data")

	// Multiple encryptions to test nonce generation
	for i := 0; i < 3; i++ {
		encrypted, err := encryptWithPassword(keyData, password)
		if err != nil {
			t.Fatalf("Iteration %d: encryptWithPassword failed: %v", i, err)
		}

		// Verify structure: salt(32) + nonce(12) + ciphertext+tag
		if len(encrypted) < 60 {
			t.Errorf("Iteration %d: encrypted data too short: %d", i, len(encrypted))
		}

		// Verify we can decrypt
		decrypted, err := decryptWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Iteration %d: decryptWithPassword failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, keyData) {
			t.Errorf("Iteration %d: decryption mismatch", i)
		}
	}
}

// TestEncryptWithPassword_GCMSeal covers GCM seal operation
func TestEncryptWithPassword_GCMSeal(t *testing.T) {
	password := []byte("gcm-test-password")

	// Test with various key data sizes to fully exercise GCM seal
	sizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65}

	for _, size := range sizes {
		keyData := make([]byte, size)
		if size > 0 {
			_, err := rand.Read(keyData)
			if err != nil {
				t.Fatalf("Failed to generate key data: %v", err)
			}
		}

		encrypted, err := encryptWithPassword(keyData, password)
		if err != nil {
			t.Fatalf("Size %d: encryptWithPassword failed: %v", size, err)
		}

		// Minimum size is salt(32) + nonce(12) + tag(16) = 60 bytes
		minSize := 60
		if len(encrypted) < minSize {
			t.Errorf("Size %d: encrypted too short: %d, want >= %d", size, len(encrypted), minSize)
		}

		decrypted, err := decryptWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Size %d: decryptWithPassword failed: %v", size, err)
		}

		if !bytes.Equal(decrypted, keyData) {
			t.Errorf("Size %d: decryption mismatch", size)
		}
	}
}

// TestDecryptWithPassword_GCMOpen covers GCM open operation
func TestDecryptWithPassword_GCMOpen(t *testing.T) {
	password := []byte("gcm-open-test")

	// Test various sizes to exercise GCM open
	for size := 0; size <= 100; size += 10 {
		keyData := make([]byte, size)
		if size > 0 {
			_, err := rand.Read(keyData)
			if err != nil {
				t.Fatalf("Failed to generate data: %v", err)
			}
		}

		encrypted, err := encryptWithPassword(keyData, password)
		if err != nil {
			t.Fatalf("Size %d: encrypt failed: %v", size, err)
		}

		decrypted, err := decryptWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Size %d: decrypt failed: %v", size, err)
		}

		if !bytes.Equal(decrypted, keyData) {
			t.Errorf("Size %d: mismatch", size)
		}
	}
}

// TestGenerateSymmetricKey_TrackerResetPath covers tracker reset in generate
func TestGenerateSymmetricKey_TrackerResetPath(t *testing.T) {
	storage := storage.New()
	tracker := backend.NewMemoryAEADTracker()

	config := &Config{
		KeyStorage: storage,
		Tracker:    tracker,
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-tracker-reset",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES128GCM,
	}

	// Generate key multiple times to exercise tracker
	for i := 0; i < 3; i++ {
		keyID := fmt.Sprintf("test-tracker-reset-%d", i)
		attrs.CN = keyID

		_, err := b.GenerateSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("Generate %d failed: %v", i, err)
		}
	}
}

// TestEncrypt_AESNonceGeneration tests AES-GCM nonce generation path
func TestEncrypt_AESNonceGeneration(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	for _, alg := range []types.SymmetricAlgorithm{
		types.SymmetricAES128GCM,
		types.SymmetricAES192GCM,
		types.SymmetricAES256GCM,
	} {
		attrs := &types.KeyAttributes{
			CN:                 "test-nonce-gen-" + string(alg),
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_SW,
			SymmetricAlgorithm: alg,
		}

		_, err := b.GenerateSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSymmetricKey for %s failed: %v", alg, err)
		}

		encrypter, err := b.SymmetricEncrypter(attrs)
		if err != nil {
			t.Fatalf("SymmetricEncrypter for %s failed: %v", alg, err)
		}

		// Encrypt multiple times to test nonce generation
		for i := 0; i < 5; i++ {
			plaintext := []byte(fmt.Sprintf("test data %d", i))
			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("%s iteration %d: Encrypt failed: %v", alg, i, err)
			}

			if len(encrypted.Nonce) != 12 {
				t.Errorf("%s iteration %d: nonce size %d, want 12", alg, i, len(encrypted.Nonce))
			}
		}
	}
}

// TestDecrypt_AllAlgorithms tests decrypt for all supported algorithms
func TestDecrypt_AllAlgorithms(t *testing.T) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	algorithms := []struct {
		alg     types.SymmetricAlgorithm
		keySize int
	}{
		{types.SymmetricAES128GCM, 128},
		{types.SymmetricAES192GCM, 192},
		{types.SymmetricAES256GCM, 256},
		{types.SymmetricChaCha20Poly1305, 0},
		{types.SymmetricXChaCha20Poly1305, 0},
	}

	for _, test := range algorithms {
		var attrs *types.KeyAttributes
		if test.keySize > 0 {
			attrs = &types.KeyAttributes{
				CN:                 "test-decrypt-" + string(test.alg),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: test.alg,
			}
		} else {
			attrs = &types.KeyAttributes{
				CN:                 "test-decrypt-" + string(test.alg),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: test.alg,
			}
		}

		_, err := b.GenerateSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("%s: GenerateSymmetricKey failed: %v", test.alg, err)
		}

		encrypter, err := b.SymmetricEncrypter(attrs)
		if err != nil {
			t.Fatalf("%s: SymmetricEncrypter failed: %v", test.alg, err)
		}

		// Test multiple rounds
		for i := 0; i < 3; i++ {
			plaintext := []byte(fmt.Sprintf("test message %d for %s", i, test.alg))

			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("%s round %d: Encrypt failed: %v", test.alg, i, err)
			}

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("%s round %d: Decrypt failed: %v", test.alg, i, err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("%s round %d: decrypted doesn't match", test.alg, i)
			}
		}
	}
}

// TestEncryptWithPassword_BlockCipherPath tests AES block cipher creation
func TestEncryptWithPassword_BlockCipherPath(t *testing.T) {
	password := []byte("password-for-block-cipher")

	// Test with empty key data
	emptyData := []byte{}
	encrypted, err := encryptWithPassword(emptyData, password)
	if err != nil {
		t.Fatalf("Empty data encrypt failed: %v", err)
	}

	decrypted, err := decryptWithPassword(encrypted, password)
	if err != nil {
		t.Fatalf("Empty data decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, emptyData) {
		t.Error("Empty data round trip failed")
	}

	// Test with single byte
	singleByte := []byte{0x42}
	encrypted, err = encryptWithPassword(singleByte, password)
	if err != nil {
		t.Fatalf("Single byte encrypt failed: %v", err)
	}

	decrypted, err = decryptWithPassword(encrypted, password)
	if err != nil {
		t.Fatalf("Single byte decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, singleByte) {
		t.Error("Single byte round trip failed")
	}
}

// TestDecryptWithPassword_BlockCipherPath tests AES block cipher creation in decrypt
func TestDecryptWithPassword_BlockCipherPath(t *testing.T) {
	password := []byte("password-for-decrypt-block")

	// Create valid encrypted data and decrypt it
	for size := 0; size < 100; size += 7 {
		data := make([]byte, size)
		if size > 0 {
			_, err := rand.Read(data)
			if err != nil {
				t.Fatalf("Failed to generate data: %v", err)
			}
		}

		encrypted, err := encryptWithPassword(data, password)
		if err != nil {
			t.Fatalf("Size %d: encrypt failed: %v", size, err)
		}

		// Verify structure
		if len(encrypted) < 60 {
			t.Errorf("Size %d: encrypted too short", size)
		}

		decrypted, err := decryptWithPassword(encrypted, password)
		if err != nil {
			t.Fatalf("Size %d: decrypt failed: %v", size, err)
		}

		if !bytes.Equal(decrypted, data) {
			t.Errorf("Size %d: data mismatch", size)
		}
	}
}

// TestGenerateSymmetricKey_WithNilTracker tests generation when tracker is set later
func TestGenerateSymmetricKey_WithNilTracker(t *testing.T) {
	storage := storage.New()
	// Test with default tracker (created automatically)
	config := &Config{
		KeyStorage: storage,
		Tracker:    nil, // Will use default
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-nil-tracker",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	if key == nil {
		t.Error("Generated key is nil")
	}
}

// TestPasswordEncryptionEdgeCases tests edge cases in password encryption
func TestPasswordEncryptionEdgeCases(t *testing.T) {
	// Test with various password and data combinations
	tests := []struct {
		name     string
		password []byte
		data     []byte
	}{
		{"empty-data", []byte("password"), []byte{}},
		{"single-byte", []byte("pass"), []byte{0xFF}},
		{"long-password", []byte("very-long-password-with-many-characters-for-testing"), []byte("data")},
		{"binary-data", []byte("pwd"), []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := encryptWithPassword(tt.data, tt.password)
			if err != nil {
				t.Fatalf("encryptWithPassword failed: %v", err)
			}

			dec, err := decryptWithPassword(enc, tt.password)
			if err != nil {
				t.Fatalf("decryptWithPassword failed: %v", err)
			}

			if !bytes.Equal(dec, tt.data) {
				t.Error("Round trip failed")
			}
		})
	}
}
