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

package backend

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/aes"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// createAESBackend creates a test backend with in-memory storage
func createAESBackend(t *testing.T) (types.SymmetricBackend, storage.Backend) {
	t.Helper()

	keyStorage := storage.New()
	config := &aes.Config{
		KeyStorage: keyStorage,
		Tracker:    backend.NewMemoryAEADTracker(),
	}

	be, err := aes.NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	return be, keyStorage
}

// createAESAttrs creates AES key attributes
func createAESAttrs(cn string, keySize int, algorithm types.SymmetricAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: algorithm,
		Exportable:         true,
		AESAttributes: &types.AESAttributes{
			KeySize: keySize,
		},
	}
}

// TestAES_EndToEnd_AllKeySizes tests complete workflow for all AES key sizes
func TestAES_EndToEnd_AllKeySizes(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		algorithm types.SymmetricAlgorithm
	}{
		{"AES-128-GCM", 128, types.SymmetricAES128GCM},
		{"AES-192-GCM", 192, types.SymmetricAES192GCM},
		{"AES-256-GCM", 256, types.SymmetricAES256GCM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, _ := createAESBackend(t)
			defer func() { _ = be.Close() }()

			attrs := createAESAttrs("test-"+tt.name, tt.keySize, tt.algorithm)

			// Generate key
			key, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
			}

			if key.KeySize() != tt.keySize {
				t.Errorf("Key size = %d, want %d", key.KeySize(), tt.keySize)
			}

			// Verify we can retrieve it
			retrievedKey, err := be.GetSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GetSymmetricKey failed: %v", err)
			}

			rawOriginal, _ := key.Raw()
			rawRetrieved, _ := retrievedKey.Raw()
			if !bytes.Equal(rawOriginal, rawRetrieved) {
				t.Error("Retrieved key doesn't match original")
			}

			// Test encryption/decryption
			plaintext := []byte("Hello, World! This is a test message for " + tt.name)

			encrypter, err := be.SymmetricEncrypter(attrs)
			if err != nil {
				t.Fatalf("SymmetricEncrypter failed: %v", err)
			}

			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if len(encrypted.Nonce) == 0 {
				t.Error("Nonce is empty")
			}
			if len(encrypted.Tag) == 0 {
				t.Error("Tag is empty")
			}
			if len(encrypted.Ciphertext) == 0 {
				t.Error("Ciphertext is empty")
			}

			decrypted, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Error("Decrypted data doesn't match original plaintext")
			}

			// Test key deletion
			if err := be.DeleteKey(attrs); err != nil {
				t.Fatalf("DeleteKey failed: %v", err)
			}

			// Verify key is gone
			_, err = be.GetSymmetricKey(attrs)
			if err != backend.ErrKeyNotFound {
				t.Errorf("Expected ErrKeyNotFound, got %v", err)
			}
		})
	}
}

// TestAES_Encryption_WithAdditionalData tests encryption with AAD
func TestAES_Encryption_WithAdditionalData(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test-aad", 256, types.SymmetricAES256GCM)

	if _, err := be.GenerateSymmetricKey(attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := be.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	plaintext := []byte("Secret message")
	aad := []byte("Additional authenticated data")

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with correct AAD
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match original plaintext")
	}

	// Decrypt with wrong AAD should fail
	wrongAAD := []byte("Wrong additional data")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		t.Error("Expected decryption to fail with wrong AAD")
	}
}

// TestAES_Encryption_LargeData tests encryption of large data
func TestAES_Encryption_LargeData(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test-large", 256, types.SymmetricAES256GCM)

	if _, err := be.GenerateSymmetricKey(attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := be.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Test with 1MB of data
	plaintext := make([]byte, 1024*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match original plaintext")
	}
}

// TestAES_PasswordProtection tests password-protected keys
func TestAES_PasswordProtection(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	password := backend.StaticPassword("test-password-123")
	attrs := createAESAttrs("test-password", 256, types.SymmetricAES256GCM)
	attrs.Password = password

	// Generate password-protected key
	key, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	rawOriginal, _ := key.Raw()

	// Retrieve with correct password
	retrievedKey, err := be.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey with correct password failed: %v", err)
	}

	rawRetrieved, _ := retrievedKey.Raw()
	if !bytes.Equal(rawOriginal, rawRetrieved) {
		t.Error("Retrieved key doesn't match original")
	}

	// Try to retrieve with wrong password
	wrongPasswordAttrs := createAESAttrs("test-password", 256, types.SymmetricAES256GCM)
	wrongPasswordAttrs.Password = backend.StaticPassword("wrong-password")

	_, err = be.GetSymmetricKey(wrongPasswordAttrs)
	if err == nil {
		t.Error("Expected error with wrong password")
	}
}

// TestAES_KeyRotation tests key rotation functionality
func TestAES_KeyRotation(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test-rotation", 256, types.SymmetricAES256GCM)

	// Generate initial key
	originalKey, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	rawOriginal, _ := originalKey.Raw()

	// Rotate the key
	if err := be.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Retrieve rotated key
	rotatedKey, err := be.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey after rotation failed: %v", err)
	}

	rawRotated, _ := rotatedKey.Raw()

	// Keys should be different
	if bytes.Equal(rawOriginal, rawRotated) {
		t.Error("Rotated key is the same as original key")
	}

	// Key size should remain the same
	if rotatedKey.KeySize() != originalKey.KeySize() {
		t.Error("Rotated key has different size than original")
	}
}

// TestAES_ListKeys tests key listing functionality
func TestAES_ListKeys(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	// Create multiple keys
	keyNames := []string{"key1", "key2", "key3"}
	for _, name := range keyNames {
		attrs := createAESAttrs(name, 256, types.SymmetricAES256GCM)
		if _, err := be.GenerateSymmetricKey(attrs); err != nil {
			t.Fatalf("GenerateSymmetricKey failed for %s: %v", name, err)
		}
	}

	// List keys
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != len(keyNames) {
		t.Errorf("Expected %d keys, got %d", len(keyNames), len(keys))
	}
}

// TestAES_ImportExport_RSA_OAEP tests import/export with RSA-OAEP wrapping
func TestAES_ImportExport_RSA_OAEP(t *testing.T) {
	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			be, _ := createAESBackend(t)
			defer func() { _ = be.Close() }()

			exportBackend, ok := be.(backend.ImportExportBackend)
			if !ok {
				t.Fatal("Backend does not implement ImportExportBackend")
			}

			// Generate a key to export
			attrs := createAESAttrs("test-export-"+string(algorithm), 256, types.SymmetricAES256GCM)
			originalKey, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
			}

			rawOriginal, _ := originalKey.Raw()

			// Export the key
			wrapped, err := exportBackend.ExportKey(attrs, algorithm)
			if err != nil {
				t.Fatalf("ExportKey failed: %v", err)
			}

			if len(wrapped.WrappedKey) == 0 {
				t.Error("Wrapped key is empty")
			}

			// Delete the original key
			if err := be.DeleteKey(attrs); err != nil {
				t.Fatalf("DeleteKey failed: %v", err)
			}

			// Import the key back
			importAttrs := createAESAttrs("test-import-"+string(algorithm), 256, types.SymmetricAES256GCM)
			if err := exportBackend.ImportKey(importAttrs, wrapped); err != nil {
				t.Fatalf("ImportKey failed: %v", err)
			}

			// Retrieve and verify
			importedKey, err := be.GetSymmetricKey(importAttrs)
			if err != nil {
				t.Fatalf("GetSymmetricKey after import failed: %v", err)
			}

			rawImported, _ := importedKey.Raw()
			if !bytes.Equal(rawOriginal, rawImported) {
				t.Error("Imported key doesn't match original")
			}
		})
	}
}

// TestAES_ImportExport_RSA_AES_KeyWrap tests import/export with RSA-AES key wrapping
func TestAES_ImportExport_RSA_AES_KeyWrap(t *testing.T) {
	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			be, _ := createAESBackend(t)
			defer func() { _ = be.Close() }()

			exportBackend, ok := be.(backend.ImportExportBackend)
			if !ok {
				t.Fatal("Backend does not implement ImportExportBackend")
			}

			// Generate a key to export
			attrs := createAESAttrs("test-export-wrap-"+string(algorithm), 256, types.SymmetricAES256GCM)
			originalKey, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
			}

			rawOriginal, _ := originalKey.Raw()

			// Export the key
			wrapped, err := exportBackend.ExportKey(attrs, algorithm)
			if err != nil {
				t.Fatalf("ExportKey failed: %v", err)
			}

			// Delete the original key
			if err := be.DeleteKey(attrs); err != nil {
				t.Fatalf("DeleteKey failed: %v", err)
			}

			// Import the key back
			importAttrs := createAESAttrs("test-import-wrap-"+string(algorithm), 256, types.SymmetricAES256GCM)
			if err := exportBackend.ImportKey(importAttrs, wrapped); err != nil {
				t.Fatalf("ImportKey failed: %v", err)
			}

			// Retrieve and verify
			importedKey, err := be.GetSymmetricKey(importAttrs)
			if err != nil {
				t.Fatalf("GetSymmetricKey after import failed: %v", err)
			}

			rawImported, _ := importedKey.Raw()
			if !bytes.Equal(rawOriginal, rawImported) {
				t.Error("Imported key doesn't match original")
			}
		})
	}
}

// TestAES_ImportExport_AllKeySizes tests import/export for all key sizes
func TestAES_ImportExport_AllKeySizes(t *testing.T) {
	keySizes := []struct {
		size      int
		algorithm types.SymmetricAlgorithm
	}{
		{128, types.SymmetricAES128GCM},
		{192, types.SymmetricAES192GCM},
		{256, types.SymmetricAES256GCM},
	}

	for _, ks := range keySizes {
		t.Run(string(ks.algorithm), func(t *testing.T) {
			be, _ := createAESBackend(t)
			defer func() { _ = be.Close() }()

			exportBackend := be.(backend.ImportExportBackend)

			attrs := createAESAttrs("test-size-export", ks.size, ks.algorithm)
			originalKey, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
			}

			rawOriginal, _ := originalKey.Raw()

			wrapped, err := exportBackend.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				t.Fatalf("ExportKey failed: %v", err)
			}

			if err := be.DeleteKey(attrs); err != nil {
				t.Fatalf("DeleteKey failed: %v", err)
			}

			importAttrs := createAESAttrs("test-size-import", ks.size, ks.algorithm)
			if err := exportBackend.ImportKey(importAttrs, wrapped); err != nil {
				t.Fatalf("ImportKey failed: %v", err)
			}

			importedKey, err := be.GetSymmetricKey(importAttrs)
			if err != nil {
				t.Fatalf("GetSymmetricKey after import failed: %v", err)
			}

			rawImported, _ := importedKey.Raw()
			if !bytes.Equal(rawOriginal, rawImported) {
				t.Error("Imported key doesn't match original")
			}
		})
	}
}

// TestAES_Capabilities tests backend capabilities
func TestAES_Capabilities(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	caps := be.Capabilities()

	if !caps.Keys {
		t.Error("Expected Keys capability to be true")
	}
	if caps.HardwareBacked {
		t.Error("Expected HardwareBacked to be false for AES backend")
	}
	if caps.Signing {
		t.Error("Expected Signing to be false for AES backend")
	}
	if caps.Decryption {
		t.Error("Expected Decryption to be false for AES backend")
	}
	if !caps.SymmetricEncryption {
		t.Error("Expected SymmetricEncryption to be true")
	}
	if !caps.SupportsImportExport() {
		t.Error("Expected Import and Export to be true")
	}
}

// TestAES_ErrorHandling_InvalidAttributes tests error handling
func TestAES_ErrorHandling_InvalidAttributes(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	// Test with asymmetric algorithm
	invalidAttrs := &types.KeyAttributes{
		CN:           "invalid",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA, // Wrong type
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err := be.GenerateSymmetricKey(invalidAttrs)
	if err == nil {
		t.Error("Expected error for asymmetric algorithm")
	}
}

// TestAES_ErrorHandling_NonExistentKey tests error when key doesn't exist
func TestAES_ErrorHandling_NonExistentKey(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("nonexistent", 256, types.SymmetricAES256GCM)

	_, err := be.GetSymmetricKey(attrs)
	if err != backend.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}

	err = be.DeleteKey(attrs)
	if err != backend.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound on delete, got %v", err)
	}
}

// TestAES_ErrorHandling_TamperedCiphertext tests authentication failure
func TestAES_ErrorHandling_TamperedCiphertext(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test-tamper", 256, types.SymmetricAES256GCM)

	if _, err := be.GenerateSymmetricKey(attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	encrypter, err := be.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	plaintext := []byte("Secret message")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with ciphertext
	if len(encrypted.Ciphertext) > 0 {
		encrypted.Ciphertext[0] ^= 0xFF
	}

	// Decryption should fail
	_, err = encrypter.Decrypt(encrypted, nil)
	if err == nil {
		t.Error("Expected decryption to fail with tampered ciphertext")
	}
}

// TestAES_ErrorHandling_ClosedBackend tests operations on closed backend
func TestAES_ErrorHandling_ClosedBackend(t *testing.T) {
	be, _ := createAESBackend(t)

	// Close the backend
	if err := be.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	attrs := createAESAttrs("test-closed", 256, types.SymmetricAES256GCM)

	// All operations should fail
	_, err := be.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error for GenerateSymmetricKey on closed backend")
	}

	_, err = be.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error for GetSymmetricKey on closed backend")
	}

	err = be.DeleteKey(attrs)
	if err == nil {
		t.Error("Expected error for DeleteKey on closed backend")
	}
}

// TestAES_ConcurrentOperations tests thread-safety
func TestAES_ConcurrentOperations(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Generate keys concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			attrs := createAESAttrs(
				"concurrent-key-"+string(rune(id)),
				256,
				types.SymmetricAES256GCM,
			)

			_, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Errorf("GenerateSymmetricKey failed in goroutine %d: %v", id, err)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all keys were created
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != numGoroutines {
		t.Errorf("Expected %d keys, got %d", numGoroutines, len(keys))
	}
}

// TestAES_Type tests backend type
func TestAES_Type(t *testing.T) {
	be, _ := createAESBackend(t)
	defer func() { _ = be.Close() }()

	if be.Type() != types.BackendTypeAES {
		t.Errorf("Expected backend type %s, got %s", types.BackendTypeAES, be.Type())
	}
}
