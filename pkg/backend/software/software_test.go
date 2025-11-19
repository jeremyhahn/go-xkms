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

package software

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// createTestBackend creates a test backend with in-memory storage
func createTestBackend(t *testing.T) (types.SymmetricBackend, storage.Backend) {
	t.Helper()

	keyStorage := memory.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	return be, keyStorage
}

// createRSAAttrs creates RSA key attributes
func createRSAAttrs(cn string, keySize int) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: keySize,
		},
	}
}

// createECDSAAttrs creates ECDSA key attributes
func createECDSAAttrs(cn, curve string) *types.KeyAttributes {
	parsedCurve, _ := types.ParseCurve(curve)
	// Note: parsedCurve may be nil for invalid curves - tests should handle this
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: parsedCurve,
		},
	}
}

// createEd25519Attrs creates Ed25519 key attributes
func createEd25519Attrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}
}

// createAESAttrs creates AES key attributes
func createAESAttrs(cn string, keySize int, algorithm types.SymmetricAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: algorithm,
		AESAttributes: &types.AESAttributes{
			KeySize: keySize,
		},
	}
}

// TestNewBackend_ValidConfig tests backend creation with valid configuration
func TestNewBackend_ValidConfig(t *testing.T) {
	keyStorage := memory.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	if be == nil {
		t.Fatal("NewBackend returned nil")
	}

	defer func() { _ = be.Close() }()

	// Verify type
	if be.Type() != backend.BackendTypeSoftware {
		t.Errorf("Expected type %s, got %s", backend.BackendTypeSoftware, be.Type())
	}

	// Verify capabilities
	caps := be.Capabilities()
	if !caps.Keys {
		t.Error("Expected Keys capability to be true")
	}
	if caps.HardwareBacked {
		t.Error("Expected HardwareBacked to be false")
	}
	if !caps.Signing {
		t.Error("Expected Signing capability to be true")
	}
	if !caps.Decryption {
		t.Error("Expected Decryption capability to be true")
	}
	if !caps.KeyRotation {
		t.Error("Expected KeyRotation capability to be true")
	}
	if !caps.SymmetricEncryption {
		t.Error("Expected SymmetricEncryption capability to be true")
	}
}

// TestNewBackend_InvalidConfig tests backend creation with invalid configurations
func TestNewBackend_InvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{"NilConfig", nil},
		{"NilStorage", &Config{KeyStorage: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be, err := NewBackend(tt.config)
			if err == nil {
				if be != nil {
					_ = be.Close()
				}
				t.Fatal("Expected error, got nil")
			}
			if be != nil {
				t.Error("Expected nil backend on error")
			}
		})
	}
}

// TestGenerateKey_RSA tests RSA key generation
func TestGenerateKey_RSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-rsa", 2048)

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *rsa.PrivateKey, got %T", key)
	}

	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d-bit", rsaKey.N.BitLen())
	}
}

// TestGenerateKey_ECDSA tests ECDSA key generation
func TestGenerateKey_ECDSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createECDSAAttrs("test-ecdsa", "P-256")

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", key)
	}

	if ecdsaKey.Curve.Params().Name != "P-256" {
		t.Errorf("Expected P-256 curve, got %s", ecdsaKey.Curve.Params().Name)
	}
}

// TestGenerateKey_Ed25519 tests Ed25519 key generation
func TestGenerateKey_Ed25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createEd25519Attrs("test-ed25519")

	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Expected ed25519.PrivateKey, got %T", key)
	}

	if len(ed25519Key) != ed25519.PrivateKeySize {
		t.Errorf("Expected key size %d, got %d", ed25519.PrivateKeySize, len(ed25519Key))
	}
}

// TestGetKey_Asymmetric tests retrieving asymmetric keys
func TestGetKey_Asymmetric(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-get-rsa", 2048)

	// Generate key
	origKey, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Retrieve key
	retrievedKey, err := be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	// Compare keys
	origRSA := origKey.(*rsa.PrivateKey)
	retrievedRSA := retrievedKey.(*rsa.PrivateKey)

	if origRSA.N.Cmp(retrievedRSA.N) != 0 {
		t.Error("Retrieved key does not match original")
	}
}

// TestGenerateSymmetricKey_AllSizes tests symmetric key generation for all AES sizes
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
			be, _ := createTestBackend(t)
			defer func() { _ = be.Close() }()

			attrs := createAESAttrs("test-aes-"+tt.name, tt.keySize, tt.algorithm)

			key, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
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

// TestGetSymmetricKey tests retrieving symmetric keys
func TestGetSymmetricKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test-get-aes", 256, types.SymmetricAES256GCM)

	// Generate key
	origKey, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Retrieve key
	retrievedKey, err := be.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey failed: %v", err)
	}

	// Compare keys
	rawOrig, err := origKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw original key: %v", err)
	}
	rawRetrieved, err := retrievedKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw retrieved key: %v", err)
	}
	if string(rawOrig) != string(rawRetrieved) {
		t.Error("Retrieved key does not match original")
	}
}

// TestSymmetricEncrypter tests symmetric encryption and decryption
func TestSymmetricEncrypter(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test-encrypt", 256, types.SymmetricAES256GCM)

	// Generate key
	_, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Get encrypter
	encrypter, err := be.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	// Test data
	plaintext := []byte("Hello, World! This is a test message.")

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}
	if len(encrypted.Nonce) == 0 {
		t.Error("Nonce is empty")
	}
	if len(encrypted.Tag) == 0 {
		t.Error("Tag is empty")
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match original. Got %q, want %q", decrypted, plaintext)
	}
}

// TestSymmetricEncrypter_WithAAD tests encryption with additional authenticated data
func TestSymmetricEncrypter_WithAAD(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test-encrypt-aad", 256, types.SymmetricAES256GCM)

	// Generate key
	_, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Get encrypter
	encrypter, err := be.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter failed: %v", err)
	}

	plaintext := []byte("Secret message")
	aad := []byte("additional-authenticated-data")

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

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match. Got %q, want %q", decrypted, plaintext)
	}

	// Decrypt with wrong AAD should fail
	wrongAAD := []byte("wrong-aad")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		t.Error("Expected error when decrypting with wrong AAD, got nil")
	}
}

// TestSigner tests crypto.Signer interface
func TestSigner(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-signer", 2048)

	// Generate key
	_, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get signer
	signer, err := be.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	// Sign some data
	hash := sha256.Sum256([]byte("test data"))
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}
}

// TestDecrypter tests crypto.Decrypter interface
func TestDecrypter(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-decrypter", 2048)

	// Generate key
	key, err := be.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	rsaKey := key.(*rsa.PrivateKey)

	// Get decrypter
	decrypter, err := be.Decrypter(attrs)
	if err != nil {
		t.Fatalf("Decrypter failed: %v", err)
	}

	// Encrypt some data with the public key
	plaintext := []byte("secret message")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with the decrypter
	decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match. Got %q, want %q", decrypted, plaintext)
	}
}

// TestDeleteKey tests key deletion for both asymmetric and symmetric keys
func TestDeleteKey(t *testing.T) {
	t.Run("AsymmetricKey", func(t *testing.T) {
		be, _ := createTestBackend(t)
		defer func() { _ = be.Close() }()

		attrs := createRSAAttrs("test-delete-rsa", 2048)

		// Generate key
		_, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Delete key
		err = be.DeleteKey(attrs)
		if err != nil {
			t.Fatalf("DeleteKey failed: %v", err)
		}

		// Verify key is deleted
		_, err = be.GetKey(attrs)
		if err == nil {
			t.Error("Expected error when getting deleted key, got nil")
		}
	})

	t.Run("SymmetricKey", func(t *testing.T) {
		be, _ := createTestBackend(t)
		defer func() { _ = be.Close() }()

		attrs := createAESAttrs("test-delete-aes", 256, types.SymmetricAES256GCM)

		// Generate key
		_, err := be.GenerateSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSymmetricKey failed: %v", err)
		}

		// Delete key
		err = be.DeleteKey(attrs)
		if err != nil {
			t.Fatalf("DeleteKey failed: %v", err)
		}

		// Verify key is deleted
		_, err = be.GetSymmetricKey(attrs)
		if err == nil {
			t.Error("Expected error when getting deleted key, got nil")
		}
	})
}

// TestListKeys tests listing all keys (both asymmetric and symmetric)
func TestListKeys(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Generate some asymmetric keys
	rsaAttrs := createRSAAttrs("test-list-rsa", 2048)
	_, err := be.GenerateKey(rsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	ecdsaAttrs := createECDSAAttrs("test-list-ecdsa", "P-256")
	_, err = be.GenerateKey(ecdsaAttrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Generate some symmetric keys
	aes128Attrs := createAESAttrs("test-list-aes128", 128, types.SymmetricAES128GCM)
	_, err = be.GenerateSymmetricKey(aes128Attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	aes256Attrs := createAESAttrs("test-list-aes256", 256, types.SymmetricAES256GCM)
	_, err = be.GenerateSymmetricKey(aes256Attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// List all keys
	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	// Note: We expect 4 unique keys, but the current implementation might
	// return duplicates since both backends share the same storage.
	// The key IDs are different, so we won't get exact duplicates.
	if len(keys) < 4 {
		t.Errorf("Expected at least 4 keys, got %d", len(keys))
	}

	// Verify we can find all our test keys by CN
	cnMap := make(map[string]bool)
	for _, k := range keys {
		cnMap[k.CN] = true
	}

	expectedCNs := []string{"test-list-rsa", "test-list-ecdsa", "test-list-aes128", "test-list-aes256"}
	for _, cn := range expectedCNs {
		if !cnMap[cn] {
			t.Errorf("Expected to find key with CN %s", cn)
		}
	}
}

// TestRotateKey tests key rotation for both asymmetric and symmetric keys
func TestRotateKey(t *testing.T) {
	t.Run("AsymmetricKey", func(t *testing.T) {
		be, _ := createTestBackend(t)
		defer func() { _ = be.Close() }()

		attrs := createRSAAttrs("test-rotate-rsa", 2048)

		// Generate initial key
		origKey, err := be.GenerateKey(attrs)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Rotate key
		err = be.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}

		// Get new key
		newKey, err := be.GetKey(attrs)
		if err != nil {
			t.Fatalf("GetKey after rotation failed: %v", err)
		}

		// Verify keys are different
		origRSA := origKey.(*rsa.PrivateKey)
		newRSA := newKey.(*rsa.PrivateKey)

		if origRSA.N.Cmp(newRSA.N) == 0 {
			t.Error("Rotated key is the same as original key")
		}
	})

	t.Run("SymmetricKey", func(t *testing.T) {
		be, _ := createTestBackend(t)
		defer func() { _ = be.Close() }()

		attrs := createAESAttrs("test-rotate-aes", 256, types.SymmetricAES256GCM)

		// Generate initial key
		origKey, err := be.GenerateSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("GenerateSymmetricKey failed: %v", err)
		}

		// Rotate key
		err = be.RotateKey(attrs)
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}

		// Get new key
		newKey, err := be.GetSymmetricKey(attrs)
		if err != nil {
			t.Fatalf("GetSymmetricKey after rotation failed: %v", err)
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
	})
}

// TestClose tests backend closure
func TestClose(t *testing.T) {
	be, _ := createTestBackend(t)

	err := be.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail
	attrs := createRSAAttrs("test-after-close", 2048)
	_, err = be.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error after close, got nil")
	}
	if !errors.Is(err, ErrStorageClosed) {
		t.Errorf("Expected ErrStorageClosed, got %v", err)
	}
}

// TestConcurrency tests concurrent operations
func TestConcurrency(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // asymmetric + symmetric

	// Concurrent asymmetric key operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			attrs := createRSAAttrs("concurrent-rsa-"+string(rune(id)), 2048)

			// Generate
			_, err := be.GenerateKey(attrs)
			if err != nil {
				t.Errorf("GenerateKey failed: %v", err)
				return
			}

			// Get
			_, err = be.GetKey(attrs)
			if err != nil {
				t.Errorf("GetKey failed: %v", err)
				return
			}

			// Delete
			err = be.DeleteKey(attrs)
			if err != nil {
				t.Errorf("DeleteKey failed: %v", err)
			}
		}(i)
	}

	// Concurrent symmetric key operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			attrs := createAESAttrs("concurrent-aes-"+string(rune(id)), 256, types.SymmetricAES256GCM)

			// Generate
			_, err := be.GenerateSymmetricKey(attrs)
			if err != nil {
				t.Errorf("GenerateSymmetricKey failed: %v", err)
				return
			}

			// Get
			_, err = be.GetSymmetricKey(attrs)
			if err != nil {
				t.Errorf("GetSymmetricKey failed: %v", err)
				return
			}

			// Delete
			err = be.DeleteKey(attrs)
			if err != nil {
				t.Errorf("DeleteKey failed: %v", err)
			}
		}(i)
	}

	wg.Wait()
}

// TestBackendType tests the backend type identifier
func TestBackendType(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	if be.Type() != backend.BackendTypeSoftware {
		t.Errorf("Expected type %s, got %s", backend.BackendTypeSoftware, be.Type())
	}
}

// TestCapabilities tests the backend capabilities
func TestCapabilities(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	caps := be.Capabilities()

	// Verify all expected capabilities
	expectedCaps := map[string]bool{
		"Keys":                caps.Keys,
		"HardwareBacked":      !caps.HardwareBacked, // Should be false
		"Signing":             caps.Signing,
		"Decryption":          caps.Decryption,
		"KeyRotation":         caps.KeyRotation,
		"SymmetricEncryption": caps.SymmetricEncryption,
	}

	for name, value := range expectedCaps {
		if !value {
			t.Errorf("Expected %s capability to be true", name)
		}
	}
}

// TestClosedBackendOperations tests that operations fail after backend is closed
func TestClosedBackendOperations(t *testing.T) {
	be, _ := createTestBackend(t)

	// Close the backend
	if err := be.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Double close should be safe
	if err := be.Close(); err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}

	rsaAttrs := createRSAAttrs("test-closed-rsa", 2048)
	aesAttrs := createAESAttrs("test-closed-aes", 256, types.SymmetricAES256GCM)

	// Test all operations that should fail after close
	tests := []struct {
		name string
		fn   func() error
	}{
		{"GenerateKey", func() error {
			_, err := be.GenerateKey(rsaAttrs)
			return err
		}},
		{"GetKey", func() error {
			_, err := be.GetKey(rsaAttrs)
			return err
		}},
		{"DeleteKey", func() error {
			return be.DeleteKey(rsaAttrs)
		}},
		{"ListKeys", func() error {
			_, err := be.ListKeys()
			return err
		}},
		{"Signer", func() error {
			_, err := be.Signer(rsaAttrs)
			return err
		}},
		{"Decrypter", func() error {
			_, err := be.Decrypter(rsaAttrs)
			return err
		}},
		{"RotateKey", func() error {
			return be.RotateKey(rsaAttrs)
		}},
		{"GenerateSymmetricKey", func() error {
			_, err := be.GenerateSymmetricKey(aesAttrs)
			return err
		}},
		{"GetSymmetricKey", func() error {
			_, err := be.GetSymmetricKey(aesAttrs)
			return err
		}},
		{"SymmetricEncrypter", func() error {
			_, err := be.SymmetricEncrypter(aesAttrs)
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Errorf("%s: expected error after close, got nil", tt.name)
			}
			if !errors.Is(err, ErrStorageClosed) {
				t.Errorf("%s: expected ErrStorageClosed, got %v", tt.name, err)
			}
		})
	}
}

// TestGetKey_SymmetricKeyError tests error handling when getting symmetric keys via GetKey
func TestGetKey_SymmetricKeyError(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Create a symmetric key
	aesAttrs := createAESAttrs("test-symmetric-error", 256, types.SymmetricAES256GCM)
	_, err := be.GenerateSymmetricKey(aesAttrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Try to get it as an asymmetric key (should fail at the PKCS8 backend level)
	_, err = be.GetKey(aesAttrs)
	if err == nil {
		t.Error("Expected error when getting symmetric key via GetKey, got nil")
	}
}

// TestListKeys_Empty tests listing keys when no keys exist
func TestListKeys_Empty(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	keys, err := be.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}
}

// TestRotateKey_NonExistentKey tests rotating a key that doesn't exist
func TestRotateKey_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Rotating a non-existent key succeeds by creating a new key
	// (DeleteKey ignores ErrKeyNotFound, then GenerateKey creates the key)
	attrs := createRSAAttrs("non-existent-key", 2048)
	err := be.RotateKey(attrs)
	if err != nil {
		t.Fatalf("RotateKey should succeed for non-existent key (creates new key): %v", err)
	}

	// Verify the key was created
	_, err = be.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey should succeed after rotation: %v", err)
	}
}

// TestDeleteKey_NonExistentKey tests deleting a key that doesn't exist
func TestDeleteKey_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("non-existent-delete", 2048)
	err := be.DeleteKey(attrs)
	if err == nil {
		t.Error("Expected error when deleting non-existent key, got nil")
	}
}

// TestSigner_NonExistentKey tests getting signer for non-existent key
func TestSigner_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("non-existent-signer", 2048)
	_, err := be.Signer(attrs)
	if err == nil {
		t.Error("Expected error when getting signer for non-existent key, got nil")
	}
}

// TestDecrypter_NonExistentKey tests getting decrypter for non-existent key
func TestDecrypter_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("non-existent-decrypter", 2048)
	_, err := be.Decrypter(attrs)
	if err == nil {
		t.Error("Expected error when getting decrypter for non-existent key, got nil")
	}
}

// TestSymmetricEncrypter_NonExistentKey tests getting encrypter for non-existent key
func TestSymmetricEncrypter_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("non-existent-encrypter", 256, types.SymmetricAES256GCM)
	_, err := be.SymmetricEncrypter(attrs)
	if err == nil {
		t.Error("Expected error when getting encrypter for non-existent key, got nil")
	}
}

// TestGetKey_NonExistentKey tests getting a non-existent asymmetric key
func TestGetKey_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("non-existent-get", 2048)
	_, err := be.GetKey(attrs)
	if err == nil {
		t.Error("Expected error when getting non-existent key, got nil")
	}
}

// TestGetSymmetricKey_NonExistentKey tests getting a non-existent symmetric key
func TestGetSymmetricKey_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("non-existent-get-sym", 256, types.SymmetricAES256GCM)
	_, err := be.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error when getting non-existent symmetric key, got nil")
	}
}
