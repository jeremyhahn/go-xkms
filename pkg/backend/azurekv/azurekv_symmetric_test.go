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

//go:build azurekv

package azurekv

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// testBackend creates a test backend with mock client and memory storage
func testBackend(t *testing.T) (*Backend, *MockKeyVaultClient) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	return b, mockClient
}

// TestSymmetricBackendImplementation verifies that Backend implements SymmetricBackend interface
func TestSymmetricBackendImplementation(t *testing.T) {
	var _ types.SymmetricBackend = (*Backend)(nil)
}

// TestGenerateSymmetricKey tests symmetric key generation
func TestGenerateSymmetricKey(t *testing.T) {
	// Skip symmetric tests - they require Azure Secrets API which isn't mocked
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")

	tests := []struct {
		name      string
		keySize   int
		algorithm types.SymmetricAlgorithm
		wantErr   bool
	}{
		{
			name:      "AES-128-GCM",
			keySize:   128,
			algorithm: types.SymmetricAES128GCM,
			wantErr:   false,
		},
		{
			name:      "AES-192-GCM",
			keySize:   192,
			algorithm: types.SymmetricAES192GCM,
			wantErr:   false,
		},
		{
			name:      "AES-256-GCM",
			keySize:   256,
			algorithm: types.SymmetricAES256GCM,
			wantErr:   false,
		},
		{
			name:      "Invalid key size",
			keySize:   512,
			algorithm: types.SymmetricAES256GCM,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := testBackend(t)
			defer func() { _ = b.Close() }()

			// Create key attributes
			attrs := &types.KeyAttributes{
				CN:                 "test-symmetric-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				SymmetricAlgorithm: tt.algorithm,
			}

			// Generate symmetric key
			key, err := b.GenerateSymmetricKey(attrs)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to generate symmetric key: %v", err)
			}

			if key == nil {
				t.Fatal("Generated key is nil")
			}

			// Verify key properties
			if key.Algorithm() != string(tt.algorithm) {
				t.Errorf("Algorithm mismatch: got %s, want %s", key.Algorithm(), tt.algorithm)
			}

			if key.KeySize() != tt.keySize {
				t.Errorf("Key size mismatch: got %d, want %d", key.KeySize(), tt.keySize)
			}

			// For Azure Key Vault, Raw() should return nil (key is not extractable)
			rawKey, _ := key.Raw()
			if rawKey != nil {
				t.Error("Expected Raw() to return nil for Azure Key Vault symmetric key")
			}
		})
	}
}

// TestGenerateSymmetricKeyIdempotent verifies that generating the same key twice returns existing key
func TestGenerateSymmetricKeyIdempotent(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-idempotent-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate first time
	key1, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Generate second time with same attributes
	key2, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key on second attempt: %v", err)
	}

	// Verify both keys have the same properties
	if key1.Algorithm() != key2.Algorithm() {
		t.Errorf("Algorithm mismatch between keys: %s != %s", key1.Algorithm(), key2.Algorithm())
	}

	if key1.KeySize() != key2.KeySize() {
		t.Errorf("Key size mismatch between keys: %d != %d", key1.KeySize(), key2.KeySize())
	}
}

// TestGetSymmetricKey tests retrieving an existing symmetric key
func TestGetSymmetricKey(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-get-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate key first
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Retrieve the key
	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric key: %v", err)
	}

	if key == nil {
		t.Fatal("Retrieved key is nil")
	}

	if key.Algorithm() != string(types.SymmetricAES256GCM) {
		t.Errorf("Algorithm mismatch: got %s, want %s", key.Algorithm(), types.SymmetricAES256GCM)
	}

	if key.KeySize() != 256 {
		t.Errorf("Key size mismatch: got %d, want 256", key.KeySize())
	}
}

// TestGetSymmetricKeyNotFound tests error when key doesn't exist
func TestGetSymmetricKeyNotFound(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "non-existent-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Try to get a key that doesn't exist
	_, err := b.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error for non-existent key, got nil")
	}
}

// TestSymmetricEncryptDecrypt tests encryption and decryption operations
func TestSymmetricEncryptDecrypt(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-encrypt-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate symmetric key
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	// Test data
	plaintext := []byte("Sensitive data to encrypt using Azure Key Vault")

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if encrypted == nil {
		t.Fatal("Encrypted data is nil")
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

	if encrypted.Algorithm != string(types.SymmetricAES256GCM) {
		t.Errorf("Algorithm mismatch: got %s, want %s", encrypted.Algorithm, types.SymmetricAES256GCM)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data mismatch:\ngot:  %s\nwant: %s", string(decrypted), string(plaintext))
	}
}

// TestSymmetricEncryptDecryptWithAAD tests encryption/decryption with Additional Authenticated Data
func TestSymmetricEncryptDecryptWithAAD(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-aad-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate symmetric key
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	plaintext := []byte("Secret message")
	aad := []byte("context-information")

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Encryption with AAD failed: %v", err)
	}

	// Decrypt with correct AAD
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Decryption with AAD failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}

	// Decrypt with wrong AAD should fail
	wrongAAD := []byte("wrong-context")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		t.Error("Expected decryption to fail with wrong AAD, but it succeeded")
	}
}

// TestSymmetricEncryptEmptyData tests encryption of empty data
func TestSymmetricEncryptEmptyData(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-empty-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate symmetric key
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	// Encrypt empty data
	plaintext := []byte{}
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption of empty data failed: %v", err)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption of empty data failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Expected empty decrypted data, got %d bytes", len(decrypted))
	}
}

// TestSymmetricEncryptLargeData tests encryption of larger data
func TestSymmetricEncryptLargeData(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-large-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate symmetric key
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	// Create 1MB of test data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption of large data failed: %v", err)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption of large data failed: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Decrypted data length mismatch: got %d, want %d", len(decrypted), len(plaintext))
	}

	// Verify data integrity
	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Data mismatch at byte %d: got %d, want %d", i, decrypted[i], plaintext[i])
			break
		}
	}
}

// TestSymmetricInvalidAttributes tests error handling for invalid attributes
func TestSymmetricInvalidAttributes(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name:  "Nil attributes",
			attrs: nil,
		},
		{
			name: "Asymmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-invalid",
				KeyType:      backend.KEY_TYPE_SECRET,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.RSA, // Asymmetric algorithm
			},
		},
		{
			name: "Missing symmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:        "test-missing-attrs",
				KeyType:   backend.KEY_TYPE_SECRET,
				StoreType: backend.STORE_AZUREKV,
				// No SymmetricAlgorithm set
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.GenerateSymmetricKey(tt.attrs)
			if err == nil {
				t.Error("Expected error for invalid attributes, got nil")
			}
		})
	}
}

// TestCapabilitiesSymmetricEncryption verifies symmetric encryption capability is reported
func TestCapabilitiesSymmetricEncryption(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	caps := b.Capabilities()
	if !caps.SymmetricEncryption {
		t.Error("SymmetricEncryption capability should be true")
	}

	if !caps.SupportsSymmetricEncryption() {
		t.Error("SupportsSymmetricEncryption() should return true")
	}
}

// TestAzureKVBackend_NonceReuse tests AEAD nonce reuse detection.
func TestAzureKVBackend_NonceReuse(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	// Generate a key with nonce tracking enabled
	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-reuse",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Generate a fixed nonce for testing
	fixedNonce := make([]byte, 12)
	copy(fixedNonce, []byte("testnonce123"))

	plaintext := []byte("Test message")
	opts := &types.EncryptOptions{
		Nonce: fixedNonce,
	}

	// First encryption with fixed nonce - should succeed
	_, err = encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("First encryption with fixed nonce failed: %v", err)
	}

	// Second encryption with same nonce - should fail
	_, err = encrypter.Encrypt(plaintext, opts)
	if err == nil {
		t.Fatal("Expected nonce reuse to be detected")
	}

	// Verify error contains AEAD safety check message
	if !contains(err.Error(), "nonce reused") && !contains(err.Error(), "AEAD safety check failed") {
		t.Errorf("Expected nonce reuse error, got: %v", err)
	}
}

// TestAzureKVBackend_BytesLimit tests AEAD bytes limit enforcement.
func TestAzureKVBackend_BytesLimit(t *testing.T) {
	t.Skip("Skipping: Symmetric encryption requires Azure Secrets API (not mocked)")
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	// Generate a key with small bytes limit for testing
	smallLimit := int64(100) // 100 bytes
	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      true,
			BytesTrackingLimit: smallLimit,
		},
	}

	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Encrypt up to the limit
	plaintext := make([]byte, 50)

	// First 50 bytes - should succeed
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second 50 bytes - should succeed (total 100)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Third 50 bytes - should fail (would exceed 100 byte limit)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err == nil {
		t.Fatal("Expected bytes limit to be enforced")
	}

	// Verify error contains bytes limit message
	if !contains(err.Error(), "bytes") && !contains(err.Error(), "limit") && !contains(err.Error(), "AEAD safety check failed") {
		t.Errorf("Expected bytes limit error, got: %v", err)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && containsHelper(s, substr)
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
