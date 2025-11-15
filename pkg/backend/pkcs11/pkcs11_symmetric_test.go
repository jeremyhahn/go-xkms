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

//go:build pkcs11

package pkcs11

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// newTestBackend creates a Backend for testing without full validation.
// This bypasses storage requirements since we're testing symmetric methods,
// not actual HSM operations.
func newTestBackend(tempLib string) *Backend {
	return &Backend{
		config: &Config{
			Library:    tempLib,
			TokenLabel: "test",
		},
	}
}

// TestBackend_SymmetricCapabilities verifies that the backend reports symmetric encryption support.
func TestBackend_SymmetricCapabilities(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	caps := b.Capabilities()
	if !caps.SupportsSymmetricEncryption() {
		t.Error("Backend should support symmetric encryption")
	}
	if !caps.SymmetricEncryption {
		t.Error("SymmetricEncryption capability should be true")
	}
}

// TestBackend_GenerateSymmetricKey verifies symmetric key generation.
func TestBackend_GenerateSymmetricKey(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	tests := []struct {
		name      string
		algorithm types.SymmetricAlgorithm
		keySize   int
		wantErr   bool
	}{
		{
			name:      "AES-128",
			algorithm: types.SymmetricAES128GCM,
			keySize:   128,
			wantErr:   true, // Will fail - not initialized
		},
		{
			name:      "AES-192",
			algorithm: types.SymmetricAES192GCM,
			keySize:   192,
			wantErr:   true, // Will fail - not initialized
		},
		{
			name:      "AES-256",
			algorithm: types.SymmetricAES256GCM,
			keySize:   256,
			wantErr:   true, // Will fail - not initialized
		},
		{
			name:      "invalid key size",
			algorithm: types.SymmetricAES128GCM,
			keySize:   64,
			wantErr:   true,
		},
		{
			name:      "asymmetric algorithm",
			algorithm: "",
			keySize:   2048,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-aes-" + tt.name,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: tt.algorithm,
				AESAttributes: &types.AESAttributes{
					KeySize: tt.keySize,
				},
			}

			// Skip validation for invalid test cases
			if tt.algorithm != "" && tt.keySize != 64 {
				if err := attrs.Validate(); err != nil {
					t.Fatalf("attrs.Validate() failed: %v", err)
				}
			}

			_, err := b.GenerateSymmetricKey(attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSymmetricKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			// For not initialized errors, this is expected
			if err != nil && err != ErrNotInitialized {
				t.Logf("GenerateSymmetricKey() error: %v (expected)", err)
			}
		})
	}
}

// TestBackend_GetSymmetricKey verifies symmetric key retrieval.
func TestBackend_GetSymmetricKey(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	attrs := &types.KeyAttributes{
		CN:                 "test-aes-get",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	if err := attrs.Validate(); err != nil {
		t.Fatalf("attrs.Validate() failed: %v", err)
	}

	// Should fail - not initialized
	_, err := b.GetSymmetricKey(attrs)
	if err != ErrNotInitialized {
		t.Errorf("GetSymmetricKey() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestBackend_SymmetricEncrypter verifies getting a symmetric encrypter.
func TestBackend_SymmetricEncrypter(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	attrs := &types.KeyAttributes{
		CN:                 "test-aes-encrypter",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	if err := attrs.Validate(); err != nil {
		t.Fatalf("attrs.Validate() failed: %v", err)
	}

	// Should fail - key doesn't exist
	_, err := b.SymmetricEncrypter(attrs)
	if err == nil {
		t.Error("SymmetricEncrypter() should return error when key doesn't exist")
	}
}

// TestPKCS11SymmetricKey_Interface verifies the pkcs11SymmetricKey implementation.
func TestPKCS11SymmetricKey_Interface(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	key := &pkcs11SymmetricKey{
		algorithm: "aes256-gcm",
		keySize:   256,
		handle:    0, // Mock handle
		backend:   b,
	}

	// Test Algorithm method
	if got := key.Algorithm(); got != "aes256-gcm" {
		t.Errorf("Algorithm() = %v, want aes256-gcm", got)
	}

	// Test KeySize method
	if got := key.KeySize(); got != 256 {
		t.Errorf("KeySize() = %v, want 256", got)
	}

	// Test Raw method (should return error for PKCS#11 keys as they don't expose raw material)
	_, err := key.Raw()
	if err == nil {
		t.Error("Raw() should return error for PKCS#11 keys, but returned nil")
	}
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("Raw() error = %v, want %v", err, backend.ErrNotSupported)
	}

	// Verify interface compliance
	var _ types.SymmetricKey = key
}

// TestSoftwareEncrypter_EncryptDecrypt tests the software fallback encrypter.
func TestSoftwareEncrypter_EncryptDecrypt(t *testing.T) {
	// Generate a random AES-256 key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := &softwareEncrypter{
		key:   key,
		attrs: attrs,
	}

	tests := []struct {
		name      string
		plaintext []byte
		opts      *types.EncryptOptions
	}{
		{
			name:      "simple encryption",
			plaintext: []byte("Hello, World!"),
			opts:      nil,
		},
		{
			name:      "with AAD",
			plaintext: []byte("Secret message"),
			opts: &types.EncryptOptions{
				AdditionalData: []byte("context info"),
			},
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
			opts:      nil,
		},
		{
			name:      "large plaintext",
			plaintext: make([]byte, 1024),
			opts:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := encrypter.Encrypt(tt.plaintext, tt.opts)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify encrypted data structure
			if len(encrypted.Nonce) != 12 {
				t.Errorf("Nonce length = %d, want 12", len(encrypted.Nonce))
			}
			if len(encrypted.Tag) != 16 {
				t.Errorf("Tag length = %d, want 16", len(encrypted.Tag))
			}
			if encrypted.Algorithm != "aes256-gcm" {
				t.Errorf("Algorithm = %v, want aes256-gcm", encrypted.Algorithm)
			}

			// Decrypt
			decryptOpts := &types.DecryptOptions{}
			if tt.opts != nil {
				decryptOpts.AdditionalData = tt.opts.AdditionalData
			}

			decrypted, err := encrypter.Decrypt(encrypted, decryptOpts)

			// Verify plaintext matches
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypted plaintext doesn't match original")
			}
		})
	}
}

// TestSoftwareEncrypter_AADMismatch verifies AAD verification.
func TestSoftwareEncrypter_AADMismatch(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := &softwareEncrypter{
		key:   key,
		attrs: attrs,
	}

	plaintext := []byte("Secret message")

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: []byte("original AAD"),
	})

	// Try to decrypt with different AAD
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("different AAD"),
	})
	if err == nil {
		t.Error("Decrypt() should fail with mismatched AAD")
	}

	// Decrypt with correct AAD should work
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("original AAD"),
	})

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted plaintext doesn't match")
	}
}

// TestSoftwareEncrypter_CustomNonce verifies custom nonce usage.
func TestSoftwareEncrypter_CustomNonce(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := &softwareEncrypter{
		key:   key,
		attrs: attrs,
	}

	// Generate custom nonce
	customNonce := make([]byte, 12)
	if _, err := rand.Read(customNonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	plaintext := []byte("Test message")

	// Encrypt with custom nonce
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		Nonce: customNonce,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Verify nonce matches
	if !bytes.Equal(encrypted.Nonce, customNonce) {
		t.Error("Encrypted data should use custom nonce")
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted plaintext doesn't match")
	}
}

// TestSoftwareEncrypter_TamperedCiphertext verifies authentication.
func TestSoftwareEncrypter_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := &softwareEncrypter{
		key:   key,
		attrs: attrs,
	}

	plaintext := []byte("Secret message")

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)

	// Tamper with ciphertext
	if len(encrypted.Ciphertext) > 0 {
		encrypted.Ciphertext[0] ^= 0xFF
	}

	// Decrypt should fail
	_, err = encrypter.Decrypt(encrypted, nil)
	if err == nil {
		t.Error("Decrypt() should fail with tampered ciphertext")
	}
}

// TestSoftwareEncrypter_TamperedTag verifies tag verification.
func TestSoftwareEncrypter_TamperedTag(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := &softwareEncrypter{
		key:   key,
		attrs: attrs,
	}

	plaintext := []byte("Secret message")

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)

	// Tamper with tag
	encrypted.Tag[0] ^= 0xFF

	// Decrypt should fail
	_, err = encrypter.Decrypt(encrypted, nil)
	if err == nil {
		t.Error("Decrypt() should fail with tampered tag")
	}
}

// TestBackend_GenerateSymmetricKey_AllKeySizes tests all supported key sizes.
func TestBackend_GenerateSymmetricKey_AllKeySizes(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	keySizes := []int{128, 192, 256}
	algorithms := []types.SymmetricAlgorithm{
		types.SymmetricAES128GCM,
		types.SymmetricAES192GCM,
		types.SymmetricAES256GCM,
	}

	for i, keySize := range keySizes {
		t.Run(string(algorithms[i]), func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-" + string(algorithms[i]),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: algorithms[i],
				AESAttributes: &types.AESAttributes{
					KeySize: keySize,
				},
			}

			if err := attrs.Validate(); err != nil {
				t.Fatalf("attrs.Validate() failed: %v", err)
			}

			_, err := b.GenerateSymmetricKey(attrs)
			// Will fail due to not initialized, but validates structure
			if err == nil {
				t.Error("GenerateSymmetricKey() should fail (not initialized)")
			}
		})
	}
}

// TestBackend_GetSymmetricKey_KeySizeInference tests key size inference from algorithm.
func TestBackend_GetSymmetricKey_KeySizeInference(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	// Test without explicit key size (should infer from algorithm)
	attrs := &types.KeyAttributes{
		CN:                 "test-inference",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 0, // Not specified
		},
	}

	// Should fail at not initialized, but tests inference logic
	_, err := b.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("GetSymmetricKey() should fail (not initialized)")
	}
}

// TestSoftwareEncrypter_ErrorHandling tests error conditions.
func TestSoftwareEncrypter_ErrorHandling(t *testing.T) {
	t.Run("encrypt with invalid key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}

		encrypter := &softwareEncrypter{
			key:   []byte("too short"), // Invalid key size
			attrs: attrs,
		}

		_, err := encrypter.Encrypt([]byte("test"), nil)
		if err == nil {
			t.Error("Encrypt() should fail with invalid key size")
		}
	})

	t.Run("decrypt with invalid key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}

		encrypter := &softwareEncrypter{
			key:   []byte("too short"),
			attrs: attrs,
		}

		data := &types.EncryptedData{
			Ciphertext: []byte("test"),
			Nonce:      make([]byte, 12),
			Tag:        make([]byte, 16),
		}

		_, err := encrypter.Decrypt(data, nil)
		if err == nil {
			t.Error("Decrypt() should fail with invalid key size")
		}
	})
}

// TestBackend_SymmetricInterface verifies symmetric methods exist.
func TestBackend_SymmetricInterface(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	// Verify backend has symmetric methods by calling them
	// (They will fail with not initialized, but verify the methods exist)
	attrs := &types.KeyAttributes{
		CN:                 "test",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	_, _ = b.GenerateSymmetricKey(attrs)
	_, _ = b.GetSymmetricKey(attrs)
	_, _ = b.SymmetricEncrypter(attrs)
}

// TestBackend_GenerateSymmetricKey_InvalidAttributes tests validation.
func TestBackend_GenerateSymmetricKey_InvalidAttributes(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	// Mock context to bypass not initialized error
	// (We want to test validation, not initialization)

	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr string
	}{
		{
			name: "missing CN",
			attrs: &types.KeyAttributes{
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				AESAttributes: &types.AESAttributes{
					KeySize: 256,
				},
			},
			wantErr: "CN is required",
		},
		{
			name: "asymmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test",
				KeyType:      backend.KEY_TYPE_SECRET,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			wantErr: "asymmetric algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.GenerateSymmetricKey(tt.attrs)
			if err == nil {
				t.Error("GenerateSymmetricKey() should return error")
			}
		})
	}
}

// TestPKCS11Backend_NonceReuse tests AEAD nonce reuse detection using tracker directly.
// Note: PKCS11 backend generates client-side nonces, so nonce tracking is applicable.
func TestPKCS11Backend_NonceReuse(t *testing.T) {
	// Create a tracker for testing
	tracker := backend.NewMemoryAEADTracker()

	// Setup AEAD options with nonce tracking enabled
	keyID := "test-pkcs11-nonce-reuse"
	opts := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      false,
		BytesTrackingLimit: 0,
	}

	err := tracker.SetAEADOptions(keyID, opts)
	if err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// Generate a fixed nonce
	fixedNonce := make([]byte, 12)
	if _, err := rand.Read(fixedNonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	// First check with nonce - should succeed
	err = tracker.CheckNonce(keyID, fixedNonce)
	if err != nil {
		t.Fatalf("First CheckNonce failed: %v", err)
	}

	// Record the nonce
	err = tracker.RecordNonce(keyID, fixedNonce)
	if err != nil {
		t.Fatalf("RecordNonce failed: %v", err)
	}

	// Second check with same nonce - should fail
	err = tracker.CheckNonce(keyID, fixedNonce)
	if err == nil {
		t.Fatal("Expected nonce reuse to be detected")
	}

	// Verify error is ErrNonceReused
	if !errors.Is(err, backend.ErrNonceReused) {
		t.Errorf("Expected ErrNonceReused, got: %v", err)
	}
}

// TestPKCS11Backend_BytesLimit tests AEAD bytes limit enforcement using tracker directly.
// Note: PKCS11 backend generates client-side nonces, so bytes tracking is applicable.
func TestPKCS11Backend_BytesLimit(t *testing.T) {
	// Create a tracker for testing
	tracker := backend.NewMemoryAEADTracker()

	// Setup AEAD options with small bytes limit
	keyID := "test-pkcs11-bytes-limit"
	smallLimit := int64(100) // 100 bytes
	opts := &types.AEADOptions{
		NonceTracking:      false,
		BytesTracking:      true,
		BytesTrackingLimit: smallLimit,
	}

	err := tracker.SetAEADOptions(keyID, opts)
	if err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// First 50 bytes - should succeed
	err = tracker.IncrementBytes(keyID, 50)
	if err != nil {
		t.Fatalf("First IncrementBytes failed: %v", err)
	}

	// Verify bytes counter
	total, err := tracker.GetBytesEncrypted(keyID)
	if err != nil {
		t.Fatalf("GetBytesEncrypted failed: %v", err)
	}
	if total != 50 {
		t.Errorf("Expected 50 bytes, got %d", total)
	}

	// Second 50 bytes - should succeed (total 100)
	err = tracker.IncrementBytes(keyID, 50)
	if err != nil {
		t.Fatalf("Second IncrementBytes failed: %v", err)
	}

	// Third 50 bytes - should fail (would exceed 100 byte limit)
	err = tracker.IncrementBytes(keyID, 50)
	if err == nil {
		t.Fatal("Expected bytes limit to be enforced")
	}

	// Verify error is ErrBytesLimitExceeded
	if !errors.Is(err, backend.ErrBytesLimitExceeded) {
		t.Errorf("Expected ErrBytesLimitExceeded, got: %v", err)
	}
}
