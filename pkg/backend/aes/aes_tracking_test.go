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

package aes

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestAESBackend_TrackingEnabled(t *testing.T) {
	// Create backend with default tracker (memory-based)
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Close()

	// Generate a key with default tracking options
	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		AEADOptions: nil, // Use defaults
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Encrypt some data
	plaintext1 := []byte("Hello, World!")
	encrypted1, err := encrypter.Encrypt(plaintext1, nil)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Encrypt more data
	plaintext2 := []byte("This is a test of AEAD safety tracking")
	encrypted2, err := encrypter.Encrypt(plaintext2, nil)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Verify nonces are different
	if string(encrypted1.Nonce) == string(encrypted2.Nonce) {
		t.Error("Nonces should be different for each encryption")
	}

	// Verify tracking recorded the nonces
	aesBackend := b.(*AESBackend)
	tracker := aesBackend.GetTracker()
	keyID := attrs.ID()

	// Check bytes encrypted
	total, err := tracker.GetBytesEncrypted(keyID)
	if err != nil {
		t.Fatalf("Failed to get bytes encrypted: %v", err)
	}

	expectedBytes := int64(len(plaintext1) + len(plaintext2))
	if total != expectedBytes {
		t.Errorf("Expected %d bytes encrypted, got %d", expectedBytes, total)
	}

	// Decrypt to verify correctness
	decrypted1, err := encrypter.Decrypt(encrypted1, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if string(decrypted1) != string(plaintext1) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestAESBackend_NonceReuse(t *testing.T) {
	// Create backend
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Close()

	// Generate a key with nonce tracking enabled
	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-reuse",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Generate a fixed nonce
	fixedNonce := make([]byte, 12)
	if _, err := rand.Read(fixedNonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// First encryption with fixed nonce - should succeed
	plaintext := []byte("Test message")
	opts := &types.EncryptOptions{
		Nonce: fixedNonce,
	}

	_, err = encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("First encryption with fixed nonce failed: %v", err)
	}

	// Second encryption with same nonce - should fail
	_, err = encrypter.Encrypt(plaintext, opts)
	if err == nil {
		t.Fatal("Expected nonce reuse to be detected")
	}

	// Verify error is ErrNonceReused
	if !errors.Is(err, backend.ErrNonceReused) {
		t.Errorf("Expected ErrNonceReused, got: %v", err)
	}
}

func TestAESBackend_BytesLimit(t *testing.T) {
	// Create backend
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Close()

	// Generate a key with small bytes limit for testing
	smallLimit := int64(100) // 100 bytes
	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      true,
			BytesTrackingLimit: smallLimit,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
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
	rand.Read(plaintext)

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

	// Verify error is ErrBytesLimitExceeded
	if !errors.Is(err, backend.ErrBytesLimitExceeded) {
		t.Errorf("Expected ErrBytesLimitExceeded, got: %v", err)
	}
}

func TestAESBackend_TrackingDisabled(t *testing.T) {
	// Create backend
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Close()

	// Generate a key with tracking disabled
	attrs := &types.KeyAttributes{
		CN:                 "test-no-tracking",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Use same nonce multiple times - should succeed when tracking disabled
	fixedNonce := make([]byte, 12)
	rand.Read(fixedNonce)

	opts := &types.EncryptOptions{
		Nonce: fixedNonce,
	}

	plaintext := []byte("Test message")

	// First encryption
	_, err = encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second encryption with same nonce - should succeed when tracking disabled
	_, err = encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Errorf("Second encryption should succeed when tracking disabled: %v", err)
	}
}

func TestAESBackend_KeyRotation(t *testing.T) {
	// Create backend
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Close()

	// Generate a key
	attrs := &types.KeyAttributes{
		CN:                 "test-rotation",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      true,
			BytesTrackingLimit: 1000,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter and encrypt some data
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	plaintext := make([]byte, 500)
	rand.Read(plaintext)

	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify bytes were tracked
	aesBackend := b.(*AESBackend)
	tracker := aesBackend.GetTracker()
	keyID := attrs.ID()

	total, _ := tracker.GetBytesEncrypted(keyID)
	if total != 500 {
		t.Errorf("Expected 500 bytes before rotation, got %d", total)
	}

	// Rotate the key
	err = b.RotateKey(attrs)
	if err != nil {
		t.Fatalf("Key rotation failed: %v", err)
	}

	// Verify tracking was reset
	total, _ = tracker.GetBytesEncrypted(keyID)
	if total != 0 {
		t.Errorf("Expected 0 bytes after rotation, got %d", total)
	}

	// Verify we can encrypt with the new key
	encrypter, err = b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter after rotation: %v", err)
	}

	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption after rotation failed: %v", err)
	}

	// Verify bytes were tracked with new key
	total, _ = tracker.GetBytesEncrypted(keyID)
	if total != 500 {
		t.Errorf("Expected 500 bytes after rotation, got %d", total)
	}
}

func TestAESBackend_CustomTracker(t *testing.T) {
	// Create custom tracker
	customTracker := backend.NewMemoryAEADTracker()

	// Create backend with custom tracker
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
		Tracker:    customTracker,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Close()

	// Verify backend uses custom tracker
	aesBackend := b.(*AESBackend)
	if aesBackend.GetTracker() != customTracker {
		t.Error("Backend should use custom tracker")
	}

	// Generate a key and verify tracking works
	attrs := &types.KeyAttributes{
		CN:                 "test-custom-tracker",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	_, err = b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encrypt data
	encrypter, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	plaintext := []byte("Test with custom tracker")
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify custom tracker recorded the bytes
	keyID := attrs.ID()
	total, err := customTracker.GetBytesEncrypted(keyID)
	if err != nil {
		t.Fatalf("Failed to get bytes from custom tracker: %v", err)
	}

	if total != int64(len(plaintext)) {
		t.Errorf("Expected %d bytes in custom tracker, got %d", len(plaintext), total)
	}
}

func BenchmarkAESBackend_EncryptWithTracking(b *testing.B) {
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
	}

	aesBackend, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer aesBackend.Close()

	attrs := &types.KeyAttributes{
		CN:                 "bench-tracking",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	_, err = aesBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := aesBackend.SymmetricEncrypter(attrs)
	if err != nil {
		b.Fatalf("Failed to get encrypter: %v", err)
	}

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkAESBackend_EncryptWithoutTracking(b *testing.B) {
	storage := memory.New()
	config := &Config{
		KeyStorage: storage,
	}

	aesBackend, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer aesBackend.Close()

	attrs := &types.KeyAttributes{
		CN:                 "bench-no-tracking",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	_, err = aesBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := aesBackend.SymmetricEncrypter(attrs)
	if err != nil {
		b.Fatalf("Failed to get encrypter: %v", err)
	}

	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}
