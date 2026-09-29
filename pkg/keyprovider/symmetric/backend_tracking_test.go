// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package symmetric

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestBackend_TrackingEnabled(t *testing.T) {
	// Create backend with default tracker (memory-based)
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Generate a key with default tracking options
	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions:        nil, // Use defaults
	}

	_, err = b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
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
	symmetricBackend := b.(*Backend)
	tracker := symmetricBackend.GetTracker()
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

func TestBackend_NonceReuse(t *testing.T) {
	// Create backend
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Generate a key with nonce tracking enabled
	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-reuse",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	_, err = b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
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

	if _, ok := requireEncrypt(t, encrypter, plaintext, opts); !ok {
		return
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

func TestBackend_BytesLimit(t *testing.T) {
	// Create backend
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Generate a key with small bytes limit for testing
	smallLimit := int64(100) // 100 bytes
	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      true,
			BytesTrackingLimit: smallLimit,
		},
	}

	_, err = b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	// Encrypt up to the limit
	plaintext := make([]byte, 50)
	_, _ = rand.Read(plaintext)

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

// TestBackend_NonceReuseRefusedEvenWithTrackingOptedOut proves nonce-reuse
// protection is no longer something AEADOptions.NonceTracking can opt a key
// out of. Before go-xkms#1201, NonceTracking:false skipped the per-backend
// AEADSafetyTracker's CheckNonce/RecordNonce entirely, so a caller could
// silently disable the one guarantee AES-GCM depends on. The claim now goes
// through the shared, unconditional aead.KeyNonceGuard on every Encrypt call
// regardless of this setting -- NIST SP 800-38D forbids nonce reuse outright,
// so it is not optional.
func TestBackend_NonceReuseRefusedEvenWithTrackingOptedOut(t *testing.T) {
	// Create backend
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Generate a key with AEADOptions.NonceTracking opted out.
	attrs := &types.KeyAttributes{
		CN:                 "test-no-tracking",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	_, err = b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	fixedNonce := make([]byte, 12)
	_, _ = rand.Read(fixedNonce)

	opts := &types.EncryptOptions{
		Nonce: fixedNonce,
	}

	plaintext := []byte("Test message")

	// First encryption
	if _, ok := requireEncrypt(t, encrypter, plaintext, opts); !ok {
		return
	}

	// Second encryption with the same nonce must still be refused: the guard
	// is unconditional, independent of AEADOptions.NonceTracking.
	_, err = encrypter.Encrypt(plaintext, opts)
	if !errors.Is(err, backend.ErrNonceReused) {
		t.Errorf("expected ErrNonceReused regardless of NonceTracking, got: %v", err)
	}
}

func TestBackend_KeyRotation(t *testing.T) {
	// Create backend
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Generate a key
	attrs := &types.KeyAttributes{
		CN:                 "test-rotation",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      true,
			BytesTrackingLimit: 1000,
		},
	}

	_, err = b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get encrypter and encrypt some data
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to get encrypter: %v", err)
	}

	plaintext := make([]byte, 500)
	_, _ = rand.Read(plaintext)

	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify bytes were tracked
	symmetricBackend := b.(*Backend)
	tracker := symmetricBackend.GetTracker()
	keyID := attrs.ID()

	total, _ := tracker.GetBytesEncrypted(keyID)
	if total != 500 {
		t.Errorf("Expected 500 bytes before rotation, got %d", total)
	}

	// Rotate the key
	err = b.RotateKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Key rotation failed: %v", err)
	}

	// Verify tracking was reset
	total, _ = tracker.GetBytesEncrypted(keyID)
	if total != 0 {
		t.Errorf("Expected 0 bytes after rotation, got %d", total)
	}

	// Verify we can encrypt with the new key
	encrypter, err = b.SymmetricEncrypter(context.Background(), attrs)
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

func TestBackend_CustomTracker(t *testing.T) {
	// Create custom tracker
	customTracker := backend.NewMemoryAEADTracker()

	// Create backend with custom tracker
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
		Tracker:    customTracker,
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	// Verify backend uses custom tracker
	symmetricBackend := b.(*Backend)
	if symmetricBackend.GetTracker() != customTracker {
		t.Error("Backend should use custom tracker")
	}

	// Generate a key and verify tracking works
	attrs := &types.KeyAttributes{
		CN:                 "test-custom-tracker",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encrypt data
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
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

func BenchmarkBackend_EncryptWithTracking(b *testing.B) {
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}

	symmetricBackend, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = symmetricBackend.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "bench-tracking",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symmetricBackend.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := symmetricBackend.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		b.Fatalf("Failed to get encrypter: %v", err)
	}

	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkBackend_EncryptWithoutTracking(b *testing.B) {
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}

	symmetricBackend, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = symmetricBackend.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "bench-no-tracking",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	_, err = symmetricBackend.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	encrypter, err := symmetricBackend.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		b.Fatalf("Failed to get encrypter: %v", err)
	}

	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}
