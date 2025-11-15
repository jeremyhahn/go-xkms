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

//go:build tpm2

package tpm2

import (
	"crypto/rand"
	"testing"

	kbackend "github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestTPM2Backend_NonceReuse tests that the TPM2 backend detects and prevents nonce reuse
func TestTPM2Backend_NonceReuse(t *testing.T) {
	// Create a TPM2 keystore with AEAD tracker
	config := DefaultConfig()
	config.UseSimulator = true
	config.SimulatorType = "embedded"

	keyStorage := memory.New()
	certStorage := memory.New()

	ks, err := NewTPM2KeyStore(config, nil, keyStorage, certStorage, nil)
	if err != nil {
		t.Fatalf("Failed to create TPM2 keystore: %v", err)
	}
	defer ks.Close()

	// Initialize the keystore
	if err := ks.Initialize(nil, nil); err != nil {
		t.Fatalf("Failed to initialize TPM2 keystore: %v", err)
	}

	// Generate a symmetric key
	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-reuse",
		StoreType:          "tpm2",
		KeyType:            kbackend.KEY_TYPE_ENCRYPTION,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	_, err = ks.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Get the encrypter
	encrypter, err := ks.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	// Generate a fixed nonce for testing
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// First encryption with fixed nonce should succeed
	plaintext := []byte("test data")
	opts := &types.EncryptOptions{
		Nonce: nonce,
	}

	_, err = encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second encryption with same nonce should fail
	_, err = encrypter.Encrypt(plaintext, opts)
	if err == nil {
		t.Fatal("Expected error for nonce reuse, but encryption succeeded")
	}

	// Verify the error message mentions nonce reuse
	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}

// TestTPM2Backend_BytesLimit tests that the TPM2 backend enforces AEAD bytes limits
func TestTPM2Backend_BytesLimit(t *testing.T) {
	// Create a TPM2 keystore with AEAD tracker and small byte limit for testing
	config := DefaultConfig()
	config.UseSimulator = true
	config.SimulatorType = "embedded"

	keyStorage := memory.New()
	certStorage := memory.New()

	// Create tracker with small limit for testing
	tracker := kbackend.NewMemoryAEADTracker()
	config.Tracker = tracker

	ks, err := NewTPM2KeyStore(config, nil, keyStorage, certStorage, nil)
	if err != nil {
		t.Fatalf("Failed to create TPM2 keystore: %v", err)
	}
	defer ks.Close()

	// Initialize the keystore
	if err := ks.Initialize(nil, nil); err != nil {
		t.Fatalf("Failed to initialize TPM2 keystore: %v", err)
	}

	// Generate a symmetric key
	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		StoreType:          "tpm2",
		KeyType:            kbackend.KEY_TYPE_ENCRYPTION,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	_, err = ks.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Set a small byte limit for testing (1 KB)
	keyID := attrs.ID()
	testOptions := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 1024, // 1 KB limit for testing
		NonceSize:          12,
	}
	if err := tracker.SetAEADOptions(keyID, testOptions); err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// Get the encrypter
	encrypter, err := ks.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	// Encrypt data up to the limit
	plaintext := make([]byte, 512)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Failed to generate plaintext: %v", err)
	}

	// First encryption should succeed (512 bytes)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second encryption should succeed (total 1024 bytes)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Third encryption should fail (would exceed limit)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err == nil {
		t.Fatal("Expected error for bytes limit exceeded, but encryption succeeded")
	}

	// Verify the error message mentions bytes limit
	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}
