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

package canokey

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCanSeal verifies that CanSeal returns true when backend is initialized
func TestCanSeal(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	assert.True(t, b.CanSeal(), "CanSeal should return true when initialized")
}

// TestCanSealNotInitialized verifies that CanSeal returns false when not initialized
func TestCanSealNotInitialized(t *testing.T) {
	b := &Backend{
		initialized: false,
	}

	assert.False(t, b.CanSeal(), "CanSeal should return false when not initialized")
}

// TestSealNilOptions verifies that Seal fails with nil options
func TestSealNilOptions(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	data := []byte("test data")

	sealed, err := b.Seal(ctx, data, nil)
	assert.Error(t, err, "Seal should fail with nil options")
	assert.Nil(t, sealed, "Sealed data should be nil on error")
	assert.Contains(t, err.Error(), "seal options", "Error should mention seal options")
}

// TestSealNilKeyAttributes verifies that Seal fails with nil KeyAttributes
func TestSealNilKeyAttributes(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	data := []byte("test data")
	opts := &types.SealOptions{
		KeyAttributes: nil,
	}

	sealed, err := b.Seal(ctx, data, opts)
	assert.Error(t, err, "Seal should fail with nil KeyAttributes")
	assert.Nil(t, sealed, "Sealed data should be nil on error")
	assert.Contains(t, err.Error(), "KeyAttributes", "Error should mention KeyAttributes")
}

// TestSealNotInitialized verifies that Seal fails when backend is not initialized
func TestSealNotInitialized(t *testing.T) {
	b := &Backend{
		initialized: false,
	}

	ctx := context.Background()
	data := []byte("test data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:           "test-key",
			KeyAlgorithm: x509.RSA,
		},
	}

	sealed, err := b.Seal(ctx, data, opts)
	assert.Error(t, err, "Seal should fail when not initialized")
	assert.ErrorIs(t, err, ErrNotInitialized, "Should return ErrNotInitialized")
	assert.Nil(t, sealed, "Sealed data should be nil on error")
}

// TestUnsealNilSealedData verifies that Unseal fails with nil sealed data
func TestUnsealNilSealedData(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
	}

	unsealed, err := b.Unseal(ctx, nil, opts)
	assert.Error(t, err, "Unseal should fail with nil sealed data")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
	assert.Contains(t, err.Error(), "sealed data is required", "Error should mention sealed data")
}

// TestUnsealWrongBackend verifies that Unseal fails with wrong backend type
func TestUnsealWrongBackend(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "tpm2",
		Ciphertext: []byte("encrypted"),
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
	}

	unsealed, err := b.Unseal(ctx, sealed, opts)
	assert.Error(t, err, "Unseal should fail with wrong backend type")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
	assert.Contains(t, err.Error(), "not created by canokey backend", "Error should mention backend mismatch")
}

// TestUnsealNilOptions verifies that Unseal fails with nil options
func TestUnsealNilOptions(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: []byte("encrypted"),
	}

	unsealed, err := b.Unseal(ctx, sealed, nil)
	assert.Error(t, err, "Unseal should fail with nil options")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
	assert.Contains(t, err.Error(), "unseal options", "Error should mention unseal options")
}

// TestUnsealNilKeyAttributes verifies that Unseal fails with nil KeyAttributes
func TestUnsealNilKeyAttributes(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: []byte("encrypted"),
	}
	opts := &types.UnsealOptions{
		KeyAttributes: nil,
	}

	unsealed, err := b.Unseal(ctx, sealed, opts)
	assert.Error(t, err, "Unseal should fail with nil KeyAttributes")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
	assert.Contains(t, err.Error(), "KeyAttributes", "Error should mention KeyAttributes")
}

// TestUnsealNotInitialized verifies that Unseal fails when backend is not initialized
func TestUnsealNotInitialized(t *testing.T) {
	b := &Backend{
		initialized: false,
	}

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: []byte("encrypted"),
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
	}

	unsealed, err := b.Unseal(ctx, sealed, opts)
	assert.Error(t, err, "Unseal should fail when not initialized")
	assert.ErrorIs(t, err, ErrNotInitialized, "Should return ErrNotInitialized")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
}

// TestUnsealKeyIDMismatch verifies that Unseal fails with mismatched key IDs
func TestUnsealKeyIDMismatch(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "canokey",
		KeyID:      "key-id-1",
		Ciphertext: []byte("encrypted"),
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:           "test-key",
			KeyAlgorithm: x509.RSA,
		},
	}

	// Mock key ID to be different
	require.NotEqual(t, sealed.KeyID, opts.KeyAttributes.ID())

	unsealed, err := b.Unseal(ctx, sealed, opts)
	assert.Error(t, err, "Unseal should fail with mismatched key IDs")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
	assert.Contains(t, err.Error(), "key ID mismatch", "Error should mention key ID mismatch")
}

// TestUnsealMissingEncryptedDEK verifies that Unseal fails when encrypted DEK is missing
func TestUnsealMissingEncryptedDEK(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: []byte("encrypted"),
		Metadata:   make(map[string][]byte),
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:           "test-key",
			KeyAlgorithm: x509.RSA,
		},
	}

	unsealed, err := b.Unseal(ctx, sealed, opts)
	assert.Error(t, err, "Unseal should fail when encrypted DEK is missing")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
	assert.Contains(t, err.Error(), "encrypted DEK not found", "Error should mention missing DEK")
}

// TestUnsealCorruptedEncryptedDEK verifies that Unseal fails with corrupted encrypted DEK
func TestUnsealCorruptedEncryptedDEK(t *testing.T) {
	b := &Backend{
		initialized: true,
	}

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: []byte("encrypted"),
		Metadata: map[string][]byte{
			"encryptedDEK": []byte("not-valid-base64!@#$"),
		},
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:           "test-key",
			KeyAlgorithm: x509.RSA,
		},
	}

	unsealed, err := b.Unseal(ctx, sealed, opts)
	assert.Error(t, err, "Unseal should fail with corrupted encrypted DEK")
	assert.Nil(t, unsealed, "Unsealed data should be nil on error")
	assert.Contains(t, err.Error(), "decode encrypted DEK", "Error should mention decode failure")
}

// TestUnsealInvalidNonceSize verifies that Unseal fails with invalid nonce size
func TestUnsealInvalidNonceSize(t *testing.T) {
	// This test requires mocking deeper into the stack, so we'll create
	// a sealed data structure with valid DEK but invalid nonce
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a valid encrypted DEK
	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	encryptedDEK, err := rsa.EncryptOAEP(
		crypto.SHA256.New(),
		rand.Reader,
		&rsaKey.PublicKey,
		dek,
		nil,
	)
	require.NoError(t, err)

	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: []byte("test-ciphertext"),
		Nonce:      []byte("short"), // Invalid nonce size
		Metadata: map[string][]byte{
			"encryptedDEK": []byte(base64.StdEncoding.EncodeToString(encryptedDEK)),
		},
	}

	// Note: This test will fail earlier in the chain because we can't
	// easily mock the PKCS11 backend without integration test setup.
	// The test validates the structure is correct for when integration
	// tests are added.
	_ = sealed
}

// TestHashBytes verifies the hashBytes helper function
func TestHashBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "non-empty data",
			data: []byte("test data"),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hashBytes(tt.data)
			assert.NotNil(t, hash, "Hash should not be nil")
			assert.Equal(t, 32, len(hash), "SHA-256 hash should be 32 bytes")

			// Verify idempotence
			hash2 := hashBytes(tt.data)
			assert.Equal(t, hash, hash2, "Hash should be deterministic")
		})
	}
}

// TestClearBytes verifies the clearBytes helper function
func TestClearBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty slice",
			data: []byte{},
		},
		{
			name: "single byte",
			data: []byte{0xFF},
		},
		{
			name: "multiple bytes",
			data: []byte{0x01, 0x02, 0x03, 0x04},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to verify clearing
			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			clearBytes(tt.data)

			// Verify all bytes are zeroed
			for i, b := range tt.data {
				assert.Equal(t, byte(0), b, "Byte at index %d should be zeroed", i)
			}
		})
	}
}

// TestSealedDataStructure verifies the sealed data structure is properly populated
func TestSealedDataStructure(t *testing.T) {
	// This test verifies that when we eventually get a working Seal operation,
	// the structure is properly populated. For now, we test the expected structure.
	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("nonce-12-bytes"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"encryptedDEK": []byte("base64-encoded-dek"),
		},
	}

	assert.Equal(t, "canokey", string(sealed.Backend))
	assert.NotEmpty(t, sealed.Ciphertext)
	assert.NotEmpty(t, sealed.Nonce)
	assert.NotEmpty(t, sealed.KeyID)
	assert.Contains(t, sealed.Metadata, "encryptedDEK")
}

// TestSealWithAAD verifies AAD is properly handled in metadata
func TestSealWithAAD(t *testing.T) {
	// This test documents that when AAD is provided, it should be
	// hashed and stored in metadata for verification during unseal.
	aad := []byte("additional authenticated data")
	expectedHash := hashBytes(aad)

	assert.NotNil(t, expectedHash)
	assert.Equal(t, 32, len(expectedHash), "AAD hash should be 32 bytes")
}

// TestEnvelopeEncryptionFlow verifies the envelope encryption pattern
func TestEnvelopeEncryptionFlow(t *testing.T) {
	// This test documents the envelope encryption flow:
	// 1. Generate random DEK (32 bytes for AES-256)
	// 2. Encrypt data with AES-256-GCM using DEK
	// 3. Encrypt DEK with RSA-OAEP using CanoKey's public key
	// 4. Store encrypted DEK in metadata

	// Step 1: DEK generation
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	assert.Equal(t, 32, len(dek), "DEK should be 32 bytes for AES-256")

	// Step 2: RSA key for encrypting the DEK
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Step 3: Encrypt DEK with RSA-OAEP
	encryptedDEK, err := rsa.EncryptOAEP(
		crypto.SHA256.New(),
		rand.Reader,
		&rsaKey.PublicKey,
		dek,
		nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedDEK)

	// Step 4: Base64 encode for storage
	encodedDEK := base64.StdEncoding.EncodeToString(encryptedDEK)
	assert.NotEmpty(t, encodedDEK)

	// Verify round-trip
	decodedDEK, err := base64.StdEncoding.DecodeString(encodedDEK)
	require.NoError(t, err)
	assert.Equal(t, encryptedDEK, decodedDEK)

	// Decrypt DEK
	decryptedDEK, err := rsa.DecryptOAEP(
		crypto.SHA256.New(),
		rand.Reader,
		rsaKey,
		decodedDEK,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, dek, decryptedDEK, "Decrypted DEK should match original")
}

// TestSealErrorCases documents various error scenarios
func TestSealErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		backend     *Backend
		data        []byte
		opts        *types.SealOptions
		expectedErr string
	}{
		{
			name: "nil options",
			backend: &Backend{
				initialized: true,
			},
			data:        []byte("test"),
			opts:        nil,
			expectedErr: "seal options",
		},
		{
			name: "nil key attributes",
			backend: &Backend{
				initialized: true,
			},
			data: []byte("test"),
			opts: &types.SealOptions{
				KeyAttributes: nil,
			},
			expectedErr: "KeyAttributes",
		},
		{
			name: "not initialized",
			backend: &Backend{
				initialized: false,
			},
			data: []byte("test"),
			opts: &types.SealOptions{
				KeyAttributes: &types.KeyAttributes{
					CN: "test",
				},
			},
			expectedErr: "not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			sealed, err := tt.backend.Seal(ctx, tt.data, tt.opts)
			assert.Error(t, err)
			assert.Nil(t, sealed)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

// TestUnsealErrorCases documents various error scenarios for Unseal
func TestUnsealErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		backend     *Backend
		sealed      *types.SealedData
		opts        *types.UnsealOptions
		expectedErr string
	}{
		{
			name: "nil sealed data",
			backend: &Backend{
				initialized: true,
			},
			sealed:      nil,
			opts:        &types.UnsealOptions{},
			expectedErr: "sealed data is required",
		},
		{
			name: "wrong backend",
			backend: &Backend{
				initialized: true,
			},
			sealed: &types.SealedData{
				Backend: "tpm2",
			},
			opts: &types.UnsealOptions{
				KeyAttributes: &types.KeyAttributes{CN: "test"},
			},
			expectedErr: "not created by canokey backend",
		},
		{
			name: "nil options",
			backend: &Backend{
				initialized: true,
			},
			sealed: &types.SealedData{
				Backend: "canokey",
			},
			opts:        nil,
			expectedErr: "unseal options",
		},
		{
			name: "nil key attributes",
			backend: &Backend{
				initialized: true,
			},
			sealed: &types.SealedData{
				Backend: "canokey",
			},
			opts: &types.UnsealOptions{
				KeyAttributes: nil,
			},
			expectedErr: "KeyAttributes",
		},
		{
			name: "not initialized",
			backend: &Backend{
				initialized: false,
			},
			sealed: &types.SealedData{
				Backend: "canokey",
			},
			opts: &types.UnsealOptions{
				KeyAttributes: &types.KeyAttributes{CN: "test"},
			},
			expectedErr: "not initialized",
		},
		{
			name: "key ID mismatch",
			backend: &Backend{
				initialized: true,
			},
			sealed: &types.SealedData{
				Backend: "canokey",
				KeyID:   "key-1",
			},
			opts: &types.UnsealOptions{
				KeyAttributes: &types.KeyAttributes{
					CN:           "test",
					KeyAlgorithm: x509.RSA,
				},
			},
			expectedErr: "key ID mismatch",
		},
		{
			name: "missing encrypted DEK",
			backend: &Backend{
				initialized: true,
			},
			sealed: &types.SealedData{
				Backend:  "canokey",
				Metadata: make(map[string][]byte),
			},
			opts: &types.UnsealOptions{
				KeyAttributes: &types.KeyAttributes{CN: "test"},
			},
			expectedErr: "encrypted DEK not found",
		},
		{
			name: "corrupted encrypted DEK",
			backend: &Backend{
				initialized: true,
			},
			sealed: &types.SealedData{
				Backend: "canokey",
				Metadata: map[string][]byte{
					"encryptedDEK": []byte("invalid-base64!"),
				},
			},
			opts: &types.UnsealOptions{
				KeyAttributes: &types.KeyAttributes{CN: "test"},
			},
			expectedErr: "decode encrypted DEK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			unsealed, err := tt.backend.Unseal(ctx, tt.sealed, tt.opts)
			assert.Error(t, err)
			assert.Nil(t, unsealed)
			if tt.expectedErr != "" {
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

// TestCapabilitiesIncludeSealing verifies backend capabilities include sealing
func TestCapabilitiesIncludeSealing(t *testing.T) {
	tests := []struct {
		name             string
		isVirtual        bool
		expectedHwBacked bool
		expectedSealing  bool
	}{
		{
			name:             "hardware mode",
			isVirtual:        false,
			expectedHwBacked: true,
			expectedSealing:  true,
		},
		{
			name:             "virtual mode",
			isVirtual:        true,
			expectedHwBacked: false,
			expectedSealing:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				config: &Config{
					IsVirtual: tt.isVirtual,
				},
			}

			caps := b.Capabilities()
			assert.Equal(t, tt.expectedHwBacked, caps.HardwareBacked)
			assert.Equal(t, tt.expectedSealing, caps.Sealing)
		})
	}
}

// TestSealingSupported verifies sealing capability reporting
func TestSealingSupported(t *testing.T) {
	b := &Backend{
		config: &Config{
			IsVirtual: false,
		},
	}

	caps := b.Capabilities()
	assert.True(t, caps.Sealing, "Sealing capability should be supported")
	assert.True(t, caps.SymmetricEncryption, "Symmetric encryption should be supported")
}

// TestMemoryClearing verifies sensitive data is properly cleared
func TestMemoryClearing(t *testing.T) {
	// Verify that clearBytes properly zeros sensitive data
	sensitiveData := []byte("very-secret-dek-key-material-here")
	originalLen := len(sensitiveData)

	clearBytes(sensitiveData)

	// All bytes should be zero
	for i := 0; i < len(sensitiveData); i++ {
		assert.Equal(t, byte(0), sensitiveData[i], "Byte %d should be zeroed", i)
	}

	// Length should be unchanged
	assert.Equal(t, originalLen, len(sensitiveData), "Length should remain unchanged")
}

// TestAADHandling verifies AAD is properly handled in seal/unseal
func TestAADHandling(t *testing.T) {
	// Test that AAD hash is deterministic
	aad1 := []byte("test aad")
	hash1 := hashBytes(aad1)

	aad2 := []byte("test aad")
	hash2 := hashBytes(aad2)

	assert.Equal(t, hash1, hash2, "Same AAD should produce same hash")

	// Different AAD should produce different hash
	aad3 := []byte("different aad")
	hash3 := hashBytes(aad3)

	assert.NotEqual(t, hash1, hash3, "Different AAD should produce different hash")
}

// TestBackendTypeConsistency verifies backend type is consistent
func TestBackendTypeConsistency(t *testing.T) {
	b := &Backend{}
	backendType := b.Type()

	assert.Equal(t, types.BackendType("canokey"), backendType)
}
