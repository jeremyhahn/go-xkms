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

//go:build yubikey && pkcs11

package yubikey

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackend_CanSeal tests the CanSeal method
func TestBackend_CanSeal(t *testing.T) {
	tests := []struct {
		name        string
		initialized bool
		expected    bool
	}{
		{
			name:        "Initialized backend can seal",
			initialized: true,
			expected:    true,
		},
		{
			name:        "Uninitialized backend cannot seal",
			initialized: false,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, ok := getTestConfig(t)
			if !ok {
				t.Skip("YubiKey not available")
			}

			backend, err := NewBackend(config)
			require.NoError(t, err)
			defer func() { _ = backend.Close() }()

			if tt.initialized {
				err = backend.Initialize()
				require.NoError(t, err)
			}

			canSeal := backend.CanSeal()
			assert.Equal(t, tt.expected, canSeal)
		})
	}
}

// TestBackend_Seal_ValidData tests sealing with valid data and options
func TestBackend_Seal_ValidData(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Generate an RSA key for sealing
	attrs := &types.KeyAttributes{
		CN:           "auth-seal-test-rsa",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = backend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}
	defer backend.DeleteKey(attrs)

	tests := []struct {
		name    string
		data    []byte
		aad     []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Seal small data",
			data:    []byte("test secret data"),
			aad:     nil,
			wantErr: false,
		},
		{
			name:    "Seal data with AAD",
			data:    []byte("authenticated encryption test"),
			aad:     []byte("additional authenticated data"),
			wantErr: false,
		},
		{
			name:    "Seal empty data",
			data:    []byte(""),
			aad:     nil,
			wantErr: false,
		},
		{
			name:    "Seal large data",
			data:    make([]byte, 1024*10), // 10KB
			aad:     nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			opts := &types.SealOptions{
				KeyAttributes: attrs,
				AAD:           tt.aad,
			}

			sealed, err := backend.Seal(ctx, tt.data, opts)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, sealed)

				// Verify sealed data structure
				assert.Equal(t, "yubikey", sealed.Backend)
				assert.NotEmpty(t, sealed.Ciphertext)
				assert.NotEmpty(t, sealed.Nonce)
				assert.Equal(t, attrs.ID(), sealed.KeyID)
				assert.NotNil(t, sealed.Metadata)
				assert.NotEmpty(t, sealed.Metadata["encryptedDEK"])

				// Verify encrypted DEK is base64 encoded
				_, err := base64.StdEncoding.DecodeString(string(sealed.Metadata["encryptedDEK"]))
				assert.NoError(t, err, "encryptedDEK should be valid base64")

				// If AAD was provided, verify it's hashed in metadata
				if tt.aad != nil {
					assert.NotEmpty(t, sealed.Metadata["yubikey:aad_hash"])
				}
			}
		})
	}
}

// TestBackend_Seal_InvalidOptions tests sealing with invalid/nil options
func TestBackend_Seal_InvalidOptions(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("test data")

	tests := []struct {
		name   string
		opts   *types.SealOptions
		errMsg string
	}{
		{
			name:   "Nil options",
			opts:   nil,
			errMsg: "seal options with KeyAttributes required",
		},
		{
			name: "Nil KeyAttributes",
			opts: &types.SealOptions{
				KeyAttributes: nil,
			},
			errMsg: "seal options with KeyAttributes required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := backend.Seal(ctx, data, tt.opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestBackend_Seal_NotInitialized tests sealing when backend is not initialized
func TestBackend_Seal_NotInitialized(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("test data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
	}

	_, err = backend.Seal(ctx, data, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend not initialized")
}

// TestBackend_Seal_NonRSAKey tests sealing with a non-RSA key
func TestBackend_Seal_NonRSAKey(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Try to use attributes for an ECDSA key (not supported for sealing)
	attrs := &types.KeyAttributes{
		CN:           "sig-seal-test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
	}

	ctx := context.Background()
	data := []byte("test data")
	opts := &types.SealOptions{
		KeyAttributes: attrs,
	}

	_, err = backend.Seal(ctx, data, opts)
	require.Error(t, err)
	// Error message will vary depending on whether key exists and its type
}

// TestBackend_Unseal_ValidData tests unsealing with valid sealed data
func TestBackend_Unseal_ValidData(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Generate an RSA key for sealing/unsealing
	attrs := &types.KeyAttributes{
		CN:           "auth-unseal-test-rsa",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = backend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}
	defer backend.DeleteKey(attrs)

	tests := []struct {
		name string
		data []byte
		aad  []byte
	}{
		{
			name: "Unseal small data",
			data: []byte("test secret data"),
			aad:  nil,
		},
		{
			name: "Unseal data with AAD",
			data: []byte("authenticated encryption test"),
			aad:  []byte("additional authenticated data"),
		},
		{
			name: "Unseal empty data",
			data: []byte(""),
			aad:  nil,
		},
		{
			name: "Unseal large data",
			data: make([]byte, 1024*10), // 10KB
			aad:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Seal the data
			sealOpts := &types.SealOptions{
				KeyAttributes: attrs,
				AAD:           tt.aad,
			}

			sealed, err := backend.Seal(ctx, tt.data, sealOpts)
			require.NoError(t, err)
			require.NotNil(t, sealed)

			// Unseal the data
			unsealOpts := &types.UnsealOptions{
				KeyAttributes: attrs,
				AAD:           tt.aad,
			}

			unsealed, err := backend.Unseal(ctx, sealed, unsealOpts)
			require.NoError(t, err)
			assert.Equal(t, tt.data, unsealed)
		})
	}
}

// TestBackend_Unseal_InvalidData tests unsealing with invalid/corrupted data
func TestBackend_Unseal_InvalidData(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Generate an RSA key
	attrs := &types.KeyAttributes{
		CN:           "auth-unseal-invalid-test",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = backend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}
	defer backend.DeleteKey(attrs)

	ctx := context.Background()
	data := []byte("test secret data")

	// First, create valid sealed data
	sealOpts := &types.SealOptions{
		KeyAttributes: attrs,
	}

	sealed, err := backend.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	tests := []struct {
		name         string
		modifySealed func(*types.SealedData)
		opts         *types.UnsealOptions
		errMsg       string
	}{
		{
			name: "Nil sealed data",
			modifySealed: func(s *types.SealedData) {
				// Will pass nil in test
			},
			opts: &types.UnsealOptions{
				KeyAttributes: attrs,
			},
			errMsg: "sealed data is required",
		},
		{
			name: "Wrong backend",
			modifySealed: func(s *types.SealedData) {
				s.Backend = "tpm2"
			},
			opts: &types.UnsealOptions{
				KeyAttributes: attrs,
			},
			errMsg: "sealed data was not created by yubikey backend",
		},
		{
			name: "Corrupted ciphertext",
			modifySealed: func(s *types.SealedData) {
				s.Ciphertext[0] ^= 0xFF
			},
			opts: &types.UnsealOptions{
				KeyAttributes: attrs,
			},
			errMsg: "failed to decrypt",
		},
		{
			name: "Corrupted nonce",
			modifySealed: func(s *types.SealedData) {
				s.Nonce = []byte{0x00}
			},
			opts: &types.UnsealOptions{
				KeyAttributes: attrs,
			},
			errMsg: "invalid nonce size",
		},
		{
			name: "Missing encrypted DEK",
			modifySealed: func(s *types.SealedData) {
				delete(s.Metadata, "encryptedDEK")
			},
			opts: &types.UnsealOptions{
				KeyAttributes: attrs,
			},
			errMsg: "encrypted DEK not found",
		},
		{
			name: "Invalid base64 encrypted DEK",
			modifySealed: func(s *types.SealedData) {
				s.Metadata["encryptedDEK"] = []byte("invalid!!!base64")
			},
			opts: &types.UnsealOptions{
				KeyAttributes: attrs,
			},
			errMsg: "failed to decode encrypted DEK",
		},
		{
			name: "Corrupted encrypted DEK",
			modifySealed: func(s *types.SealedData) {
				// Decode, corrupt, re-encode
				dekBytes, _ := base64.StdEncoding.DecodeString(string(s.Metadata["encryptedDEK"]))
				dekBytes[0] ^= 0xFF
				s.Metadata["encryptedDEK"] = []byte(base64.StdEncoding.EncodeToString(dekBytes))
			},
			opts: &types.UnsealOptions{
				KeyAttributes: attrs,
			},
			errMsg: "failed to decrypt DEK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh copy of sealed data for each test
			testSealed := &types.SealedData{
				Backend:    sealed.Backend,
				Ciphertext: make([]byte, len(sealed.Ciphertext)),
				Nonce:      make([]byte, len(sealed.Nonce)),
				KeyID:      sealed.KeyID,
				Metadata:   make(map[string][]byte),
			}
			copy(testSealed.Ciphertext, sealed.Ciphertext)
			copy(testSealed.Nonce, sealed.Nonce)
			for k, v := range sealed.Metadata {
				testSealed.Metadata[k] = make([]byte, len(v))
				copy(testSealed.Metadata[k], v)
			}

			// Apply modification
			tt.modifySealed(testSealed)

			// Attempt to unseal
			var unsealed []byte
			var err error
			if tt.name == "Nil sealed data" {
				unsealed, err = backend.Unseal(ctx, nil, tt.opts)
			} else {
				unsealed, err = backend.Unseal(ctx, testSealed, tt.opts)
			}

			require.Error(t, err)
			assert.Nil(t, unsealed)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestBackend_Unseal_WrongKeyID tests unsealing with wrong key ID
func TestBackend_Unseal_WrongKeyID(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Generate an RSA key for sealing
	attrs1 := &types.KeyAttributes{
		CN:           "auth-key1",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = backend.GenerateRSA(attrs1)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}
	defer backend.DeleteKey(attrs1)

	ctx := context.Background()
	data := []byte("test secret data")

	// Seal with first key
	sealOpts := &types.SealOptions{
		KeyAttributes: attrs1,
	}

	sealed, err := backend.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	// Try to unseal with different key ID
	attrs2 := &types.KeyAttributes{
		CN:           "sig-key2",
		KeyAlgorithm: x509.RSA,
	}

	unsealOpts := &types.UnsealOptions{
		KeyAttributes: attrs2,
	}

	_, err = backend.Unseal(ctx, sealed, unsealOpts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key ID mismatch")
}

// TestBackend_Unseal_WrongAAD tests unsealing with wrong AAD
func TestBackend_Unseal_WrongAAD(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Generate an RSA key
	attrs := &types.KeyAttributes{
		CN:           "auth-aad-test",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = backend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}
	defer backend.DeleteKey(attrs)

	ctx := context.Background()
	data := []byte("test secret data")
	aad := []byte("correct AAD")

	// Seal with AAD
	sealOpts := &types.SealOptions{
		KeyAttributes: attrs,
		AAD:           aad,
	}

	sealed, err := backend.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	tests := []struct {
		name   string
		aad    []byte
		errMsg string
	}{
		{
			name:   "Wrong AAD",
			aad:    []byte("wrong AAD"),
			errMsg: "failed to decrypt",
		},
		{
			name:   "Missing AAD",
			aad:    nil,
			errMsg: "failed to decrypt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsealOpts := &types.UnsealOptions{
				KeyAttributes: attrs,
				AAD:           tt.aad,
			}

			_, err := backend.Unseal(ctx, sealed, unsealOpts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestBackend_Unseal_InvalidOptions tests unsealing with invalid/nil options
func TestBackend_Unseal_InvalidOptions(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "yubikey",
		Ciphertext: []byte("fake ciphertext"),
		Nonce:      []byte("fake nonce"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"encryptedDEK": []byte(base64.StdEncoding.EncodeToString([]byte("fake dek"))),
		},
	}

	tests := []struct {
		name   string
		opts   *types.UnsealOptions
		errMsg string
	}{
		{
			name:   "Nil options",
			opts:   nil,
			errMsg: "unseal options with KeyAttributes required",
		},
		{
			name: "Nil KeyAttributes",
			opts: &types.UnsealOptions{
				KeyAttributes: nil,
			},
			errMsg: "unseal options with KeyAttributes required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := backend.Unseal(ctx, sealed, tt.opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestBackend_Unseal_NotInitialized tests unsealing when backend is not initialized
func TestBackend_Unseal_NotInitialized(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    "yubikey",
		Ciphertext: []byte("fake ciphertext"),
		Nonce:      []byte("fake nonce"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"encryptedDEK": []byte(base64.StdEncoding.EncodeToString([]byte("fake dek"))),
		},
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
	}

	_, err = backend.Unseal(ctx, sealed, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend not initialized")
}

// TestBackend_SealUnseal_RoundTrip tests complete seal/unseal round trip
func TestBackend_SealUnseal_RoundTrip(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Generate an RSA key
	attrs := &types.KeyAttributes{
		CN:           "auth-roundtrip-test",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	key, err := backend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}
	require.NotNil(t, key)
	defer backend.DeleteKey(attrs)

	// Verify it's an RSA key
	rsaPub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok, "Expected RSA public key")
	assert.NotNil(t, rsaPub)

	ctx := context.Background()

	testData := [][]byte{
		[]byte("simple test"),
		[]byte(""),
		[]byte("longer test data with multiple words and special characters: !@#$%^&*()"),
		make([]byte, 1024), // 1KB of zeros
	}

	for i, data := range testData {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			// Seal
			sealOpts := &types.SealOptions{
				KeyAttributes: attrs,
			}
			sealed, err := backend.Seal(ctx, data, sealOpts)
			require.NoError(t, err)
			require.NotNil(t, sealed)

			// Unseal
			unsealOpts := &types.UnsealOptions{
				KeyAttributes: attrs,
			}
			unsealed, err := backend.Unseal(ctx, sealed, unsealOpts)
			require.NoError(t, err)
			assert.Equal(t, data, unsealed)
		})
	}
}

// TestBackend_SealingSupported tests the SealingSupported capability
func TestBackend_SealingSupported(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Check capabilities
	caps := backend.Capabilities()
	assert.True(t, caps.Sealing, "YubiKey should support sealing")

	// Check CanSeal
	canSeal := backend.CanSeal()
	assert.True(t, canSeal, "YubiKey should support sealing when initialized")
}

// TestBackend_Seal_DEKSecurity tests that DEK is properly secured
func TestBackend_Seal_DEKSecurity(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	err = backend.Initialize()
	require.NoError(t, err)

	// Generate an RSA key
	attrs := &types.KeyAttributes{
		CN:           "auth-dek-security-test",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = backend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}
	defer backend.DeleteKey(attrs)

	ctx := context.Background()
	data := []byte("sensitive data")

	// Seal the same data multiple times
	sealOpts := &types.SealOptions{
		KeyAttributes: attrs,
	}

	sealed1, err := backend.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	sealed2, err := backend.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	// Verify that different DEKs and nonces are generated each time
	assert.NotEqual(t, sealed1.Nonce, sealed2.Nonce, "Nonces should be different")
	assert.NotEqual(t, sealed1.Ciphertext, sealed2.Ciphertext, "Ciphertexts should be different")
	assert.NotEqual(t, sealed1.Metadata["encryptedDEK"], sealed2.Metadata["encryptedDEK"], "Encrypted DEKs should be different")

	// Both should unseal to the same data
	unsealOpts := &types.UnsealOptions{
		KeyAttributes: attrs,
	}

	unsealed1, err := backend.Unseal(ctx, sealed1, unsealOpts)
	require.NoError(t, err)
	assert.Equal(t, data, unsealed1)

	unsealed2, err := backend.Unseal(ctx, sealed2, unsealOpts)
	require.NoError(t, err)
	assert.Equal(t, data, unsealed2)
}
