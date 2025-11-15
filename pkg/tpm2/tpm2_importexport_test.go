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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTPM2_GetImportParameters tests the GetImportParameters method
func TestTPM2_GetImportParameters(t *testing.T) {
	ks, cleanup := setupTPM2KeyStore(t)
	defer cleanup()

	attrs := &types.KeyAttributes{
		CN:           "test-import-key",
		StoreType:    backend.STORE_TPM2,
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Test with supported algorithm
	t.Run("RSA_OAEP_SHA256", func(t *testing.T) {
		params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		require.NoError(t, err, "GetImportParameters should succeed")
		assert.NotNil(t, params, "Import parameters should not be nil")
		assert.NotNil(t, params.WrappingPublicKey, "Wrapping public key should not be nil")
		assert.NotNil(t, params.ImportToken, "Import token should not be nil")
		assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, params.Algorithm)
		assert.NotNil(t, params.ExpiresAt, "Expiration time should be set")
		assert.Equal(t, "RSA_2048", params.KeySpec, "Key spec should match")

		// Verify the wrapping public key is RSA
		rsaPub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
		assert.True(t, ok, "Wrapping public key should be RSA")
		assert.NotNil(t, rsaPub, "RSA public key should not be nil")
		assert.Equal(t, 2048, rsaPub.N.BitLen(), "RSA key should be 2048 bits")
	})

	// Test with hybrid algorithm
	t.Run("RSA_AES_KEY_WRAP_SHA256", func(t *testing.T) {
		params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err, "GetImportParameters should succeed")
		assert.NotNil(t, params, "Import parameters should not be nil")
		assert.Equal(t, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, params.Algorithm)
	})

	// Test with unsupported algorithm
	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_1)
		assert.Error(t, err, "Should error on unsupported algorithm")
		assert.Nil(t, params, "Parameters should be nil on error")
		assert.Contains(t, err.Error(), "unsupported wrapping algorithm")
	})

	// Test with nil attributes
	t.Run("NilAttributes", func(t *testing.T) {
		params, err := ks.GetImportParameters(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "Should error on nil attributes")
		assert.Nil(t, params, "Parameters should be nil on error")
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})
}

// TestTPM2_WrapKey tests the WrapKey method
func TestTPM2_WrapKey(t *testing.T) {
	ks, cleanup := setupTPM2KeyStore(t)
	defer cleanup()

	attrs := &types.KeyAttributes{
		CN:           "test-wrap-key",
		StoreType:    backend.STORE_TPM2,
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Get import parameters
	params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err, "GetImportParameters should succeed")

	// Create some test key material (32 bytes for AES-256)
	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err, "Should generate random key material")

	// Test wrapping with RSA-OAEP
	t.Run("WrapWithRSAOAEP", func(t *testing.T) {
		wrapped, err := ks.WrapKey(keyMaterial, params)
		require.NoError(t, err, "WrapKey should succeed")
		assert.NotNil(t, wrapped, "Wrapped key material should not be nil")
		assert.NotEmpty(t, wrapped.WrappedKey, "Wrapped key should not be empty")
		assert.Equal(t, params.Algorithm, wrapped.Algorithm)
		assert.Equal(t, params.ImportToken, wrapped.ImportToken)
		assert.NotNil(t, wrapped.Metadata, "Metadata should be initialized")

		// Wrapped key should be larger than plaintext (due to RSA encryption overhead)
		assert.Greater(t, len(wrapped.WrappedKey), len(keyMaterial))
	})

	// Test wrapping with hybrid algorithm (for larger keys)
	t.Run("WrapWithRSAAES", func(t *testing.T) {
		// Get parameters with hybrid algorithm
		hybridParams, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		require.NoError(t, err, "GetImportParameters should succeed")

		// Create larger key material (RSA private key would be ~1200 bytes)
		largeKeyMaterial := make([]byte, 1200)
		_, err = rand.Read(largeKeyMaterial)
		require.NoError(t, err, "Should generate random key material")

		wrapped, err := ks.WrapKey(largeKeyMaterial, hybridParams)
		require.NoError(t, err, "WrapKey should succeed with hybrid algorithm")
		assert.NotNil(t, wrapped, "Wrapped key material should not be nil")
		assert.NotEmpty(t, wrapped.WrappedKey, "Wrapped key should not be empty")
	})

	// Test with nil key material
	t.Run("NilKeyMaterial", func(t *testing.T) {
		wrapped, err := ks.WrapKey(nil, params)
		assert.Error(t, err, "Should error on nil key material")
		assert.Nil(t, wrapped, "Wrapped key should be nil on error")
		assert.Contains(t, err.Error(), "cannot be nil or empty")
	})

	// Test with empty key material
	t.Run("EmptyKeyMaterial", func(t *testing.T) {
		wrapped, err := ks.WrapKey([]byte{}, params)
		assert.Error(t, err, "Should error on empty key material")
		assert.Nil(t, wrapped, "Wrapped key should be nil on error")
	})

	// Test with nil parameters
	t.Run("NilParameters", func(t *testing.T) {
		wrapped, err := ks.WrapKey(keyMaterial, nil)
		assert.Error(t, err, "Should error on nil parameters")
		assert.Nil(t, wrapped, "Wrapped key should be nil on error")
	})
}

// TestTPM2_UnwrapKey tests that UnwrapKey returns ErrNotSupported
func TestTPM2_UnwrapKey(t *testing.T) {
	ks, cleanup := setupTPM2KeyStore(t)
	defer cleanup()

	attrs := &types.KeyAttributes{
		CN:           "test-unwrap-key",
		StoreType:    backend.STORE_TPM2,
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Get import parameters and wrap some key material
	params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err, "GetImportParameters should succeed")

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err, "Should generate random key material")

	wrapped, err := ks.WrapKey(keyMaterial, params)
	require.NoError(t, err, "WrapKey should succeed")

	// Test that UnwrapKey returns ErrNotSupported
	t.Run("ReturnsErrNotSupported", func(t *testing.T) {
		unwrapped, err := ks.UnwrapKey(wrapped, params)
		assert.Error(t, err, "UnwrapKey should return error")
		assert.Nil(t, unwrapped, "Unwrapped key should be nil")
		assert.ErrorIs(t, err, backend.ErrNotSupported)
		assert.Contains(t, err.Error(), "TPM2 unwraps keys in hardware")
	})
}

// TestTPM2_ImportKey tests the ImportKey method
func TestTPM2_ImportKey(t *testing.T) {
	ks, cleanup := setupTPM2KeyStore(t)
	defer cleanup()

	attrs := &types.KeyAttributes{
		CN:           "test-import-key-full",
		StoreType:    backend.STORE_TPM2,
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Get import parameters and wrap some key material
	params, err := ks.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err, "GetImportParameters should succeed")

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err, "Should generate random key material")

	wrapped, err := ks.WrapKey(keyMaterial, params)
	require.NoError(t, err, "WrapKey should succeed")

	// Test ImportKey
	t.Run("ImportNotFullyImplemented", func(t *testing.T) {
		err := ks.ImportKey(attrs, wrapped)
		// Currently returns "not yet fully implemented" error
		assert.Error(t, err, "ImportKey should return error (not fully implemented)")
		assert.Contains(t, err.Error(), "not yet fully implemented")
	})

	// Test with nil attributes
	t.Run("NilAttributes", func(t *testing.T) {
		err := ks.ImportKey(nil, wrapped)
		assert.Error(t, err, "Should error on nil attributes")
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	// Test with nil wrapped material
	t.Run("NilWrappedMaterial", func(t *testing.T) {
		err := ks.ImportKey(attrs, nil)
		assert.Error(t, err, "Should error on nil wrapped material")
		assert.Contains(t, err.Error(), "cannot be nil")
	})
}

// TestTPM2_ExportKey tests the ExportKey method
func TestTPM2_ExportKey(t *testing.T) {
	ks, cleanup := setupTPM2KeyStore(t)
	defer cleanup()

	// Generate a regular TPM key (with FixedTPM=true)
	attrs := &types.KeyAttributes{
		CN:           "test-export-key",
		StoreType:    backend.STORE_TPM2,
		KeyType:      backend.KEY_TYPE_TLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err := ks.GenerateKey(attrs)
	require.NoError(t, err, "Key generation should succeed")

	// Test export of FixedTPM key (should fail)
	t.Run("ExportFixedTPMKey", func(t *testing.T) {
		wrapped, err := ks.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "ExportKey should fail for FixedTPM keys")
		assert.Nil(t, wrapped, "Wrapped key should be nil")
		assert.ErrorIs(t, err, keychain.ErrOperationNotSupported)
		assert.Contains(t, err.Error(), "FixedTPM")
	})

	// Test with non-existent key
	t.Run("NonExistentKey", func(t *testing.T) {
		nonExistentAttrs := &types.KeyAttributes{
			CN:           "non-existent-key",
			StoreType:    backend.STORE_TPM2,
			KeyType:      backend.KEY_TYPE_TLS,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		wrapped, err := ks.ExportKey(nonExistentAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "ExportKey should fail for non-existent key")
		assert.Nil(t, wrapped, "Wrapped key should be nil")
		assert.ErrorIs(t, err, backend.ErrKeyNotFound)
	})

	// Test with nil attributes
	t.Run("NilAttributes", func(t *testing.T) {
		wrapped, err := ks.ExportKey(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
		assert.Error(t, err, "Should error on nil attributes")
		assert.Nil(t, wrapped, "Wrapped key should be nil")
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})
}

// TestTPM2_ImportExportCapability tests that the backend reports ImportExport capability
func TestTPM2_ImportExportCapability(t *testing.T) {
	ks, cleanup := setupTPM2KeyStore(t)
	defer cleanup()

	caps := ks.Capabilities()
	assert.True(t, caps.Import, "TPM2 should support import")
	assert.True(t, caps.Export, "TPM2 should support export")
	assert.True(t, caps.SupportsImportExport(), "SupportsImportExport() should return true")
}

// TestTPM2_ImportExportInterfaceCompliance tests that TPM2KeyStore implements ImportExportBackend
func TestTPM2_ImportExportInterfaceCompliance(t *testing.T) {
	ks, cleanup := setupTPM2KeyStore(t)
	defer cleanup()

	// Verify that TPM2KeyStore implements ImportExportBackend
	var _ backend.ImportExportBackend = ks
	t.Log("✓ TPM2KeyStore correctly implements ImportExportBackend interface")
}

// TestTPM2_DetermineKeySpec tests the determineKeySpec helper function
func TestTPM2_DetermineKeySpec(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		expected string
	}{
		{
			name: "RSA_2048",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			expected: "RSA_2048",
		},
		{
			name: "RSA_4096",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			},
			expected: "RSA_4096",
		},
		{
			name: "ECDSA_P256",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expected: "EC_P-256",
		},
		{
			name: "AES_128",
			attrs: &types.KeyAttributes{
				SymmetricAlgorithm: types.SymmetricAES128GCM,
			},
			expected: "AES_128",
		},
		{
			name: "AES_256",
			attrs: &types.KeyAttributes{
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			expected: "AES_256",
		},
		{
			name: "Unknown",
			attrs: &types.KeyAttributes{
				SymmetricAlgorithm: "UNKNOWN",
			},
			expected: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineKeySpec(tt.attrs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// setupTPM2KeyStore creates a test TPM2 keystore with embedded simulator
func setupTPM2KeyStore(t *testing.T) (*TPM2KeyStore, func()) {
	t.Helper()

	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create file-based storage
	keyStorage, err := file.New(tempDir)
	require.NoError(t, err, "Failed to create key storage")

	certStorage, err := file.New(tempDir)
	require.NoError(t, err, "Failed to create certificate storage")

	// Configure TPM2 with embedded simulator
	config := &Config{
		CN:            "test-tpm2",
		DevicePath:    "/dev/tpmrm0",
		UseSimulator:  true,
		SimulatorType: "embedded", // Use embedded simulator for tests
		SRKHandle:     0x81000001,
	}

	// Create TPM2 keystore
	ks, err := NewTPM2KeyStore(config, nil, keyStorage, certStorage, nil)
	require.NoError(t, err, "Failed to create TPM2 keystore")

	// Initialize the keystore
	err = ks.Initialize(nil, nil)
	if err != nil && !errors.Is(err, keychain.ErrAlreadyInitialized) {
		t.Fatalf("Failed to initialize TPM2 keystore: %v", err)
	}

	cleanup := func() {
		if ks != nil {
			ks.Close()
		}
	}

	return ks, cleanup
}
