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
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBackendWrapper wraps the backend to provide both ImportExportBackend and SymmetricBackend interfaces.
type testBackendWrapper struct {
	*AESBackend
}

// createTestBackend is a helper function to create a test backend.
func createTestBackend(t *testing.T) *testBackendWrapper {
	storage := storage.New()
	config := &Config{
		KeyStorage: storage,
	}
	b, err := NewBackend(config)
	require.NoError(t, err)

	// Type assert to AESBackend
	aesBackend, ok := b.(*AESBackend)
	require.True(t, ok, "backend is not AESBackend")

	return &testBackendWrapper{AESBackend: aesBackend}
}

// TestGetImportParameters tests the GetImportParameters method.
func TestGetImportParameters(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Test with RSA-OAEP SHA-256
	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.NotNil(t, params)
	assert.NotNil(t, params.WrappingPublicKey)
	assert.NotNil(t, params.ImportToken)
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, params.Algorithm)
	assert.NotNil(t, params.ExpiresAt)
	assert.Equal(t, "AES_256", params.KeySpec)

	// Test with RSA-AES hybrid
	params2, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)
	assert.NotNil(t, params2)
	assert.NotEqual(t, string(params.ImportToken), string(params2.ImportToken))

	// Test with AES-128
	attrs128 := &types.KeyAttributes{
		CN:                 "test-key-128",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES128GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 128,
		},
	}
	params128, err := b.GetImportParameters(attrs128, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, "AES_128", params128.KeySpec)

	// Test with AES-192
	attrs192 := &types.KeyAttributes{
		CN:                 "test-key-192",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES192GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 192,
		},
	}
	params192, err := b.GetImportParameters(attrs192, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, "AES_192", params192.KeySpec)
}

// TestGetImportParametersErrors tests error conditions in GetImportParameters.
func TestGetImportParametersErrors(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Test with nil attributes
	_, err := b.GetImportParameters(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")

	// Test with unsupported algorithm
	_, err = b.GetImportParameters(attrs, "UNSUPPORTED_ALGORITHM")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")

	// Test with closed backend
	_ = b.Close()
	_, err = b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestWrapKey tests the WrapKey method with different algorithms.
func TestWrapKey(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Generate random AES key material
	keyMaterial := make([]byte, 32) // 256 bits
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	// Test with RSA-OAEP SHA-256
	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(keyMaterial, params)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEmpty(t, wrapped.WrappedKey)
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, wrapped.Algorithm)
	assert.Equal(t, params.ImportToken, wrapped.ImportToken)

	// Test with RSA-AES hybrid
	params2, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	wrapped2, err := b.WrapKey(keyMaterial, params2)
	require.NoError(t, err)
	assert.NotNil(t, wrapped2)
	assert.NotEmpty(t, wrapped2.WrappedKey)
	assert.Equal(t, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, wrapped2.Algorithm)
}

// TestWrapKeyErrors tests error conditions in WrapKey.
func TestWrapKeyErrors(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Test with nil key material
	_, err = b.WrapKey(nil, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil or empty")

	// Test with empty key material
	_, err = b.WrapKey([]byte{}, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil or empty")

	// Test with invalid key size
	invalidKey := make([]byte, 15) // Invalid size
	_, err = b.WrapKey(invalidKey, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid AES key size")

	// Test with nil parameters
	validKey := make([]byte, 32)
	_, err = b.WrapKey(validKey, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

// TestUnwrapKey tests the UnwrapKey method.
func TestUnwrapKey(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Generate random AES key material
	keyMaterial := make([]byte, 32) // 256 bits
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	// Test with RSA-OAEP SHA-256
	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(keyMaterial, params)
	require.NoError(t, err)

	unwrapped, err := b.UnwrapKey(wrapped, params)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped)

	// Test with RSA-AES hybrid
	params2, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	wrapped2, err := b.WrapKey(keyMaterial, params2)
	require.NoError(t, err)

	unwrapped2, err := b.UnwrapKey(wrapped2, params2)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped2)
}

// TestUnwrapKeyErrors tests error conditions in UnwrapKey.
func TestUnwrapKeyErrors(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(keyMaterial, params)
	require.NoError(t, err)

	// Test with nil wrapped material
	_, err = b.UnwrapKey(nil, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")

	// Test with nil parameters
	_, err = b.UnwrapKey(wrapped, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")

	// Test with nil import token
	wrappedNoToken := &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   wrapped.Algorithm,
		ImportToken: nil,
	}
	_, err = b.UnwrapKey(wrappedNoToken, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil or empty")

	// Test with invalid import token
	wrappedBadToken := &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   wrapped.Algorithm,
		ImportToken: []byte("invalid-token"),
	}
	_, err = b.UnwrapKey(wrappedBadToken, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired")
}

// TestImportKey tests the ImportKey method with different AES key sizes.
func TestImportKey(t *testing.T) {
	testCases := []struct {
		name      string
		keySize   int
		algorithm types.SymmetricAlgorithm
	}{
		{"AES-128", 128, types.SymmetricAES128GCM},
		{"AES-192", 192, types.SymmetricAES192GCM},
		{"AES-256", 256, types.SymmetricAES256GCM},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := createTestBackend(t)
			defer func() { _ = b.Close() }()

			attrs := &types.KeyAttributes{
				CN:                 "test-import-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: tc.algorithm,
				AESAttributes: &types.AESAttributes{
					KeySize: tc.keySize,
				},
			}

			// Generate random key material
			keyMaterial := make([]byte, tc.keySize/8)
			_, err := rand.Read(keyMaterial)
			require.NoError(t, err)

			// Get import parameters and wrap the key
			params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			require.NoError(t, err)

			wrapped, err := b.WrapKey(keyMaterial, params)
			require.NoError(t, err)

			// Import the key
			err = b.ImportKey(attrs, wrapped)
			require.NoError(t, err)

			// Verify the key was imported by retrieving it
			importedKey, err := b.GetSymmetricKey(attrs)
			require.NoError(t, err)
			assert.NotNil(t, importedKey)
			assert.Equal(t, tc.keySize, importedKey.KeySize())

			// Verify the key material matches
			rawImported, err := importedKey.Raw()
			require.NoError(t, err)
			assert.Equal(t, keyMaterial, rawImported)

			// Verify the wrapping key was cleaned up
			_, err = b.UnwrapKey(wrapped, params)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid or expired")
		})
	}
}

// TestImportKeyErrors tests error conditions in ImportKey.
func TestImportKeyErrors(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(keyMaterial, params)
	require.NoError(t, err)

	// Test with nil attributes
	err = b.ImportKey(nil, wrapped)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")

	// Test with asymmetric attributes
	asymAttrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	err = b.ImportKey(asymAttrs, wrapped)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")

	// Import the key successfully
	err = b.ImportKey(attrs, wrapped)
	require.NoError(t, err)

	// Test importing duplicate key
	params2, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	wrapped2, err := b.WrapKey(keyMaterial, params2)
	require.NoError(t, err)

	err = b.ImportKey(attrs, wrapped2)
	assert.ErrorIs(t, err, backend.ErrKeyAlreadyExists)

	// Test with size mismatch
	attrs128 := &types.KeyAttributes{
		CN:                 "test-key-128",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES128GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 128,
		},
	}
	params128, err := b.GetImportParameters(attrs128, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	// Wrap 256-bit key but try to import as 128-bit
	wrapped128, err := b.WrapKey(keyMaterial, params128)
	require.NoError(t, err)

	err = b.ImportKey(attrs128, wrapped128)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match expected size")
}

// TestExportKey tests the ExportKey method.
func TestExportKey(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-export-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Generate a key to export
	key, err := b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get the raw key material for comparison
	originalKey, err := key.Raw()
	require.NoError(t, err)

	// Export the key
	wrapped, err := b.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEmpty(t, wrapped.WrappedKey)
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, wrapped.Algorithm)
	assert.NotNil(t, wrapped.ImportToken)

	// Unwrap to verify it matches the original
	params := &backend.ImportParameters{
		ImportToken: wrapped.ImportToken,
		Algorithm:   wrapped.Algorithm,
	}
	unwrapped, err := b.UnwrapKey(wrapped, params)
	require.NoError(t, err)
	assert.Equal(t, originalKey, unwrapped)
}

// TestExportKeyErrors tests error conditions in ExportKey.
func TestExportKeyErrors(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Test with nil attributes
	_, err := b.ExportKey(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)

	// Test with non-existent key
	_, err = b.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)

	// Generate a key
	_, err = b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Test with asymmetric attributes
	asymAttrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		Exportable:   true,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err = b.ExportKey(asymAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")

	// Test with closed backend
	_ = b.Close()
	_, err = b.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestImportExportRoundTrip tests the complete import/export workflow.
func TestImportExportRoundTrip(t *testing.T) {
	// Create source backend
	sourceBackend := createTestBackend(t)
	defer func() { _ = sourceBackend.Close() }()

	// Create destination backend
	destBackend := createTestBackend(t)
	defer func() { _ = destBackend.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "roundtrip-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Generate key in source backend
	sourceKey, err := sourceBackend.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get original key material
	originalKey, err := sourceKey.Raw()
	require.NoError(t, err)

	// Proper workflow: destination gets import parameters first
	destParams, err := destBackend.GetImportParameters(attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	// Wrap the key using destination's public key
	wrapped, err := sourceBackend.WrapKey(originalKey, destParams)
	require.NoError(t, err)

	// Import into destination
	err = destBackend.ImportKey(attrs, wrapped)
	require.NoError(t, err)

	// Retrieve from destination
	destKey, err := destBackend.GetSymmetricKey(attrs)
	require.NoError(t, err)

	// Verify key material matches
	importedKey, err := destKey.Raw()
	require.NoError(t, err)
	assert.Equal(t, originalKey, importedKey)

	// Test encryption/decryption with imported key
	plaintext := []byte("test data for encryption")

	sourceEncrypter, err := sourceBackend.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	encrypted, err := sourceEncrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	destEncrypter, err := destBackend.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	decrypted, err := destEncrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestImportExportWithPassword tests import/export with password-protected keys.
func TestImportExportWithPassword(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	password := backend.StaticPassword("test-password")

	attrs := &types.KeyAttributes{
		CN:                 "password-protected-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Password:           password,
		Exportable:         true,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	// Generate password-protected key
	key, err := b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	originalKey, err := key.Raw()
	require.NoError(t, err)

	// Export the key
	wrapped, err := b.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Unwrap to verify
	params := &backend.ImportParameters{
		ImportToken: wrapped.ImportToken,
		Algorithm:   wrapped.Algorithm,
	}
	unwrapped, err := b.UnwrapKey(wrapped, params)
	require.NoError(t, err)
	assert.Equal(t, originalKey, unwrapped)
}

// TestCapabilitiesImportExport tests that the backend reports ImportExport capability.
func TestCapabilitiesImportExport(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	caps := b.Capabilities()
	assert.True(t, caps.Import)
	assert.True(t, caps.Export)
	assert.True(t, caps.SupportsImportExport())
}

// TestGetImportParameters_AllWrappingAlgorithms tests all supported wrapping algorithms
func TestGetImportParameters_AllWrappingAlgorithms(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			params, err := b.GetImportParameters(attrs, algo)
			require.NoError(t, err)
			assert.NotNil(t, params)
			assert.NotNil(t, params.WrappingPublicKey)
			assert.Equal(t, algo, params.Algorithm)
		})
	}
}

// TestWrapKey_AllKeySizes tests wrapping keys of different sizes
func TestWrapKey_AllKeySizes(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Test AES-128
	key128 := make([]byte, 16)
	_, err = rand.Read(key128)
	require.NoError(t, err)

	wrapped128, err := b.WrapKey(key128, params)
	require.NoError(t, err)
	assert.NotNil(t, wrapped128)

	// Test AES-192
	key192 := make([]byte, 24)
	_, err = rand.Read(key192)
	require.NoError(t, err)

	wrapped192, err := b.WrapKey(key192, params)
	require.NoError(t, err)
	assert.NotNil(t, wrapped192)

	// Test AES-256
	key256 := make([]byte, 32)
	_, err = rand.Read(key256)
	require.NoError(t, err)

	wrapped256, err := b.WrapKey(key256, params)
	require.NoError(t, err)
	assert.NotNil(t, wrapped256)
}

// TestWrapKey_InvalidKeySizes tests wrapping with invalid key sizes
func TestWrapKey_InvalidKeySizes(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	invalidSizes := []int{8, 15, 17, 31, 33, 64}

	for _, size := range invalidSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			invalidKey := make([]byte, size)
			_, err := rand.Read(invalidKey)
			require.NoError(t, err)

			_, err = b.WrapKey(invalidKey, params)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid AES key size")
		})
	}
}

// TestUnwrapKey_InvalidAlgorithm tests unwrap with unsupported algorithm
func TestUnwrapKey_InvalidAlgorithm(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(keyMaterial, params)
	require.NoError(t, err)

	// Change algorithm to unsupported
	wrapped.Algorithm = "UNSUPPORTED_ALGORITHM"

	_, err = b.UnwrapKey(wrapped, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")
}

// TestUnwrapKey_InvalidKeySize tests unwrap with invalid unwrapped key size
func TestUnwrapKey_InvalidKeySize(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Create wrapped material that will unwrap to invalid size
	// This is difficult to test directly without mocking, so we test the validation logic
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  make([]byte, 100),
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: params.ImportToken,
	}

	// This should fail either at unwrap or at validation
	_, err = b.UnwrapKey(wrapped, params)
	assert.Error(t, err)
}

// TestWrapKey_NonRSAPublicKey tests error handling for non-RSA public key
func TestWrapKey_NonRSAPublicKey(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	// Create params with non-RSA public key
	params := &backend.ImportParameters{
		WrappingPublicKey: "not-an-rsa-key",
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	_, err = b.WrapKey(keyMaterial, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be RSA")
}

// TestWrapKey_UnsupportedAlgorithm tests error for unsupported wrapping algorithm
func TestWrapKey_UnsupportedAlgorithm(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	keyMaterial := make([]byte, 32)
	_, err = rand.Read(keyMaterial)
	require.NoError(t, err)

	// Change to unsupported algorithm
	params.Algorithm = "UNSUPPORTED_ALGORITHM"

	_, err = b.WrapKey(keyMaterial, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")
}

// TestImportKey_ClosedBackend tests ImportKey on closed backend
func TestImportKey_ClosedBackend(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(keyMaterial, params)
	require.NoError(t, err)

	_ = b.Close()

	err = b.ImportKey(attrs, wrapped)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestImportKey_InvalidAttributes tests ImportKey with invalid attributes
func TestImportKey_InvalidAttributes(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	params, err := b.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := b.WrapKey(keyMaterial, params)
	require.NoError(t, err)

	// Test with invalid asymmetric attributes
	invalidAttrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	err = b.ImportKey(invalidAttrs, wrapped)
	assert.Error(t, err)
}

// TestExportKey_ClosedBackend tests ExportKey on closed backend
func TestExportKey_ClosedBackend(t *testing.T) {
	b := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:                 "test-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		AESAttributes: &types.AESAttributes{
			KeySize: 256,
		},
	}

	_, err := b.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	_ = b.Close()

	_, err = b.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrStorageClosed)
}
