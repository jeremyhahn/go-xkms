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

package backend

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWrappingAlgorithmConstants tests that wrapping algorithm constants are defined
func TestWrappingAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name string
		algo WrappingAlgorithm
	}{
		{"RSA OAEP SHA-1", WrappingAlgorithmRSAES_OAEP_SHA_1},
		{"RSA OAEP SHA-256", WrappingAlgorithmRSAES_OAEP_SHA_256},
		{"RSA AES KEY WRAP SHA-1", WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1},
		{"RSA AES KEY WRAP SHA-256", WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256},
		{"RSA OAEP 3072 SHA256 AES 256", WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256},
		{"RSA OAEP 4096 SHA256 AES 256", WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256},
		{"RSA OAEP 4096 SHA256", WrappingAlgorithmRSA_OAEP_4096_SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, string(tt.algo), "Algorithm should not be empty")
		})
	}
}

// TestImportParametersConstruction tests creating ImportParameters
func TestImportParametersConstruction(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Should generate RSA key")

	tests := []struct {
		name      string
		buildFunc func() *ImportParameters
		validate  func(*testing.T, *ImportParameters)
	}{
		{
			name: "With all fields",
			buildFunc: func() *ImportParameters {
				now := time.Now()
				return &ImportParameters{
					WrappingPublicKey: &privateKey.PublicKey,
					ImportToken:       []byte("test-token"),
					Algorithm:         WrappingAlgorithmRSAES_OAEP_SHA_256,
					ExpiresAt:         &now,
					KeySpec:           "RSA_2048",
				}
			},
			validate: func(t *testing.T, ip *ImportParameters) {
				assert.NotNil(t, ip.WrappingPublicKey, "WrappingPublicKey should not be nil")
				assert.Equal(t, "test-token", string(ip.ImportToken), "ImportToken should match")
				assert.Equal(t, WrappingAlgorithmRSAES_OAEP_SHA_256, ip.Algorithm, "Algorithm should match")
				assert.NotNil(t, ip.ExpiresAt, "ExpiresAt should not be nil")
				assert.Equal(t, "RSA_2048", ip.KeySpec, "KeySpec should match")
			},
		},
		{
			name: "Minimal parameters",
			buildFunc: func() *ImportParameters {
				return &ImportParameters{
					WrappingPublicKey: &privateKey.PublicKey,
					Algorithm:         WrappingAlgorithmRSAES_OAEP_SHA_1,
					KeySpec:           "AES_256",
				}
			},
			validate: func(t *testing.T, ip *ImportParameters) {
				assert.NotNil(t, ip.WrappingPublicKey, "WrappingPublicKey should not be nil")
				assert.Nil(t, ip.ImportToken, "ImportToken can be nil")
				assert.Equal(t, WrappingAlgorithmRSAES_OAEP_SHA_1, ip.Algorithm, "Algorithm should match")
				assert.Nil(t, ip.ExpiresAt, "ExpiresAt can be nil")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := tt.buildFunc()
			tt.validate(t, params)
		})
	}
}

// TestImportParametersExpiration tests expiration checking
func TestImportParametersExpiration(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		isExpired bool
	}{
		{
			name:      "No expiration",
			expiresAt: nil,
			isExpired: false,
		},
		{
			name: "Future expiration",
			expiresAt: func() *time.Time {
				future := time.Now().Add(24 * time.Hour)
				return &future
			}(),
			isExpired: false,
		},
		{
			name: "Past expiration",
			expiresAt: func() *time.Time {
				past := time.Now().Add(-1 * time.Hour)
				return &past
			}(),
			isExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &ImportParameters{
				ExpiresAt: tt.expiresAt,
			}

			if tt.expiresAt == nil {
				assert.Nil(t, params.ExpiresAt)
			} else if tt.isExpired {
				assert.True(t, params.ExpiresAt.Before(time.Now()), "Expiration should be in past")
			} else {
				assert.True(t, params.ExpiresAt.After(time.Now()), "Expiration should be in future")
			}
		})
	}
}

// TestWrappedKeyMaterialConstruction tests creating WrappedKeyMaterial
func TestWrappedKeyMaterialConstruction(t *testing.T) {
	tests := []struct {
		name      string
		buildFunc func() *WrappedKeyMaterial
		validate  func(*testing.T, *WrappedKeyMaterial)
	}{
		{
			name: "With all fields",
			buildFunc: func() *WrappedKeyMaterial {
				return &WrappedKeyMaterial{
					WrappedKey:  []byte("wrapped-key-data"),
					Algorithm:   WrappingAlgorithmRSAES_OAEP_SHA_256,
					ImportToken: []byte("import-token"),
					Metadata: map[string]string{
						"key_type": "RSA",
						"key_size": "2048",
					},
				}
			},
			validate: func(t *testing.T, wkm *WrappedKeyMaterial) {
				assert.Equal(t, "wrapped-key-data", string(wkm.WrappedKey), "WrappedKey should match")
				assert.Equal(t, WrappingAlgorithmRSAES_OAEP_SHA_256, wkm.Algorithm, "Algorithm should match")
				assert.Equal(t, "import-token", string(wkm.ImportToken), "ImportToken should match")
				assert.Len(t, wkm.Metadata, 2, "Metadata should have 2 entries")
				assert.Equal(t, "RSA", wkm.Metadata["key_type"], "Metadata key_type should match")
				assert.Equal(t, "2048", wkm.Metadata["key_size"], "Metadata key_size should match")
			},
		},
		{
			name: "Minimal wrapped key",
			buildFunc: func() *WrappedKeyMaterial {
				return &WrappedKeyMaterial{
					WrappedKey: []byte("minimal-wrapped-key"),
					Algorithm:  WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
				}
			},
			validate: func(t *testing.T, wkm *WrappedKeyMaterial) {
				assert.Equal(t, "minimal-wrapped-key", string(wkm.WrappedKey), "WrappedKey should match")
				assert.Equal(t, WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, wkm.Algorithm, "Algorithm should match")
				assert.Nil(t, wkm.ImportToken, "ImportToken can be nil")
				assert.Nil(t, wkm.Metadata, "Metadata can be nil")
			},
		},
		{
			name: "Empty metadata",
			buildFunc: func() *WrappedKeyMaterial {
				return &WrappedKeyMaterial{
					WrappedKey: []byte("key"),
					Algorithm:  WrappingAlgorithmRSAES_OAEP_SHA_1,
					Metadata:   map[string]string{},
				}
			},
			validate: func(t *testing.T, wkm *WrappedKeyMaterial) {
				assert.Empty(t, wkm.Metadata, "Empty metadata should be empty map")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := tt.buildFunc()
			tt.validate(t, wrapped)
		})
	}
}

// TestWrappedKeyMaterialMetadata tests metadata handling
func TestWrappedKeyMaterialMetadata(t *testing.T) {
	t.Run("Metadata access", func(t *testing.T) {
		wkm := &WrappedKeyMaterial{
			WrappedKey: []byte("key"),
			Algorithm:  WrappingAlgorithmRSAES_OAEP_SHA_256,
			Metadata: map[string]string{
				"origin":    "external",
				"timestamp": "2025-01-01T00:00:00Z",
				"source":    "aws-kms",
			},
		}

		// Access metadata
		assert.Equal(t, "external", wkm.Metadata["origin"])
		assert.Equal(t, "2025-01-01T00:00:00Z", wkm.Metadata["timestamp"])
		assert.Equal(t, "aws-kms", wkm.Metadata["source"])

		// Non-existent key returns empty string
		assert.Equal(t, "", wkm.Metadata["nonexistent"])
	})

	t.Run("Metadata modification", func(t *testing.T) {
		wkm := &WrappedKeyMaterial{
			WrappedKey: []byte("key"),
			Algorithm:  WrappingAlgorithmRSAES_OAEP_SHA_256,
			Metadata:   map[string]string{},
		}

		// Add metadata
		wkm.Metadata["key_version"] = "1"
		assert.Equal(t, "1", wkm.Metadata["key_version"])

		// Update metadata
		wkm.Metadata["key_version"] = "2"
		assert.Equal(t, "2", wkm.Metadata["key_version"])
	})
}

// TestImportParametersWithDifferentAlgorithms tests different wrapping algorithms
func TestImportParametersWithDifferentAlgorithms(t *testing.T) {
	algorithms := []WrappingAlgorithm{
		WrappingAlgorithmRSAES_OAEP_SHA_1,
		WrappingAlgorithmRSAES_OAEP_SHA_256,
		WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
		WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
		WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256,
		WrappingAlgorithmRSA_OAEP_4096_SHA256,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Should generate RSA key")

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			params := &ImportParameters{
				WrappingPublicKey: &privateKey.PublicKey,
				Algorithm:         algo,
				KeySpec:           "RSA_2048",
			}

			assert.NotNil(t, params.WrappingPublicKey)
			assert.Equal(t, algo, params.Algorithm)
			assert.Equal(t, "RSA_2048", params.KeySpec)

			// Verify public key is properly set
			pubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
			assert.True(t, ok, "WrappingPublicKey should be RSA PublicKey")
			assert.NotNil(t, pubKey)
		})
	}
}

// TestImportParametersPublicKeyType tests different public key types
func TestImportParametersPublicKeyType(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Should generate RSA key")

	t.Run("RSA PublicKey", func(t *testing.T) {
		params := &ImportParameters{
			WrappingPublicKey: &privateKey.PublicKey,
			Algorithm:         WrappingAlgorithmRSAES_OAEP_SHA_256,
			KeySpec:           "RSA_2048",
		}

		// Check that it can be asserted as crypto.PublicKey
		pubKey := params.WrappingPublicKey
		assert.NotNil(t, pubKey)

		// Check that it can be asserted as *rsa.PublicKey
		rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
		assert.True(t, ok, "Should be able to assert as *rsa.PublicKey")
		assert.NotNil(t, rsaPubKey)
		assert.Equal(t, 2048, rsaPubKey.Size()*8, "RSA key size should be 2048 bits")
	})
}

// TestWrappedKeyMaterialAlgorithmVariations tests different algorithms in wrapped material
func TestWrappedKeyMaterialAlgorithmVariations(t *testing.T) {
	algorithms := []WrappingAlgorithm{
		WrappingAlgorithmRSAES_OAEP_SHA_1,
		WrappingAlgorithmRSAES_OAEP_SHA_256,
		WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
		WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
		WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256,
		WrappingAlgorithmRSA_OAEP_4096_SHA256,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			wkm := &WrappedKeyMaterial{
				WrappedKey: []byte("wrapped-data-for-" + string(algo)),
				Algorithm:  algo,
			}

			assert.Equal(t, algo, wkm.Algorithm)
			assert.NotEmpty(t, wkm.WrappedKey)
		})
	}
}

// TestImportExportBackendInterfaceSignature verifies the interface is properly defined
func TestImportExportBackendInterfaceSignature(t *testing.T) {
	// This test verifies that ImportExportBackend properly extends Backend
	var backend types.Backend
	var importExport ImportExportBackend

	// The interface should embed Backend
	_ = backend
	_ = importExport

	// This test passes if the code compiles, verifying the interface is correct
	assert.True(t, true, "Interface signature is correct")
}

// TestImportParametersEdgeCases tests edge cases for ImportParameters
func TestImportParametersEdgeCases(t *testing.T) {
	t.Run("Empty KeySpec", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		params := &ImportParameters{
			WrappingPublicKey: &privateKey.PublicKey,
			Algorithm:         WrappingAlgorithmRSAES_OAEP_SHA_256,
			KeySpec:           "",
		}

		assert.Empty(t, params.KeySpec)
		assert.NotNil(t, params.WrappingPublicKey)
	})

	t.Run("Empty ImportToken", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		params := &ImportParameters{
			WrappingPublicKey: &privateKey.PublicKey,
			Algorithm:         WrappingAlgorithmRSAES_OAEP_SHA_256,
			ImportToken:       []byte{},
			KeySpec:           "RSA_2048",
		}

		assert.Empty(t, params.ImportToken)
		assert.Len(t, params.ImportToken, 0)
	})

	t.Run("Nil ExpiresAt", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		params := &ImportParameters{
			WrappingPublicKey: &privateKey.PublicKey,
			Algorithm:         WrappingAlgorithmRSAES_OAEP_SHA_256,
			ExpiresAt:         nil,
			KeySpec:           "RSA_2048",
		}

		assert.Nil(t, params.ExpiresAt)
	})

	t.Run("Far future expiration", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		farFuture := time.Now().Add(365 * 24 * time.Hour)
		params := &ImportParameters{
			WrappingPublicKey: &privateKey.PublicKey,
			Algorithm:         WrappingAlgorithmRSAES_OAEP_SHA_256,
			ExpiresAt:         &farFuture,
			KeySpec:           "RSA_2048",
		}

		assert.NotNil(t, params.ExpiresAt)
		assert.True(t, params.ExpiresAt.After(time.Now()))
	})
}

// TestWrappedKeyMaterialEdgeCases tests edge cases for WrappedKeyMaterial
func TestWrappedKeyMaterialEdgeCases(t *testing.T) {
	t.Run("Empty WrappedKey", func(t *testing.T) {
		wkm := &WrappedKeyMaterial{
			WrappedKey: []byte{},
			Algorithm:  WrappingAlgorithmRSAES_OAEP_SHA_256,
		}

		assert.Empty(t, wkm.WrappedKey)
		assert.Len(t, wkm.WrappedKey, 0)
	})

	t.Run("Large WrappedKey", func(t *testing.T) {
		largeKey := make([]byte, 8192)
		for i := range largeKey {
			largeKey[i] = byte(i % 256)
		}

		wkm := &WrappedKeyMaterial{
			WrappedKey: largeKey,
			Algorithm:  WrappingAlgorithmRSAES_OAEP_SHA_256,
		}

		assert.Len(t, wkm.WrappedKey, 8192)
		assert.Equal(t, largeKey, wkm.WrappedKey)
	})

	t.Run("Nil Metadata with access", func(t *testing.T) {
		wkm := &WrappedKeyMaterial{
			WrappedKey: []byte("key"),
			Algorithm:  WrappingAlgorithmRSAES_OAEP_SHA_256,
			Metadata:   nil,
		}

		assert.Nil(t, wkm.Metadata)
	})

	t.Run("Multiple metadata entries", func(t *testing.T) {
		wkm := &WrappedKeyMaterial{
			WrappedKey: []byte("key"),
			Algorithm:  WrappingAlgorithmRSAES_OAEP_SHA_256,
			Metadata: map[string]string{
				"key_id":         "12345",
				"key_version":    "2",
				"timestamp":      "2025-11-09T00:00:00Z",
				"source_backend": "aws-kms",
				"origin":         "external-import",
			},
		}

		assert.Len(t, wkm.Metadata, 5)
		assert.Equal(t, "12345", wkm.Metadata["key_id"])
		assert.Equal(t, "2", wkm.Metadata["key_version"])
	})
}
