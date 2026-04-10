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

package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveKey tests the SaveKey adapter function.
func TestSaveKey(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		keyData   []byte
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name:    "successful save",
			id:      "test-key",
			keyData: []byte("test-data"),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name:    "empty ID",
			id:      "",
			keyData: []byte("test-data"),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name:    "nil key data",
			id:      "test-key",
			keyData: nil,
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name:    "backend closed",
			id:      "test-key",
			keyData: []byte("test-data"),
			setupFunc: func() Backend {
				b := &errorMockBackend{putErr: ErrClosed}
				return b
			},
			wantErr: ErrClosed,
		},
		{
			name:    "overwrite existing key",
			id:      "test-key",
			keyData: []byte("new-data"),
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, KeyPath("test-key"), []byte("old-data"))
				return b
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := SaveKey(ctx, backend, tt.id, tt.keyData)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Verify the data was saved correctly
				if tt.id != "" {
					data, err := backend.Get(ctx, KeyPath(tt.id))
					assert.NoError(t, err)
					assert.Equal(t, tt.keyData, data)
				}
			}
		})
	}
}

// TestGetKey tests the GetKey adapter function.
func TestGetKey(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		setupFunc func() Backend
		wantData  []byte
		wantErr   error
	}{
		{
			name: "successful get",
			id:   "test-key",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, KeyPath("test-key"), []byte("test-data"))
				return b
			},
			wantData: []byte("test-data"),
			wantErr:  nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantData: nil,
			wantErr:  ErrInvalidID,
		},
		{
			name: "key not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantData: nil,
			wantErr:  ErrNotFound,
		},
		{
			name: "backend closed",
			id:   "test-key",
			setupFunc: func() Backend {
				return &errorMockBackend{getErr: ErrClosed}
			},
			wantData: nil,
			wantErr:  ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			data, err := GetKey(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, data)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantData, data)
			}
		})
	}
}

// TestDeleteKey tests the DeleteKey adapter function.
func TestDeleteKey(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name: "successful delete",
			id:   "test-key",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, KeyPath("test-key"), []byte("test-data"))
				return b
			},
			wantErr: nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name: "key not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrNotFound,
		},
		{
			name: "backend closed",
			id:   "test-key",
			setupFunc: func() Backend {
				return &errorMockBackend{deleteErr: ErrClosed}
			},
			wantErr: ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := DeleteKey(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Verify the key was deleted
				exists, err := backend.Exists(ctx, KeyPath(tt.id))
				assert.NoError(t, err)
				assert.False(t, exists)
			}
		})
	}
}

// TestKeyExists tests the KeyExists adapter function.
func TestKeyExists(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		id         string
		setupFunc  func() Backend
		wantExists bool
		wantErr    error
	}{
		{
			name: "key exists",
			id:   "test-key",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, KeyPath("test-key"), []byte("test-data"))
				return b
			},
			wantExists: true,
			wantErr:    nil,
		},
		{
			name: "key does not exist",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantExists: false,
			wantErr:    nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantExists: false,
			wantErr:    ErrInvalidID,
		},
		{
			name: "backend closed",
			id:   "test-key",
			setupFunc: func() Backend {
				return &errorMockBackend{existsErr: ErrClosed}
			},
			wantExists: false,
			wantErr:    ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			exists, err := KeyExists(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantExists, exists)
			}
		})
	}
}

// TestSaveCert tests the SaveCert adapter function.
func TestSaveCert(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		certData  []byte
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name:     "successful save",
			id:       "test-cert",
			certData: []byte("-----BEGIN CERTIFICATE-----"),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name:     "empty ID",
			id:       "",
			certData: []byte("cert-data"),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name:     "nil cert data",
			id:       "test-cert",
			certData: nil,
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name:     "backend closed",
			id:       "test-cert",
			certData: []byte("cert-data"),
			setupFunc: func() Backend {
				return &errorMockBackend{putErr: ErrClosed}
			},
			wantErr: ErrClosed,
		},
		{
			name:     "overwrite existing cert",
			id:       "test-cert",
			certData: []byte("new-cert"),
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertPath("test-cert"), []byte("old-cert"))
				return b
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := SaveCert(ctx, backend, tt.id, tt.certData)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Verify the data was saved correctly
				if tt.id != "" {
					data, err := backend.Get(ctx, CertPath(tt.id))
					assert.NoError(t, err)
					assert.Equal(t, tt.certData, data)
				}
			}
		})
	}
}

// TestGetCert tests the GetCert adapter function.
func TestGetCert(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		setupFunc func() Backend
		wantData  []byte
		wantErr   error
	}{
		{
			name: "successful get",
			id:   "test-cert",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertPath("test-cert"), []byte("cert-data"))
				return b
			},
			wantData: []byte("cert-data"),
			wantErr:  nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantData: nil,
			wantErr:  ErrInvalidID,
		},
		{
			name: "cert not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantData: nil,
			wantErr:  ErrNotFound,
		},
		{
			name: "backend closed",
			id:   "test-cert",
			setupFunc: func() Backend {
				return &errorMockBackend{getErr: ErrClosed}
			},
			wantData: nil,
			wantErr:  ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			data, err := GetCert(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, data)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantData, data)
			}
		})
	}
}

// TestDeleteCert tests the DeleteCert adapter function.
func TestDeleteCert(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name: "successful delete",
			id:   "test-cert",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertPath("test-cert"), []byte("cert-data"))
				return b
			},
			wantErr: nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name: "cert not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrNotFound,
		},
		{
			name: "backend closed",
			id:   "test-cert",
			setupFunc: func() Backend {
				return &errorMockBackend{deleteErr: ErrClosed}
			},
			wantErr: ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := DeleteCert(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Verify the cert was deleted
				exists, err := backend.Exists(ctx, CertPath(tt.id))
				assert.NoError(t, err)
				assert.False(t, exists)
			}
		})
	}
}

// TestCertExists tests the CertExists adapter function.
func TestCertExists(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		id         string
		setupFunc  func() Backend
		wantExists bool
		wantErr    error
	}{
		{
			name: "cert exists",
			id:   "test-cert",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertPath("test-cert"), []byte("cert-data"))
				return b
			},
			wantExists: true,
			wantErr:    nil,
		},
		{
			name: "cert does not exist",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantExists: false,
			wantErr:    nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantExists: false,
			wantErr:    ErrInvalidID,
		},
		{
			name: "backend closed",
			id:   "test-cert",
			setupFunc: func() Backend {
				return &errorMockBackend{existsErr: ErrClosed}
			},
			wantExists: false,
			wantErr:    ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			exists, err := CertExists(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantExists, exists)
			}
		})
	}
}

// TestSaveCertChain tests the SaveCertChain adapter function.
func TestSaveCertChain(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		chainData []byte
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name:      "successful save",
			id:        "test-chain",
			chainData: []byte("-----BEGIN CERTIFICATE-----\n..."),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name:      "empty ID",
			id:        "",
			chainData: []byte("chain-data"),
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name:      "nil chain data",
			id:        "test-chain",
			chainData: nil,
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: nil,
		},
		{
			name:      "backend closed",
			id:        "test-chain",
			chainData: []byte("chain-data"),
			setupFunc: func() Backend {
				return &errorMockBackend{putErr: ErrClosed}
			},
			wantErr: ErrClosed,
		},
		{
			name:      "overwrite existing chain",
			id:        "test-chain",
			chainData: []byte("new-chain"),
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertChainPath("test-chain"), []byte("old-chain"))
				return b
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := SaveCertChain(ctx, backend, tt.id, tt.chainData)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Verify the data was saved correctly
				if tt.id != "" {
					data, err := backend.Get(ctx, CertChainPath(tt.id))
					assert.NoError(t, err)
					assert.Equal(t, tt.chainData, data)
				}
			}
		})
	}
}

// TestGetCertChain tests the GetCertChain adapter function.
func TestGetCertChain(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		setupFunc func() Backend
		wantData  []byte
		wantErr   error
	}{
		{
			name: "successful get",
			id:   "test-chain",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertChainPath("test-chain"), []byte("chain-data"))
				return b
			},
			wantData: []byte("chain-data"),
			wantErr:  nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantData: nil,
			wantErr:  ErrInvalidID,
		},
		{
			name: "chain not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantData: nil,
			wantErr:  ErrNotFound,
		},
		{
			name: "backend closed",
			id:   "test-chain",
			setupFunc: func() Backend {
				return &errorMockBackend{getErr: ErrClosed}
			},
			wantData: nil,
			wantErr:  ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			data, err := GetCertChain(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, data)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantData, data)
			}
		})
	}
}

// TestDeleteCertChain tests the DeleteCertChain adapter function.
func TestDeleteCertChain(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		id        string
		setupFunc func() Backend
		wantErr   error
	}{
		{
			name: "successful delete",
			id:   "test-chain",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertChainPath("test-chain"), []byte("chain-data"))
				return b
			},
			wantErr: nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrInvalidID,
		},
		{
			name: "chain not found",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantErr: ErrNotFound,
		},
		{
			name: "backend closed",
			id:   "test-chain",
			setupFunc: func() Backend {
				return &errorMockBackend{deleteErr: ErrClosed}
			},
			wantErr: ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			err := DeleteCertChain(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				// Verify the chain was deleted
				exists, err := backend.Exists(ctx, CertChainPath(tt.id))
				assert.NoError(t, err)
				assert.False(t, exists)
			}
		})
	}
}

// TestCertChainExists tests the CertChainExists adapter function.
func TestCertChainExists(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		id         string
		setupFunc  func() Backend
		wantExists bool
		wantErr    error
	}{
		{
			name: "chain exists",
			id:   "test-chain",
			setupFunc: func() Backend {
				b := newMockBackend()
				_ = b.Put(ctx, CertChainPath("test-chain"), []byte("chain-data"))
				return b
			},
			wantExists: true,
			wantErr:    nil,
		},
		{
			name: "chain does not exist",
			id:   "nonexistent",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantExists: false,
			wantErr:    nil,
		},
		{
			name: "empty ID",
			id:   "",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			wantExists: false,
			wantErr:    ErrInvalidID,
		},
		{
			name: "backend closed",
			id:   "test-chain",
			setupFunc: func() Backend {
				return &errorMockBackend{existsErr: ErrClosed}
			},
			wantExists: false,
			wantErr:    ErrClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			exists, err := CertChainExists(ctx, backend, tt.id)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantExists, exists)
			}
		})
	}
}

// TestAdaptersIntegration tests that all adapters work together correctly.
func TestAdaptersIntegration(t *testing.T) {
	ctx := context.Background()
	backend := newMockBackend()

	// Test key operations
	t.Run("key lifecycle", func(t *testing.T) {
		keyID := "integration-key"
		keyData := []byte("secret-key-data")

		// Save
		err := SaveKey(ctx, backend, keyID, keyData)
		require.NoError(t, err)

		// Check exists
		exists, err := KeyExists(ctx, backend, keyID)
		require.NoError(t, err)
		assert.True(t, exists)

		// Get
		retrieved, err := GetKey(ctx, backend, keyID)
		require.NoError(t, err)
		assert.Equal(t, keyData, retrieved)

		// Delete
		err = DeleteKey(ctx, backend, keyID)
		require.NoError(t, err)

		// Verify deleted
		exists, err = KeyExists(ctx, backend, keyID)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// Test cert operations
	t.Run("cert lifecycle", func(t *testing.T) {
		certID := "integration-cert"
		certData := []byte("-----BEGIN CERTIFICATE-----")

		// Save
		err := SaveCert(ctx, backend, certID, certData)
		require.NoError(t, err)

		// Check exists
		exists, err := CertExists(ctx, backend, certID)
		require.NoError(t, err)
		assert.True(t, exists)

		// Get
		retrieved, err := GetCert(ctx, backend, certID)
		require.NoError(t, err)
		assert.Equal(t, certData, retrieved)

		// Delete
		err = DeleteCert(ctx, backend, certID)
		require.NoError(t, err)

		// Verify deleted
		exists, err = CertExists(ctx, backend, certID)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// Test cert chain operations
	t.Run("cert chain lifecycle", func(t *testing.T) {
		chainID := "integration-chain"
		chainData := []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")

		// Save
		err := SaveCertChain(ctx, backend, chainID, chainData)
		require.NoError(t, err)

		// Check exists
		exists, err := CertChainExists(ctx, backend, chainID)
		require.NoError(t, err)
		assert.True(t, exists)

		// Get
		retrieved, err := GetCertChain(ctx, backend, chainID)
		require.NoError(t, err)
		assert.Equal(t, chainData, retrieved)

		// Delete
		err = DeleteCertChain(ctx, backend, chainID)
		require.NoError(t, err)

		// Verify deleted
		exists, err = CertChainExists(ctx, backend, chainID)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// Test that different types don't interfere
	t.Run("isolation between types", func(t *testing.T) {
		id := "shared-id"

		// Save key, cert, and chain with same ID
		err := SaveKey(ctx, backend, id, []byte("key-data"))
		require.NoError(t, err)

		err = SaveCert(ctx, backend, id, []byte("cert-data"))
		require.NoError(t, err)

		err = SaveCertChain(ctx, backend, id, []byte("chain-data"))
		require.NoError(t, err)

		// Verify all exist independently
		keyExists, err := KeyExists(ctx, backend, id)
		require.NoError(t, err)
		assert.True(t, keyExists)

		certExists, err := CertExists(ctx, backend, id)
		require.NoError(t, err)
		assert.True(t, certExists)

		chainExists, err := CertChainExists(ctx, backend, id)
		require.NoError(t, err)
		assert.True(t, chainExists)

		// Retrieve and verify correct data
		keyData, err := GetKey(ctx, backend, id)
		require.NoError(t, err)
		assert.Equal(t, []byte("key-data"), keyData)

		certData, err := GetCert(ctx, backend, id)
		require.NoError(t, err)
		assert.Equal(t, []byte("cert-data"), certData)

		chainData, err := GetCertChain(ctx, backend, id)
		require.NoError(t, err)
		assert.Equal(t, []byte("chain-data"), chainData)
	})
}

// TestAdaptersWithCustomErrors tests adapters with custom backend errors.
func TestAdaptersWithCustomErrors(t *testing.T) {
	ctx := context.Background()
	customErr := errors.New("custom backend error")

	t.Run("custom Get error", func(t *testing.T) {
		backend := &errorMockBackend{getErr: customErr}

		_, err := GetKey(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)

		_, err = GetCert(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)

		_, err = GetCertChain(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)
	})

	t.Run("custom Put error", func(t *testing.T) {
		backend := &errorMockBackend{putErr: customErr}

		err := SaveKey(ctx, backend, "test", []byte("data"))
		assert.ErrorIs(t, err, customErr)

		err = SaveCert(ctx, backend, "test", []byte("data"))
		assert.ErrorIs(t, err, customErr)

		err = SaveCertChain(ctx, backend, "test", []byte("data"))
		assert.ErrorIs(t, err, customErr)
	})

	t.Run("custom Delete error", func(t *testing.T) {
		backend := &errorMockBackend{deleteErr: customErr}

		err := DeleteKey(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)

		err = DeleteCert(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)

		err = DeleteCertChain(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)
	})

	t.Run("custom Exists error", func(t *testing.T) {
		backend := &errorMockBackend{existsErr: customErr}

		_, err := KeyExists(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)

		_, err = CertExists(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)

		_, err = CertChainExists(ctx, backend, "test")
		assert.ErrorIs(t, err, customErr)
	})
}
