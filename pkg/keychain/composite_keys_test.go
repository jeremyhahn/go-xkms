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

package keychain_test

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	backmocks "github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	storagemocks "github.com/jeremyhahn/go-keychain/pkg/storage/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func setupKeyStore() (keychain.KeyStore, *backmocks.MockBackend, *storagemocks.MockCertStorage) {
	mockBackend := backmocks.NewMockBackend()
	certStorage := storagemocks.NewMockCertStorage()

	ks, err := keychain.New(&keychain.Config{
		Backend:     mockBackend,
		CertStorage: certStorage,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create keystore: %v", err))
	}

	return ks, mockBackend, certStorage
}

func TestCompositeKeyStore_GenerateRSA(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		expectError bool
	}{
		{
			name: "valid RSA generation",
			attrs: &types.KeyAttributes{
				CN:           "test-rsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			expectError: false,
		},
		{
			name:        "nil attributes",
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer func() { _ = ks.Close() }()

			key, err := ks.GenerateRSA(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key == nil {
				t.Fatal("expected key, got nil")
			}

			// Verify backend was called
			if len(mockBackend.GenerateKeyCalls) != 1 {
				t.Errorf("expected 1 GenerateKey call, got %d", len(mockBackend.GenerateKeyCalls))
			}
		})
	}
}

func TestCompositeKeyStore_GenerateECDSA(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		expectError bool
	}{
		{
			name: "valid ECDSA generation",
			attrs: &types.KeyAttributes{
				CN:           "test-ecdsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expectError: false,
		},
		{
			name:        "nil attributes",
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer func() { _ = ks.Close() }()

			key, err := ks.GenerateECDSA(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key == nil {
				t.Fatal("expected key, got nil")
			}

			// Verify backend was called
			if len(mockBackend.GenerateKeyCalls) != 1 {
				t.Errorf("expected 1 GenerateKey call, got %d", len(mockBackend.GenerateKeyCalls))
			}
		})
	}
}

func TestCompositeKeyStore_GenerateEd25519(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		expectError bool
	}{
		{
			name: "valid Ed25519 generation",
			attrs: &types.KeyAttributes{
				CN:           "test-ed25519",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.Ed25519,
			},
			expectError: false,
		},
		{
			name:        "nil attributes",
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer func() { _ = ks.Close() }()

			key, err := ks.GenerateEd25519(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key == nil {
				t.Fatal("expected key, got nil")
			}

			// Verify backend was called
			if len(mockBackend.GenerateKeyCalls) != 1 {
				t.Errorf("expected 1 GenerateKey call, got %d", len(mockBackend.GenerateKeyCalls))
			}
		})
	}
}

func TestCompositeKeyStore_GetKey(t *testing.T) {
	tests := []struct {
		name         string
		setupBackend func(*backmocks.MockBackend)
		attrs        *types.KeyAttributes
		expectError  bool
	}{
		{
			name: "existing key",
			setupBackend: func(b *backmocks.MockBackend) {
				// Generate a key first
				attrs := &types.KeyAttributes{
					CN:           "test-get",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				ks, err := keychain.New(&keychain.Config{
					Backend:     b,
					CertStorage: storagemocks.NewMockCertStorage(),
				})
				if err == nil {
					_, _ = ks.GenerateRSA(attrs)
				}
			},
			attrs: &types.KeyAttributes{
				CN:           "test-get",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: false,
		},
		{
			name: "non-existent key",
			setupBackend: func(b *backmocks.MockBackend) {
				// No setup needed
			},
			attrs: &types.KeyAttributes{
				CN:           "non-existent",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: true,
		},
		{
			name: "nil attributes",
			setupBackend: func(b *backmocks.MockBackend) {
				// No setup needed
			},
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBackend := backmocks.NewMockBackend()
			tt.setupBackend(mockBackend)

			ks, _ := keychain.New(&keychain.Config{
				Backend:     mockBackend,
				CertStorage: storagemocks.NewMockCertStorage(),
			})
			defer func() { _ = ks.Close() }()

			key, err := ks.GetKey(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key == nil {
				t.Fatal("expected key, got nil")
			}
		})
	}
}

func TestCompositeKeyStore_DeleteKey(t *testing.T) {
	tests := []struct {
		name         string
		setupBackend func(*backmocks.MockBackend)
		attrs        *types.KeyAttributes
		expectError  bool
	}{
		{
			name: "delete existing key",
			setupBackend: func(b *backmocks.MockBackend) {
				attrs := &types.KeyAttributes{
					CN:           "test-delete",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				ks, err := keychain.New(&keychain.Config{
					Backend:     b,
					CertStorage: storagemocks.NewMockCertStorage(),
				})
				if err == nil {
					_, _ = ks.GenerateRSA(attrs)
				}
			},
			attrs: &types.KeyAttributes{
				CN:           "test-delete",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: false,
		},
		{
			name: "delete non-existent key",
			setupBackend: func(b *backmocks.MockBackend) {
				// No setup needed
			},
			attrs: &types.KeyAttributes{
				CN:           "non-existent",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: true,
		},
		{
			name: "nil attributes",
			setupBackend: func(b *backmocks.MockBackend) {
				// No setup needed
			},
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBackend := backmocks.NewMockBackend()
			tt.setupBackend(mockBackend)

			ks, _ := keychain.New(&keychain.Config{
				Backend:     mockBackend,
				CertStorage: storagemocks.NewMockCertStorage(),
			})
			defer func() { _ = ks.Close() }()

			err := ks.DeleteKey(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCompositeKeyStore_ListKeys(t *testing.T) {
	ks, mockBackend, _ := setupKeyStore()
	defer func() { _ = ks.Close() }()

	// Generate some keys
	for i := 0; i < 3; i++ {
		attrs := &types.KeyAttributes{
			CN:           fmt.Sprintf("test-list-%d", i),
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
		_, _ = ks.GenerateRSA(attrs)
	}

	keys, err := ks.ListKeys()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	// Verify backend was called
	if mockBackend.ListKeysCalls != 1 {
		t.Errorf("expected 1 ListKeys call, got %d", mockBackend.ListKeysCalls)
	}
}

func TestCompositeKeyStore_RotateKey(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		expectError bool
	}{
		{
			name: "rotate RSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-rotate",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			expectError: false,
		},
		{
			name: "rotate ECDSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-rotate-ecdsa",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expectError: false,
		},
		{
			name: "rotate Ed25519 key",
			attrs: &types.KeyAttributes{
				CN:           "test-rotate-ed25519",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.Ed25519,
			},
			expectError: false,
		},
		{
			name:        "nil attributes",
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer func() { _ = ks.Close() }()

			// Generate initial key first
			if tt.attrs != nil {
				switch tt.attrs.KeyAlgorithm {
				case x509.RSA:
					_, _ = ks.GenerateRSA(tt.attrs)
				case x509.ECDSA:
					_, _ = ks.GenerateECDSA(tt.attrs)
				case x509.Ed25519:
					_, _ = ks.GenerateEd25519(tt.attrs)
				}
			}

			// Reset call tracking
			mockBackend.DeleteKeyCalls = nil
			mockBackend.GenerateKeyCalls = nil

			// Rotate the key
			newKey, err := ks.RotateKey(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if newKey == nil {
				t.Fatal("expected new key, got nil")
			}

			// Verify delete and generate were called
			if len(mockBackend.DeleteKeyCalls) != 1 {
				t.Errorf("expected 1 DeleteKey call, got %d", len(mockBackend.DeleteKeyCalls))
			}
			if len(mockBackend.GenerateKeyCalls) != 1 {
				t.Errorf("expected 1 GenerateKey call, got %d", len(mockBackend.GenerateKeyCalls))
			}
		})
	}
}

// ========================================================================
// Edge Case Tests for Improved Coverage
// ========================================================================

// TestCompositeKeyStore_GenerateRSA_EdgeCases tests backend errors and edge cases
func TestCompositeKeyStore_GenerateRSA_EdgeCases(t *testing.T) {
	t.Run("backend generation error", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("backend error: hardware failure")
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-backend-error",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		_, err := ks.GenerateRSA(attrs)
		if err == nil {
			t.Fatal("expected error from backend, got nil")
		}
		if !contains(err.Error(), "failed to generate RSA key") {
			t.Errorf("expected wrapped error message, got: %v", err)
		}
	})

	t.Run("backend returns nil key", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil // Return nil key, no error
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-nil-key",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		_, err := ks.GenerateRSA(attrs)
		if err == nil {
			t.Fatal("expected error for nil key, got nil")
		}
		if !contains(err.Error(), "failed to extract public key") {
			t.Errorf("expected public key extraction error, got: %v", err)
		}
	})

	t.Run("backend returns non-crypto.Signer key", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		// Return a struct that doesn't implement Public() method
		type invalidKey struct{}
		mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return &invalidKey{}, nil
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-invalid-key",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		_, err := ks.GenerateRSA(attrs)
		if err == nil {
			t.Fatal("expected error for invalid key type, got nil")
		}
	})
}

// TestCompositeKeyStore_GenerateECDSA_EdgeCases tests ECDSA edge cases
func TestCompositeKeyStore_GenerateECDSA_EdgeCases(t *testing.T) {
	t.Run("backend generation error", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("curve not supported")
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-error",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		_, err := ks.GenerateECDSA(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to generate ECDSA key") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})

	t.Run("backend returns nil key", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa-nil",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		_, err := ks.GenerateECDSA(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to extract public key") {
			t.Errorf("expected public key error, got: %v", err)
		}
	})
}

// TestCompositeKeyStore_GenerateEd25519_EdgeCases tests Ed25519 edge cases
func TestCompositeKeyStore_GenerateEd25519_EdgeCases(t *testing.T) {
	t.Run("backend generation error", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("random source exhausted")
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-ed25519-error",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.Ed25519,
		}

		_, err := ks.GenerateEd25519(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to generate Ed25519 key") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})

	t.Run("backend returns nil key", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GenerateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-ed25519-nil",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.Ed25519,
		}

		_, err := ks.GenerateEd25519(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to extract public key") {
			t.Errorf("expected public key error, got: %v", err)
		}
	})
}

// TestCompositeKeyStore_GetKey_EdgeCases tests GetKey edge cases
func TestCompositeKeyStore_GetKey_EdgeCases(t *testing.T) {
	t.Run("backend get error", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("key storage corrupted")
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-get-error",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
		}

		_, err := ks.GetKey(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to get key") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})

	t.Run("backend returns nil key", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-get-nil",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
		}

		_, err := ks.GetKey(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to extract public key") {
			t.Errorf("expected public key error, got: %v", err)
		}
	})
}

// TestCompositeKeyStore_ListKeys_EdgeCases tests ListKeys error paths
func TestCompositeKeyStore_ListKeys_EdgeCases(t *testing.T) {
	t.Run("backend list error", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		mockBackend.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return nil, fmt.Errorf("database connection lost")
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		_, err := ks.ListKeys()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to list keys") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		ks, _, _ := setupKeyStore()
		defer func() { _ = ks.Close() }()

		keys, err := ks.ListKeys()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if keys == nil {
			t.Fatal("expected empty slice, got nil")
		}

		if len(keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(keys))
		}
	})
}

// TestCompositeKeyStore_RotateKey_EdgeCases tests RotateKey edge cases
func TestCompositeKeyStore_RotateKey_EdgeCases(t *testing.T) {
	t.Run("unsupported algorithm", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		// Create a key with unsupported algorithm for rotation
		attrs := &types.KeyAttributes{
			CN:           "test-rotate-unsupported",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA, // Start with RSA
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate initial key
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("failed to generate initial key: %v", err)
		}

		// Change algorithm to unsupported value
		attrs.KeyAlgorithm = x509.UnknownPublicKeyAlgorithm

		_, err = ks.RotateKey(attrs)
		if err == nil {
			t.Fatal("expected error for unsupported algorithm, got nil")
		}
	})

	t.Run("delete error during rotation", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		deleteAttempted := false

		mockBackend.DeleteKeyFunc = func(attrs *types.KeyAttributes) error {
			if !deleteAttempted {
				deleteAttempted = true
				return fmt.Errorf("key is locked")
			}
			return fmt.Errorf("key not found: %s", attrs.CN)
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-rotate-delete-error",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Generate initial key (this won't use our delete func)
		mockBackend.DeleteKeyFunc = nil
		_, err := ks.GenerateRSA(attrs)
		if err != nil {
			t.Fatalf("failed to generate initial key: %v", err)
		}

		// Now set the delete func to return error
		mockBackend.DeleteKeyFunc = func(attrs *types.KeyAttributes) error {
			return fmt.Errorf("key is locked")
		}

		_, err = ks.RotateKey(attrs)
		if err == nil {
			t.Fatal("expected error during delete, got nil")
		}
		if !contains(err.Error(), "failed to delete old key during rotation") {
			t.Errorf("expected rotation delete error, got: %v", err)
		}
	})
}

// TestCompositeKeyStore_PublicKeyHelper tests the publicKey helper function edge cases
func TestCompositeKeyStore_PublicKeyHelper(t *testing.T) {
	t.Run("nil key returns nil", func(t *testing.T) {
		// Test via GetKey with nil backend response
		mockBackend := backmocks.NewMockBackend()
		mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, nil
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-nil-pub",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
		}

		_, err := ks.GetKey(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to extract public key") {
			t.Errorf("expected public key extraction error, got: %v", err)
		}
	})

	t.Run("key without Public() method", func(t *testing.T) {
		mockBackend := backmocks.NewMockBackend()
		type badKey struct{}
		mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return &badKey{}, nil
		}

		ks, _ := keychain.New(&keychain.Config{
			Backend:     mockBackend,
			CertStorage: storagemocks.NewMockCertStorage(),
		})
		defer func() { _ = ks.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-bad-pub",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.RSA,
		}

		_, err := ks.GetKey(attrs)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to extract public key") {
			t.Errorf("expected public key extraction error, got: %v", err)
		}
	})
}

// TestCompositeKeyStore_MultipleKeyTypes verifies all key types work correctly
func TestCompositeKeyStore_MultipleKeyTypes(t *testing.T) {
	ks, _, _ := setupKeyStore()
	defer func() { _ = ks.Close() }()

	tests := []struct {
		name      string
		genFunc   func(*types.KeyAttributes) (crypto.PrivateKey, error)
		attrs     *types.KeyAttributes
		verifyKey func(crypto.PrivateKey) bool
	}{
		{
			name:    "RSA-2048",
			genFunc: ks.GenerateRSA,
			attrs: &types.KeyAttributes{
				CN:           "test-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			verifyKey: func(k crypto.PrivateKey) bool {
				return k != nil
			},
		},
		{
			name:    "ECDSA-P256",
			genFunc: ks.GenerateECDSA,
			attrs: &types.KeyAttributes{
				CN:           "test-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			verifyKey: func(k crypto.PrivateKey) bool {
				return k != nil
			},
		},
		{
			name:    "ECDSA-P384",
			genFunc: ks.GenerateECDSA,
			attrs: &types.KeyAttributes{
				CN:           "test-ecdsa-p384",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			},
			verifyKey: func(k crypto.PrivateKey) bool {
				return k != nil
			},
		},
		{
			name:    "Ed25519",
			genFunc: ks.GenerateEd25519,
			attrs: &types.KeyAttributes{
				CN:           "test-ed25519",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.Ed25519,
			},
			verifyKey: func(k crypto.PrivateKey) bool {
				return k != nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.genFunc(tt.attrs)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			if !tt.verifyKey(key) {
				t.Error("key verification failed")
			}

			// Verify we can retrieve it
			retrieved, err := ks.GetKey(tt.attrs)
			if err != nil {
				t.Fatalf("failed to retrieve key: %v", err)
			}

			if retrieved == nil {
				t.Fatal("retrieved key is nil")
			}
		})
	}
}

// TestPublicKeyExtraction - Removed, public key extraction already tested via integration tests

// Helper function to check if error message contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && hasSubstring(s, substr)))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
