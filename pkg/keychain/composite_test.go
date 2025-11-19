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
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	backmocks "github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	storagemocks "github.com/jeremyhahn/go-keychain/pkg/storage/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		config      *keychain.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &keychain.Config{
				Backend:     backmocks.NewMockBackend(),
				CertStorage: storagemocks.NewMockCertStorage(),
			},
			expectError: false,
		},
		{
			name: "nil backend",
			config: &keychain.Config{
				Backend:     nil,
				CertStorage: storagemocks.NewMockCertStorage(),
			},
			expectError: true,
			errorMsg:    "backend is required",
		},
		{
			name: "nil cert storage",
			config: &keychain.Config{
				Backend:     backmocks.NewMockBackend(),
				CertStorage: nil,
			},
			expectError: true,
			errorMsg:    "certificate storage is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, err := keychain.New(tt.config)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ks == nil {
					t.Error("expected keystore, got nil")
				}
			}
		})
	}
}

func TestCompositeKeyStore_Backend(t *testing.T) {
	mockBackend := backmocks.NewMockBackend()
	certStorage := storagemocks.NewMockCertStorage()

	ks, err := keychain.New(&keychain.Config{
		Backend:     mockBackend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	// Test Backend() accessor
	if ks.Backend() != mockBackend {
		t.Error("Backend() returned wrong backend")
	}
}

func TestCompositeKeyStore_CertStorage(t *testing.T) {
	mockBackend := backmocks.NewMockBackend()
	certStorage := storagemocks.NewMockCertStorage()

	ks, err := keychain.New(&keychain.Config{
		Backend:     mockBackend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	// Test CertStorage() accessor
	// CertStorage() returns a CertAdapter wrapping the original backend
	adapter := ks.CertStorage()
	if adapter == nil {
		t.Error("CertStorage() returned nil")
	}
	// Type-assert to *storage.CertAdapter to access the underlying backend
	certAdapter, ok := adapter.(*storage.CertAdapter)
	if !ok {
		t.Error("CertStorage() did not return *storage.CertAdapter")
	}
	// Verify the underlying backend is correct
	if certAdapter.Backend() != certStorage {
		t.Error("CertStorage().Backend() returned wrong storage")
	}
}

func TestCompositeKeyStore_Close(t *testing.T) {
	tests := []struct {
		name              string
		backendCloseError error
		storageCloseError error
		expectError       bool
	}{
		{
			name:              "successful close",
			backendCloseError: nil,
			storageCloseError: nil,
			expectError:       false,
		},
		{
			name:              "backend close error",
			backendCloseError: keychain.ErrBackendClosed,
			storageCloseError: nil,
			expectError:       true,
		},
		{
			name:              "storage close error",
			backendCloseError: nil,
			storageCloseError: keychain.ErrStorageClosed,
			expectError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBackend := backmocks.NewMockBackend()
			certStorage := storagemocks.NewMockCertStorage()

			// Configure error behavior
			if tt.backendCloseError != nil {
				mockBackend.CloseFunc = func() error {
					return tt.backendCloseError
				}
			}
			if tt.storageCloseError != nil {
				certStorage.CloseFunc = func() error {
					return tt.storageCloseError
				}
			}

			ks, err := keychain.New(&keychain.Config{
				Backend:     mockBackend,
				CertStorage: certStorage,
			})
			if err != nil {
				t.Fatalf("failed to create keystore: %v", err)
			}

			err = ks.Close()

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			// Verify Close was called on both
			if mockBackend.CloseCalls == 0 {
				t.Error("backend Close was not called")
			}
			// Note: storage Close might not be called if backend Close fails
			if !tt.expectError && certStorage.CloseCalls == 0 {
				t.Error("cert storage Close was not called")
			}
		})
	}
}

func TestCompositeKeyStore_InterfaceCompliance(t *testing.T) {
	mockBackend := backmocks.NewMockBackend()
	certStorage := storagemocks.NewMockCertStorage()

	ks, err := keychain.New(&keychain.Config{
		Backend:     mockBackend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	// Verify it implements KeyStore interface
	_ = ks

	// Test that all methods are available
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
	}

	// These will fail but we're just checking the interface
	_, _ = ks.GenerateRSA(attrs)
	_, _ = ks.GenerateECDSA(attrs)
	_, _ = ks.GenerateEd25519(attrs)
	_, _ = ks.GetKey(attrs)
	_ = ks.DeleteKey(attrs)
	_, _ = ks.ListKeys()
	_, _ = ks.RotateKey(attrs)
	_, _ = ks.Signer(attrs)
	_, _ = ks.Decrypter(attrs)
	_ = ks.SaveCert("test", nil)
	_, _ = ks.GetCert("test")
	_ = ks.DeleteCert("test")
	_ = ks.SaveCertChain("test", nil)
	_, _ = ks.GetCertChain("test")
	_, _ = ks.ListCerts()
	_, _ = ks.CertExists("test")
	_, _ = ks.GetTLSCertificate("test", attrs)
	_ = ks.Backend()
	_ = ks.CertStorage()
	_ = ks.Close()
}
