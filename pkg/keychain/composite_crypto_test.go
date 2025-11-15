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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	backmocks "github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	storagemocks "github.com/jeremyhahn/go-keychain/pkg/storage/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestCompositeKeyStore_Signer(t *testing.T) {
	tests := []struct {
		name         string
		setupBackend func(*keychain.KeyStore)
		attrs        *types.KeyAttributes
		expectError  bool
	}{
		{
			name: "valid signer",
			setupBackend: func(ks *keychain.KeyStore) {
				attrs := &types.KeyAttributes{
					CN:           "test-signer",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				_, _ = (*ks).GenerateRSA(attrs)
			},
			attrs: &types.KeyAttributes{
				CN:           "test-signer",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: false,
		},
		{
			name: "non-existent key",
			setupBackend: func(ks *keychain.KeyStore) {
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
			setupBackend: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer ks.Close()

			tt.setupBackend(&ks)

			// Reset call tracking
			mockBackend.SignerCalls = nil

			signer, err := ks.Signer(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if signer == nil {
				t.Fatal("expected signer, got nil")
			}

			// Verify backend was called
			if len(mockBackend.SignerCalls) != 1 {
				t.Errorf("expected 1 Signer call, got %d", len(mockBackend.SignerCalls))
			}
		})
	}
}

func TestCompositeKeyStore_Decrypter(t *testing.T) {
	tests := []struct {
		name         string
		setupBackend func(*keychain.KeyStore)
		attrs        *types.KeyAttributes
		expectError  bool
	}{
		{
			name: "valid decrypter",
			setupBackend: func(ks *keychain.KeyStore) {
				attrs := &types.KeyAttributes{
					CN:           "test-decrypter",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				_, _ = (*ks).GenerateRSA(attrs)
			},
			attrs: &types.KeyAttributes{
				CN:           "test-decrypter",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: false,
		},
		{
			name: "non-existent key",
			setupBackend: func(ks *keychain.KeyStore) {
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
			setupBackend: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			attrs:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer ks.Close()

			tt.setupBackend(&ks)

			// Reset call tracking
			mockBackend.DecrypterCalls = nil

			decrypter, err := ks.Decrypter(tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decrypter == nil {
				t.Fatal("expected decrypter, got nil")
			}

			// Verify backend was called
			if len(mockBackend.DecrypterCalls) != 1 {
				t.Errorf("expected 1 Decrypter call, got %d", len(mockBackend.DecrypterCalls))
			}
		})
	}
}

func TestCompositeKeyStore_GetTLSCertificate(t *testing.T) {
	tests := []struct {
		name          string
		setupKeyStore func(*keychain.KeyStore)
		keyID         string
		attrs         *types.KeyAttributes
		expectError   bool
	}{
		{
			name: "valid TLS certificate with chain",
			setupKeyStore: func(ks *keychain.KeyStore) {
				attrs := &types.KeyAttributes{
					CN:           "test-tls",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				_, _ = (*ks).GenerateRSA(attrs)
				cert := generateTestCert("test-tls")
				_ = (*ks).SaveCert("test-tls", cert)
				chain := []*x509.Certificate{cert, generateTestCert("intermediate")}
				_ = (*ks).SaveCertChain("test-tls", chain)
			},
			keyID: "test-tls",
			attrs: &types.KeyAttributes{
				CN:           "test-tls",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: false,
		},
		{
			name: "valid TLS certificate without chain",
			setupKeyStore: func(ks *keychain.KeyStore) {
				attrs := &types.KeyAttributes{
					CN:           "test-tls-no-chain",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				_, _ = (*ks).GenerateRSA(attrs)
				cert := generateTestCert("test-tls-no-chain")
				_ = (*ks).SaveCert("test-tls-no-chain", cert)
			},
			keyID: "test-tls-no-chain",
			attrs: &types.KeyAttributes{
				CN:           "test-tls-no-chain",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: false,
		},
		{
			name: "missing key",
			setupKeyStore: func(ks *keychain.KeyStore) {
				cert := generateTestCert("test-missing-key")
				_ = (*ks).SaveCert("test-missing-key", cert)
			},
			keyID: "test-missing-key",
			attrs: &types.KeyAttributes{
				CN:           "test-missing-key",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: true,
		},
		{
			name: "missing certificate",
			setupKeyStore: func(ks *keychain.KeyStore) {
				attrs := &types.KeyAttributes{
					CN:           "test-missing-cert",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				_, _ = (*ks).GenerateRSA(attrs)
			},
			keyID: "test-missing-cert",
			attrs: &types.KeyAttributes{
				CN:           "test-missing-cert",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: true,
		},
		{
			name: "empty keyID",
			setupKeyStore: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID: "",
			attrs: &types.KeyAttributes{
				CN:           "test",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: true,
		},
		{
			name: "nil attributes",
			setupKeyStore: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:       "test",
			attrs:       nil,
			expectError: true,
		},
		{
			name: "cert chain retrieval error falls back to certificate only",
			setupKeyStore: func(ks *keychain.KeyStore) {
				attrs := &types.KeyAttributes{
					CN:           "test-tls-chain-error",
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
				}
				_, _ = (*ks).GenerateRSA(attrs)
				cert := generateTestCert("test-tls-chain-error")
				_ = (*ks).SaveCert("test-tls-chain-error", cert)
				// Note: We don't save a cert chain, so GetCertChain will return error
				// This tests the error path (line 84) that falls back to just the leaf cert
			},
			keyID: "test-tls-chain-error",
			attrs: &types.KeyAttributes{
				CN:           "test-tls-chain-error",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.RSA,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _, _ := setupKeyStore()
			defer ks.Close()

			tt.setupKeyStore(&ks)

			tlsCert, err := ks.GetTLSCertificate(tt.keyID, tt.attrs)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tlsCert.PrivateKey == nil {
				t.Error("expected private key in TLS certificate, got nil")
			}

			if len(tlsCert.Certificate) == 0 {
				t.Error("expected certificate chain in TLS certificate, got empty")
			}

			if tlsCert.Leaf == nil {
				t.Error("expected leaf certificate in TLS certificate, got nil")
			}
		})
	}
}

// TestCompositeKeyStore_GetTLSCertificate_EmptyChain tests the case where GetCertChain returns an empty list
func TestCompositeKeyStore_GetTLSCertificate_EmptyChain(t *testing.T) {
	mockBackend := backmocks.NewMockBackend()
	mockStorage := storagemocks.NewMockCertStorage()

	// Mock GetCertChain to return an empty list (not an error, but empty data)
	// Note: Using "test-empty-list" as ID to avoid ambiguity with IDs ending in "-chain"
	cert := generateTestCert("test-empty-list")
	mockStorage.GetCertChainFunc = func(id string) ([]*x509.Certificate, error) {
		if id == "test-empty-list" {
			// Return empty chain without error - this is the edge case on line 88
			return []*x509.Certificate{}, nil
		}
		return nil, keychain.ErrCertNotFound
	}
	mockStorage.GetCertFunc = func(id string) (*x509.Certificate, error) {
		if id == "test-empty-list" {
			return cert, nil
		}
		return nil, keychain.ErrCertNotFound
	}

	// Mock backend to return a test key
	mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		if attrs.CN == "test-empty-list" {
			// Generate a real RSA key for testing
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			return key, nil
		}
		return nil, keychain.ErrKeyNotFound
	}

	// Create keystore with mocks
	ks, err := keychain.New(&keychain.Config{
		Backend:     mockBackend,
		CertStorage: mockStorage,
	})
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}
	defer ks.Close()

	// Call GetTLSCertificate - this should hit the len(chain) == 0 case
	attrs := &types.KeyAttributes{
		CN:           "test-empty-list",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
	}

	tlsCert, err := ks.GetTLSCertificate("test-empty-list", attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tlsCert.Certificate) == 0 {
		t.Error("expected certificate chain in TLS certificate, got empty")
	}

	if tlsCert.Leaf == nil {
		t.Error("expected leaf certificate in TLS certificate, got nil")
	}
}
