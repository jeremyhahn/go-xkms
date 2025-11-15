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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/keychain"
)

func generateTestCert(cn string) *x509.Certificate {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func TestCompositeKeyStore_SaveCert(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		cert        *x509.Certificate
		expectError bool
	}{
		{
			name:        "valid certificate",
			keyID:       "test-cert",
			cert:        generateTestCert("test-cert"),
			expectError: false,
		},
		{
			name:        "empty keyID",
			keyID:       "",
			cert:        generateTestCert("test-cert"),
			expectError: true,
		},
		{
			name:        "nil certificate",
			keyID:       "test-cert",
			cert:        nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _, certStorage := setupKeyStore()
			defer ks.Close()

			err := ks.SaveCert(tt.keyID, tt.cert)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify cert storage was called
			if len(certStorage.SaveCertCalls) != 1 {
				t.Errorf("expected 1 SaveCert call, got %d", len(certStorage.SaveCertCalls))
			}
		})
	}
}

func TestCompositeKeyStore_GetCert(t *testing.T) {
	tests := []struct {
		name         string
		setupStorage func(*keychain.KeyStore)
		keyID        string
		expectError  bool
	}{
		{
			name: "existing certificate",
			setupStorage: func(ks *keychain.KeyStore) {
				cert := generateTestCert("test-get-cert")
				_ = (*ks).SaveCert("test-get-cert", cert)
			},
			keyID:       "test-get-cert",
			expectError: false,
		},
		{
			name: "non-existent certificate",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:       "non-existent",
			expectError: true,
		},
		{
			name: "empty keyID",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _, certStorage := setupKeyStore()
			defer ks.Close()

			tt.setupStorage(&ks)

			cert, err := ks.GetCert(tt.keyID)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cert == nil {
				t.Fatal("expected certificate, got nil")
			}

			// Verify cert storage was called
			if len(certStorage.GetCertCalls) == 0 {
				t.Error("GetCert was not called on cert storage")
			}
		})
	}
}

func TestCompositeKeyStore_DeleteCert(t *testing.T) {
	tests := []struct {
		name         string
		setupStorage func(*keychain.KeyStore)
		keyID        string
		expectError  bool
	}{
		{
			name: "delete existing certificate",
			setupStorage: func(ks *keychain.KeyStore) {
				cert := generateTestCert("test-delete-cert")
				_ = (*ks).SaveCert("test-delete-cert", cert)
			},
			keyID:       "test-delete-cert",
			expectError: false,
		},
		{
			name: "delete non-existent certificate",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:       "non-existent",
			expectError: true,
		},
		{
			name: "empty keyID",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _, certStorage := setupKeyStore()
			defer ks.Close()

			tt.setupStorage(&ks)

			err := ks.DeleteCert(tt.keyID)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify cert storage was called
			if len(certStorage.DeleteCertCalls) == 0 {
				t.Error("DeleteCert was not called on cert storage")
			}
		})
	}
}

func TestCompositeKeyStore_SaveCertChain(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		chain       []*x509.Certificate
		expectError bool
	}{
		{
			name:  "valid chain",
			keyID: "test-chain",
			chain: []*x509.Certificate{
				generateTestCert("leaf"),
				generateTestCert("intermediate"),
				generateTestCert("root"),
			},
			expectError: false,
		},
		{
			name:        "empty keyID",
			keyID:       "",
			chain:       []*x509.Certificate{generateTestCert("leaf")},
			expectError: true,
		},
		{
			name:        "empty chain",
			keyID:       "test-chain",
			chain:       []*x509.Certificate{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _, certStorage := setupKeyStore()
			defer ks.Close()

			err := ks.SaveCertChain(tt.keyID, tt.chain)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify cert storage was called
			if len(certStorage.SaveCertChainCalls) != 1 {
				t.Errorf("expected 1 SaveCertChain call, got %d", len(certStorage.SaveCertChainCalls))
			}
		})
	}
}

func TestCompositeKeyStore_GetCertChain(t *testing.T) {
	tests := []struct {
		name         string
		setupStorage func(*keychain.KeyStore)
		keyID        string
		expectError  bool
	}{
		{
			name: "existing chain",
			setupStorage: func(ks *keychain.KeyStore) {
				chain := []*x509.Certificate{
					generateTestCert("leaf"),
					generateTestCert("intermediate"),
				}
				_ = (*ks).SaveCertChain("test-get-chain", chain)
			},
			keyID:       "test-get-chain",
			expectError: false,
		},
		{
			name: "non-existent chain",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:       "non-existent",
			expectError: true,
		},
		{
			name: "empty keyID",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _, certStorage := setupKeyStore()
			defer ks.Close()

			tt.setupStorage(&ks)

			chain, err := ks.GetCertChain(tt.keyID)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if chain == nil {
				t.Fatal("expected chain, got nil")
			}

			// Verify cert storage was called
			if len(certStorage.GetCertChainCalls) == 0 {
				t.Error("GetCertChain was not called on cert storage")
			}
		})
	}
}

func TestCompositeKeyStore_ListCerts(t *testing.T) {
	ks, _, certStorage := setupKeyStore()
	defer ks.Close()

	// Save some certificates
	for i := 0; i < 3; i++ {
		cert := generateTestCert("test-list-cert")
		_ = ks.SaveCert("test-list-cert", cert)
	}

	certs, err := ks.ListCerts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if certs == nil {
		t.Fatal("expected cert list, got nil")
	}

	// Verify cert storage was called
	if certStorage.ListCertsCalls != 1 {
		t.Errorf("expected 1 ListCerts call, got %d", certStorage.ListCertsCalls)
	}
}

func TestCompositeKeyStore_CertExists(t *testing.T) {
	tests := []struct {
		name         string
		setupStorage func(*keychain.KeyStore)
		keyID        string
		expectExists bool
		expectError  bool
	}{
		{
			name: "existing certificate",
			setupStorage: func(ks *keychain.KeyStore) {
				cert := generateTestCert("test-exists")
				_ = (*ks).SaveCert("test-exists", cert)
			},
			keyID:        "test-exists",
			expectExists: true,
			expectError:  false,
		},
		{
			name: "non-existent certificate",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:        "non-existent",
			expectExists: false,
			expectError:  false,
		},
		{
			name: "empty keyID",
			setupStorage: func(ks *keychain.KeyStore) {
				// No setup needed
			},
			keyID:        "",
			expectExists: false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _, certStorage := setupKeyStore()
			defer ks.Close()

			tt.setupStorage(&ks)

			exists, err := ks.CertExists(tt.keyID)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if exists != tt.expectExists {
				t.Errorf("expected exists=%v, got %v", tt.expectExists, exists)
			}

			// Verify cert storage was called
			if len(certStorage.CertExistsCalls) == 0 {
				t.Error("CertExists was not called on cert storage")
			}
		})
	}
}

// ========================================================================
// Edge Case Tests for Certificate Operations
// ========================================================================

func TestCompositeKeyStore_SaveCert_EdgeCases(t *testing.T) {
	t.Run("storage error", func(t *testing.T) {
		ks, _, certStorage := setupKeyStore()
		defer ks.Close()

		// Configure storage to return error
		certStorage.SaveCertFunc = func(id string, cert *x509.Certificate) error {
			return fmt.Errorf("disk full")
		}

		cert := generateTestCert("test-storage-error")
		err := ks.SaveCert("test-storage-error", cert)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to save certificate") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})
}

func TestCompositeKeyStore_GetCert_EdgeCases(t *testing.T) {
	t.Run("storage error", func(t *testing.T) {
		ks, _, certStorage := setupKeyStore()
		defer ks.Close()

		// Configure storage to return error
		certStorage.GetCertFunc = func(id string) (*x509.Certificate, error) {
			return nil, fmt.Errorf("certificate corrupted")
		}

		_, err := ks.GetCert("test-storage-error")

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to get certificate") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})
}

func TestCompositeKeyStore_DeleteCert_EdgeCases(t *testing.T) {
	t.Run("storage error", func(t *testing.T) {
		ks, _, certStorage := setupKeyStore()
		defer ks.Close()

		// Configure storage to return error
		certStorage.DeleteCertFunc = func(id string) error {
			return fmt.Errorf("certificate is locked")
		}

		err := ks.DeleteCert("test-delete-error")

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to delete certificate") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})
}

func TestCompositeKeyStore_SaveCertChain_EdgeCases(t *testing.T) {
	t.Run("storage error", func(t *testing.T) {
		ks, _, certStorage := setupKeyStore()
		defer ks.Close()

		// Configure storage to return error
		certStorage.SaveCertChainFunc = func(id string, chain []*x509.Certificate) error {
			return fmt.Errorf("chain too large")
		}

		chain := []*x509.Certificate{
			generateTestCert("leaf"),
			generateTestCert("intermediate"),
		}

		err := ks.SaveCertChain("test-chain-error", chain)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to save certificate chain") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})

	t.Run("nil chain", func(t *testing.T) {
		ks, _, _ := setupKeyStore()
		defer ks.Close()

		err := ks.SaveCertChain("test-nil-chain", nil)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "certificate chain cannot be empty") {
			t.Errorf("expected empty chain error, got: %v", err)
		}
	})
}

func TestCompositeKeyStore_GetCertChain_EdgeCases(t *testing.T) {
	t.Run("storage error", func(t *testing.T) {
		ks, _, certStorage := setupKeyStore()
		defer ks.Close()

		// Configure storage to return error
		certStorage.GetCertChainFunc = func(id string) ([]*x509.Certificate, error) {
			return nil, fmt.Errorf("chain validation failed")
		}

		_, err := ks.GetCertChain("test-chain-error")

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to get certificate chain") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})
}

func TestCompositeKeyStore_ListCerts_EdgeCases(t *testing.T) {
	t.Run("storage error", func(t *testing.T) {
		ks, _, certStorage := setupKeyStore()
		defer ks.Close()

		// Configure storage to return error
		certStorage.ListCertsFunc = func() ([]string, error) {
			return nil, fmt.Errorf("database connection lost")
		}

		_, err := ks.ListCerts()

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to list certificates") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		ks, _, _ := setupKeyStore()
		defer ks.Close()

		certs, err := ks.ListCerts()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if certs == nil {
			t.Fatal("expected empty slice, got nil")
		}

		if len(certs) != 0 {
			t.Errorf("expected 0 certificates, got %d", len(certs))
		}
	})
}

func TestCompositeKeyStore_CertExists_EdgeCases(t *testing.T) {
	t.Run("storage error", func(t *testing.T) {
		ks, _, certStorage := setupKeyStore()
		defer ks.Close()

		// Configure storage to return error
		certStorage.CertExistsFunc = func(id string) (bool, error) {
			return false, fmt.Errorf("storage unavailable")
		}

		_, err := ks.CertExists("test-exists-error")

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "failed to check if certificate exists") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})
}

// TestCompositeCertOperations_Integration tests comprehensive certificate workflows
func TestCompositeCertOperations_Integration(t *testing.T) {
	ks, _, _ := setupKeyStore()
	defer ks.Close()

	// Test full lifecycle: save, get, exists, delete
	t.Run("full lifecycle", func(t *testing.T) {
		keyID := "lifecycle-test"
		cert := generateTestCert(keyID)

		// Save
		if err := ks.SaveCert(keyID, cert); err != nil {
			t.Fatalf("SaveCert failed: %v", err)
		}

		// Verify exists
		exists, err := ks.CertExists(keyID)
		if err != nil {
			t.Fatalf("CertExists failed: %v", err)
		}
		if !exists {
			t.Error("certificate should exist after save")
		}

		// Get
		retrieved, err := ks.GetCert(keyID)
		if err != nil {
			t.Fatalf("GetCert failed: %v", err)
		}
		if retrieved == nil {
			t.Fatal("retrieved certificate is nil")
		}

		// Delete
		if err := ks.DeleteCert(keyID); err != nil {
			t.Fatalf("DeleteCert failed: %v", err)
		}

		// Verify doesn't exist
		exists, err = ks.CertExists(keyID)
		if err != nil {
			t.Fatalf("CertExists failed: %v", err)
		}
		if exists {
			t.Error("certificate should not exist after delete")
		}
	})

	// Test chain operations
	t.Run("chain lifecycle", func(t *testing.T) {
		keyID := "chain-lifecycle-test"
		chain := []*x509.Certificate{
			generateTestCert("leaf"),
			generateTestCert("intermediate"),
			generateTestCert("root"),
		}

		// Save chain
		if err := ks.SaveCertChain(keyID, chain); err != nil {
			t.Fatalf("SaveCertChain failed: %v", err)
		}

		// Get chain
		retrieved, err := ks.GetCertChain(keyID)
		if err != nil {
			t.Fatalf("GetCertChain failed: %v", err)
		}
		if len(retrieved) != len(chain) {
			t.Errorf("expected chain length %d, got %d", len(chain), len(retrieved))
		}
	})

	// Test multiple certificates
	t.Run("multiple certificates", func(t *testing.T) {
		certIDs := []string{"cert1", "cert2", "cert3"}

		// Save multiple certs
		for _, id := range certIDs {
			cert := generateTestCert(id)
			if err := ks.SaveCert(id, cert); err != nil {
				t.Fatalf("failed to save cert %s: %v", id, err)
			}
		}

		// List certificates
		list, err := ks.ListCerts()
		if err != nil {
			t.Fatalf("ListCerts failed: %v", err)
		}

		// Should have at least the 3 we added (may have more from other tests)
		if len(list) < 3 {
			t.Errorf("expected at least 3 certs, got %d", len(list))
		}

		// Cleanup
		for _, id := range certIDs {
			_ = ks.DeleteCert(id)
		}
	})
}
