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

package hardware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	storagepkg "github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper functions for testing

func generateTestCertificate(subject string) (*x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func generateTestCertificateChain(count int) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, count)
	for i := 0; i < count; i++ {
		cert, err := generateTestCertificate(fmt.Sprintf("test-cert-%d", i))
		if err != nil {
			return nil, err
		}
		chain[i] = cert
	}
	return chain, nil
}

// Test cases - Unit tests that don't require real PKCS#11 hardware

func TestNewPKCS11CertStorage_NilContext(t *testing.T) {
	storage, err := NewPKCS11CertStorage(
		nil,
		1,
		"test-token",
		0,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cannot be nil")
	assert.Nil(t, storage)
}

func TestPKCS11CertStorage_HelperFunctions(t *testing.T) {
	// Test helper functions that don't require PKCS#11 context
	storage := &PKCS11CertStorage{
		closed: false,
	}

	t.Run("chainID", func(t *testing.T) {
		id := "test-cert"
		expected := "test-cert-chain"
		assert.Equal(t, expected, storage.chainID(id))
	})

	t.Run("isChainCertificate", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
			want bool
		}{
			{"chain certificate", "test-chain-0", true},
			{"chain certificate 2", "test-chain-1", true},
			{"regular certificate", "test-cert", false},
			{"short ID", "test", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := storage.isChainCertificate(tt.id)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

func TestPKCS11CertStorage_InterfaceMethods(t *testing.T) {
	// Test interface methods with a closed storage (doesn't require PKCS#11 context)
	storage := &PKCS11CertStorage{
		closed: true,
	}

	cert, err := generateTestCertificate("test")
	require.NoError(t, err)

	chain, err := generateTestCertificateChain(2)
	require.NoError(t, err)

	t.Run("SaveCert on closed storage", func(t *testing.T) {
		err := storage.SaveCert("test", cert)
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("GetCert on closed storage", func(t *testing.T) {
		_, err := storage.GetCert("test")
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("DeleteCert on closed storage", func(t *testing.T) {
		err := storage.DeleteCert("test")
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("SaveCertChain on closed storage", func(t *testing.T) {
		err := storage.SaveCertChain("test", chain)
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("GetCertChain on closed storage", func(t *testing.T) {
		_, err := storage.GetCertChain("test")
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("ListCerts on closed storage", func(t *testing.T) {
		_, err := storage.ListCerts()
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("CertExists on closed storage", func(t *testing.T) {
		_, err := storage.CertExists("test")
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("GetCapacity on closed storage", func(t *testing.T) {
		_, _, err := storage.GetCapacity()
		assert.ErrorIs(t, err, ErrStorageClosed)
	})

	t.Run("SupportsChains", func(t *testing.T) {
		assert.True(t, storage.SupportsChains())
	})

	t.Run("IsHardwareBacked", func(t *testing.T) {
		assert.True(t, storage.IsHardwareBacked())
	})

	t.Run("Compact", func(t *testing.T) {
		err := storage.Compact()
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("Close is idempotent", func(t *testing.T) {
		err := storage.Close()
		require.NoError(t, err)

		// Close again
		err = storage.Close()
		require.NoError(t, err)
	})
}

func TestPKCS11CertStorage_Validation(t *testing.T) {
	// Test input validation without requiring PKCS#11 context
	storage := &PKCS11CertStorage{
		closed: false,
	}

	t.Run("SaveCert with empty ID", func(t *testing.T) {
		cert, err := generateTestCertificate("test")
		require.NoError(t, err)

		err = storage.SaveCert("", cert)
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidID)
	})

	t.Run("SaveCert with nil cert", func(t *testing.T) {
		err := storage.SaveCert("test", nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidData)
	})

	t.Run("GetCert with empty ID", func(t *testing.T) {
		_, err := storage.GetCert("")
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidID)
	})

	t.Run("DeleteCert with empty ID", func(t *testing.T) {
		err := storage.DeleteCert("")
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidID)
	})

	t.Run("SaveCertChain with empty ID", func(t *testing.T) {
		chain, err := generateTestCertificateChain(2)
		require.NoError(t, err)

		err = storage.SaveCertChain("", chain)
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidID)
	})

	t.Run("SaveCertChain with empty chain", func(t *testing.T) {
		err := storage.SaveCertChain("test", []*x509.Certificate{})
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidData)
	})

	t.Run("SaveCertChain with nil chain", func(t *testing.T) {
		err := storage.SaveCertChain("test", nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidData)
	})

	t.Run("SaveCertChain with nil certificate in chain", func(t *testing.T) {
		chain := []*x509.Certificate{nil, nil}
		err := storage.SaveCertChain("test", chain)
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidData)
	})

	t.Run("GetCertChain with empty ID", func(t *testing.T) {
		_, err := storage.GetCertChain("")
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidID)
	})

	t.Run("CertExists with empty ID", func(t *testing.T) {
		_, err := storage.CertExists("")
		assert.Error(t, err)
		assert.ErrorIs(t, err, storagepkg.ErrInvalidID)
	})
}

func TestPKCS11CertStorage_InterfaceCompliance(t *testing.T) {
	var _ HardwareCertStorage = (*PKCS11CertStorage)(nil)
}

// TestGenerateTestCertificate tests the test helper function
func TestGenerateTestCertificate(t *testing.T) {
	cert, err := generateTestCertificate("test-subject")
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, "test-subject", cert.Subject.CommonName)
	assert.Equal(t, []string{"Test Organization"}, cert.Subject.Organization)
	assert.True(t, cert.NotBefore.Before(time.Now()))
	assert.True(t, cert.NotAfter.After(time.Now()))
}

// TestGenerateTestCertificateChain tests the test helper function
func TestGenerateTestCertificateChain(t *testing.T) {
	chain, err := generateTestCertificateChain(3)
	require.NoError(t, err)
	require.NotNil(t, chain)
	assert.Equal(t, 3, len(chain))

	for i, cert := range chain {
		assert.NotNil(t, cert)
		expected := fmt.Sprintf("test-cert-%d", i)
		assert.Equal(t, expected, cert.Subject.CommonName)
	}
}

// Additional unit tests for edge cases and helper functions
// Note: These tests focus on validation and helpers that don't require PKCS#11 context

// Test: chainID helper function
func TestPKCS11CertStorage_ChainIDHelper(t *testing.T) {
	storage := &PKCS11CertStorage{}

	tests := []struct {
		input    string
		expected string
	}{
		{"test", "test-chain"},
		{"my-cert", "my-cert-chain"},
		{"", "-chain"},
		{"a", "a-chain"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := storage.chainID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test: isChainCertificate helper function
func TestPKCS11CertStorage_IsChainCertificateHelper(t *testing.T) {
	storage := &PKCS11CertStorage{}

	tests := []struct {
		id       string
		expected bool
	}{
		{"test-chain-0", true},
		{"test-chain-1", true},
		{"test-chain-999", true},
		{"test-chain-", false}, // Has chain but no digit after
		{"test-cert", false},
		{"chain-test", false}, // Chain not followed by dash
		{"test", false},
		{"", false},
		{"test-chai", false},       // Incomplete chain suffix
		{"myapp-chain-id-0", true}, // Multiple dashes with chain pattern
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := storage.isChainCertificate(tt.id)
			assert.Equal(t, tt.expected, result, "ID: %s", tt.id)
		})
	}
}

// Test: GetCapacity on closed storage
func TestPKCS11CertStorage_GetCapacityOnClosed(t *testing.T) {
	storage := &PKCS11CertStorage{closed: true}

	total, available, err := storage.GetCapacity()
	assert.ErrorIs(t, err, ErrStorageClosed)
	assert.Equal(t, 0, total)
	assert.Equal(t, 0, available)
}

// Test: Multiple operations on closed storage
func TestPKCS11CertStorage_MultipleOpsOnClosed(t *testing.T) {
	storage := &PKCS11CertStorage{closed: true}

	// All operations should return ErrStorageClosed
	_, err := storage.GetCert("test")
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = storage.ListCerts()
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = storage.CertExists("test")
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = storage.GetCertChain("test")
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = storage.DeleteCert("test")
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = storage.SaveCert("test", nil)
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = storage.SaveCertChain("test", nil)
	assert.ErrorIs(t, err, ErrStorageClosed)
}
