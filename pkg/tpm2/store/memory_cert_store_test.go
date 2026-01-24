// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCertLogger creates a logger for certificate store testing
func testCertLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}

// generateTestCertificatePEM creates a PEM-encoded self-signed certificate for testing
func generateTestCertificatePEM(t *testing.T, cn string) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	return pem.EncodeToMemory(pemBlock)
}

// =============================================================================
// MemoryCertStore Tests
// =============================================================================

func TestMemoryCertStore_NewMemoryCertStore(t *testing.T) {
	logger := testCertLogger()

	store := NewMemoryCertStore(logger)

	assert.NotNil(t, store)
	assert.NotNil(t, store.certs)
	assert.Equal(t, logger, store.logger)
}

func TestMemoryCertStore_certKey(t *testing.T) {
	logger := testCertLogger()
	store := NewMemoryCertStore(logger)

	t.Run("nil attributes returns empty string", func(t *testing.T) {
		key := store.certKey(nil)
		assert.Equal(t, "", key)
	})

	t.Run("attributes without parent", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "test-cert",
		}
		key := store.certKey(attrs)
		assert.Equal(t, "test-cert", key)
	})

	t.Run("attributes with parent", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "child-cert",
			Parent: &types.KeyAttributes{
				CN: "parent-cert",
			},
		}
		key := store.certKey(attrs)
		assert.Equal(t, "parent-cert/child-cert", key)
	})

	t.Run("attributes with parent but empty parent CN", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "child-cert",
			Parent: &types.KeyAttributes{
				CN: "",
			},
		}
		key := store.certKey(attrs)
		assert.Equal(t, "child-cert", key)
	})
}

func TestMemoryCertStore_Get(t *testing.T) {
	logger := testCertLogger()
	store := NewMemoryCertStore(logger)

	t.Run("get with nil attributes returns error", func(t *testing.T) {
		cert, err := store.Get(nil)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Equal(t, ErrInvalidKeyAttributes, err)
	})

	t.Run("get non-existent certificate returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "non-existent-cert",
		}
		cert, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Equal(t, ErrCertNotFound, err)
	})

	t.Run("get existing certificate", func(t *testing.T) {
		testCert := generateTestCertificate(t, "test-get-cert")
		attrs := &types.KeyAttributes{
			CN: "test-get-cert",
		}

		// Save first
		err := store.Save(attrs, testCert)
		require.NoError(t, err)

		// Get it back
		retrievedCert, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, retrievedCert)
		assert.Equal(t, testCert.Subject.CommonName, retrievedCert.Subject.CommonName)
	})

	t.Run("get certificate with parent key", func(t *testing.T) {
		testCert := generateTestCertificate(t, "child-get-cert")
		attrs := &types.KeyAttributes{
			CN: "child-get-cert",
			Parent: &types.KeyAttributes{
				CN: "parent-get-cert",
			},
		}

		// Save first
		err := store.Save(attrs, testCert)
		require.NoError(t, err)

		// Get it back
		retrievedCert, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, retrievedCert)
		assert.Equal(t, testCert.Subject.CommonName, retrievedCert.Subject.CommonName)
	})
}

func TestMemoryCertStore_Save(t *testing.T) {
	logger := testCertLogger()
	store := NewMemoryCertStore(logger)

	t.Run("save with nil attributes returns error", func(t *testing.T) {
		testCert := generateTestCertificate(t, "save-nil-attrs")
		err := store.Save(nil, testCert)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidKeyAttributes, err)
	})

	t.Run("save nil certificate returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "nil-cert",
		}
		err := store.Save(attrs, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate is nil")
	})

	t.Run("save certificate successfully", func(t *testing.T) {
		testCert := generateTestCertificate(t, "save-test-cert")
		attrs := &types.KeyAttributes{
			CN: "save-test-cert",
		}

		err := store.Save(attrs, testCert)
		assert.NoError(t, err)

		// Verify it was saved
		retrievedCert, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.Equal(t, testCert.Subject.CommonName, retrievedCert.Subject.CommonName)
	})

	t.Run("save certificate with parent key", func(t *testing.T) {
		testCert := generateTestCertificate(t, "save-child-cert")
		attrs := &types.KeyAttributes{
			CN: "save-child-cert",
			Parent: &types.KeyAttributes{
				CN: "save-parent-cert",
			},
		}

		err := store.Save(attrs, testCert)
		assert.NoError(t, err)

		// Verify it was saved
		retrievedCert, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.Equal(t, testCert.Subject.CommonName, retrievedCert.Subject.CommonName)
	})

	t.Run("overwrite existing certificate", func(t *testing.T) {
		cert1 := generateTestCertificate(t, "overwrite-cert-1")
		cert2 := generateTestCertificate(t, "overwrite-cert-2")
		attrs := &types.KeyAttributes{
			CN: "overwrite-cert",
		}

		// Save first certificate
		err := store.Save(attrs, cert1)
		require.NoError(t, err)

		// Overwrite with second certificate
		err = store.Save(attrs, cert2)
		assert.NoError(t, err)

		// Verify the second certificate is stored
		retrievedCert, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.Equal(t, cert2.Subject.CommonName, retrievedCert.Subject.CommonName)
	})
}

func TestMemoryCertStore_Delete(t *testing.T) {
	logger := testCertLogger()
	store := NewMemoryCertStore(logger)

	t.Run("delete with nil attributes returns error", func(t *testing.T) {
		err := store.Delete(nil)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidKeyAttributes, err)
	})

	t.Run("delete non-existent certificate returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "non-existent-delete",
		}
		err := store.Delete(attrs)
		assert.Error(t, err)
		assert.Equal(t, ErrCertNotFound, err)
	})

	t.Run("delete existing certificate", func(t *testing.T) {
		testCert := generateTestCertificate(t, "delete-test-cert")
		attrs := &types.KeyAttributes{
			CN: "delete-test-cert",
		}

		// Save first
		err := store.Save(attrs, testCert)
		require.NoError(t, err)

		// Verify it exists
		_, err = store.Get(attrs)
		require.NoError(t, err)

		// Delete it
		err = store.Delete(attrs)
		assert.NoError(t, err)

		// Verify it's gone
		_, err = store.Get(attrs)
		assert.Error(t, err)
		assert.Equal(t, ErrCertNotFound, err)
	})

	t.Run("delete certificate with parent key", func(t *testing.T) {
		testCert := generateTestCertificate(t, "delete-child-cert")
		attrs := &types.KeyAttributes{
			CN: "delete-child-cert",
			Parent: &types.KeyAttributes{
				CN: "delete-parent-cert",
			},
		}

		// Save first
		err := store.Save(attrs, testCert)
		require.NoError(t, err)

		// Delete it
		err = store.Delete(attrs)
		assert.NoError(t, err)

		// Verify it's gone
		_, err = store.Get(attrs)
		assert.Error(t, err)
		assert.Equal(t, ErrCertNotFound, err)
	})
}

func TestMemoryCertStore_ImportCertificate(t *testing.T) {
	logger := testCertLogger()
	store := NewMemoryCertStore(logger)

	t.Run("import with nil attributes returns error", func(t *testing.T) {
		certPEM := generateTestCertificatePEM(t, "import-nil-attrs")
		cert, err := store.ImportCertificate(nil, certPEM)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Equal(t, ErrInvalidKeyAttributes, err)
	})

	t.Run("import invalid PEM returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "import-invalid-pem",
		}
		cert, err := store.ImportCertificate(attrs, []byte("not valid pem"))
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("import invalid certificate data returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "import-invalid-cert",
		}
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid certificate data"),
		})
		cert, err := store.ImportCertificate(attrs, invalidPEM)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})

	t.Run("import valid certificate successfully", func(t *testing.T) {
		certPEM := generateTestCertificatePEM(t, "import-valid-cert")
		attrs := &types.KeyAttributes{
			CN: "import-valid-cert",
		}

		cert, err := store.ImportCertificate(attrs, certPEM)
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, "import-valid-cert", cert.Subject.CommonName)

		// Verify it was stored
		retrievedCert, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)
	})

	t.Run("import certificate with parent key", func(t *testing.T) {
		certPEM := generateTestCertificatePEM(t, "import-child-cert")
		attrs := &types.KeyAttributes{
			CN: "import-child-cert",
			Parent: &types.KeyAttributes{
				CN: "import-parent-cert",
			},
		}

		cert, err := store.ImportCertificate(attrs, certPEM)
		assert.NoError(t, err)
		assert.NotNil(t, cert)

		// Verify it was stored
		retrievedCert, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.Equal(t, cert.Subject.CommonName, retrievedCert.Subject.CommonName)
	})
}

func TestMemoryCertStore_ConcurrentAccess(t *testing.T) {
	logger := testCertLogger()
	store := NewMemoryCertStore(logger)

	// Test concurrent reads and writes
	done := make(chan bool)

	// Start concurrent writers
	for i := 0; i < 10; i++ {
		go func(id int) {
			cert := generateTestCertificate(t, "concurrent-cert")
			attrs := &types.KeyAttributes{
				CN: "concurrent-cert",
			}
			_ = store.Save(attrs, cert)
			done <- true
		}(i)
	}

	// Start concurrent readers
	for i := 0; i < 10; i++ {
		go func(id int) {
			attrs := &types.KeyAttributes{
				CN: "concurrent-cert",
			}
			_, _ = store.Get(attrs)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestMemoryCertStore_InterfaceCompliance(t *testing.T) {
	// Verify MemoryCertStore implements CertificateStorer interface
	var _ CertificateStorer = (*MemoryCertStore)(nil)
}
