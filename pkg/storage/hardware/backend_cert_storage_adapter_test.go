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

package hardware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertForBackendAdapter creates a test certificate
func generateTestCertForBackendAdapter(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestNewBackendCertStorageAdapter tests the constructor
func TestNewBackendCertStorageAdapter(t *testing.T) {
	backend := storage.NewMemory()
	adapter := NewBackendCertStorageAdapter(backend)

	require.NotNil(t, adapter)
	assert.Implements(t, (*HardwareCertStorage)(nil), adapter)
}

// TestBackendCertStorageAdapter_SaveCert tests SaveCert operation
func TestBackendCertStorageAdapter_SaveCert(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")

		err := adapter.SaveCert("test-cert", cert)
		require.NoError(t, err)

		// Verify stored in backend
		data, err := backend.Get(context.Background(), "certs/test-cert.pem")
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, data)
	})

	t.Run("EmptyID", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")

		err := adapter.SaveCert("", cert)
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("NilCertificate", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.SaveCert("test-cert", nil)
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidData, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")

		err := adapter.Close()
		require.NoError(t, err)

		err = adapter.SaveCert("test-cert", cert)
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestBackendCertStorageAdapter_GetCert tests GetCert operation
func TestBackendCertStorageAdapter_GetCert(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")
		err := adapter.SaveCert("test-cert", cert)
		require.NoError(t, err)

		retrieved, err := adapter.GetCert("test-cert")
		require.NoError(t, err)
		assert.True(t, cert.Equal(retrieved))
	})

	t.Run("EmptyID", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		_, err := adapter.GetCert("")
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("NotFound", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		_, err := adapter.GetCert("nonexistent")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.Close()
		require.NoError(t, err)

		_, err = adapter.GetCert("test-cert")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})

	t.Run("InvalidStoredData", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		// Store invalid data directly
		err := backend.Put(context.Background(), "certs/test-cert.pem", []byte("invalid cert data"))
		require.NoError(t, err)

		_, err = adapter.GetCert("test-cert")
		require.Error(t, err)
		// Should be wrapped in OperationError
		assert.Contains(t, err.Error(), "parse certificate")
	})
}

// TestBackendCertStorageAdapter_DeleteCert tests DeleteCert operation
func TestBackendCertStorageAdapter_DeleteCert(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")
		err := adapter.SaveCert("test-cert", cert)
		require.NoError(t, err)

		err = adapter.DeleteCert("test-cert")
		require.NoError(t, err)

		// Verify deleted
		_, err = adapter.GetCert("test-cert")
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("EmptyID", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.DeleteCert("")
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.Close()
		require.NoError(t, err)

		err = adapter.DeleteCert("test-cert")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestBackendCertStorageAdapter_SaveCertChain tests SaveCertChain operation
func TestBackendCertStorageAdapter_SaveCertChain(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert1 := generateTestCertForBackendAdapter(t, "cert1")
		cert2 := generateTestCertForBackendAdapter(t, "cert2")
		chain := []*x509.Certificate{cert1, cert2}

		err := adapter.SaveCertChain("test-chain", chain)
		require.NoError(t, err)

		// Verify stored
		retrieved, err := adapter.GetCertChain("test-chain")
		require.NoError(t, err)
		assert.Len(t, retrieved, 2)
	})

	t.Run("EmptyID", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")
		chain := []*x509.Certificate{cert}

		err := adapter.SaveCertChain("", chain)
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("EmptyChain", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.SaveCertChain("test-chain", []*x509.Certificate{})
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidData, err)
	})

	t.Run("NilCertInChain", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")
		chain := []*x509.Certificate{cert, nil}

		err := adapter.SaveCertChain("test-chain", chain)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate at index 1 is nil")
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")
		chain := []*x509.Certificate{cert}

		err := adapter.Close()
		require.NoError(t, err)

		err = adapter.SaveCertChain("test-chain", chain)
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestBackendCertStorageAdapter_GetCertChain tests GetCertChain operation
func TestBackendCertStorageAdapter_GetCertChain(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert1 := generateTestCertForBackendAdapter(t, "cert1")
		cert2 := generateTestCertForBackendAdapter(t, "cert2")
		chain := []*x509.Certificate{cert1, cert2}

		err := adapter.SaveCertChain("test-chain", chain)
		require.NoError(t, err)

		retrieved, err := adapter.GetCertChain("test-chain")
		require.NoError(t, err)
		assert.Len(t, retrieved, 2)
		assert.True(t, cert1.Equal(retrieved[0]))
		assert.True(t, cert2.Equal(retrieved[1]))
	})

	t.Run("EmptyID", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		_, err := adapter.GetCertChain("")
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("NotFound", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		_, err := adapter.GetCertChain("nonexistent")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.Close()
		require.NoError(t, err)

		_, err = adapter.GetCertChain("test-chain")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})

	t.Run("InvalidStoredChainData", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		// Store invalid data directly
		err := backend.Put(context.Background(), "certs/test-chain-chain.pem", []byte("invalid chain data"))
		require.NoError(t, err)

		_, err = adapter.GetCertChain("test-chain")
		require.Error(t, err)
		// Should be wrapped in OperationError
		assert.Contains(t, err.Error(), "parse certificate chain")
	})

	t.Run("EmptyStoredChainData", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		// Store empty data directly
		err := backend.Put(context.Background(), "certs/test-chain-chain.pem", []byte{})
		require.NoError(t, err)

		_, err = adapter.GetCertChain("test-chain")
		require.Error(t, err)
		assert.Equal(t, ErrInvalidCertificate, err)
	})
}

// TestBackendCertStorageAdapter_ListCerts tests ListCerts operation
func TestBackendCertStorageAdapter_ListCerts(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert1 := generateTestCertForBackendAdapter(t, "cert1")
		cert2 := generateTestCertForBackendAdapter(t, "cert2")

		err := adapter.SaveCert("cert-a", cert1)
		require.NoError(t, err)
		err = adapter.SaveCert("cert-b", cert2)
		require.NoError(t, err)

		ids, err := adapter.ListCerts()
		require.NoError(t, err)
		assert.Len(t, ids, 2)
		assert.Contains(t, ids, "cert-a")
		assert.Contains(t, ids, "cert-b")
	})

	t.Run("Empty", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		ids, err := adapter.ListCerts()
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.Close()
		require.NoError(t, err)

		_, err = adapter.ListCerts()
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})

	t.Run("FiltersNonCertKeys", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")
		err := adapter.SaveCert("test-cert", cert)
		require.NoError(t, err)

		// Add non-cert data
		err = backend.Put(context.Background(), "keys/some-key.key", []byte("key data"))
		require.NoError(t, err)
		err = backend.Put(context.Background(), "certs/invalid-no-suffix", []byte("data"))
		require.NoError(t, err)

		ids, err := adapter.ListCerts()
		require.NoError(t, err)
		assert.Len(t, ids, 1)
		assert.Contains(t, ids, "test-cert")
	})
}

// TestBackendCertStorageAdapter_CertExists tests CertExists operation
func TestBackendCertStorageAdapter_CertExists(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		cert := generateTestCertForBackendAdapter(t, "test")
		err := adapter.SaveCert("test-cert", cert)
		require.NoError(t, err)

		exists, err := adapter.CertExists("test-cert")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("NotExists", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		exists, err := adapter.CertExists("nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("EmptyID", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		_, err := adapter.CertExists("")
		require.Error(t, err)
		assert.Equal(t, storage.ErrInvalidID, err)
	})

	t.Run("ClosedStorage", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.Close()
		require.NoError(t, err)

		_, err = adapter.CertExists("test-cert")
		require.Error(t, err)
		assert.Equal(t, ErrStorageClosed, err)
	})
}

// TestBackendCertStorageAdapter_Close tests Close operation
func TestBackendCertStorageAdapter_Close(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.Close()
		require.NoError(t, err)
	})

	t.Run("Idempotent", func(t *testing.T) {
		backend := storage.NewMemory()
		adapter := NewBackendCertStorageAdapter(backend)

		err := adapter.Close()
		require.NoError(t, err)

		// Close again should return nil
		err = adapter.Close()
		require.NoError(t, err)
	})
}

// TestBackendCertStorageAdapter_GetCapacity tests GetCapacity operation
func TestBackendCertStorageAdapter_GetCapacity(t *testing.T) {
	backend := storage.NewMemory()
	adapter := NewBackendCertStorageAdapter(backend)

	total, available, err := adapter.GetCapacity()
	require.Error(t, err)
	assert.Equal(t, ErrNotSupported, err)
	assert.Equal(t, 0, total)
	assert.Equal(t, 0, available)
}

// TestBackendCertStorageAdapter_SupportsChains tests SupportsChains
func TestBackendCertStorageAdapter_SupportsChains(t *testing.T) {
	backend := storage.NewMemory()
	adapter := NewBackendCertStorageAdapter(backend)

	assert.True(t, adapter.SupportsChains())
}

// TestBackendCertStorageAdapter_IsHardwareBacked tests IsHardwareBacked
func TestBackendCertStorageAdapter_IsHardwareBacked(t *testing.T) {
	backend := storage.NewMemory()
	adapter := NewBackendCertStorageAdapter(backend)

	assert.False(t, adapter.IsHardwareBacked())
}

// TestBackendCertStorageAdapter_Compact tests Compact operation
func TestBackendCertStorageAdapter_Compact(t *testing.T) {
	backend := storage.NewMemory()
	adapter := NewBackendCertStorageAdapter(backend)

	err := adapter.Compact()
	require.Error(t, err)
	assert.Equal(t, ErrNotSupported, err)
}

// TestBackendCertStorageAdapter_InterfaceCompliance verifies interface implementation
func TestBackendCertStorageAdapter_InterfaceCompliance(t *testing.T) {
	var _ HardwareCertStorage = (*BackendCertStorageAdapter)(nil)
}
