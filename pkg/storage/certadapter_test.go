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

package storage_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCert creates a simple self-signed certificate for testing.
func createTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

func TestCertAdapter_SaveAndGetCert(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	// Save certificate
	err := adapter.SaveCert(ctx, "test-id", cert)
	require.NoError(t, err)

	// Retrieve certificate
	retrieved, err := adapter.GetCert(ctx, "test-id")
	require.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, cert.Subject.CommonName, retrieved.Subject.CommonName)
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
}

func TestCertAdapter_DeleteCert(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	// Save certificate
	err := adapter.SaveCert(ctx, "test-id", cert)
	require.NoError(t, err)

	// Verify it exists
	exists, err := adapter.CertExists(ctx, "test-id")
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete certificate
	err = adapter.DeleteCert(ctx, "test-id")
	require.NoError(t, err)

	// Verify it no longer exists
	exists, err = adapter.CertExists(ctx, "test-id")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestCertAdapter_SaveAndGetCertChain(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Create a chain of certificates
	cert1 := createTestCert(t, "cert1")
	cert2 := createTestCert(t, "cert2")
	cert3 := createTestCert(t, "cert3")
	chain := []*x509.Certificate{cert1, cert2, cert3}

	// Save chain
	err := adapter.SaveCertChain(ctx, "chain-id", chain)
	require.NoError(t, err)

	// Retrieve chain
	retrieved, err := adapter.GetCertChain(ctx, "chain-id")
	require.NoError(t, err)
	require.Len(t, retrieved, 3)
	assert.Equal(t, cert1.Subject.CommonName, retrieved[0].Subject.CommonName)
	assert.Equal(t, cert2.Subject.CommonName, retrieved[1].Subject.CommonName)
	assert.Equal(t, cert3.Subject.CommonName, retrieved[2].Subject.CommonName)
}

func TestCertAdapter_ListCerts(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Save multiple certificates
	cert1 := createTestCert(t, "cert1")
	cert2 := createTestCert(t, "cert2")
	cert3 := createTestCert(t, "cert3")

	err := adapter.SaveCert(ctx, "id1", cert1)
	require.NoError(t, err)
	err = adapter.SaveCert(ctx, "id2", cert2)
	require.NoError(t, err)
	err = adapter.SaveCert(ctx, "id3", cert3)
	require.NoError(t, err)

	// List all certificates
	ids, err := adapter.ListCerts(ctx)
	require.NoError(t, err)
	assert.Len(t, ids, 3)
	assert.Contains(t, ids, "id1")
	assert.Contains(t, ids, "id2")
	assert.Contains(t, ids, "id3")
}

func TestCertAdapter_CertExists(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	// Check non-existent certificate
	exists, err := adapter.CertExists(ctx, "test-id")
	require.NoError(t, err)
	assert.False(t, exists)

	// Save certificate
	err = adapter.SaveCert(ctx, "test-id", cert)
	require.NoError(t, err)

	// Check existing certificate
	exists, err = adapter.CertExists(ctx, "test-id")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestCertAdapter_ErrorCases(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	t.Run("SaveCert with nil certificate", func(t *testing.T) {
		err := adapter.SaveCert(ctx, "test-id", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate cannot be nil")
	})

	t.Run("SaveCertChain with empty chain", func(t *testing.T) {
		err := adapter.SaveCertChain(ctx, "chain-id", []*x509.Certificate{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate chain cannot be empty")
	})

	t.Run("SaveCertChain with nil certificate in chain", func(t *testing.T) {
		cert1 := createTestCert(t, "cert1")
		chain := []*x509.Certificate{cert1, nil}
		err := adapter.SaveCertChain(ctx, "chain-id", chain)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate at index 1 is nil")
	})

	t.Run("GetCert with non-existent ID", func(t *testing.T) {
		_, err := adapter.GetCert(ctx, "non-existent")
		assert.Error(t, err)
	})

	t.Run("GetCertChain with non-existent ID", func(t *testing.T) {
		_, err := adapter.GetCertChain(ctx, "non-existent")
		assert.Error(t, err)
	})

	t.Run("DeleteCert with non-existent ID", func(t *testing.T) {
		err := adapter.DeleteCert(ctx, "non-existent")
		assert.Error(t, err)
	})
}

// TestCertAdapter_Backend tests the Backend() accessor method.
func TestCertAdapter_Backend(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	retrievedBackend := adapter.Backend()
	assert.NotNil(t, retrievedBackend)
	assert.Equal(t, backend, retrievedBackend)
}

// TestCertAdapter_InvalidID tests empty ID validation across all methods.
func TestCertAdapter_InvalidID(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	t.Run("SaveCert empty ID", func(t *testing.T) {
		err := adapter.SaveCert(ctx, "", cert)
		assert.ErrorIs(t, err, storage.ErrInvalidID)
	})

	t.Run("GetCert empty ID", func(t *testing.T) {
		_, err := adapter.GetCert(ctx, "")
		assert.ErrorIs(t, err, storage.ErrInvalidID)
	})

	t.Run("DeleteCert empty ID", func(t *testing.T) {
		err := adapter.DeleteCert(ctx, "")
		assert.ErrorIs(t, err, storage.ErrInvalidID)
	})

	t.Run("SaveCertChain empty ID", func(t *testing.T) {
		chain := []*x509.Certificate{cert}
		err := adapter.SaveCertChain(ctx, "", chain)
		assert.ErrorIs(t, err, storage.ErrInvalidID)
	})

	t.Run("GetCertChain empty ID", func(t *testing.T) {
		_, err := adapter.GetCertChain(ctx, "")
		assert.ErrorIs(t, err, storage.ErrInvalidID)
	})

	t.Run("CertExists empty ID", func(t *testing.T) {
		exists, err := adapter.CertExists(ctx, "")
		assert.ErrorIs(t, err, storage.ErrInvalidID)
		assert.False(t, exists)
	})
}

// TestCertAdapter_SaveCert_EmptyRawData tests SaveCert with certificate missing raw data.
func TestCertAdapter_SaveCert_EmptyRawData(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	err := adapter.SaveCert(ctx, "test-id", cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate has no raw data")
}

// TestCertAdapter_GetCert_InvalidData tests GetCert with invalid certificate data in backend.
func TestCertAdapter_GetCert_InvalidData(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	certPath := storage.CertPath("test-id")
	err := backend.Put(ctx, certPath, []byte("invalid certificate data"))
	require.NoError(t, err)

	_, err = adapter.GetCert(ctx, "test-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// TestCertAdapter_SaveCertChain_CertWithNoRawData tests SaveCertChain with cert missing raw data.
func TestCertAdapter_SaveCertChain_CertWithNoRawData(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert1 := createTestCert(t, "cert1")
	cert2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "cert2",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	chain := []*x509.Certificate{cert1, cert2}
	err := adapter.SaveCertChain(ctx, "chain-id", chain)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 1 has no raw data")
}

// TestCertAdapter_GetCertChain_InvalidData tests GetCertChain with invalid data in backend.
func TestCertAdapter_GetCertChain_InvalidData(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	chainPath := storage.CertChainPath("chain-id")
	err := backend.Put(ctx, chainPath, []byte("invalid chain data"))
	require.NoError(t, err)

	_, err = adapter.GetCertChain(ctx, "chain-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate chain")
}

// mockErrorBackend is a backend that returns configured errors for testing.
type mockErrorBackend struct {
	getErr    error
	putErr    error
	deleteErr error
	existsErr error
	listErr   error
}

func (m *mockErrorBackend) Get(_ context.Context, key string) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return nil, storage.ErrNotFound
}

func (m *mockErrorBackend) Put(_ context.Context, key string, value []byte) error {
	if m.putErr != nil {
		return m.putErr
	}
	return nil
}

func (m *mockErrorBackend) Delete(_ context.Context, key string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return storage.ErrNotFound
}

func (m *mockErrorBackend) Exists(_ context.Context, key string) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	return false, nil
}

func (m *mockErrorBackend) List(_ context.Context, prefix string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return nil, nil
}

func (m *mockErrorBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	if m.listErr != nil {
		return m.listErr
	}
	return nil
}

func (m *mockErrorBackend) Close() error {
	return nil
}

// TestCertAdapter_BackendErrors tests all methods when the backend returns errors.
func TestCertAdapter_BackendErrors(t *testing.T) {
	ctx := context.Background()
	cert := createTestCert(t, "test-cert")

	t.Run("GetCert backend error", func(t *testing.T) {
		backend := &mockErrorBackend{getErr: storage.ErrClosed}
		adapter := storage.NewCertAdapter(backend)
		_, err := adapter.GetCert(ctx, "test-id")
		assert.ErrorIs(t, err, storage.ErrClosed)
	})

	t.Run("DeleteCert backend error", func(t *testing.T) {
		backend := &mockErrorBackend{deleteErr: storage.ErrClosed}
		adapter := storage.NewCertAdapter(backend)
		err := adapter.DeleteCert(ctx, "test-id")
		assert.ErrorIs(t, err, storage.ErrClosed)
	})

	t.Run("SaveCert backend error", func(t *testing.T) {
		backend := &mockErrorBackend{putErr: storage.ErrClosed}
		adapter := storage.NewCertAdapter(backend)
		err := adapter.SaveCert(ctx, "test-id", cert)
		assert.ErrorIs(t, err, storage.ErrClosed)
	})

	t.Run("GetCertChain backend error", func(t *testing.T) {
		backend := &mockErrorBackend{getErr: storage.ErrClosed}
		adapter := storage.NewCertAdapter(backend)
		_, err := adapter.GetCertChain(ctx, "chain-id")
		assert.ErrorIs(t, err, storage.ErrClosed)
	})

	t.Run("SaveCertChain backend error", func(t *testing.T) {
		backend := &mockErrorBackend{putErr: storage.ErrClosed}
		adapter := storage.NewCertAdapter(backend)
		chain := []*x509.Certificate{cert}
		err := adapter.SaveCertChain(ctx, "chain-id", chain)
		assert.ErrorIs(t, err, storage.ErrClosed)
	})

	t.Run("CertExists backend error", func(t *testing.T) {
		backend := &mockErrorBackend{existsErr: storage.ErrClosed}
		adapter := storage.NewCertAdapter(backend)
		exists, err := adapter.CertExists(ctx, "test-id")
		assert.ErrorIs(t, err, storage.ErrClosed)
		assert.False(t, exists)
	})
}
