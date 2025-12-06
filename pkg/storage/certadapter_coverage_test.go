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

package storage_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCertAdapter_Backend tests the Backend() accessor method.
func TestCertAdapter_Backend(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Verify Backend() returns the same backend
	retrievedBackend := adapter.Backend()
	assert.NotNil(t, retrievedBackend)
	assert.Equal(t, backend, retrievedBackend)
}

// TestCertAdapter_SaveCert_InvalidID tests SaveCert with empty ID.
func TestCertAdapter_SaveCert_InvalidID(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	err := adapter.SaveCert("", cert)
	assert.ErrorIs(t, err, storage.ErrInvalidID)
}

// TestCertAdapter_SaveCert_EmptyRawData tests SaveCert with certificate missing raw data.
func TestCertAdapter_SaveCert_EmptyRawData(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Create a certificate with no Raw data
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		// Raw field is not set
	}

	err := adapter.SaveCert("test-id", cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate has no raw data")
}

// TestCertAdapter_GetCert_InvalidID tests GetCert with empty ID.
func TestCertAdapter_GetCert_InvalidID(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	_, err := adapter.GetCert("")
	assert.ErrorIs(t, err, storage.ErrInvalidID)
}

// TestCertAdapter_GetCert_InvalidData tests GetCert with invalid certificate data.
func TestCertAdapter_GetCert_InvalidData(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Save invalid certificate data directly to backend
	certPath := storage.CertPath("test-id")
	err := backend.Put(certPath, []byte("invalid certificate data"), nil)
	require.NoError(t, err)

	// Try to get the certificate
	_, err = adapter.GetCert("test-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// TestCertAdapter_DeleteCert_InvalidID tests DeleteCert with empty ID.
func TestCertAdapter_DeleteCert_InvalidID(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	err := adapter.DeleteCert("")
	assert.ErrorIs(t, err, storage.ErrInvalidID)
}

// TestCertAdapter_SaveCertChain_InvalidID tests SaveCertChain with empty ID.
func TestCertAdapter_SaveCertChain_InvalidID(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")
	chain := []*x509.Certificate{cert}

	err := adapter.SaveCertChain("", chain)
	assert.ErrorIs(t, err, storage.ErrInvalidID)
}

// TestCertAdapter_SaveCertChain_CertWithNoRawData tests SaveCertChain with cert missing raw data.
func TestCertAdapter_SaveCertChain_CertWithNoRawData(t *testing.T) {
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
		// Raw field is not set
	}

	chain := []*x509.Certificate{cert1, cert2}
	err := adapter.SaveCertChain("chain-id", chain)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 1 has no raw data")
}

// TestCertAdapter_GetCertChain_InvalidID tests GetCertChain with empty ID.
func TestCertAdapter_GetCertChain_InvalidID(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	_, err := adapter.GetCertChain("")
	assert.ErrorIs(t, err, storage.ErrInvalidID)
}

// TestCertAdapter_GetCertChain_InvalidData tests GetCertChain with invalid data.
func TestCertAdapter_GetCertChain_InvalidData(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Save invalid certificate chain data directly to backend
	chainPath := storage.CertChainPath("chain-id")
	err := backend.Put(chainPath, []byte("invalid chain data"), nil)
	require.NoError(t, err)

	// Try to get the certificate chain
	_, err = adapter.GetCertChain("chain-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate chain")
}

// TestCertAdapter_CertExists_InvalidID tests CertExists with empty ID.
func TestCertAdapter_CertExists_InvalidID(t *testing.T) {
	backend := storage.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	exists, err := adapter.CertExists("")
	assert.ErrorIs(t, err, storage.ErrInvalidID)
	assert.False(t, exists)
}

// TestCertAdapter_GetCert_BackendError tests GetCert when backend returns error.
func TestCertAdapter_GetCert_BackendError(t *testing.T) {
	// Create a mock backend that returns an error
	backend := &mockErrorBackend{
		getErr: storage.ErrClosed,
	}
	adapter := storage.NewCertAdapter(backend)

	_, err := adapter.GetCert("test-id")
	assert.ErrorIs(t, err, storage.ErrClosed)
}

// TestCertAdapter_DeleteCert_BackendError tests DeleteCert when backend returns error.
func TestCertAdapter_DeleteCert_BackendError(t *testing.T) {
	backend := &mockErrorBackend{
		deleteErr: storage.ErrClosed,
	}
	adapter := storage.NewCertAdapter(backend)

	err := adapter.DeleteCert("test-id")
	assert.ErrorIs(t, err, storage.ErrClosed)
}

// TestCertAdapter_SaveCert_BackendError tests SaveCert when backend returns error.
func TestCertAdapter_SaveCert_BackendError(t *testing.T) {
	backend := &mockErrorBackend{
		putErr: storage.ErrClosed,
	}
	adapter := storage.NewCertAdapter(backend)

	cert := createTestCert(t, "test-cert")
	err := adapter.SaveCert("test-id", cert)
	assert.ErrorIs(t, err, storage.ErrClosed)
}

// TestCertAdapter_GetCertChain_BackendError tests GetCertChain when backend returns error.
func TestCertAdapter_GetCertChain_BackendError(t *testing.T) {
	backend := &mockErrorBackend{
		getErr: storage.ErrClosed,
	}
	adapter := storage.NewCertAdapter(backend)

	_, err := adapter.GetCertChain("chain-id")
	assert.ErrorIs(t, err, storage.ErrClosed)
}

// TestCertAdapter_SaveCertChain_BackendError tests SaveCertChain when backend returns error.
func TestCertAdapter_SaveCertChain_BackendError(t *testing.T) {
	backend := &mockErrorBackend{
		putErr: storage.ErrClosed,
	}
	adapter := storage.NewCertAdapter(backend)

	cert := createTestCert(t, "test-cert")
	chain := []*x509.Certificate{cert}
	err := adapter.SaveCertChain("chain-id", chain)
	assert.ErrorIs(t, err, storage.ErrClosed)
}

// TestCertAdapter_CertExists_BackendError tests CertExists when backend returns error.
func TestCertAdapter_CertExists_BackendError(t *testing.T) {
	backend := &mockErrorBackend{
		existsErr: storage.ErrClosed,
	}
	adapter := storage.NewCertAdapter(backend)

	exists, err := adapter.CertExists("test-id")
	assert.ErrorIs(t, err, storage.ErrClosed)
	assert.False(t, exists)
}

// mockErrorBackend is a backend that returns configured errors for testing.
type mockErrorBackend struct {
	getErr    error
	putErr    error
	deleteErr error
	existsErr error
	listErr   error
}

func (m *mockErrorBackend) Get(key string) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return nil, storage.ErrNotFound
}

func (m *mockErrorBackend) Put(key string, value []byte, opts *storage.Options) error {
	if m.putErr != nil {
		return m.putErr
	}
	return nil
}

func (m *mockErrorBackend) Delete(key string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return storage.ErrNotFound
}

func (m *mockErrorBackend) Exists(key string) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	return false, nil
}

func (m *mockErrorBackend) List(prefix string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return nil, nil
}

func (m *mockErrorBackend) Close() error {
	return nil
}
