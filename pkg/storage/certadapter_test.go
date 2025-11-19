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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
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
	backend := memory.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	// Save certificate
	err := adapter.SaveCert("test-id", cert)
	require.NoError(t, err)

	// Retrieve certificate
	retrieved, err := adapter.GetCert("test-id")
	require.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, cert.Subject.CommonName, retrieved.Subject.CommonName)
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
}

func TestCertAdapter_DeleteCert(t *testing.T) {
	backend := memory.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	// Save certificate
	err := adapter.SaveCert("test-id", cert)
	require.NoError(t, err)

	// Verify it exists
	exists, err := adapter.CertExists("test-id")
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete certificate
	err = adapter.DeleteCert("test-id")
	require.NoError(t, err)

	// Verify it no longer exists
	exists, err = adapter.CertExists("test-id")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestCertAdapter_SaveAndGetCertChain(t *testing.T) {
	backend := memory.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Create a chain of certificates
	cert1 := createTestCert(t, "cert1")
	cert2 := createTestCert(t, "cert2")
	cert3 := createTestCert(t, "cert3")
	chain := []*x509.Certificate{cert1, cert2, cert3}

	// Save chain
	err := adapter.SaveCertChain("chain-id", chain)
	require.NoError(t, err)

	// Retrieve chain
	retrieved, err := adapter.GetCertChain("chain-id")
	require.NoError(t, err)
	require.Len(t, retrieved, 3)
	assert.Equal(t, cert1.Subject.CommonName, retrieved[0].Subject.CommonName)
	assert.Equal(t, cert2.Subject.CommonName, retrieved[1].Subject.CommonName)
	assert.Equal(t, cert3.Subject.CommonName, retrieved[2].Subject.CommonName)
}

func TestCertAdapter_ListCerts(t *testing.T) {
	backend := memory.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	// Save multiple certificates
	cert1 := createTestCert(t, "cert1")
	cert2 := createTestCert(t, "cert2")
	cert3 := createTestCert(t, "cert3")

	err := adapter.SaveCert("id1", cert1)
	require.NoError(t, err)
	err = adapter.SaveCert("id2", cert2)
	require.NoError(t, err)
	err = adapter.SaveCert("id3", cert3)
	require.NoError(t, err)

	// List all certificates
	ids, err := adapter.ListCerts()
	require.NoError(t, err)
	assert.Len(t, ids, 3)
	assert.Contains(t, ids, "id1")
	assert.Contains(t, ids, "id2")
	assert.Contains(t, ids, "id3")
}

func TestCertAdapter_CertExists(t *testing.T) {
	backend := memory.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	cert := createTestCert(t, "test-cert")

	// Check non-existent certificate
	exists, err := adapter.CertExists("test-id")
	require.NoError(t, err)
	assert.False(t, exists)

	// Save certificate
	err = adapter.SaveCert("test-id", cert)
	require.NoError(t, err)

	// Check existing certificate
	exists, err = adapter.CertExists("test-id")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestCertAdapter_ErrorCases(t *testing.T) {
	backend := memory.New()
	adapter := storage.NewCertAdapter(backend)
	defer func() { _ = adapter.Close() }()

	t.Run("SaveCert with nil certificate", func(t *testing.T) {
		err := adapter.SaveCert("test-id", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate cannot be nil")
	})

	t.Run("SaveCertChain with empty chain", func(t *testing.T) {
		err := adapter.SaveCertChain("chain-id", []*x509.Certificate{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate chain cannot be empty")
	})

	t.Run("SaveCertChain with nil certificate in chain", func(t *testing.T) {
		cert1 := createTestCert(t, "cert1")
		chain := []*x509.Certificate{cert1, nil}
		err := adapter.SaveCertChain("chain-id", chain)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate at index 1 is nil")
	})

	t.Run("GetCert with non-existent ID", func(t *testing.T) {
		_, err := adapter.GetCert("non-existent")
		assert.Error(t, err)
	})

	t.Run("GetCertChain with non-existent ID", func(t *testing.T) {
		_, err := adapter.GetCertChain("non-existent")
		assert.Error(t, err)
	})

	t.Run("DeleteCert with non-existent ID", func(t *testing.T) {
		err := adapter.DeleteCert("non-existent")
		assert.Error(t, err)
	})
}
