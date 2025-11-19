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

package certstore

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCertStorage is a simple in-memory implementation of CertificateStorageAdapter for testing.
type mockCertStorage struct {
	certs  map[string]*x509.Certificate
	chains map[string][]*x509.Certificate
	closed bool
}

func newMockCertStorage() *mockCertStorage {
	return &mockCertStorage{
		certs:  make(map[string]*x509.Certificate),
		chains: make(map[string][]*x509.Certificate),
		closed: false,
	}
}

func (m *mockCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	if m.closed {
		return ErrStorageClosed
	}
	m.certs[id] = cert
	return nil
}

func (m *mockCertStorage) GetCert(id string) (*x509.Certificate, error) {
	if m.closed {
		return nil, ErrStorageClosed
	}
	cert, ok := m.certs[id]
	if !ok {
		return nil, ErrCertNotFound
	}
	return cert, nil
}

func (m *mockCertStorage) DeleteCert(id string) error {
	if m.closed {
		return ErrStorageClosed
	}
	if _, ok := m.certs[id]; !ok {
		return ErrCertNotFound
	}
	delete(m.certs, id)
	delete(m.chains, id)
	return nil
}

func (m *mockCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	if m.closed {
		return ErrStorageClosed
	}
	m.chains[id] = chain
	return nil
}

func (m *mockCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	if m.closed {
		return nil, ErrStorageClosed
	}
	chain, ok := m.chains[id]
	if !ok {
		return nil, ErrChainNotFound
	}
	return chain, nil
}

func (m *mockCertStorage) ListCerts() ([]string, error) {
	if m.closed {
		return nil, ErrStorageClosed
	}
	var ids []string
	for id := range m.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *mockCertStorage) CertExists(id string) (bool, error) {
	if m.closed {
		return false, ErrStorageClosed
	}
	_, ok := m.certs[id]
	return ok, nil
}

func (m *mockCertStorage) Close() error {
	m.closed = true
	return nil
}

// Helper functions for test certificate generation

func generateTestCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.KeyUsage |= x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	var certParent *x509.Certificate
	var signingKey *ecdsa.PrivateKey

	if parent != nil && parentKey != nil {
		certParent = parent
		signingKey = parentKey
		template.Issuer = parent.Subject
	} else {
		// Self-signed
		certParent = template
		signingKey = key
		template.Issuer = template.Subject
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, certParent, &key.PublicKey, signingKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func generateExpiredCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func generateNotYetValidCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(24 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// ========================================================================
// Configuration Tests
// ========================================================================

func TestNew_Success(t *testing.T) {
	storage := newMockCertStorage()
	config := &Config{
		CertStorage: storage,
	}

	cs, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, cs)

	err = cs.Close()
	require.NoError(t, err)
}

func TestNew_NilConfig(t *testing.T) {
	cs, err := New(nil)
	assert.Error(t, err)
	assert.Nil(t, cs)
	assert.Equal(t, ErrInvalidConfig, err)
}

func TestNew_NilStorage(t *testing.T) {
	config := &Config{
		CertStorage: nil,
	}

	cs, err := New(config)
	assert.Error(t, err)
	assert.Nil(t, cs)
	assert.Equal(t, ErrStorageRequired, err)
}

// ========================================================================
// Certificate Storage Tests
// ========================================================================

func TestStoreCertificate_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)

	err = cs.StoreCertificate(cert)
	assert.NoError(t, err)

	// Verify it was stored
	retrieved, err := cs.GetCertificate(cert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
}

func TestStoreCertificate_NilCert(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	err = cs.StoreCertificate(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrCertInvalid, err)
}

func TestStoreCertificate_EmptyCN(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	cert.Subject.CommonName = ""

	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCN, err)
}

func TestStoreCertificate_Expired(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert := generateExpiredCert(t, "expired.example.com")

	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, ErrCertExpired, err)
}

func TestStoreCertificate_NotYetValid(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert := generateNotYetValidCert(t, "future.example.com")

	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, ErrCertNotYetValid, err)
}

func TestGetCertificate_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	retrieved, err := cs.GetCertificate(cert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
}

func TestGetCertificate_NotFound(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	_, err = cs.GetCertificate("nonexistent.example.com")
	assert.Error(t, err)
}

func TestGetCertificate_EmptyCN(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	_, err = cs.GetCertificate("")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCN, err)
}

func TestDeleteCertificate_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	err = cs.DeleteCertificate(cert.Subject.CommonName)
	assert.NoError(t, err)

	// Verify it was deleted
	_, err = cs.GetCertificate(cert.Subject.CommonName)
	assert.Error(t, err)
}

func TestDeleteCertificate_NotFound(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	err = cs.DeleteCertificate("nonexistent.example.com")
	assert.Error(t, err)
}

func TestDeleteCertificate_EmptyCN(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	err = cs.DeleteCertificate("")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCN, err)
}

func TestListCertificates_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert1, _ := generateTestCert(t, "test1.example.com", false, nil, nil)
	cert2, _ := generateTestCert(t, "test2.example.com", false, nil, nil)

	err = cs.StoreCertificate(cert1)
	require.NoError(t, err)
	err = cs.StoreCertificate(cert2)
	require.NoError(t, err)

	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestListCertificates_Empty(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Empty(t, certs)
}

// ========================================================================
// Certificate Chain Tests
// ========================================================================

func TestStoreCertificateChain_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Create a certificate chain: root -> intermediate -> leaf
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	intermediateCert, intermediateKey := generateTestCert(t, "intermediate.example.com", true, rootCert, rootKey)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, intermediateCert, intermediateKey)

	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}

	err = cs.StoreCertificateChain(chain)
	assert.NoError(t, err)

	// Verify chain was stored
	retrieved, err := cs.GetCertificateChain(leafCert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 3)
}

func TestStoreCertificateChain_Empty(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	err = cs.StoreCertificateChain([]*x509.Certificate{})
	assert.Error(t, err)
	assert.Equal(t, ErrChainEmpty, err)
}

func TestStoreCertificateChain_NilCertInChain(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	chain := []*x509.Certificate{cert, nil}

	err = cs.StoreCertificateChain(chain)
	assert.Error(t, err)
}

func TestGetCertificateChain_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, rootCert, rootKey)

	chain := []*x509.Certificate{leafCert, rootCert}
	err = cs.StoreCertificateChain(chain)
	require.NoError(t, err)

	retrieved, err := cs.GetCertificateChain(leafCert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 2)
}

func TestGetCertificateChain_NotFound(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	_, err = cs.GetCertificateChain("nonexistent.example.com")
	assert.Error(t, err)
}

func TestGetCertificateChain_EmptyCN(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	_, err = cs.GetCertificateChain("")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCN, err)
}

// ========================================================================
// CRL Tests
// ========================================================================

func TestStoreCRL_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Create a CRL
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	assert.NoError(t, err)
}

func TestStoreCRL_Nil(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	err = cs.StoreCRL(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrCRLInvalid, err)
}

func TestStoreCRL_Expired(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	assert.Error(t, err)
	assert.Equal(t, ErrCRLExpired, err)
}

func TestGetCRL_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	retrieved, err := cs.GetCRL(caCert.Subject.CommonName)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
}

func TestGetCRL_NotFound(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	_, err = cs.GetCRL("nonexistent.example.com")
	assert.Error(t, err)
	assert.Equal(t, ErrCRLNotFound, err)
}

func TestGetCRL_EmptyIssuer(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	_, err = cs.GetCRL("")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidIssuer, err)
}

// ========================================================================
// Certificate Verification Tests
// ========================================================================

func TestVerifyCertificate_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Create a CA and a certificate signed by it
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestVerifyCertificate_NilCert(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	roots := x509.NewCertPool()
	err = cs.VerifyCertificate(nil, roots)
	assert.Error(t, err)
	assert.Equal(t, ErrCertInvalid, err)
}

func TestVerifyCertificate_NilRoots(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)

	err = cs.VerifyCertificate(cert, nil)
	assert.Error(t, err)
	assert.Equal(t, ErrNoRoots, err)
}

func TestVerifyCertificate_UntrustedRoot(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Create a CA and a certificate signed by it
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create a different CA for the root pool
	differentCA, _ := generateTestCert(t, "different-ca.example.com", true, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(differentCA)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.Error(t, err)
}

// ========================================================================
// Revocation Tests
// ========================================================================

func TestIsRevoked_NotRevoked(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create empty CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestIsRevoked_Revoked(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with revoked certificate
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   leafCert.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

func TestIsRevoked_NilCert(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	_, err = cs.IsRevoked(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrCertInvalid, err)
}

func TestIsRevoked_NoCRL(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// No CRL stored
	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.False(t, revoked) // Assume not revoked if no CRL
}

func TestStoreCertificate_RevokedWithAllowRevoked(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{
		CertStorage:  storage,
		AllowRevoked: true, // Allow storing revoked certs
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with revoked certificate
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   leafCert.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	// Should succeed because AllowRevoked is true
	err = cs.StoreCertificate(leafCert)
	assert.NoError(t, err)
}

func TestStoreCertificate_RevokedWithoutAllowRevoked(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{
		CertStorage:  storage,
		AllowRevoked: false, // Don't allow storing revoked certs
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with revoked certificate
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   leafCert.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	// Should fail because cert is revoked
	err = cs.StoreCertificate(leafCert)
	assert.Error(t, err)
	assert.Equal(t, ErrCertRevoked, err)
}

// ========================================================================
// Lifecycle Tests
// ========================================================================

func TestClose_Success(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)

	err = cs.Close()
	assert.NoError(t, err)

	// Subsequent operations should fail
	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
}

func TestClose_Idempotent(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)

	err = cs.Close()
	assert.NoError(t, err)

	// Closing again should not error
	err = cs.Close()
	assert.NoError(t, err)
}

// ========================================================================
// Concurrent Access Tests
// ========================================================================

func TestConcurrentAccess(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Test concurrent reads and writes
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			cert, _ := generateTestCert(t, fmt.Sprintf("test%d.example.com", i), false, nil, nil)
			_ = cs.StoreCertificate(cert)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 10; i++ {
			_, _ = cs.ListCertificates()
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}

// ========================================================================
// Additional Edge Case Tests for 90%+ Coverage
// ========================================================================

func TestListCertificates_ErrorLoadingCert(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	// Corrupt the certificate in storage
	storage.certs["test.example.com"] = nil

	// ListCertificates should skip the bad cert
	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Empty(t, certs) // Should skip the nil cert
}

func TestStoreCertificateChain_EmptyCNInFirstCert(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	cert.Subject.CommonName = ""

	chain := []*x509.Certificate{cert}

	err = cs.StoreCertificateChain(chain)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCN, err)
}

func TestVerifyCertificate_WithIntermediates(t *testing.T) {
	storage := newMockCertStorage()

	// Create a certificate chain
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	intermediateCert, intermediateKey := generateTestCert(t, "intermediate.example.com", true, rootCert, rootKey)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	verifyOpts := &x509.VerifyOptions{
		Intermediates: intermediates,
	}

	cs, err := New(&Config{
		CertStorage:   storage,
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	leafCert, _ := generateTestCert(t, "leaf.example.com", false, intermediateCert, intermediateKey)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestVerifyCertificate_WithKeyUsages(t *testing.T) {
	storage := newMockCertStorage()
	verifyOpts := &x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cs, err := New(&Config{
		CertStorage:   storage,
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestIsRevoked_ExpiredCRL(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create expired CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   leafCert.SerialNumber,
				RevocationTime: time.Now().Add(-36 * time.Hour),
			},
		},
	}

	// Force store the expired CRL by bypassing validation
	impl := cs.(*compositeCertStore)
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	impl.mu.Lock()
	impl.crlCache[caCert.Subject.CommonName] = crl
	impl.mu.Unlock()

	// Should still check revocation even with expired CRL
	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

func TestIsRevoked_CertWithoutIssuer(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	cert.Issuer.CommonName = ""

	// Should not error, just return false
	revoked, err := cs.IsRevoked(cert)
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestClosed_Operations(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)

	// Close the certstore
	err = cs.Close()
	require.NoError(t, err)

	// All operations should fail with ErrStorageClosed
	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	_, err = cs.GetCertificate("test")
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	err = cs.DeleteCertificate("test")
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	_, err = cs.ListCertificates()
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	err = cs.StoreCertificateChain([]*x509.Certificate{cert})
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	_, err = cs.GetCertificateChain("test")
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	crl, _ := x509.ParseRevocationList(crlDER)

	err = cs.StoreCRL(crl)
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	_, err = cs.GetCRL("test")
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	roots := x509.NewCertPool()
	err = cs.VerifyCertificate(cert, roots)
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)

	_, err = cs.IsRevoked(cert)
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)
}
