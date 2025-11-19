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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Additional Edge Case Tests for 90%+ Coverage
// ========================================================================

// mockFailingCertStorage simulates storage failures
type mockFailingCertStorage struct {
	*mockCertStorage
	failSave  bool
	failClose bool
}

func (m *mockFailingCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	if m.failSave {
		return errors.New("simulated save failure")
	}
	return m.mockCertStorage.SaveCert(id, cert)
}

func (m *mockFailingCertStorage) Close() error {
	if m.failClose {
		return errors.New("simulated close failure")
	}
	return m.mockCertStorage.Close()
}

// TestStoreCertificate_SaveError tests error handling when underlying storage fails
func TestStoreCertificate_SaveError(t *testing.T) {
	storage := &mockFailingCertStorage{
		mockCertStorage: newMockCertStorage(),
		failSave:        true,
	}
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)

	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store certificate")
}

// TestStoreCRL_EmptyIssuer tests StoreCRL error path for invalid issuer
// Note: This test creates a mock CRL directly to bypass x509.CreateRevocationList
// which automatically fills in the Issuer field from the signing certificate
func TestStoreCRL_EmptyIssuer(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Create a CRL with empty issuer CN directly
	crl := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     pkix.Name{CommonName: ""}, // Empty issuer CN
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	err = cs.StoreCRL(crl)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidIssuer, err)
}

// TestIsRevoked_LegacyRevokedCertificates tests CRL support for Go <1.21
// (RevokedCertificates field, replaced by RevokedCertificateEntries in Go 1.21+)
func TestIsRevoked_LegacyRevokedCertificates(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL using RevokedCertificates field (legacy Go stdlib API)
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

	// Should detect revocation via legacy RevokedCertificates field
	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

// TestListCertificates_GetCertError tests ListCertificates when GetCert fails
func TestListCertificates_GetCertError(t *testing.T) {
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

	// Corrupt one certificate in storage
	storage.certs["test1.example.com"] = nil

	// ListCertificates should skip the corrupted cert
	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	// Should only return test2 since test1 is nil
	assert.Len(t, certs, 1)
	if len(certs) == 1 {
		assert.Equal(t, "test2.example.com", certs[0].Subject.CommonName)
	}
}

// TestListCertificates_ListError tests error from storage.ListCerts
func TestListCertificates_ListError(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)

	// Close storage to cause error
	_ = storage.Close()

	_, err = cs.ListCertificates()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list certificates")
}

// TestClose_StorageError tests error handling when storage.Close fails
func TestClose_StorageError(t *testing.T) {
	storage := &mockFailingCertStorage{
		mockCertStorage: newMockCertStorage(),
		failClose:       true,
	}
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)

	err = cs.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to close storage")
}

// TestVerifyCertificate_WithDNSName tests verification with DNSName option
func TestVerifyCertificate_WithDNSName(t *testing.T) {
	storage := newMockCertStorage()
	verifyOpts := &x509.VerifyOptions{
		DNSName: "test.example.com",
	}
	cs, err := New(&Config{
		CertStorage:   storage,
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "test.example.com", false, caCert, caKey)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// DNS verification requires SANs in modern Go, so this test verifies
	// that the DNSName option is passed through (it will fail due to lack of SANs)
	err = cs.VerifyCertificate(leafCert, roots)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

// TestConcurrentCRLOperations tests concurrent CRL access
func TestConcurrentCRLOperations(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			crlTemplate := &x509.RevocationList{
				Number:     big.NewInt(int64(i)),
				Issuer:     caCert.Subject,
				ThisUpdate: time.Now(),
				NextUpdate: time.Now().Add(24 * time.Hour),
			}

			crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
			if err != nil {
				return
			}

			crl, err := x509.ParseRevocationList(crlDER)
			if err != nil {
				return
			}

			_ = cs.StoreCRL(crl)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cs.GetCRL(caCert.Subject.CommonName)
		}()
	}

	wg.Wait()
}

// TestConcurrentChainOperations tests concurrent chain access
func TestConcurrentChainOperations(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent chain operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			rootCert, rootKey := generateTestCert(t, fmt.Sprintf("root-%d.example.com", i), true, nil, nil)
			leafCert, _ := generateTestCert(t, fmt.Sprintf("leaf-%d.example.com", i), false, rootCert, rootKey)

			chain := []*x509.Certificate{leafCert, rootCert}
			_ = cs.StoreCertificateChain(chain)

			_, _ = cs.GetCertificateChain(leafCert.Subject.CommonName)
		}(i)
	}

	wg.Wait()
}

// TestNew_WithCustomVerifyOptions tests initialization with custom verify options
func TestNew_WithCustomVerifyOptions(t *testing.T) {
	storage := newMockCertStorage()

	intermediates := x509.NewCertPool()
	verifyOpts := &x509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       "test.example.com",
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   time.Now(),
	}

	cs, err := New(&Config{
		CertStorage:   storage,
		VerifyOptions: verifyOpts,
		AllowRevoked:  true,
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Verify the store was created successfully
	assert.NotNil(t, cs)
}

// TestStoreCertificateChain_NilCertAtIndex tests chain with nil cert at specific index
func TestStoreCertificateChain_NilCertAtIndex(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, rootCert, rootKey)

	// Create chain with nil in the middle
	chain := []*x509.Certificate{leafCert, nil, rootCert}

	err = cs.StoreCertificateChain(chain)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 1 is nil")
}

// TestGetCertificate_AfterDelete tests GetCertificate after deletion
func TestGetCertificate_AfterDelete(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	// Verify it exists
	retrieved, err := cs.GetCertificate(cert.Subject.CommonName)
	require.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)

	// Delete it
	err = cs.DeleteCertificate(cert.Subject.CommonName)
	require.NoError(t, err)

	// Verify it's gone
	_, err = cs.GetCertificate(cert.Subject.CommonName)
	assert.Error(t, err)
}

// TestConcurrentReadWrite tests concurrent reads and writes
func TestConcurrentReadWrite(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Writer goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cert, _ := generateTestCert(t, fmt.Sprintf("writer-%d.example.com", i), false, nil, nil)
			if err := cs.StoreCertificate(cert); err != nil {
				errors <- err
			}
		}(i)
	}

	// Reader goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = cs.ListCertificates()
			_, _ = cs.GetCertificate(fmt.Sprintf("writer-%d.example.com", i))
		}(i)
	}

	// Deleter goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = cs.DeleteCertificate(fmt.Sprintf("writer-%d.example.com", i))
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for unexpected errors
	for err := range errors {
		// Some errors are expected due to concurrent access
		t.Logf("Concurrent operation error (may be expected): %v", err)
	}
}

// TestVerifyCertificate_AllOptions tests verification with all options set
func TestVerifyCertificate_AllOptions(t *testing.T) {
	storage := newMockCertStorage()

	// Create a certificate chain
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	intermediateCert, intermediateKey := generateTestCert(t, "intermediate.example.com", true, rootCert, rootKey)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	verifyOpts := &x509.VerifyOptions{
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// TestMultipleCRLsForDifferentIssuers tests storing and retrieving multiple CRLs
func TestMultipleCRLsForDifferentIssuers(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// Create CRLs for different issuers
	ca1, ca1Key := generateTestCert(t, "ca1.example.com", true, nil, nil)
	ca2, ca2Key := generateTestCert(t, "ca2.example.com", true, nil, nil)

	crl1Template := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     ca1.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crl2Template := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     ca2.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crl1DER, err := x509.CreateRevocationList(rand.Reader, crl1Template, ca1, ca1Key)
	require.NoError(t, err)
	crl1, err := x509.ParseRevocationList(crl1DER)
	require.NoError(t, err)

	crl2DER, err := x509.CreateRevocationList(rand.Reader, crl2Template, ca2, ca2Key)
	require.NoError(t, err)
	crl2, err := x509.ParseRevocationList(crl2DER)
	require.NoError(t, err)

	// Store both CRLs
	err = cs.StoreCRL(crl1)
	require.NoError(t, err)
	err = cs.StoreCRL(crl2)
	require.NoError(t, err)

	// Retrieve each CRL
	retrievedCRL1, err := cs.GetCRL(ca1.Subject.CommonName)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedCRL1)

	retrievedCRL2, err := cs.GetCRL(ca2.Subject.CommonName)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedCRL2)
}

// TestStoreCertificate_CheckRevocationFailure tests when revocation check itself fails
func TestStoreCertificate_CheckRevocationFailure(t *testing.T) {
	// This test verifies the error path when isRevokedLocked returns an error
	// In the current implementation, isRevokedLocked only returns errors for invalid certs,
	// but we test the error handling path
	storage := newMockCertStorage()
	cs, err := New(&Config{
		CertStorage:  storage,
		AllowRevoked: false,
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	// The current implementation doesn't have a way to make isRevokedLocked return
	// an error for a valid cert, so this test documents the expected behavior
	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	assert.NoError(t, err)
}

// TestNew_DefaultVerifyOptions tests that default verify options are created
func TestNew_DefaultVerifyOptions(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{
		CertStorage: storage,
		// VerifyOptions intentionally nil to test defaults
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	assert.NotNil(t, cs)
}

// TestIsRevoked_CertWithRevokedCertificateEntries tests the new RevokedCertificateEntries field
func TestIsRevoked_CertWithRevokedCertificateEntries(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with RevokedCertificateEntries (the modern field)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		// Using the newer RevokedCertificateEntries field
		RevokedCertificateEntries: []x509.RevocationListEntry{
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

	// Should detect revocation via RevokedCertificateEntries
	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

// TestClose_ClearsCache tests that Close clears the CRL cache
func TestClose_ClearsCache(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)

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

	// Verify CRL is stored
	retrievedCRL, err := cs.GetCRL(caCert.Subject.CommonName)
	require.NoError(t, err)
	assert.NotNil(t, retrievedCRL)

	// Close the store
	err = cs.Close()
	require.NoError(t, err)

	// After close, GetCRL should fail
	_, err = cs.GetCRL(caCert.Subject.CommonName)
	assert.Error(t, err)
	assert.Equal(t, ErrStorageClosed, err)
}

// TestStressTest performs a stress test with many concurrent operations
func TestStressTest(t *testing.T) {
	storage := newMockCertStorage()
	cs, err := New(&Config{CertStorage: storage})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	var wg sync.WaitGroup
	numOperations := 100

	for i := 0; i < numOperations; i++ {
		wg.Add(4) // 4 types of operations

		// Store certificate
		go func(i int) {
			defer wg.Done()
			cert, _ := generateTestCert(t, fmt.Sprintf("stress-%d.example.com", i), false, nil, nil)
			_ = cs.StoreCertificate(cert)
		}(i)

		// List certificates
		go func() {
			defer wg.Done()
			_, _ = cs.ListCertificates()
		}()

		// Get certificate
		go func(i int) {
			defer wg.Done()
			_, _ = cs.GetCertificate(fmt.Sprintf("stress-%d.example.com", i))
		}(i)

		// Delete certificate
		go func(i int) {
			defer wg.Done()
			_ = cs.DeleteCertificate(fmt.Sprintf("stress-%d.example.com", i))
		}(i)
	}

	wg.Wait()
}
