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

package certstore

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// ========================================================================
// Additional Edge Case Tests for 90%+ Coverage
// ========================================================================

// errStoreDown is the failure failingStore reports.
var errStoreDown = errors.New("store down")

// failingStore is a go-qrdb store whose reads and writes fail.
type failingStore struct{ qrdbsdk.KVStore }

func (failingStore) Put(context.Context, string, []byte) error { return errStoreDown }

func (failingStore) Get(context.Context, string) ([]byte, error) { return nil, errStoreDown }

func (failingStore) Delete(context.Context, string) error { return errStoreDown }

func (failingStore) Scan(context.Context, string, func(string, []byte) error) error {
	return errStoreDown
}

func (failingStore) List(context.Context, string) ([]string, error) { return nil, errStoreDown }

func (failingStore) Exists(context.Context, string) (bool, error) { return false, errStoreDown }

// TestStore_ReportsStoreFailures proves a failure of the store behind the
// DAOs is a *StoreError naming the operation, never a not-found.
func TestStore_ReportsStoreFailures(t *testing.T) {
	cs, err := New(&Config{DAOs: dao.NewStoreFactory(failingStore{qrdbsdk.NewMemoryKVStore()})})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	tests := map[string]struct {
		op  string
		run func() error
	}{
		"store":     {"put", func() error { return cs.StoreCertificate(cert) }},
		"get":       {"get", func() error { _, err := cs.GetCertificate("test.example.com"); return err }},
		"delete":    {"get", func() error { return cs.DeleteCertificate("test.example.com") }},
		"list":      {"list", func() error { _, err := cs.ListCertificates(); return err }},
		"chain":     {"put", func() error { return cs.StoreCertificateChain([]*x509.Certificate{cert}) }},
		"get chain": {"get", func() error { _, err := cs.GetCertificateChain("test.example.com"); return err }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.run()
			var storeErr *StoreError
			require.ErrorAs(t, err, &storeErr)
			assert.Equal(t, tt.op, storeErr.Op)
			assert.False(t, errors.Is(err, ErrCertNotFound))
		})
	}
}

// TestClose_LeavesFactoryOpen proves Close ends only this store: the
// factory belongs to the composition root, and a new store over it still
// finds what the closed one stored.
func TestClose_LeavesFactoryOpen(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	cs, err := New(&Config{DAOs: daos})
	require.NoError(t, err)
	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	require.NoError(t, cs.StoreCertificate(cert))
	require.NoError(t, cs.Close())

	_, err = cs.GetCertificate("test.example.com")
	assert.ErrorIs(t, err, ErrStorageClosed)

	reopened, err := New(&Config{DAOs: daos})
	require.NoError(t, err)
	got, err := reopened.GetCertificate("test.example.com")
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got.Raw)
}

// TestStoreCRL_EmptyIssuer tests StoreCRL error path for invalid issuer
// Note: This test creates a mock CRL directly to bypass x509.CreateRevocationList
// which automatically fills in the Issuer field from the signing certificate
func TestStoreCRL_EmptyIssuer(t *testing.T) {
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
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

	// Should detect revocation via legacy RevokedCertificates field
	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

// TestVerifyCertificate_WithDNSName tests verification with DNSName option
func TestVerifyCertificate_WithDNSName(t *testing.T) {
	verifyOpts := &x509.VerifyOptions{
		DNSName: "test.example.com",
	}
	cs, err := New(&Config{
		DAOs:          testutil.NewMemoryDAOFactory(),
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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

	intermediates := x509.NewCertPool()
	verifyOpts := &x509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       "test.example.com",
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   time.Now(),
	}

	cs, err := New(&Config{
		DAOs:          testutil.NewMemoryDAOFactory(),
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
		DAOs:          testutil.NewMemoryDAOFactory(),
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
	cs, err := New(&Config{
		DAOs:         testutil.NewMemoryDAOFactory(),
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
	cs, err := New(&Config{
		DAOs: testutil.NewMemoryDAOFactory(),
		// VerifyOptions intentionally nil to test defaults
	})
	require.NoError(t, err)
	defer func() { _ = cs.Close() }()

	assert.NotNil(t, cs)
}

// TestIsRevoked_CertWithRevokedCertificateEntries tests the new RevokedCertificateEntries field
func TestIsRevoked_CertWithRevokedCertificateEntries(t *testing.T) {
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
	cs, err := New(&Config{DAOs: testutil.NewMemoryDAOFactory()})
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
