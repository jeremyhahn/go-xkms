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

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================
// Mock CertStore for Tests
// =====================================================

// mockCertStoreProvision implements store.CertificateStorer for testing
type mockCertStoreProvision struct {
	certs map[string]*x509.Certificate
}

func newMockCertStoreProvision() *mockCertStoreProvision {
	return &mockCertStoreProvision{
		certs: make(map[string]*x509.Certificate),
	}
}

func (m *mockCertStoreProvision) Get(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	cert, ok := m.certs[attrs.CN]
	if !ok {
		return nil, store.ErrCertNotFound
	}
	return cert, nil
}

func (m *mockCertStoreProvision) Save(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	m.certs[attrs.CN] = cert
	return nil
}

func (m *mockCertStoreProvision) Delete(attrs *types.KeyAttributes) error {
	delete(m.certs, attrs.CN)
	return nil
}

func (m *mockCertStoreProvision) ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	return nil, nil
}

// =====================================================
// Clear Function Coverage Tests
// =====================================================

// TestClearWithNilAuthCoverage tests Clear with nil lockout authorization.
func TestClearWithNilAuthCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Clear with nil lockout auth
	err := tpm.Clear(nil)
	require.NoError(t, err)
}

// TestClearWithInvalidAuthCoverage tests Clear with invalid lockout authorization.
func TestClearWithInvalidAuthCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// First set a non-empty lockout auth
	lockoutHierarchy := tpm2.TPMRHLockout
	newAuth := store.NewClearPassword([]byte("lockout-auth"))
	err := tpm.SetHierarchyAuth(nil, newAuth, &lockoutHierarchy)
	require.NoError(t, err)

	// Now try to clear with wrong auth (should fail)
	err = tpm.Clear([]byte("wrong-auth"))
	assert.Error(t, err)
}

// =====================================================
// ProvisionEKCert Function Coverage Tests
// =====================================================

// TestProvisionEKCertWithCertStoreCoverage tests ProvisionEKCert when CertHandle is 0
// (certificate is stored in cert store instead of NVRAM).
func TestProvisionEKCertWithCertStoreCoverage(t *testing.T) {
	logger := slog.Default()
	sim, err := OpenSimulator()
	if err != nil {
		t.Skip("simulator not available")
	}

	storageFactory, err := store.NewStorageFactory(logger, "")
	require.NoError(t, err)

	certStore := newMockCertStoreProvision()

	config := &Config{
		UseSimulator:    true,
		Hash:            "SHA-256",
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		EK: &EKConfig{
			CertHandle:    0, // Use cert store
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
		},
		SSRK: &SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &store.RSAConfig{KeySize: 2048},
		},
		IAK: &IAKConfig{
			CN:                 "device-id-001",
			Hash:               crypto.SHA256.String(),
			Handle:             uint32(0x81010002),
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
	}

	params := &Params{
		Logger:    logger,
		Config:    config,
		BlobStore: storageFactory.BlobStore(),
		Backend:   storageFactory.KeyBackend(),
		CertStore: certStore,
		Transport: sim.Transport(),
	}

	tpmObj, err := NewTPM2(params)
	if err == ErrNotInitialized {
		err = tpmObj.Provision(nil)
		require.NoError(t, err)
	} else {
		require.NoError(t, err)
	}
	defer func() {
		_ = tpmObj.Close()
		_ = sim.Close()
	}()

	// Create a test certificate
	cert := createProvisionTestCertificate(t)

	// Provision EK cert (should go to cert store since CertHandle = 0)
	err = tpmObj.ProvisionEKCert(nil, cert.Raw)
	require.NoError(t, err)
}

// TestProvisionEKCertNilCertStoreCoverage tests ProvisionEKCert when CertHandle is 0
// but cert store is nil (should return error).
func TestProvisionEKCertNilCertStoreCoverage(t *testing.T) {
	logger := slog.Default()
	sim, err := OpenSimulator()
	if err != nil {
		t.Skip("simulator not available")
	}

	storageFactory, err := store.NewStorageFactory(logger, "")
	require.NoError(t, err)

	config := &Config{
		UseSimulator:    true,
		Hash:            "SHA-256",
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		EK: &EKConfig{
			CertHandle:    0, // Use cert store
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
		},
		SSRK: &SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &store.RSAConfig{KeySize: 2048},
		},
		IAK: &IAKConfig{
			CN:                 "device-id-001",
			Hash:               crypto.SHA256.String(),
			Handle:             uint32(0x81010002),
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
	}

	params := &Params{
		Logger:    logger,
		Config:    config,
		BlobStore: storageFactory.BlobStore(),
		Backend:   storageFactory.KeyBackend(),
		CertStore: nil, // No cert store
		Transport: sim.Transport(),
	}

	tpmObj, err := NewTPM2(params)
	if err == ErrNotInitialized {
		err = tpmObj.Provision(nil)
		require.NoError(t, err)
	} else {
		require.NoError(t, err)
	}
	defer func() {
		_ = tpmObj.Close()
		_ = sim.Close()
	}()

	cert := createProvisionTestCertificate(t)

	// Should fail because cert store is nil
	err = tpmObj.ProvisionEKCert(nil, cert.Raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate store not initialized")
}

// =====================================================
// WriteEKCert Function Coverage Tests
// =====================================================

// TestWriteEKCertCoverage tests the WriteEKCert wrapper function.
func TestWriteEKCertCoverage(t *testing.T) {
	logger := slog.Default()
	sim, err := OpenSimulator()
	if err != nil {
		t.Skip("simulator not available")
	}

	storageFactory, err := store.NewStorageFactory(logger, "")
	require.NoError(t, err)

	certStore := newMockCertStoreProvision()

	config := &Config{
		UseSimulator:    true,
		Hash:            "SHA-256",
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		EK: &EKConfig{
			CertHandle:    0, // Use cert store
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
		},
		SSRK: &SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &store.RSAConfig{KeySize: 2048},
		},
		IAK: &IAKConfig{
			CN:                 "device-id-001",
			Hash:               crypto.SHA256.String(),
			Handle:             uint32(0x81010002),
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
	}

	params := &Params{
		Logger:    logger,
		Config:    config,
		BlobStore: storageFactory.BlobStore(),
		Backend:   storageFactory.KeyBackend(),
		CertStore: certStore,
		Transport: sim.Transport(),
	}

	tpmObj, err := NewTPM2(params)
	if err == ErrNotInitialized {
		err = tpmObj.Provision(nil)
		require.NoError(t, err)
	} else {
		require.NoError(t, err)
	}
	defer func() {
		_ = tpmObj.Close()
		_ = sim.Close()
	}()

	cert := createProvisionTestCertificate(t)

	// Use WriteEKCert (wrapper for ProvisionEKCert with nil hierarchy auth)
	err = tpmObj.WriteEKCert(cert.Raw)
	require.NoError(t, err)
}

// =====================================================
// ParseEKCertificate Function Coverage Tests
// =====================================================

// TestParseEKCertificateValidCoverage tests parsing of valid DER-encoded certificates.
func TestParseEKCertificateValidCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	testCert := createProvisionTestCertificate(t)

	// Parse valid certificate
	parsed, err := tpm.ParseEKCertificate(testCert.Raw)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, testCert.Subject.CommonName, parsed.Subject.CommonName)
}

// TestParseEKCertificateInvalidCoverage tests parsing of invalid certificate data.
func TestParseEKCertificateInvalidCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to parse invalid data
	_, err := tpm.ParseEKCertificate([]byte("not a valid certificate"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse EK certificate")
}

// TestParseEKCertificateEmptyCoverage tests parsing empty certificate data.
func TestParseEKCertificateEmptyCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to parse empty data
	_, err := tpm.ParseEKCertificate([]byte{})
	assert.Error(t, err)
}

// =====================================================
// PlatformPolicyDigestHash Function Coverage Tests
// =====================================================

// TestPlatformPolicyDigestHashCoverage tests retrieving the platform policy digest hash.
func TestPlatformPolicyDigestHashCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	digest, err := tpm.PlatformPolicyDigestHash()
	require.NoError(t, err)
	assert.NotNil(t, digest)
	assert.True(t, len(digest) > 0)
}

// =====================================================
// CreatePlatformPolicy Function Coverage Tests
// =====================================================

// TestCreatePlatformPolicyCoverage tests the platform policy creation.
func TestCreatePlatformPolicyCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	err := tpm.CreatePlatformPolicy()
	require.NoError(t, err)

	// Verify policy digest is set
	policyDigest := tpm.PlatformPolicyDigest()
	assert.NotNil(t, policyDigest.Buffer)
}

// TestCreatePlatformPolicyEmptyGoldenPCRsCoverage tests CreatePlatformPolicy
// when no golden PCRs are configured.
func TestCreatePlatformPolicyEmptyGoldenPCRsCoverage(t *testing.T) {
	logger := slog.Default()
	sim, err := OpenSimulator()
	if err != nil {
		t.Skip("simulator not available")
	}

	storageFactory, err := store.NewStorageFactory(logger, "")
	require.NoError(t, err)

	config := &Config{
		UseSimulator:    true,
		Hash:            "SHA-256",
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{}, // Empty golden PCRs
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
		},
		SSRK: &SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &store.RSAConfig{KeySize: 2048},
		},
		IAK: &IAKConfig{
			CN:                 "device-id-001",
			Hash:               crypto.SHA256.String(),
			Handle:             uint32(0x81010002),
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
	}

	params := &Params{
		Logger:    logger,
		Config:    config,
		BlobStore: storageFactory.BlobStore(),
		Backend:   storageFactory.KeyBackend(),
		Transport: sim.Transport(),
	}

	tpmObj, err := NewTPM2(params)
	if err == ErrNotInitialized {
		err = tpmObj.Provision(nil)
		require.NoError(t, err)
	} else {
		require.NoError(t, err)
	}
	defer func() {
		_ = tpmObj.Close()
		_ = sim.Close()
	}()

	// CreatePlatformPolicy should return nil and skip PCR extension
	err = tpmObj.CreatePlatformPolicy()
	require.NoError(t, err)
}

// =====================================================
// SetHierarchyAuth Function Coverage Tests
// =====================================================

// TestSetHierarchyAuthSpecificHierarchyCoverage tests setting auth for specific hierarchies.
func TestSetHierarchyAuthSpecificHierarchyCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	newPassword := store.NewClearPassword([]byte("new-hierarchy-auth"))

	// Test setting Owner hierarchy auth
	ownerHierarchy := tpm2.TPMRHOwner
	err := tpm.SetHierarchyAuth(nil, newPassword, &ownerHierarchy)
	require.NoError(t, err)

	// Test setting Endorsement hierarchy auth
	endorsementHierarchy := tpm2.TPMRHEndorsement
	err = tpm.SetHierarchyAuth(nil, newPassword, &endorsementHierarchy)
	require.NoError(t, err)

	// Test setting Lockout hierarchy auth
	lockoutHierarchy := tpm2.TPMRHLockout
	err = tpm.SetHierarchyAuth(nil, newPassword, &lockoutHierarchy)
	require.NoError(t, err)
}

// =====================================================
// GoldenMeasurements Function Coverage Tests
// =====================================================

// TestGoldenMeasurementsCoverage tests the GoldenMeasurements function.
func TestGoldenMeasurementsCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	goldenPCR := tpm.GoldenMeasurements()
	assert.NotNil(t, goldenPCR)
	assert.True(t, len(goldenPCR) > 0)
}

// =====================================================
// Helper Functions
// =====================================================

// createProvisionTestCertificate creates a test X.509 certificate for testing.
func createProvisionTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
			CommonName:   "Test EK Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}
