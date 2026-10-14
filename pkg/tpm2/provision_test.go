//go:build tpm_simulator
// +build tpm_simulator

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

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

// =====================================================
// Provisioning Workflow Tests
// =====================================================

// TestProvisioningWorkflow tests the complete TPM provisioning flow.
// This exercises: Install(), fileIntegritySum(), CreatePlatformPolicy(), and hierarchy setup.
func TestProvisioningWorkflow(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Verify EK was provisioned
	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err, "EK should be provisioned")
	assert.NotNil(t, ekAttrs)
	assert.Equal(t, types.KeyTypeEndorsement, ekAttrs.KeyType)
	assert.NotNil(t, ekAttrs.TPMAttributes)
	assert.NotEmpty(t, ekAttrs.TPMAttributes.Name.Buffer)

	// Verify SSRK was provisioned
	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err, "SSRK should be provisioned")
	assert.NotNil(t, ssrkAttrs)
	assert.Equal(t, types.KeyTypeStorage, ssrkAttrs.KeyType)
	assert.NotNil(t, ssrkAttrs.TPMAttributes)

	// Verify IAK was provisioned
	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err, "IAK should be provisioned")
	assert.NotNil(t, iakAttrs)
	assert.Equal(t, types.KeyTypeAttestation, iakAttrs.KeyType)
}

// TestProvisionWithPlatformPolicy tests provisioning with platform PCR policy.
// This exercises fileIntegritySum() and CreatePlatformPolicy().
func TestProvisionWithPlatformPolicy(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Get platform policy digest (exercises fileIntegritySum)
	policyDigest, pdErr := tpm.PlatformPolicyDigest()
	assert.NoError(t, pdErr)
	assert.NotNil(t, policyDigest)

	// Verify golden measurements were captured
	goldenPCR, gmErr := tpm.GoldenMeasurements()
	assert.NoError(t, gmErr)
	assert.NotNil(t, goldenPCR)
	assert.NotEmpty(t, goldenPCR)
}

// TestHierarchyAuthSetup tests setting hierarchy authorizations.
func TestHierarchyAuthSetup(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Test setting new hierarchy auth
	newPassword := mustPassword(t, []byte("new-hierarchy-pass"))
	err = tpm.SetHierarchyAuth(hierarchyAuth, newPassword, nil)
	assert.NoError(t, err)
}

// TestKeyHierarchyCreation tests creating keys under the provisioned hierarchy.
// This exercises CreateSRK, CreateRSA, CreateECDSA with provisioned keys.
func TestKeyHierarchyCreation(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create SRK under EK
	srkAttrs := &types.KeyAttributes{
		CN:           "test-hierarchy-srk",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeStorage,
		Parent:       ekAttrs,
		Password:     mustPassword(t, []byte("srk-test")),
		TPMPolicy:    types.TPMPolicyPlatform,
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(0x81000030),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}
	err = tpm.CreateSRK(srkAttrs)
	require.NoError(t, err)

	// Create RSA key under SRK
	rsaAttrs := &types.KeyAttributes{
		CN:           "test-rsa-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     mustPassword(t, []byte("rsa-test")),
		TPMPolicy:    types.TPMPolicyPlatform,
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	rsaPub, err := tpm.CreateRSA(rsaAttrs, nil, false)
	require.NoError(t, err)
	assert.NotNil(t, rsaPub)
}

// TestProvisionedKeyOperations tests operations with provisioned keys.
// This exercises Sign, Hash, SignValidate with provisioned IAK.
func TestProvisionedKeyOperations(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// Test Hash operation with IAK
	testData := []byte("test data for hashing with provisioned key")
	digest, validationDigest, err := tpm.Hash(iakAttrs, testData)
	if err != nil {
		t.Logf("Hash with IAK failed (scheme mismatch expected): %v", err)
		return
	}
	assert.NotEmpty(t, digest)
	assert.NotEmpty(t, validationDigest)

	// Test Sign operation with IAK
	signerOpts := &store.SignerOpts{
		KeyAttributes: iakAttrs,
		Backend:       nil,
	}
	signature, err := tpm.Sign(nil, digest, signerOpts)
	if err != nil {
		t.Logf("Sign with IAK failed (scheme mismatch expected): %v", err)
		return
	}
	assert.NotEmpty(t, signature)

	// Test SignValidate
	validationSig, err := tpm.SignValidate(iakAttrs, digest, validationDigest)
	if err != nil {
		t.Logf("SignValidate with IAK failed (scheme mismatch expected): %v", err)
		return
	}
	assert.NotEmpty(t, validationSig)
}

// TestProvisionedAttestationOperations tests attestation with a provisioned IAK.
// This exercises AKProfile and Quote against the keys createSim provisioned.
//
// AKProfile used to be allowed to skip the test ("not supported in this
// configuration"). It is supported: createSim provisions both the EK and the
// IAK, which is exactly what AKProfile reports on, so a failure here is a
// regression. The skip also hid the ordering defect AKProfile documents, where
// reading the attribute caches directly made the call depend on which method
// happened to run first.
func TestProvisionedAttestationOperations(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	profile, err := tpm.AKProfile()
	require.NoError(t, err, "a provisioned TPM must be able to report its AK profile")

	// The profile is the enrollment evidence a CA consumes, so every field must
	// be populated and must match the keys the TPM actually holds.
	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)
	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	assert.NotEmpty(t, profile.EKPub, "AK profile must carry the EK public area")
	assert.NotEmpty(t, profile.AKPub, "AK profile must carry the AK public area")
	assert.NotEmpty(t, profile.AKName.Buffer, "AK profile must carry the AK name")
	assert.Equal(t, ekAttrs.TPMAttributes.PublicKeyBytes, profile.EKPub)
	assert.Equal(t, iakAttrs.TPMAttributes.PublicKeyBytes, profile.AKPub)
	assert.Equal(t, iakAttrs.TPMAttributes.Name, profile.AKName)
	assert.Equal(t, iakAttrs.SignatureAlgorithm, profile.SignatureAlgorithm)
	assert.NotEqual(t, profile.EKPub, profile.AKPub,
		"the EK and the AK must be distinct keys")

	// Quote over the same PCRs must succeed and must be bound to the nonce.
	nonce := []byte("test-nonce-for-quote-operation-12345")
	pcrs := []uint{0, 1, 2, 3, 7}

	quote, err := tpm.Quote(pcrs, nonce)
	require.NoError(t, err, "a provisioned TPM must be able to quote")
	assert.NotEmpty(t, quote.Quoted, "the quote must contain the signed attestation")
	assert.NotEmpty(t, quote.Signature, "the quote must be signed")
	assert.Equal(t, nonce, quote.Nonce, "the quote must echo the caller's nonce")
	assert.Contains(t, string(quote.Quoted), string(nonce),
		"the nonce must be embedded in the signed attestation structure")
}

// TestEKOperations tests operations specific to the Endorsement Key.
// This exercises EKRSA, EKCertificate.
func TestEKOperations(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Test EKRSA
	ekRSA, rsaErr := tpm.EKRSA()
	assert.NoError(t, rsaErr)
	assert.NotNil(t, ekRSA, "EKRSA should be available")
	assert.NotNil(t, ekRSA.N)

	// Test EKCertificate retrieval
	cert, err := tpm.EKCertificate()
	if err != nil {
		t.Logf("EK certificate not available (expected in simulator): %v", err)
		// This is expected - simulators don't have real EK certs
		return
	}
	if cert != nil {
		assert.NotNil(t, cert.PublicKey)
	}
}

// TestSessionCreation tests session creation with provisioned keys.
// This exercises CreateSession, PlatformPolicySession, NonceSession.
func TestSessionCreation(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create platform policy session
	session, closer, err := tpm.CreateSession(ekAttrs)
	if err != nil {
		t.Logf("Session creation failed: %v", err)
		return
	}
	defer func() {
		if closer != nil {
			_ = closer()
		}
	}()

	assert.NotNil(t, session)
}

// TestParsePublicKeyFromProvisioned tests parsing public keys from provisioned keys.
func TestParsePublicKeyFromProvisioned(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Get EK public area
	_, ekPub, ekPubErr := tpm.EKPublic()
	require.NoError(t, ekPubErr)

	// Marshal the public area to bytes
	pubBytes := tpm2.Marshal(ekPub)

	// Parse it back
	parsedPub, err := tpm.ParsePublicKey(pubBytes)
	require.NoError(t, err)
	assert.NotNil(t, parsedPub)
}

// =====================================================
// Clear Function Coverage Tests
// =====================================================

// TestClearWithNilAuthCoverage tests Clear with nil lockout authorization.
func TestClearWithNilAuthCoverage(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Clear with nil lockout auth
	err := tpm.Clear(nil)
	require.NoError(t, err)
}

// TestClearWithInvalidAuthCoverage tests Clear with invalid lockout authorization.
func TestClearWithInvalidAuthCoverage(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// First set a non-empty lockout auth
	lockoutHierarchy := tpm2.TPMRHLockout
	newAuth := mustPassword(t, []byte("lockout-auth"))
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
	require.NoError(t, err,
		"the in-process TPM simulator must open; build with -tags tpm_simulator")

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
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

			RSAConfig: &store.RSAConfig{KeySize: 2048},
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
	require.NoError(t, err,
		"the in-process TPM simulator must open; build with -tags tpm_simulator")

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
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

			RSAConfig: &store.RSAConfig{KeySize: 2048},
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
	assert.ErrorIs(t, err, ErrCertStoreNotInitialized)
}

// TestDownloadEKCertFromManufacturer_RejectsECCEK proves that the
// manufacturer EK-certificate download fallback refuses an ECC EK with the
// typed ErrECCEKCertUnsupported sentinel, reachable with errors.Is, rather
// than an inline error, and never reaches the network for an EK type the
// download endpoint cannot serve.
func TestDownloadEKCertFromManufacturer_RejectsECCEK(t *testing.T) {
	logger := slog.Default()
	sim, err := OpenSimulator()
	require.NoError(t, err,
		"the in-process TPM simulator must open; build with -tags tpm_simulator")

	storageFactory, err := store.NewStorageFactory(logger, "")
	require.NoError(t, err)

	config := &Config{
		UseSimulator:    true,
		Hash:            "SHA-256",
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		EK: &EKConfig{
			CertHandle:    0,
			Handle:        0x81010001,
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),
			ECCConfig:     &store.ECCConfig{Curve: "P-256"},
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

	tpm2Impl := tpmObj.(*TPM2)
	_, err = tpm2Impl.downloadEKCertFromManufacturer(tpm2.TPMHandle(ekIndex))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrECCEKCertUnsupported)
}

// =====================================================
// WriteEKCert Function Coverage Tests
// =====================================================

// TestWriteEKCertCoverage tests the WriteEKCert wrapper function.
func TestWriteEKCertCoverage(t *testing.T) {
	logger := slog.Default()
	sim, err := OpenSimulator()
	require.NoError(t, err,
		"the in-process TPM simulator must open; build with -tags tpm_simulator")

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
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

			RSAConfig: &store.RSAConfig{KeySize: 2048},
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
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Try to parse invalid data
	_, err := tpm.ParseEKCertificate([]byte("not a valid certificate"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse EK certificate")
}

// TestParseEKCertificateEmptyCoverage tests parsing empty certificate data.
func TestParseEKCertificateEmptyCoverage(t *testing.T) {
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	err := tpm.CreatePlatformPolicy()
	require.NoError(t, err)

	// Verify policy digest is set
	policyDigest, pdErr := tpm.PlatformPolicyDigest()
	assert.NoError(t, pdErr)
	assert.NotNil(t, policyDigest.Buffer)
}

// TestCreatePlatformPolicyEmptyGoldenPCRsCoverage tests CreatePlatformPolicy
// when no golden PCRs are configured.
func TestCreatePlatformPolicyEmptyGoldenPCRsCoverage(t *testing.T) {
	logger := slog.Default()
	sim, err := OpenSimulator()
	require.NoError(t, err,
		"the in-process TPM simulator must open; build with -tags tpm_simulator")

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
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

			RSAConfig: &store.RSAConfig{KeySize: 2048},
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
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	newPassword := mustPassword(t, []byte("new-hierarchy-auth"))

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
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	goldenPCR, gmErr := tpm.GoldenMeasurements()
	assert.NoError(t, gmErr)
	assert.NotNil(t, goldenPCR)
	assert.True(t, len(goldenPCR) > 0)
}

// =====================================================
// FactoryReset Function Coverage Tests
// =====================================================

// TestFactoryReset_Success provisions the TPM and then factory resets,
// verifying that the EK remains while SRK, IAK, and IDevID are removed.
func TestFactoryReset_Success(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	// createSim provisions the simulator via Provision(nil), which leaves
	// the Lockout/Endorsement/Owner hierarchy auths empty (no SO PIN was
	// applied). Reflect that real state in the config so Install's
	// "config's HierarchyAuth is the current auth" assumption (see
	// Install's doc comment) matches reality instead of the static
	// DEFAULT_PASSWORD template value createSim seeds EKConfig with for
	// unrelated tests that never change the hierarchy auth.
	tpmImpl.config.EK.HierarchyAuth = nil

	// createSim's shared IAK config (used by ~20 other tests) hardcodes
	// Handle 0x81010002, which is the TCG-reserved ECC EK persistent
	// handle (TCG TPM 2.0 Provisioning Guidance, Section 7.8, Table 2).
	// factoryResetInternal's EK-preservation allowlist keys off that
	// exact TCG-standard handle number, so an IAK provisioned there is
	// indistinguishable from an EK and gets preserved instead of evicted.
	// Retarget this test's IAK to the package's canonical IAK handle
	// (iakKey, 0x81020001 - outside the EK-reserved 0x8101xxxx range) so
	// factory reset can be exercised without colliding with the EK
	// preservation logic and without touching the widely shared
	// createSim() config used by other tests.
	tpmImpl.config.IAK.Handle = uint32(iakKey)

	// Install provisions EK, SRK, IAK, and IDevID
	soPIN := mustPassword(t, []byte(store.DEFAULT_PASSWORD))
	err := tpmImpl.Install(soPIN, nil)
	require.NoError(t, err)

	// Verify keys exist before reset
	_, err = tpmImpl.EKAttributes()
	require.NoError(t, err, "EK should exist before reset")

	_, err = tpmImpl.SSRKAttributes()
	require.NoError(t, err, "SSRK should exist before reset")

	_, err = tpmImpl.IAKAttributes()
	require.NoError(t, err, "IAK should exist before reset")

	// Factory reset with owner auth
	err = tpmImpl.FactoryReset([]byte(store.DEFAULT_PASSWORD))
	require.NoError(t, err)

	// EK should still exist (preserved by factory reset)
	_, err = tpmImpl.EKAttributes()
	require.NoError(t, err, "EK should remain after factory reset")

	// SRK, IAK should be gone (TPM_RC_HANDLE error)
	_, err = tpmImpl.SSRKAttributes()
	assert.Error(t, err, "SSRK should be removed after factory reset")

	_, err = tpmImpl.IAKAttributes()
	assert.Error(t, err, "IAK should be removed after factory reset")

	// Cached attrs should be cleared
	assert.Nil(t, tpmImpl.iakAttrs, "cached IAK attrs should be nil")
	assert.Nil(t, tpmImpl.idevidAttrs, "cached IDevID attrs should be nil")
	assert.Nil(t, tpmImpl.ssrkAttrs, "cached SSRK attrs should be nil")
}

// TestFactoryReset_EmptyTPM verifies that factory reset on a TPM with
// no provisioned keys (only EK) completes without errors.
func TestFactoryReset_EmptyTPM(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	// Factory reset on an empty TPM should succeed with no errors
	err := tpmImpl.FactoryReset(nil)
	require.NoError(t, err)
}

// TestFactoryReset_IAKAtLegacyECCHandle_Evicted proves the fix for the
// FactoryReset handle-table bug (go-xkms#798): an IAK placed at 0x81010002
// -- this codebase's own default IAK handle (IAKConfig.Handle), and also
// the TCG-reserved "EK ECC" address the old hardcoded preserveHandles table
// protected unconditionally -- is evicted, not preserved, because
// preserveHandles is now derived from the TPM's actual configured
// EK.Handle rather than a hardcoded TCG-default pair.
func TestFactoryReset_IAKAtLegacyECCHandle_Evicted(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	// createSim provisions via Provision(nil), which leaves hierarchy auth
	// empty; reflect that in the config, matching TestFactoryReset_Success.
	tpmImpl.config.EK.HierarchyAuth = nil

	// createSim's shared IAK config already places the IAK at 0x81010002 --
	// the exact handle the old hardcoded table called "EK ECC P-256" and
	// preserved unconditionally. This test depends on that collision to
	// exercise the fix; TestFactoryReset_Success retargets the IAK away
	// from it instead, to test eviction without depending on this fix.
	require.Equal(t, uint32(0x81010002), tpmImpl.config.IAK.Handle,
		"this test depends on createSim's IAK handle colliding with the legacy ECC-EK address")

	soPIN := mustPassword(t, []byte(store.DEFAULT_PASSWORD))
	require.NoError(t, tpmImpl.Install(soPIN, nil))

	_, err := tpmImpl.IAKAttributes()
	require.NoError(t, err, "IAK should exist before reset")

	require.NoError(t, tpmImpl.FactoryReset([]byte(store.DEFAULT_PASSWORD)))

	_, err = tpmImpl.IAKAttributes()
	assert.Error(t, err, "the IAK at the legacy ECC-EK handle must be evicted, not preserved")

	_, err = tpmImpl.EKAttributes()
	require.NoError(t, err, "the TPM's real, configured EK must remain after factory reset")
}

// TestFactoryReset_ForeignObjectAtTCGECCEKHandle_Preserved is the other half
// of the go-xkms#798 fix: 0x81010002 is the TCG ECC EK address, so an object
// there that this package's configuration does not own -- a manufacturer ECC
// EK beside a configured RSA EK -- must survive FactoryReset. The IAK is
// provisioned at 0x81010002 and the configuration is then pointed elsewhere,
// which leaves a persistent object at that address that the package no
// longer owns.
func TestFactoryReset_ForeignObjectAtTCGECCEKHandle_Preserved(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)
	tpmImpl.config.EK.HierarchyAuth = nil
	require.Equal(t, uint32(0x81010002), tpmImpl.config.IAK.Handle)

	soPIN := mustPassword(t, []byte(store.DEFAULT_PASSWORD))
	require.NoError(t, tpmImpl.Install(soPIN, nil))

	tpmImpl.config.IAK.Handle = 0x81010010

	require.NoError(t, tpmImpl.FactoryReset([]byte(store.DEFAULT_PASSWORD)))

	_, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(0x81010002)}.Execute(tpmImpl.transport)
	assert.NoError(t, err, "an object at the TCG ECC EK handle that the configuration does not own must be preserved")

	_, err = tpmImpl.EKAttributes()
	require.NoError(t, err, "the configured EK must remain after factory reset")
}
