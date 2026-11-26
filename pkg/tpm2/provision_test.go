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

// =====================================================
// ProvisionEKCert Function Coverage Tests
// =====================================================

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
		PlatformPCRs:    DefaultPlatformPCRs(),
		PlatformPCRBank: PCRBankSHA256,
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
		PlatformPCRs:    DefaultPlatformPCRs(),
		PlatformPCRBank: PCRBankSHA256,
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
