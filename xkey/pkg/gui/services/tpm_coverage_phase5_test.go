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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ---------------------------------------------------------------------------
// p5a mock helpers — unique names to avoid conflicts with other test files
// ---------------------------------------------------------------------------

// p5aMockPINBackend adds configurable VerifySOPIN support.
type p5aMockPINBackend struct {
	strategy        qrdbsdk.PINStrategyID
	soPINSet        bool
	userPINSet      bool
	initialized     bool
	setSOPINErr     error
	setUserPINErr   error
	changeSOPINErr  error
	changeUserErr   error
	verifyUserErr   error
	verifySOPINErr  error
	resetLockoutErr error
	lockoutStatus   *qrdbsdk.PINLockoutStatus
}

func (m *p5aMockPINBackend) Strategy() qrdbsdk.PINStrategyID             { return m.strategy }
func (m *p5aMockPINBackend) SOPINSet() bool                              { return m.soPINSet }
func (m *p5aMockPINBackend) UserPINSet() bool                            { return m.userPINSet }
func (m *p5aMockPINBackend) IsInitialized() bool                         { return m.initialized }
func (m *p5aMockPINBackend) GetLockoutStatus() *qrdbsdk.PINLockoutStatus { return m.lockoutStatus }
func (m *p5aMockPINBackend) SetSOPIN(_, _ string) error                  { return m.setSOPINErr }
func (m *p5aMockPINBackend) SetUserPIN(_, _ string) error                { return m.setUserPINErr }
func (m *p5aMockPINBackend) ChangeSOPIN(_, _ string) error               { return m.changeSOPINErr }
func (m *p5aMockPINBackend) ChangeUserPIN(_, _ string) error             { return m.changeUserErr }
func (m *p5aMockPINBackend) VerifySOPIN(_ string) error                  { return m.verifySOPINErr }
func (m *p5aMockPINBackend) VerifyUserPIN(_ string) error                { return m.verifyUserErr }
func (m *p5aMockPINBackend) ResetLockout(_ string) error                 { return m.resetLockoutErr }
func (m *p5aMockPINBackend) SetMaxAttempts(_ int)                        {}

// p5aNewPINService creates a PINService with the given backend and context.
func p5aNewPINService(backend qrdbsdk.PINBackend) *PINService {
	svc := NewPINService()
	svc.SetContext(context.Background())
	if backend != nil {
		pSvc := qrdbsdk.NewPINService(backend, slog.Default())
		svc.SetPINService(pSvc)
	}
	return svc
}

// p5aDefaultMockTPM returns a minimal mock suitable for most tests.
func p5aDefaultMockTPM() *mockTPM {
	return &mockTPM{
		device: "/dev/tpmrm0",
		config: &xkms.TPMConfig{
			Hash: "SHA-256",
			SSRK: &xkms.SRKConfig{
				Handle:       0x81000001,
				KeyAlgorithm: "RSA",
			},
		},
		fixedProps: &xkms.PropertiesFixed{
			Manufacturer:       "P5TestMFG",
			VendorID:           "P5ID",
			Family:             "2.0",
			Revision:           "1.38",
			FwMajor:            7,
			FwMinor:            85,
			NVBufferMax:        2048,
			MaxAuthFail:        32,
			ActiveSessionsMax:  64,
			AuthSessionsLoaded: 3,
			PersistentLoaded:   5,
			PersistentAvail:    7,
			NVIndexesDefined:   4,
			NVIndexesMax:       32,
			MaxRSAKeyBits:      2048,
			MaxECCKeyBits:      384,
		},
		ekAttrs: &xkms.KeyAttributes{
			KeyAlgorithm:  x509.RSA,
			RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
			TPMAttributes: &xkms.TPMAttributes{Handle: 0x81010001},
		},
		ssrkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		pcrBanks: []xkms.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []xkms.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB}},
				},
			},
		},
		randomBytesVal: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		supportedAlgos: []string{"RSA", "SHA-256"},
	}
}

// p5aGenerateTestCert generates a self-signed test certificate.
func p5aGenerateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "p5a-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// p5aTestCertPEM returns a PEM-encoded test certificate.
func p5aTestCertPEM(t *testing.T) string {
	t.Helper()
	cert := p5aGenerateTestCert(t)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// p5aMockTrustStore implements truststore.TrustStore for testing.
type p5aMockTrustStore struct {
	certs map[truststore.CertPurpose][]*x509.Certificate
}

func (m *p5aMockTrustStore) AddCertificate(_ *x509.Certificate) error { return nil }
func (m *p5aMockTrustStore) AddCertificateWithOptions(_ *x509.Certificate, _ *truststore.AddCertificateOptions) error {
	return nil
}
func (m *p5aMockTrustStore) RemoveCertificate(_ string) error { return nil }
func (m *p5aMockTrustStore) CertificatesByPurpose(purpose truststore.CertPurpose) ([]*x509.Certificate, error) {
	return m.certs[purpose], nil
}
func (m *p5aMockTrustStore) Certificates() ([]*x509.Certificate, error) { return nil, nil }
func (m *p5aMockTrustStore) AddPEM(_ []byte) (int, error)               { return 0, nil }
func (m *p5aMockTrustStore) ImportPEM(_ []byte, _ *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	return truststore.ImportResult{}, nil
}
func (m *p5aMockTrustStore) CertPool() (*x509.CertPool, error)                   { return x509.NewCertPool(), nil }
func (m *p5aMockTrustStore) Contains(_ string) (bool, error)                     { return false, nil }
func (m *p5aMockTrustStore) Count() (int, error)                                 { return 0, nil }
func (m *p5aMockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) { return nil, nil }
func (m *p5aMockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error { return nil }
func (m *p5aMockTrustStore) SetSource(_ string, _ string) error                  { return nil }
func (m *p5aMockTrustStore) SetSystemInstalled(_ string, _ bool) error           { return nil }
func (m *p5aMockTrustStore) SetTags(_ string, _ []string) error                  { return nil }
func (m *p5aMockTrustStore) Close() error                                        { return nil }
func (m *p5aMockTrustStore) Reload() error                                       { return nil }

// ---------------------------------------------------------------------------
// PIN Service tests — covering specific uncovered branches
// ---------------------------------------------------------------------------

// TestP5A_PINService_VerifySOPIN_SuccessPath tests the happy path of VerifySOPIN
// when the underlying manager returns nil (success). The original mockPINBackend
// always returns nil from VerifySOPIN, so this explicitly tests with our p5a mock.
func TestP5A_PINService_VerifySOPIN_SuccessPath(t *testing.T) {
	mgr := &p5aMockPINBackend{
		strategy:       qrdbsdk.PINStrategySoftware,
		verifySOPINErr: nil,
	}
	svc := p5aNewPINService(mgr)

	err := svc.VerifySOPIN("valid-so-pin")
	assert.NoError(t, err)
}

// TestP5A_PINService_VerifySOPIN_FailurePath tests VerifySOPIN when the
// manager returns an error.
func TestP5A_PINService_VerifySOPIN_FailurePath(t *testing.T) {
	mgr := &p5aMockPINBackend{
		strategy:       qrdbsdk.PINStrategySoftware,
		verifySOPINErr: qrdbsdk.ErrPINInvalid,
	}
	svc := p5aNewPINService(mgr)

	err := svc.VerifySOPIN("wrong-pin")
	assert.ErrorIs(t, err, qrdbsdk.ErrPINInvalid)
}

// TestP5A_PINService_GetLockoutStatus_NilStatus tests GetLockoutStatus when
// the PINManager returns a nil LockoutStatus. The service must translate the
// backend's nil (software backend has no lockout) into a zero-value status so
// the Wails binding never serializes JSON null to the frontend.
func TestP5A_PINService_GetLockoutStatus_NilStatus(t *testing.T) {
	mgr := &p5aMockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		lockoutStatus: nil,
	}
	svc := p5aNewPINService(mgr)

	status, err := svc.GetLockoutStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Zero(t, status.FailedAttempts)
	assert.False(t, status.IsLocked)
}

// TestP5A_PINService_ResetLockout_SuccessWithMgr tests ResetLockout through the
// full success path including the manager returning nil.
func TestP5A_PINService_ResetLockout_SuccessWithMgr(t *testing.T) {
	mgr := &p5aMockPINBackend{
		strategy:        qrdbsdk.PINStrategySoftware,
		resetLockoutErr: nil,
	}
	svc := p5aNewPINService(mgr)

	err := svc.ResetLockout("valid-so-pin")
	assert.NoError(t, err)
}

// TestP5A_PINService_SetSOPIN_SuccessPath tests SetSOPIN success path
// with the mock manager returning no error.
func TestP5A_PINService_SetSOPIN_SuccessPath(t *testing.T) {
	mgr := &p5aMockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := p5aNewPINService(mgr)

	err := svc.SetSOPIN("current-sopin", "new-sopin")
	assert.NoError(t, err)
}

// TestP5A_PINService_ChangeSOPIN_ErrorPath tests ChangeSOPIN when the
// manager returns an error.
func TestP5A_PINService_ChangeSOPIN_ErrorPath(t *testing.T) {
	testErr := errors.New("p5a: change sopin failed")
	mgr := &p5aMockPINBackend{
		strategy:       qrdbsdk.PINStrategySoftware,
		changeSOPINErr: testErr,
	}
	svc := p5aNewPINService(mgr)

	err := svc.ChangeSOPIN("old-sopin", "new-sopin")
	assert.Equal(t, testErr, err)
}

// TestP5A_PINService_VerifyUserPIN_ErrorPath tests VerifyUserPIN when the
// manager returns an error.
func TestP5A_PINService_VerifyUserPIN_ErrorPath(t *testing.T) {
	mgr := &p5aMockPINBackend{
		strategy:      qrdbsdk.PINStrategySoftware,
		verifyUserErr: qrdbsdk.ErrPINInvalid,
	}
	svc := p5aNewPINService(mgr)

	err := svc.VerifyUserPIN("wrong-pin")
	assert.ErrorIs(t, err, qrdbsdk.ErrPINInvalid)
}

// TestP5A_PINService_GetPINStatus_MixedState tests GetPINStatus with partial
// initialization (SO PIN set but user PIN not set).
func TestP5A_PINService_GetPINStatus_MixedState(t *testing.T) {
	mgr := &p5aMockPINBackend{
		strategy:    qrdbsdk.PINStrategyTPM2,
		soPINSet:    true,
		userPINSet:  false,
		initialized: true,
	}
	svc := p5aNewPINService(mgr)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.SOPINSet)
	assert.False(t, status.UserPINSet)
	assert.True(t, status.Initialized)
	assert.Equal(t, string(qrdbsdk.PINStrategyTPM2), status.Strategy)
}

// ---------------------------------------------------------------------------
// TPM Service tests — covering uncovered branches
// ---------------------------------------------------------------------------

// TestP5A_AlgoDisplayName_RSAPSS tests the RSA-PSS branch of algoDisplayName
// which is the only uncovered case at 88.9%.
func TestP5A_AlgoDisplayName_RSAPSS(t *testing.T) {
	attrs := &xkms.KeyAttributes{
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}
	result := algoDisplayName(attrs)
	assert.Equal(t, "RSA-PSS", result)
}

// TestP5A_AlgoDisplayName_RSAPSS384 tests with SHA384 PSS variant.
func TestP5A_AlgoDisplayName_RSAPSS384(t *testing.T) {
	attrs := &xkms.KeyAttributes{
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
	}
	assert.Equal(t, "RSA-PSS", algoDisplayName(attrs))
}

// TestP5A_AlgoDisplayName_RSAPSS512 tests with SHA512 PSS variant.
func TestP5A_AlgoDisplayName_RSAPSS512(t *testing.T) {
	attrs := &xkms.KeyAttributes{
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA512WithRSAPSS,
	}
	assert.Equal(t, "RSA-PSS", algoDisplayName(attrs))
}

// TestP5A_GetInfo_SupportedCommandsFallback tests the GetInfo code path where
// the TPM is not a concrete *tpm2pkg.TPM2, so it falls back to the
// SupportedCommands interface method instead of SupportedCommandsInfo.
func TestP5A_GetInfo_SupportedCommandsFallback(t *testing.T) {
	mock := p5aDefaultMockTPM()
	// Mock supports SupportedCommands but is not *tpm2pkg.TPM2.
	// The mock's SupportedCommands() returns nil, nil by default.
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "P5TestMFG", info.Manufacturer)
}

// TestP5A_GetInfo_AlgorithmsFallbackToConfigHash tests the algorithm detection
// fallback when SupportedAlgorithms fails but config.Hash is set.
func TestP5A_GetInfo_AlgorithmsFallbackToConfigHash(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("not supported")
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Should fall back to config.Hash.
	assert.Contains(t, info.Algorithms, "SHA-256")
}

// TestP5A_GetInfo_NoAlgorithmsNoConfig tests when both SupportedAlgorithms
// and config.Hash are unavailable.
func TestP5A_GetInfo_NoAlgorithmsNoConfig(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("not supported")
	mock.config = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.Algorithms)
}

// TestP5A_GetInfo_FIPSError tests GetInfo when IsFIPS140_2 returns an error.
func TestP5A_GetInfo_FIPSError(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.fipsErr = errors.New("FIPS check failed")
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// FIPS error is warned but not returned.
	assert.False(t, info.FIPSMode)
}

// TestP5A_GetInfo_FixedPropsError tests GetInfo when FixedProperties fails.
func TestP5A_GetInfo_FixedPropsError(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.fixedPropsErr = errors.New("props error")
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Returns an empty TPMInfo on error.
	assert.Equal(t, "", info.Manufacturer)
}

// TestP5A_GetInfo_MaxKeySizeDefaults tests that default key sizes are used
// when FixedProperties returns zero values for key bits.
func TestP5A_GetInfo_MaxKeySizeDefaults(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.fixedProps.MaxRSAKeyBits = 0
	mock.fixedProps.MaxECCKeyBits = 0
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Should fall back to defaults.
	assert.Equal(t, 2048, info.MaxRSAKeySize)
	assert.Equal(t, 521, info.MaxECCKeySize)
}

// TestP5A_GetInfo_PCRBanksEmpty tests GetInfo when ReadPCRs returns empty banks.
func TestP5A_GetInfo_PCRBanksEmpty(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.pcrBanksErr = errors.New("PCR read failed")
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Falls back to ["sha256"].
	assert.Equal(t, []string{"sha256"}, info.PCRBanks)
}

// TestP5A_GetInfo_WithEKCert tests GetInfo when EK certificate is available,
// triggering TCG OID attribute parsing.
func TestP5A_GetInfo_WithEKCert(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.ekCert = p5aGenerateTestCert(t)
	mock.ekCertErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
}

// TestP5A_GetEKECCInfo_Success tests GetEKECCInfo with a valid ECC cert.
func TestP5A_GetEKECCInfo_Success(t *testing.T) {
	mock := p5aDefaultMockTPM()
	cert := p5aGenerateTestCert(t)
	mock.ekCertEC = cert
	mock.ekCertECErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Certificate)
}

// TestP5A_GetEKECCInfo_NilCert tests GetEKECCInfo when cert is nil.
func TestP5A_GetEKECCInfo_NilCert(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.ekCertEC = nil
	mock.ekCertECErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// TestP5A_GetIAKInfo_NilAttrs tests GetIAKInfo when IAKAttributes returns
// nil attributes without error.
func TestP5A_GetIAKInfo_NilAttrs(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.iakAttrs = nil
	mock.iakAttrsErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// TestP5A_GetIDevIDInfo_NilAttrs tests GetIDevIDInfo when IDevIDAttributes
// returns nil without error.
func TestP5A_GetIDevIDInfo_NilAttrs(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.idevidAttrs = nil
	mock.idevidAttrsErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// TestP5A_GetIAKInfo_WithCert tests GetIAKInfo when IAK certificate is available.
func TestP5A_GetIAKInfo_WithCert(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.iakAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020001},
	}
	mock.iakAttrsErr = nil
	mock.iakCert = p5aGenerateTestCert(t)
	mock.iakCertErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.Equal(t, "0x81020001", info.Handle)
	assert.NotEmpty(t, info.Certificate)
}

// TestP5A_GetIDevIDInfo_WithCertAndTrustStore tests GetIDevIDInfo with a
// trust store configured for verification.
func TestP5A_GetIDevIDInfo_WithCertAndTrustStore(t *testing.T) {
	cert := p5aGenerateTestCert(t)
	mock := p5aDefaultMockTPM()
	mock.idevidAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &xkms.ECCAttributes{Curve: elliptic.P256()},
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020000},
	}
	mock.idevidAttrsErr = nil
	mock.idevidCert = cert
	mock.idevidCertErr = nil

	svc, _ := p5aNewTPMService(t, mock)
	ts := &p5aMockTrustStore{
		certs: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeIDevIDIssuer: {cert},
		},
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Certificate)
}

// TestP5A_GetSharedSRKInfo_WithSSRKConfig tests GetSharedSRKInfo when the
// SSRK config provides a handle.
func TestP5A_GetSharedSRKInfo_WithSSRKConfig(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.ssrkAttrs = &xkms.KeyAttributes{KeyAlgorithm: x509.RSA}
	mock.ssrkAttrsErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.Equal(t, "RSA-SSA", info.Algorithm)
	assert.Equal(t, "0x81000001", info.Handle)
}

// TestP5A_GetSharedSRKInfo_NoSSRK tests GetSharedSRKInfo when SSRKAttributes fails.
func TestP5A_GetSharedSRKInfo_NoSSRK(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.ssrkAttrs = nil
	mock.ssrkAttrsErr = errors.New("not found")
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
	assert.Equal(t, "unknown", info.Algorithm)
}

// TestP5A_GetPlatformSRKInfo_ConfigFallback tests GetPlatformSRKInfo when
// SRKAttributes returns nil but PlatformSRK config provides a handle.
func TestP5A_GetPlatformSRKInfo_ConfigFallback(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.config.PlatformSRK = &xkms.PlatformSRKConfig{
		SRKHandle: 0x81010003,
	}
	pks := &mockPlatformKeyStorer{
		srkAttrs:    nil,
		initialized: false,
	}
	mock.platformKeyStore = pks
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// SRK attrs nil -> Algorithm stays "N/A", handle from config fallback.
	assert.Equal(t, "0x81010003", info.Handle)
}

// TestP5A_GetPlatformSRKInfo_PolicyEnabled tests GetPlatformSRKInfo with
// platform policy enabled and key store initialized.
func TestP5A_GetPlatformSRKInfo_PolicyEnabled(t *testing.T) {
	mock := p5aDefaultMockTPM()
	pks := &mockPlatformKeyStorer{
		srkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
			TPMAttributes: &xkms.TPMAttributes{
				Handle: 0x81010003,
			},
		},
		initialized:   true,
		policyEnabled: true,
	}
	mock.platformKeyStore = pks
	mock.readHandleErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.True(t, info.Initialized)
	assert.True(t, info.PolicyEnabled)
	assert.Equal(t, "Platform Policy", info.PolicyName)
}

// TestP5A_VerifyCertAgainstTrustStore_NilTrustStore tests verifyCertAgainstTrustStore
// when no trust store is configured.
func TestP5A_VerifyCertAgainstTrustStore_NilTrustStore(t *testing.T) {
	svc := NewTPMService()
	cert := p5aGenerateTestCert(t)

	result := svc.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

// TestP5A_VerifyCertAgainstTrustStore_NilCert tests verifyCertAgainstTrustStore
// with a nil certificate.
func TestP5A_VerifyCertAgainstTrustStore_NilCert(t *testing.T) {
	svc := NewTPMService()
	svc.SetTrustStore(&p5aMockTrustStore{})

	result := svc.verifyCertAgainstTrustStore(nil, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

// TestP5A_VerifyCertAgainstTrustStore_EmptyCerts tests verifyCertAgainstTrustStore
// when the trust store has no certificates for the given purpose.
func TestP5A_VerifyCertAgainstTrustStore_EmptyCerts(t *testing.T) {
	svc := NewTPMService()
	svc.SetTrustStore(&p5aMockTrustStore{
		certs: map[truststore.CertPurpose][]*x509.Certificate{},
	})

	cert := p5aGenerateTestCert(t)
	result := svc.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

// TestP5A_LoadHandleDescriptions_InvalidJSON tests loadHandleDescriptions when
// the file contains invalid JSON.
func TestP5A_LoadHandleDescriptions_InvalidJSON(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	require.NoError(t, os.WriteFile(
		filepath.Join(dataDir, handleDescriptionsFile),
		[]byte("not valid json"),
		0600,
	))

	descriptions := svc.loadHandleDescriptions()
	assert.Empty(t, descriptions)
}

// TestP5A_GetStatus_NoTPM tests GetStatus when no TPM accessor is set.
// GetStatus returns Available=false when TPM initialization fails,
// regardless of whether the device node exists on the host.
func TestP5A_GetStatus_NoTPM(t *testing.T) {
	svc := NewTPMService()
	// No TPM accessor set.

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
	assert.False(t, status.Available)
}

// TestP5A_GetStatus_FullProvisioningLevels tests GetStatus through the full
// provisioning level chain: none -> manufacturer -> owner -> device_identity.
func TestP5A_GetStatus_FullProvisioningLevels(t *testing.T) {
	mock := p5aDefaultMockTPM()
	// EK present, SRK present, IDevID present with cert.
	mock.idevidAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020000},
	}
	mock.idevidAttrsErr = nil
	mock.idevidCert = p5aGenerateTestCert(t)
	mock.idevidCertErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.True(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelDeviceIdentity, status.StatusLevel)
}

// TestP5A_GetStatus_ManufacturerLevel tests GetStatus at manufacturer level
// (EK exists but no SRK).
func TestP5A_GetStatus_ManufacturerLevel(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.ssrkAttrs = nil
	mock.ssrkAttrsErr = errors.New("no SRK")
	svc, _ := p5aNewTPMService(t, mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelManufacturer, status.StatusLevel)
}

// TestP5A_GetStatus_OwnerLevel tests GetStatus at owner level (SRK exists but
// no IDevID).
func TestP5A_GetStatus_OwnerLevel(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.idevidAttrs = nil
	mock.idevidAttrsErr = errors.New("no IDevID")
	svc, _ := p5aNewTPMService(t, mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelOwner, status.StatusLevel)
}

// TestP5A_GetStatus_NoEK tests GetStatus when no EK exists.
func TestP5A_GetStatus_NoEK(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.ekAttrs = nil
	mock.ekAttrsErr = errors.New("no EK")
	svc, _ := p5aNewTPMService(t, mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

// TestP5A_GetStatus_FixedPropsError tests GetStatus when FixedProperties fails.
func TestP5A_GetStatus_FixedPropsError(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.fixedPropsErr = errors.New("props error")
	svc, _ := p5aNewTPMService(t, mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Available)
	// Returns early with no manufacturer info.
	assert.Equal(t, "", status.Manufacturer)
}

// TestP5A_ImportManufacturerCA_WithTrustStore tests ImportManufacturerCA when
// a trust store is configured, covering the persistence path.
func TestP5A_ImportManufacturerCA_WithTrustStore(t *testing.T) {
	svc := NewTPMService()
	ts := &p5aMockTrustStore{
		certs: make(map[truststore.CertPurpose][]*x509.Certificate),
	}
	svc.SetTrustStore(ts)

	certPEM := p5aTestCertPEM(t)
	err := svc.ImportManufacturerCA(certPEM)
	require.NoError(t, err)
	assert.Len(t, svc.mfgCACerts, 1)
}

// TestP5A_ImportManufacturerCA_InvalidPEM tests ImportManufacturerCA with
// invalid PEM data.
func TestP5A_ImportManufacturerCA_InvalidPEM(t *testing.T) {
	svc := NewTPMService()

	err := svc.ImportManufacturerCA("not a PEM block")
	assert.ErrorIs(t, err, ErrTPMInvalidCACert)
}

// TestP5A_ImportManufacturerCA_WrongPEMType tests ImportManufacturerCA with
// a PEM block that is not type CERTIFICATE.
func TestP5A_ImportManufacturerCA_WrongPEMType(t *testing.T) {
	svc := NewTPMService()

	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{0x01}}))
	err := svc.ImportManufacturerCA(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCACert)
}

// TestP5A_VerifyTPM_NoCertsLoaded tests VerifyTPM when no CA certificates
// are loaded, but the TPM and EK cert are available.
func TestP5A_VerifyTPM_NoCertsLoaded(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.ekCert = p5aGenerateTestCert(t)
	mock.ekCertErr = nil
	svc, _ := p5aNewTPMService(t, mock)

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Verified)
	assert.Equal(t, "no manufacturer CA certificates loaded", status.ErrorMessage)
}

// TestP5A_VerifyTPM_WithTrustStoreCerts tests VerifyTPM with CA certs from
// both the mfgCACerts slice and the trust store.
func TestP5A_VerifyTPM_WithTrustStoreCerts(t *testing.T) {
	cert := p5aGenerateTestCert(t)
	mock := p5aDefaultMockTPM()
	mock.ekCert = cert
	mock.ekCertErr = nil

	svc, _ := p5aNewTPMService(t, mock)
	// Add the self-signed cert as its own CA (will succeed verification).
	svc.SetTrustStore(&p5aMockTrustStore{
		certs: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {cert},
		},
	})

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Verified)
	assert.Equal(t, "p5a-test", status.Issuer)
}

// TestP5A_ImportEKCert_InvalidPEMType tests ImportEKCert with wrong PEM type.
func TestP5A_ImportEKCert_InvalidPEMType(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01}}))
	err := svc.ImportEKCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// TestP5A_ImportEKCert_MalformedDER tests ImportEKCert with valid PEM wrapping
// but malformed DER bytes.
func TestP5A_ImportEKCert_MalformedDER(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02, 0x03}}))
	err := svc.ImportEKCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// TestP5A_ImportEKECCCert_InvalidPEM tests ImportEKECCCert with non-PEM input.
func TestP5A_ImportEKECCCert_InvalidPEM(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	err := svc.ImportEKECCCert("not-pem-data")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// TestP5A_ImportEKECCCert_MalformedDER tests ImportEKECCCert with malformed
// certificate DER bytes.
func TestP5A_ImportEKECCCert_MalformedDER(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0xFF, 0xFE}}))
	err := svc.ImportEKECCCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// TestP5A_ImportIAKCert_MalformedDER tests ImportIAKCert with malformed DER.
func TestP5A_ImportIAKCert_MalformedDER(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x00}}))
	err := svc.ImportIAKCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// TestP5A_ImportIDevIDCert_MalformedDER tests ImportIDevIDCert with malformed DER.
func TestP5A_ImportIDevIDCert_MalformedDER(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x00}}))
	err := svc.ImportIDevIDCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// TestP5A_SetHandleDescription_NoDataDir tests SetHandleDescription when
// no data directory is configured.
func TestP5A_SetHandleDescription_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	// No dataDir set.

	err := svc.SetHandleDescription("0x81000001", "Test Key")
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// TestP5A_SetHandleDescription_RemoveEntry tests SetHandleDescription with
// an empty description to remove an entry.
func TestP5A_SetHandleDescription_RemoveEntry(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	// First add a description.
	require.NoError(t, svc.SetHandleDescription("0x81000001", "My Key"))

	// Then remove it.
	require.NoError(t, svc.SetHandleDescription("0x81000001", ""))

	descriptions := svc.loadHandleDescriptions()
	_, exists := descriptions["0x81000001"]
	assert.False(t, exists)
}

// TestP5A_SaveHandleDescriptions_NoDataDir tests saveHandleDescriptions when
// no data directory is configured.
func TestP5A_SaveHandleDescriptions_NoDataDir(t *testing.T) {
	svc := NewTPMService()

	err := svc.saveHandleDescriptions(map[string]string{"0x81": "test"})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// TestP5A_GetEKInfo_WithTrustStoreVerification tests GetEKInfo when the EK cert
// is verified against the trust store.
func TestP5A_GetEKInfo_WithTrustStoreVerification(t *testing.T) {
	cert := p5aGenerateTestCert(t)
	mock := p5aDefaultMockTPM()
	mock.ekCert = cert
	mock.ekCertErr = nil

	svc, _ := p5aNewTPMService(t, mock)
	svc.SetTrustStore(&p5aMockTrustStore{
		certs: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {cert},
		},
	})

	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Certificate)
	assert.True(t, info.Verified)
}

// TestP5A_GetEKECCInfo_WithTrustStoreVerification tests GetEKECCInfo with
// trust store verification.
func TestP5A_GetEKECCInfo_WithTrustStoreVerification(t *testing.T) {
	cert := p5aGenerateTestCert(t)
	mock := p5aDefaultMockTPM()
	mock.ekCertEC = cert
	mock.ekCertECErr = nil

	svc, _ := p5aNewTPMService(t, mock)
	svc.SetTrustStore(&p5aMockTrustStore{
		certs: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {cert},
		},
	})

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.True(t, info.Verified)
}

// TestP5A_DetectPCRBanks_SHA384Variant tests detectPCRBanks with the SHA386
// typo variant that some TPMs return.
func TestP5A_DetectPCRBanks_SHA384Variant(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.pcrBanks = []xkms.PCRBank{
		{Algorithm: "SHA1", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
		{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x02}}}},
		{Algorithm: "SHA386", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x03}}}},
		{Algorithm: "SHA512", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x04}}}},
	}

	banks := detectPCRBanks(mock)
	assert.Equal(t, []string{"sha1", "sha256", "sha384", "sha512"}, banks)
}

// TestP5A_DetectPCRBanks_Error tests detectPCRBanks when ReadPCRs returns
// an error.
func TestP5A_DetectPCRBanks_Error(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.pcrBanksErr = errors.New("read error")

	banks := detectPCRBanks(mock)
	assert.Nil(t, banks)
}

// TestP5A_BuildCapabilities_FIPS tests buildCapabilities with FIPS mode enabled.
func TestP5A_BuildCapabilities_FIPS(t *testing.T) {
	info := &TPMInfo{
		MaxRSAKeySize:     2048,
		MaxECCKeySize:     256,
		NVIndexesMax:      32,
		NVIndexesDefined:  4,
		PersistentLoaded:  5,
		PersistentAvail:   7,
		ActiveSessionsMax: 64,
		FIPSMode:          true,
	}
	caps := buildCapabilities(info)
	assert.Contains(t, caps, "FIPS 140-2")
}

// TestP5A_BuildCapabilities_NoOptionalFields tests buildCapabilities when
// optional fields are zero.
func TestP5A_BuildCapabilities_NoOptionalFields(t *testing.T) {
	info := &TPMInfo{
		MaxRSAKeySize: 0,
		MaxECCKeySize: 0,
	}
	caps := buildCapabilities(info)
	// Should still have the standard capabilities.
	assert.Contains(t, caps, "PCR Read/Extend")
	assert.Contains(t, caps, "Quoting")
}

// TestP5A_GetPCRs_SHA384Mismatch tests GetPCRs with the SHA384/SHA386
// mismatch handling.
func TestP5A_GetPCRs_SHA384Mismatch(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.pcrBanks = []xkms.PCRBank{
		{
			Algorithm: "SHA386",
			PCRs: []xkms.PCR{
				{ID: 0, Value: []byte{0x11, 0x22}},
			},
		},
	}
	svc, _ := p5aNewTPMService(t, mock)

	values, err := svc.GetPCRs("sha384")
	require.NoError(t, err)
	require.Len(t, values, 1)
	assert.Equal(t, "1122", values[0].Digest)
	assert.Equal(t, "sha384", values[0].Bank)
}

// TestP5A_GetPCRs_BankNotSupported tests GetPCRs when the requested bank
// is not present in the TPM response.
func TestP5A_GetPCRs_BankNotSupported(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.pcrBanks = []xkms.PCRBank{
		{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
	}
	svc, _ := p5aNewTPMService(t, mock)

	_, err := svc.GetPCRs("sha512")
	assert.ErrorIs(t, err, ErrTPMBankNotSupported)
}

// TestP5A_GenerateQuote_AutoNonce tests GenerateQuote with an empty nonce,
// triggering automatic nonce generation.
func TestP5A_GenerateQuote_AutoNonce(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.randomBytesVal = make([]byte, 32)
	mock.quoteResult = xkms.Quote{
		Quoted:    []byte{0x01},
		Signature: []byte{0x02},
		PCRs:      []byte{0x03},
		Nonce:     []byte{0x04},
	}
	svc, _ := p5aNewTPMService(t, mock)

	quote, err := svc.GenerateQuote("", []int{0}, "sha256")
	require.NoError(t, err)
	require.NotNil(t, quote)
}

// TestP5A_GenerateQuote_InvalidPCR tests GenerateQuote with an out-of-range PCR.
func TestP5A_GenerateQuote_InvalidPCR(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.randomBytesVal = make([]byte, 32)
	svc, _ := p5aNewTPMService(t, mock)

	_, err := svc.GenerateQuote("", []int{0, 24}, "sha256")
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

// TestP5A_GenerateQuote_NegativePCR tests GenerateQuote with a negative PCR index.
func TestP5A_GenerateQuote_NegativePCR(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.randomBytesVal = make([]byte, 32)
	svc, _ := p5aNewTPMService(t, mock)

	_, err := svc.GenerateQuote("", []int{-1}, "sha256")
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

// TestP5A_GetEventLog_EmptyDigests tests GetEventLog when events have no digests.
func TestP5A_GetEventLog_EmptyDigests(t *testing.T) {
	mock := p5aDefaultMockTPM()
	mock.parsedEvents = []xkms.TPMEvent{
		{
			PCRIndex:    0,
			EventType:   "EV_POST_CODE",
			EventString: "test",
			Digests:     nil, // No digests.
		},
	}
	svc, _ := p5aNewTPMService(t, mock)

	entries, err := svc.GetEventLog()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "", entries[0].DigestHex)
}

// TestP5A_WriteNVData_EmptyData tests WriteNVData with decoded empty data.
func TestP5A_WriteNVData_EmptyData(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	err := svc.WriteNVData(0x01800000, "", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

// TestP5A_ExtendNV_InvalidHex tests ExtendNV with invalid hex data.
func TestP5A_ExtendNV_InvalidHex(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	err := svc.ExtendNV(0x01800000, "zzzz", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

// TestP5A_ExtendNV_EmptyData tests ExtendNV with empty hex string that
// decodes to empty bytes.
func TestP5A_ExtendNV_EmptyData(t *testing.T) {
	mock := p5aDefaultMockTPM()
	svc, _ := p5aNewTPMService(t, mock)

	err := svc.ExtendNV(0x01800000, "", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

// p5aNewTPMService returns a TPMService over mock with a temporary data
// directory.
func p5aNewTPMService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return mock }))
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}
