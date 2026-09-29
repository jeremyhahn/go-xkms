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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// p6a test helpers
// ---------------------------------------------------------------------------

// p6aDefaultMock returns a minimal mock suitable for most phase 6 tests.
func p6aDefaultMock() *mockTPM {
	return &mockTPM{
		device: "/dev/tpmrm0",
		config: &xkms.TPMConfig{
			Hash: "SHA-256",
			SSRK: &xkms.SRKConfig{Handle: 0x81000001, KeyAlgorithm: "RSA"},
		},
		fixedProps: &xkms.PropertiesFixed{
			Manufacturer:  "P6TestMFG",
			FwMajor:       7,
			FwMinor:       85,
			MaxRSAKeyBits: 2048,
			MaxECCKeyBits: 384,
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
			{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0xAA, 0xBB}}}},
		},
		randomBytesVal: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		supportedAlgos: []string{"RSA", "SHA-256"},
	}
}

// p6aGenCert generates a self-signed test certificate.
func p6aGenCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "p6a-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// p6aCertPEM returns a PEM-encoded test certificate string.
func p6aCertPEM(t *testing.T) string {
	t.Helper()
	cert := p6aGenCert(t)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// p6aMockTrustStore implements truststore.TrustStore for testing.
type p6aMockTrustStore struct {
	certs      map[truststore.CertPurpose][]*x509.Certificate
	addErr     error
	addCallCnt int
}

func (m *p6aMockTrustStore) AddCertificate(_ *x509.Certificate) error { return nil }
func (m *p6aMockTrustStore) AddCertificateWithOptions(_ *x509.Certificate, _ *truststore.AddCertificateOptions) error {
	m.addCallCnt++
	return m.addErr
}
func (m *p6aMockTrustStore) RemoveCertificate(_ string) error { return nil }
func (m *p6aMockTrustStore) CertificatesByPurpose(purpose truststore.CertPurpose) ([]*x509.Certificate, error) {
	return m.certs[purpose], nil
}
func (m *p6aMockTrustStore) Certificates() ([]*x509.Certificate, error) { return nil, nil }
func (m *p6aMockTrustStore) AddPEM(_ []byte) (int, error)               { return 0, nil }
func (m *p6aMockTrustStore) ImportPEM(_ []byte, _ *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	return truststore.ImportResult{}, nil
}
func (m *p6aMockTrustStore) CertPool() (*x509.CertPool, error)                   { return x509.NewCertPool(), nil }
func (m *p6aMockTrustStore) Contains(_ string) (bool, error)                     { return false, nil }
func (m *p6aMockTrustStore) Count() (int, error)                                 { return 0, nil }
func (m *p6aMockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) { return nil, nil }
func (m *p6aMockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error { return nil }
func (m *p6aMockTrustStore) SetSource(_ string, _ string) error                  { return nil }
func (m *p6aMockTrustStore) SetSystemInstalled(_ string, _ bool) error           { return nil }
func (m *p6aMockTrustStore) SetTags(_ string, _ []string) error                  { return nil }
func (m *p6aMockTrustStore) Close() error                                        { return nil }
func (m *p6aMockTrustStore) Reload() error                                       { return nil }

// ---------------------------------------------------------------------------
// ViewKey tests -- covering uncovered error branches (lines 2161-2217)
// ---------------------------------------------------------------------------

func TestP6A_ViewKey_EKECC_Error(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCertECErr = errors.New("no ECC EK")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ViewKey("EK-ECC")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EK-ECC not available")
}

func TestP6A_ViewKey_EKECC_NilCert(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCertEC = nil
	mock.ekCertECErr = nil
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ViewKey("EK-ECC")
	assert.Error(t, err)
}

func TestP6A_ViewKey_EK_Error(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekAttrsErr = errors.New("no EK attrs")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ViewKey("EK")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EK not available")
}

func TestP6A_ViewKey_EK_WithPublicKeyBytes(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
		TPMAttributes: &xkms.TPMAttributes{
			Handle:         0x81010001,
			PublicKeyBytes: []byte{0x30, 0x82, 0x01, 0x22},
		},
	}
	cert := p6aGenCert(t)
	mock.ekCert = cert
	svc, _ := p6aNewTPMService(t, mock)

	data, err := svc.ViewKey("EK")
	require.NoError(t, err)
	assert.NotEmpty(t, data.PublicKeyPEM)
	assert.NotEmpty(t, data.Certificate)
	assert.Equal(t, "0x81010001", data.Handle)
}

func TestP6A_ViewKey_IAK_Error(t *testing.T) {
	mock := p6aDefaultMock()
	mock.iakAttrsErr = errors.New("no IAK")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ViewKey("IAK")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IAK not available")
}

func TestP6A_ViewKey_IAK_WithPublicKeyBytes(t *testing.T) {
	mock := p6aDefaultMock()
	mock.iakAttrs = &xkms.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
		TPMAttributes: &xkms.TPMAttributes{
			Handle:         0x81020001,
			PublicKeyBytes: []byte{0x04, 0xAA, 0xBB},
		},
	}
	cert := p6aGenCert(t)
	mock.iakCert = cert
	svc, _ := p6aNewTPMService(t, mock)

	data, err := svc.ViewKey("IAK")
	require.NoError(t, err)
	assert.NotEmpty(t, data.PublicKeyPEM)
	assert.NotEmpty(t, data.Certificate)
}

func TestP6A_ViewKey_IDevID_Error(t *testing.T) {
	mock := p6aDefaultMock()
	mock.idevidAttrsErr = errors.New("no IDevID")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ViewKey("IDevID")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IDevID not available")
}

func TestP6A_ViewKey_IDevID_WithPublicKeyBytes(t *testing.T) {
	mock := p6aDefaultMock()
	mock.idevidAttrs = &xkms.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
		TPMAttributes: &xkms.TPMAttributes{
			Handle:         0x81020000,
			PublicKeyBytes: []byte{0x04, 0xCC, 0xDD},
		},
	}
	cert := p6aGenCert(t)
	mock.idevidCert = cert
	svc, _ := p6aNewTPMService(t, mock)

	data, err := svc.ViewKey("IDevID")
	require.NoError(t, err)
	assert.NotEmpty(t, data.PublicKeyPEM)
	assert.NotEmpty(t, data.Certificate)
}

func TestP6A_ViewKey_SRK_Error(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ssrkAttrsErr = errors.New("no SRK")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ViewKey("SRK")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SRK not available")
}

func TestP6A_ViewKey_Unknown(t *testing.T) {
	mock := p6aDefaultMock()
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ViewKey("UNKNOWN-KEY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key name")
}

// ---------------------------------------------------------------------------
// GetStatus -- nil TPM accessor returns unavailable status (line 693)
// ---------------------------------------------------------------------------

func TestP6A_GetStatus_NilAccessor(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
	// When the accessor is nil, GetStatus returns Available=false
	// regardless of whether the device node exists on the host.
	assert.False(t, status.Available)
}

// ---------------------------------------------------------------------------
// GetPCRs -- read PCRs error (line 1242)
// ---------------------------------------------------------------------------

func TestP6A_GetPCRs_ReadError(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanksErr = errors.New("PCR read failed")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GetPCRs("sha256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read PCRs")
}

// ---------------------------------------------------------------------------
// GenerateQuote -- random nonce generation error (line 1548)
// ---------------------------------------------------------------------------

func TestP6A_GenerateQuote_NonceGenError(t *testing.T) {
	mock := p6aDefaultMock()
	mock.randomBytesErr = errors.New("RNG failure")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GenerateQuote("", []int{0, 7}, "sha256")
	assert.ErrorIs(t, err, ErrTPMNonceGenFailed)
}

// ---------------------------------------------------------------------------
// ReadNVData -- auto-size fallback with size not found (line 2506)
// ---------------------------------------------------------------------------

func TestP6A_ReadNVData_AutoSizeNotFound(t *testing.T) {
	mock := p6aDefaultMock()
	mock.nvIndexes = []xkms.NVIndexInfo{}
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ReadNVData(0x01800001, 0, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestP6A_GenerateIDevIDCSR_IAKFallback(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCert = p6aGenCert(t)
	mock.iakAttrsErr = errors.New("no IAK attrs")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{
		0x81020001: {KeyAlgorithm: x509.ECDSA, TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020001}},
	}
	mock.idevidAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020000},
	}
	mock.createTCGCSRErr = errors.New("CSR creation not supported in mock")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GenerateIDevIDCSR()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CSR generation failed")
}

func TestP6A_GenerateIDevIDCSR_IAKNotFound(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCert = p6aGenCert(t)
	mock.iakAttrsErr = errors.New("no IAK attrs")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GenerateIDevIDCSR()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IAK required for CSR")
}

func TestP6A_GenerateIDevIDCSR_IDevIDFallback(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCert = p6aGenCert(t)
	mock.iakAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020001},
	}
	mock.idevidAttrsErr = errors.New("no IDevID attrs")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{
		0x81020000: {KeyAlgorithm: x509.ECDSA, TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020000}},
	}
	mock.createTCGCSRErr = errors.New("CSR mock")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GenerateIDevIDCSR()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CSR generation failed")
}

func TestP6A_GenerateIDevIDCSR_IDevIDNotFound(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCert = p6aGenCert(t)
	mock.iakAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020001},
	}
	mock.idevidAttrsErr = errors.New("no IDevID")
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GenerateIDevIDCSR()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IDevID required for CSR")
}

// ---------------------------------------------------------------------------
// ImportManufacturerCA -- trust store error paths
// ---------------------------------------------------------------------------

func TestP6A_ImportManufacturerCA_TrustStoreError(t *testing.T) {
	svc := NewTPMService()
	ts := &p6aMockTrustStore{
		addErr: errors.New("trust store write failed"),
	}
	svc.SetTrustStore(ts)

	certPEM := p6aCertPEM(t)
	err := svc.ImportManufacturerCA(certPEM)
	require.NoError(t, err)
	assert.Equal(t, 1, ts.addCallCnt)
}

func TestP6A_ImportManufacturerCA_TrustStoreCertExists(t *testing.T) {
	svc := NewTPMService()
	ts := &p6aMockTrustStore{
		addErr: truststore.ErrCertificateExists,
	}
	svc.SetTrustStore(ts)

	certPEM := p6aCertPEM(t)
	err := svc.ImportManufacturerCA(certPEM)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// VerifyTPM -- trust store integration
// ---------------------------------------------------------------------------

func TestP6A_VerifyTPM_WithTrustStore(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCert = p6aGenCert(t)
	svc, _ := p6aNewTPMService(t, mock)

	caCert := p6aGenCert(t)
	ts := &p6aMockTrustStore{
		certs: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.NotEmpty(t, status.ErrorMessage)
}

func TestP6A_VerifyTPM_NoCACerts(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCert = p6aGenCert(t)
	svc, _ := p6aNewTPMService(t, mock)

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Contains(t, status.ErrorMessage, "no manufacturer CA")
}

// ---------------------------------------------------------------------------
// Misc helper coverage
// ---------------------------------------------------------------------------

func TestP6A_BuildSubjectAltNames(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames:       []string{"example.com"},
		EmailAddresses: []string{"test@example.com"},
	}
	sans := buildSubjectAltNames(cert)
	assert.Contains(t, sans, "DNS:example.com")
	assert.Contains(t, sans, "email:test@example.com")
}

func TestP6A_PublicKeyBitSize_Unknown(t *testing.T) {
	size := publicKeyBitSize("not a key")
	assert.Equal(t, 0, size)
}

func TestP6A_FormatFingerprint(t *testing.T) {
	hash := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	fp := formatFingerprint(hash)
	assert.Equal(t, "DE:AD:BE:EF", fp)
}

func TestP6A_SaveHandleDescriptions_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/directory")

	err := svc.saveHandleDescriptions(map[string]string{"0x1": "test"})
	assert.ErrorIs(t, err, ErrTPMHandleDescriptionFailed)
}

func TestP6A_SaveHandleDescriptions_EmptyDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveHandleDescriptions(map[string]string{"0x1": "test"})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// CreatePolicy -- with PCR selections that trigger TPM read
// ---------------------------------------------------------------------------

func TestP6A_GetPCRs_SHA384_SHA386Mismatch(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []xkms.PCRBank{
		{Algorithm: "SHA386", PCRs: []xkms.PCR{
			{ID: 0, Value: []byte{0x11}},
			{ID: 1, Value: []byte{0x22}},
		}},
	}
	svc, _ := p6aNewTPMService(t, mock)

	values, err := svc.GetPCRs("sha384")
	require.NoError(t, err)
	assert.Len(t, values, 2)
	assert.Equal(t, "sha384", values[0].Bank)
}

func TestP6A_SanityCheck(t *testing.T) {
	svc := NewTPMService()
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

// p6aSuppressUnused avoids "imported and not used" for fmt.
var _ = fmt.Sprintf

func TestP6A_ReadNVData_AutoSizeFromIndex(t *testing.T) {
	mock := p6aDefaultMock()
	mock.nvIndexes = []xkms.NVIndexInfo{
		{Handle: 0x01800001, Size: 32, Type: "ordinary"},
	}
	mock.nvReadResult = make([]byte, 32)
	svc, _ := p6aNewTPMService(t, mock)

	result, err := svc.ReadNVData(0x01800001, 0, "")
	require.NoError(t, err)
	assert.Len(t, result, 64)
}

func TestP6A_GetInfo_TCGCertOverrides(t *testing.T) {
	mock := p6aDefaultMock()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "P6A CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	_ = caCert

	sanExt, err := p4BuildSANExtension("id:49465800", "TestModel", "id:00070002")
	require.NoError(t, err)
	sdaExt, err := p4BuildSDAttrExtension("2.0", 3, 164)
	require.NoError(t, err)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "P6A EK"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{sanExt, sdaExt},
	}
	ekDER, err := x509.CreateCertificate(rand.Reader, ekTmpl, caCert, &ekKey.PublicKey, caKey)
	require.NoError(t, err)
	ekCert, err := x509.ParseCertificate(ekDER)
	require.NoError(t, err)

	mock.ekCert = ekCert
	mock.iakAttrs = &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	mock.idevidAttrs = &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	mock.idevidCert = p6aGenCert(t)

	svc, _ := p6aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.NotEmpty(t, info.Manufacturer)
}

func TestP6A_GetPCRs_BankNotSupported(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []xkms.PCRBank{
		{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0xAA}}}},
	}
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GetPCRs("sha512")
	assert.ErrorIs(t, err, ErrTPMBankNotSupported)
}

func TestP6A_LoadHandleDescriptions_CorruptJSON(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	err := os.WriteFile(filepath.Join(dataDir, handleDescriptionsFile), []byte("not json"), 0600)
	require.NoError(t, err)

	descriptions := svc.loadHandleDescriptions()
	assert.Empty(t, descriptions)
}

// p6aNewTPMService returns a TPMService over mock with a temporary data
// directory.
func p6aNewTPMService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return mock }))
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}
