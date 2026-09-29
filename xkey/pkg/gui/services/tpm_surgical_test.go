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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: create a TPMService with a temp dataDir and a mock TPM wired up.
// ---------------------------------------------------------------------------

func TestTS_GetStatus_NoAccessor(t *testing.T) {
	svc := NewTPMService()
	// tpmAccessor is nil -> getTPM returns error -> Available=false
	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Available)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

// ---------------------------------------------------------------------------
// L887, L890, L893: GetInfo - EK cert with TCG spec attributes
// Covers SpecFamily, SpecLevel, SpecRevision overrides from EK cert.
// ---------------------------------------------------------------------------

func tsBuildTCGSpecCert(t *testing.T) *x509.Certificate {
	t.Helper()

	// Build ASN.1 SubjectDirectoryAttributes extension with TPM specification.
	// OID: 2.23.133.2.16 (tcg-at-tpmSpecification)
	oidTPMSpec := asn1.ObjectIdentifier{2, 23, 133, 2, 16}

	specValue, err := asn1.Marshal(struct {
		Family   string
		Level    int
		Revision int
	}{
		Family:   "2.0",
		Level:    2,
		Revision: 138,
	})
	require.NoError(t, err)

	attr := struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}{
		Type:   oidTPMSpec,
		Values: asn1.RawValue{Tag: 17, Class: asn1.ClassUniversal, IsCompound: true, Bytes: specValue},
	}

	attrs, err := asn1.Marshal([]interface{}{attr})
	require.NoError(t, err)

	// Build SAN with manufacturer/model/version via directoryName entries.
	oidManufacturer := asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidModel := asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidVersion := asn1.ObjectIdentifier{2, 23, 133, 2, 3}

	dirName := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			{Type: oidManufacturer, Value: "id:49465800"},
		},
		pkix.RelativeDistinguishedNameSET{
			{Type: oidModel, Value: "SLB 9670"},
		},
		pkix.RelativeDistinguishedNameSET{
			{Type: oidVersion, Value: "id:00070055"},
		},
	}

	dirNameBytes, err := asn1.Marshal(dirName)
	require.NoError(t, err)

	generalName := asn1.RawValue{
		Tag:        4, // directoryName
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      dirNameBytes,
	}

	sanValue, err := asn1.Marshal([]asn1.RawValue{generalName})
	require.NoError(t, err)

	cert := &x509.Certificate{
		Raw:          []byte{0x30, 0x82, 0x01, 0x22},
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "TCG-EK-Test"},
		Extensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 9}, // subjectDirectoryAttributes
				Value: attrs,
			},
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // subjectAltName
				Value: sanValue,
			},
		},
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1), //nolint:staticcheck // synthetic test fixture; a fixed non-curve point is the input under test and a validating constructor would refuse to build it.
			Y:     big.NewInt(2), //nolint:staticcheck // synthetic test fixture; a fixed non-curve point is the input under test and a validating constructor would refuse to build it.
		},
	}

	return cert
}

func TestTS_GetInfo_TCGSpecAttributes(t *testing.T) {
	tcgCert := tsBuildTCGSpecCert(t)

	mock := defaultMockTPM()
	mock.ekCert = tcgCert
	mock.ekCertErr = nil

	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	// L887: SpecFamily override
	assert.Equal(t, "2.0", info.Family)

	// L890: SpecLevel override
	assert.Equal(t, 2, info.Level)

	// L893: SpecRevision override
	assert.Equal(t, "138", info.Revision)

	// Manufacturer/Model/Version from SAN directoryName
	assert.Contains(t, info.VendorID, "id:49465800")
	assert.Equal(t, "SLB 9670", info.Model)
}

func TestTS_GetInfo_TCGSpecAttributes_NoEKCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertErr = errors.New("not available")

	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	// Without EK cert, the TCG overrides (L887-L893) are not reached.
	// Family comes from fixed props.
	assert.Equal(t, "2.0\x00", info.Family)
}

// ---------------------------------------------------------------------------
// L1548: GenerateQuote - TPM Quote returns error
// ---------------------------------------------------------------------------

func TestTS_GenerateQuote_QuoteError(t *testing.T) {
	mock := defaultMockTPM()
	mock.quoteErr = errors.New("tpm2: quote failed")

	svc := newServiceWithMock(mock)

	result, err := svc.GenerateQuote("deadbeef", []int{0, 7}, "sha256")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quote")
}

func TestTS_GenerateQuote_QuoteSuccess(t *testing.T) {
	mock := defaultMockTPM()
	mock.quoteResult = xkms.Quote{
		Quoted:    []byte{0x01},
		Signature: []byte{0x02},
		PCRs:      []byte{0x03},
		Nonce:     []byte{0x04},
	}
	mock.quoteErr = nil

	svc := newServiceWithMock(mock)

	result, err := svc.GenerateQuote("aabb", []int{0}, "sha256")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "01", result.QuoteData)
	assert.Equal(t, "02", result.Signature)
}

// ---------------------------------------------------------------------------
// L1987: saveHandleDescriptions - exercise the JSON marshal and write paths
// ---------------------------------------------------------------------------

func TestTS_SaveHandleDescriptions_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	descriptions := map[string]string{
		"0x81000001": "SRK",
		"0x81010001": "EK",
	}

	err := svc.saveHandleDescriptions(descriptions)
	require.NoError(t, err)

	// Verify file was written.
	data, readErr := os.ReadFile(filepath.Join(dataDir, handleDescriptionsFile))
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "SRK")
}

func TestTS_SaveHandleDescriptions_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	// dataDir is empty.
	err := svc.saveHandleDescriptions(map[string]string{"k": "v"})
	require.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// L2291: GenerateIDevIDCSR - CSR generation and marshaling paths
// ---------------------------------------------------------------------------

func TestTS_GenerateIDevIDCSR_CSRError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = nil
	mock.idevidAttrsErr = nil
	mock.createTCGCSRErr = errors.New("csr generation failed")

	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	assert.Empty(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CSR generation failed")
}

func TestTS_GenerateIDevIDCSR_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = nil
	mock.idevidAttrsErr = nil
	mock.createTCGCSRErr = nil
	// Zero CSR will marshal to a binary; we just verify no error.
	mock.createTCGCSRResult = xkms.TCG_CSR_IDEVID{}

	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	require.NoError(t, err)
	// Result should be a hex-encoded binary string.
	assert.NotEmpty(t, result)
}

// ---------------------------------------------------------------------------
// L2506: ReadNVData - NVRead returns error
// ---------------------------------------------------------------------------

func TestTS_ReadNVData_NVReadError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadErr = errors.New("nv read failed")

	svc := newServiceWithMock(mock)

	result, err := svc.ReadNVData(0x01500001, 64, "")
	assert.Empty(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read NV data")
}

func TestTS_ReadNVData_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadResult = []byte{0xAA, 0xBB, 0xCC}
	mock.nvReadErr = nil

	svc := newServiceWithMock(mock)

	result, err := svc.ReadNVData(0x01500001, 3, "")
	require.NoError(t, err)
	assert.Equal(t, "aabbcc", result)
}

// ---------------------------------------------------------------------------
// L3026: CreatePolicy - nil policy
// ---------------------------------------------------------------------------

func TestTS_ReadNVData_AutoDetectSize(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []xkms.NVIndexInfo{
		{Handle: tpm2.TPMHandle(0x01500001), Size: 32},
	}
	mock.nvReadResult = make([]byte, 32)
	mock.nvReadErr = nil

	svc := newServiceWithMock(mock)

	result, err := svc.ReadNVData(0x01500001, 0, "") // size=0 -> auto-detect
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(make([]byte, 32)), result)
}

func TestTS_ReadNVData_AutoDetectNotFound(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []xkms.NVIndexInfo{} // No indexes

	svc := newServiceWithMock(mock)

	result, err := svc.ReadNVData(0x01500001, 0, "")
	assert.Empty(t, result)
	require.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestTS_GenerateIDevIDCSR_IAKFallback(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	// IAKAttributes fails -> fallback to KeyAttributes.
	mock.iakAttrsErr = errors.New("iak not available")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{} // empty -> fallback fails too
	mock.idevidAttrsErr = nil

	svc := newServiceWithMock(mock)

	// Should fail because IAK fallback handles also fail.
	result, err := svc.GenerateIDevIDCSR()
	assert.Empty(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IAK required")
}

func TestTS_GenerateIDevIDCSR_IDevIDFallback(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = nil
	mock.iakAttrs = &xkms.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020001},
	}
	// IDevIDAttributes fails -> fallback to KeyAttributes.
	mock.idevidAttrsErr = errors.New("idevid not available")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{} // empty -> fallback fails too

	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	assert.Empty(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IDevID required")
}

func TestTS_GenerateIDevIDCSR_IAKFallbackSuccess(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = errors.New("iak not available")
	// Provide fallback handle attributes.
	iakFallbackAttrs := &xkms.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
		TPMAttributes: &xkms.TPMAttributes{Handle: 0x81020001},
	}
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{
		0x81020001: iakFallbackAttrs,
	}
	mock.idevidAttrsErr = nil
	mock.createTCGCSRErr = nil
	mock.createTCGCSRResult = xkms.TCG_CSR_IDEVID{}

	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestTS_ReadNVData_AutoDetectWithMatchingHandle(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []xkms.NVIndexInfo{
		{Handle: tpm2.TPMHandle(0x01400001), Size: 16},
		{Handle: tpm2.TPMHandle(0x01500002), Size: 64},
	}
	mock.nvReadResult = make([]byte, 64)
	mock.nvReadErr = nil

	svc := newServiceWithMock(mock)

	// Auto-detect size for second handle.
	result, err := svc.ReadNVData(0x01500002, 0, "")
	require.NoError(t, err)
	assert.Len(t, result, 128) // 64 bytes -> 128 hex chars
}

// tsCreateService returns a TPMService over mock with a temporary data
// directory.
func tsCreateService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}
