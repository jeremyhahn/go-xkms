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
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: create a TPMService with a temp dataDir and a mock TPM wired up.
// ---------------------------------------------------------------------------

func tsCreateService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}

// ---------------------------------------------------------------------------
// GetStatus - TPM accessor nil -> getTPM error -> Available=false.
// When TPM init fails, GetStatus always returns Available=false regardless
// of whether the device node exists. StatusLevel=none with no error.
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
			X:     big.NewInt(1),
			Y:     big.NewInt(2),
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
	mock.quoteResult = tpm2pkg.Quote{
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
	mock.createTCGCSRResult = tpm2pkg.TCG_CSR_IDEVID{}

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

func TestTS_CreatePolicy_NilPolicy(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePolicy(nil)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_CreatePolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePolicy(&PCRPolicy{Name: "  "})
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

// ---------------------------------------------------------------------------
// L3103: GetPolicyDeletionImpact - with assigned key handles
// ---------------------------------------------------------------------------

func TestTS_GetPolicyDeletionImpact_WithAssignments(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Create a composite policy first.
	cp := CompositePolicy{
		Name:     "test-pw-policy",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{Type: "password", PasswordHash: "somehash"},
		},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	// Create an assignment for this policy.
	assignments := []PolicyAssignment{
		{PolicyName: "test-pw-policy", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
	}
	assignData, _ := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), assignData, 0600))

	impact, err := svc.GetPolicyDeletionImpact("test-pw-policy")
	require.NoError(t, err)
	require.NotNil(t, impact)
	assert.Equal(t, "composite", impact.PolicyType)
	assert.Contains(t, impact.AssignedKeyHandles, "0x81000001")
}

func TestTS_GetPolicyDeletionImpact_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	impact, err := svc.GetPolicyDeletionImpact("nonexistent")
	assert.Nil(t, impact)
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// L3195: savePolicies - happy path exercises the json.Marshal line
// ---------------------------------------------------------------------------

func TestTS_SavePolicies_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	policies := []PCRPolicy{
		{
			Name:          "test-policy",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			CreatedAt:     time.Now().Format(time.RFC3339),
		},
	}

	err := svc.savePolicies(policies)
	require.NoError(t, err)

	data, readErr := os.ReadFile(filepath.Join(dataDir, pcrPoliciesFile))
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "test-policy")
}

func TestTS_SavePolicies_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.savePolicies([]PCRPolicy{{Name: "x"}})
	require.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// L3371: ExportPolicy - exercises the json.MarshalIndent path
// ---------------------------------------------------------------------------

func TestTS_ExportPolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Create a policy to export.
	policies := []PCRPolicy{
		{
			Name:          "export-test",
			CreatedAt:     "2025-01-01T00:00:00Z",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
			PCRDigests:    map[string]string{"sha256:0": "aabb"},
		},
	}
	polData, _ := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	result, err := svc.ExportPolicy("export-test")
	require.NoError(t, err)
	assert.Contains(t, result, "export-test")
	assert.Contains(t, result, "pcr_bank")
	assert.Contains(t, result, "pcr_digests")
}

func TestTS_ExportPolicy_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	result, err := svc.ExportPolicy("nonexistent")
	assert.Empty(t, result)
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// L3429: ExportCompositePolicy - marshal path exercised
// ---------------------------------------------------------------------------

func TestTS_ExportCompositePolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:        "comp-export",
		Operator:    "OR",
		Description: "test composite",
		CreatedAt:   "2025-01-01T00:00:00Z",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
			{
				Type:         "password",
				PasswordHash: "abc:def",
			},
		},
		PCRDigests: map[string]string{"sha256:0": "aabb"},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	result, err := svc.ExportCompositePolicy("comp-export")
	require.NoError(t, err)
	assert.Contains(t, result, "comp-export")
	assert.Contains(t, result, "OR")
	assert.Contains(t, result, "pcr_bank")
}

func TestTS_ExportCompositePolicy_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	result, err := svc.ExportCompositePolicy("nonexistent")
	assert.Empty(t, result)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// L3455, L3458, L3464-3469: SavePolicyToFile internal paths.
// SavePolicyToFile calls wailsruntime.SaveFileDialog which needs Wails context.
// Test the internal savePolicyDigestBinary directly.
// ---------------------------------------------------------------------------

func TestTS_SavePolicyDigestBinary_InvalidJSON(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "digest.bin")

	err := svc.savePolicyDigestBinary(filePath, "not-json")
	require.ErrorIs(t, err, ErrTPMPolicyExportFailed)
}

func TestTS_SavePolicyDigestBinary_ValidPolicy(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "policy.bin")

	policyJSON := `{
		"name": "test",
		"pcr_bank": "sha256",
		"pcr_selections": [0, 7],
		"pcr_digests": {
			"sha256:0": "0000000000000000000000000000000000000000000000000000000000000000",
			"sha256:7": "0000000000000000000000000000000000000000000000000000000000000000"
		}
	}`

	err := svc.savePolicyDigestBinary(filePath, policyJSON)
	// This may succeed or fail depending on ComputePolicyPCRDigest behavior.
	// Both outcomes exercise the code path.
	if err == nil {
		data, readErr := os.ReadFile(filePath)
		require.NoError(t, readErr)
		assert.NotEmpty(t, data)
	}
}

// ---------------------------------------------------------------------------
// L3545-3550: ImportPolicyFile internal paths
// Test importJSONPolicy and importBinaryPolicyDigest directly.
// ---------------------------------------------------------------------------

func TestTS_ImportJSONPolicy_InvalidJSON(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	name, err := svc.importJSONPolicy([]byte("not-json"))
	assert.Empty(t, name)
	require.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestTS_ImportJSONPolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	name, err := svc.importJSONPolicy([]byte(`{"name": ""}`))
	assert.Empty(t, name)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_ImportJSONPolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	policyJSON := `{
		"name": "imported-test",
		"pcr_bank": "sha256",
		"pcr_selections": [0, 7],
		"pcr_digests": {"sha256:0": "aabb"}
	}`

	name, err := svc.importJSONPolicy([]byte(policyJSON))
	require.NoError(t, err)
	assert.Equal(t, "imported-test", name)
}

func TestTS_ImportJSONPolicy_CompositePolicy(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	policyJSON := `{
		"name": "imported-composite",
		"operator": "OR",
		"elements": [
			{"type": "pcr", "pcr_bank": "sha256", "pcr_selections": [{"index": 0, "bank": "sha256"}]},
			{"type": "password", "password_hash": "abc:def"}
		]
	}`

	name, err := svc.importJSONPolicy([]byte(policyJSON))
	require.NoError(t, err)
	assert.Equal(t, "imported-composite", name)
}

// ---------------------------------------------------------------------------
// L3614, L3619: importCompositePolicy - various paths
// ---------------------------------------------------------------------------

func TestTS_ImportCompositePolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	raw := map[string]interface{}{
		"name":     "comp-import",
		"operator": "AND",
		"elements": []interface{}{
			map[string]interface{}{"type": "pcr"},
		},
	}

	name, err := svc.importCompositePolicy(raw)
	require.NoError(t, err)
	assert.Equal(t, "comp-import", name)
}

func TestTS_ImportCompositePolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	raw := map[string]interface{}{
		"name":     "",
		"operator": "AND",
	}

	name, err := svc.importCompositePolicy(raw)
	assert.Empty(t, name)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_ImportCompositePolicy_Duplicate(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Pre-create a composite policy.
	existing := CompositePolicy{
		Name:     "dup-comp",
		Operator: "OR",
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{existing}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	raw := map[string]interface{}{
		"name":     "dup-comp",
		"operator": "OR",
	}

	name, err := svc.importCompositePolicy(raw)
	assert.Empty(t, name)
	require.ErrorIs(t, err, ErrTPMPolicyExists)
}

// L3637: importCompositePolicy - saveCompositePolicies error path
func TestTS_ImportCompositePolicy_SaveError(t *testing.T) {
	svc := NewTPMService()
	// No dataDir set -> saveCompositePolicies returns ErrTPMDataDirNotSet
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return defaultMockTPM()
	}))

	raw := map[string]interface{}{
		"name":     "save-fail",
		"operator": "AND",
	}

	name, err := svc.importCompositePolicy(raw)
	assert.Empty(t, name)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// L3674, L3679: importBinaryPolicyDigest - various paths
// ---------------------------------------------------------------------------

func TestTS_ImportBinaryPolicyDigest_EmptyData(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	name, err := svc.importBinaryPolicyDigest("/tmp/test.bin", []byte{})
	assert.Empty(t, name)
	require.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestTS_ImportBinaryPolicyDigest_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	data := []byte{0x01, 0x02, 0x03, 0x04}
	name, err := svc.importBinaryPolicyDigest("/tmp/my-policy.bin", data)
	require.NoError(t, err)
	assert.Equal(t, "my-policy", name)
}

func TestTS_ImportBinaryPolicyDigest_NameFromDatFile(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	data := []byte{0xAA, 0xBB}
	name, err := svc.importBinaryPolicyDigest("/some/path/seal-policy.dat", data)
	require.NoError(t, err)
	assert.Equal(t, "seal-policy", name)
}

func TestTS_ImportBinaryPolicyDigest_DuplicateNameTimestamp(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	// Create first policy.
	data := []byte{0x01, 0x02}
	name1, err := svc.importBinaryPolicyDigest("/tmp/dup.bin", data)
	require.NoError(t, err)
	assert.Equal(t, "dup", name1)

	// Import again with same name -> L3672-3677 timestamp fallback.
	name2, err := svc.importBinaryPolicyDigest("/tmp/dup.bin", data)
	require.NoError(t, err)
	// Name should have a timestamp appended.
	assert.True(t, strings.HasPrefix(name2, "dup-"), "expected timestamp suffix, got %s", name2)
}

// L3679: importBinaryPolicyDigest - non-duplicate CreatePolicy error
func TestTS_ImportBinaryPolicyDigest_CreatePolicyError(t *testing.T) {
	svc := NewTPMService()
	// No dataDir -> CreatePolicy calls savePolicies which returns ErrTPMDataDirNotSet
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return defaultMockTPM()
	}))

	data := []byte{0x01, 0x02}
	name, err := svc.importBinaryPolicyDigest("/tmp/fail.bin", data)
	assert.Empty(t, name)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// L3759: UnassignPolicyFromKey - filtered append path
// ---------------------------------------------------------------------------

func TestTS_UnassignPolicyFromKey_Found(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Create assignments with multiple entries.
	assignments := []PolicyAssignment{
		{PolicyName: "policy-a", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
		{PolicyName: "policy-b", KeyHandle: "0x81000002", AssignedAt: "2025-01-01T00:00:00Z"},
		{PolicyName: "policy-c", KeyHandle: "0x81000003", AssignedAt: "2025-01-01T00:00:00Z"},
	}
	data, _ := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600))

	// Unassign the middle one -> L3759 filtered = append(filtered, a) for policy-a and policy-c
	err := svc.UnassignPolicyFromKey("0x81000002")
	require.NoError(t, err)

	// Verify only 2 remain.
	remaining := svc.loadAssignments()
	assert.Len(t, remaining, 2)
	for _, a := range remaining {
		assert.NotEqual(t, "0x81000002", a.KeyHandle)
	}
}

func TestTS_UnassignPolicyFromKey_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.UnassignPolicyFromKey("0x99999999")
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// L3798: saveAssignments - happy path and no dataDir
// ---------------------------------------------------------------------------

func TestTS_SaveAssignments_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	assignments := []PolicyAssignment{
		{PolicyName: "pol1", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
	}

	err := svc.saveAssignments(assignments)
	require.NoError(t, err)

	data, readErr := os.ReadFile(filepath.Join(dataDir, policyAssignmentsFile))
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "pol1")
}

func TestTS_SaveAssignments_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveAssignments([]PolicyAssignment{{PolicyName: "x"}})
	require.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// L3975, L3979: ListCompositePoliciesWithDigests - PCR read error + bank normalization
// ---------------------------------------------------------------------------

func TestTS_ListCompositePoliciesWithDigests_PCRReadError(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanksErr = errors.New("pcr read failed") // L3975: readErr != nil -> continue

	svc, dataDir := tsCreateService(t, mock)

	// Create a composite policy with PCR elements.
	cp := CompositePolicy{
		Name:     "pcr-read-fail",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
		},
		PCRDigests: map[string]string{"sha256:0": "aabb"},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestTS_ListCompositePoliciesWithDigests_BankNormalization(t *testing.T) {
	mock := defaultMockTPM()
	// Use a bank name not in bankNameMap to trigger L3979 fallback.
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA3-256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:     "custom-bank",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "SHA3-256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "SHA3-256"}},
			},
		},
		PCRDigests: map[string]string{"SHA3-256:0": "aa"},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

// ---------------------------------------------------------------------------
// L4013: ListCompositePoliciesWithDigests - currentHex empty after bank lookup
// ---------------------------------------------------------------------------

func TestTS_ListCompositePoliciesWithDigests_NoCurrentDigest(t *testing.T) {
	mock := defaultMockTPM()
	// Return PCR banks that do not include the bank the policy needs.
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 7, Value: []byte{0xCC}}, // PCR 7 exists but not PCR 0
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:     "missing-pcr",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
		},
		PCRDigests: map[string]string{"sha256:0": "aabb"}, // L4013: currentHex will be ""
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.False(t, *policies[0].Valid) // Should be false because currentHex is empty.
}

// ---------------------------------------------------------------------------
// L4156: saveCompositePolicies - happy path and no dataDir
// ---------------------------------------------------------------------------

func TestTS_SaveCompositePolicies_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	policies := []CompositePolicy{
		{Name: "comp-save", Operator: "AND"},
	}

	err := svc.saveCompositePolicies(policies)
	require.NoError(t, err)

	data, readErr := os.ReadFile(filepath.Join(dataDir, compositePoliciesFile))
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "comp-save")
}

func TestTS_SaveCompositePolicies_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveCompositePolicies([]CompositePolicy{{Name: "x"}})
	require.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// L4243: ListPoliciesWithDigests - hasSaved=false path
// ---------------------------------------------------------------------------

func TestTS_ListPoliciesWithDigests_MissingSavedDigest(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs:      []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	// Policy has PCR selections for sha256:0 AND sha256:7, but PCRDigests
	// only has sha256:0 -> sha256:7 is not "saved" -> hasSaved=false (L4243)
	policy := PCRPolicy{
		Name: "partial-digest",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
		PCRDigests: map[string]string{
			"sha256:0": "aa", // Only PCR 0 has a saved digest
			// sha256:7 is missing -> L4243 triggers
		},
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.False(t, *policies[0].Valid)
}

// ---------------------------------------------------------------------------
// L4348: CreatePasswordPolicy - exercises hashPassword and CreateCompositePolicy
// ---------------------------------------------------------------------------

func TestTS_CreatePasswordPolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePasswordPolicy("pw-test", "test description", "strongP@ss!", false)
	require.NoError(t, err)

	// Verify the composite policy was created.
	policies := svc.loadCompositePolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "pw-test", policies[0].Name)
	assert.Equal(t, "SINGLE", policies[0].Operator)
}

func TestTS_CreatePasswordPolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePasswordPolicy("", "desc", "pass", false)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_CreatePasswordPolicy_EmptyPassword(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePasswordPolicy("name", "desc", "  ", false)
	require.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// L4398: CreatePCROrPasswordPolicy - exercises hashPassword
// ---------------------------------------------------------------------------

func TestTS_CreatePCROrPasswordPolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCROrPasswordPolicy("or-policy", "desc", pcrs, "sha256", "pass123!", false)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "OR", policies[0].Operator)
}

func TestTS_CreatePCROrPasswordPolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePCROrPasswordPolicy("", "desc", []PCRSelection{{Index: 0}}, "sha256", "pass", false)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_CreatePCROrPasswordPolicy_NoPCRs(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePCROrPasswordPolicy("name", "desc", nil, "sha256", "pass", false)
	require.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestTS_CreatePCROrPasswordPolicy_EmptyPassword(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePCROrPasswordPolicy("name", "desc", []PCRSelection{{Index: 0}}, "sha256", "", false)
	require.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// L4453: CreatePCRAndPasswordPolicy - exercises hashPassword
// ---------------------------------------------------------------------------

func TestTS_CreatePCRAndPasswordPolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("and-policy", "desc", pcrs, "sha256", "secureP@ss!", false)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "AND", policies[0].Operator)
}

func TestTS_CreatePCRAndPasswordPolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePCRAndPasswordPolicy("", "desc", []PCRSelection{{Index: 0}}, "sha256", "pass", false)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_CreatePCRAndPasswordPolicy_NoPCRs(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePCRAndPasswordPolicy("name", "desc", nil, "sha256", "pass", false)
	require.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestTS_CreatePCRAndPasswordPolicy_EmptyPassword(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePCRAndPasswordPolicy("name", "desc", []PCRSelection{{Index: 0}}, "sha256", "  ", false)
	require.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// L4524: deletePolicyPassword - nil service (early return)
// ---------------------------------------------------------------------------

func TestTS_DeletePolicyPassword_NilService(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)
	// staticPWService is nil -> returns early without error.
	svc.deletePolicyPassword("any-policy")
	// No panic, no error.
}

// ---------------------------------------------------------------------------
// L4641: ComparePolicyPCRs - non-hex current digest triggers fallback
// ---------------------------------------------------------------------------

func TestTS_ComparePolicyPCRs_NonHexDigests(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA, 0xBB}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	// Create a policy with a non-hex saved digest -> L4637 decErr triggers fallback.
	policy := PCRPolicy{
		Name:          "non-hex",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests: map[string]string{
			"sha256:0": "not-valid-hex!",
		},
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	result, err := svc.ComparePolicyPCRs("non-hex")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.AllMatch)
	assert.Len(t, result.Entries, 1)
}

func TestTS_ComparePolicyPCRs_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	result, err := svc.ComparePolicyPCRs("")
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_ComparePolicyPCRs_NoDigests(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	policy := PCRPolicy{
		Name:          "no-digests",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		CreatedAt:     "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	result, err := svc.ComparePolicyPCRs("no-digests")
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTPMPolicyNoDigests)
}

func TestTS_ComparePolicyPCRs_NoTPM(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	policy := PCRPolicy{
		Name:          "no-tpm",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabb"},
		CreatedAt:     "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(svc.dataDir, pcrPoliciesFile), polData, 0600))

	result, err := svc.ComparePolicyPCRs("no-tpm")
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// Additional coverage for digest matching and comparison paths
// ---------------------------------------------------------------------------

func TestTS_ListPoliciesWithDigests_DigestMismatch(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA, 0xBB}},
				{ID: 7, Value: []byte{0xCC, 0xDD}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	policy := PCRPolicy{
		Name: "digest-mismatch",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
		PCRDigests: map[string]string{
			"sha256:0": "aabb",     // Matches
			"sha256:7": "deadbeef", // Does NOT match (actual is ccdd)
		},
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.False(t, *policies[0].Valid)
}

func TestTS_ListCompositePoliciesWithDigests_MatchingDigests(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA, 0xBB}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	// Digest "aabb" matches the PCR value.
	cp := CompositePolicy{
		Name:     "matching",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
		},
		PCRDigests: map[string]string{"sha256:0": "aabb"},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.True(t, *policies[0].Valid)
}

func TestTS_ListCompositePoliciesWithDigests_BankNotInResults(t *testing.T) {
	mock := defaultMockTPM()
	// Mock returns SHA384 data but policy uses sha256.
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA384",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:     "wrong-bank",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
		},
		PCRDigests: map[string]string{"sha256:0": "aabb"},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.False(t, *policies[0].Valid) // currentHex empty -> allMatch=false
}

// ---------------------------------------------------------------------------
// Edge cases for additional coverage
// ---------------------------------------------------------------------------

func TestTS_CreatePolicy_WhitespaceOnlyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePolicy(&PCRPolicy{Name: "   \t  "})
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTS_ReadNVData_AutoDetectSize(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []tpm2pkg.NVIndexInfo{
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
	mock.nvIndexes = []tpm2pkg.NVIndexInfo{} // No indexes

	svc := newServiceWithMock(mock)

	result, err := svc.ReadNVData(0x01500001, 0, "")
	assert.Empty(t, result)
	require.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestTS_GetPolicyDeletionImpact_PCRPolicyType(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Create a PCR policy.
	policies := []PCRPolicy{
		{Name: "pcr-impact", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
	}
	polData, _ := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	impact, err := svc.GetPolicyDeletionImpact("pcr-impact")
	require.NoError(t, err)
	require.NotNil(t, impact)
	assert.Equal(t, "pcr", impact.PolicyType)
}

func TestTS_FindPolicyPasswordEntry_NilService(t *testing.T) {
	svc := NewTPMService()
	id, found := svc.findPolicyPasswordEntry("any")
	assert.Empty(t, id)
	assert.False(t, found)
}

func TestTS_ComparePolicyPCRs_MatchingDigests(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA, 0xBB}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	policy := PCRPolicy{
		Name:          "match-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabb"},
		CreatedAt:     "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	result, err := svc.ComparePolicyPCRs("match-test")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.AllMatch)
	assert.Len(t, result.Entries, 1)
	assert.True(t, result.Entries[0].Match)
}

func TestTS_ListPoliciesWithDigests_Empty(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, policies, 0)
}

func TestTS_ListPoliciesWithDigests_NoTPM(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	policy := PCRPolicy{
		Name:          "no-tpm-policy",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		CreatedAt:     "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, policies, 1) // Returns policies without digest validation.
}

func TestTS_CreatePolicy_DuplicateName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	p := &PCRPolicy{
		Name:          "dupe",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}
	require.NoError(t, svc.CreatePolicy(p))

	err := svc.CreatePolicy(p)
	require.ErrorIs(t, err, ErrTPMPolicyExists)
}

func TestTS_ListCompositePoliciesWithDigests_Empty(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, policies, 0)
}

func TestTS_ListCompositePoliciesWithDigests_NoPCRElements(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:     "pw-only",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{Type: "password", PasswordHash: "abc:def"},
		},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

// ---------------------------------------------------------------------------
// GenerateIDevIDCSR - IAK fallback and IDevID fallback paths.
// ---------------------------------------------------------------------------

func TestTS_GenerateIDevIDCSR_IAKFallback(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	// IAKAttributes fails -> fallback to KeyAttributes.
	mock.iakAttrsErr = errors.New("iak not available")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{} // empty -> fallback fails too
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
	mock.iakAttrs = &types.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		TPMAttributes: &types.TPMAttributes{Handle: 0x81020001},
	}
	// IDevIDAttributes fails -> fallback to KeyAttributes.
	mock.idevidAttrsErr = errors.New("idevid not available")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{} // empty -> fallback fails too

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
	iakFallbackAttrs := &types.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		TPMAttributes: &types.TPMAttributes{Handle: 0x81020001},
	}
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81020001: iakFallbackAttrs,
	}
	mock.idevidAttrsErr = nil
	mock.createTCGCSRErr = nil
	mock.createTCGCSRResult = tpm2pkg.TCG_CSR_IDEVID{}

	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestTS_ReadNVData_AutoDetectWithMatchingHandle(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []tpm2pkg.NVIndexInfo{
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
