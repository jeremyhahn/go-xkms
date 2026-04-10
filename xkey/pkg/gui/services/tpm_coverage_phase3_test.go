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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: generate a valid self-signed certificate PEM string for import tests
// ---------------------------------------------------------------------------

func phase3CertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "phase3-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// ---------------------------------------------------------------------------
// ListKeys: panic recovery (60% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ListKeys_PanicRecovery(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// ---------------------------------------------------------------------------
// GetRandomBytes: TPM error path (78.6% -> higher)
// ---------------------------------------------------------------------------

func TestP3_GetRandomBytes_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.randomBytesErr = errors.New("rng failure")
	svc := newServiceWithMock(mock)
	_, err := svc.GetRandomBytes(16)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "random bytes")
}

func TestP3_GetRandomBytes_SuccessReturnsHex(t *testing.T) {
	mock := defaultMockTPM()
	mock.randomBytesVal = []byte{0xCA, 0xFE, 0xBA, 0xBE}
	svc := newServiceWithMock(mock)
	result, err := svc.GetRandomBytes(4)
	require.NoError(t, err)
	assert.Equal(t, "cafebabe", result)
}

// ---------------------------------------------------------------------------
// ImportEKCert: success path + write error (78.6% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ImportEKCert_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeEKCertErr = nil
	svc := newServiceWithMock(mock)
	certPEM := phase3CertPEM(t)
	err := svc.ImportEKCert(certPEM)
	require.NoError(t, err)
}

func TestP3_ImportEKCert_WriteError(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeEKCertErr = errors.New("nv write failed")
	svc := newServiceWithMock(mock)
	certPEM := phase3CertPEM(t)
	err := svc.ImportEKCert(certPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nv write failed")
}

func TestP3_ImportEKCert_BadDER(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	// Valid PEM block but garbage DER bytes
	badPEM := "-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n"
	err := svc.ImportEKCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// ---------------------------------------------------------------------------
// ImportEKECCCert: success + parse error (78.6% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ImportEKECCCert_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeEKCertErr = nil
	svc := newServiceWithMock(mock)
	certPEM := phase3CertPEM(t)
	err := svc.ImportEKECCCert(certPEM)
	require.NoError(t, err)
}

func TestP3_ImportEKECCCert_BadDER(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	badPEM := "-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n"
	err := svc.ImportEKECCCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// ---------------------------------------------------------------------------
// ExportIAKCert: success path (75% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ExportIAKCert_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakCert = testCert()
	mock.iakCertErr = nil
	svc := newServiceWithMock(mock)
	result, err := svc.ExportIAKCert("pem")
	require.NoError(t, err)
	assert.Contains(t, result, "BEGIN CERTIFICATE")
}

// ---------------------------------------------------------------------------
// ExportIDevIDCert: success path (75% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ExportIDevIDCert_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidCert = testCert()
	mock.idevidCertErr = nil
	svc := newServiceWithMock(mock)
	result, err := svc.ExportIDevIDCert("pem")
	require.NoError(t, err)
	assert.Contains(t, result, "BEGIN CERTIFICATE")
}

// ---------------------------------------------------------------------------
// ImportIAKCert: write error path (86.7% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ImportIAKCert_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeIAKCertErr = nil
	svc := newServiceWithMock(mock)
	certPEM := phase3CertPEM(t)
	err := svc.ImportIAKCert(certPEM)
	require.NoError(t, err)
}

func TestP3_ImportIAKCert_WriteError(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeIAKCertErr = errors.New("provision failed")
	svc := newServiceWithMock(mock)
	certPEM := phase3CertPEM(t)
	err := svc.ImportIAKCert(certPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provision failed")
}

func TestP3_ImportIAKCert_BadDER(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	badPEM := "-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n"
	err := svc.ImportIAKCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// ---------------------------------------------------------------------------
// ImportIDevIDCert: success + write error + parse error (80% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ImportIDevIDCert_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeIDevIDErr = nil
	svc := newServiceWithMock(mock)
	certPEM := phase3CertPEM(t)
	err := svc.ImportIDevIDCert(certPEM)
	require.NoError(t, err)
}

func TestP3_ImportIDevIDCert_WriteError(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeIDevIDErr = errors.New("nv full")
	svc := newServiceWithMock(mock)
	certPEM := phase3CertPEM(t)
	err := svc.ImportIDevIDCert(certPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nv full")
}

func TestP3_ImportIDevIDCert_BadDER(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	badPEM := "-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n"
	err := svc.ImportIDevIDCert(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// ---------------------------------------------------------------------------
// saveHandleDescriptions: success + write error (77.8% -> higher)
// ---------------------------------------------------------------------------

func TestP3_SaveHandleDescriptions_Success(t *testing.T) {
	svc, dataDir := createTestTPMService(t, defaultMockTPM())
	descs := map[string]string{"0x81000001": "SRK", "0x81010001": "EK"}
	err := svc.saveHandleDescriptions(descs)
	require.NoError(t, err)

	// Verify file written and data round-trips
	data, readErr := os.ReadFile(filepath.Join(dataDir, handleDescriptionsFile))
	require.NoError(t, readErr)
	var loaded map[string]string
	require.NoError(t, json.Unmarshal(data, &loaded))
	assert.Equal(t, "SRK", loaded["0x81000001"])
	assert.Equal(t, "EK", loaded["0x81010001"])
}

func TestP3_SaveHandleDescriptions_ReadOnlyDir(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	svc.SetDataDir("/proc/nonexistent_dir_for_test")
	descs := map[string]string{"0x81000001": "SRK"}
	err := svc.saveHandleDescriptions(descs)
	assert.ErrorIs(t, err, ErrTPMHandleDescriptionFailed)
}

// ---------------------------------------------------------------------------
// GenerateIDevIDCSR: happy path + IAK fallback + IDevID fallback (63.2% -> higher)
// ---------------------------------------------------------------------------

func TestP3_GenerateIDevIDCSR_Success(t *testing.T) {
	mock := defaultMockTPM()
	// Provide an EK certificate
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	// IAKAttributes and IDevIDAttributes succeed directly
	mock.iakAttrsErr = nil
	mock.idevidAttrsErr = nil
	// CreateTCG_CSR_IDEVID returns a valid CSR
	mock.createTCGCSRResult = tpm2pkg.TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x00, 0x01},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x00},
		SigSz:     [4]byte{0x00, 0x00, 0x00, 0x00},
	}
	mock.createTCGCSRErr = nil
	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	// Validate it is valid hex
	_, decodeErr := hex.DecodeString(result)
	assert.NoError(t, decodeErr)
}

func TestP3_GenerateIDevIDCSR_IAKFallbackSuccess(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	// IAKAttributes fails, triggering fallback
	mock.iakAttrsErr = errors.New("no iak attrs")
	// handleKeyAttrs provides fallback handle 0x81020001
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81020001: {
			KeyAlgorithm: x509.RSA,
			TPMAttributes: &types.TPMAttributes{
				Handle: 0x81020001,
			},
		},
	}
	mock.idevidAttrsErr = nil
	mock.createTCGCSRResult = tpm2pkg.TCG_CSR_IDEVID{}
	mock.createTCGCSRErr = nil
	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestP3_GenerateIDevIDCSR_IDevIDFallbackSuccess(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = nil
	// IDevIDAttributes fails, triggering fallback to handle 0x81020000
	mock.idevidAttrsErr = errors.New("no idevid attrs")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81020000: {
			KeyAlgorithm: x509.ECDSA,
			TPMAttributes: &types.TPMAttributes{
				Handle: 0x81020000,
			},
		},
	}
	mock.createTCGCSRResult = tpm2pkg.TCG_CSR_IDEVID{}
	mock.createTCGCSRErr = nil
	svc := newServiceWithMock(mock)

	result, err := svc.GenerateIDevIDCSR()
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestP3_GenerateIDevIDCSR_IAKFallbackAllFail(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	// IAKAttributes fails and no fallback handles found
	mock.iakAttrsErr = errors.New("no iak")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{}
	svc := newServiceWithMock(mock)

	_, err := svc.GenerateIDevIDCSR()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IAK required")
}

func TestP3_GenerateIDevIDCSR_IDevIDFallbackFails(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = nil
	mock.idevidAttrsErr = errors.New("no idevid")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{}
	svc := newServiceWithMock(mock)

	_, err := svc.GenerateIDevIDCSR()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IDevID required")
}

func TestP3_GenerateIDevIDCSR_CSRCreationFails(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = nil
	mock.idevidAttrsErr = nil
	mock.createTCGCSRErr = errors.New("csr creation failed")
	svc := newServiceWithMock(mock)

	_, err := svc.GenerateIDevIDCSR()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CSR generation failed")
}

// ---------------------------------------------------------------------------
// ChangeOwnerAuth / ChangeEndorsementAuth / ChangeLockoutAuth (60% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ChangeOwnerAuth_ErrorFromTPM(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("auth change rejected")
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth change rejected")
}

func TestP3_ChangeOwnerAuth_EmptyPasswords(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("", "")
	require.NoError(t, err)
}

func TestP3_ChangeEndorsementAuth_SuccessWithValues(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("old-pw", "new-pw")
	require.NoError(t, err)
}

func TestP3_ChangeEndorsementAuth_ErrorFromTPM(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("endorsement auth failed")
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("old", "new")
	require.Error(t, err)
}

func TestP3_ChangeLockoutAuth_ErrorFromTPM(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("lockout auth failed")
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("old", "new")
	require.Error(t, err)
}

func TestP3_ChangeLockoutAuth_SuccessWithValues(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("oldpw", "newpw")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetVerificationStatus (60% -> higher)
// ---------------------------------------------------------------------------

func TestP3_GetVerificationStatus_WithVerifiedEK(t *testing.T) {
	caPEM, _, ekCert := testCASignedCert(t)
	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)
	require.NoError(t, svc.ImportManufacturerCA(caPEM))

	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Verified)
}

func TestP3_GetVerificationStatus_DelegatesToVerifyTPM(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertErr = errors.New("no ek cert")
	svc := newServiceWithMock(mock)
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Contains(t, status.ErrorMessage, "EK certificate not found")
}

// ---------------------------------------------------------------------------
// ListPolicies: with data (60% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ListPolicies_NoDataDir(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	// No dataDir set, returns empty list
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestP3_ListPolicies_WithSavedPolicies(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "pol-a",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "pol-b",
		PCRSelections: []PCRSelection{{Index: 7, Bank: "sha256"}},
	}))

	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 2)
}

// ---------------------------------------------------------------------------
// GetPolicy: found + no data (77.8% -> higher)
// ---------------------------------------------------------------------------

func TestP3_GetPolicy_Found(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "findme",
		Description:   "test policy",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))

	policy, err := svc.GetPolicy("findme")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "findme", policy.Name)
	assert.Equal(t, "test policy", policy.Description)
}

func TestP3_GetPolicy_NoDataDir(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.GetPolicy("anything")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// savePolicies: write error path (66.7% -> higher)
// ---------------------------------------------------------------------------

func TestP3_SavePolicies_WriteError(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	svc.SetDataDir("/proc/nonexistent_dir_for_test")
	err := svc.savePolicies([]PCRPolicy{{Name: "x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write policies")
}

func TestP3_SavePolicies_NoDataDir(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.savePolicies([]PCRPolicy{{Name: "x"}})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// ExportPolicy: branches for UpdatedAt, Digests, and empty selections (77.3% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ExportPolicy_WithUpdatedAt(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "export-updated",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	// Update to set UpdatedAt
	_, updateErr := svc.UpdatePolicy("export-updated", &PCRPolicy{
		Name:          "export-updated",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
	})
	require.NoError(t, updateErr)

	exported, err := svc.ExportPolicy("export-updated")
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.NotEmpty(t, parsed["updated_at"])
}

func TestP3_ExportPolicy_WithDigests(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "export-digests",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabbccdd"},
	}))

	exported, err := svc.ExportPolicy("export-digests")
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	digests, ok := parsed["pcr_digests"].(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, digests)
}

func TestP3_ExportPolicy_NoPCRSelections(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name: "export-nopcr",
	}))

	exported, err := svc.ExportPolicy("export-nopcr")
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	// No pcr_bank or pcr_selections keys should be present
	_, hasBankKey := parsed["pcr_bank"]
	assert.False(t, hasBankKey)
}

// ---------------------------------------------------------------------------
// ListPolicyAssignments: with data (60% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ListPolicyAssignments_NoDataDir(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

func TestP3_ListPolicyAssignments_WithData(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "assign-list",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.AssignPolicyToKey("assign-list", "0x81000001"))

	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Len(t, assignments, 1)
	assert.Equal(t, "0x81000001", assignments[0].KeyHandle)
}

// ---------------------------------------------------------------------------
// ListCompositePolicies: with data (60% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ListCompositePolicies_NoDataDir(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestP3_ListCompositePolicies_AfterCreate(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-list",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
		},
	}))

	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.Equal(t, "comp-list", policies[0].Name)
}

// ---------------------------------------------------------------------------
// GetCompositePolicy: no data dir (77.8% -> higher)
// ---------------------------------------------------------------------------

func TestP3_GetCompositePolicy_EmptyDataDir(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.GetCompositePolicy("anything")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// VerifyPolicyPassword: more branch coverage (72.7% -> higher)
// ---------------------------------------------------------------------------

func TestP3_VerifyPolicyPassword_NoPasswordElement(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "pcr-only-comp-p3",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
		},
	}))

	_, err := svc.VerifyPolicyPassword("pcr-only-comp-p3", "anything")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyType)
}

func TestP3_VerifyPolicyPassword_EmptyPasswordHash(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "empty-hash-comp-p3",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "password", PasswordHash: ""},
		},
	}))

	_, err := svc.VerifyPolicyPassword("empty-hash-comp-p3", "anything")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyType)
}

func TestP3_VerifyPolicyPassword_PolicyNotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	_, err := svc.VerifyPolicyPassword("nonexistent-p3", "pw")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// ImportManufacturerCA: parse error paths (76.5% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ImportManufacturerCA_BadDER(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	badPEM := "-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n"
	err := svc.ImportManufacturerCA(badPEM)
	assert.ErrorIs(t, err, ErrTPMInvalidCACert)
}

func TestP3_ImportManufacturerCA_NotCertBlock(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.ImportManufacturerCA("-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n")
	assert.ErrorIs(t, err, ErrTPMInvalidCACert)
}

func TestP3_ImportManufacturerCA_EmptyInput(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.ImportManufacturerCA("")
	assert.ErrorIs(t, err, ErrTPMInvalidCACert)
}

// ---------------------------------------------------------------------------
// ExportEKECCCert: success (coverage boost)
// ---------------------------------------------------------------------------

func TestP3_ExportEKECCCert_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = testECCCert()
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)
	result, err := svc.ExportEKECCCert("pem")
	require.NoError(t, err)
	assert.Contains(t, result, "BEGIN CERTIFICATE")
}

// ---------------------------------------------------------------------------
// GetEKECCInfo: attrs error path (78.6% -> higher)
// ---------------------------------------------------------------------------

func TestP3_GetEKECCInfo_AttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekAttrsErr = errors.New("no ecc attrs")
	mock.ekCertECErr = nil
	mock.ekCertEC = testECCCert()
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
}

// ---------------------------------------------------------------------------
// VerifyTPM: with trust store certs (85.2% -> higher)
// ---------------------------------------------------------------------------

func TestP3_VerifyTPM_WithTrustStoreCerts(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)

	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil

	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}

	svc := newServiceWithMock(mock)
	svc.SetTrustStore(ts)

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Verified)
	assert.Equal(t, "Test Manufacturer CA", status.Issuer)
}

func TestP3_VerifyTPM_VerificationFails(t *testing.T) {
	_, caCert, _ := testCASignedCert(t)
	_, _, ekCertFromDifferentCA := testCASignedCert(t)

	mock := defaultMockTPM()
	mock.ekCert = ekCertFromDifferentCA
	mock.ekCertErr = nil

	svc := newServiceWithMock(mock)
	svc.mfgCACerts = []*x509.Certificate{caCert}

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.NotEmpty(t, status.ErrorMessage)
}

func TestP3_VerifyTPM_NoCACertsLoaded(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Contains(t, status.ErrorMessage, "no manufacturer CA certificates loaded")
}

// ---------------------------------------------------------------------------
// GetConflictingAssignments: whitespace handles (86.7% -> higher)
// ---------------------------------------------------------------------------

func TestP3_GetConflictingAssignments_WhitespaceHandles(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "ws-pol-p3",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.AssignPolicyToKey("ws-pol-p3", "0x81000001"))

	// Request with whitespace-padded handles
	conflicts, err := svc.GetConflictingAssignments([]string{"  0x81000001  ", "", "  "})
	require.NoError(t, err)
	assert.Len(t, conflicts, 1)
}

func TestP3_GetConflictingAssignments_EmptyList(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	conflicts, err := svc.GetConflictingAssignments(nil)
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

// ---------------------------------------------------------------------------
// buildSubjectAltNames: all SAN types (80% -> 100%)
// ---------------------------------------------------------------------------

func TestP3_BuildSubjectAltNames_AllTypes(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames:       []string{"example.com", "test.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		URIs:           []*url.URL{{Scheme: "https", Host: "example.com"}},
		EmailAddresses: []string{"admin@example.com"},
	}
	result := buildSubjectAltNames(cert)
	assert.Contains(t, result, "DNS:example.com")
	assert.Contains(t, result, "DNS:test.example.com")
	assert.Contains(t, result, "IP:192.168.1.1")
	assert.Contains(t, result, "URI:https://example.com")
	assert.Contains(t, result, "email:admin@example.com")
}

func TestP3_BuildSubjectAltNames_DNSOnly(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"single.example.com"},
	}
	result := buildSubjectAltNames(cert)
	assert.Equal(t, "DNS:single.example.com", result)
}

// ---------------------------------------------------------------------------
// ExportCompositePolicy: additional branches (80% -> higher)
// ---------------------------------------------------------------------------

func TestP3_ExportCompositePolicy_WithUpdatedAt(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-export-updated-p3",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
		},
	}))

	// Manually set UpdatedAt by modifying saved policies
	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	policies[0].UpdatedAt = time.Now().Format(time.RFC3339)
	policies[0].Description = "updated desc"
	policies[0].PCRDigests = map[string]string{"sha256:0": "aabb"}
	require.NoError(t, svc.saveCompositePolicies(policies))

	exported, err := svc.ExportCompositePolicy("comp-export-updated-p3")
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.NotEmpty(t, parsed["updated_at"])
	assert.Equal(t, "updated desc", parsed["description"])
	assert.NotNil(t, parsed["pcr_digests"])
	assert.Equal(t, "sha256", parsed["pcr_bank"])
}

func TestP3_ExportCompositePolicy_PasswordOnly(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-pw-only-p3",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{Type: "password", PasswordHash: "somehash"},
		},
	}))

	exported, err := svc.ExportCompositePolicy("comp-pw-only-p3")
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	_, hasBankKey := parsed["pcr_bank"]
	assert.False(t, hasBankKey)
}

func TestP3_ExportCompositePolicy_PCRExplicitBank(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-explicit-bank-p3",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha384", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha384"}}},
		},
	}))

	exported, err := svc.ExportCompositePolicy("comp-explicit-bank-p3")
	require.NoError(t, err)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Equal(t, "sha384", parsed["pcr_bank"])
}
