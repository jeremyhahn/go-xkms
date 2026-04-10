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
	"fmt"
	"log/slog"
	"math/big"
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
// p6a test helpers
// ---------------------------------------------------------------------------

// p6aNewTPMService creates a TPMService wired to the given mock with a temp dir.
func p6aNewTPMService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}

// p6aDefaultMock returns a minimal mock suitable for most phase 6 tests.
func p6aDefaultMock() *mockTPM {
	return &mockTPM{
		device: "/dev/tpmrm0",
		config: &tpm2pkg.Config{
			Hash: "SHA-256",
			SSRK: &tpm2pkg.SRKConfig{Handle: 0x81000001, KeyAlgorithm: "RSA"},
		},
		fixedProps: &tpm2pkg.PropertiesFixed{
			Manufacturer:  "P6TestMFG",
			FwMajor:       7,
			FwMinor:       85,
			MaxRSAKeyBits: 2048,
			MaxECCKeyBits: 384,
		},
		ekAttrs: &types.KeyAttributes{
			KeyAlgorithm:  x509.RSA,
			RSAAttributes: &types.RSAAttributes{KeySize: 2048},
			TPMAttributes: &types.TPMAttributes{Handle: 0x81010001},
		},
		ssrkAttrs: &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		pcrBanks: []tpm2pkg.PCRBank{
			{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA, 0xBB}}}},
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
func (m *p6aMockTrustStore) Certificates() ([]*x509.Certificate, error)          { return nil, nil }
func (m *p6aMockTrustStore) AddPEM(_ []byte) (int, error)                        { return 0, nil }
func (m *p6aMockTrustStore) CertPool() (*x509.CertPool, error)                   { return x509.NewCertPool(), nil }
func (m *p6aMockTrustStore) Contains(_ string) (bool, error)                     { return false, nil }
func (m *p6aMockTrustStore) Count() (int, error)                                 { return 0, nil }
func (m *p6aMockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) { return nil, nil }
func (m *p6aMockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error { return nil }
func (m *p6aMockTrustStore) SetSource(_ string, _ string) error                  { return nil }
func (m *p6aMockTrustStore) SetSystemInstalled(_ string, _ bool) error           { return nil }
func (m *p6aMockTrustStore) SetTags(_ string, _ []string) error                  { return nil }
func (m *p6aMockTrustStore) Close() error                                        { return nil }

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
	mock.ekAttrs = &types.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		TPMAttributes: &types.TPMAttributes{
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
	mock.iakAttrs = &types.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
		TPMAttributes: &types.TPMAttributes{
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
	mock.idevidAttrs = &types.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
		TPMAttributes: &types.TPMAttributes{
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
	mock.nvIndexes = []tpm2pkg.NVIndexInfo{}
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ReadNVData(0x01800001, 0, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestP6A_ReadNVData_AutoSizeFromIndex(t *testing.T) {
	mock := p6aDefaultMock()
	mock.nvIndexes = []tpm2pkg.NVIndexInfo{
		{Handle: 0x01800001, Size: 32, Type: "ordinary"},
	}
	mock.nvReadResult = make([]byte, 32)
	svc, _ := p6aNewTPMService(t, mock)

	result, err := svc.ReadNVData(0x01800001, 0, "")
	require.NoError(t, err)
	assert.Len(t, result, 64)
}

// ---------------------------------------------------------------------------
// importJSONPolicy and importBinaryPolicyDigest -- file import paths
// ---------------------------------------------------------------------------

func TestP6A_ImportJSONPolicy_InvalidJSON(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	_, err := svc.importJSONPolicy([]byte("not valid json"))
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestP6A_ImportJSONPolicy_EmptyName(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	raw := `{"pcr_bank":"sha256"}`
	_, err := svc.importJSONPolicy([]byte(raw))
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestP6A_ImportJSONPolicy_PCRPolicy(t *testing.T) {
	mock := p6aDefaultMock()
	svc, _ := p6aNewTPMService(t, mock)

	raw := `{
		"name": "p6a-imported-pcr",
		"pcr_bank": "sha256",
		"pcr_selections": [0, 7],
		"pcr_digests": {"sha256:0": "aabb", "sha256:7": "ccdd"}
	}`
	name, err := svc.importJSONPolicy([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, "p6a-imported-pcr", name)

	policy, err := svc.GetPolicy("p6a-imported-pcr")
	require.NoError(t, err)
	assert.Len(t, policy.PCRSelections, 2)
	assert.Equal(t, "aabb", policy.PCRDigests["sha256:0"])
}

func TestP6A_ImportJSONPolicy_CompositePolicy(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	raw := `{
		"name": "p6a-composite-import",
		"operator": "OR",
		"elements": [
			{"type": "pcr", "pcr_bank": "sha256", "pcr_selections": [{"index": 0, "bank": "sha256"}]},
			{"type": "password", "password_hash": "test-hash"}
		]
	}`
	name, err := svc.importJSONPolicy([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, "p6a-composite-import", name)
}

func TestP6A_ImportCompositePolicy_EmptyName(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	raw := map[string]interface{}{
		"name":     "",
		"operator": "AND",
		"elements": []interface{}{},
	}
	_, err := svc.importCompositePolicy(raw)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestP6A_ImportCompositePolicy_Duplicate(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	existing := CompositePolicy{
		Name:      "p6a-dup",
		Operator:  "AND",
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent([]CompositePolicy{existing}, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	raw := map[string]interface{}{
		"name":     "p6a-dup",
		"operator": "AND",
		"elements": []interface{}{},
	}
	_, err = svc.importCompositePolicy(raw)
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

func TestP6A_ImportBinaryPolicyDigest_Empty(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	_, err := svc.importBinaryPolicyDigest("/tmp/empty.bin", []byte{})
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestP6A_ImportBinaryPolicyDigest_Success(t *testing.T) {
	mock := p6aDefaultMock()
	svc, _ := p6aNewTPMService(t, mock)

	digestBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	name, err := svc.importBinaryPolicyDigest("/tmp/my-policy.bin", digestBytes)
	require.NoError(t, err)
	assert.Equal(t, "my-policy", name)

	policy, err := svc.GetPolicy("my-policy")
	require.NoError(t, err)
	assert.Contains(t, policy.Description, "Imported binary policy digest")
	assert.Equal(t, hex.EncodeToString(digestBytes), policy.PCRDigests["policy_digest"])
}

func TestP6A_ImportBinaryPolicyDigest_NameConflict(t *testing.T) {
	mock := p6aDefaultMock()
	svc, _ := p6aNewTPMService(t, mock)

	digest := []byte{0xAA, 0xBB}

	name1, err := svc.importBinaryPolicyDigest("/tmp/conflict.bin", digest)
	require.NoError(t, err)
	assert.Equal(t, "conflict", name1)

	name2, err := svc.importBinaryPolicyDigest("/tmp/conflict.bin", digest)
	require.NoError(t, err)
	assert.NotEqual(t, "conflict", name2)
	assert.Contains(t, name2, "conflict-")
}

func TestP6A_ImportBinaryPolicyDigest_EmptyFilename(t *testing.T) {
	mock := p6aDefaultMock()
	svc, _ := p6aNewTPMService(t, mock)

	name, err := svc.importBinaryPolicyDigest("/tmp/.bin", []byte{0xFF})
	require.NoError(t, err)
	assert.Equal(t, "imported-policy", name)
}

// ---------------------------------------------------------------------------
// savePolicyDigestBinary
// ---------------------------------------------------------------------------

func TestP6A_SavePolicyDigestBinary_InvalidJSON(t *testing.T) {
	svc := NewTPMService()

	err := svc.savePolicyDigestBinary("/tmp/test.bin", "not json")
	assert.ErrorIs(t, err, ErrTPMPolicyExportFailed)
}

func TestP6A_SavePolicyDigestBinary_Success(t *testing.T) {
	svc := NewTPMService()
	outPath := filepath.Join(t.TempDir(), "policy.bin")

	policyJSON := `{
		"pcr_bank": "sha256",
		"pcr_selections": [0, 7],
		"pcr_digests": {
			"sha256:0": "aabbccdd",
			"sha256:7": "11223344"
		}
	}`
	err := svc.savePolicyDigestBinary(outPath, policyJSON)
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// ---------------------------------------------------------------------------
// ExportPolicy -- branches for UpdatedAt and PCRDigests
// ---------------------------------------------------------------------------

func TestP6A_ExportPolicy_WithUpdateAndDigests(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policy := PCRPolicy{
		Name:          "p6a-export",
		CreatedAt:     time.Now().Format(time.RFC3339),
		UpdatedAt:     time.Now().Format(time.RFC3339),
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabbccdd"},
	}
	data, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	exported, err := svc.ExportPolicy("p6a-export")
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Contains(t, parsed, "updated_at")
	assert.Contains(t, parsed, "pcr_digests")
	assert.Contains(t, parsed, "pcr_bank")
	assert.Contains(t, parsed, "pcr_selections")
}

func TestP6A_ExportPolicy_NotFound(t *testing.T) {
	mock := p6aDefaultMock()
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.ExportPolicy("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// ExportCompositePolicy -- branches
// ---------------------------------------------------------------------------

func TestP6A_ExportCompositePolicy_AllBranches(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	cp := CompositePolicy{
		Name:        "p6a-comp-export",
		Operator:    "OR",
		Description: "testing export",
		UpdatedAt:   time.Now().Format(time.RFC3339),
		CreatedAt:   time.Now().Format(time.RFC3339),
		PCRDigests:  map[string]string{"sha256:0": "aabb"},
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
			},
			{Type: "password", PasswordHash: "hash"},
		},
	}
	data, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	exported, err := svc.ExportCompositePolicy("p6a-comp-export")
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Contains(t, parsed, "updated_at")
	assert.Contains(t, parsed, "description")
	assert.Contains(t, parsed, "pcr_digests")
	assert.Contains(t, parsed, "pcr_bank")
	assert.Contains(t, parsed, "pcr_selections")
}

func TestP6A_ExportCompositePolicy_PCRBankFallback(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	cp := CompositePolicy{
		Name:      "p6a-bank-fallback",
		Operator:  "SINGLE",
		CreatedAt: time.Now().Format(time.RFC3339),
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha384"}},
			},
		},
	}
	data, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	exported, err := svc.ExportCompositePolicy("p6a-bank-fallback")
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Equal(t, "sha384", parsed["pcr_bank"])
}

// ---------------------------------------------------------------------------
// UnassignPolicyFromKey -- not found
// ---------------------------------------------------------------------------

func TestP6A_UnassignPolicyFromKey_NotFound(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	err := svc.UnassignPolicyFromKey("0xDEADBEEF")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// removeAssignmentsForPolicy -- save error branch
// ---------------------------------------------------------------------------

func TestP6A_RemoveAssignmentsForPolicy_SaveError(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	assignments := []PolicyAssignment{
		{PolicyName: "p6a-remove-me", KeyHandle: "0x81000001", AssignedAt: "2025-01-01"},
	}
	data, _ := json.MarshalIndent(assignments, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600)
	require.NoError(t, err)

	assignFile := filepath.Join(dataDir, policyAssignmentsFile)
	os.Chmod(assignFile, 0444)
	defer os.Chmod(assignFile, 0600)

	// Should not panic, just log the error.
	svc.removeAssignmentsForPolicy("p6a-remove-me")
}

// ---------------------------------------------------------------------------
// DeleteCompositePolicy
// ---------------------------------------------------------------------------

func TestP6A_DeleteCompositePolicy_NotFound(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	err := svc.DeleteCompositePolicy("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestP6A_DeleteCompositePolicy_Cascade(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	policies := []CompositePolicy{
		{Name: "keep-this", Operator: "AND", CreatedAt: "2025-01-01"},
		{Name: "delete-this", Operator: "OR", CreatedAt: "2025-01-02"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	assignments := []PolicyAssignment{
		{PolicyName: "delete-this", KeyHandle: "0x81000099", AssignedAt: "2025-01-01"},
	}
	aData, _ := json.MarshalIndent(assignments, "", "  ")
	err = os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), aData, 0600)
	require.NoError(t, err)

	err = svc.DeleteCompositePolicy("delete-this")
	require.NoError(t, err)

	remaining := svc.loadCompositePolicies()
	require.Len(t, remaining, 1)
	assert.Equal(t, "keep-this", remaining[0].Name)
}

// ---------------------------------------------------------------------------
// RefreshCompositePolicyPCRs
// ---------------------------------------------------------------------------

func TestP6A_RefreshCompositePolicyPCRs_NoPCRSelections(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	policies := []CompositePolicy{
		{Name: "no-pcrs", Operator: "SINGLE", CreatedAt: "2025-01-01",
			Elements: []PolicyElement{{Type: "password", PasswordHash: "hash"}}},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	mock := p6aDefaultMock()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))

	result, err := svc.RefreshCompositePolicyPCRs("no-pcrs")
	require.NoError(t, err)
	assert.Equal(t, "no-pcrs", result.Name)
}

func TestP6A_RefreshCompositePolicyPCRs_SaveError(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []CompositePolicy{
		{Name: "p6a-refresh", Operator: "SINGLE", CreatedAt: "2025-01-01",
			Elements: []PolicyElement{{Type: "pcr", PCRBank: "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}}}},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	cpFile := filepath.Join(dataDir, compositePoliciesFile)
	err := os.WriteFile(cpFile, data, 0600)
	require.NoError(t, err)

	os.Chmod(cpFile, 0444)
	defer os.Chmod(cpFile, 0600)

	_, err = svc.RefreshCompositePolicyPCRs("p6a-refresh")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListPoliciesWithDigests -- PCR read error, bank normalization, digest
// comparison
// ---------------------------------------------------------------------------

func TestP6A_ListPoliciesWithDigests_PCRReadError(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanksErr = errors.New("PCR read failed")
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-digest-err", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			PCRDigests: map[string]string{"sha256:0": "aabb"}, CreatedAt: "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestP6A_ListPoliciesWithDigests_UnknownBank(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "CUSTOMALG", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
	}
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-custom-bank", PCRSelections: []PCRSelection{{Index: 0, Bank: "customalg"}},
			PCRDigests: map[string]string{"customalg:0": hex.EncodeToString([]byte{0xAA})},
			CreatedAt:  "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestP6A_ListPoliciesWithDigests_DigestMismatch(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x11, 0x22}}}},
	}
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-mismatch", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			PCRDigests: map[string]string{"sha256:0": "aabb"},
			CreatedAt:  "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].Valid)
	assert.False(t, *result[0].Valid)
}

func TestP6A_ListPoliciesWithDigests_DigestMatch(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA, 0xBB}}}},
	}
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-match", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			PCRDigests: map[string]string{"sha256:0": hex.EncodeToString([]byte{0xAA, 0xBB})},
			CreatedAt:  "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].Valid)
	assert.True(t, *result[0].Valid)
}

func TestP6A_ListPoliciesWithDigests_NoSavedDigests(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-no-digests", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			CreatedAt: "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Nil(t, result[0].Valid)
}

func TestP6A_ListPoliciesWithDigests_MissingSavedKey(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
	}
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-missing-key",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
			PCRDigests:    map[string]string{"sha256:0": hex.EncodeToString([]byte{0xAA}), "sha256:7": "beef"},
			CreatedAt:     "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].Valid)
	assert.False(t, *result[0].Valid)
}

// ---------------------------------------------------------------------------
// ListCompositePoliciesWithDigests
// ---------------------------------------------------------------------------

func TestP6A_ListCompositePoliciesWithDigests_NoPCRBanks(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	policies := []CompositePolicy{
		{Name: "p6a-no-pcr-comp", Operator: "SINGLE", CreatedAt: "2025-01-01",
			Elements: []PolicyElement{{Type: "password"}}},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestP6A_ListCompositePoliciesWithDigests_DigestComparison(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x11, 0x22}}}},
	}
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []CompositePolicy{
		{Name: "p6a-comp-digest", Operator: "SINGLE", CreatedAt: "2025-01-01",
			PCRDigests: map[string]string{"sha256:0": hex.EncodeToString([]byte{0x11, 0x22})},
			Elements: []PolicyElement{
				{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
			}},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].Valid)
	assert.True(t, *result[0].Valid)
}

func TestP6A_ListCompositePoliciesWithDigests_MismatchMissingCurrent(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
	}
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []CompositePolicy{
		{Name: "p6a-comp-missing", Operator: "SINGLE", CreatedAt: "2025-01-01",
			PCRDigests: map[string]string{"sha256:0": "aabb", "sha256:7": "ccdd"},
			Elements: []PolicyElement{
				{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{
					{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}}},
			}},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].Valid)
	assert.False(t, *result[0].Valid)
}

func TestP6A_ListCompositePoliciesWithDigests_NoSavedDigests(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []CompositePolicy{
		{Name: "p6a-comp-nodigest", Operator: "SINGLE", CreatedAt: "2025-01-01",
			Elements: []PolicyElement{
				{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
			}},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Nil(t, result[0].Valid)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKeys -- branches
// ---------------------------------------------------------------------------

func TestP6A_AssignPolicyToKeys_EmptyPolicyName(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	err := svc.AssignPolicyToKeys("  ", []string{"0x81000001"})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestP6A_AssignPolicyToKeys_EmptyHandles(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	err := svc.AssignPolicyToKeys("test-policy", []string{})
	assert.ErrorIs(t, err, ErrTPMInvalidHandle)
}

func TestP6A_AssignPolicyToKeys_SkipEmptyHandle(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-assign-skip", CreatedAt: "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	err = svc.AssignPolicyToKeys("p6a-assign-skip", []string{"0x81000001", "  ", "0x81000002"})
	require.NoError(t, err)

	assignments := svc.loadAssignments()
	assert.Len(t, assignments, 2)
}

func TestP6A_AssignPolicyToKeys_UpdateExisting(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-update", CreatedAt: "2025-01-01"},
	}
	pData, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), pData, 0600)
	require.NoError(t, err)

	existing := []PolicyAssignment{
		{PolicyName: "old-policy", KeyHandle: "0x81000001", AssignedAt: "2024-01-01"},
	}
	aData, _ := json.MarshalIndent(existing, "", "  ")
	err = os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), aData, 0600)
	require.NoError(t, err)

	err = svc.AssignPolicyToKeys("p6a-update", []string{"0x81000001"})
	require.NoError(t, err)

	assignments := svc.loadAssignments()
	require.Len(t, assignments, 1)
	assert.Equal(t, "p6a-update", assignments[0].PolicyName)
}

func TestP6A_AssignPolicyToKeys_PlatformPolicyNotLoaded(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	ppSvc := NewPlatformPolicyService(filepath.Join(dataDir, "platform-policy.json"))
	svc.SetPlatformPolicyService(ppSvc)

	err := svc.AssignPolicyToKeys("Platform Policy", []string{"0x81000001"})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Password-related nil service paths
// ---------------------------------------------------------------------------

func TestP6A_DeletePolicyPassword_NilService(t *testing.T) {
	svc := NewTPMService()
	svc.log = slog.Default()
	svc.staticPWService = nil
	svc.deletePolicyPassword("test-delete")
}

func TestP6A_FindPolicyPasswordEntry_NilService(t *testing.T) {
	svc := NewTPMService()
	svc.staticPWService = nil

	id, found := svc.findPolicyPasswordEntry("test")
	assert.Empty(t, id)
	assert.False(t, found)
}

func TestP6A_SavePolicyPassword_NilService(t *testing.T) {
	svc := NewTPMService()
	svc.log = slog.Default()
	svc.staticPWService = nil
	svc.savePolicyPassword("test", "AND", "secret")
}

// ---------------------------------------------------------------------------
// ComparePolicyPCRs -- hex decode error branches
// ---------------------------------------------------------------------------

func TestP6A_ComparePolicyPCRs_HexDecodeErrors(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
	}
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-hex-error",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			PCRDigests:    map[string]string{"sha256:0": "not-valid-hex"},
			CreatedAt:     "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	result, err := svc.ComparePolicyPCRs("p6a-hex-error")
	require.NoError(t, err)
	assert.False(t, result.AllMatch)
	assert.Equal(t, 1, result.MismatchCount)
	assert.Equal(t, "not-valid-hex", result.Entries[0].Saved)
}

func TestP6A_ComparePolicyPCRs_EmptyPolicyName(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	_, err := svc.ComparePolicyPCRs("")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestP6A_ComparePolicyPCRs_NoDigests(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-no-digests-cmp",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			CreatedAt:     "2025-01-01"},
	}
	data, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600)
	require.NoError(t, err)

	_, err = svc.ComparePolicyPCRs("p6a-no-digests-cmp")
	assert.ErrorIs(t, err, ErrTPMPolicyNoDigests)
}

// ---------------------------------------------------------------------------
// GetInfo TCG cert attribute overrides (lines 887-895)
// ---------------------------------------------------------------------------

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
	mock.iakAttrs = &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	mock.idevidAttrs = &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	mock.idevidCert = p6aGenCert(t)

	svc, _ := p6aNewTPMService(t, mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.NotEmpty(t, info.Manufacturer)
}

// ---------------------------------------------------------------------------
// GetPolicyDeletionImpact
// ---------------------------------------------------------------------------

func TestP6A_GetPolicyDeletionImpact_PCRPolicy(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-impact", CreatedAt: "2025-01-01"},
	}
	pData, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), pData, 0600)
	require.NoError(t, err)

	assignments := []PolicyAssignment{
		{PolicyName: "p6a-impact", KeyHandle: "0x81000001", AssignedAt: "2025-01-01"},
		{PolicyName: "other-policy", KeyHandle: "0x81000002", AssignedAt: "2025-01-01"},
	}
	aData, _ := json.MarshalIndent(assignments, "", "  ")
	err = os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), aData, 0600)
	require.NoError(t, err)

	impact, err := svc.GetPolicyDeletionImpact("p6a-impact")
	require.NoError(t, err)
	assert.Equal(t, "pcr", impact.PolicyType)
	assert.Len(t, impact.AssignedKeyHandles, 1)
	assert.Equal(t, "0x81000001", impact.AssignedKeyHandles[0])
}

func TestP6A_GetPolicyDeletionImpact_CompositePolicy(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	cpolicies := []CompositePolicy{
		{Name: "p6a-impact-comp", Operator: "AND", CreatedAt: "2025-01-01"},
	}
	cpData, _ := json.MarshalIndent(cpolicies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600)
	require.NoError(t, err)

	impact, err := svc.GetPolicyDeletionImpact("p6a-impact-comp")
	require.NoError(t, err)
	assert.Equal(t, "composite", impact.PolicyType)
}

func TestP6A_GetPolicyDeletionImpact_NotFound(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	_, err := svc.GetPolicyDeletionImpact("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// DeletePolicy -- cascade removal
// ---------------------------------------------------------------------------

func TestP6A_DeletePolicy_WithCascade(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-del-keep", CreatedAt: "2025-01-01"},
		{Name: "p6a-del-target", CreatedAt: "2025-01-02"},
	}
	pData, _ := json.MarshalIndent(policies, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), pData, 0600)
	require.NoError(t, err)

	assignments := []PolicyAssignment{
		{PolicyName: "p6a-del-target", KeyHandle: "0x81000001", AssignedAt: "2025-01-01"},
	}
	aData, _ := json.MarshalIndent(assignments, "", "  ")
	err = os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), aData, 0600)
	require.NoError(t, err)

	err = svc.DeletePolicy("p6a-del-target")
	require.NoError(t, err)

	remaining := svc.loadPolicies()
	require.Len(t, remaining, 1)
	assert.Equal(t, "p6a-del-keep", remaining[0].Name)

	remainingAssignments := svc.loadAssignments()
	assert.Empty(t, remainingAssignments)
}

// ---------------------------------------------------------------------------
// Save error paths
// ---------------------------------------------------------------------------

func TestP6A_UpdatePolicy_SaveError(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-update-err", CreatedAt: "2025-01-01"},
	}
	pData, _ := json.MarshalIndent(policies, "", "  ")
	pFile := filepath.Join(dataDir, pcrPoliciesFile)
	err := os.WriteFile(pFile, pData, 0600)
	require.NoError(t, err)

	os.Chmod(pFile, 0444)
	defer os.Chmod(pFile, 0600)

	_, err = svc.UpdatePolicy("p6a-update-err", &PCRPolicy{Description: "updated"})
	assert.Error(t, err)
}

func TestP6A_RefreshPolicyPCRs_SaveError(t *testing.T) {
	mock := p6aDefaultMock()
	svc, dataDir := p6aNewTPMService(t, mock)

	policies := []PCRPolicy{
		{Name: "p6a-refresh-err", CreatedAt: "2025-01-01",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
	}
	pData, _ := json.MarshalIndent(policies, "", "  ")
	pFile := filepath.Join(dataDir, pcrPoliciesFile)
	err := os.WriteFile(pFile, pData, 0600)
	require.NoError(t, err)

	os.Chmod(pFile, 0444)
	defer os.Chmod(pFile, 0600)

	_, err = svc.RefreshPolicyPCRs("p6a-refresh-err")
	assert.Error(t, err)
}

func TestP6A_SavePolicies_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/directory/that/does/not/exist")

	err := svc.savePolicies([]PCRPolicy{{Name: "test"}})
	assert.Error(t, err)
}

func TestP6A_SavePolicies_EmptyDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.savePolicies([]PCRPolicy{})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

func TestP6A_SaveCompositePolicies_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/directory/that/does/not/exist")

	err := svc.saveCompositePolicies([]CompositePolicy{{Name: "test"}})
	assert.Error(t, err)
}

func TestP6A_SaveAssignments_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/directory/that/does/not/exist")

	err := svc.saveAssignments([]PolicyAssignment{{PolicyName: "test", KeyHandle: "0x1"}})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// compositePolicyPCRSelections -- bank fallback
// ---------------------------------------------------------------------------

func TestP6A_CompositePolicyPCRSelections_BankFallback(t *testing.T) {
	policy := &CompositePolicy{
		Elements: []PolicyElement{
			{
				Type:    "pcr",
				PCRBank: "sha384",
				PCRSelections: []PCRSelection{
					{Index: 0, Bank: ""},
					{Index: 7, Bank: "sha256"},
				},
			},
			{Type: "password"},
		},
	}

	selections := compositePolicyPCRSelections(policy)
	require.Len(t, selections, 2)
	assert.Equal(t, "sha384", selections[0].Bank)
	assert.Equal(t, "sha256", selections[1].Bank)
}

// ---------------------------------------------------------------------------
// GetConflictingAssignments
// ---------------------------------------------------------------------------

func TestP6A_GetConflictingAssignments_WithConflicts(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	assignments := []PolicyAssignment{
		{PolicyName: "policy-a", KeyHandle: "0x81000001", AssignedAt: "2025-01-01"},
		{PolicyName: "policy-b", KeyHandle: "0x81000002", AssignedAt: "2025-01-02"},
		{PolicyName: "policy-c", KeyHandle: "0x81000003", AssignedAt: "2025-01-03"},
	}
	data, _ := json.MarshalIndent(assignments, "", "  ")
	err := os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600)
	require.NoError(t, err)

	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001", "0x81000003", "  "})
	require.NoError(t, err)
	assert.Len(t, conflicts, 2)
	assert.Equal(t, "policy-a", conflicts[0].CurrentPolicy)
	assert.Equal(t, "policy-c", conflicts[1].CurrentPolicy)
}

func TestP6A_GetConflictingAssignments_NoConflicts(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	conflicts, err := svc.GetConflictingAssignments([]string{"0xDEADBEEF"})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

// ---------------------------------------------------------------------------
// GenerateIDevIDCSR -- IAK and IDevID fallback paths
// ---------------------------------------------------------------------------

func TestP6A_GenerateIDevIDCSR_IAKFallback(t *testing.T) {
	mock := p6aDefaultMock()
	mock.ekCert = p6aGenCert(t)
	mock.iakAttrsErr = errors.New("no IAK attrs")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81020001: {KeyAlgorithm: x509.ECDSA, TPMAttributes: &types.TPMAttributes{Handle: 0x81020001}},
	}
	mock.idevidAttrs = &types.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		TPMAttributes: &types.TPMAttributes{Handle: 0x81020000},
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
	mock.iakAttrs = &types.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		TPMAttributes: &types.TPMAttributes{Handle: 0x81020001},
	}
	mock.idevidAttrsErr = errors.New("no IDevID attrs")
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81020000: {KeyAlgorithm: x509.ECDSA, TPMAttributes: &types.TPMAttributes{Handle: 0x81020000}},
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
	mock.iakAttrs = &types.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		TPMAttributes: &types.TPMAttributes{Handle: 0x81020001},
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

func TestP6A_CreatePolicy_WithPCRSelections(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "sha256", PCRs: []tpm2pkg.PCR{
			{ID: 0, Value: []byte{0xAA, 0xBB}},
			{ID: 7, Value: []byte{0xCC, 0xDD}},
		}},
	}
	svc, _ := p6aNewTPMService(t, mock)

	policy := &PCRPolicy{
		Name: "p6a-create-pcr",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
	}
	err := svc.CreatePolicy(policy)
	require.NoError(t, err)

	saved, err := svc.GetPolicy("p6a-create-pcr")
	require.NoError(t, err)
	assert.NotEmpty(t, saved.CreatedAt)
	assert.NotEmpty(t, saved.PCRDigests)
}

// ---------------------------------------------------------------------------
// GetPCRs -- SHA384/SHA386 mismatch handling
// ---------------------------------------------------------------------------

func TestP6A_GetPCRs_SHA384_SHA386Mismatch(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA386", PCRs: []tpm2pkg.PCR{
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

func TestP6A_GetPCRs_BankNotSupported(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
	}
	svc, _ := p6aNewTPMService(t, mock)

	_, err := svc.GetPCRs("sha512")
	assert.ErrorIs(t, err, ErrTPMBankNotSupported)
}

// ---------------------------------------------------------------------------
// CreateDefaultPlatformPolicy -- idempotent
// ---------------------------------------------------------------------------

func TestP6A_CreateDefaultPlatformPolicy_Idempotent(t *testing.T) {
	mock := p6aDefaultMock()
	svc, _ := p6aNewTPMService(t, mock)

	err := svc.CreateDefaultPlatformPolicy()
	require.NoError(t, err)

	err = svc.CreateDefaultPlatformPolicy()
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// loadHandleDescriptions -- corrupt JSON
// ---------------------------------------------------------------------------

func TestP6A_LoadHandleDescriptions_CorruptJSON(t *testing.T) {
	svc := NewTPMService()
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	err := os.WriteFile(filepath.Join(dataDir, handleDescriptionsFile), []byte("not json"), 0600)
	require.NoError(t, err)

	descriptions := svc.loadHandleDescriptions()
	assert.Empty(t, descriptions)
}

// ---------------------------------------------------------------------------
// readPCRDigests -- read error per bank
// ---------------------------------------------------------------------------

func TestP6A_ReadPCRDigests_ReadError(t *testing.T) {
	mock := p6aDefaultMock()
	mock.pcrBanksErr = errors.New("PCR read fail")
	svc, _ := p6aNewTPMService(t, mock)

	tpmInstance, _ := svc.getTPM()
	defer svc.tpmAccessor.Release()

	digests := svc.readPCRDigests(tpmInstance, []PCRSelection{{Index: 0, Bank: "sha256"}})
	assert.Empty(t, digests)
}

// ---------------------------------------------------------------------------
// Sanity check
// ---------------------------------------------------------------------------

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
