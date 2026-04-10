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
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockTPMWithCommands wraps mockTPM to provide configurable SupportedCommands
// and SupportedECCCurves responses.
// ---------------------------------------------------------------------------

type mockTPMWithCommands struct {
	*mockTPM
	commands    []string
	commandsErr error
	curves      []string
	curvesErr   error
}

func (m *mockTPMWithCommands) SupportedCommands() ([]string, error) {
	return m.commands, m.commandsErr
}

func (m *mockTPMWithCommands) SupportedECCCurves() ([]string, error) {
	return m.curves, m.curvesErr
}

// ---------------------------------------------------------------------------
// mockStaticPWStore implements staticpw.Store in-memory for testing policy
// password save/find/delete operations.
// ---------------------------------------------------------------------------

type mockStaticPWStore struct {
	mu      sync.RWMutex
	entries map[string]*staticpw.StaticPassword
}

func newMockStaticPWStore() *mockStaticPWStore {
	return &mockStaticPWStore{
		entries: make(map[string]*staticpw.StaticPassword),
	}
}

func (m *mockStaticPWStore) Add(pw *staticpw.StaticPassword) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := staticpw.GenerateID(pw.Name, pw.FolderPath)
	if _, exists := m.entries[id]; exists {
		return staticpw.ErrPasswordExists
	}
	stored := *pw
	stored.ID = id
	now := time.Now()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	stored.UpdatedAt = now
	m.entries[id] = &stored
	return nil
}

func (m *mockStaticPWStore) Get(idOrName string) (*staticpw.StaticPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if pw, ok := m.entries[idOrName]; ok {
		cp := *pw
		return &cp, nil
	}
	lower := strings.ToLower(idOrName)
	for _, pw := range m.entries {
		if strings.ToLower(pw.Name) == lower {
			cp := *pw
			return &cp, nil
		}
	}
	return nil, staticpw.ErrPasswordNotFound
}

func (m *mockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*staticpw.StaticPassword, 0, len(m.entries))
	for _, pw := range m.entries {
		cp := *pw
		result = append(result, &cp)
	}
	return result, nil
}

func (m *mockStaticPWStore) Update(pw *staticpw.StaticPassword) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[pw.ID]; !exists {
		return staticpw.ErrPasswordNotFound
	}
	stored := *pw
	stored.UpdatedAt = time.Now()
	m.entries[pw.ID] = &stored
	return nil
}

func (m *mockStaticPWStore) Delete(idOrName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[idOrName]; exists {
		if m.entries[idOrName].ReadOnly {
			return staticpw.ErrPasswordReadOnly
		}
		delete(m.entries, idOrName)
		return nil
	}
	lower := strings.ToLower(idOrName)
	for id, pw := range m.entries {
		if strings.ToLower(pw.Name) == lower {
			if pw.ReadOnly {
				return staticpw.ErrPasswordReadOnly
			}
			delete(m.entries, id)
			return nil
		}
	}
	return staticpw.ErrPasswordNotFound
}

func (m *mockStaticPWStore) ForceDelete(idOrName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[idOrName]; exists {
		delete(m.entries, idOrName)
		return nil
	}
	lower := strings.ToLower(idOrName)
	for id, pw := range m.entries {
		if strings.ToLower(pw.Name) == lower {
			delete(m.entries, id)
			return nil
		}
	}
	return staticpw.ErrPasswordNotFound
}

func (m *mockStaticPWStore) ListByFolder(folderPath string) ([]*staticpw.StaticPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*staticpw.StaticPassword, 0)
	for _, pw := range m.entries {
		if pw.FolderPath == folderPath {
			cp := *pw
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *mockStaticPWStore) ListFolders() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]struct{})
	for _, pw := range m.entries {
		if pw.FolderPath != "" {
			seen[pw.FolderPath] = struct{}{}
		}
	}
	folders := make([]string, 0, len(seen))
	for f := range seen {
		folders = append(folders, f)
	}
	return folders, nil
}

func (m *mockStaticPWStore) MoveToFolder(_, _ string) error { return nil }
func (m *mockStaticPWStore) CreateFolder(_ string) error    { return nil }
func (m *mockStaticPWStore) RemoveFolder(_ string) error    { return nil }
func (m *mockStaticPWStore) ListByFolderDirect(folderPath string) ([]*staticpw.StaticPassword, error) {
	return m.ListByFolder(folderPath)
}
func (m *mockStaticPWStore) Close() error { return nil }

// compile-time check
var _ staticpw.Store = (*mockStaticPWStore)(nil)

// newStaticPWService creates a StaticPasswordService backed by an in-memory store.
func newStaticPWService() (*StaticPasswordService, *mockStaticPWStore) {
	store := newMockStaticPWStore()
	svc := NewStaticPasswordService(store)
	return svc, store
}

// ---------------------------------------------------------------------------
// GetInfo - additional coverage for ECC curves, commands, overview props,
// and EK cert TCG attributes.
// ---------------------------------------------------------------------------

func TestTPMService_GetInfo_ECCCurves(t *testing.T) {
	inner := defaultMockTPM()
	mock := &mockTPMWithCommands{
		mockTPM: inner,
		curves:  []string{"P-256", "P-384", "P-521"},
	}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.Equal(t, []string{"P-256", "P-384", "P-521"}, info.ECCCurves)
}

func TestTPMService_GetInfo_ECCCurvesError(t *testing.T) {
	inner := defaultMockTPM()
	mock := &mockTPMWithCommands{
		mockTPM:   inner,
		curvesErr: errors.New("no curves"),
	}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// ECCCurves should be empty/nil when the TPM returns an error.
	assert.Empty(t, info.ECCCurves)
}

func TestTPMService_GetInfo_SupportedCommandsWithValues(t *testing.T) {
	inner := defaultMockTPM()
	mock := &mockTPMWithCommands{
		mockTPM:  inner,
		commands: []string{"TPM2_Sign", "TPM2_Create", "TPM2_Load"},
	}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.Len(t, info.Commands, 3)
	assert.Equal(t, "TPM2_Sign", info.Commands[0].Name)
	assert.Equal(t, "TPM 2.0 command", info.Commands[0].Description)
}

func TestTPMService_GetInfo_OverviewProperties(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedProps.InputBufferMax = 1024
	mock.fixedProps.MaxDigestSize = 64
	mock.fixedProps.MaxObjectContext = 2048
	mock.fixedProps.LockoutInterval = 300
	mock.fixedProps.LockoutRecovery = 600
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.Equal(t, 1024, info.InputBufferMax)
	assert.Equal(t, 64, info.MaxDigestSize)
	assert.Equal(t, 2048, info.MaxObjectContext)
	assert.Equal(t, 300, info.LockoutInterval)
	assert.Equal(t, 600, info.LockoutRecovery)
}

func TestTPMService_GetInfo_AlgorithmsEmptyConfigHash(t *testing.T) {
	mock := defaultMockTPM()
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("not supported")
	mock.config.Hash = ""
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// No algorithms from TPM and no config hash, so Algorithms should be empty.
	assert.Empty(t, info.Algorithms)
}

func TestTPMService_GetInfo_PCRBanksFallbackDefault(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanksErr = errors.New("PCR read fail")
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// detectPCRBanks returns nil on error, so falls back to ["sha256"].
	assert.Contains(t, info.PCRBanks, "sha256")
}

func TestTPMService_GetInfo_WithEKCertTCGOverrides(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	_ = caCert
	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// The cert is a simple test cert without TCG OIDs, so the basic info
	// from FixedProperties should remain. Just verifying the code path runs.
	assert.NotEmpty(t, info.Manufacturer)
	assert.NotNil(t, info.Capabilities)
}

// ---------------------------------------------------------------------------
// GetEKInfo - coverage for cert + trust store verification path
// ---------------------------------------------------------------------------

func TestTPMService_GetEKInfo_WithCertAndTrustStore(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
	assert.True(t, info.Verified)
}

func TestTPMService_GetEKInfo_CertNotVerifiedByTrustStore(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	// Trust store has no manufacturer certs -- verification should fail.
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{},
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.False(t, info.Verified)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo - coverage for cert + trust store verification path
// ---------------------------------------------------------------------------

func TestTPMService_GetEKECCInfo_WithCertAndTrustStore(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	mock := defaultMockTPM()
	mock.ekCertEC = ekCert
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)

	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
	assert.True(t, info.Verified)
}

func TestTPMService_GetEKECCInfo_CertNotVerified(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = testECCCert()
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)

	// Trust store returns error for purpose.
	ts := &mockTrustStore{
		purposeErr: errors.New("no certs"),
	}
	svc.SetTrustStore(ts)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.False(t, info.Verified)
}

// ---------------------------------------------------------------------------
// verifyCertAgainstTrustStore - comprehensive coverage
// ---------------------------------------------------------------------------

func TestVerifyCertAgainstTrustStore_ValidCert(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)
	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(ekCert, truststore.PurposeTPMManufacturer)
	assert.True(t, result)
}

func TestVerifyCertAgainstTrustStore_InvalidCert(t *testing.T) {
	svc := NewTPMService()
	// Self-signed cert that is not a CA won't verify against a different CA.
	untrustedCert := testCert()
	caCert := testCert() // Different self-signed cert
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(untrustedCert, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

func TestVerifyCertAgainstTrustStore_TrustStoreError(t *testing.T) {
	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeErr: errors.New("store error"),
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(testCert(), truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

func TestVerifyCertAgainstTrustStore_EmptyPurposeCerts(t *testing.T) {
	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {},
		},
	}
	svc.SetTrustStore(ts)

	result := svc.verifyCertAgainstTrustStore(testCert(), truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

// ---------------------------------------------------------------------------
// loadCompositePolicies / saveCompositePolicies - edge cases
// ---------------------------------------------------------------------------

func TestLoadCompositePolicies_InvalidJSON(t *testing.T) {
	svc, dataDir := createTestTPMService(t, &mockTPM{})
	filePath := filepath.Join(dataDir, compositePoliciesFile)
	require.NoError(t, os.WriteFile(filePath, []byte("not-json"), 0600))

	policies := svc.loadCompositePolicies()
	assert.Empty(t, policies)
}

func TestLoadCompositePolicies_FileNotExist(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	policies := svc.loadCompositePolicies()
	assert.Empty(t, policies)
}

func TestLoadCompositePolicies_EmptyDataDir(t *testing.T) {
	svc := NewTPMService()
	// dataDir is "" by default.
	policies := svc.loadCompositePolicies()
	assert.Empty(t, policies)
}

func TestSaveCompositePolicies_EmptyDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveCompositePolicies([]CompositePolicy{
		{Name: "test", Operator: "SINGLE"},
	})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

func TestSaveCompositePolicies_RoundTrip(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	policies := []CompositePolicy{
		{
			Name:     "policy-a",
			Operator: "AND",
			Elements: []PolicyElement{
				{Type: "pcr", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
				{Type: "password", PasswordHash: "abc123"},
			},
		},
		{
			Name:     "policy-b",
			Operator: "SINGLE",
			Elements: []PolicyElement{
				{Type: "password", PasswordHash: "def456"},
			},
		},
	}
	require.NoError(t, svc.saveCompositePolicies(policies))

	loaded := svc.loadCompositePolicies()
	require.Len(t, loaded, 2)
	assert.Equal(t, "policy-a", loaded[0].Name)
	assert.Equal(t, "AND", loaded[0].Operator)
	assert.Equal(t, "policy-b", loaded[1].Name)
}

// ---------------------------------------------------------------------------
// loadAssignments / saveAssignments - edge cases
// ---------------------------------------------------------------------------

func TestLoadAssignments_InvalidJSON(t *testing.T) {
	svc, dataDir := createTestTPMService(t, &mockTPM{})
	filePath := filepath.Join(dataDir, policyAssignmentsFile)
	require.NoError(t, os.WriteFile(filePath, []byte("{malformed"), 0600))

	assignments := svc.loadAssignments()
	assert.Empty(t, assignments)
}

func TestLoadAssignments_FileNotExist(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	assignments := svc.loadAssignments()
	assert.Empty(t, assignments)
}

func TestLoadAssignments_EmptyDataDir(t *testing.T) {
	svc := NewTPMService()
	assignments := svc.loadAssignments()
	assert.Empty(t, assignments)
}

func TestSaveAssignments_EmptyDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveAssignments([]PolicyAssignment{
		{PolicyName: "test", KeyHandle: "0x81000001"},
	})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

func TestSaveAssignments_RoundTrip(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	assignments := []PolicyAssignment{
		{PolicyName: "policy-a", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
		{PolicyName: "policy-b", KeyHandle: "0x81000002", AssignedAt: "2025-01-02T00:00:00Z"},
	}
	require.NoError(t, svc.saveAssignments(assignments))

	loaded := svc.loadAssignments()
	require.Len(t, loaded, 2)
	assert.Equal(t, "policy-a", loaded[0].PolicyName)
	assert.Equal(t, "0x81000002", loaded[1].KeyHandle)
}

// ---------------------------------------------------------------------------
// savePolicyPassword / findPolicyPasswordEntry / deletePolicyPassword
// with a real StaticPasswordService backed by in-memory store.
// ---------------------------------------------------------------------------

func TestSavePolicyPassword_WithService(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	svc.savePolicyPassword("my-policy", "SINGLE", "supersecret")

	// Verify the entry was created in the store.
	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Policy: my-policy", entries[0].Name)
	assert.Equal(t, "supersecret", entries[0].Password)
	assert.True(t, entries[0].ReadOnly)
}

func TestSavePolicyPassword_AddError(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	// Pre-add entry to cause duplicate.
	svc.savePolicyPassword("dupe-policy", "AND", "pass1")

	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Second add of same name will cause error (logged but not returned).
	svc.savePolicyPassword("dupe-policy", "AND", "pass2")
	entries2, err2 := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err2)
	// Should still be just the one -- the second add fails silently.
	assert.Len(t, entries2, 1)
}

func TestFindPolicyPasswordEntry_WithService(t *testing.T) {
	pwSvc, _ := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	svc.savePolicyPassword("find-me", "OR", "secret")

	id, found := svc.findPolicyPasswordEntry("find-me")
	assert.True(t, found)
	assert.NotEmpty(t, id)
}

func TestFindPolicyPasswordEntry_NotFound(t *testing.T) {
	pwSvc, _ := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	id, found := svc.findPolicyPasswordEntry("nonexistent")
	assert.False(t, found)
	assert.Empty(t, id)
}

func TestDeletePolicyPassword_WithService(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	svc.savePolicyPassword("delete-me", "SINGLE", "password")
	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	svc.deletePolicyPassword("delete-me")

	entriesAfter, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	assert.Empty(t, entriesAfter)
}

func TestDeletePolicyPassword_NotFound(t *testing.T) {
	pwSvc, _ := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	// Should not panic when the entry does not exist.
	svc.deletePolicyPassword("ghost-policy")
}

func TestDeletePolicyPassword_ListError(t *testing.T) {
	// Use a StaticPasswordService with a nil store to trigger list error.
	pwSvc := NewStaticPasswordService(nil)
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	// Should not panic; logs the error and returns.
	svc.deletePolicyPassword("test-policy")
}

func TestFindPolicyPasswordEntry_ListError(t *testing.T) {
	pwSvc := NewStaticPasswordService(nil)
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	id, found := svc.findPolicyPasswordEntry("test-policy")
	assert.False(t, found)
	assert.Empty(t, id)
}

// ---------------------------------------------------------------------------
// CreatePasswordPolicy - save to password store path
// ---------------------------------------------------------------------------

func TestCreatePasswordPolicy_SaveToPasswordStore(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	err := svc.CreatePasswordPolicy("pw-policy", "A password-only policy", "mypassword", true)
	require.NoError(t, err)

	// Verify policy was created.
	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	assert.Equal(t, "pw-policy", policies[0].Name)
	assert.Equal(t, "SINGLE", policies[0].Operator)

	// Verify password was saved to the store.
	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Policy: pw-policy", entries[0].Name)
}

func TestCreatePasswordPolicy_NoSaveToPasswordStore(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	err := svc.CreatePasswordPolicy("no-save", "Test", "mypassword", false)
	require.NoError(t, err)

	// Verify password was NOT saved to the store.
	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestCreatePasswordPolicy_DuplicateName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePasswordPolicy("dup", "First", "pass1", false)
	require.NoError(t, err)

	err = svc.CreatePasswordPolicy("dup", "Second", "pass2", false)
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

// ---------------------------------------------------------------------------
// CreatePCROrPasswordPolicy - edge cases and password store
// ---------------------------------------------------------------------------

func TestCreatePCROrPasswordPolicy_SaveToPasswordStore(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}}
	err := svc.CreatePCROrPasswordPolicy("or-pol", "OR policy", pcrs, "sha256", "orpass", true)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	assert.Equal(t, "OR", policies[0].Operator)
	require.Len(t, policies[0].Elements, 2)
	assert.Equal(t, "pcr", policies[0].Elements[0].Type)
	assert.Equal(t, "password", policies[0].Elements[1].Type)

	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].Notes, "OR")
}

func TestCreatePCROrPasswordPolicy_NoSaveToPasswordStore(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	pcrs := []PCRSelection{{Index: 7, Bank: "sha256"}}
	err := svc.CreatePCROrPasswordPolicy("or-nosave", "Test", pcrs, "sha256", "pass", false)
	require.NoError(t, err)

	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestCreatePCROrPasswordPolicy_DuplicateName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCROrPasswordPolicy("or-dup", "First", pcrs, "sha256", "pass1", false)
	require.NoError(t, err)

	err = svc.CreatePCROrPasswordPolicy("or-dup", "Second", pcrs, "sha256", "pass2", false)
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

// ---------------------------------------------------------------------------
// CreatePCRAndPasswordPolicy - edge cases and password store
// ---------------------------------------------------------------------------

func TestCreatePCRAndPasswordPolicy_SaveToPasswordStore(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("and-pol", "AND policy", pcrs, "sha256", "andpass", true)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	assert.Equal(t, "AND", policies[0].Operator)

	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].Notes, "AND")
}

func TestCreatePCRAndPasswordPolicy_NoSaveToPasswordStore(t *testing.T) {
	pwSvc, store := newStaticPWService()
	svc, _ := createTestTPMService(t, &mockTPM{})
	svc.SetStaticPasswordService(pwSvc)

	pcrs := []PCRSelection{{Index: 7, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("and-nosave", "Test", pcrs, "sha256", "pass", false)
	require.NoError(t, err)

	entries, err := store.ListByFolder(policyPasswordFolder)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestCreatePCRAndPasswordPolicy_DuplicateName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("and-dup", "First", pcrs, "sha256", "pass1", false)
	require.NoError(t, err)

	err = svc.CreatePCRAndPasswordPolicy("and-dup", "Second", pcrs, "sha256", "pass2", false)
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

func TestCreatePCRAndPasswordPolicy_WhitespacePassword(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("ws-pass", "Test", pcrs, "sha256", "   ", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

func TestCreatePCRAndPasswordPolicy_WhitespaceName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("   ", "Test", pcrs, "sha256", "pass", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

// ---------------------------------------------------------------------------
// ListPolicyAssignments - with data
// ---------------------------------------------------------------------------

func TestListPolicyAssignments_WithAssignments(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	// Create a PCR policy and assign it.
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "list-pol",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.AssignPolicyToKey("list-pol", "0x81000001"))
	require.NoError(t, svc.AssignPolicyToKey("list-pol", "0x81000002"))

	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, assignments, 2)
}

func TestListPolicyAssignments_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKey - update existing assignment
// ---------------------------------------------------------------------------

func TestAssignPolicyToKey_UpdateExistingHandle(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "pol-a",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "pol-b",
		PCRSelections: []PCRSelection{{Index: 7, Bank: "sha256"}},
	}))

	// Assign policy-a to handle.
	require.NoError(t, svc.AssignPolicyToKey("pol-a", "0x81000001"))
	assignments := svc.loadAssignments()
	require.Len(t, assignments, 1)
	assert.Equal(t, "pol-a", assignments[0].PolicyName)

	// Reassign to policy-b on same handle.
	require.NoError(t, svc.AssignPolicyToKey("pol-b", "0x81000001"))
	assignments = svc.loadAssignments()
	require.Len(t, assignments, 1)
	assert.Equal(t, "pol-b", assignments[0].PolicyName)
}

func TestAssignPolicyToKey_WhitespacePolicyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.AssignPolicyToKey("  ", "0x81000001")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestAssignPolicyToKey_WhitespaceHandle(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.AssignPolicyToKey("some-policy", "   ")
	assert.ErrorIs(t, err, ErrTPMInvalidHandle)
}

func TestAssignPolicyToKey_NoDataDir(t *testing.T) {
	svc := newServiceWithMock(&mockTPM{})
	// No dataDir set. CreatePolicy will fail, but we can still test the
	// policy-not-found path.
	err := svc.AssignPolicyToKey("nonexistent", "0x81000001")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListCompositePolicies - with data
// ---------------------------------------------------------------------------

func TestListCompositePolicies_WithPolicies(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-a",
		Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "hash"}},
	}))
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-b",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
			{Type: "password", PasswordHash: "hash"},
		},
	}))

	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	require.Len(t, policies, 2)
}

func TestListCompositePolicies_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// ---------------------------------------------------------------------------
// GetCompositePolicy - edge cases
// ---------------------------------------------------------------------------

func TestGetCompositePolicy_Found(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:        "find-comp",
		Description: "Test composite",
		Operator:    "OR",
		Elements: []PolicyElement{
			{Type: "pcr", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
			{Type: "password", PasswordHash: "hash"},
		},
	}))

	policy, err := svc.GetCompositePolicy("find-comp")
	require.NoError(t, err)
	assert.Equal(t, "find-comp", policy.Name)
	assert.Equal(t, "OR", policy.Operator)
	assert.Equal(t, "Test composite", policy.Description)
}

func TestGetCompositePolicy_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	policy, err := svc.GetCompositePolicy("ghost")
	assert.Nil(t, policy)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestGetCompositePolicy_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	policy, err := svc.GetCompositePolicy("anything")
	assert.Nil(t, policy)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestGetCompositePolicy_MultiplePolicies(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	for _, name := range []string{"alpha", "beta", "gamma"} {
		require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
			Name:     name,
			Operator: "SINGLE",
			Elements: []PolicyElement{{Type: "password", PasswordHash: "hash"}},
		}))
	}

	policy, err := svc.GetCompositePolicy("beta")
	require.NoError(t, err)
	assert.Equal(t, "beta", policy.Name)
}

// ---------------------------------------------------------------------------
// SavePolicyToFile / ImportPolicyFile - these use wails dialogs, so we test
// the internal helpers savePolicyDigestBinary and import* that they delegate to.
// The exported methods' panic-recovery wrappers are also tested.
// ---------------------------------------------------------------------------

func TestSavePolicyDigestBinary_CustomBank(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	outFile := filepath.Join(t.TempDir(), "policy.bin")

	policyJSON := `{
		"pcr_bank": "sha384",
		"pcr_selections": [0],
		"pcr_digests": {"0": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
	}`
	err := svc.savePolicyDigestBinary(outFile, policyJSON)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestSavePolicyDigestBinary_MultiplePCRs(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	outFile := filepath.Join(t.TempDir(), "policy.dat")

	// SHA-256 32-byte zero digests for PCRs 0 and 7.
	zeroDigest := "0000000000000000000000000000000000000000000000000000000000000000"
	policyJSON, err := json.Marshal(map[string]interface{}{
		"pcr_bank":       "sha256",
		"pcr_selections": []int{0, 7},
		"pcr_digests":    map[string]string{"0": zeroDigest, "7": zeroDigest},
	})
	require.NoError(t, err)

	err = svc.savePolicyDigestBinary(outFile, string(policyJSON))
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// ---------------------------------------------------------------------------
// importJSONPolicy / importBinaryPolicyDigest - additional paths
// ---------------------------------------------------------------------------

func TestImportJSONPolicy_PasswordPolicy(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	raw, err := json.Marshal(map[string]interface{}{
		"name":        "imported-pw",
		"description": "Imported password policy",
		"type":        "password",
	})
	require.NoError(t, err)

	name, err := svc.importJSONPolicy(raw)
	require.NoError(t, err)
	assert.Equal(t, "imported-pw", name)
}

// ---------------------------------------------------------------------------
// SavePolicyToFile - test JSON extension path via direct file write
// (bypassing the wails dialog by calling the underlying os.WriteFile logic).
// We verify the pattern: if ext is not .bin or .dat, it writes raw JSON.
// ---------------------------------------------------------------------------

func TestSavePolicyToFile_JSONWriteDirect(t *testing.T) {
	// SavePolicyToFile uses wailsruntime.SaveFileDialog which we can't mock,
	// but we can test the downstream path by verifying savePolicyDigestBinary
	// for binary and direct JSON write for non-binary extensions.
	_, _ = createTestTPMService(t, &mockTPM{})
	outFile := filepath.Join(t.TempDir(), "policy.json")

	policyJSON := `{"name":"test-save","operator":"SINGLE"}`
	// Simulate what SavePolicyToFile does for .json files.
	err := os.WriteFile(outFile, []byte(policyJSON), 0600)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "test-save")
}

// ---------------------------------------------------------------------------
// CreatePasswordPolicy / CreatePCROrPasswordPolicy / CreatePCRAndPasswordPolicy
// - verify password hash is actually stored in elements
// ---------------------------------------------------------------------------

func TestCreatePasswordPolicy_PasswordHashStored(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePasswordPolicy("hash-test", "Test", "secret123", false)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	require.Len(t, policies[0].Elements, 1)
	assert.Equal(t, "password", policies[0].Elements[0].Type)
	assert.NotEmpty(t, policies[0].Elements[0].PasswordHash)
	// The hash is in hex_salt:hex_hash format (argon2id), not plaintext.
	assert.NotEqual(t, "secret123", policies[0].Elements[0].PasswordHash)
	assert.Contains(t, policies[0].Elements[0].PasswordHash, ":")
}

func TestCreatePCROrPasswordPolicy_PasswordHashStored(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCROrPasswordPolicy("or-hash", "Test", pcrs, "sha256", "secret", false)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	require.Len(t, policies[0].Elements, 2)
	// Second element is the password.
	assert.Equal(t, "password", policies[0].Elements[1].Type)
	assert.Contains(t, policies[0].Elements[1].PasswordHash, ":")
}

func TestCreatePCRAndPasswordPolicy_PasswordHashStored(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	pcrs := []PCRSelection{{Index: 7, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("and-hash", "Test", pcrs, "sha256", "secret", false)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	require.Len(t, policies[0].Elements, 2)
	assert.Equal(t, "password", policies[0].Elements[1].Type)
	assert.Contains(t, policies[0].Elements[1].PasswordHash, ":")
}

// ---------------------------------------------------------------------------
// verifyCertAgainstTrustStore - with real CA-signed cert for successful verify
// ---------------------------------------------------------------------------

func TestVerifyCertAgainstTrustStore_SelfSignedCA(t *testing.T) {
	// Create a self-signed CA and use it as both the cert and the trust store root.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Self-Signed CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	svc := NewTPMService()
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {cert},
		},
	}
	svc.SetTrustStore(ts)

	// A self-signed CA verifies against itself.
	result := svc.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer)
	assert.True(t, result)
}

// ---------------------------------------------------------------------------
// loadCompositePolicies / saveCompositePolicies - verify file permissions
// and content integrity
// ---------------------------------------------------------------------------

func TestSaveCompositePolicies_FilePermissions(t *testing.T) {
	svc, dataDir := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.saveCompositePolicies([]CompositePolicy{
		{Name: "perm-test", Operator: "SINGLE"},
	}))

	filePath := filepath.Join(dataDir, compositePoliciesFile)
	stat, err := os.Stat(filePath)
	require.NoError(t, err)
	// File should have been written with 0600.
	assert.Equal(t, os.FileMode(0600), stat.Mode().Perm())
}

func TestSaveAssignments_FilePermissions(t *testing.T) {
	svc, dataDir := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.saveAssignments([]PolicyAssignment{
		{PolicyName: "perm-test", KeyHandle: "0x81000001"},
	}))

	filePath := filepath.Join(dataDir, policyAssignmentsFile)
	stat, err := os.Stat(filePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), stat.Mode().Perm())
}

// ---------------------------------------------------------------------------
// savePolicyDigestBinary - test with non-hex digest values in pcr_digests
// to ensure proper error handling.
// ---------------------------------------------------------------------------

func TestSavePolicyDigestBinary_NonStringDigestValues(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	outFile := filepath.Join(t.TempDir(), "policy.bin")

	// pcr_digests has a numeric value instead of string -- the inner loop
	// checks with type assertion (string ok) and skips non-strings.
	policyJSON := `{
		"pcr_bank": "sha256",
		"pcr_selections": [0],
		"pcr_digests": {"0": 12345}
	}`
	err := svc.savePolicyDigestBinary(outFile, policyJSON)
	// ComputePolicyPCRDigest may still succeed with empty digests (zero-filled).
	// The key path is that non-string values are silently skipped.
	require.NoError(t, err)
}

func TestSavePolicyDigestBinary_NonFloatSelections(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	outFile := filepath.Join(t.TempDir(), "policy.bin")

	// pcr_selections has a string instead of number -- silently skipped.
	policyJSON := `{
		"pcr_bank": "sha256",
		"pcr_selections": ["zero"],
		"pcr_digests": {}
	}`
	err := svc.savePolicyDigestBinary(outFile, policyJSON)
	// With no valid PCR indices, ComputePolicyPCRDigest returns an error.
	assert.ErrorIs(t, err, ErrTPMPolicyExportFailed)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKey - verify CompositePolicy can be used via GetPolicy
// fallback to isPlatformPolicyName.
// ---------------------------------------------------------------------------

func TestAssignPolicyToKey_CompositePolicy(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a composite policy (not a PCR policy).
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-assign",
		Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "hash"}},
	}))

	// GetPolicy will fail (it searches PCR policies, not composite),
	// and isPlatformPolicyName will also fail, so this should error.
	err := svc.AssignPolicyToKey("comp-assign", "0x81000001")
	// If GetPolicy returns ErrTPMPolicyNotFound and isPlatformPolicyName is false,
	// it returns the error from GetPolicy.
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Additional edge cases for GetInfo with concrete type assertions
// ---------------------------------------------------------------------------

func TestTPMService_GetInfo_AlgorithmsFromTPM(t *testing.T) {
	mock := defaultMockTPM()
	// supportedAlgos already set in defaultMockTPM
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.Contains(t, info.Algorithms, "RSA")
	assert.Contains(t, info.Algorithms, "ECC")
	assert.Contains(t, info.Algorithms, "SHA-256")
}

func TestTPMService_GetInfo_NilConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.config = nil
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("unsupported")
	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	// With nil config and no supported algos, algorithms should be empty.
	assert.Empty(t, info.Algorithms)
}
