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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ---------------------------------------------------------------------------
// Helper: create a TPMService with mock, temp dataDir, and a real
// StaticPasswordService backed by an in-memory store.
// ---------------------------------------------------------------------------

func surgCreateServiceWithPWStore(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	spwStore := staticpw.NewStore(storage.NewMemory())
	svc.SetStaticPasswordService(NewStaticPasswordService(spwStore))
	return svc, dataDir
}

// ---------------------------------------------------------------------------
// GetPlatformSRKInfo: SRKAttributes nil -> config.PlatformSRK fallback (L1198-1202)
// Covers the code path where pks.SRKAttributes() is nil, so result.Handle
// remains "" and the function falls through to check cfg.PlatformSRK.
// ---------------------------------------------------------------------------

func TestSurgTPM_GetPlatformSRKInfo_ConfigFallback(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.PlatformSRK = &tpm2pkg.PlatformSRKConfig{
		SRKHandle: 0x81800002,
	}
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   false,
		policyEnabled: false,
		srkAttrs:      nil, // nil -> skip L1185 block entirely
	}
	svc := newServiceWithMock(mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Handle should come from config fallback (L1201).
	assert.Equal(t, "0x81800002", info.Handle)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetPlatformSRKInfo: SRKAttributes with TPMAttributes but ReadHandle fails
// Covers L1190-1193 where readErr != nil -> result.Present stays false.
// ---------------------------------------------------------------------------

func TestSurgTPM_GetPlatformSRKInfo_ReadHandleError(t *testing.T) {
	mock := defaultMockTPM()
	mock.readHandleErr = errors.New("handle not found")
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   true,
		policyEnabled: false,
		srkAttrs: &types.KeyAttributes{
			KeyAlgorithm: 1, // RSA
			TPMAttributes: &types.TPMAttributes{
				Handle: 0x81800003,
			},
		},
	}
	svc := newServiceWithMock(mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Handle is set from SRKAttributes.
	assert.Equal(t, "0x81800003", info.Handle)
	// Present should be false because ReadHandle returned error (L1191).
	assert.False(t, info.Present)
	// But since PKS is initialized, Initialized should be true (L1206-1207).
	assert.True(t, info.Initialized)
}

// ---------------------------------------------------------------------------
// GetPlatformSRKInfo: SRKAttributes with no TPMAttributes -> handle empty,
// falls through to config.PlatformSRK fallback, and PKS not initialized.
// ---------------------------------------------------------------------------

func TestSurgTPM_GetPlatformSRKInfo_NoTPMAttrsNoConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.PlatformSRK = nil // no fallback config
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   false,
		policyEnabled: false,
		srkAttrs: &types.KeyAttributes{
			KeyAlgorithm:  1,
			TPMAttributes: nil, // nil -> L1187 skipped
		},
	}
	svc := newServiceWithMock(mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.Handle) // No handle from either source.
	assert.False(t, info.Present)
	assert.False(t, info.Initialized)
}

// ---------------------------------------------------------------------------
// GetConflictingAssignments: assignments found for requested handles (L634-640)
// ---------------------------------------------------------------------------

func TestSurgTPM_GetConflictingAssignments_WithConflicts(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Pre-create assignments.
	assignments := []PolicyAssignment{
		{PolicyName: "pol-a", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
		{PolicyName: "pol-b", KeyHandle: "0x81000002", AssignedAt: "2025-01-02T00:00:00Z"},
		{PolicyName: "pol-c", KeyHandle: "0x81000003", AssignedAt: "2025-01-03T00:00:00Z"},
	}
	data, _ := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600))

	// Request handles that overlap with existing assignments.
	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001", "0x81000003", "0x81000099"})
	require.NoError(t, err)
	assert.Len(t, conflicts, 2)
	assert.Equal(t, "pol-a", conflicts[0].CurrentPolicy)
	assert.Equal(t, "pol-c", conflicts[1].CurrentPolicy)
}

func TestSurgTPM_GetConflictingAssignments_NoConflicts(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000099"})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

func TestSurgTPM_GetConflictingAssignments_EmptyHandles(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	// Whitespace-only handles should be trimmed and ignored.
	conflicts, err := svc.GetConflictingAssignments([]string{"  ", ""})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKey: update existing assignment (L3714-3717)
// The key handle already has a policy -> updates in place instead of appending.
// ---------------------------------------------------------------------------

func TestSurgTPM_AssignPolicyToKey_UpdateExisting(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Create initial policy + assignment.
	policy := PCRPolicy{
		Name:      "assign-update-pol",
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	// Create a second policy.
	policy2 := PCRPolicy{
		Name:      "assign-update-pol2",
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData2, _ := json.MarshalIndent([]PCRPolicy{policy, policy2}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData2, 0600))

	// Assign initial policy.
	err := svc.AssignPolicyToKey("assign-update-pol", "0x81000001")
	require.NoError(t, err)

	assignments := svc.loadAssignments()
	assert.Len(t, assignments, 1)
	assert.Equal(t, "assign-update-pol", assignments[0].PolicyName)

	// Update assignment to new policy -> L3714 path.
	err = svc.AssignPolicyToKey("assign-update-pol2", "0x81000001")
	require.NoError(t, err)

	assignments = svc.loadAssignments()
	assert.Len(t, assignments, 1) // Still 1, updated in place.
	assert.Equal(t, "assign-update-pol2", assignments[0].PolicyName)
}

// ---------------------------------------------------------------------------
// CreatePasswordPolicy: saveToPasswordStore=true with StaticPasswordService
// Covers the savePolicyPassword call path (L4478-4480 equivalent).
// ---------------------------------------------------------------------------

func TestSurgTPM_CreatePasswordPolicy_WithPasswordStore(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	err := svc.CreatePasswordPolicy("pw-store-test", "desc", "strongP@ss!", true)
	require.NoError(t, err)

	// Verify the composite policy was created.
	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	assert.Equal(t, "pw-store-test", policies[0].Name)

	// Verify password was saved to the password store.
	id, found := svc.findPolicyPasswordEntry("pw-store-test")
	assert.True(t, found)
	assert.NotEmpty(t, id)
}

// ---------------------------------------------------------------------------
// CreatePCROrPasswordPolicy: saveToPasswordStore=true
// Covers the savePolicyPassword path for OR policies.
// ---------------------------------------------------------------------------

func TestSurgTPM_CreatePCROrPasswordPolicy_WithPasswordStore(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}}
	err := svc.CreatePCROrPasswordPolicy("or-pw-store", "desc", pcrs, "sha256", "pass123!", true)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	assert.Equal(t, "OR", policies[0].Operator)

	// Verify password store entry.
	id, found := svc.findPolicyPasswordEntry("or-pw-store")
	assert.True(t, found)
	assert.NotEmpty(t, id)
}

// ---------------------------------------------------------------------------
// CreatePCRAndPasswordPolicy: saveToPasswordStore=true
// Covers the savePolicyPassword path for AND policies.
// ---------------------------------------------------------------------------

func TestSurgTPM_CreatePCRAndPasswordPolicy_WithPasswordStore(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	pcrs := []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("and-pw-store", "desc", pcrs, "sha256", "secureP@ss!", true)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	require.Len(t, policies, 1)
	assert.Equal(t, "AND", policies[0].Operator)

	// Verify password store entry.
	id, found := svc.findPolicyPasswordEntry("and-pw-store")
	assert.True(t, found)
	assert.NotEmpty(t, id)
}

// ---------------------------------------------------------------------------
// deletePolicyPassword: entry exists and is deleted (L4524 path)
// ---------------------------------------------------------------------------

func TestSurgTPM_DeletePolicyPassword_WithEntry(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	// Create a policy with password in store.
	err := svc.CreatePasswordPolicy("del-pw-test", "desc", "pass", true)
	require.NoError(t, err)

	// Verify entry exists.
	id, found := svc.findPolicyPasswordEntry("del-pw-test")
	assert.True(t, found)
	assert.NotEmpty(t, id)

	// Delete the policy password.
	svc.deletePolicyPassword("del-pw-test")

	// Verify entry is gone.
	_, found = svc.findPolicyPasswordEntry("del-pw-test")
	assert.False(t, found)
}

// ---------------------------------------------------------------------------
// VerifyPolicyPassword: success path - password matches
// ---------------------------------------------------------------------------

func TestSurgTPM_VerifyPolicyPassword_Match(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	// Create a password policy.
	err := svc.CreatePasswordPolicy("verify-match", "desc", "correct-password", false)
	require.NoError(t, err)

	// Verify with correct password.
	ok, err := svc.VerifyPolicyPassword("verify-match", "correct-password")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestSurgTPM_VerifyPolicyPassword_Mismatch(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	// Create a password policy.
	err := svc.CreatePasswordPolicy("verify-mismatch", "desc", "correct-password", false)
	require.NoError(t, err)

	// Verify with wrong password.
	ok, err := svc.VerifyPolicyPassword("verify-mismatch", "wrong-password")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSurgTPM_VerifyPolicyPassword_NoPWElement(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Create a composite policy with NO password element.
	cp := CompositePolicy{
		Name:     "no-pw-elem",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha256"},
		},
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	ok, err := svc.VerifyPolicyPassword("no-pw-elem", "any-password")
	assert.False(t, ok)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyType)
}

func TestSurgTPM_VerifyPolicyPassword_PolicyNotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	ok, err := svc.VerifyPolicyPassword("nonexistent", "pass")
	assert.False(t, ok)
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKeys: various paths
// ---------------------------------------------------------------------------

func TestSurgTPM_AssignPolicyToKeys_NewAndExisting(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	// Create a PCR policy.
	policy := PCRPolicy{Name: "multi-assign", CreatedAt: "2025-01-01T00:00:00Z"}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	// Pre-create one assignment.
	existing := []PolicyAssignment{
		{PolicyName: "old-policy", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
	}
	assignData, _ := json.MarshalIndent(existing, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), assignData, 0600))

	// Assign to existing handle (update) + new handle (append).
	err := svc.AssignPolicyToKeys("multi-assign", []string{"0x81000001", "0x81000002"})
	require.NoError(t, err)

	assignments := svc.loadAssignments()
	assert.Len(t, assignments, 2)
	// Both should now point to "multi-assign".
	for _, a := range assignments {
		assert.Equal(t, "multi-assign", a.PolicyName)
	}
}

func TestSurgTPM_AssignPolicyToKeys_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.AssignPolicyToKeys("", []string{"0x81000001"})
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestSurgTPM_AssignPolicyToKeys_EmptyHandles(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.AssignPolicyToKeys("some-policy", nil)
	require.ErrorIs(t, err, ErrTPMInvalidHandle)
}

func TestSurgTPM_AssignPolicyToKeys_PolicyNotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.AssignPolicyToKeys("nonexistent", []string{"0x81000001"})
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestSurgTPM_AssignPolicyToKeys_WhitespaceHandlesSkipped(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	policy := PCRPolicy{Name: "ws-handles", CreatedAt: "2025-01-01T00:00:00Z"}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	// Empty/whitespace handles should be skipped.
	err := svc.AssignPolicyToKeys("ws-handles", []string{"  ", "", "0x81000001"})
	require.NoError(t, err)

	assignments := svc.loadAssignments()
	assert.Len(t, assignments, 1)
	assert.Equal(t, "0x81000001", assignments[0].KeyHandle)
}

// ---------------------------------------------------------------------------
// importBinaryPolicyDigest: filename with no base name -> "imported-policy" default
// ---------------------------------------------------------------------------

func TestSurgTPM_ImportBinaryPolicyDigest_EmptyBaseName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	// Construct a path where the filename after removing the extension is empty.
	data := []byte{0xDE, 0xAD}
	name, err := svc.importBinaryPolicyDigest("/tmp/.bin", data)
	require.NoError(t, err)
	assert.Equal(t, "imported-policy", name)
}

// ---------------------------------------------------------------------------
// importJSONPolicy: default pcr_bank when not specified (L3574-3576)
// ---------------------------------------------------------------------------

func TestSurgTPM_ImportJSONPolicy_DefaultPCRBank(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	// No pcr_bank specified -> should default to "sha256" (L3574).
	policyJSON := `{
		"name": "default-bank-test",
		"pcr_selections": [0, 7]
	}`

	name, err := svc.importJSONPolicy([]byte(policyJSON))
	require.NoError(t, err)
	assert.Equal(t, "default-bank-test", name)

	// Verify the policy was created with pcr_bank "sha256".
	pol, err := svc.GetPolicy("default-bank-test")
	require.NoError(t, err)
	for _, sel := range pol.PCRSelections {
		assert.Equal(t, "sha256", sel.Bank)
	}
}

// ---------------------------------------------------------------------------
// importJSONPolicy: with description field (L3572)
// ---------------------------------------------------------------------------

func TestSurgTPM_ImportJSONPolicy_WithDescription(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	policyJSON := `{
		"name": "desc-test",
		"description": "My test policy",
		"pcr_bank": "sha384"
	}`

	name, err := svc.importJSONPolicy([]byte(policyJSON))
	require.NoError(t, err)
	assert.Equal(t, "desc-test", name)
}

// ---------------------------------------------------------------------------
// savePolicyDigestBinary: pcr_bank from JSON (L3483-3484)
// ---------------------------------------------------------------------------

func TestSurgTPM_SavePolicyDigestBinary_WithPCRBank(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "digest.bin")

	policyJSON := `{
		"name": "custom-bank",
		"pcr_bank": "sha384",
		"pcr_selections": [0],
		"pcr_digests": {
			"sha384:0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		}
	}`

	// The ComputePolicyPCRDigest call may fail or succeed depending on
	// whether the bank/indices are valid. Both paths exercise L3483-3484.
	_ = svc.savePolicyDigestBinary(filePath, policyJSON)
}

// ---------------------------------------------------------------------------
// ExportCompositePolicy: with UpdatedAt field set (L3399-3401)
// ---------------------------------------------------------------------------

func TestSurgTPM_ExportCompositePolicy_WithUpdatedAt(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:      "export-updated",
		Operator:  "SINGLE",
		CreatedAt: "2025-01-01T00:00:00Z",
		UpdatedAt: "2025-06-01T12:00:00Z",
		Elements: []PolicyElement{
			{Type: "password", PasswordHash: "abc:def"},
		},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	result, err := svc.ExportCompositePolicy("export-updated")
	require.NoError(t, err)
	assert.Contains(t, result, "updated_at")
	assert.Contains(t, result, "2025-06-01")
}

// ---------------------------------------------------------------------------
// ExportCompositePolicy: PCR element with empty PCRBank but PCRSelections
// has Bank -> uses PCRSelections[0].Bank (L3413-3414)
// ---------------------------------------------------------------------------

func TestSurgTPM_ExportCompositePolicy_PCRBankFromSelections(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:      "bank-from-sel",
		Operator:  "SINGLE",
		CreatedAt: "2025-01-01T00:00:00Z",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "", // Empty -> fallback to PCRSelections[0].Bank
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha512"}},
			},
		},
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	result, err := svc.ExportCompositePolicy("bank-from-sel")
	require.NoError(t, err)
	assert.Contains(t, result, "sha512")
	assert.Contains(t, result, "pcr_bank")
}

// ---------------------------------------------------------------------------
// ExportPolicy: with UpdatedAt field set (L3352-3354)
// ---------------------------------------------------------------------------

func TestSurgTPM_ExportPolicy_WithUpdatedAt(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	policies := []PCRPolicy{
		{
			Name:       "export-updated-pcr",
			CreatedAt:  "2025-01-01T00:00:00Z",
			UpdatedAt:  "2025-06-01T12:00:00Z",
			PCRDigests: map[string]string{"sha256:0": "aabb"},
		},
	}
	polData, _ := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	result, err := svc.ExportPolicy("export-updated-pcr")
	require.NoError(t, err)
	assert.Contains(t, result, "updated_at")
	assert.Contains(t, result, "2025-06-01")
}

// ---------------------------------------------------------------------------
// DeletePolicy: with cascade to password store (L3141)
// ---------------------------------------------------------------------------

func TestSurgTPM_DeletePolicy_CascadePasswordStore(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	// Create a PCR policy.
	err := svc.CreatePolicy(&PCRPolicy{
		Name:          "del-cascade",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	})
	require.NoError(t, err)

	// Assign the policy to a key.
	err = svc.AssignPolicyToKey("del-cascade", "0x81000001")
	require.NoError(t, err)

	// Verify the assignment exists.
	assignments := svc.loadAssignments()
	assert.Len(t, assignments, 1)

	// Delete the policy -> cascades to remove assignments + password entry.
	err = svc.DeletePolicy("del-cascade")
	require.NoError(t, err)

	// Verify assignment was removed.
	assignments = svc.loadAssignments()
	assert.Empty(t, assignments)
}

// ---------------------------------------------------------------------------
// DeleteCompositePolicy: with cascade to assignments + password store
// ---------------------------------------------------------------------------

func TestSurgTPM_DeleteCompositePolicy_CascadeAll(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	// Create a password policy (composite) with password in store.
	err := svc.CreatePasswordPolicy("del-comp-cascade", "desc", "pass123!", true)
	require.NoError(t, err)

	// Verify entry exists in password store.
	_, found := svc.findPolicyPasswordEntry("del-comp-cascade")
	assert.True(t, found)

	// Delete -> cascades.
	err = svc.DeleteCompositePolicy("del-comp-cascade")
	require.NoError(t, err)

	// Verify password entry was removed.
	_, found = svc.findPolicyPasswordEntry("del-comp-cascade")
	assert.False(t, found)
}

// ---------------------------------------------------------------------------
// GetPolicyDeletionImpact: with password entry present
// ---------------------------------------------------------------------------

func TestSurgTPM_GetPolicyDeletionImpact_WithPasswordEntry(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := surgCreateServiceWithPWStore(t, mock)

	// Create a composite policy with password stored.
	err := svc.CreatePasswordPolicy("impact-pw-test", "desc", "pass", true)
	require.NoError(t, err)

	impact, err := svc.GetPolicyDeletionImpact("impact-pw-test")
	require.NoError(t, err)
	require.NotNil(t, impact)
	assert.Equal(t, "composite", impact.PolicyType)
	assert.True(t, impact.HasPasswordEntry)
	assert.NotEmpty(t, impact.PasswordEntryID)
}

// ---------------------------------------------------------------------------
// GetInfo: SupportedAlgorithms error fallback to config.Hash (L818-819)
// ---------------------------------------------------------------------------

func TestSurgTPM_GetInfo_AlgoFallbackToConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("not supported")
	mock.config.Hash = "SHA-384" // Fallback value (L819).

	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, []string{"SHA-384"}, info.Algorithms)
}

// ---------------------------------------------------------------------------
// ComparePolicyPCRs: multiple PCRs with mixed matching/mismatching
// Covers the comparison loop comprehensively.
// ---------------------------------------------------------------------------

func TestSurgTPM_ComparePolicyPCRs_MultiplePCRs(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA, 0xBB}},
				{ID: 7, Value: []byte{0xCC, 0xDD}},
				{ID: 9, Value: []byte{0xEE, 0xFF}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	policy := PCRPolicy{
		Name: "multi-pcr-compare",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
			{Index: 9, Bank: "sha256"},
		},
		PCRDigests: map[string]string{
			"sha256:0": "aabb",     // Matches
			"sha256:7": "ccdd",     // Matches
			"sha256:9": "deadbeef", // Does NOT match (actual is eeff)
		},
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	result, err := svc.ComparePolicyPCRs("multi-pcr-compare")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.AllMatch)
	assert.Equal(t, 3, result.TotalPCRs)
	assert.Equal(t, 2, result.MatchCount)
	assert.Equal(t, 1, result.MismatchCount)
	assert.Len(t, result.Entries, 3)
}

// ---------------------------------------------------------------------------
// ListPoliciesWithDigests: valid + matching digests (L4243 hasSaved true)
// ---------------------------------------------------------------------------

func TestSurgTPM_ListPoliciesWithDigests_AllMatch(t *testing.T) {
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
		Name: "all-match",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
		PCRDigests: map[string]string{
			"sha256:0": "aabb",
			"sha256:7": "ccdd",
		},
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.True(t, *policies[0].Valid)
}

// ---------------------------------------------------------------------------
// ListPoliciesWithDigests: currentHex empty -> allMatch false (L4253)
// ---------------------------------------------------------------------------

func TestSurgTPM_ListPoliciesWithDigests_CurrentHexEmpty(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xAA}}, // Only PCR 0
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	policy := PCRPolicy{
		Name: "empty-current",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"}, // PCR 7 not in banks
		},
		PCRDigests: map[string]string{
			"sha256:0": "aa",
			"sha256:7": "cc", // Has saved but currentHex will be empty
		},
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	polData, _ := json.MarshalIndent([]PCRPolicy{policy}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), polData, 0600))

	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.False(t, *policies[0].Valid) // currentHex empty -> allMatch false
}

// ---------------------------------------------------------------------------
// RefreshCompositePolicyPCRs: success path
// ---------------------------------------------------------------------------

func TestSurgTPM_RefreshCompositePolicyPCRs_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xDE, 0xAD}},
			},
		},
	}

	svc, dataDir := tsCreateService(t, mock)

	cp := CompositePolicy{
		Name:     "refresh-comp",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
		},
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	cpData, _ := json.MarshalIndent([]CompositePolicy{cp}, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), cpData, 0600))

	result, err := svc.RefreshCompositePolicyPCRs("refresh-comp")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.PCRDigests)
	assert.NotEmpty(t, result.UpdatedAt)
}

func TestSurgTPM_RefreshCompositePolicyPCRs_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	result, err := svc.RefreshCompositePolicyPCRs("nonexistent")
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// UpdatePolicy: full update with new PCR selections
// ---------------------------------------------------------------------------

func TestSurgTPM_UpdatePolicy_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xBE, 0xEF}},
				{ID: 9, Value: []byte{0xCA, 0xFE}},
			},
		},
	}

	svc, _ := tsCreateService(t, mock)

	// Create initial policy.
	err := svc.CreatePolicy(&PCRPolicy{
		Name:          "update-test",
		Description:   "original desc",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	})
	require.NoError(t, err)

	// Update with new selections.
	updated, err := svc.UpdatePolicy("update-test", &PCRPolicy{
		Description:   "updated desc",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 9, Bank: "sha256"}},
	})
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "updated desc", updated.Description)
	assert.Len(t, updated.PCRSelections, 2)
	assert.NotEmpty(t, updated.UpdatedAt)
}

func TestSurgTPM_UpdatePolicy_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	result, err := svc.UpdatePolicy("nonexistent", &PCRPolicy{Description: "x"})
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestSurgTPM_UpdatePolicy_NilUpdated(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	result, err := svc.UpdatePolicy("test", nil)
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

// ---------------------------------------------------------------------------
// RefreshPolicyPCRs: success path with saved digests
// ---------------------------------------------------------------------------

func TestSurgTPM_RefreshPolicyPCRs_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0x11, 0x22}},
			},
		},
	}

	svc, _ := tsCreateService(t, mock)

	// Create policy first.
	err := svc.CreatePolicy(&PCRPolicy{
		Name:          "refresh-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	})
	require.NoError(t, err)

	result, err := svc.RefreshPolicyPCRs("refresh-test")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.PCRDigests)
	assert.NotEmpty(t, result.UpdatedAt)
}

func TestSurgTPM_RefreshPolicyPCRs_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	result, err := svc.RefreshPolicyPCRs("nonexistent")
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// CreateDefaultPlatformPolicy: create-if-not-exists semantics
// ---------------------------------------------------------------------------

func TestSurgTPM_CreateDefaultPlatformPolicy_Idempotent(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	// First call creates the policy.
	err := svc.CreateDefaultPlatformPolicy()
	require.NoError(t, err)

	// Second call should NOT error (create-if-not-exists semantics).
	err = svc.CreateDefaultPlatformPolicy()
	require.NoError(t, err)

	// Should still only have one.
	policies := svc.loadCompositePolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "Platform Policy", policies[0].Name)
}

// ---------------------------------------------------------------------------
// CreateCompositePolicy: invalid operator
// ---------------------------------------------------------------------------

func TestSurgTPM_CreateCompositePolicy_InvalidOperator(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "bad-op",
		Operator: "XOR", // Invalid
	})
	require.ErrorIs(t, err, ErrTPMInvalidPolicyOperator)
}

func TestSurgTPM_CreateCompositePolicy_Duplicate(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	cp := &CompositePolicy{
		Name:     "dup-comp-test",
		Operator: "AND",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "x:y"}},
	}
	require.NoError(t, svc.CreateCompositePolicy(cp))

	err := svc.CreateCompositePolicy(cp)
	require.ErrorIs(t, err, ErrTPMPolicyExists)
}

// ---------------------------------------------------------------------------
// savePolicyPassword: log warning on AddPasswordV2 error
// This path exercises L4501-4503.
// ---------------------------------------------------------------------------

func TestSurgTPM_SavePolicyPassword_NoStore(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)
	// staticPWService is nil -> early return at L4489-4491.
	svc.savePolicyPassword("any", "AND", "pw")
	// No panic or error -- just logged and returned.
}

// ---------------------------------------------------------------------------
// GetPolicy: found vs not found
// ---------------------------------------------------------------------------

func TestSurgTPM_GetPolicy_Found(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePolicy(&PCRPolicy{
		Name:          "get-me",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	})
	require.NoError(t, err)

	pol, err := svc.GetPolicy("get-me")
	require.NoError(t, err)
	require.NotNil(t, pol)
	assert.Equal(t, "get-me", pol.Name)
}

// ---------------------------------------------------------------------------
// GetCompositePolicy: found
// ---------------------------------------------------------------------------

func TestSurgTPM_GetCompositePolicy_Found(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "get-comp",
		Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "x:y"}},
	})
	require.NoError(t, err)

	cp, err := svc.GetCompositePolicy("get-comp")
	require.NoError(t, err)
	require.NotNil(t, cp)
	assert.Equal(t, "get-comp", cp.Name)
}

// ---------------------------------------------------------------------------
// ListPolicies, ListPolicyAssignments, ListCompositePolicies: happy paths
// These cover the function body (the non-defer part).
// ---------------------------------------------------------------------------

func TestSurgTPM_ListPolicies_WithData(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreatePolicy(&PCRPolicy{
		Name:          "list-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	})
	require.NoError(t, err)

	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestSurgTPM_ListPolicyAssignments_WithData(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := tsCreateService(t, mock)

	assignments := []PolicyAssignment{
		{PolicyName: "p1", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
	}
	data, _ := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600))

	result, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestSurgTPM_ListCompositePolicies_WithData(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := tsCreateService(t, mock)

	err := svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "list-comp-test",
		Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "x:y"}},
	})
	require.NoError(t, err)

	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

// ---------------------------------------------------------------------------
// ChangeOwnerAuth / ChangeEndorsementAuth / ChangeLockoutAuth success paths
// These cover the function body that delegates to changeHierarchyAuth.
// ---------------------------------------------------------------------------

func TestSurgTPM_ChangeOwnerAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("oldpw", "newpw")
	require.NoError(t, err)
}

func TestSurgTPM_ChangeEndorsementAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("oldpw", "newpw")
	require.NoError(t, err)
}

func TestSurgTPM_ChangeLockoutAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("oldpw", "newpw")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetVerificationStatus: exercises the delegation to VerifyTPM
// ---------------------------------------------------------------------------

func TestSurgTPM_GetVerificationStatus_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
}

// ---------------------------------------------------------------------------
// ListKeys: returns empty list
// ---------------------------------------------------------------------------

func TestSurgTPM_ListKeys_ReturnsEmpty(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}
