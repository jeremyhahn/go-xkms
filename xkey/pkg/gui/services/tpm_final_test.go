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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock infrastructure with unique prefix "tf" to avoid conflicts.
// ---------------------------------------------------------------------------

type tfFailDeleteStore struct {
	*mockStaticPWStore
	forceDeleteErr error
}

func (s *tfFailDeleteStore) ForceDelete(idOrName string) error {
	return s.forceDeleteErr
}

var _ staticpw.Store = (*tfFailDeleteStore)(nil)

func tfCreateService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}

func tfCreateServiceWithPW(t *testing.T, mock *mockTPM, store staticpw.Store) (*TPMService, string) {
	t.Helper()
	svc, dataDir := tfCreateService(t, mock)
	pwSvc := NewStaticPasswordService(store)
	svc.SetStaticPasswordService(pwSvc)
	return svc, dataDir
}

func TestTF_ImportCompositePolicy_MarshalError(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{
		"name":     "test-composite",
		"operator": "AND",
		"elements": make(chan int),
	}
	name, err := svc.importCompositePolicy(raw)
	assert.Empty(t, name)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestTF_ImportCompositePolicy_UnmarshalError(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{
		"name":     "bad-elements",
		"operator": "AND",
		"elements": "not-a-slice",
	}
	name, err := svc.importCompositePolicy(raw)
	assert.Empty(t, name)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestTF_ImportBinaryPolicyDigest_EmptyData(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	name, err := svc.importBinaryPolicyDigest("/tmp/test.bin", nil)
	assert.Empty(t, name)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestTF_ImportBinaryPolicyDigest_NameConflictRetryFails(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policy := &PCRPolicy{Name: "mydigest", Description: "original"}
	require.NoError(t, svc.CreatePolicy(policy))

	// Make the policies file read-only so the retry savePolicies fails.
	policiesFile := filepath.Join(svc.dataDir, pcrPoliciesFile)
	require.NoError(t, os.Chmod(policiesFile, 0400))
	t.Cleanup(func() { os.Chmod(policiesFile, 0600) }) //nolint:errcheck

	binaryData := []byte{0xAA, 0xBB, 0xCC}
	name, importErr := svc.importBinaryPolicyDigest("/tmp/mydigest.bin", binaryData)
	assert.Empty(t, name)
	require.Error(t, importErr)
}

func TestTF_ImportBinaryPolicyDigest_Success(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	binaryData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	name, err := svc.importBinaryPolicyDigest("/tmp/my-policy.bin", binaryData)
	require.NoError(t, err)
	assert.Equal(t, "my-policy", name)

	policy, getErr := svc.GetPolicy("my-policy")
	require.NoError(t, getErr)
	assert.Contains(t, policy.Description, "my-policy.bin")
	assert.Equal(t, "deadbeef", policy.PCRDigests["policy_digest"])
}

func TestTF_ImportBinaryPolicyDigest_NameConflictRetrySuccess(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "conflict"}))

	binaryData := []byte{0x01, 0x02}
	name, importErr := svc.importBinaryPolicyDigest("/tmp/conflict.bin", binaryData)
	require.NoError(t, importErr)
	assert.Contains(t, name, "conflict-")
	assert.NotEqual(t, "conflict", name)
}

func TestTF_ImportBinaryPolicyDigest_EmptyBaseName(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	binaryData := []byte{0x01}
	name, err := svc.importBinaryPolicyDigest("/tmp/.bin", binaryData)
	require.NoError(t, err)
	assert.Equal(t, "imported-policy", name)
}

func TestTF_ImportJSONPolicy_CompositeDetection(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{
		"name":     "comp-test",
		"operator": "AND",
		"elements": []interface{}{
			map[string]interface{}{"type": "pcr", "pcr_bank": "sha256"},
		},
	}
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	name, importErr := svc.importJSONPolicy(data)
	require.NoError(t, importErr)
	assert.Equal(t, "comp-test", name)
}

func TestTF_ImportJSONPolicy_InvalidJSON(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	name, err := svc.importJSONPolicy([]byte("not json"))
	assert.Empty(t, name)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestTF_ImportJSONPolicy_EmptyName(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	data, _ := json.Marshal(map[string]interface{}{"name": ""})
	name, err := svc.importJSONPolicy(data)
	assert.Empty(t, name)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTF_ImportJSONPolicy_PCRPolicy_WithDigests(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{
		"name":           "pcr-import",
		"description":    "test import",
		"pcr_bank":       "sha256",
		"pcr_selections": []interface{}{float64(0), float64(7)},
		"pcr_digests":    map[string]interface{}{"sha256:0": "aabb", "sha256:7": "ccdd"},
	}
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	name, importErr := svc.importJSONPolicy(data)
	require.NoError(t, importErr)
	assert.Equal(t, "pcr-import", name)

	policy, getErr := svc.GetPolicy("pcr-import")
	require.NoError(t, getErr)
	assert.Len(t, policy.PCRSelections, 2)
	assert.Equal(t, "aabb", policy.PCRDigests["sha256:0"])
}

func TestTF_ImportJSONPolicy_DefaultBank(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{
		"name":           "default-bank",
		"pcr_selections": []interface{}{float64(0)},
	}
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	name, importErr := svc.importJSONPolicy(data)
	require.NoError(t, importErr)
	assert.Equal(t, "default-bank", name)

	policy, getErr := svc.GetPolicy("default-bank")
	require.NoError(t, getErr)
	assert.Equal(t, "sha256", policy.PCRSelections[0].Bank)
}

func TestTF_DeletePolicyPassword_ForceDeleteError(t *testing.T) {
	baseStore := newMockStaticPWStore()
	failStore := &tfFailDeleteStore{mockStaticPWStore: baseStore, forceDeleteErr: errors.New("forced delete failed")}
	svc, _ := tfCreateServiceWithPW(t, defaultMockTPM(), failStore)

	_, addErr := svc.staticPWService.AddPasswordV2(AddPasswordParams{
		Name: "Policy: test-delete-err", Password: "secret123",
		FolderPath: policyPasswordFolder, ReadOnly: true,
	})
	require.NoError(t, addErr)

	svc.deletePolicyPassword("test-delete-err")
	entries, _ := svc.staticPWService.ListPasswordsByFolder(policyPasswordFolder)
	assert.Len(t, entries, 1)
}

func TestTF_DeletePolicyPassword_NoMatch(t *testing.T) {
	baseStore := newMockStaticPWStore()
	svc, _ := tfCreateServiceWithPW(t, defaultMockTPM(), baseStore)
	_, addErr := svc.staticPWService.AddPasswordV2(AddPasswordParams{
		Name: "Policy: other-policy", Password: "secret",
		FolderPath: policyPasswordFolder, ReadOnly: true,
	})
	require.NoError(t, addErr)
	svc.deletePolicyPassword("nonexistent")
	entries, _ := svc.staticPWService.ListPasswordsByFolder(policyPasswordFolder)
	assert.Len(t, entries, 1)
}

func TestTF_ComparePolicyPCRs_SavedDigestInvalidHex(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policy := &PCRPolicy{
		Name:          "bad-hex-policy",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "not-valid-hex!"},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	result, compErr := svc.ComparePolicyPCRs("bad-hex-policy")
	require.NoError(t, compErr)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.TotalPCRs, 1)
}

func TestTF_ComparePolicyPCRs_EmptyName(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	result, err := svc.ComparePolicyPCRs("")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTF_ComparePolicyPCRs_PolicyNotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	result, err := svc.ComparePolicyPCRs("nonexistent")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_ComparePolicyPCRs_NoDigests(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	// No PCRSelections => CreatePolicy won't auto-populate digests.
	policy := &PCRPolicy{Name: "no-digests"}
	require.NoError(t, svc.CreatePolicy(policy))

	saved, getErr := svc.GetPolicy("no-digests")
	require.NoError(t, getErr)

	if len(saved.PCRDigests) == 0 {
		result, err := svc.ComparePolicyPCRs("no-digests")
		assert.Nil(t, result)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTPMPolicyNoDigests)
	} else {
		result, err := svc.ComparePolicyPCRs("no-digests")
		require.NoError(t, err)
		assert.NotNil(t, result)
	}
}

func TestTF_ComparePolicyPCRs_NoTPM(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())
	policies := []PCRPolicy{{
		Name:          "test-no-tpm",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabb"},
	}}
	require.NoError(t, svc.savePolicies(policies))
	result, err := svc.ComparePolicyPCRs("test-no-tpm")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_SavePolicies_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.savePolicies([]PCRPolicy{{Name: "test"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

func TestTF_SavePolicies_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/path/that/does/not/exist")
	err := svc.savePolicies([]PCRPolicy{{Name: "test"}})
	require.Error(t, err)
}

func TestTF_SaveAssignments_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveAssignments([]PolicyAssignment{{PolicyName: "p", KeyHandle: "0x81000001"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

func TestTF_SaveAssignments_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/path")
	err := svc.saveAssignments([]PolicyAssignment{{PolicyName: "p"}})
	require.Error(t, err)
}

func TestTF_SaveCompositePolicies_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveCompositePolicies([]CompositePolicy{{Name: "test"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

func TestTF_SaveCompositePolicies_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/path")
	err := svc.saveCompositePolicies([]CompositePolicy{{Name: "test"}})
	require.Error(t, err)
}

func TestTF_SaveHandleDescriptions_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/path")
	err := svc.saveHandleDescriptions(map[string]string{"0x81000001": "SRK"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMHandleDescriptionFailed)
}

func TestTF_ImportCompositePolicy_Success(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{
		"name": "imported-comp", "operator": "OR",
		"elements": []interface{}{
			map[string]interface{}{"type": "pcr", "pcr_bank": "sha256",
				"pcr_selections": []interface{}{map[string]interface{}{"index": float64(0), "bank": "sha256"}}},
			map[string]interface{}{"type": "password", "password_hash": "salt:hash"},
		},
	}
	name, err := svc.importCompositePolicy(raw)
	require.NoError(t, err)
	assert.Equal(t, "imported-comp", name)
	cp, getErr := svc.GetCompositePolicy("imported-comp")
	require.NoError(t, getErr)
	assert.Equal(t, "OR", cp.Operator)
}

func TestTF_ImportCompositePolicy_Duplicate(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{"name": "dup-comp", "operator": "SINGLE", "elements": []interface{}{}}
	name, err := svc.importCompositePolicy(raw)
	require.NoError(t, err)
	assert.Equal(t, "dup-comp", name)
	name2, err2 := svc.importCompositePolicy(raw)
	assert.Empty(t, name2)
	require.Error(t, err2)
	assert.ErrorIs(t, err2, ErrTPMPolicyExists)
}

func TestTF_ImportCompositePolicy_EmptyName(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	raw := map[string]interface{}{"name": "", "operator": "AND"}
	name, err := svc.importCompositePolicy(raw)
	assert.Empty(t, name)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTF_ExportCompositePolicy_NotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	result, err := svc.ExportCompositePolicy("nonexistent")
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_ExportCompositePolicy_WithPCRElements(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policy := &CompositePolicy{
		Name: "export-test", Description: "testing export", Operator: "OR",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}}},
			{Type: "password", PasswordHash: "salt:hash"},
		},
		PCRDigests: map[string]string{"sha256:0": "aabb"},
	}
	require.NoError(t, svc.CreateCompositePolicy(policy))
	result, err := svc.ExportCompositePolicy("export-test")
	require.NoError(t, err)
	assert.Contains(t, result, "export-test")
	assert.Contains(t, result, "pcr_bank")
}

func TestTF_ExportCompositePolicy_WithUpdatedAt(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policy := &CompositePolicy{Name: "updated-export", Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "s:h"}}}
	require.NoError(t, svc.CreateCompositePolicy(policy))
	policies := svc.loadCompositePolicies()
	policies[0].UpdatedAt = time.Now().Format(time.RFC3339)
	policies[0].Description = "has update time"
	require.NoError(t, svc.saveCompositePolicies(policies))
	result, err := svc.ExportCompositePolicy("updated-export")
	require.NoError(t, err)
	assert.Contains(t, result, "updated_at")
}

func TestTF_ExportCompositePolicy_EmptyPCRBank_FallbackToSelection(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policy := &CompositePolicy{Name: "fallback-bank", Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "pcr", PCRBank: "", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha384"}}}}}
	require.NoError(t, svc.CreateCompositePolicy(policy))
	result, err := svc.ExportCompositePolicy("fallback-bank")
	require.NoError(t, err)
	assert.Contains(t, result, "sha384")
}

func TestTF_ExportPolicy_NotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	result, err := svc.ExportPolicy("missing")
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_ExportPolicy_WithDigestsAndSelections(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policy := &PCRPolicy{Name: "export-pcr", Description: "pcr export test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabb", "sha256:7": "ccdd"}}
	require.NoError(t, svc.CreatePolicy(policy))
	result, err := svc.ExportPolicy("export-pcr")
	require.NoError(t, err)
	assert.Contains(t, result, "export-pcr")
	assert.Contains(t, result, "pcr_selections")
}

func TestTF_ListPolicies_Empty(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestTF_ListKeys_Empty(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestTF_ListCompositePolicies_Empty(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestTF_ListCompositePoliciesWithDigests_Empty(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestTF_ListPolicyAssignments_Empty(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

func TestTF_DeleteCompositePolicy_NotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	err := svc.DeleteCompositePolicy("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_DeleteCompositePolicy_CascadesAssignments(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	// Create PCR policy (needed for AssignPolicyToKey which calls GetPolicy).
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "cascade-del"}))
	// Create composite policy with same name.
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name: "cascade-del", Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "s:h"}}}))
	require.NoError(t, svc.AssignPolicyToKey("cascade-del", "0x81000001"))
	assignments, _ := svc.ListPolicyAssignments()
	assert.Len(t, assignments, 1)
	require.NoError(t, svc.DeleteCompositePolicy("cascade-del"))
	assignments, _ = svc.ListPolicyAssignments()
	assert.Empty(t, assignments)
}

func TestTF_RefreshCompositePolicyPCRs_NotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	result, err := svc.RefreshCompositePolicyPCRs("nonexistent")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_RefreshCompositePolicyPCRs_NoPCRElements(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	policy := &CompositePolicy{Name: "no-pcr-elements", Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "s:h"}}}
	require.NoError(t, svc.CreateCompositePolicy(policy))
	result, err := svc.RefreshCompositePolicyPCRs("no-pcr-elements")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "no-pcr-elements", result.Name)
}

func TestTF_GetConflictingAssignments_NoConflicts(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001"})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

func TestTF_GetConflictingAssignments_WithConflicts(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "conflict-check"}))
	require.NoError(t, svc.AssignPolicyToKey("conflict-check", "0x81000001"))
	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001", "0x81000002"})
	require.NoError(t, err)
	assert.Len(t, conflicts, 1)
	assert.Equal(t, "0x81000001", conflicts[0].KeyHandle)
}

func TestTF_GetConflictingAssignments_EmptyHandles(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	conflicts, err := svc.GetConflictingAssignments([]string{" ", ""})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

func TestTF_GetPolicyDeletionImpact_PCRPolicy(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "impact-pcr"}))
	require.NoError(t, svc.AssignPolicyToKey("impact-pcr", "0x81000001"))
	impact, err := svc.GetPolicyDeletionImpact("impact-pcr")
	require.NoError(t, err)
	assert.Equal(t, "pcr", impact.PolicyType)
	assert.Len(t, impact.AssignedKeyHandles, 1)
}

func TestTF_GetPolicyDeletionImpact_CompositePolicy(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name: "impact-comp", Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "s:h"}}}))
	impact, err := svc.GetPolicyDeletionImpact("impact-comp")
	require.NoError(t, err)
	assert.Equal(t, "composite", impact.PolicyType)
}

func TestTF_GetPolicyDeletionImpact_NotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	impact, err := svc.GetPolicyDeletionImpact("nonexistent")
	assert.Nil(t, impact)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_GetPolicyDeletionImpact_WithPasswordStore(t *testing.T) {
	baseStore := newMockStaticPWStore()
	svc, _ := tfCreateServiceWithPW(t, defaultMockTPM(), baseStore)
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name: "pw-impact", Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "s:h"}}}))
	_, addErr := svc.staticPWService.AddPasswordV2(AddPasswordParams{
		Name: "Policy: pw-impact", Password: "secret",
		FolderPath: policyPasswordFolder, ReadOnly: true})
	require.NoError(t, addErr)
	impact, err := svc.GetPolicyDeletionImpact("pw-impact")
	require.NoError(t, err)
	assert.True(t, impact.HasPasswordEntry)
}

func TestTF_AssignPolicyToKeys_EmptyName(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	err := svc.AssignPolicyToKeys("", []string{"0x81000001"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTF_AssignPolicyToKeys_EmptyHandles(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	err := svc.AssignPolicyToKeys("my-policy", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidHandle)
}

func TestTF_AssignPolicyToKeys_UpdateExisting(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "multi-assign"}))
	require.NoError(t, svc.AssignPolicyToKey("multi-assign", "0x81000001"))
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "multi-assign-2"}))
	err := svc.AssignPolicyToKeys("multi-assign-2", []string{"0x81000001", "0x81000002", " "})
	require.NoError(t, err)
	assignments, _ := svc.ListPolicyAssignments()
	assert.Len(t, assignments, 2)
}

func TestTF_VerifyPolicyPassword_NotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	ok, err := svc.VerifyPolicyPassword("nonexistent", "pass")
	assert.False(t, ok)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_VerifyPolicyPassword_NoPasswordElement(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name: "no-pw-elem", Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "pcr", PCRBank: "sha256",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}}}}))
	ok, err := svc.VerifyPolicyPassword("no-pw-elem", "pass")
	assert.False(t, ok)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyType)
}

func TestTF_ReplayEventLog_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ReplayEventLog()
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReplayEventLog_NoEventLog(t *testing.T) {
	mock := defaultMockTPM()
	mock.parsedEventsErr = errors.New("no event log")
	svc := newServiceWithMock(mock)
	result, err := svc.ReplayEventLog()
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMEventLogNotFound)
}

func TestTF_GenerateIDevIDCSR_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.GenerateIDevIDCSR()
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_GenerateIDevIDCSR_NoEKCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertErr = errors.New("no EK cert")
	svc := newServiceWithMock(mock)
	result, err := svc.GenerateIDevIDCSR()
	assert.Empty(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EK certificate")
}

func TestTF_UnassignPolicyFromKey_NotFound(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	err := svc.UnassignPolicyFromKey("0x81000001")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTF_UnassignPolicyFromKey_Success(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "unassign-test"}))
	require.NoError(t, svc.AssignPolicyToKey("unassign-test", "0x81000001"))
	require.NoError(t, svc.UnassignPolicyFromKey("0x81000001"))
	assignments, _ := svc.ListPolicyAssignments()
	assert.Empty(t, assignments)
}

func TestTF_ChangeOwnerAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeOwnerAuth("old", "new")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ChangeEndorsementAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeEndorsementAuth("old", "new")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ChangeLockoutAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeLockoutAuth("old", "new")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_DefineNVOrdinary_InvalidSize(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.DefineNVOrdinary(0x01800001, 0, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
	err = svc.DefineNVOrdinary(0x01800001, 3000, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestTF_DefineNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVCounter(0x01800001, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_DefineNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVExtend(0x01800001, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReadNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ReadNVData(0x01800001, 0, "")
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_WriteNVData_InvalidHex(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.WriteNVData(0x01800001, "not-hex!", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_WriteNVData_EmptyData(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.WriteNVData(0x01800001, "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_ExtendNV_InvalidHex(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.ExtendNV(0x01800001, "zzzz", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_ExtendNV_EmptyData(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.ExtendNV(0x01800001, "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_IncrementNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	val, err := svc.IncrementNVCounter(0x01800001, "")
	assert.Zero(t, val)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReadNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	val, err := svc.ReadNVCounter(0x01800001, "")
	assert.Zero(t, val)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReadNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ReadNVExtend(0x01800001, "")
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_DeleteNVIndex_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DeleteNVIndex(0x01800001, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ImportManufacturerCA_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportManufacturerCA("not a PEM")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidCACert)
}

func TestTF_VerifyTPM_NoTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Contains(t, status.ErrorMessage, "not available")
}

func TestTF_GetVerificationStatus_NoTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	assert.False(t, status.Verified)
}

func TestTF_ParseCertificate_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ParseCertificate("not a cert")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTF_CreateDefaultPlatformPolicy_Success(t *testing.T) {
	svc, _ := tfCreateService(t, defaultMockTPM())
	require.NoError(t, svc.CreateDefaultPlatformPolicy())
	require.NoError(t, svc.CreateDefaultPlatformPolicy()) // idempotent
}

func TestTF_SavePolicyDigestBinary_InvalidJSON(t *testing.T) {
	svc := NewTPMService()
	err := svc.savePolicyDigestBinary("/tmp/test.bin", "not json")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMPolicyExportFailed)
}

func TestTF_SavePolicyDigestBinary_Success(t *testing.T) {
	svc := NewTPMService()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "policy.bin")
	policyJSON := `{"pcr_bank":"sha256","pcr_selections":[0,7],"pcr_digests":{"sha256:0":"0000000000000000000000000000000000000000000000000000000000000000"}}`
	require.NoError(t, svc.savePolicyDigestBinary(outPath, policyJSON))
	data, readErr := os.ReadFile(outPath)
	require.NoError(t, readErr)
	assert.NotEmpty(t, data)
}

func TestTF_FindPolicyPasswordEntry_Found(t *testing.T) {
	baseStore := newMockStaticPWStore()
	svc, _ := tfCreateServiceWithPW(t, defaultMockTPM(), baseStore)
	_, addErr := svc.staticPWService.AddPasswordV2(AddPasswordParams{
		Name: "Policy: find-me", Password: "secret",
		FolderPath: policyPasswordFolder, ReadOnly: true})
	require.NoError(t, addErr)
	id, found := svc.findPolicyPasswordEntry("find-me")
	assert.True(t, found)
	assert.NotEmpty(t, id)
}

func TestTF_FindPolicyPasswordEntry_NotFound(t *testing.T) {
	baseStore := newMockStaticPWStore()
	svc, _ := tfCreateServiceWithPW(t, defaultMockTPM(), baseStore)
	id, found := svc.findPolicyPasswordEntry("not-here")
	assert.False(t, found)
	assert.Empty(t, id)
}

func TestTF_FindPolicyPasswordEntry_NilService(t *testing.T) {
	svc := NewTPMService()
	id, found := svc.findPolicyPasswordEntry("any")
	assert.False(t, found)
	assert.Empty(t, id)
}
