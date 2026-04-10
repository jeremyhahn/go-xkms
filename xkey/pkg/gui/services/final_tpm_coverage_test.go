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
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: create TPMService with temp dataDir and mock
// ---------------------------------------------------------------------------

func ftCreateService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}

// ftCreatePolicyService creates a PlatformPolicyService wired to the given
// policyMockTPM with a temp directory.
func ftCreatePolicyService(t *testing.T, mock *policyMockTPM) *PlatformPolicyService {
	t.Helper()
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	svc := NewPlatformPolicyService(policyPath)
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))
	svc.SetContext(context.Background())
	return svc
}

// ============================================================================
// TPM SERVICE TESTS
// ============================================================================

// ---------------------------------------------------------------------------
// ChangeOwnerAuth / ChangeEndorsementAuth / ChangeLockoutAuth
// These are at 60% because only the defer block is covered.
// The actual path goes through changeHierarchyAuth.
// ---------------------------------------------------------------------------

func TestFT_ChangeOwnerAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("old", "new")
	require.NoError(t, err)
}

func TestFT_ChangeOwnerAuth_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("auth change failed")
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth change failed")
}

func TestFT_ChangeOwnerAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeOwnerAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ChangeEndorsementAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("old", "new")
	require.NoError(t, err)
}

func TestFT_ChangeEndorsementAuth_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("endorsement fail")
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endorsement fail")
}

func TestFT_ChangeEndorsementAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeEndorsementAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ChangeLockoutAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("old", "new")
	require.NoError(t, err)
}

func TestFT_ChangeLockoutAuth_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("lockout fail")
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lockout fail")
}

func TestFT_ChangeLockoutAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeLockoutAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// changeHierarchyAuth with empty auth strings (nil Password paths)
func TestFT_ChangeHierarchyAuth_EmptyAuths(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	// Both empty -> both passwords are nil
	err := svc.ChangeOwnerAuth("", "")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetVerificationStatus (60%) - delegates to VerifyTPM
// ---------------------------------------------------------------------------

func TestFT_GetVerificationStatus_NoTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Verified)
}

func TestFT_GetVerificationStatus_WithTPM(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	// Without a trust store loaded, verification fails gracefully
	assert.False(t, status.Verified)
}

// ---------------------------------------------------------------------------
// ListPolicies (60%) - only defer is uncovered
// ---------------------------------------------------------------------------

func TestFT_ListPolicies_EmptyDataDir(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	// No dataDir set -> loadPolicies returns empty
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestFT_ListPolicies_WithPolicies(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	// Write a policy file manually
	policies := []PCRPolicy{
		{Name: "test-policy", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
	}
	data, err := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600))

	result, err := svc.ListPolicies()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "test-policy", result[0].Name)
}

// ---------------------------------------------------------------------------
// ListPolicyAssignments (60%) - only defer is uncovered
// ---------------------------------------------------------------------------

func TestFT_ListPolicyAssignments_Empty(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

func TestFT_ListPolicyAssignments_WithAssignments(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	// Write an assignment file
	assignments := []PolicyAssignment{
		{PolicyName: "policy-a", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
	}
	data, err := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600))

	result, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "policy-a", result[0].PolicyName)
}

// ---------------------------------------------------------------------------
// ListCompositePolicies (60%) - only defer is uncovered
// ---------------------------------------------------------------------------

func TestFT_ListCompositePolicies_Empty(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestFT_ListCompositePolicies_WithPolicies(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	// Write a composite policies file
	policies := []CompositePolicy{
		{Name: "comp-policy", Operator: "AND"},
	}
	data, err := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600))

	result, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "comp-policy", result[0].Name)
}

// ---------------------------------------------------------------------------
// GetConflictingAssignments (86.7%)
// Cover: empty keyHandles, whitespace handles, no conflicts path
// ---------------------------------------------------------------------------

func TestFT_GetConflictingAssignments_EmptyInput(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	conflicts, err := svc.GetConflictingAssignments([]string{})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

func TestFT_GetConflictingAssignments_WhitespaceHandles(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	conflicts, err := svc.GetConflictingAssignments([]string{"  ", "", "   "})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

func TestFT_GetConflictingAssignments_WithConflicts(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	// Write assignments
	assignments := []PolicyAssignment{
		{PolicyName: "pol-1", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
		{PolicyName: "pol-2", KeyHandle: "0x81000002", AssignedAt: "2025-01-02T00:00:00Z"},
	}
	data, err := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600))

	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001", "0x81000003"})
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.Equal(t, "0x81000001", conflicts[0].KeyHandle)
	assert.Equal(t, "pol-1", conflicts[0].CurrentPolicy)
}

func TestFT_GetConflictingAssignments_NoConflicts(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	// Write assignments for different handles
	assignments := []PolicyAssignment{
		{PolicyName: "pol-1", KeyHandle: "0x81000001", AssignedAt: "2025-01-01T00:00:00Z"},
	}
	data, err := json.MarshalIndent(assignments, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, policyAssignmentsFile), data, 0600))

	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000099"})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo (78.6%) - cover cert present path
// ---------------------------------------------------------------------------

func TestFT_GetEKECCInfo_CertPresent(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = &testECCCertForEKECC
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Algorithm)
	assert.NotEmpty(t, info.Certificate)
}

func TestFT_GetEKECCInfo_NoCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = nil
	mock.ekCertECErr = errors.New("not available")
	svc := newServiceWithMock(mock)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetEKECCInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// Test certificate with ECDSA key for EKECCInfo
var testECCCertForEKECC = *testECCCert()

// ---------------------------------------------------------------------------
// DefineNVCounter (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_DefineNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVCounter(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_DefineNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineCounterErr = nil
	svc := newServiceWithMock(mock)
	err := svc.DefineNVCounter(0x01500000, "owner-auth")
	require.NoError(t, err)
}

func TestFT_DefineNVCounter_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineCounterErr = errors.New("counter define failed")
	svc := newServiceWithMock(mock)
	err := svc.DefineNVCounter(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counter define failed")
}

// ---------------------------------------------------------------------------
// DefineNVExtend (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_DefineNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVExtend(0x01500001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_DefineNVExtend_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineExtendErr = nil
	svc := newServiceWithMock(mock)
	err := svc.DefineNVExtend(0x01500001, "owner-auth")
	require.NoError(t, err)
}

func TestFT_DefineNVExtend_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineExtendErr = errors.New("extend define failed")
	svc := newServiceWithMock(mock)
	err := svc.DefineNVExtend(0x01500001, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extend define failed")
}

// ---------------------------------------------------------------------------
// IncrementNVCounter (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_IncrementNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.IncrementNVCounter(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_IncrementNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIncrementResult = 42
	mock.nvIncrementErr = nil
	svc := newServiceWithMock(mock)
	val, err := svc.IncrementNVCounter(0x01500000, "auth")
	require.NoError(t, err)
	assert.Equal(t, uint64(42), val)
}

func TestFT_IncrementNVCounter_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIncrementErr = errors.New("increment failed")
	svc := newServiceWithMock(mock)
	_, err := svc.IncrementNVCounter(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "increment failed")
}

// ---------------------------------------------------------------------------
// ReadNVCounter (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_ReadNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVCounter(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ReadNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadCounterResult = 99
	mock.nvReadCounterErr = nil
	svc := newServiceWithMock(mock)
	val, err := svc.ReadNVCounter(0x01500000, "auth")
	require.NoError(t, err)
	assert.Equal(t, uint64(99), val)
}

func TestFT_ReadNVCounter_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadCounterErr = errors.New("counter read failed")
	svc := newServiceWithMock(mock)
	_, err := svc.ReadNVCounter(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counter read failed")
}

// ---------------------------------------------------------------------------
// DeleteNVIndex (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_DeleteNVIndex_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DeleteNVIndex(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_DeleteNVIndex_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvUndefineErr = nil
	svc := newServiceWithMock(mock)
	err := svc.DeleteNVIndex(0x01500000, "auth")
	require.NoError(t, err)
}

func TestFT_DeleteNVIndex_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvUndefineErr = errors.New("undefine failed")
	svc := newServiceWithMock(mock)
	err := svc.DeleteNVIndex(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefine failed")
}

// ---------------------------------------------------------------------------
// GetCompositePolicy (77.8%) - not-found path
// ---------------------------------------------------------------------------

func TestFT_GetCompositePolicy_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	_, err := svc.GetCompositePolicy("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestFT_GetCompositePolicy_Found(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	policies := []CompositePolicy{
		{Name: "my-comp", Operator: "AND", Elements: []PolicyElement{{Type: "password", PasswordHash: "hash"}}},
	}
	data, err := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600))

	result, err := svc.GetCompositePolicy("my-comp")
	require.NoError(t, err)
	assert.Equal(t, "my-comp", result.Name)
	assert.Equal(t, "AND", result.Operator)
}

// ---------------------------------------------------------------------------
// GetPolicy (77.8%) - not-found path
// ---------------------------------------------------------------------------

func TestFT_GetPolicy_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	_, err := svc.GetPolicy("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestFT_GetPolicy_Found(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	policies := []PCRPolicy{
		{Name: "my-pol", PCRSelections: []PCRSelection{{Index: 7, Bank: "sha256"}}},
	}
	data, err := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, pcrPoliciesFile), data, 0600))

	result, err := svc.GetPolicy("my-pol")
	require.NoError(t, err)
	assert.Equal(t, "my-pol", result.Name)
}

// ---------------------------------------------------------------------------
// VerifyPolicyPassword (81.8%) - not-found, no password element
// ---------------------------------------------------------------------------

func TestFT_VerifyPolicyPassword_PolicyNotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	_, err := svc.VerifyPolicyPassword("nonexistent", "pass")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestFT_VerifyPolicyPassword_NoPasswordElement(t *testing.T) {
	mock := defaultMockTPM()
	svc, dataDir := ftCreateService(t, mock)

	// Create a composite policy with only PCR elements
	policies := []CompositePolicy{
		{
			Name:     "pcr-only",
			Operator: "SINGLE",
			Elements: []PolicyElement{{Type: "pcr", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}}},
		},
	}
	data, err := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, compositePoliciesFile), data, 0600))

	_, err = svc.VerifyPolicyPassword("pcr-only", "some-pass")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyType)
}

// ---------------------------------------------------------------------------
// ListTransientHandles (86.7%) - success path with handles
// ---------------------------------------------------------------------------

func TestFT_ListTransientHandles_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ListTransientHandles()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ListTransientHandles_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.transientHandles = []tpm2.TPMHandle{0x80000001, 0x80000002}
	svc := newServiceWithMock(mock)
	result, err := svc.ListTransientHandles()
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "0x80000001", result[0].Handle)
	assert.Equal(t, "transient", result[0].Type)
}

func TestFT_ListTransientHandles_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("transient list failed")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	_, err := svc.ListTransientHandles()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transient list failed")
}

// ---------------------------------------------------------------------------
// CreatePasswordPolicy (82.4%) - validation paths
// ---------------------------------------------------------------------------

func TestFT_CreatePasswordPolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePasswordPolicy("", "desc", "password", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestFT_CreatePasswordPolicy_EmptyPassword(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePasswordPolicy("test-pass-pol", "desc", "", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

func TestFT_CreatePasswordPolicy_WhitespaceName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePasswordPolicy("   ", "desc", "pass", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestFT_CreatePasswordPolicy_WhitespacePassword(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePasswordPolicy("test-pass", "desc", "   ", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// CreatePCROrPasswordPolicy (84.2%) - validation paths
// ---------------------------------------------------------------------------

func TestFT_CreatePCROrPasswordPolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePCROrPasswordPolicy("", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "pass", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestFT_CreatePCROrPasswordPolicy_EmptyPCRs(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePCROrPasswordPolicy("test-or", "desc", nil, "sha256", "pass", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestFT_CreatePCROrPasswordPolicy_EmptyPassword(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePCROrPasswordPolicy("test-or", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// CreatePCRAndPasswordPolicy (84.2%) - validation paths
// ---------------------------------------------------------------------------

func TestFT_CreatePCRAndPasswordPolicy_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePCRAndPasswordPolicy("", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "pass", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestFT_CreatePCRAndPasswordPolicy_EmptyPCRs(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePCRAndPasswordPolicy("test-and", "desc", nil, "sha256", "pass", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestFT_CreatePCRAndPasswordPolicy_EmptyPassword(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	err := svc.CreatePCRAndPasswordPolicy("test-and", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "  ", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// GetPlatformPolicy (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_GetPlatformPolicy_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetPlatformPolicy()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportEKCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportEKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportEKCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportEKECCCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportEKECCCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportEKECCCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportIAKCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportIAKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportIAKCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportIDevIDCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportIDevIDCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportIDevIDCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportEKCert (85.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportEKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportEKCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportEKECCCert (85.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportEKECCCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportEKECCCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportIAKCert (86.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportIAKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportIAKCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportIDevIDCert (86.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportIDevIDCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportIDevIDCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetLockoutInfo (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_GetLockoutInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetLockoutInfo()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ResetLockout (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ResetLockout_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ResetLockout("")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ForceResetLockout (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ForceResetLockout_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ForceResetLockout("")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetNVSummary (89.5%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_GetNVSummary_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetNVSummary()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// saveAssignments (85.7%) - dataDir not set
// ---------------------------------------------------------------------------

func TestFT_SaveAssignments_NoDataDir(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	// No dataDir set -> saveAssignments returns error
	err := svc.saveAssignments([]PolicyAssignment{})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// saveCompositePolicies (85.7%) - dataDir not set
// ---------------------------------------------------------------------------

func TestFT_SaveCompositePolicies_NoDataDir(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.saveCompositePolicies([]CompositePolicy{})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// savePolicies (88.9%) - dataDir not set
// ---------------------------------------------------------------------------

func TestFT_SavePolicies_NoDataDir(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.savePolicies([]PCRPolicy{})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// GetSharedSRKInfo (83.3%) - no TPM / attrs error paths
// ---------------------------------------------------------------------------

func TestFT_GetSharedSRKInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetSharedSRKInfo_SSRKAttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ssrkAttrsErr = errors.New("no srk")
	mock.ssrkAttrs = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetIAKInfo (86.4%) - cover cert present
// ---------------------------------------------------------------------------

func TestFT_GetIAKInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakAttrs = &types.KeyAttributes{
		KeyAlgorithm: 1, // RSA
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81020001,
		},
	}
	mock.iakAttrsErr = nil
	mock.iakCert = testCert()
	mock.iakCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Handle)
	assert.NotEmpty(t, info.Certificate)
}

func TestFT_GetIAKInfo_AttrsNil(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakAttrs = nil
	mock.iakAttrsErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetIDevIDInfo (85.7%) - cover no TPM, attrs nil
// ---------------------------------------------------------------------------

func TestFT_GetIDevIDInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetIDevIDInfo_AttrsNil(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidAttrs = nil
	mock.idevidAttrsErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// InitializePlatformKeyStore (83.3%) - no TPM path + pks nil
// ---------------------------------------------------------------------------

func TestFT_InitializePlatformKeyStore_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.InitializePlatformKeyStore("so", "user")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_InitializePlatformKeyStore_NilPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = nil
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStore("so", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "platform key store not configured")
}

// ---------------------------------------------------------------------------
// InitializePlatformKeyStoreWithDefaults (83.3%) - no TPM path + pks nil
// ---------------------------------------------------------------------------

func TestFT_InitializePlatformKeyStoreWithDefaults_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.InitializePlatformKeyStoreWithDefaults()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_InitializePlatformKeyStoreWithDefaults_NilPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = nil
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStoreWithDefaults()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "platform key store not configured")
}

// ---------------------------------------------------------------------------
// FactoryReset (85.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_FactoryReset_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.FactoryReset("")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// saveHandleDescriptions (88.9%) - dataDir not set
// ---------------------------------------------------------------------------

func TestFT_SaveHandleDescriptions_NoDataDir(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	// No dataDir set
	err := svc.saveHandleDescriptions(map[string]string{"0x81000001": "test"})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// GetPCRs (92.3%) - cover no TPM
// ---------------------------------------------------------------------------

func TestFT_GetPCRs_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetPCRs("sha256")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetEventLog (88.9%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_GetEventLog_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetEventLog()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ============================================================================
// PLATFORM POLICY SERVICE TESTS
// ============================================================================

// ---------------------------------------------------------------------------
// GetStatus (70%) - configured but TPM unavailable for verify
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_GetStatus_ConfiguredNoTPM(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	svc := NewPlatformPolicyService(policyPath)
	// No TPM accessor set

	// Manually store a policy definition
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabbccdd", 7: "11223344"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Configured)
	// TPM unavailable -> verifyDigests fails -> Valid=false
	assert.False(t, status.Valid)
}

// ---------------------------------------------------------------------------
// CreatePolicy (83.3%) - save error (read-only dir)
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_CreatePolicy_SaveError(t *testing.T) {
	// Create policy path inside a non-writable location
	policyPath := filepath.Join("/dev/null", "subdir", "platform.policy")
	svc := NewPlatformPolicyService(policyPath)
	mock := defaultPolicyMock()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// ---------------------------------------------------------------------------
// UpdatePolicy (85%) - not configured, readPCRs error, save error
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_UpdatePolicy_NotConfigured(t *testing.T) {
	svc := ftCreatePolicyService(t, defaultPolicyMock())
	_, err := svc.UpdatePolicy([]int{0}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestFT_PlatformPolicy_UpdatePolicy_InvalidPCRs(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	// First create a policy
	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	// Then update with invalid PCRs
	_, err = svc.UpdatePolicy(nil, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

func TestFT_PlatformPolicy_UpdatePolicy_InvalidBank(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0}, "sha256")
	require.NoError(t, err)

	_, err = svc.UpdatePolicy([]int{0}, "md5")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)
}

func TestFT_PlatformPolicy_UpdatePolicy_ReadPCRsError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0}, "sha256")
	require.NoError(t, err)

	// Now break the TPM
	mock.pcrBanksErr = errors.New("tpm failure")
	_, err = svc.UpdatePolicy([]int{0}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
}

// ---------------------------------------------------------------------------
// VerifyPolicy (66.7%) - not configured, TPM error
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_VerifyPolicy_NotConfigured(t *testing.T) {
	svc := ftCreatePolicyService(t, defaultPolicyMock())
	_, err := svc.VerifyPolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestFT_PlatformPolicy_VerifyPolicy_TPMError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	// Create policy
	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	// Break the TPM
	mock.pcrBanksErr = errors.New("tpm died")
	valid, err := svc.VerifyPolicy()
	require.Error(t, err)
	assert.False(t, valid)
}

func TestFT_PlatformPolicy_VerifyPolicy_Mismatch(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	// Create policy
	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	// Change PCR values to simulate drift
	mock.pcrBanksOverride = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xFF, 0xFF, 0xFF, 0xFF}}, // Different from stored
				{ID: 7, Value: []byte{0x11, 0x22, 0x33, 0x44}},
			},
		},
	}

	valid, err := svc.VerifyPolicy()
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestFT_PlatformPolicy_VerifyPolicy_Success(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	valid, err := svc.VerifyPolicy()
	require.NoError(t, err)
	assert.True(t, valid)
}

// ---------------------------------------------------------------------------
// ExportPolicy (85%) - not configured, empty digests, empty pcrs
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_ExportPolicy_NotConfigured(t *testing.T) {
	svc := ftCreatePolicyService(t, defaultPolicyMock())
	_, err := svc.ExportPolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestFT_PlatformPolicy_ExportPolicy_EmptyDigests(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	// Store a policy with empty digests
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	result, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.Contains(t, result, "Platform Policy")
	assert.Contains(t, result, "sha256")
	// No pcr_digests key when empty
	assert.NotContains(t, result, "pcr_digests")
}

func TestFT_PlatformPolicy_ExportPolicy_EmptyPCRs(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabbccdd"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	result, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.Contains(t, result, "Platform Policy")
	// No pcr_selections key when empty
	assert.NotContains(t, result, "pcr_selections")
}

// ---------------------------------------------------------------------------
// GetPlatformPolicyAsPCRPolicy (75%) - empty digests (nil valid)
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_AsPCRPolicy_EmptyDigests(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	result, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "Platform Policy", result.Name)
	assert.True(t, result.IsPlatformPolicy)
	// Empty digests -> validatePlatformPolicyDigests returns nil
	assert.Nil(t, result.Valid)
}

func TestFT_PlatformPolicy_AsPCRPolicy_NotConfigured(t *testing.T) {
	svc := ftCreatePolicyService(t, defaultPolicyMock())
	result, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestFT_PlatformPolicy_AsPCRPolicy_WithDigests(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	result, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsPlatformPolicy)
	require.NotNil(t, result.Valid)
	assert.True(t, *result.Valid)
}

// ---------------------------------------------------------------------------
// RefreshPlatformPolicyPCRs (85%) - not configured, readPCRs error, save error
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_RefreshPCRs_NotConfigured(t *testing.T) {
	svc := ftCreatePolicyService(t, defaultPolicyMock())
	_, err := svc.RefreshPlatformPolicyPCRs()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestFT_PlatformPolicy_RefreshPCRs_ReadError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0}, "sha256")
	require.NoError(t, err)

	mock.pcrBanksErr = errors.New("pcr read failed")
	_, err = svc.RefreshPlatformPolicyPCRs()
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
}

func TestFT_PlatformPolicy_RefreshPCRs_SaveError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0}, "sha256")
	require.NoError(t, err)

	// Point the policy path to a read-only location
	svc.policyPath = filepath.Join("/dev/null", "subdir", "platform.policy")
	_, err = svc.RefreshPlatformPolicyPCRs()
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// ---------------------------------------------------------------------------
// verifyDigests (81%) - missing PCR in live, invalid hex
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_VerifyDigests_MissingPCR(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	// Store a policy referencing PCR 15 which the mock doesn't have
	def := &PlatformPolicyDefinition{
		PCRs:    []int{0, 15},
		Bank:    "sha256",
		Digests: map[int]string{0: hex.EncodeToString([]byte{0xAA, 0xBB, 0xCC, 0xDD}), 15: "deadbeef"},
	}
	svc.policy.Store(def)

	valid, err := svc.VerifyPolicy()
	require.NoError(t, err)
	// PCR 15 not in live -> mismatch
	assert.False(t, valid)
}

func TestFT_PlatformPolicy_VerifyDigests_InvalidStoredHex(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	// Store a policy with invalid hex in stored digests
	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "NOT_HEX_$$"},
	}
	svc.policy.Store(def)

	valid, err := svc.VerifyPolicy()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
	assert.False(t, valid)
}

// ---------------------------------------------------------------------------
// savePolicy (83.3%) - MkdirAll error, WriteFile error
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_SavePolicy_DirCreationError(t *testing.T) {
	// Use /dev/null as parent - can't create subdirectories under it
	svc := NewPlatformPolicyService(filepath.Join("/dev/null", "subdir", "deep", "platform.policy"))

	def := &PlatformPolicyDefinition{
		PCRs: []int{0},
		Bank: "sha256",
	}
	err := svc.savePolicy(def)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

func TestFT_PlatformPolicy_SavePolicy_WriteFileError(t *testing.T) {
	// Create a directory where the .tmp file should go, which will cause
	// WriteFile to fail because it can't write to a directory path
	dir := t.TempDir()
	tmpFilePath := filepath.Join(dir, "platform.policy.tmp")
	require.NoError(t, os.MkdirAll(tmpFilePath, 0700)) // Create dir at .tmp path

	svc := NewPlatformPolicyService(filepath.Join(dir, "platform.policy"))
	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabb"},
	}
	err := svc.savePolicy(def)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// ---------------------------------------------------------------------------
// validatePCRSelection edge cases
// ---------------------------------------------------------------------------

func TestFT_ValidatePCRSelection_NegativeIndex(t *testing.T) {
	err := validatePCRSelection([]int{-1})
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

func TestFT_ValidatePCRSelection_ExactMax(t *testing.T) {
	// PCR 23 is valid (maxPCRIndex = 23)
	err := validatePCRSelection([]int{23})
	require.NoError(t, err)
}

func TestFT_ValidatePCRSelection_AboveMax(t *testing.T) {
	err := validatePCRSelection([]int{24})
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

// ---------------------------------------------------------------------------
// validatePCRBank edge cases
// ---------------------------------------------------------------------------

func TestFT_ValidatePCRBank_InvalidName(t *testing.T) {
	err := validatePCRBank("sm3")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)
}

func TestFT_ValidatePCRBank_CaseSensitive(t *testing.T) {
	// Upper case should fail since validPCRBanks has lowercase keys
	err := validatePCRBank("SHA256")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)
}

// ---------------------------------------------------------------------------
// UpdatePolicy - save error path
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_UpdatePolicy_SaveError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0}, "sha256")
	require.NoError(t, err)

	// Point to invalid path
	svc.policyPath = filepath.Join("/dev/null", "deep", "platform.policy")
	_, err = svc.UpdatePolicy([]int{0}, "sha256")
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// ---------------------------------------------------------------------------
// PlatformSRKInfo (90%) - cover PlatformKeyStore nil
// ---------------------------------------------------------------------------

func TestFT_GetPlatformSRKInfo_NoPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetPlatformSRKInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetPlatformSRKInfo_WithPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   true,
		policyEnabled: true,
		srkAttrs: &types.KeyAttributes{
			KeyAlgorithm: 1, // RSA
			TPMAttributes: &types.TPMAttributes{
				Handle: 0x81800001,
			},
		},
	}
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.True(t, info.PolicyEnabled)
	assert.True(t, info.Initialized)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo with nil cert (not error but nil)
// ---------------------------------------------------------------------------

func TestFT_GetEKECCInfo_NilCertNoError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = nil
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// IDevIDInfo with cert
// ---------------------------------------------------------------------------

func TestFT_GetIDevIDInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidAttrs = &types.KeyAttributes{
		KeyAlgorithm: 3, // ECDSA
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81020000,
		},
	}
	mock.idevidAttrsErr = nil
	mock.idevidCert = &testIDevIDCertInstance
	mock.idevidCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Certificate)
}

var testIDevIDCertInstance = *testECCCert()

// ---------------------------------------------------------------------------
// ExtendNV (86.7%) - cover invalid hex, empty data
// ---------------------------------------------------------------------------

func TestFT_ExtendNV_InvalidHex(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ExtendNV(0x01500000, "NOT_VALID_HEX$$", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestFT_ExtendNV_EmptyData(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ExtendNV(0x01500000, "", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestFT_ExtendNV_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ExtendNV(0x01500000, "aabbccdd", "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ReadNVExtend (84.6%) - no TPM, success, error
// ---------------------------------------------------------------------------

func TestFT_ReadNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVExtend(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ReadNVExtend_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadExtendResult = []byte{0xDE, 0xAD}
	mock.nvReadExtendErr = nil
	svc := newServiceWithMock(mock)
	result, err := svc.ReadNVExtend(0x01500000, "")
	require.NoError(t, err)
	assert.Equal(t, "dead", result)
}

func TestFT_ReadNVExtend_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadExtendErr = errors.New("extend read fail")
	svc := newServiceWithMock(mock)
	_, err := svc.ReadNVExtend(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extend read fail")
}

// ---------------------------------------------------------------------------
// DefineNVOrdinary (84.6%) - invalid size
// ---------------------------------------------------------------------------

func TestFT_DefineNVOrdinary_InvalidSizeZero(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DefineNVOrdinary(0x01500000, 0, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestFT_DefineNVOrdinary_InvalidSizeTooLarge(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DefineNVOrdinary(0x01500000, 3000, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestFT_DefineNVOrdinary_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVOrdinary(0x01500000, 64, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// Provision (88.9%) - nil opts, invalid mode
// ---------------------------------------------------------------------------

func TestFT_Provision_NilOpts(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Provision(nil)
	assert.ErrorIs(t, err, ErrTPMProvisionFailed)
}

func TestFT_Provision_InvalidMode(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{Mode: "invalid_mode"})
	assert.ErrorIs(t, err, ErrTPMInvalidProvisionMode)
}

func TestFT_Provision_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.Provision(&ProvisionOptions{Mode: "install"})
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// Install (87.5%) - no TPM, auth error
// ---------------------------------------------------------------------------

func TestFT_Install_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.Install("auth")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_Install_EmptyAuth(t *testing.T) {
	mock := defaultMockTPM()
	mock.installErr = nil
	svc := newServiceWithMock(mock)
	err := svc.Install("")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// WriteNVData (87.5%) - no TPM
// ---------------------------------------------------------------------------

func TestFT_WriteNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.WriteNVData(0x01500000, "deadbeef", "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ReadNVData (90.9%) - no TPM
// ---------------------------------------------------------------------------

func TestFT_ReadNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVData(0x01500000, 64, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ComparePolicyPCRs (93.3%) - empty name
// ---------------------------------------------------------------------------

func TestFT_ComparePolicyPCRs_EmptyName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	_, err := svc.ComparePolicyPCRs("")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestFT_ComparePolicyPCRs_WhitespaceName(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := ftCreateService(t, mock)
	_, err := svc.ComparePolicyPCRs("   ")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

// ---------------------------------------------------------------------------
// getPolicyContext fallback
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_GetPolicyContext_FallbackToBackground(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	// ctx is nil, should return context.Background()
	ctx := svc.getPolicyContext()
	require.NotNil(t, ctx)
}

func TestFT_PlatformPolicy_GetPolicyContext_WithContext(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	expected := context.Background()
	svc.SetContext(expected)
	ctx := svc.getPolicyContext()
	assert.Equal(t, expected, ctx)
}

// ---------------------------------------------------------------------------
// GetPolicyPCRs - not configured
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_GetPolicyPCRs_NotConfigured(t *testing.T) {
	svc := ftCreatePolicyService(t, defaultPolicyMock())
	pcrs, bank, err := svc.GetPolicyPCRs()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
	assert.Nil(t, pcrs)
	assert.Empty(t, bank)
}

func TestFT_PlatformPolicy_GetPolicyPCRs_Configured(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	pcrs, bank, err := svc.GetPolicyPCRs()
	require.NoError(t, err)
	assert.Equal(t, []int{0, 7}, pcrs)
	assert.Equal(t, "sha256", bank)
}

// ---------------------------------------------------------------------------
// DeletePolicy - not configured, remove error suppressed
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_DeletePolicy_NotConfigured(t *testing.T) {
	svc := ftCreatePolicyService(t, defaultPolicyMock())
	err := svc.DeletePolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

// ---------------------------------------------------------------------------
// ExportPolicy - with populated digests and PCRs
// ---------------------------------------------------------------------------

func TestFT_PlatformPolicy_ExportPolicy_WithDigestsAndPCRs(t *testing.T) {
	mock := defaultPolicyMock()
	svc := ftCreatePolicyService(t, mock)

	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	result, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.Contains(t, result, "Platform Policy")
	assert.Contains(t, result, "pcr_selections")
	assert.Contains(t, result, "pcr_digests")
	assert.Contains(t, result, "sha256:0")
	assert.Contains(t, result, "sha256:7")
}

// ---------------------------------------------------------------------------
// isTPMAuthError - additional coverage for string-based detection
// ---------------------------------------------------------------------------

func TestFT_IsTPMAuthError_StringBased(t *testing.T) {
	assert.True(t, isTPMAuthError(errors.New("some AUTH_FAIL occurred")))
	assert.True(t, isTPMAuthError(errors.New("bad_auth detected")))
	assert.False(t, isTPMAuthError(errors.New("some random error")))
	assert.False(t, isTPMAuthError(nil))
}

// ---------------------------------------------------------------------------
// GetEKInfo with cert (covers certAlgorithmName, certKeySize branches)
// ---------------------------------------------------------------------------

func TestFT_GetEKInfo_WithECDSACert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testECCCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Certificate)
}

// ---------------------------------------------------------------------------
// GatherTPMInfo with FIPS error (fipsErr branch in GetInfo)
// ---------------------------------------------------------------------------

func TestFT_GetInfo_FIPSError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fipsErr = errors.New("not supported")
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// FIPS error is logged but doesn't cause failure
	assert.False(t, info.FIPSMode)
}

// ---------------------------------------------------------------------------
// GetInfo - fixedProperties error branch
// ---------------------------------------------------------------------------

func TestFT_GetInfo_FixedPropsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("capability error")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.Manufacturer)
}

// ---------------------------------------------------------------------------
// GetInfo - no TPM
// ---------------------------------------------------------------------------

func TestFT_GetInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.Manufacturer)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo with ECC public key in cert
// ---------------------------------------------------------------------------

func TestFT_GetEKECCInfo_ECCSAKeyInCert(t *testing.T) {
	mock := defaultMockTPM()
	cert := testECCCert()
	cert.PublicKey = &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     big.NewInt(100),
		Y:     big.NewInt(200),
	}
	mock.ekCertEC = cert
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.Equal(t, 384, info.KeySize)
}
