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

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// PIN Service - GetPINStatus, SetSOPIN, ChangeSOPIN, VerifySOPIN success paths
// ===========================================================================

// TestP4B_PINService_GetPINStatus_Success tests GetPINStatus returns correct
// status when the PINManager reports initialized with both PINs set.
func TestP4B_PINService_GetPINStatus_Success(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    pin.StrategySoftware,
		soPINSet:    true,
		userPINSet:  true,
		initialized: true,
	}
	svc := newTestPINService(mgr)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.SOPINSet)
	assert.True(t, status.UserPINSet)
	assert.True(t, status.Initialized)
	assert.Equal(t, "software", status.Strategy)
}

// TestP4B_PINService_GetPINStatus_NoPINsSet tests GetPINStatus returns correct
// status when no PINs have been set yet.
func TestP4B_PINService_GetPINStatus_NoPINsSet(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    pin.StrategyTPM2,
		soPINSet:    false,
		userPINSet:  false,
		initialized: false,
	}
	svc := newTestPINService(mgr)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.SOPINSet)
	assert.False(t, status.UserPINSet)
	assert.False(t, status.Initialized)
	assert.Equal(t, "tpm2", status.Strategy)
}

// TestP4B_PINService_SetSOPIN_Success tests the SetSOPIN success path.
func TestP4B_PINService_SetSOPIN_Success(t *testing.T) {
	mgr := &mockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestPINService(mgr)

	err := svc.SetSOPIN("", "new-so-pin")
	assert.NoError(t, err)
}

// TestP4B_PINService_SetSOPIN_ManagerError tests SetSOPIN with a manager error.
func TestP4B_PINService_SetSOPIN_ManagerError(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    pin.StrategySoftware,
		setSOPINErr: errors.New("tpm locked"),
	}
	svc := newTestPINService(mgr)

	err := svc.SetSOPIN("", "new-so-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tpm locked")
}

// TestP4B_PINService_ChangeSOPIN_Success tests the ChangeSOPIN success path.
func TestP4B_PINService_ChangeSOPIN_Success(t *testing.T) {
	mgr := &mockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestPINService(mgr)

	err := svc.ChangeSOPIN("old-pin", "new-pin")
	assert.NoError(t, err)
}

// TestP4B_PINService_ChangeSOPIN_NotConfigured tests ChangeSOPIN when
// no PINManager is set.
func TestP4B_PINService_ChangeSOPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	err := svc.ChangeSOPIN("old", "new")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

// TestP4B_PINService_ChangeSOPIN_ManagerError tests ChangeSOPIN with
// a manager error.
func TestP4B_PINService_ChangeSOPIN_ManagerError(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:       pin.StrategySoftware,
		changeSOPINErr: errors.New("pin mismatch"),
	}
	svc := newTestPINService(mgr)

	err := svc.ChangeSOPIN("old-pin-123", "new-pin-456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pin mismatch")
}

// TestP4B_PINService_VerifySOPIN_Success tests the VerifySOPIN success path.
func TestP4B_PINService_VerifySOPIN_Success(t *testing.T) {
	// mockPINBackend.VerifySOPIN always returns nil.
	mgr := &mockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestPINService(mgr)

	err := svc.VerifySOPIN("so-pin-value")
	assert.NoError(t, err)
}

// TestP4B_PINService_VerifySOPIN_NotConfigured tests VerifySOPIN when
// no PINManager is set.
func TestP4B_PINService_VerifySOPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	err := svc.VerifySOPIN("so-pin-value")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

// ===========================================================================
// Platform Policy Service - GetStatus, CreatePolicy, VerifyPolicy, savePolicy
// ===========================================================================

// TestP4B_PlatformPolicyService_GetStatus_WithPolicy tests GetStatus when
// a policy is stored but the TPM is unavailable for digest verification.
func TestP4B_PlatformPolicyService_GetStatus_WithPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabbccdd", 7: "11223344"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	svc.policy.Store(def)

	// No TPM accessor set, so verifyDigests will fail, valid should be false.
	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Configured)
	assert.Equal(t, []int{0, 7}, status.PCRs)
	assert.Equal(t, "sha256", status.Bank)
	assert.False(t, status.Valid) // TPM unavailable so verification fails
	assert.NotEmpty(t, status.CreatedAt)
	assert.NotEmpty(t, status.UpdatedAt)
}

// TestP4B_PlatformPolicyService_GetStatus_NoPolicy tests GetStatus with
// no policy configured.
func TestP4B_PlatformPolicyService_GetStatus_NoPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Configured)
}

// TestP4B_PlatformPolicyService_GetStatus_WithTPM tests GetStatus when
// a TPM mock is available and digests match.
func TestP4B_PlatformPolicyService_GetStatus_WithTPM(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

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
	assert.True(t, status.Valid)
}

// TestP4B_PlatformPolicyService_CreatePolicy_InvalidPCRs tests
// CreatePolicy with empty PCR selection.
func TestP4B_PlatformPolicyService_CreatePolicy_InvalidPCRs(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	_, err := svc.CreatePolicy(nil, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	_, err = svc.CreatePolicy([]int{}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

// TestP4B_PlatformPolicyService_CreatePolicy_InvalidPCRIndex tests
// CreatePolicy with an out-of-range PCR index.
func TestP4B_PlatformPolicyService_CreatePolicy_InvalidPCRIndex(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	_, err := svc.CreatePolicy([]int{24}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	_, err = svc.CreatePolicy([]int{-1}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

// TestP4B_PlatformPolicyService_CreatePolicy_InvalidBank tests
// CreatePolicy with an invalid bank name.
func TestP4B_PlatformPolicyService_CreatePolicy_InvalidBank(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	_, err := svc.CreatePolicy([]int{0}, "md5")
	assert.ErrorIs(t, err, ErrPolicyInvalidBank)
}

// TestP4B_PlatformPolicyService_CreatePolicy_TPMSuccess tests CreatePolicy
// with a mock TPM that provides PCR values.
func TestP4B_PlatformPolicyService_CreatePolicy_TPMSuccess(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	status, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Configured)
	assert.True(t, status.Valid)
	assert.Equal(t, []int{0, 7}, status.PCRs)
	assert.Equal(t, "sha256", status.Bank)
	assert.NotEmpty(t, status.CreatedAt)
}

// TestP4B_PlatformPolicyService_VerifyPolicy_NotConfigured tests
// VerifyPolicy when no policy is stored.
func TestP4B_PlatformPolicyService_VerifyPolicy_NotConfigured(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

// TestP4B_PlatformPolicyService_VerifyPolicy_Match tests VerifyPolicy
// when the stored digests match the TPM PCR values.
func TestP4B_PlatformPolicyService_VerifyPolicy_Match(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabbccdd", 7: "11223344"},
	}
	svc.policy.Store(def)

	valid, err := svc.VerifyPolicy()
	require.NoError(t, err)
	assert.True(t, valid)
}

// TestP4B_PlatformPolicyService_VerifyPolicy_Mismatch tests VerifyPolicy
// when the stored digests do not match the TPM PCR values.
func TestP4B_PlatformPolicyService_VerifyPolicy_Mismatch(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "deadbeef"},
	}
	svc.policy.Store(def)

	valid, err := svc.VerifyPolicy()
	require.NoError(t, err)
	assert.False(t, valid)
}

// TestP4B_PlatformPolicyService_SavePolicy_WriteError tests savePolicy
// when the directory is not writable.
func TestP4B_PlatformPolicyService_SavePolicy_WriteError(t *testing.T) {
	// Use a read-only directory to cause write failure.
	roDir := filepath.Join(t.TempDir(), "readonly")
	require.NoError(t, os.MkdirAll(roDir, 0500))
	policyPath := filepath.Join(roDir, "subdir", "policy.json")

	svc := NewPlatformPolicyService(policyPath)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := svc.savePolicy(def)
	assert.ErrorIs(t, err, ErrPolicySaveFailed)
}

// TestP4B_PlatformPolicyService_SavePolicy_Success tests savePolicy
// writing and verifying the file content.
func TestP4B_PlatformPolicyService_SavePolicy_Success(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7, 14},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb", 7: "ccdd", 14: "eeff"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	err := svc.savePolicy(def)
	require.NoError(t, err)

	// Verify the file was created.
	data, readErr := os.ReadFile(policyPath)
	require.NoError(t, readErr)

	var loaded PlatformPolicyDefinition
	require.NoError(t, json.Unmarshal(data, &loaded))
	assert.Equal(t, []int{0, 7, 14}, loaded.PCRs)
	assert.Equal(t, "sha256", loaded.Bank)
	assert.Len(t, loaded.Digests, 3)
}

// TestP4B_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy_NoPolicy tests
// GetPlatformPolicyAsPCRPolicy when no policy is set.
func TestP4B_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy_NoPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	svc := NewPlatformPolicyService(policyPath)

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	assert.Nil(t, policy)
}

// TestP4B_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy_WithTPMMatch tests
// GetPlatformPolicyAsPCRPolicy when TPM digests match stored policy.
func TestP4B_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy_WithTPMMatch(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabbccdd", 7: "11223344"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "Platform Policy", policy.Name)
	assert.True(t, policy.IsPlatformPolicy)
	require.NotNil(t, policy.Valid)
	assert.True(t, *policy.Valid)
}
