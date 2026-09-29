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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
		strategy:    qrdbsdk.PINStrategySoftware,
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
		strategy:    qrdbsdk.PINStrategyTPM2,
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
	mgr := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
	svc := newTestPINService(mgr)

	err := svc.SetSOPIN("", "new-so-pin")
	assert.NoError(t, err)
}

// TestP4B_PINService_SetSOPIN_ManagerError tests SetSOPIN with a manager error.
func TestP4B_PINService_SetSOPIN_ManagerError(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    qrdbsdk.PINStrategySoftware,
		setSOPINErr: errors.New("tpm locked"),
	}
	svc := newTestPINService(mgr)

	err := svc.SetSOPIN("", "new-so-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tpm locked")
}

// TestP4B_PINService_ChangeSOPIN_Success tests the ChangeSOPIN success path.
func TestP4B_PINService_ChangeSOPIN_Success(t *testing.T) {
	mgr := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
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
		strategy:       qrdbsdk.PINStrategySoftware,
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
	mgr := &mockPINBackend{strategy: qrdbsdk.PINStrategySoftware}
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
