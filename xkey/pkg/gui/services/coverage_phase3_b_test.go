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
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Setup Wizard Service - uncovered branches
// ===========================================================================

// TestP3B_ApplySetup_InitDataDirFuncError tests the data directory
// initialization failure path in ApplySetup (Step 3).
func TestP3B_ApplySetup_InitDataDirFuncError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("permission denied")
	})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
	})
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "data directory initialization failed"))
}

// TestP3B_ApplySetup_InitDataDirFuncSuccess tests the data directory
// initialization success path in ApplySetup (Step 3).
func TestP3B_ApplySetup_InitDataDirFuncSuccess(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})
	tw.svc.SetInitDataDirFunc(func() error { return nil })

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
}

// TestP3B_ApplySetup_PasswordStoreMode_AESSoftware_UseUserPinAsMaster tests
// the UseUserPinAsMaster branch in the aes_software password store mode.
func TestP3B_ApplySetup_PasswordStoreMode_AESSoftware_UseUserPinAsMaster(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:               "standalone",
		PasswordStoreMode:  "aes_software",
		EnableMasterPW:     false,
		UseUserPinAsMaster: true,
		SOPin:              testSOPin,
		UserPin:            testUserPin,
	})
	require.NoError(t, err)
	// Without barrier or platform policy services, setup still succeeds
	// but produces warnings about unavailable services.
	assert.True(t, result.Success)
	assert.Contains(t, result.Warnings, "platform policy service unavailable")
}

// TestP3B_ApplySetup_AutoUnseal_LUKSWithPolicy tests the auto-unseal
// path when LUKS storage is enabled with a platform policy.
func TestP3B_ApplySetup_AutoUnseal_LUKSNoAutoUnsealSvc(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		EnableAutoUnseal: true,
		EnableStorage:    true,
		StorageType:      "luks",
		StoragePass:      "long-passphrase-here",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Warnings, "auto-unseal service unavailable")
}

// TestP3B_ApplySetup_AutoUnseal_BarrierType tests that auto-unseal with
// barrier storage type does not produce warnings about auto-unseal service.
func TestP3B_ApplySetup_AutoUnseal_BarrierType(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		EnableAutoUnseal: true,
		StorageType:      "barrier",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
	// Barrier auto-unseal is handled inherently, no warning expected.
	assert.False(t, containsSubstring(result.Warnings, "auto-unseal"))
}

// TestP3B_ApplySetup_PINService_SetSOPINAndUserPIN tests the PIN
// configuration paths with a real PIN service mock.
func TestP3B_ApplySetup_PINService_SetSOPINAndUserPIN(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	mgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(mgr)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SetHierarchyAuth: true,
		SOPin:            testSOPin,
		UserPin:          testUserPin,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify event payload reflects PINs set.
	completedEvt := lastEventOfType(tw.eventLog, events.EventSetupCompleted)
	require.NotNil(t, completedEvt)
	payload, ok := completedEvt.Payload.(events.SetupCompletedPayload)
	require.True(t, ok)
	assert.True(t, payload.SOPINSet)
	assert.True(t, payload.UserPINSet)
}

// TestP3B_ApplySetup_PINService_SetSOPINError tests the SO PIN setup
// warning path when SetSOPIN returns an error.
func TestP3B_ApplySetup_PINService_SetSOPINError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	mgr := &mockPINBackend{
		strategy:    pin.StrategySoftware,
		setSOPINErr: errors.New("tpm failure"),
	}
	pinSvc := newTestPINService(mgr)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SetHierarchyAuth: true,
		SOPin:            testSOPin,
		UserPin:          testUserPin,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.True(t, containsSubstring(result.Warnings, "SO PIN setup"))
}

// TestP3B_ApplySetup_PINService_SetUserPINError tests the User PIN
// setup warning path when SetUserPIN returns an error.
func TestP3B_ApplySetup_PINService_SetUserPINError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	mgr := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		setUserPINErr: errors.New("pin validation failed"),
	}
	pinSvc := newTestPINService(mgr)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.True(t, containsSubstring(result.Warnings, "User PIN setup"))
}

// TestP3B_SkipSetup_InitDataDirFuncError tests that SkipSetup returns
// ErrSetupStorageFailed when initDataDirFunc fails.
func TestP3B_SkipSetup_InitDataDirFuncError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("cannot create directory")
	})

	err := tw.svc.SkipSetup()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

// TestP3B_SkipSetup_InitDataDirFuncSuccess tests that SkipSetup succeeds
// when initDataDirFunc succeeds.
func TestP3B_SkipSetup_InitDataDirFuncSuccess(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})
	tw.svc.SetInitDataDirFunc(func() error { return nil })

	err := tw.svc.SkipSetup()
	require.NoError(t, err)

	saved := tw.configFunc()
	assert.True(t, saved.SetupComplete)
}

// TestP3B_SetupWizard_SetConfigDir tests the SetConfigDir setter.
func TestP3B_SetupWizard_SetConfigDir(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigDir("/tmp/test-config")
	assert.Equal(t, "/tmp/test-config", svc.configDir)
}

// TestP3B_SetupWizard_SetInitDataDirFunc tests the SetInitDataDirFunc setter.
func TestP3B_SetupWizard_SetInitDataDirFunc(t *testing.T) {
	svc := NewSetupWizardService()
	called := false
	svc.SetInitDataDirFunc(func() error {
		called = true
		return nil
	})
	require.NotNil(t, svc.initDataDirFunc)
	err := svc.initDataDirFunc()
	require.NoError(t, err)
	assert.True(t, called)
}

// TestP3B_ApplySetup_BarrierAlreadyInit_WrongPassword tests that when
// the barrier is already initialized and the wizard re-runs with the
// wrong password, the unseal fallback fails and an error is returned.
func TestP3B_ApplySetup_BarrierAlreadyInit_WrongPassword(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	// Create a barrier service and initialize it so that a second init
	// will return ErrBarrierAlreadyInit.
	barrierDir := filepath.Join(t.TempDir(), "barrier-err")
	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	require.NoError(t, barrierSvc.Initialize("first-password", "software"))

	// Create a fresh barrier service pointing at the same directory so
	// Initialize sees the existing root key.
	barrierSvc2 := NewBarrierService(barrierDir, slog.Default())
	barrierSvc2.SetContext(context.Background())
	tw.svc.SetBarrierService(barrierSvc2)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		UserPin:         testUserPin,
		StorageType:     "barrier",
		BarrierPassword: "second-password",
	})
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "barrier unseal failed"))
}

// TestP3B_EmitProgress_NilEmitter tests that emitProgress does not
// panic when eventEmitter is nil.
func TestP3B_EmitProgress_NilEmitter(t *testing.T) {
	svc := NewSetupWizardService()
	// eventEmitter is nil, should not panic.
	svc.emitProgress(1, "test step")
	svc.emitSOProvisioningProgress(1, "test SO step")
	svc.emitUserOnboardingProgress(1, "test user step")
}

// TestP3B_EmitProgress_WithEmitter tests that emitProgress sends
// the correct progress event.
func TestP3B_EmitProgress_WithEmitter(t *testing.T) {
	svc := NewSetupWizardService()
	var received []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		received = append(received, e)
	})

	svc.emitProgress(3, "Creating encrypted storage")
	require.Len(t, received, 1)
	assert.Equal(t, events.EventSetupProgress, received[0].Type)
	payload, ok := received[0].Payload.(events.SetupProgressPayload)
	require.True(t, ok)
	assert.Equal(t, 3, payload.Step)
	assert.Equal(t, setupTotalSteps, payload.TotalStep)
	assert.Equal(t, "Creating encrypted storage", payload.Label)
}

// TestP3B_EmitSOProvisioningProgress_WithEmitter tests SO provisioning
// progress events.
func TestP3B_EmitSOProvisioningProgress_WithEmitter(t *testing.T) {
	svc := NewSetupWizardService()
	var received []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		received = append(received, e)
	})

	svc.emitSOProvisioningProgress(5, "Provisioning TPM keys")
	require.Len(t, received, 1)
	payload, ok := received[0].Payload.(events.SetupProgressPayload)
	require.True(t, ok)
	assert.Equal(t, 5, payload.Step)
	assert.Equal(t, soProvisioningTotalSteps, payload.TotalStep)
}

// TestP3B_EmitUserOnboardingProgress_WithEmitter tests user onboarding
// progress events.
func TestP3B_EmitUserOnboardingProgress_WithEmitter(t *testing.T) {
	svc := NewSetupWizardService()
	var received []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		received = append(received, e)
	})

	svc.emitUserOnboardingProgress(2, "Configuring User PIN")
	require.Len(t, received, 1)
	payload, ok := received[0].Payload.(events.SetupProgressPayload)
	require.True(t, ok)
	assert.Equal(t, 2, payload.Step)
	assert.Equal(t, userOnboardingTotalSteps, payload.TotalStep)
}

// TestP3B_GetStartupState_SetupCompleteStandalone tests the startup state
// when setup is complete in standalone mode.
func TestP3B_GetStartupState_SetupCompleteStandalone(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})
	// Use a clean temp dir so no stale HMAC file triggers enterprise mode.
	svc.SetConfigDir(t.TempDir())

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.SetupComplete)
	assert.False(t, state.EnterpriseMode)
	assert.Empty(t, state.EnterpriseWizardMode)
}

// TestP3B_GetStartupState_NotComplete_NoEnterprise tests the startup state
// when setup is not complete and not in enterprise mode without configDir.
func TestP3B_GetStartupState_NotComplete_NoEnterprise(t *testing.T) {
	// Change to a clean temp dir so that IsEnterpriseMode("") does not
	// find a stale xkey_policy.hmac in the package directory.
	t.Chdir(t.TempDir())

	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})
	// No configDir set.

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
	assert.False(t, state.EnterpriseMode)
	// No configDir -> EnterpriseWizardMode stays empty.
	assert.Empty(t, state.EnterpriseWizardMode)
}

// TestP3B_GetStartupState_NotComplete_WithConfigDir tests the startup state
// when setup is not complete and configDir is set (SO provisioning mode).
func TestP3B_GetStartupState_NotComplete_WithConfigDir(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})
	// configDir is set to a directory without an HMAC file (no enterprise mode).
	svc.SetConfigDir(t.TempDir())

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
	assert.False(t, state.EnterpriseMode)
	assert.Equal(t, "so_provisioning", state.EnterpriseWizardMode)
}

// TestP3B_GetStartupState_WithPINService tests the startup state when a
// PIN service is available.
func TestP3B_GetStartupState_WithPINService(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})

	mgr := &mockPINBackend{
		strategy:   pin.StrategySoftware,
		soPINSet:   true,
		userPINSet: true,
	}
	pinSvc := newTestPINService(mgr)
	svc.SetPINService(pinSvc)

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.SOPINSet)
	assert.True(t, state.UserPINSet)
}

// TestP3B_GetStartupState_NilConfigFunc tests GetStartupState when
// configFunc is nil.
func TestP3B_GetStartupState_NilConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	// configFunc is nil.

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
}

// TestP3B_GetStartupState_NilConfigResult tests GetStartupState when
// configFunc returns nil.
func TestP3B_GetStartupState_NilConfigResult(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData { return nil })

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
}

// ===========================================================================
// Storage Service - uncovered branches
// ===========================================================================

// TestP3B_StorageService_ValidateVolumeSize tests volume size validation.
func TestP3B_StorageService_ValidateVolumeSize(t *testing.T) {
	tests := []struct {
		name    string
		sizeGB  int
		wantErr bool
	}{
		{"valid minimum", 1, false},
		{"valid maximum", 100, false},
		{"valid middle", 50, false},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too large", 101, true},
		{"way too large", 1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVolumeSize(tt.sizeGB)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrStorageInvalidSize)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestP3B_StorageService_ValidatePassphrase tests passphrase validation.
func TestP3B_StorageService_ValidatePassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		wantErr    bool
	}{
		{"valid", "12345678", false},
		{"valid long", "this-is-a-very-long-passphrase", false},
		{"too short", "1234567", true},
		{"empty", "", true},
		{"exactly 8", "abcdefgh", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassphrase(tt.passphrase)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestP3B_StorageService_RunElevatedCmd_NilElevator tests that
// runElevatedCmd returns ErrStorageRequiresRoot when elevator is nil.
func TestP3B_StorageService_RunElevatedCmd_NilElevator(t *testing.T) {
	svc := NewStorageService()
	err := svc.runElevatedCmd([]string{"luks2", "seal"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

// TestP3B_StorageService_RunElevatedCmd_UnavailableElevator tests that
// runElevatedCmd returns ErrStorageRequiresRoot when elevator is not available.
func TestP3B_StorageService_RunElevatedCmd_UnavailableElevator(t *testing.T) {
	svc := NewStorageService()
	svc.SetElevator(&p3bMockElevator{available: false})
	err := svc.runElevatedCmd([]string{"luks2", "seal"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

// TestP3B_StorageService_RunElevatedCmd_ElevatorRunError tests that
// runElevatedCmd returns the error from the elevator Run call.
func TestP3B_StorageService_RunElevatedCmd_ElevatorRunError(t *testing.T) {
	runErr := errors.New("sudo failed")
	svc := NewStorageService()
	svc.SetElevator(&p3bMockElevator{available: true, runErr: runErr})
	err := svc.runElevatedCmd([]string{"luks2", "seal"}, nil)
	assert.Equal(t, runErr, err)
}

// TestP3B_StorageService_RunElevatedCmd_Success tests the success path.
func TestP3B_StorageService_RunElevatedCmd_Success(t *testing.T) {
	svc := NewStorageService()
	svc.SetElevator(&p3bMockElevator{available: true})
	err := svc.runElevatedCmd([]string{"luks2", "seal"}, []byte("data"))
	assert.NoError(t, err)
}

// TestP3B_StorageService_WipeVolume_InvalidStandard tests WipeVolume
// with an invalid standard name.
func TestP3B_StorageService_WipeVolume_InvalidStandard(t *testing.T) {
	svc := NewStorageService()
	err := svc.WipeVolume("invalid-standard")
	assert.ErrorIs(t, err, ErrStorageInvalidStandard)
}

// TestP3B_StorageService_WipeVolume_ValidStandards tests that valid
// standard names pass validation (non-root path).
func TestP3B_StorageService_WipeVolume_ValidStandards(t *testing.T) {
	// Not running as root, so this will try elevated path which requires
	// elevator to be set.
	if os.Geteuid() == 0 {
		t.Skip("test must not run as root")
	}
	svc := NewStorageService()

	for _, std := range []string{"nist", "dod3", "dod7"} {
		t.Run(std, func(t *testing.T) {
			err := svc.WipeVolume(std)
			// Should fail with ErrStorageRequiresRoot (no elevator), not
			// ErrStorageInvalidStandard.
			assert.ErrorIs(t, err, ErrStorageRequiresRoot)
		})
	}
}

// TestP3B_StorageService_SetContext tests SetContext.
func TestP3B_StorageService_SetContext(t *testing.T) {
	svc := NewStorageService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

// TestP3B_StorageService_SetElevator tests SetElevator.
func TestP3B_StorageService_SetElevator(t *testing.T) {
	svc := NewStorageService()
	assert.Nil(t, svc.elevator)
	e := &p3bMockElevator{available: true}
	svc.SetElevator(e)
	assert.NotNil(t, svc.elevator)
}

// p3bMockElevator implements the Elevator interface for testing.
type p3bMockElevator struct {
	available bool
	runErr    error
	runOut    []byte
}

func (m *p3bMockElevator) IsAvailable() bool { return m.available }
func (m *p3bMockElevator) Run(args []string, stdin []byte) ([]byte, error) {
	return m.runOut, m.runErr
}

// ===========================================================================
// PIN Service - uncovered branches
// ===========================================================================

// TestP3B_PINService_VerifyUserPIN_NotConfigured tests VerifyUserPIN
// when the manager is not set.
func TestP3B_PINService_VerifyUserPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	err := svc.VerifyUserPIN("some-pin")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

// TestP3B_PINService_VerifyUserPIN_ManagerError tests VerifyUserPIN
// when the manager returns an error.
func TestP3B_PINService_VerifyUserPIN_ManagerError(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		verifyUserErr: pin.ErrPINInvalid,
	}
	svc := newTestPINService(mgr)
	err := svc.VerifyUserPIN("wrong-pin")
	assert.ErrorIs(t, err, pin.ErrPINInvalid)
}

// TestP3B_PINService_VerifyUserPIN_Success tests VerifyUserPIN success.
func TestP3B_PINService_VerifyUserPIN_Success(t *testing.T) {
	mgr := &mockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestPINService(mgr)
	err := svc.VerifyUserPIN("correct-pin")
	assert.NoError(t, err)
}

// TestP3B_PINService_GetLockoutStatus_NotConfigured tests GetLockoutStatus
// when the manager is not set.
func TestP3B_PINService_GetLockoutStatus_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	status, err := svc.GetLockoutStatus()
	assert.Nil(t, status)
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

// TestP3B_PINService_GetLockoutStatus_Success tests GetLockoutStatus
// when a lockout status is available.
func TestP3B_PINService_GetLockoutStatus_Success(t *testing.T) {
	lockoutSt := &pin.LockoutStatus{
		IsLocked:        false,
		FailedAttempts:  2,
		MaxAttempts:     5,
		RecoverySeconds: 300,
	}
	mgr := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		lockoutStatus: lockoutSt,
	}
	svc := newTestPINService(mgr)
	status, err := svc.GetLockoutStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, 5, status.MaxAttempts)
	assert.Equal(t, 2, status.FailedAttempts)
	assert.False(t, status.IsLocked)
	assert.Equal(t, 300, status.RecoverySeconds)
}

// TestP3B_PINService_ResetLockout_NotConfigured tests ResetLockout
// when the manager is not set.
func TestP3B_PINService_ResetLockout_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	err := svc.ResetLockout("so-pin")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

// TestP3B_PINService_ResetLockout_ManagerError tests ResetLockout
// when the manager returns an error.
func TestP3B_PINService_ResetLockout_ManagerError(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:        pin.StrategySoftware,
		resetLockoutErr: errors.New("lockout reset failed"),
	}
	svc := newTestPINService(mgr)
	err := svc.ResetLockout("so-pin")
	assert.Error(t, err)
}

// TestP3B_PINService_ResetLockout_Success tests ResetLockout success.
func TestP3B_PINService_ResetLockout_Success(t *testing.T) {
	mgr := &mockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestPINService(mgr)
	err := svc.ResetLockout("so-pin")
	assert.NoError(t, err)
}

// ===========================================================================
// Barrier Service - uncovered branches
// ===========================================================================

// TestP3B_BarrierService_Initialize_EmptyPassword_WithTPMAvailable tests
// that Initialize succeeds without a password when TPM strategy is the
// best available (hardware-backed).
func TestP3B_BarrierService_Initialize_EmptyPassword_WithTPM(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetContext(context.Background())
	svc.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: true}
	})

	// TPM is best strategy (hardware-backed), so empty password is acceptable.
	err := svc.Initialize("", "tpm2")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed())
}

// TestP3B_BarrierService_Unseal_ReinitAfterSeal tests the full
// init -> seal -> unseal lifecycle.
func TestP3B_BarrierService_Unseal_ReinitAfterSeal(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	pw := "test-barrier-pw"
	require.NoError(t, svc.Initialize(pw, "software"))
	assert.True(t, svc.IsUnsealed())

	require.NoError(t, svc.Seal())
	assert.False(t, svc.IsUnsealed())

	// Create a fresh service pointing to the same directory.
	svc2 := NewBarrierService(dir, slog.Default())
	svc2.SetContext(context.Background())
	require.NoError(t, svc2.Unseal(pw, "software"))
	assert.True(t, svc2.IsUnsealed())
}

// TestP3B_BarrierService_GetBackend_NilBarrier tests that GetBackend
// returns nil when the barrier is not initialized.
func TestP3B_BarrierService_GetBackend_NilBarrier(t *testing.T) {
	svc := newTestBarrierService(t)
	backend := svc.GetBackend()
	assert.Nil(t, backend)
}

// TestP3B_BarrierService_GetBackend_Initialized tests that GetBackend
// returns a non-nil backend after initialization.
func TestP3B_BarrierService_GetBackend_Initialized(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("test-password", "software"))
	backend := svc.GetBackend()
	assert.NotNil(t, backend)
}

// TestP3B_BarrierService_Status_Initialized tests barrier status after init.
func TestP3B_BarrierService_Status_Initialized(t *testing.T) {
	svc := newTestBarrierService(t)
	require.NoError(t, svc.Initialize("test-password", "software"))

	status := svc.Status()
	require.NotNil(t, status)
	assert.False(t, status.Sealed, "should be unsealed after init")
}

// TestP3B_BarrierService_Seal_NotInitialized tests Seal when barrier is nil.
func TestP3B_BarrierService_Seal_NotInitialized(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.Seal()
	assert.ErrorIs(t, err, ErrBarrierNotInitialized)
}

// ===========================================================================
// Connection Service - uncovered branches
// ===========================================================================

// TestP3B_ConnectionService_Connect_ValidProtocols tests Connect with
// each valid protocol to exercise protocol validation and the protocol
// dispatch code path. gRPC uses lazy connections so it may not fail
// immediately; we accept both outcomes.
func TestP3B_ConnectionService_Connect_ValidProtocols(t *testing.T) {
	protocols := []string{"unix", "rest", "grpc", "quic", "mcp"}
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			svc := NewConnectionService()
			svc.SetContext(context.Background())

			// Verify the protocol passes validation by checking no
			// ErrInvalidProtocol is returned. Some transports (gRPC)
			// use lazy connections and may succeed without a real server.
			info, err := svc.Connect(proto, "localhost:9443", false, "", "")
			assert.NotErrorIs(t, err, ErrInvalidProtocol)
			require.NotNil(t, info)
			assert.Equal(t, proto, info.Protocol)

			// Clean up if the connection succeeded.
			if err == nil {
				_ = svc.Disconnect()
			}
		})
	}
}

// TestP3B_ConnectionService_SetErrorState_Stores tests that setErrorState
// properly stores the error state and emits the event.
func TestP3B_ConnectionService_SetErrorState_OperationTypes(t *testing.T) {
	operations := []string{"connect", "health_check", "custom_op"}
	for _, op := range operations {
		t.Run(op, func(t *testing.T) {
			svc := NewConnectionService()
			var received []events.Event
			svc.SetEventEmitter(func(e events.Event) {
				received = append(received, e)
			})

			testErr := errors.New("test failure")
			info := svc.setErrorState("grpc", "host:443", true, op, testErr)

			assert.Equal(t, "error", info.State)
			assert.Equal(t, "test failure", info.Error)

			require.Len(t, received, 1)
			payload, ok := received[0].Payload.(events.ServerErrorPayload)
			require.True(t, ok)
			assert.Equal(t, op, payload.Operation)
		})
	}
}

// ===========================================================================
// Clipboard Service - uncovered branches
// ===========================================================================

// TestP3B_ClipboardService_ScheduleClear_CancelsPrevious tests that
// scheduleClear cancels any previously pending clear timer.
func TestP3B_ClipboardService_ScheduleClear_CancelsPrevious(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone // Prevent actual clipboard operations.

	// Set a first cancel function.
	firstCancelled := false
	svc.clearMu.Lock()
	svc.cancelFn = func() { firstCancelled = true }
	svc.clearMu.Unlock()

	// Schedule a new clear, which should cancel the first.
	svc.scheduleClear("test-text", 1*time.Hour) // Long delay so it doesn't fire.

	assert.True(t, firstCancelled, "previous cancel function should have been called")
}

// TestP3B_ClipboardService_ScheduleClear_ContextCancel tests that
// cancelling the context stops the scheduled clear goroutine.
func TestP3B_ClipboardService_ScheduleClear_ContextCancel(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	svc.scheduleClear("test-text", 10*time.Second)

	// Cancel immediately.
	svc.clearMu.Lock()
	if svc.cancelFn != nil {
		svc.cancelFn()
	}
	svc.clearMu.Unlock()

	// Give the goroutine time to exit.
	time.Sleep(50 * time.Millisecond)
	// If we get here without hanging, the goroutine properly exited.
}

// TestP3B_ClipboardService_WriteClipboard_AllToolPaths tests the default
// case in writeClipboard.
func TestP3B_ClipboardService_WriteClipboard_DefaultCase(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	err := svc.writeClipboard("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestP3B_ClipboardService_ReadClipboard_DefaultCase tests the default
// case in readClipboard.
func TestP3B_ClipboardService_ReadClipboard_DefaultCase(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	result, err := svc.readClipboard()
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// ===========================================================================
// OATH Service - uncovered branches
// ===========================================================================

// TestP3B_OATHService_GenerateHOTP_NonExistentAccount tests GenerateHOTP
// with an account ID that does not exist.
func TestP3B_OATHService_GenerateHOTP_NonExistentAccount(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("non-existent-id")
	assert.Error(t, err)
}

// TestP3B_OATHService_GenerateTOTP_NonExistentAccount tests GenerateTOTP
// with an account ID that does not exist.
func TestP3B_OATHService_GenerateTOTP_NonExistentAccount(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	_, err := svc.GenerateTOTP("non-existent-id")
	assert.Error(t, err)
}

// TestP3B_OATHService_SetStore_ReplaceNil tests that SetStore can replace
// a nil store with a working store and operations succeed afterward.
func TestP3B_OATHService_SetStore_ReplaceNil(t *testing.T) {
	svc := NewOATHService(nil)

	// Operations fail with nil store.
	_, err := svc.ListAccounts()
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)

	// Set a real store.
	store := oath.NewMemoryStore()
	svc.SetStore(store)

	// Operations succeed.
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	assert.Empty(t, accounts)

	uri := "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&issuer=Test"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)
	assert.Equal(t, "Test", acct.Issuer)
}

// TestP3B_CredentialToAccount_FieldMapping tests that credentialToAccount
// properly maps all fields from a Credential to an OATHAccount.
func TestP3B_CredentialToAccount_FieldMapping(t *testing.T) {
	now := time.Now()
	cred := &oath.Credential{
		ID:          "test-id-123",
		Name:        "Test Account",
		Issuer:      "TestIssuer",
		AccountName: "user@test.com",
		Type:        "totp",
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
		Counter:     42,
		CreatedAt:   now,
	}

	acct := credentialToAccount(cred)
	assert.Equal(t, "test-id-123", acct.ID)
	assert.Equal(t, "Test Account", acct.Name)
	assert.Equal(t, "TestIssuer", acct.Issuer)
	assert.Equal(t, "user@test.com", acct.AccountName)
	assert.Equal(t, "totp", acct.Type)
	assert.Equal(t, "SHA1", acct.Algorithm)
	assert.Equal(t, 6, acct.Digits)
	assert.Equal(t, 30, acct.Period)
	assert.Equal(t, uint64(42), acct.Counter)
	assert.Equal(t, now, acct.CreatedAt)
}

// ===========================================================================
// Seal Service - uncovered branches
// ===========================================================================

// TestP3B_SealService_EnsureStorageDir_Empty tests ensureStorageDir
// when storageDir is empty.
func TestP3B_SealService_EnsureStorageDir_Empty(t *testing.T) {
	svc := NewSealService("")
	err := svc.ensureStorageDir()
	assert.ErrorIs(t, err, ErrSealStorageDirNotSet)
}

// TestP3B_SealService_EnsureStorageDir_Relative tests ensureStorageDir
// when storageDir is a relative path.
func TestP3B_SealService_EnsureStorageDir_Relative(t *testing.T) {
	svc := NewSealService("relative/path")
	err := svc.ensureStorageDir()
	assert.ErrorIs(t, err, ErrSealStorageDirRelative)
}

// TestP3B_SealService_EnsureStorageDir_Valid tests ensureStorageDir
// with a valid absolute path.
func TestP3B_SealService_EnsureStorageDir_Valid(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seal-storage")
	svc := NewSealService(dir)
	err := svc.ensureStorageDir()
	assert.NoError(t, err)

	// Directory should now exist.
	info, statErr := os.Stat(dir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

// TestP3B_SealService_DeleteBlob_EmptyID tests DeleteBlob with empty ID.
func TestP3B_SealService_DeleteBlob_EmptyID(t *testing.T) {
	svc := NewSealService(t.TempDir())
	err := svc.DeleteBlob("")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// TestP3B_SealService_DeleteBlob_NonExistent tests DeleteBlob with a
// non-existent ID.
func TestP3B_SealService_DeleteBlob_NonExistent(t *testing.T) {
	svc := NewSealService(t.TempDir())
	err := svc.DeleteBlob("non-existent-blob-id")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// REMOVED: TestP3B_SealService_DeleteBlob_Success tests the full seal -> delete lifecycle. (uses removed RegisterSealer API)

// TestP3B_SealService_UnsealData_EmptyID tests UnsealData with empty ID.
func TestP3B_SealService_UnsealData_EmptyID(t *testing.T) {
	svc := NewSealService(t.TempDir())
	result, err := svc.UnsealData("", "")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// TestP3B_SealService_UnsealData_NonExistent tests UnsealData with a
// non-existent blob ID.
func TestP3B_SealService_UnsealData_NonExistent(t *testing.T) {
	svc := NewSealService(t.TempDir())
	result, err := svc.UnsealData("non-existent-id", "")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// TestP3B_SealService_SealData_NilRequest tests SealData with nil request.
func TestP3B_SealService_SealData_NilRequest(t *testing.T) {
	svc := NewSealService(t.TempDir())
	entry, err := svc.SealData(nil)
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)
}

// TestP3B_SealService_SealData_EmptyLabel tests SealData with empty label.
func TestP3B_SealService_SealData_EmptyLabel(t *testing.T) {
	svc := NewSealService(t.TempDir())
	entry, err := svc.SealData(&SealRequest{Data: "dGVzdA=="})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)
}

// TestP3B_SealService_SealData_EmptyData tests SealData with empty data.
func TestP3B_SealService_SealData_EmptyData(t *testing.T) {
	svc := NewSealService(t.TempDir())
	entry, err := svc.SealData(&SealRequest{Label: "test"})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealInvalidData)
}

// TestP3B_SealService_SealData_InvalidBase64 tests SealData with
// invalid base64 data.
func TestP3B_SealService_SealData_InvalidBase64(t *testing.T) {
	svc := NewSealService(t.TempDir())
	entry, err := svc.SealData(&SealRequest{
		Label: "test",
		Data:  "not-valid-base64!!!",
	})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealDecodeFailed)
}

// TestP3B_SealService_SealData_BackendNotFound tests SealData when the
// specified backend is not registered.
func TestP3B_SealService_SealData_BackendNotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	entry, err := svc.SealData(&SealRequest{
		Label:   "test",
		Data:    base64.StdEncoding.EncodeToString([]byte("data")),
		Backend: "nonexistent",
	})
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, ErrSealBackendNotFound)
}

// REMOVED: TestP3B_SealService_SealData_CannotSeal tests SealData when the (uses removed RegisterSealer API)

// REMOVED: TestP3B_SealService_SealData_InvalidPolicyType tests SealData with an (uses removed RegisterSealer API)

// REMOVED: TestP3B_SealService_SealData_PasswordPolicyNoPassword tests SealData (uses removed RegisterSealer API)

// REMOVED: TestP3B_SealService_SealData_PasswordPolicyWithPassword tests the (uses removed RegisterSealer API)

// TestP3B_SealService_ListBlobs_Empty tests ListBlobs with no blobs.
func TestP3B_SealService_ListBlobs_Empty(t *testing.T) {
	svc := NewSealService(t.TempDir())
	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

// REMOVED: TestP3B_SealService_ListBlobs_WithBlobs tests ListBlobs returns sorted blobs. (uses removed RegisterSealer API)

// TestP3B_SealService_ListBlobs_InvalidJSON tests that ListBlobs skips
// files with invalid JSON.
func TestP3B_SealService_ListBlobs_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	// Write an invalid JSON file.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "bad-blob.json"),
		[]byte("not-json"),
		0600,
	))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs) // Invalid file should be skipped.
}

// TestP3B_SealService_ListBlobs_SkipsDirectories tests that ListBlobs
// ignores subdirectories.
func TestP3B_SealService_ListBlobs_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	// Create a subdirectory.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0700))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

// TestP3B_SealService_ListBlobs_SkipsNonJSON tests that ListBlobs
// ignores non-JSON files.
func TestP3B_SealService_ListBlobs_SkipsNonJSON(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	// Write a non-JSON file.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "readme.txt"),
		[]byte("not a blob"),
		0600,
	))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

// TestP3B_SealService_ListBlobs_EmptyStorageDir tests ListBlobs when
// storageDir is empty.
func TestP3B_SealService_ListBlobs_EmptyStorageDir(t *testing.T) {
	svc := NewSealService("")
	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

// TestP3B_SealService_ListBlobs_CategoryClassification tests that blobs
// get properly categorized as system or user.
func TestP3B_SealService_ListBlobs_CategoryClassification(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	// Write a blob with a system label.
	systemBlob := &sealedBlobStorage{
		ID:         "sys-001",
		Label:      "user_pin",
		SizeBytes:  32,
		SealedData: &types.SealedData{Backend: types.BackendTypeTPM2},
		CreatedAt:  time.Now(),
	}
	data, err := json.Marshal(systemBlob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "sys-001.json"),
		data, 0600,
	))

	// Write a blob with a user label.
	userBlob := &sealedBlobStorage{
		ID:         "usr-001",
		Label:      "my-secret-note",
		SizeBytes:  64,
		SealedData: &types.SealedData{Backend: types.BackendTypeTPM2},
		CreatedAt:  time.Now(),
	}
	data, err = json.Marshal(userBlob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "usr-001.json"),
		data, 0600,
	))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, blobs, 2)

	categoryMap := make(map[string]string)
	for _, b := range blobs {
		categoryMap[b.Label] = b.Category
	}
	assert.Equal(t, "user", categoryMap["user_pin"])
	assert.Equal(t, "user", categoryMap["my-secret-note"])
}

// TestP3B_ClassifyCategory tests the classifyCategory helper for all
// known system labels and a user label.
func TestP3B_ClassifyCategory(t *testing.T) {
	systemLabels := []string{"password_master_key", "auto-unseal-passphrase"}
	for _, label := range systemLabels {
		assert.Equal(t, "system", classifyCategory(label), "expected %q to be system", label)
	}

	// user_pin is user-category so it can be deleted from the Sealed Data UI.
	assert.Equal(t, "user", classifyCategory("user_pin"))

	userLabels := []string{"my-secret", "backup-key", "notes", ""}
	for _, label := range userLabels {
		assert.Equal(t, "user", classifyCategory(label), "expected %q to be user", label)
	}
}

// TestP3B_SplitPasswordHash tests the splitPasswordHash helper.
func TestP3B_SplitPasswordHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
		parts []string
		isNil bool
	}{
		{"valid", "abc:def", []string{"abc", "def"}, false},
		{"no colon", "abcdef", nil, true},
		{"empty", "", nil, true},
		{"colon at start", ":value", []string{"", "value"}, false},
		{"colon at end", "key:", []string{"key", ""}, false},
		{"multiple colons", "a:b:c", []string{"a", "b:c"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitPasswordHash(tt.input)
			if tt.isNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.parts, result)
			}
		})
	}
}

// TestP3B_HashAndVerifyPassword tests the hash/verify password round trip.
func TestP3B_HashAndVerifyPassword(t *testing.T) {
	password := "test-password-123"
	hash, err := hashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify correct password.
	assert.True(t, verifyPassword(password, hash))

	// Verify wrong password.
	assert.False(t, verifyPassword("wrong-password", hash))

	// Verify with invalid hash format.
	assert.False(t, verifyPassword(password, "no-colon-here"))
	assert.False(t, verifyPassword(password, ""))

	// Verify with invalid hex in salt.
	assert.False(t, verifyPassword(password, "ZZZZ:aabb"))

	// Verify with invalid hex in hash.
	assert.False(t, verifyPassword(password, "aabb:ZZZZ"))
}

// TestP3B_SealService_CanSeal_NoBackend tests CanSeal when the default
// backend is not registered.
func TestP3B_SealService_CanSeal_NoBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetDefaultBackend("nonexistent")
	canSeal, err := svc.CanSeal()
	require.NoError(t, err)
	assert.False(t, canSeal)
}

// REMOVED: TestP3B_SealService_CanSeal_BackendCannotSeal tests CanSeal when the (uses removed RegisterSealer API)

// REMOVED: TestP3B_SealService_CanSeal_Success tests CanSeal success. (uses removed RegisterSealer API)

// REMOVED: TestP3B_SealService_SealData_TPMOnlyPolicyOnNonTPMBackend tests that (uses removed RegisterSealer API)

// REMOVED: TestP3B_SealService_SealData_CustomPCRPolicyOnNonTPMBackend tests that (uses removed RegisterSealer API)

// TestP3B_HandlePolicyNone_NoOp tests that handlePolicyNone returns nil.
func TestP3B_HandlePolicyNone_NoOp(t *testing.T) {
	err := handlePolicyNone(nil, nil, nil)
	assert.NoError(t, err)
}

// TestP3B_HandlePolicyPassword_EmptyPassword tests handlePolicyPassword
// with an empty password.
func TestP3B_HandlePolicyPassword_EmptyPassword(t *testing.T) {
	err := handlePolicyPassword(nil, &SealRequest{Password: ""}, nil)
	assert.ErrorIs(t, err, ErrSealPasswordRequired)
}

// TestP3B_HandlePolicyPassword_WithPassword tests handlePolicyPassword
// with a valid password.
func TestP3B_HandlePolicyPassword_WithPassword(t *testing.T) {
	err := handlePolicyPassword(nil, &SealRequest{Password: "secret"}, nil)
	assert.NoError(t, err)
}

// TestP3B_HandlePolicyCustomPCR_NoPCRs tests handlePolicyCustomPCR
// with no PCRs (returns nil, no-op).
func TestP3B_HandlePolicyCustomPCR_NoPCRs(t *testing.T) {
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, &SealRequest{}, opts)
	assert.NoError(t, err)
	assert.Nil(t, opts.TPMPolicy)
}

// TestP3B_HandlePolicyCustomPCR_WithPCRs tests handlePolicyCustomPCR
// with specific PCRs and bank.
func TestP3B_HandlePolicyCustomPCR_WithPCRs(t *testing.T) {
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, &SealRequest{
		PCRs:    []int{0, 7, 9},
		PCRBank: "sha256",
	}, opts)
	assert.NoError(t, err)
	require.NotNil(t, opts.TPMPolicy)
}

// TestP3B_HandlePolicyCustomPCR_DefaultBank tests handlePolicyCustomPCR
// with an empty bank (defaults to sha256).
func TestP3B_HandlePolicyCustomPCR_DefaultBank(t *testing.T) {
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, &SealRequest{
		PCRs:    []int{0},
		PCRBank: "",
	}, opts)
	assert.NoError(t, err)
	require.NotNil(t, opts.TPMPolicy)
}

// TestP3B_HandlePolicyCustomPCR_UnknownBank tests handlePolicyCustomPCR
// with an unknown bank name (should default to SHA256 alg).
func TestP3B_HandlePolicyCustomPCR_UnknownBank(t *testing.T) {
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, &SealRequest{
		PCRs:    []int{0},
		PCRBank: "unknown-bank",
	}, opts)
	assert.NoError(t, err)
	require.NotNil(t, opts.TPMPolicy)
}

// TestP3B_HandlePolicyPlatformPolicy_NilPolicyService tests
// handlePolicyPlatformPolicy when policyService is nil.
func TestP3B_HandlePolicyPlatformPolicy_NilPolicyService(t *testing.T) {
	svc := NewSealService(t.TempDir())
	err := handlePolicyPlatformPolicy(svc, &SealRequest{}, &types.SealOptions{})
	assert.ErrorIs(t, err, ErrSealPolicyNotAvailable)
}
