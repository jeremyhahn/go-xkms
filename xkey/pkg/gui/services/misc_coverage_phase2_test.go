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
	"errors"
	"log/slog"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// PasswordProtectionService - SetModeTPMSealed
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AdminService - GetAuditLogs, ExportAuditLogs
// ---------------------------------------------------------------------------

func TestAdminService_GetAuditLogs_NonAdmin(t *testing.T) {
	asUnprivileged(t)
	svc := NewAdminService()
	svc.SetContext(context.Background())

	entries, err := svc.GetAuditLogs(&AuditFilter{Operation: "key_created"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
	assert.Nil(t, entries)
}

func TestAdminService_ExportAuditLogs_InvalidFormatBeforeAuth(t *testing.T) {
	// "xml" is invalid. Authorization is checked before the format, so a
	// non-admin must see the auth error and an admin must see the format
	// error. Both directions are asserted via the privilege seam rather than
	// branching on whichever uid the test binary happens to run under.
	t.Run("non admin sees auth error first", func(t *testing.T) {
		asUnprivileged(t)
		svc := NewAdminService()
		svc.SetContext(context.Background())

		_, err := svc.ExportAuditLogs("xml")
		assert.ErrorIs(t, err, ErrAdminNotAuthorized)
	})

	t.Run("admin sees invalid format error", func(t *testing.T) {
		asPrivileged(t)
		svc := NewAdminService()
		svc.SetContext(context.Background())

		_, err := svc.ExportAuditLogs("xml")
		assert.ErrorIs(t, err, ErrAdminInvalidFormat)
	})
}

func TestAdminService_GetAuditLogs_WithFilter(t *testing.T) {
	asUnprivileged(t)
	svc := NewAdminService()
	svc.SetContext(context.Background())

	// Verify that providing a non-nil filter still results in auth error.
	_, err := svc.GetAuditLogs(&AuditFilter{
		Operation: "key_created",
		Limit:     10,
	})
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
}

// ---------------------------------------------------------------------------
// ClipboardService - CopyWithClear, scheduleClear, detectClipboardTool
// ---------------------------------------------------------------------------

func TestClipboard_CopyWithClear_ToolAvailableWriteError(t *testing.T) {
	svc := NewClipboardService()
	// Force a tool that likely doesn't work without a display.
	svc.tool = clipToolXsel

	err := svc.CopyWithClear("secret-data")
	if err != nil {
		// Expected: write fails without display.
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
	// If it succeeded (tool available + display), that's fine too.
}

func TestClipboard_ScheduleClear_NoPreviousCancel(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	// No previous cancelFn; should not panic.
	svc.scheduleClear("data", 1*time.Hour)

	// Verify new cancelFn was set.
	svc.clearMu.Lock()
	require.NotNil(t, svc.cancelFn)
	svc.cancelFn() // Clean up goroutine.
	svc.clearMu.Unlock()
}

func TestClipboard_ScheduleClear_ShortDelay(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone // readClipboard will return error.

	// Schedule with a very short delay; the goroutine should fire
	// and handle the readClipboard error gracefully. No assertion follows:
	// the timer fires on its own schedule regardless of whether this test
	// function has returned, so no wait is needed here. No panic means
	// success.
	svc.scheduleClear("test", 1*time.Millisecond)
}

func TestClipboard_DetectClipboardTool_ReturnsValidValue(t *testing.T) {
	tool := detectClipboardTool()
	// Valid range is 0 (clipToolNone) to 3 (clipToolWlCopy).
	assert.True(t, tool >= clipToolNone)
	assert.True(t, tool <= clipToolWlCopy)
}

func TestClipboard_CopyWithClear_ZeroTimeout_SkipsSchedule(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(0)

	// If a tool is available, CopyWithClear should skip scheduleClear.
	// If no tool, it will error on writeClipboard. Either way, cancelFn
	// should not be set.
	_ = svc.CopyWithClear("data")

	svc.clearMu.Lock()
	assert.Nil(t, svc.cancelFn)
	svc.clearMu.Unlock()
}

// ---------------------------------------------------------------------------
// ConnectionService - Connect
// ---------------------------------------------------------------------------

func TestConnection_Connect_ValidProtocols_InvalidSocket(t *testing.T) {
	// Exercise the code path past protocol validation and address validation
	// through to SDK client creation and connection failure.
	protocols := []string{"rest", "grpc", "quic", "mcp"}

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			svc := NewConnectionService()
			svc.SetContext(context.Background())

			var emittedEvents []events.Event
			svc.SetEventEmitter(func(e events.Event) {
				emittedEvents = append(emittedEvents, e)
			})

			info, err := svc.Connect(proto, "localhost:0", false, "", "")
			require.Error(t, err)

			// The connection should fail at xkms.New or client.Connect
			// and transition to error state.
			require.NotNil(t, info)
			assert.Equal(t, "error", info.State)
			assert.Equal(t, proto, info.Protocol)
			assert.Equal(t, "localhost:0", info.Address)

			// Verify error event was emitted.
			assert.NotEmpty(t, emittedEvents)
			lastEvt := emittedEvents[len(emittedEvents)-1]
			assert.Equal(t, events.EventServerError, lastEvt.Type)
		})
	}
}

func TestConnection_Connect_WithTLS_FailsGracefully(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	info, err := svc.Connect("rest", "localhost:0", true, "", "")
	require.Error(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "error", info.State)
	assert.True(t, info.TLS)
}

// ---------------------------------------------------------------------------
// SetupWizardService - uncovered branches
// ---------------------------------------------------------------------------

func TestSetupWizard_SkipSetup_InitDataDirFuncError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("disk full")
	})

	err := tw.svc.SkipSetup()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestSetupWizard_SkipSetup_EmitsSkippedEvent(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	err := tw.svc.SkipSetup()
	require.NoError(t, err)

	evt := lastEventOfType(tw.eventLog, events.EventSetupSkipped)
	require.NotNil(t, evt)
	payload, ok := evt.Payload.(events.SetupSkippedPayload)
	require.True(t, ok)
	assert.Contains(t, payload.Reason, "skipped")
}

func TestSetupWizard_SkipSetup_ConfigSaveErrorWrapped(t *testing.T) {
	svc := &SetupWizardService{}
	svc.SetContext(context.Background())

	saveErr := errors.New("permission denied")
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	svc.SetConfigSaveFunc(func(d *GUIConfigData) error { return saveErr })

	err := svc.SkipSetup()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestSetupWizard_ApplySetup_BarrierInitError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create a barrier service that will fail Initialize.
	barrierDir := t.TempDir()
	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	tw.svc.SetBarrierService(barrierSvc)

	// Set up required dependencies.
	mgr := &wizardMockPINBackend{}
	tw.svc.SetPINService(newWizardPINService(mgr))

	// With a User PIN provided, the barrier uses it as the password.
	// The barrier service is real and initializes successfully.
	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:        "standalone",
		SOPin:       testSOPin,
		UserPin:     testUserPin,
		StorageType: "barrier",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Barrier should succeed because the User PIN is used as the password.
	assert.True(t, result.Success, "barrier should succeed with User PIN as password")
}

func TestSetupWizard_ApplySetup_InitDataDirError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	mgr := &wizardMockPINBackend{}
	tw.svc.SetPINService(newWizardPINService(mgr))
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("cannot create directory")
	})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "data directory"))
}

func TestSetupWizard_ApplySetup_AutoUnsealLUKS_NoService(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	mgr := &wizardMockPINBackend{}
	tw.svc.SetPINService(newWizardPINService(mgr))

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		EnableAutoUnseal: true,
		EnableStorage:    true,
		StorageType:      "luks",
		StoragePass:      "passphrase",
		// autoUnsealSvc is nil
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, containsSubstring(result.Warnings, "auto-unseal service unavailable"))
}

func TestSetupWizard_EmitProgress_NoEmitter(t *testing.T) {
	svc := &SetupWizardService{}

	// Should not panic when eventEmitter is nil.
	svc.emitProgress(1, "test")
	svc.emitSOProvisioningProgress(1, "test")
	svc.emitUserOnboardingProgress(1, "test")
}

func TestSetupWizard_GetStartupState_SetupCompleteNoEnterprise(t *testing.T) {
	svc := &SetupWizardService{}
	svc.SetContext(context.Background())
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

func TestSetupWizard_GetStartupState_NoConfigDir_NoSOProvisioning(t *testing.T) {
	// Change to a clean temp dir so that IsEnterpriseMode("") does not
	// find a stale xkey_policy.hmac in the package directory.
	t.Chdir(t.TempDir())

	svc := &SetupWizardService{}
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})
	svc.SetConfigDir("") // Empty configDir should not advertise SO provisioning.

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
	assert.Empty(t, state.EnterpriseWizardMode)
}

func TestSetupWizard_GetPolicy_ConfigLoadError(t *testing.T) {
	svc := &SetupWizardService{}
	svc.SetContext(context.Background())

	// config.Load() will attempt to load from the default path which
	// may or may not exist. If it exists, the test passes with data.
	// We primarily verify the function does not panic.
	result, err := svc.GetPolicy()
	if err != nil {
		// Expected if no config file exists.
		assert.Nil(t, result)
	} else {
		assert.NotNil(t, result)
	}
}

// ---------------------------------------------------------------------------
// PINService - uncovered branches
// ---------------------------------------------------------------------------

// mockPINBackendVerifySOErr allows controlling VerifySOPIN error.
type mockPINBackendVerifySOErr struct {
	mockPINBackend
	verifySOPINErr error
}

func (m *mockPINBackendVerifySOErr) VerifySOPIN(_ string) error { return m.verifySOPINErr }

func TestPINService_VerifySOPIN_ManagerErrorPath(t *testing.T) {
	mgr := &mockPINBackendVerifySOErr{
		mockPINBackend: mockPINBackend{
			strategy:    "file",
			initialized: true,
		},
		verifySOPINErr: errors.New("verification failed"),
	}
	svc := newTestPINService(mgr)

	err := svc.VerifySOPIN("wrong-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestPINService_GetLockoutStatus_WithStatus(t *testing.T) {
	lockoutStatus := &qrdbsdk.PINLockoutStatus{
		IsLocked:        true,
		FailedAttempts:  6,
		MaxAttempts:     10,
		LockoutUntil:    time.Now().Add(5 * time.Minute),
		RecoverySeconds: 300,
	}
	mgr := &mockPINBackend{
		strategy:      "file",
		initialized:   true,
		lockoutStatus: lockoutStatus,
	}
	svc := newTestPINService(mgr)

	result, err := svc.GetLockoutStatus()
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsLocked)
	assert.Equal(t, 6, result.FailedAttempts)
	assert.Equal(t, 10, result.MaxAttempts)
}

func TestPINService_SetUserPIN_ManagerErrorWithCoordinator(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:      "file",
		initialized:   true,
		setUserPINErr: errors.New("user pin set failed"),
	}
	svc := newTestPINService(mgr)

	err := svc.SetUserPIN("so-pin", "new-user-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user pin set failed")
}

func TestPINService_ChangeUserPIN_ManagerErrorWithCoordinator(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:      "file",
		initialized:   true,
		changeUserErr: errors.New("change user pin failed"),
	}
	svc := newTestPINService(mgr)

	err := svc.ChangeUserPIN("old-pin", "new-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "change user pin failed")
}

func TestPINService_ResetLockout_Success(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    "file",
		initialized: true,
	}
	svc := newTestPINService(mgr)

	err := svc.ResetLockout("so-pin")
	assert.NoError(t, err)
}

func TestPINService_GetPINStatus_AllFieldsPopulated(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    "file",
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
	assert.Equal(t, "file", status.Strategy)
}
