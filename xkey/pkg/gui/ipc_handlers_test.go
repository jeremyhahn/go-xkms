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

package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// TestGUIIPCHandler_HandleTouch_NoPending verifies HandleTouch reports
// no-pending both when the FIDO2 device service is nil (not yet started)
// and when it is constructed but not started, so nothing is awaiting
// approval, rather than panicking on a nil service.
func TestGUIIPCHandler_HandleTouch_NoPending(t *testing.T) {
	t.Run("nil device service", func(t *testing.T) {
		h := &guiIPCHandler{app: &App{log: lifecycleTestLogger()}}
		resp, err := h.HandleTouch()
		require.NoError(t, err)
		assert.Equal(t, ipc.ActionNoPending, resp.Action)
	})

	t.Run("constructed with nothing pending", func(t *testing.T) {
		app := newLifecycleApp(t)
		h := &guiIPCHandler{app: app}
		resp, err := h.HandleTouch()
		require.NoError(t, err)
		assert.Equal(t, ipc.ActionNoPending, resp.Action)
	})
}

// TestGUIIPCHandler_HandleTypePassword verifies the always-fails stub bridge
// returns ipc.ErrHandlerFailed and no response, matching the documented
// "typing a password over IPC is unsupported" contract.
func TestGUIIPCHandler_HandleTypePassword(t *testing.T) {
	h := &guiIPCHandler{app: &App{log: lifecycleTestLogger()}}
	resp, err := h.HandleTypePassword("example.com")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ipc.ErrHandlerFailed)
}

// TestGUIIPCHandler_HandleStatus covers both the locked and unlocked report
// paths, delegating to the real AppLockService rather than a mock so the
// wiring (not just the delegation call) is exercised.
func TestGUIIPCHandler_HandleStatus(t *testing.T) {
	app := newLifecycleApp(t)
	h := &guiIPCHandler{app: app}

	t.Run("locked", func(t *testing.T) {
		app.appLockService.LockForStartup()
		resp, err := h.HandleStatus()
		require.NoError(t, err)
		assert.Equal(t, ipc.ActionLocked, resp.Action)
	})

	t.Run("unlocked", func(t *testing.T) {
		app.appLockService.AutoUnlock()
		resp, err := h.HandleStatus()
		require.NoError(t, err)
		assert.Equal(t, ipc.ActionUnlocked, resp.Action)
	})
}

// TestGUIIPCHandler_HandleUnlock verifies the delegation to
// AppLockService.HandleUnlock returns a non-nil, non-panicking result. A
// fresh (uninitialized) barrier and unconfigured PIN have nothing to
// unlock, so HandleUnlock reports success with nothing changed rather than
// an error -- there is no PIN or barrier for "000000" to fail against.
func TestGUIIPCHandler_HandleUnlock(t *testing.T) {
	app := newLifecycleApp(t)
	h := &guiIPCHandler{app: app}

	result, err := h.HandleUnlock("000000")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Empty(t, result.Unlocked, "nothing was configured to unlock")
}

// TestGUIIPCHandler_AutofillDelegators_DisabledByDefault exercises every
// one-line guiIPCHandler autofill bridge method that gates on
// AutoFillService.checkPreconditions. AutoFillService starts disabled
// (services.NewAutoFillService, autofill_service.go) and none of these
// tests enable it, so each must deterministically fail closed with
// ErrAutoFillDisabled -- proving the bridge forwards both the call and the
// service's fail-closed default rather than panicking or silently
// swallowing the precondition.
func TestGUIIPCHandler_AutofillDelegators_DisabledByDefault(t *testing.T) {
	app := newLifecycleApp(t)
	h := &guiIPCHandler{app: app}
	require.False(t, app.autofillService.IsEnabled())

	t.Run("Search", func(t *testing.T) {
		_, err := h.HandleAutofillSearch("example.com")
		assert.ErrorIs(t, err, services.ErrAutoFillDisabled)
	})
	t.Run("Get", func(t *testing.T) {
		_, err := h.HandleAutofillGet("some-id", "challenge")
		assert.ErrorIs(t, err, services.ErrAutoFillDisabled)
	})
	t.Run("TOTP", func(t *testing.T) {
		_, err := h.HandleAutofillTOTP("example.com")
		assert.ErrorIs(t, err, services.ErrAutoFillDisabled)
	})
	t.Run("TOTPByID", func(t *testing.T) {
		_, err := h.HandleAutofillTOTPByID("some-id")
		assert.ErrorIs(t, err, services.ErrAutoFillDisabled)
	})
	t.Run("Save", func(t *testing.T) {
		_, err := h.HandleAutofillSave("example.com", "user", "pw", "title")
		assert.ErrorIs(t, err, services.ErrAutoFillDisabled)
	})
	t.Run("IgnoreDomain", func(t *testing.T) {
		_, err := h.HandleAutofillIgnoreDomain("example.com")
		assert.ErrorIs(t, err, services.ErrAutoFillDisabled)
	})
}

// TestGUIIPCHandler_AutofillDelegators_NoPreconditionGate covers the two
// autofill bridge methods that intentionally bypass checkPreconditions
// (status/policy are read-only and safe to query while disabled) plus Focus,
// which only raises the window.
func TestGUIIPCHandler_AutofillDelegators_NoPreconditionGate(t *testing.T) {
	app := newLifecycleApp(t)
	h := &guiIPCHandler{app: app}

	t.Run("Status", func(t *testing.T) {
		result, err := h.HandleAutofillStatus()
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotNil(t, result.Status)
	})
	t.Run("Policy", func(t *testing.T) {
		result, err := h.HandleAutofillPolicy()
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotNil(t, result.Policy)
	})
	t.Run("Focus", func(t *testing.T) {
		// ShowWindow no-ops safely with a.ctx == nil (see
		// TestApp_ShowWindow_NilContext); this covers HandleAutofillFocus's
		// own bridging line.
		result, err := h.HandleAutofillFocus()
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

// TestGUIIPCHandler_HandlePairingNotifyCode verifies the pairing-code bridge
// logs and emits without panicking when a.ctx is nil (EmitEvent's guard
// covers the rest).
func TestGUIIPCHandler_HandlePairingNotifyCode(t *testing.T) {
	h := &guiIPCHandler{app: &App{log: lifecycleTestLogger()}}
	err := h.HandlePairingNotifyCode("123456", "identity-key", "https://example.com")
	assert.NoError(t, err)
}

// TestGUIIPCHandler_HandlePairingCompleted verifies the pairing-completed
// bridge logs and emits without panicking when a.ctx is nil.
func TestGUIIPCHandler_HandlePairingCompleted(t *testing.T) {
	h := &guiIPCHandler{app: &App{log: lifecycleTestLogger()}}
	err := h.HandlePairingCompleted("https://example.com")
	assert.NoError(t, err)
}
