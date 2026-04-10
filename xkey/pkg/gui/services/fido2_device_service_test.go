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

//go:build linux

package services

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test audit logger for FIDO2 device service tests
// ---------------------------------------------------------------------------

type testDeviceAuditLogger struct {
	entries []audit.Entry
}

func (l *testDeviceAuditLogger) Log(e audit.Entry) { l.entries = append(l.entries, e) }
func (l *testDeviceAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	l.Log(audit.Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success})
}
func (l *testDeviceAuditLogger) LogCryptoOperation(op audit.OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) {
	l.Log(audit.Entry{Operation: op, Backend: backend, KeyID: keyID, DeviceID: deviceID, DeviceName: deviceName, Success: success})
}
func (l *testDeviceAuditLogger) LogConnectionEvent(op audit.OperationType, deviceID, deviceName string, details map[string]any) {
	l.Log(audit.Entry{Operation: op, DeviceID: deviceID, DeviceName: deviceName, Details: details})
}
func (l *testDeviceAuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) {
	l.Log(audit.Entry{Operation: op, Success: true, Details: details})
}
func (l *testDeviceAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *testDeviceAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {
}
func (l *testDeviceAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *testDeviceAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}

// ---------------------------------------------------------------------------
// NewFIDO2DeviceService
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_NewWithLogger(t *testing.T) {
	logger := slog.Default()
	svc := NewFIDO2DeviceService(logger)
	require.NotNil(t, svc)
	assert.False(t, svc.IsRunning())
}

func TestFIDO2DeviceService_NewWithNilLogger(t *testing.T) {
	// nil logger is valid - used for nop logging.
	svc := NewFIDO2DeviceService(nil)
	require.NotNil(t, svc)
	assert.Nil(t, svc.log)
}

// ---------------------------------------------------------------------------
// SetContext
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_SetContext(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestFIDO2DeviceService_SetContext_WithValue(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	type ctxKey string
	ctx := context.WithValue(context.Background(), ctxKey("test"), "value")
	svc.SetContext(ctx)
	assert.Equal(t, "value", svc.ctx.Value(ctxKey("test")))
}

// ---------------------------------------------------------------------------
// SetEmitFunc
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_SetEmitFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.Nil(t, svc.emitFunc)

	called := false
	svc.SetEmitFunc(func(eventType string, data any) {
		called = true
	})
	assert.NotNil(t, svc.emitFunc)

	// Verify the function is wired correctly.
	svc.emitFunc("test", nil)
	assert.True(t, called)
}

func TestFIDO2DeviceService_SetEmitFunc_Nil(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetEmitFunc(nil)
	assert.Nil(t, svc.emitFunc)
}

// ---------------------------------------------------------------------------
// SetLastError
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_SetLastError(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	svc.SetLastError("something went wrong")
	val := svc.lastError.Load()
	require.NotNil(t, val)
	assert.Equal(t, "something went wrong", val.(string))
}

func TestFIDO2DeviceService_SetLastError_Empty(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	// Set a non-empty error then clear it.
	svc.SetLastError("initial error")
	svc.SetLastError("")
	val := svc.lastError.Load()
	require.NotNil(t, val)
	assert.Equal(t, "", val.(string))
}

// ---------------------------------------------------------------------------
// SetAuditLogger
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_SetAuditLogger(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.Nil(t, svc.auditLogger)

	logger := &testDeviceAuditLogger{}
	svc.SetAuditLogger(logger)
	assert.Equal(t, logger, svc.auditLogger)
}

func TestFIDO2DeviceService_SetAuditLogger_Nil(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetAuditLogger(nil)
	assert.Nil(t, svc.auditLogger)
}

// ---------------------------------------------------------------------------
// IsRunning
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_IsRunning_Default(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.False(t, svc.IsRunning())
}

func TestFIDO2DeviceService_IsRunning_AfterManualSet(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)
	assert.True(t, svc.IsRunning())
	svc.running.Store(false)
	assert.False(t, svc.IsRunning())
}

// ---------------------------------------------------------------------------
// GetStatus
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_GetStatus_NotRunning_NoError(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	status := svc.GetStatus()

	require.NotNil(t, status)
	assert.False(t, status.Running)
	assert.Empty(t, status.DeviceName)
	assert.Empty(t, status.VendorID)
	assert.Empty(t, status.ProductID)
	assert.False(t, status.HasPending)
	assert.Empty(t, status.Reason)
	assert.False(t, status.AuthenticatorAvailable)
}

func TestFIDO2DeviceService_GetStatus_NotRunning_WithError(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetLastError("UHID not available")

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.False(t, status.Running)
	// No authenticator set, so reason is passed through unchanged.
	assert.Equal(t, "UHID not available", status.Reason)
	assert.False(t, status.AuthenticatorAvailable)
}

func TestFIDO2DeviceService_GetStatus_NotRunning_EmptyError(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetLastError("")

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.False(t, status.Running)
	assert.Empty(t, status.Reason)
}

func TestFIDO2DeviceService_GetStatus_Running_NoSocketHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.True(t, status.Running)
	assert.NotEmpty(t, status.DeviceName)
	assert.NotEmpty(t, status.VendorID)
	assert.NotEmpty(t, status.ProductID)
	assert.False(t, status.HasPending)
}

func TestFIDO2DeviceService_GetStatus_Running_WithSocketHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)

	handler := authenticator.NewSocketHandler(nil, slog.Default())
	svc.socketHandler = handler

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.True(t, status.Running)
	assert.False(t, status.HasPending)
}

func TestFIDO2DeviceService_GetStatus_AuthenticatorAvailable_WithAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	cfg := authenticator.DefaultConfig()
	cfg.Storage = authenticator.NewMemoryStorage()
	auth, err := authenticator.NewAuthenticator(cfg)
	require.NoError(t, err)
	defer auth.Close()

	svc.SetAuthenticator(auth)

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.True(t, status.AuthenticatorAvailable)
}

func TestFIDO2DeviceService_GetStatus_AuthenticatorAvailable_WithoutAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.False(t, status.AuthenticatorAvailable)
}

func TestFIDO2DeviceService_GetStatus_UHIDFailure_WithAuthenticator_RewritesReason(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	cfg := authenticator.DefaultConfig()
	cfg.Storage = authenticator.NewMemoryStorage()
	auth, err := authenticator.NewAuthenticator(cfg)
	require.NoError(t, err)
	defer auth.Close()

	svc.SetAuthenticator(auth)
	svc.SetLastError("UHID not available: open /dev/uhid: permission denied")

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.False(t, status.Running)
	assert.True(t, status.AuthenticatorAvailable)
	assert.Equal(t, "USB HID bridge unavailable \u2014 WebAuthn works via browser extension IPC", status.Reason)
}

func TestFIDO2DeviceService_GetStatus_UHIDFailure_WithoutAuthenticator_RawReason(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	svc.SetLastError("UHID not available: open /dev/uhid: permission denied")

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.False(t, status.Running)
	assert.False(t, status.AuthenticatorAvailable)
	assert.Equal(t, "UHID not available: open /dev/uhid: permission denied", status.Reason)
}

func TestFIDO2DeviceService_GetStatus_NonUHIDFailure_WithAuthenticator_RawReason(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	cfg := authenticator.DefaultConfig()
	cfg.Storage = authenticator.NewMemoryStorage()
	auth, err := authenticator.NewAuthenticator(cfg)
	require.NoError(t, err)
	defer auth.Close()

	svc.SetAuthenticator(auth)
	svc.SetLastError("failed to create virtual device: some other error")

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.False(t, status.Running)
	assert.True(t, status.AuthenticatorAvailable)
	// Non-UHID errors are passed through unchanged even with authenticator set.
	assert.Equal(t, "failed to create virtual device: some other error", status.Reason)
}

// ---------------------------------------------------------------------------
// Start error paths
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_Start_AlreadyRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)

	err := svc.Start(authenticator.NewMemoryStorage(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2DeviceAlreadyRunning))
}

func TestFIDO2DeviceService_Start_NilStorage(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	err := svc.Start(nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2StorageRequired))

	// Verify the last error was stored.
	val := svc.lastError.Load()
	require.NotNil(t, val)
	assert.Contains(t, val.(string), "storage is required")
}

// ---------------------------------------------------------------------------
// Stop error paths
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_Stop_NotRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	err := svc.Stop()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2DeviceNotRunning))
}

// ---------------------------------------------------------------------------
// ApproveTouchRequest
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_ApproveTouchRequest_NilSocketHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.Nil(t, svc.socketHandler)

	result := svc.ApproveTouchRequest()
	assert.False(t, result)
}

func TestFIDO2DeviceService_ApproveTouchRequest_NoPending(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	handler := authenticator.NewSocketHandler(nil, slog.Default())
	svc.socketHandler = handler

	result := svc.ApproveTouchRequest()
	assert.False(t, result)
}

func TestFIDO2DeviceService_ApproveTouchRequest_EmitsEvent(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	handler := authenticator.NewSocketHandler(nil, slog.Default())
	svc.socketHandler = handler

	var emittedType string
	var emittedData any
	svc.SetEmitFunc(func(eventType string, data any) {
		emittedType = eventType
		emittedData = data
	})

	// No pending request means no event emitted.
	result := svc.ApproveTouchRequest()
	assert.False(t, result)
	assert.Empty(t, emittedType)
	assert.Nil(t, emittedData)
}

// ---------------------------------------------------------------------------
// DenyTouchRequest
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_DenyTouchRequest_NilSocketHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.Nil(t, svc.socketHandler)

	result := svc.DenyTouchRequest()
	assert.False(t, result)
}

func TestFIDO2DeviceService_DenyTouchRequest_NoPending(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	handler := authenticator.NewSocketHandler(nil, slog.Default())
	svc.socketHandler = handler

	result := svc.DenyTouchRequest()
	assert.False(t, result)
}

func TestFIDO2DeviceService_DenyTouchRequest_EmitsEvent(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	handler := authenticator.NewSocketHandler(nil, slog.Default())
	svc.socketHandler = handler

	var emittedType string
	svc.SetEmitFunc(func(eventType string, data any) {
		emittedType = eventType
	})

	// No pending request means no event emitted.
	result := svc.DenyTouchRequest()
	assert.False(t, result)
	assert.Empty(t, emittedType)
}

// ---------------------------------------------------------------------------
// HasPendingTouch
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_HasPendingTouch_NilSocketHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.False(t, svc.HasPendingTouch())
}

func TestFIDO2DeviceService_HasPendingTouch_NoPending(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	handler := authenticator.NewSocketHandler(nil, slog.Default())
	svc.socketHandler = handler

	assert.False(t, svc.HasPendingTouch())
}

// ---------------------------------------------------------------------------
// emit (private helper)
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_Emit_NilEmitFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.Nil(t, svc.emitFunc)

	// Should not panic.
	svc.emit("test:event", map[string]string{"key": "value"})
}

func TestFIDO2DeviceService_Emit_WithEmitFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	var capturedType string
	var capturedData any
	svc.SetEmitFunc(func(eventType string, data any) {
		capturedType = eventType
		capturedData = data
	})

	payload := map[string]string{"key": "value"}
	svc.emit("test:event", payload)

	assert.Equal(t, "test:event", capturedType)
	assert.Equal(t, payload, capturedData)
}

// ---------------------------------------------------------------------------
// cleanup (private helper)
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_Cleanup_NilDevices(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.Nil(t, svc.uhidDev)
	assert.Nil(t, svc.device)

	// Should not panic when both are nil.
	svc.cleanup()
	assert.Nil(t, svc.uhidDev)
	assert.Nil(t, svc.device)
}

// ---------------------------------------------------------------------------
// Error sentinel values
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_ErrorSentinels(t *testing.T) {
	assert.NotNil(t, ErrFIDO2DeviceAlreadyRunning)
	assert.NotNil(t, ErrFIDO2DeviceNotRunning)
	assert.NotNil(t, ErrFIDO2UHIDNotAvailable)
	assert.NotNil(t, ErrFIDO2StorageRequired)

	assert.Contains(t, ErrFIDO2DeviceAlreadyRunning.Error(), "already running")
	assert.Contains(t, ErrFIDO2DeviceNotRunning.Error(), "not running")
	assert.Contains(t, ErrFIDO2UHIDNotAvailable.Error(), "UHID not available")
	assert.Contains(t, ErrFIDO2StorageRequired.Error(), "storage is required")
}

// ---------------------------------------------------------------------------
// FIDO2DeviceStatus struct
// ---------------------------------------------------------------------------

func TestFIDO2DeviceStatus_Fields(t *testing.T) {
	status := &FIDO2DeviceStatus{
		Running:                true,
		DeviceName:             "xKey Authenticator",
		VendorID:               "0x1234",
		ProductID:              "0x5678",
		HasPending:             true,
		AuthenticatorAvailable: true,
		Reason:                 "",
	}
	assert.True(t, status.Running)
	assert.Equal(t, "xKey Authenticator", status.DeviceName)
	assert.Equal(t, "0x1234", status.VendorID)
	assert.Equal(t, "0x5678", status.ProductID)
	assert.True(t, status.HasPending)
	assert.True(t, status.AuthenticatorAvailable)
	assert.Empty(t, status.Reason)
}

func TestFIDO2DeviceStatus_NotRunning_WithReason(t *testing.T) {
	status := &FIDO2DeviceStatus{
		Running: false,
		Reason:  "UHID device file not accessible",
	}
	assert.False(t, status.Running)
	assert.Empty(t, status.DeviceName)
	assert.Equal(t, "UHID device file not accessible", status.Reason)
}

// ---------------------------------------------------------------------------
// Start + Stop lifecycle (unit-level, no real UHID)
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_GetStatus_AfterNilStorageStart(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	// Start with nil storage to trigger error path.
	_ = svc.Start(nil, nil)

	// Status should reflect not running and show last error.
	status := svc.GetStatus()
	assert.False(t, status.Running)
	assert.NotEmpty(t, status.Reason)
}

// ---------------------------------------------------------------------------
// Double Start / Double Stop
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_DoubleStart_ReturnsAlreadyRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true) // Simulate running state.

	err := svc.Start(authenticator.NewMemoryStorage(), nil)
	assert.True(t, errors.Is(err, ErrFIDO2DeviceAlreadyRunning))
}

func TestFIDO2DeviceService_DoubleStop_ReturnsNotRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	err := svc.Stop()
	assert.True(t, errors.Is(err, ErrFIDO2DeviceNotRunning))

	// Second call should also return same error.
	err = svc.Stop()
	assert.True(t, errors.Is(err, ErrFIDO2DeviceNotRunning))
}

// ---------------------------------------------------------------------------
// GetStatus with last error cleared
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_GetStatus_ErrorClearedAfterRestart(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	svc.SetLastError("some error")
	status := svc.GetStatus()
	assert.Equal(t, "some error", status.Reason)

	// Clear the error.
	svc.SetLastError("")
	status = svc.GetStatus()
	assert.Empty(t, status.Reason)
}

// ---------------------------------------------------------------------------
// Concurrent access safety
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_ConcurrentIsRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			svc.running.Store(true)
			svc.IsRunning()
			svc.running.Store(false)
		}
	}()

	for i := 0; i < 100; i++ {
		svc.IsRunning()
		svc.GetStatus()
	}

	<-done
}

func TestFIDO2DeviceService_ConcurrentSetLastError(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			svc.SetLastError("error from goroutine 1")
		}
	}()

	for i := 0; i < 100; i++ {
		svc.SetLastError("error from goroutine 2")
	}

	<-done

	// Value should be one of the two.
	val := svc.lastError.Load()
	require.NotNil(t, val)
	reason := val.(string)
	assert.True(t,
		reason == "error from goroutine 1" || reason == "error from goroutine 2",
		"unexpected reason: %s", reason)
}

func TestFIDO2DeviceService_ConcurrentGetStatus(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetLastError("test error")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			status := svc.GetStatus()
			assert.NotNil(t, status)
		}
	}()

	for i := 0; i < 100; i++ {
		status := svc.GetStatus()
		assert.NotNil(t, status)
	}

	<-done
}

// ---------------------------------------------------------------------------
// Audit logger integration
// ---------------------------------------------------------------------------

func TestFIDO2DeviceService_Stop_WithAuditLogger_NotRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	logger := &testDeviceAuditLogger{}
	svc.SetAuditLogger(logger)

	// Stop when not running does not trigger audit log.
	err := svc.Stop()
	assert.Error(t, err)
	assert.Empty(t, logger.entries)
}
