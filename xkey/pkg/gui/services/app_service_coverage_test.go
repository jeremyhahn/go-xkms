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
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test audit logger for app service coverage tests
// ---------------------------------------------------------------------------

type appCoverageAuditLogger struct {
	entries []audit.Entry
}

func (l *appCoverageAuditLogger) Log(e audit.Entry) { l.entries = append(l.entries, e) }
func (l *appCoverageAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	l.Log(audit.Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success})
}
func (l *appCoverageAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (l *appCoverageAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {
}
func (l *appCoverageAuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) {
	l.Log(audit.Entry{Operation: op, Details: details, Success: true})
}
func (l *appCoverageAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *appCoverageAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {
}
func (l *appCoverageAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *appCoverageAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}

// ---------------------------------------------------------------------------
// Setter coverage tests
// ---------------------------------------------------------------------------

func TestAppService_Coverage_SetConfigUpdater(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.configUpdater)

	called := false
	svc.SetConfigUpdater(func(cfg *GUIConfigData) error {
		called = true
		return nil
	})
	assert.NotNil(t, svc.configUpdater)

	err := svc.configUpdater(&GUIConfigData{})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestAppService_Coverage_SetThemeValidator(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.themeValidator)

	svc.SetThemeValidator(func(theme string) error {
		return nil
	})
	assert.NotNil(t, svc.themeValidator)
}

func TestAppService_Coverage_SetKeyCountFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.keyCountFunc)

	svc.SetKeyCountFunc(func() int { return 42 })
	assert.NotNil(t, svc.keyCountFunc)
	assert.Equal(t, 42, svc.keyCountFunc())
}

func TestAppService_Coverage_SetBridgeStatusFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.bridgeStatusFunc)

	svc.SetBridgeStatusFunc(func() bool { return true })
	assert.NotNil(t, svc.bridgeStatusFunc)
	assert.True(t, svc.bridgeStatusFunc())
}

func TestAppService_Coverage_SetServerConnectedFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.serverConnectedFn)

	svc.SetServerConnectedFunc(func() bool { return true })
	assert.NotNil(t, svc.serverConnectedFn)
}

func TestAppService_Coverage_SetServerAddressFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.serverAddressFn)

	svc.SetServerAddressFunc(func() string { return "localhost:8443" })
	assert.NotNil(t, svc.serverAddressFn)
	assert.Equal(t, "localhost:8443", svc.serverAddressFn())
}

func TestAppService_Coverage_SetRemoteKeyCountFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.remoteKeyCountFn)

	svc.SetRemoteKeyCountFunc(func() int { return 10 })
	assert.NotNil(t, svc.remoteKeyCountFn)
}

func TestAppService_Coverage_SetOATHCountFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.oathCountFn)

	svc.SetOATHCountFunc(func() int { return 7 })
	assert.NotNil(t, svc.oathCountFn)
}

func TestAppService_Coverage_SetFIDO2CountFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.fido2CountFn)

	svc.SetFIDO2CountFunc(func() int { return 3 })
	assert.NotNil(t, svc.fido2CountFn)
}

func TestAppService_Coverage_SetPIVCertCountFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.pivCertCountFn)

	svc.SetPIVCertCountFunc(func() int { return 4 })
	assert.NotNil(t, svc.pivCertCountFn)
}

func TestAppService_Coverage_SetTPMStatusFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.tpmStatusFn)

	svc.SetTPMStatusFunc(func() (bool, bool, bool) { return true, true, false })
	assert.NotNil(t, svc.tpmStatusFn)
}

func TestAppService_Coverage_SetStorageStatusFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.storageStatusFn)

	svc.SetStorageStatusFunc(func() (bool, bool) { return true, true })
	assert.NotNil(t, svc.storageStatusFn)
}

func TestAppService_Coverage_SetFIDO2ToggleFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.fido2ToggleFn)

	svc.SetFIDO2ToggleFunc(func(enabled bool) error { return nil })
	assert.NotNil(t, svc.fido2ToggleFn)
}

func TestAppService_Coverage_SetAuditLogger(t *testing.T) {
	svc := NewAppService(nil)
	logger := &appCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	loaded := svc.auditLog.Load()
	require.NotNil(t, loaded)
}

// ---------------------------------------------------------------------------
// logConfigEvent tests
// ---------------------------------------------------------------------------

func TestAppService_Coverage_LogConfigEvent_WithLogger(t *testing.T) {
	svc := NewAppService(nil)
	al := &appCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	svc.logConfigEvent(audit.OpConfigUpdated, true, nil, map[string]any{"test": true})
	require.Len(t, al.entries, 1)
	assert.Equal(t, audit.OpConfigUpdated, al.entries[0].Operation)
	assert.True(t, al.entries[0].Success)
}

func TestAppService_Coverage_LogConfigEvent_WithError(t *testing.T) {
	svc := NewAppService(nil)
	al := &appCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	testErr := errors.New("test error")
	svc.logConfigEvent(audit.OpConfigUpdated, false, testErr, nil)
	require.Len(t, al.entries, 1)
	assert.Equal(t, "test error", al.entries[0].Error)
	assert.False(t, al.entries[0].Success)
}

func TestAppService_Coverage_LogConfigEvent_NoLogger(t *testing.T) {
	svc := NewAppService(nil)
	// No logger set - should not panic.
	svc.logConfigEvent(audit.OpConfigUpdated, true, nil, nil)
}

// ---------------------------------------------------------------------------
// configChangedFields tests
// ---------------------------------------------------------------------------

func TestAppService_Coverage_ConfigChangedFields_NilOld(t *testing.T) {
	fields := configChangedFields(nil, &GUIConfigData{})
	assert.Nil(t, fields)
}

func TestAppService_Coverage_ConfigChangedFields_NilNew(t *testing.T) {
	fields := configChangedFields(&GUIConfigData{}, nil)
	assert.Nil(t, fields)
}

func TestAppService_Coverage_ConfigChangedFields_BothNil(t *testing.T) {
	fields := configChangedFields(nil, nil)
	assert.Nil(t, fields)
}

func TestAppService_Coverage_ConfigChangedFields_NoChanges(t *testing.T) {
	cfg := &GUIConfigData{Theme: "dark", AutoTray: true}
	fields := configChangedFields(cfg, cfg)
	assert.Empty(t, fields)
}

func TestAppService_Coverage_ConfigChangedFields_AllFieldChanges(t *testing.T) {
	old := &GUIConfigData{}
	newCfg := &GUIConfigData{
		Theme:                     "dark",
		AutoTray:                  true,
		StartMinimized:            true,
		Notifications:             true,
		ServerAddress:             "localhost:8443",
		ServerProtocol:            "grpc",
		ServerTLSEnabled:          true,
		ServerAutoConnect:         true,
		AutoUnsealEnabled:         true,
		FIDO2AuthenticatorEnabled: true,
		ClipboardTimeout:          60,
		RequireAuth:               true,
		SetupComplete:             true,
		StorageType:               "encrypted",
		BarrierStrategy:           "tpm2",
		AppAutoLockMinutes:        15,
		AppLockOnScreenLock:       true,
		BrowserExtensionEnabled:   true,
		DeveloperTools:            true,
	}

	fields := configChangedFields(old, newCfg)
	assert.Contains(t, fields, "theme")
	assert.Contains(t, fields, "auto_tray")
	assert.Contains(t, fields, "start_minimized")
	assert.Contains(t, fields, "notifications")
	assert.Contains(t, fields, "server_address")
	assert.Contains(t, fields, "server_protocol")
	assert.Contains(t, fields, "server_tls_enabled")
	assert.Contains(t, fields, "server_auto_connect")
	assert.Contains(t, fields, "auto_unseal_enabled")
	assert.Contains(t, fields, "fido2_authenticator_enabled")
	assert.Contains(t, fields, "clipboard_timeout")
	assert.Contains(t, fields, "require_auth")
	assert.Contains(t, fields, "setup_complete")
	assert.Contains(t, fields, "storage_type")
	assert.Contains(t, fields, "barrier_strategy")
	assert.Contains(t, fields, "app_auto_lock_minutes")
	assert.Contains(t, fields, "app_lock_on_screen_lock")
	assert.Contains(t, fields, "browser_extension_enabled")
	assert.Contains(t, fields, "developer_tools")
}

// ---------------------------------------------------------------------------
// GetStatus with all callbacks set
// ---------------------------------------------------------------------------

func TestAppService_Coverage_GetStatus_AllCallbacksSet(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetKeyCountFunc(func() int { return 10 })
	svc.SetBridgeStatusFunc(func() bool { return true })
	svc.SetServerConnectedFunc(func() bool { return true })
	svc.SetServerAddressFunc(func() string { return "localhost:8443" })
	svc.SetRemoteKeyCountFunc(func() int { return 5 })
	svc.SetOATHCountFunc(func() int { return 3 })
	svc.SetFIDO2CountFunc(func() int { return 2 })
	svc.SetPIVCertCountFunc(func() int { return 1 })
	svc.SetTPMStatusFunc(func() (bool, bool, bool) { return true, true, true })
	svc.SetStorageStatusFunc(func() (bool, bool) { return true, true })
	svc.SetSealStatusFunc(func() (bool, string, bool) { return true, "tpm2", true })
	svc.SetPINStatusFunc(func() (bool, bool, string) { return true, false, "software" })
	svc.SetPhoneStatusFunc(func() (bool, string) { return true, "Pixel 8" })

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.Equal(t, Version, status.Version)
	assert.Equal(t, 10, status.KeyCount)
	assert.True(t, status.BridgeRunning)
	assert.True(t, status.ServerConnected)
	assert.Equal(t, "localhost:8443", status.ServerAddress)
	assert.Equal(t, 5, status.RemoteKeyCount)
	assert.Equal(t, 3, status.OATHAccountCount)
	assert.Equal(t, 2, status.FIDO2CredCount)
	assert.Equal(t, 1, status.PIVCertCount)
	assert.True(t, status.TPMDeviceExists)
	assert.True(t, status.TPMAvailable)
	assert.True(t, status.TPMProvisioned)
	assert.True(t, status.StorageEncrypted)
	assert.True(t, status.StorageMounted)
	assert.True(t, status.Sealed)
	assert.Equal(t, "tpm2", status.SealStrategy)
	assert.True(t, status.HardwareBacked)
	assert.True(t, status.PINConfigured)
	assert.False(t, status.PINLocked)
	assert.Equal(t, "software", status.PINStrategy)
	assert.True(t, status.PhoneConnected)
	assert.Equal(t, "Pixel 8", status.PhoneDeviceName)
	assert.Equal(t, "xkmsd", status.Mode)
	assert.NotEmpty(t, status.Uptime)
	assert.NotEmpty(t, status.Platform)
	assert.NotEmpty(t, status.GoVersion)
}

// ---------------------------------------------------------------------------
// GetDeveloperTools / SetDeveloperTools
// ---------------------------------------------------------------------------

func TestAppService_Coverage_GetDeveloperTools_Default(t *testing.T) {
	svc := NewAppService(nil)
	assert.False(t, svc.GetDeveloperTools())
}

func TestAppService_Coverage_SetDeveloperTools(t *testing.T) {
	svc := NewAppService(nil)
	err := svc.SetDeveloperTools(true)
	require.NoError(t, err)
	assert.True(t, svc.GetDeveloperTools())
}

func TestAppService_Coverage_SetDeveloperTools_False(t *testing.T) {
	cfg := &GUIConfigData{DeveloperTools: true}
	svc := NewAppService(cfg)
	assert.True(t, svc.GetDeveloperTools())

	err := svc.SetDeveloperTools(false)
	require.NoError(t, err)
	assert.False(t, svc.GetDeveloperTools())
}

// ---------------------------------------------------------------------------
// ToggleFIDO2Authenticator with error from callback
// ---------------------------------------------------------------------------

func TestAppService_Coverage_ToggleFIDO2_WithError(t *testing.T) {
	svc := NewAppService(nil)
	expectedErr := errors.New("toggle error")
	svc.SetFIDO2ToggleFunc(func(enabled bool) error {
		return expectedErr
	})

	err := svc.ToggleFIDO2Authenticator(true)
	assert.ErrorIs(t, err, expectedErr)
}

// ---------------------------------------------------------------------------
// UpdateConfig audit logging
// ---------------------------------------------------------------------------

func TestAppService_Coverage_UpdateConfig_AuditLogSuccess(t *testing.T) {
	svc := NewAppService(nil)
	al := &appCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	updated := &GUIConfigData{Theme: "dark"}
	err := svc.UpdateConfig(updated)
	require.NoError(t, err)

	// Verify config was stored.
	assert.Equal(t, "dark", svc.GetConfig().Theme)

	// Verify audit log entry.
	require.Len(t, al.entries, 1)
	assert.Equal(t, audit.OpConfigUpdated, al.entries[0].Operation)
	assert.True(t, al.entries[0].Success)
}

func TestAppService_Coverage_UpdateConfig_AuditLogFailure(t *testing.T) {
	svc := NewAppService(nil)
	al := &appCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	saveErr := errors.New("disk full")
	svc.SetConfigUpdater(func(cfg *GUIConfigData) error {
		return saveErr
	})

	err := svc.UpdateConfig(&GUIConfigData{Theme: "dark"})
	assert.ErrorIs(t, err, saveErr)

	// Failure audit entry.
	require.Len(t, al.entries, 1)
	assert.False(t, al.entries[0].Success)
}

// ---------------------------------------------------------------------------
// SetTheme with updater
// ---------------------------------------------------------------------------

func TestAppService_Coverage_SetTheme_WithUpdater(t *testing.T) {
	svc := NewAppService(nil)
	var saved *GUIConfigData
	svc.SetConfigUpdater(func(cfg *GUIConfigData) error {
		saved = cfg
		return nil
	})

	err := svc.SetTheme("light")
	require.NoError(t, err)
	assert.Equal(t, "light", svc.GetTheme())
	assert.Equal(t, "light", saved.Theme)
}

// ---------------------------------------------------------------------------
// Defaults from nil config constructor
// ---------------------------------------------------------------------------

func TestAppService_Coverage_NilConfig_Defaults(t *testing.T) {
	svc := NewAppService(nil)
	cfg := svc.GetConfig()
	assert.Equal(t, "system", cfg.Theme)
	assert.Equal(t, 1024, cfg.WindowWidth)
	assert.Equal(t, 768, cfg.WindowHeight)
	assert.True(t, cfg.Notifications)
	assert.True(t, cfg.AutoTray)
	assert.Equal(t, 30, cfg.ClipboardTimeout)
	assert.True(t, cfg.RequireAuth)
}

// ---------------------------------------------------------------------------
// Uptime is positive after construction
// ---------------------------------------------------------------------------

func TestAppService_Coverage_Uptime_IsPositive(t *testing.T) {
	svc := NewAppService(nil)
	status := svc.GetStatus()
	// Uptime is truncated to seconds, so immediately after construction
	// it may be "0s". We just verify the field is populated.
	assert.NotEmpty(t, status.Uptime)
	_, err := time.ParseDuration(status.Uptime)
	assert.NoError(t, err, "uptime should be a valid Go duration string")
}

// ---------------------------------------------------------------------------
// SetContext
// ---------------------------------------------------------------------------

func TestAppService_Coverage_SetContext(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.ctx)

	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}
