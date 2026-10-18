package gui

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// captureDefaultLog routes slog.Default, which NewApp derives its logger
// from, into a buffer for the rest of the test.
func captureDefaultLog(t *testing.T) *logBuffer {
	t.Helper()
	logs := &logBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

// TestNewApp_UnremovableBrowserConfigPanics verifies that a browser config
// which can neither be parsed nor removed (a non-empty directory) stops
// construction instead of starting with a browser service that silently
// ignores the user's settings.
func TestNewApp_UnremovableBrowserConfigPanics(t *testing.T) {
	isolateAppEnv(t)
	cfgDir, err := configDir()
	require.NoError(t, err)
	browserConfigPath := filepath.Join(cfgDir, "browser.json")
	require.NoError(t, os.MkdirAll(filepath.Join(browserConfigPath, "entry"), 0o700))

	defer func() {
		recovered := recover()
		require.NotNil(t, recovered, "NewApp must panic when the corrupt browser config cannot be removed")
		assert.Contains(t, recovered, "could not remove corrupt config")
	}()
	NewApp(nil)
}

// TestNewApp_BlockedSealDirectoryDegrades verifies that a seal storage
// directory which cannot be created is logged and construction continues:
// initializeDataDir relocates sealed storage to the data directory later.
func TestNewApp_BlockedSealDirectoryDegrades(t *testing.T) {
	isolateAppEnv(t)
	cfgDir, err := configDir()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "sealed"), nil, 0o600))
	logs := captureDefaultLog(t)

	app := NewApp(nil)

	require.NotNil(t, app.sealService, "the seal service must still be constructed")
	assert.True(t, logs.Contains("failed to create seal storage directory"))
}

// TestNewApp_ConfiguredAutofillPolicyApplied verifies that a persisted
// autofill policy replaces the service default at construction.
func TestNewApp_ConfiguredAutofillPolicyApplied(t *testing.T) {
	isolateAppEnv(t)
	cfg := DefaultGUIConfig()
	cfg.AutoFillPolicy = xkmssdk.DefaultAutoFillPolicy()
	cfg.AutoFillPolicy.MaxFillsPerMinute = 7

	app := NewApp(cfg)

	assert.Equal(t, 7, app.autofillService.GetPolicy().MaxFillsPerMinute)
}

// TestNewApp_InvalidAutofillPolicyKeepsDefault verifies that a persisted
// autofill policy which fails validation is logged and the service keeps
// its default policy rather than an invalid one.
func TestNewApp_InvalidAutofillPolicyKeepsDefault(t *testing.T) {
	isolateAppEnv(t)
	logs := captureDefaultLog(t)
	cfg := DefaultGUIConfig()
	cfg.AutoFillPolicy = xkmssdk.DefaultAutoFillPolicy()
	cfg.AutoFillPolicy.MaxFillsPerMinute = -1

	app := NewApp(cfg)

	assert.Equal(t, xkmssdk.DefaultAutoFillPolicy().MaxFillsPerMinute,
		app.autofillService.GetPolicy().MaxFillsPerMinute)
	assert.True(t, logs.Contains("failed to apply configured autofill policy"))
}

// TestNewApp_UnopenableLoginStoreLeavesNoLogin verifies that when the
// login token store cannot be opened, construction continues and no
// stored login is wired into the connection or the API explorer.
func TestNewApp_UnopenableLoginStoreLeavesNoLogin(t *testing.T) {
	isolateAppEnv(t)
	blocked := filepath.Join(t.TempDir(), "xkey-home")
	require.NoError(t, os.WriteFile(blocked, nil, 0o600))
	t.Setenv("XKEY_HOME", blocked)
	logs := captureDefaultLog(t)

	app := NewApp(nil)

	assert.Nil(t, app.loginTokens, "an unopenable login store leaves no token store")
	assert.True(t, logs.Contains("login token store unavailable"))
}
