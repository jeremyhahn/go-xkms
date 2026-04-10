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
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeExecCommand returns a command factory that records invocations
// instead of executing real processes.
func fakeExecCommand(recorded *[][]string, mu *sync.Mutex) func(ctx context.Context, name string, arg ...string) *exec.Cmd {
	return func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		mu.Lock()
		*recorded = append(*recorded, append([]string{name}, arg...))
		mu.Unlock()
		// Return a harmless command that succeeds immediately.
		return exec.CommandContext(ctx, "true")
	}
}

// failingExecCommand returns a command factory that always produces a
// command that fails to start.
func failingExecCommand() func(ctx context.Context, name string, arg ...string) *exec.Cmd {
	return func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent-binary-that-does-not-exist")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- NewBrowserService ---

func TestNewBrowserService_DefaultConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)

	config := svc.GetConfig()
	assert.Equal(t, BrowserSystem, config.DefaultBrowser)
	assert.Empty(t, config.CustomCommand)
}

func TestNewBrowserService_NilLogger(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, nil)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, BrowserSystem, svc.GetConfig().DefaultBrowser)
}

func TestNewBrowserService_EmptyPath_UsesDefault(t *testing.T) {
	// With empty configPath, the service resolves to ~/.xkey/config/browser.json.
	// The config file won't exist there, so it falls back to defaults.
	svc, err := NewBrowserService("", testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, BrowserSystem, svc.GetConfig().DefaultBrowser)
}

func TestNewBrowserService_LoadsExistingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	config := BrowserConfig{
		DefaultBrowser: "/usr/bin/firefox",
		CustomCommand:  "",
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0o600))

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)

	loaded := svc.GetConfig()
	assert.Equal(t, "/usr/bin/firefox", loaded.DefaultBrowser)
}

func TestNewBrowserService_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	require.NoError(t, os.WriteFile(configPath, []byte("{invalid json"), 0o600))

	svc, err := NewBrowserService(configPath, testLogger())
	assert.Error(t, err)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrBrowserConfigLoad)
}

// --- GetConfig ---

func TestBrowserService_GetConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	config := svc.GetConfig()
	assert.Equal(t, BrowserSystem, config.DefaultBrowser)
	assert.Empty(t, config.CustomCommand)
}

// --- SetConfig ---

func TestBrowserService_SetConfig_Success(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	newConfig := BrowserConfig{
		DefaultBrowser: "/usr/bin/chromium",
	}
	err = svc.SetConfig(newConfig)
	require.NoError(t, err)

	got := svc.GetConfig()
	assert.Equal(t, "/usr/bin/chromium", got.DefaultBrowser)
}

func TestBrowserService_SetConfig_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Both DefaultBrowser and CustomCommand are empty.
	err = svc.SetConfig(BrowserConfig{})
	assert.ErrorIs(t, err, ErrBrowserInvalidConfig)
}

func TestBrowserService_SetConfig_CustomCommandOnly(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// CustomCommand alone is valid.
	newConfig := BrowserConfig{
		CustomCommand: "/usr/bin/chromium --new-window {url}",
	}
	err = svc.SetConfig(newConfig)
	require.NoError(t, err)

	got := svc.GetConfig()
	assert.Equal(t, "/usr/bin/chromium --new-window {url}", got.CustomCommand)
}

func TestBrowserService_SetConfig_Persists(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	newConfig := BrowserConfig{
		DefaultBrowser: "/usr/bin/brave-browser",
		CustomCommand:  "/usr/bin/brave-browser --incognito {url}",
	}
	require.NoError(t, svc.SetConfig(newConfig))

	// Reload the service from the same config file.
	svc2, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	got := svc2.GetConfig()
	assert.Equal(t, "/usr/bin/brave-browser", got.DefaultBrowser)
	assert.Equal(t, "/usr/bin/brave-browser --incognito {url}", got.CustomCommand)
}

func TestBrowserService_SetConfig_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	// Nested path that doesn't exist yet.
	configPath := filepath.Join(dir, "nested", "deep", "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	newConfig := BrowserConfig{
		DefaultBrowser: BrowserSystem,
	}
	err = svc.SetConfig(newConfig)
	require.NoError(t, err)

	// Verify the file was created.
	_, statErr := os.Stat(configPath)
	assert.NoError(t, statErr)
}

// --- OpenURL ---

func TestBrowserService_OpenURL_EmptyURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	err = svc.OpenURL("")
	assert.ErrorIs(t, err, ErrBrowserEmptyURL)
}

func TestBrowserService_OpenURL_SystemBrowser(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	var recorded [][]string
	var mu sync.Mutex
	svc.execCommand = fakeExecCommand(&recorded, &mu)

	err = svc.OpenURL("https://example.com")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, recorded, 1)
	// First element should be the platform opener.
	assert.Contains(t, recorded[0][0], "xdg-open")
	assert.Equal(t, "https://example.com", recorded[0][1])
}

func TestBrowserService_OpenURL_CustomCommand(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	require.NoError(t, svc.SetConfig(BrowserConfig{
		CustomCommand: "/usr/bin/chromium --new-window {url}",
	}))

	var recorded [][]string
	var mu sync.Mutex
	svc.execCommand = fakeExecCommand(&recorded, &mu)

	err = svc.OpenURL("https://example.com")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, recorded, 1)
	assert.Equal(t, "/usr/bin/chromium", recorded[0][0])
	assert.Equal(t, "--new-window", recorded[0][1])
	assert.Equal(t, "https://example.com", recorded[0][2])
}

func TestBrowserService_OpenURL_SpecificBrowser(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser: "/usr/bin/firefox",
	}))

	var recorded [][]string
	var mu sync.Mutex
	svc.execCommand = fakeExecCommand(&recorded, &mu)

	err = svc.OpenURL("https://example.com/docs")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, recorded, 1)
	assert.Equal(t, "/usr/bin/firefox", recorded[0][0])
	assert.Equal(t, "https://example.com/docs", recorded[0][1])
}

func TestBrowserService_OpenURL_SystemBrowser_LaunchFailed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())
	svc.execCommand = failingExecCommand()

	err = svc.OpenURL("https://example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

func TestBrowserService_OpenURL_CustomCommand_LaunchFailed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	require.NoError(t, svc.SetConfig(BrowserConfig{
		CustomCommand: "/nonexistent-binary {url}",
	}))

	svc.execCommand = failingExecCommand()

	err = svc.OpenURL("https://example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

func TestBrowserService_OpenURL_SpecificBrowser_LaunchFailed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser: "/nonexistent-browser",
	}))

	svc.execCommand = failingExecCommand()

	err = svc.OpenURL("https://example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

func TestBrowserService_OpenURL_CustomCommandPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	// Both DefaultBrowser and CustomCommand set; CustomCommand wins.
	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser: "/usr/bin/firefox",
		CustomCommand:  "/usr/bin/chromium --app={url}",
	}))

	var recorded [][]string
	var mu sync.Mutex
	svc.execCommand = fakeExecCommand(&recorded, &mu)

	err = svc.OpenURL("https://example.com")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, recorded, 1)
	// Should use chromium from CustomCommand, not firefox.
	assert.Equal(t, "/usr/bin/chromium", recorded[0][0])
	assert.Equal(t, "--app=https://example.com", recorded[0][1])
}

// --- DetectBrowsers ---

func TestBrowserService_DetectBrowsers_AlwaysIncludesSystem(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	browsers := svc.DetectBrowsers()
	require.NotEmpty(t, browsers)

	// First entry must be the system default.
	assert.Equal(t, "System Default", browsers[0].Name)
	assert.Equal(t, BrowserSystem, browsers[0].Path)
}

func TestBrowserService_DetectBrowsers_ReturnsValidEntries(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	browsers := svc.DetectBrowsers()

	// All entries beyond "system" should have non-empty names and paths
	// that exist on the filesystem.
	for i, b := range browsers {
		assert.NotEmpty(t, b.Name, "browser %d has empty name", i)
		assert.NotEmpty(t, b.Path, "browser %d has empty path", i)

		if b.Path != BrowserSystem {
			_, err := os.Stat(b.Path)
			assert.NoError(t, err, "detected browser %s at %s should exist", b.Name, b.Path)
		}
	}
}

// --- Config persistence round-trip ---

func TestBrowserService_ConfigPersistence_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Set a custom config.
	original := BrowserConfig{
		DefaultBrowser: "/usr/bin/google-chrome",
		CustomCommand:  "/usr/bin/google-chrome --incognito {url}",
	}
	require.NoError(t, svc.SetConfig(original))

	// Read the raw file and verify it's valid JSON.
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	var persisted BrowserConfig
	require.NoError(t, json.Unmarshal(data, &persisted))
	assert.Equal(t, original.DefaultBrowser, persisted.DefaultBrowser)
	assert.Equal(t, original.CustomCommand, persisted.CustomCommand)

	// Create a new service from the same path and verify config loads.
	svc2, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	reloaded := svc2.GetConfig()
	assert.Equal(t, original.DefaultBrowser, reloaded.DefaultBrowser)
	assert.Equal(t, original.CustomCommand, reloaded.CustomCommand)
}

// --- validateConfig ---

func TestValidateConfig_Valid(t *testing.T) {
	tests := []struct {
		name   string
		config BrowserConfig
	}{
		{
			name:   "system default",
			config: BrowserConfig{DefaultBrowser: BrowserSystem},
		},
		{
			name:   "specific browser",
			config: BrowserConfig{DefaultBrowser: "/usr/bin/firefox"},
		},
		{
			name:   "custom command only",
			config: BrowserConfig{CustomCommand: "/usr/bin/chromium {url}"},
		},
		{
			name: "both set",
			config: BrowserConfig{
				DefaultBrowser: "/usr/bin/firefox",
				CustomCommand:  "/usr/bin/firefox --private {url}",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(tc.config)
			assert.NoError(t, err)
		})
	}
}

func TestValidateConfig_Invalid(t *testing.T) {
	err := validateConfig(BrowserConfig{})
	assert.ErrorIs(t, err, ErrBrowserInvalidConfig)
}

// --- knownBrowsers ---

func TestKnownBrowsers_ReturnsSlice(t *testing.T) {
	browsers := knownBrowsers()
	// On linux, we expect at least some candidates.
	// The exact result depends on the platform, but the function
	// should never panic and always return a slice.
	assert.NotNil(t, browsers)
}

// --- BrowserSystem constant ---

func TestBrowserSystemConstant(t *testing.T) {
	assert.Equal(t, "system", BrowserSystem)
}

// --- Concurrent access ---

func TestBrowserService_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	var recorded [][]string
	var mu sync.Mutex
	svc.execCommand = fakeExecCommand(&recorded, &mu)

	var wg sync.WaitGroup
	const goroutines = 20

	// Concurrent GetConfig/SetConfig/OpenURL should not race.
	for i := 0; i < goroutines; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = svc.GetConfig()
		}()
		go func() {
			defer wg.Done()
			_ = svc.SetConfig(BrowserConfig{DefaultBrowser: BrowserSystem})
		}()
		go func() {
			defer wg.Done()
			_ = svc.OpenURL("https://example.com")
		}()
	}

	wg.Wait()
}

// --- Error types ---

func TestBrowserErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrBrowserEmptyURL,
		ErrBrowserLaunchFailed,
		ErrBrowserInvalidConfig,
		ErrBrowserConfigSave,
		ErrBrowserConfigLoad,
		ErrBrowserTrustBundleExport,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors %d and %d should be distinct", i, j)
		}
	}
}

// --- SaveConfig to read-only path ---

func TestBrowserService_SetConfig_SaveFails(t *testing.T) {
	// Use a path under /proc which is not writable.
	configPath := "/proc/nonexistent/browser.json"

	svc := &BrowserService{
		configPath:  configPath,
		logger:      testLogger().With("service", "browser"),
		execCommand: exec.CommandContext,
		config: BrowserConfig{
			DefaultBrowser: BrowserSystem,
		},
	}

	err := svc.SetConfig(BrowserConfig{DefaultBrowser: BrowserSystem})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserConfigSave)
}

// --- openCustomCommand with empty fields result ---

func TestBrowserService_OpenURL_CustomCommand_EmptyAfterExpansion(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	// Set CustomCommand to just whitespace that becomes empty after Fields().
	svc.mu.Lock()
	svc.config = BrowserConfig{
		CustomCommand: "   ",
	}
	svc.mu.Unlock()

	err = svc.OpenURL("https://example.com")
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

// --- Config file permissions ---

func TestBrowserService_SetConfig_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	require.NoError(t, svc.SetConfig(BrowserConfig{DefaultBrowser: BrowserSystem}))

	info, err := os.Stat(configPath)
	require.NoError(t, err)
	// File should be owner read/write only (0600).
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// ---------------------------------------------------------------------------
// Trust bundle path tests
// ---------------------------------------------------------------------------

func TestBrowserService_SetTrustBundlePath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Initially empty.
	assert.Empty(t, svc.GetTrustBundlePath())

	// Set and verify.
	bundlePath := filepath.Join(dir, "trust-bundle.pem")
	svc.SetTrustBundlePath(bundlePath)
	assert.Equal(t, bundlePath, svc.GetTrustBundlePath())

	// Clear and verify.
	svc.SetTrustBundlePath("")
	assert.Empty(t, svc.GetTrustBundlePath())
}

func TestBrowserService_ApplyTrustBundle_SetsSSLCertFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Enable IncludeTrustBundle so applyTrustBundle actually sets env vars.
	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser:     BrowserSystem,
		IncludeTrustBundle: true,
	}))

	// Create a dummy trust bundle file.
	bundlePath := filepath.Join(dir, "trust-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"), 0o600))

	svc.SetTrustBundlePath(bundlePath)

	// Create a command and apply the trust bundle.
	cmd := exec.CommandContext(context.Background(), "true")
	svc.applyTrustBundle(cmd)

	// Verify SSL_CERT_FILE is set in the command environment.
	require.NotNil(t, cmd.Env, "command environment must be set")
	found := false
	for _, envVar := range cmd.Env {
		if strings.HasPrefix(envVar, "SSL_CERT_FILE=") {
			assert.Equal(t, "SSL_CERT_FILE="+bundlePath, envVar)
			found = true
			break
		}
	}
	assert.True(t, found, "SSL_CERT_FILE must be present in command environment")
}

func TestBrowserService_ApplyTrustBundle_NoBundlePath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// No bundle path set; applyTrustBundle should be a no-op.
	cmd := exec.CommandContext(context.Background(), "true")
	svc.applyTrustBundle(cmd)

	assert.Nil(t, cmd.Env, "command environment should not be modified when no bundle path is set")
}

func TestBrowserService_ApplyTrustBundle_BundleFileDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Enable IncludeTrustBundle.
	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser:     BrowserSystem,
		IncludeTrustBundle: true,
	}))

	// Set a path that does not exist.
	svc.SetTrustBundlePath(filepath.Join(dir, "nonexistent.pem"))

	cmd := exec.CommandContext(context.Background(), "true")
	svc.applyTrustBundle(cmd)

	assert.Nil(t, cmd.Env, "command environment should not be modified when bundle file does not exist")
}

func TestBrowserService_OpenURL_WithTrustBundle(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	svc.SetContext(context.Background())

	// Enable IncludeTrustBundle so applyTrustBundle sets SSL_CERT_FILE.
	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser:     BrowserSystem,
		IncludeTrustBundle: true,
	}))

	// Create a dummy trust bundle.
	bundlePath := filepath.Join(dir, "trust-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"), 0o600))
	svc.SetTrustBundlePath(bundlePath)

	// Use a command capturer that verifies environment is set.
	var capturedCmds []*exec.Cmd
	var mu sync.Mutex
	svc.execCommand = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "true")
		mu.Lock()
		capturedCmds = append(capturedCmds, cmd)
		mu.Unlock()
		return cmd
	}

	err = svc.OpenURL("https://example.com")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, capturedCmds, 1)

	// After applyTrustBundle runs, the command should have SSL_CERT_FILE set.
	cmd := capturedCmds[0]
	require.NotNil(t, cmd.Env)
	found := false
	for _, envVar := range cmd.Env {
		if envVar == "SSL_CERT_FILE="+bundlePath {
			found = true
			break
		}
	}
	assert.True(t, found, "SSL_CERT_FILE should be set on launched browser command")
}

// ---------------------------------------------------------------------------
// IncludeTrustBundle tests
// ---------------------------------------------------------------------------

func TestBrowserConfig_IncludeTrustBundle_Persists(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Save config with IncludeTrustBundle enabled.
	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser:     BrowserSystem,
		IncludeTrustBundle: true,
	}))

	// Create a new service loading from the same path.
	svc2, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	loaded := svc2.GetConfig()
	assert.True(t, loaded.IncludeTrustBundle, "IncludeTrustBundle should persist as true after reload")
}

func TestBrowserConfig_IncludeTrustBundle_DefaultFalse(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")

	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	config := svc.GetConfig()
	assert.False(t, config.IncludeTrustBundle, "IncludeTrustBundle should default to false")
}

func TestApplyTrustBundle_Disabled(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")
	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Create a dummy bundle file.
	bundlePath := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test"), 0o600))
	svc.SetTrustBundlePath(bundlePath)

	// IncludeTrustBundle is false by default.
	cmd := exec.CommandContext(context.Background(), "true")
	svc.applyTrustBundle(cmd)

	// Env should NOT be set since IncludeTrustBundle is false.
	assert.Nil(t, cmd.Env, "Env should be nil when IncludeTrustBundle is false")
}

func TestApplyTrustBundle_Enabled(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")
	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	// Enable trust bundle.
	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser:     BrowserSystem,
		IncludeTrustBundle: true,
	}))

	// Create a dummy bundle file.
	bundlePath := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test"), 0o600))
	svc.SetTrustBundlePath(bundlePath)

	cmd := exec.CommandContext(context.Background(), "true")
	svc.applyTrustBundle(cmd)

	// Env should contain SSL_CERT_FILE.
	require.NotNil(t, cmd.Env, "Env should be set when IncludeTrustBundle is true")
	found := false
	for _, env := range cmd.Env {
		if strings.HasPrefix(env, "SSL_CERT_FILE=") {
			found = true
			assert.Contains(t, env, bundlePath)
			break
		}
	}
	assert.True(t, found, "SSL_CERT_FILE should be in Env")
}

func TestApplyTrustBundle_Enabled_BundleNotExist(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")
	svc, err := NewBrowserService(configPath, testLogger())
	require.NoError(t, err)

	require.NoError(t, svc.SetConfig(BrowserConfig{
		DefaultBrowser:     BrowserSystem,
		IncludeTrustBundle: true,
	}))

	// Set a path to a nonexistent file.
	svc.SetTrustBundlePath(filepath.Join(dir, "nonexistent.pem"))

	cmd := exec.CommandContext(context.Background(), "true")
	svc.applyTrustBundle(cmd)

	// Env should NOT be set since the bundle file doesn't exist.
	assert.Nil(t, cmd.Env, "Env should be nil when bundle file does not exist")
}
