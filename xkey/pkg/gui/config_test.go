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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

func TestDefaultGUIConfig(t *testing.T) {
	cfg := DefaultGUIConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, ThemeSystem, cfg.Theme)
	assert.Equal(t, DefaultWindowWidth, cfg.WindowWidth)
	assert.Equal(t, DefaultWindowHeight, cfg.WindowHeight)
	assert.True(t, cfg.AutoTray)
	assert.True(t, cfg.Notifications)
	assert.True(t, cfg.RememberPosition)
	assert.False(t, cfg.StartMinimized)
}

func TestGUIConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultGUIConfig()
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestGUIConfig_Validate_InvalidTheme(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.Theme = "invalid"
	err := cfg.Validate()
	assert.Error(t, err)
}

func TestGUIConfig_Validate_InvalidProtocol(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.ServerProtocol = "carrier-pigeon"
	err := cfg.Validate()
	assert.ErrorIs(t, err, ErrInvalidProtocol)
}

func TestGUIConfig_Validate_EmptyProtocolIsAllowed(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.ServerProtocol = ""
	assert.NoError(t, cfg.Validate(), "an empty protocol means unset, not invalid")
}

func TestGUIConfig_Validate_ZeroWidth(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.WindowWidth = 0
	err := cfg.Validate()
	assert.NoError(t, err)
	assert.Equal(t, DefaultWindowWidth, cfg.WindowWidth)
}

func TestGUIConfig_Validate_ZeroHeight(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.WindowHeight = -1
	err := cfg.Validate()
	assert.NoError(t, err)
	assert.Equal(t, DefaultWindowHeight, cfg.WindowHeight)
}

func TestGUIConfig_Validate_NegativeTimeoutsDisable(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.ClipboardTimeout = -5
	cfg.AppAutoLockMinutes = -1

	require.NoError(t, cfg.Validate())

	assert.Zero(t, cfg.ClipboardTimeout, "a negative clipboard timeout means never clear")
	assert.Zero(t, cfg.AppAutoLockMinutes, "a negative auto-lock means never lock")
}

func TestDefaultGUIConfig_SandboxPolicyIsSafe(t *testing.T) {
	cfg := DefaultGUIConfig()
	assert.Equal(t, config.SafeDefaultAPIExplorerSandboxPolicy, cfg.APIExplorerSandboxPolicy)
	assert.NotContains(t, cfg.APIExplorerSandboxPolicy, "allow-same-origin",
		"the shipped default must never combine allow-same-origin with allow-scripts (go-xkms#1274)")
}

// TestGUIConfig_Validate_SandboxPolicyDangerousComboNormalized locks in the
// self-healing behavior of Validate for the allow-scripts + allow-same-origin
// combination: every installation created before go-xkms#1274 already has
// the old dangerous default persisted on disk, so Validate normalizes the
// field rather than failing the whole config load/save.
func TestGUIConfig_Validate_SandboxPolicyDangerousComboNormalized(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.APIExplorerSandboxPolicy = "allow-same-origin allow-scripts allow-forms allow-popups"

	err := cfg.Validate()

	require.NoError(t, err)
	assert.Equal(t, config.SafeDefaultAPIExplorerSandboxPolicy, cfg.APIExplorerSandboxPolicy)
}

func TestGUIConfig_Validate_SandboxPolicyForbiddenDirectiveNormalized(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.APIExplorerSandboxPolicy = "allow-forms allow-modals"

	err := cfg.Validate()

	require.NoError(t, err)
	assert.Equal(t, config.SafeDefaultAPIExplorerSandboxPolicy, cfg.APIExplorerSandboxPolicy)
}

func TestGUIConfig_Validate_SandboxPolicySafeCombinationPreserved(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.APIExplorerSandboxPolicy = "allow-same-origin allow-forms"

	err := cfg.Validate()

	require.NoError(t, err)
	assert.Equal(t, "allow-same-origin allow-forms", cfg.APIExplorerSandboxPolicy,
		"allow-same-origin without allow-scripts is not the dangerous combination")
}

func TestSaveAndLoadGUIConfig(t *testing.T) {
	// Create a temporary directory to act as HOME.
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() {
		_ = os.Setenv("HOME", origHome)
	}()

	cfg := DefaultGUIConfig()
	cfg.Theme = ThemeDark
	cfg.WindowWidth = 1280
	cfg.WindowHeight = 800
	cfg.StartMinimized = true

	// Save.
	err := SaveGUIConfig(cfg)
	require.NoError(t, err)

	// Verify file exists.
	cfgPath := filepath.Join(tmpDir, ".config", "xkey", "gui.json")
	_, statErr := os.Stat(cfgPath)
	assert.NoError(t, statErr)

	// Read file and verify JSON.
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var loaded GUIConfig
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)
	assert.Equal(t, ThemeDark, loaded.Theme)
	assert.Equal(t, 1280, loaded.WindowWidth)
	assert.Equal(t, 800, loaded.WindowHeight)
	assert.True(t, loaded.StartMinimized)
}

func TestLoadGUIConfig_InvalidThemeInFileFails(t *testing.T) {
	isolateAppEnv(t)
	cfgPath, err := guiConfigPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(cfgPath), 0700))
	require.NoError(t, os.WriteFile(cfgPath, []byte(`{"theme":"neon"}`), 0600))

	cfg, err := LoadGUIConfig()

	require.Error(t, err, "a stored config that fails validation is not loaded")
	assert.Nil(t, cfg)
}

func TestSaveGUIConfig_NilConfig(t *testing.T) {
	err := SaveGUIConfig(nil)
	assert.Error(t, err)
}

func TestSaveGUIConfig_InvalidTheme(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.Theme = "nope"
	err := SaveGUIConfig(cfg)
	assert.Error(t, err)
}

func TestLoadGUIConfig_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() {
		_ = os.Setenv("HOME", origHome)
	}()

	cfg, err := LoadGUIConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, ThemeSystem, cfg.Theme)
}

func TestLoadGUIConfig_CorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() {
		_ = os.Setenv("HOME", origHome)
	}()

	dir := filepath.Join(tmpDir, ".config", "xkey")
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gui.json"), []byte("{invalid json"), 0600))

	_, err := LoadGUIConfig()
	assert.Error(t, err)
}

func TestGUIConfig_JSONRoundtrip(t *testing.T) {
	cfg := &GUIConfig{
		AutoTray:         true,
		Theme:            ThemeLight,
		StartMinimized:   true,
		Notifications:    false,
		WindowWidth:      1920,
		WindowHeight:     1080,
		RememberPosition: true,
		WindowX:          100,
		WindowY:          200,
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var decoded GUIConfig
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, cfg.AutoTray, decoded.AutoTray)
	assert.Equal(t, cfg.Theme, decoded.Theme)
	assert.Equal(t, cfg.StartMinimized, decoded.StartMinimized)
	assert.Equal(t, cfg.Notifications, decoded.Notifications)
	assert.Equal(t, cfg.WindowWidth, decoded.WindowWidth)
	assert.Equal(t, cfg.WindowHeight, decoded.WindowHeight)
	assert.Equal(t, cfg.RememberPosition, decoded.RememberPosition)
	assert.Equal(t, cfg.WindowX, decoded.WindowX)
	assert.Equal(t, cfg.WindowY, decoded.WindowY)
}

// ---------------------------------------------------------------------------
// Auto-unseal config field tests
// ---------------------------------------------------------------------------

func TestGUIConfig_SetupComplete_DefaultFalse(t *testing.T) {
	cfg := DefaultGUIConfig()
	assert.False(t, cfg.SetupComplete)
}

func TestGUIConfig_SetupComplete_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() {
		_ = os.Setenv("HOME", origHome)
	}()

	cfg := DefaultGUIConfig()
	cfg.SetupComplete = true

	err := SaveGUIConfig(cfg)
	require.NoError(t, err)

	cfgPath := filepath.Join(tmpDir, ".config", "xkey", "gui.json")
	data, readErr := os.ReadFile(cfgPath)
	require.NoError(t, readErr)

	var loaded GUIConfig
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)
	assert.True(t, loaded.SetupComplete)
}

// ---------------------------------------------------------------------------
// configDir tests
// ---------------------------------------------------------------------------

func TestConfigDir_ReturnsXKeySubdir(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	dir, err := configDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(tmpDir, ".config", "xkey"), dir)

	// Directory must exist.
	info, statErr := os.Stat(dir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

func TestConfigDir_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	dir, err := configDir()
	require.NoError(t, err)
	require.DirExists(t, dir)
	assert.Equal(t, filepath.Join(tmpDir, ".config", "xkey"), dir)
}

// TestConfigDir_HomeUnset_ReturnsError covers the fallback branch: with
// neither XDG_CONFIG_HOME nor HOME set, os.UserConfigDir() fails ("$HOME is
// not defined"), and the fallback to os.UserHomeDir() fails for the same
// reason, so configDir must surface a wrapped ErrConfigLoad rather than
// panicking or resolving a nonsense path.
func TestConfigDir_HomeUnset_ReturnsError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	_, err := configDir()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigLoad)
}

// TestConfigDir_MkdirAllFails covers the directory-creation error branch:
// when a regular file occupies the path configDir would create the "xkey"
// subdirectory under, os.MkdirAll fails.
func TestConfigDir_MkdirAllFails(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfgBase := filepath.Join(tmpDir, ".config")
	require.NoError(t, os.MkdirAll(cfgBase, 0700))
	// Occupy the "xkey" path with a file so MkdirAll cannot create it as a directory.
	require.NoError(t, os.WriteFile(filepath.Join(cfgBase, "xkey"), []byte("x"), 0600))

	_, err := configDir()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigLoad)
}

// ---------------------------------------------------------------------------
// Error sentinel tests for new errors
// ---------------------------------------------------------------------------

func TestErrorSentinels_DataDir(t *testing.T) {
	assert.NotNil(t, ErrDataDirInit)
	assert.NotNil(t, ErrDataDirAlreadyInit)
	assert.Contains(t, ErrDataDirInit.Error(), "data directory")
	assert.Contains(t, ErrDataDirAlreadyInit.Error(), "already initialized")
}

// ---------------------------------------------------------------------------
// SetupComplete and barrier field round-trip persistence tests
// ---------------------------------------------------------------------------

func TestSaveLoadGUIConfig_SetupCompleteRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	cfg := DefaultGUIConfig()
	cfg.SetupComplete = true
	cfg.BarrierInitialized = true
	cfg.BarrierStrategy = "software"

	err := SaveGUIConfig(cfg)
	require.NoError(t, err)

	loaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.True(t, loaded.SetupComplete, "SetupComplete must survive round-trip")
	assert.True(t, loaded.BarrierInitialized, "BarrierInitialized must survive round-trip")
	assert.Equal(t, "software", loaded.BarrierStrategy, "BarrierStrategy must survive round-trip")
}

func TestSaveLoadGUIConfig_SetupCompleteDefaultFalse(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	// No config file exists at this path; LoadGUIConfig should return defaults.
	cfg, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.False(t, cfg.SetupComplete, "SetupComplete must default to false when no file exists")
}

func TestSaveLoadGUIConfig_AllBarrierFieldsPreserved(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	cfg := DefaultGUIConfig()
	cfg.SetupComplete = true
	cfg.BarrierInitialized = true
	cfg.BarrierStrategy = "tpm2"
	cfg.BarrierAutoUnsealEnabled = true
	cfg.StorageType = "barrier"
	cfg.SealerBackend = "tpm2"

	err := SaveGUIConfig(cfg)
	require.NoError(t, err)

	loaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.True(t, loaded.SetupComplete)
	assert.True(t, loaded.BarrierInitialized)
	assert.Equal(t, "tpm2", loaded.BarrierStrategy)
	assert.True(t, loaded.BarrierAutoUnsealEnabled)
	assert.Equal(t, "barrier", loaded.StorageType)
	assert.Equal(t, "tpm2", loaded.SealerBackend)
}

func TestSaveGUIConfig_CreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	cfg := DefaultGUIConfig()
	cfg.SetupComplete = true

	err := SaveGUIConfig(cfg)
	require.NoError(t, err)

	cfgPath := filepath.Join(tmpDir, ".config", "xkey", "gui.json")
	info, statErr := os.Stat(cfgPath)
	require.NoError(t, statErr, "config file must exist on disk after save")
	assert.False(t, info.IsDir())

	data, readErr := os.ReadFile(cfgPath)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), `"setup_complete": true`,
		"saved JSON must contain setup_complete set to true")
}
