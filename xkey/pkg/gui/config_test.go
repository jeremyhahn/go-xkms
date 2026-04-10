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

func TestGUIConfig_AutoUnsealFields_JSONRoundtrip(t *testing.T) {
	cfg := &GUIConfig{
		Theme:             ThemeSystem,
		WindowWidth:       1024,
		WindowHeight:      768,
		AutoUnsealEnabled: true,
		AutoUnsealBlobID:  "blob-abc123",
		AutoUnsealPCRs:    []int{0, 7, 14},
		AutoUnsealPCRBank: "sha256",
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var decoded GUIConfig
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.True(t, decoded.AutoUnsealEnabled)
	assert.Equal(t, "blob-abc123", decoded.AutoUnsealBlobID)
	assert.Equal(t, []int{0, 7, 14}, decoded.AutoUnsealPCRs)
	assert.Equal(t, "sha256", decoded.AutoUnsealPCRBank)
}

func TestGUIConfig_AutoUnsealFields_DefaultsZero(t *testing.T) {
	cfg := DefaultGUIConfig()
	assert.False(t, cfg.AutoUnsealEnabled)
	assert.Empty(t, cfg.AutoUnsealBlobID)
	assert.Nil(t, cfg.AutoUnsealPCRs)
	assert.Empty(t, cfg.AutoUnsealPCRBank)
}

func TestSaveAndLoadGUIConfig_AutoUnsealFields(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() {
		_ = os.Setenv("HOME", origHome)
	}()

	cfg := DefaultGUIConfig()
	cfg.AutoUnsealEnabled = true
	cfg.AutoUnsealBlobID = "blob-xyz789"
	cfg.AutoUnsealPCRs = []int{0, 1, 7}
	cfg.AutoUnsealPCRBank = "sha384"

	// Save.
	err := SaveGUIConfig(cfg)
	require.NoError(t, err)

	// Read file and verify the auto-unseal fields are persisted.
	cfgPath := filepath.Join(tmpDir, ".config", "xkey", "gui.json")
	data, readErr := os.ReadFile(cfgPath)
	require.NoError(t, readErr)

	var loaded GUIConfig
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)
	assert.True(t, loaded.AutoUnsealEnabled)
	assert.Equal(t, "blob-xyz789", loaded.AutoUnsealBlobID)
	assert.Equal(t, []int{0, 1, 7}, loaded.AutoUnsealPCRs)
	assert.Equal(t, "sha384", loaded.AutoUnsealPCRBank)
}

func TestGUIConfig_AutoUnsealFields_Validate_DoesNotReject(t *testing.T) {
	cfg := DefaultGUIConfig()
	cfg.AutoUnsealEnabled = true
	cfg.AutoUnsealBlobID = "test-blob"
	cfg.AutoUnsealPCRs = []int{0}
	cfg.AutoUnsealPCRBank = "sha256"

	err := cfg.Validate()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// SetupComplete config field tests
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

// ---------------------------------------------------------------------------
// Legacy migration tests
// ---------------------------------------------------------------------------

func TestLoadGUIConfig_MigratesFromLegacyPath(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	// Write config at the legacy path.
	legacyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(legacyDir, 0700))
	legacyCfg := `{"theme":"dark","window_width":1920,"window_height":1080}`
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, "gui.json"), []byte(legacyCfg), 0600))

	// Load should migrate and succeed.
	cfg, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.Equal(t, ThemeDark, cfg.Theme)
	assert.Equal(t, 1920, cfg.WindowWidth)

	// New config file should now exist.
	newPath := filepath.Join(tmpDir, ".config", "xkey", "gui.json")
	assert.FileExists(t, newPath)
}

func TestLoadGUIConfig_NewPathTakesPrecedenceOverLegacy(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", origHome) }()

	// Write config at both old and new paths with different themes.
	legacyDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(legacyDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(legacyDir, "gui.json"),
		[]byte(`{"theme":"dark","window_width":1024,"window_height":768}`),
		0600,
	))

	newDir := filepath.Join(tmpDir, ".config", "xkey")
	require.NoError(t, os.MkdirAll(newDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(newDir, "gui.json"),
		[]byte(`{"theme":"light","window_width":1024,"window_height":768}`),
		0600,
	))

	// New path should take precedence.
	cfg, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.Equal(t, ThemeLight, cfg.Theme)
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
	cfg.BarrierAutoUnsealBlobID = "blob-barrier-99"
	cfg.StorageType = "barrier"
	cfg.PINStrategy = "tpm2"
	cfg.SealerBackend = "tpm2"

	err := SaveGUIConfig(cfg)
	require.NoError(t, err)

	loaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.True(t, loaded.SetupComplete)
	assert.True(t, loaded.BarrierInitialized)
	assert.Equal(t, "tpm2", loaded.BarrierStrategy)
	assert.Equal(t, "blob-barrier-99", loaded.BarrierAutoUnsealBlobID)
	assert.Equal(t, "barrier", loaded.StorageType)
	assert.Equal(t, "tpm2", loaded.PINStrategy)
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
