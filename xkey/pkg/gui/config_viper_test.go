// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadGUIConfig_ViperOverlay verifies every viper key LoadGUIConfig
// consults actually reaches the field it documents. Each key is set to a
// value that differs from both the zero value and DefaultGUIConfig's value,
// so a key string that was mistyped (and therefore silently ignored, since
// viper.IsSet would be false) or mapped to the wrong field is caught by a
// mismatch rather than by a coincidental pass.
func TestLoadGUIConfig_ViperOverlay(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("gui.auto_tray", false) // default true
	viper.Set("gui.theme", ThemeDark) // default system
	viper.Set("gui.start_minimized", true)
	viper.Set("gui.notifications", false)
	viper.Set("gui.window_width", 1600)
	viper.Set("gui.window_height", 900)
	viper.Set("gui.remember_position", false)
	viper.Set("gui.window_x", 42)
	viper.Set("gui.window_y", 84)
	viper.Set("gui.server_address", "kms.example.com:9443")
	viper.Set("gui.server_protocol", "quic")
	viper.Set("gui.server_tls_enabled", true)
	viper.Set("gui.server_tls_skip_verify", true)
	viper.Set("gui.server_tls_ca_file", "/etc/xkey/ca.pem")
	viper.Set("gui.server_spki_pin", "deadbeef")
	viper.Set("gui.server_auto_connect", true)
	viper.Set("gui.auto_unseal_enabled", true)
	viper.Set("gui.auto_unseal_blob_id", "blob-overlay")
	viper.Set("gui.auto_unseal_pcr_bank", "sha384")
	viper.Set("gui.auto_unseal_policy_type", "pcr")
	viper.Set("gui.auto_unseal_policy_name", "boot-policy")
	viper.Set("gui.auto_unseal_backend", "tpm2")
	viper.Set("gui.fido2_authenticator_enabled", false)
	viper.Set("gui.clipboard_timeout", 90)
	viper.Set("gui.require_auth", false)
	viper.Set("gui.app_auto_lock_minutes", 5)
	viper.Set("gui.app_lock_on_screen_lock", false)
	viper.Set("gui.setup_complete", true)
	viper.Set("gui.barrier_auto_unseal_blob_id", "blob-barrier-overlay")
	viper.Set("gui.barrier_auto_unseal_enabled", true)
	viper.Set("gui.sealer_backend", "passphrase")
	viper.Set("gui.api_explorer_sandbox_policy", "allow-scripts")
	viper.Set("gui.developer_tools", false)
	viper.Set("gui.fido2_require_user_presence", false)
	viper.Set("gui.fido2_user_intent_check", false)

	cfg, err := LoadGUIConfig()
	require.NoError(t, err)

	assert.False(t, cfg.AutoTray)
	assert.Equal(t, ThemeDark, cfg.Theme)
	assert.True(t, cfg.StartMinimized)
	assert.False(t, cfg.Notifications)
	assert.Equal(t, 1600, cfg.WindowWidth)
	assert.Equal(t, 900, cfg.WindowHeight)
	assert.False(t, cfg.RememberPosition)
	assert.Equal(t, 42, cfg.WindowX)
	assert.Equal(t, 84, cfg.WindowY)
	assert.Equal(t, "kms.example.com:9443", cfg.ServerAddress)
	assert.Equal(t, "quic", cfg.ServerProtocol)
	assert.True(t, cfg.ServerTLSEnabled)
	assert.True(t, cfg.ServerTLSSkipVerify)
	assert.Equal(t, "/etc/xkey/ca.pem", cfg.ServerTLSCAFile)
	assert.True(t, cfg.AutoUnsealEnabled)
	assert.Equal(t, "blob-overlay", cfg.AutoUnsealBlobID)
	assert.Equal(t, "sha384", cfg.AutoUnsealPCRBank)
	assert.Equal(t, "pcr", cfg.AutoUnsealPolicyType)
	assert.Equal(t, "boot-policy", cfg.AutoUnsealPolicyName)
	assert.Equal(t, "tpm2", cfg.AutoUnsealBackend)
	assert.False(t, cfg.FIDO2AuthenticatorEnabled)
	assert.Equal(t, 90, cfg.ClipboardTimeout)
	assert.False(t, cfg.RequireAuth)
	assert.Equal(t, 5, cfg.AppAutoLockMinutes)
	assert.False(t, cfg.AppLockOnScreenLock)
	assert.True(t, cfg.SetupComplete)
	assert.Equal(t, "blob-barrier-overlay", cfg.BarrierAutoUnsealBlobID)
	assert.True(t, cfg.BarrierAutoUnsealEnabled)
	assert.Equal(t, "passphrase", cfg.SealerBackend)
	assert.Equal(t, "allow-scripts", cfg.APIExplorerSandboxPolicy)
	assert.False(t, cfg.DeveloperTools)
	assert.False(t, cfg.FIDO2RequireUserPresence)
	assert.False(t, cfg.FIDO2UserIntentCheck)
}

// TestLoadGUIConfig_ViperOverlayUnset confirms the companion negative case:
// with no viper keys set, LoadGUIConfig leaves every field at its
// DefaultGUIConfig value rather than picking up zero values from an
// accidentally-always-true IsSet check.
func TestLoadGUIConfig_ViperOverlayUnset(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.Reset()
	t.Cleanup(viper.Reset)

	cfg, err := LoadGUIConfig()
	require.NoError(t, err)

	want := DefaultGUIConfig()
	assert.Equal(t, want, cfg)
}

// TestLoadGUIConfig_FileThenViperOverride verifies precedence: a value
// persisted to gui.json is overridden by an explicitly-set viper key, per
// LoadGUIConfig's documented "viper values take precedence" contract.
func TestLoadGUIConfig_FileThenViperOverride(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.Reset()
	t.Cleanup(viper.Reset)

	cfg := DefaultGUIConfig()
	cfg.Theme = ThemeDark
	cfg.WindowWidth = 1234
	require.NoError(t, SaveGUIConfig(cfg))

	viper.Set("gui.theme", ThemeLight)

	loaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.Equal(t, ThemeLight, loaded.Theme, "viper must win over the persisted file")
	assert.Equal(t, 1234, loaded.WindowWidth, "a field with no viper override keeps the file's value")
}

// TestLoadGUIConfig_ReadFileNonNotExistError covers the branch where the
// config file exists but cannot be read as a regular file (e.g., a
// directory sits at the expected path). This must surface a wrapped
// ErrConfigLoad rather than silently falling back to defaults, which is
// reserved for the "file does not exist" case only.
func TestLoadGUIConfig_ReadFileNonNotExistError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.Reset()
	t.Cleanup(viper.Reset)

	cfgPath := filepath.Join(tmpDir, ".config", "xkey", "gui.json")
	require.NoError(t, os.MkdirAll(cfgPath, 0700)) // a directory, not a file

	_, err := LoadGUIConfig()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigLoad)
}

// TestSaveGUIConfig_MkdirAllFails covers SaveGUIConfig's directory-creation
// error branch: when the parent path is occupied by a regular file,
// os.MkdirAll cannot create the config directory underneath it.
func TestSaveGUIConfig_MkdirAllFails(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Occupy ~/.config with a file so configDir()'s MkdirAll("~/.config/xkey")
	// fails: "not a directory".
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".config"), []byte("x"), 0600))

	err := SaveGUIConfig(DefaultGUIConfig())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigSave)
}

// TestSaveGUIConfig_WriteFileFails covers the write-permission error branch:
// the config directory exists but is not writable, so os.WriteFile for the
// temp file fails. This assumes a non-root test runner, which every make
// test / CI invocation in this repository uses; root ignores directory
// write permissions entirely, which would make the assertion meaningless
// rather than merely inapplicable.
func TestSaveGUIConfig_WriteFileFails(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Create the directory writable first (MkdirAll needs write access on
	// the parent to create each path segment), then lock it down.
	cfgDir := filepath.Join(tmpDir, ".config", "xkey")
	require.NoError(t, os.MkdirAll(cfgDir, 0700))
	require.NoError(t, os.Chmod(cfgDir, 0500))
	t.Cleanup(func() { _ = os.Chmod(cfgDir, 0700) }) // let t.TempDir() clean up

	err := SaveGUIConfig(DefaultGUIConfig())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigSave)
}
