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

// TestLoadGUIConfig_ViperOverlayAllKeys sets every viper key LoadGUIConfig
// checks to a non-default value and verifies each lands on the
// corresponding GUIConfig field. TestLoadGUIConfig_FileThenViperOverride
// above pins the precedence contract for one field (theme); this pins that
// every other `if viper.IsSet(...)` branch actually reads its own key into
// its own field, rather than, say, a copy-pasted block that reads the wrong
// key or writes the wrong field.
func TestLoadGUIConfig_ViperOverlayAllKeys(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	viper.Reset()
	t.Cleanup(viper.Reset)

	defaults := DefaultGUIConfig()

	overlay := map[string]any{
		"gui.auto_tray":                   !defaults.AutoTray,
		"gui.theme":                       ThemeDark,
		"gui.start_minimized":             !defaults.StartMinimized,
		"gui.notifications":               !defaults.Notifications,
		"gui.window_width":                defaults.WindowWidth + 111,
		"gui.window_height":               defaults.WindowHeight + 222,
		"gui.remember_position":           !defaults.RememberPosition,
		"gui.window_x":                    42,
		"gui.window_y":                    84,
		"gui.server_address":              "kms.example.com:9443",
		"gui.server_protocol":             "unix",
		"gui.server_tls_enabled":          !defaults.ServerTLSEnabled,
		"gui.server_tls_skip_verify":      !defaults.ServerTLSSkipVerify,
		"gui.server_tls_ca_file":          "/tmp/ca.pem",
		"gui.server_spki_pin":             "deadbeef",
		"gui.server_auto_connect":         !defaults.ServerAutoConnect,
		"gui.auto_unseal_enabled":         !defaults.AutoUnsealEnabled,
		"gui.auto_unseal_blob_id":         "blob-123",
		"gui.auto_unseal_tpm_policy":      "platform",
		"gui.auto_unseal_backend":         "tpm2",
		"gui.fido2_authenticator_enabled": !defaults.FIDO2AuthenticatorEnabled,
		"gui.clipboard_timeout":           defaults.ClipboardTimeout + 5,
		"gui.require_auth":                !defaults.RequireAuth,
		"gui.app_auto_lock_minutes":       defaults.AppAutoLockMinutes + 5,
		"gui.app_lock_on_screen_lock":     !defaults.AppLockOnScreenLock,
		"gui.setup_complete":              !defaults.SetupComplete,
		"gui.barrier_auto_unseal_enabled": !defaults.BarrierAutoUnsealEnabled,
		"gui.sealer_backend":              "tpm2",
		"gui.api_explorer_sandbox_policy": "allow-forms",
		"gui.developer_tools":             !defaults.DeveloperTools,
		"gui.fido2_require_user_presence": !defaults.FIDO2RequireUserPresence,
		"gui.fido2_user_intent_check":     !defaults.FIDO2UserIntentCheck,
	}
	for key, value := range overlay {
		viper.Set(key, value)
	}

	cfg, err := LoadGUIConfig()
	require.NoError(t, err)

	want := &GUIConfig{
		AutoTray:                  overlay["gui.auto_tray"].(bool),
		Theme:                     ThemeDark,
		StartMinimized:            overlay["gui.start_minimized"].(bool),
		Notifications:             overlay["gui.notifications"].(bool),
		WindowWidth:               overlay["gui.window_width"].(int),
		WindowHeight:              overlay["gui.window_height"].(int),
		RememberPosition:          overlay["gui.remember_position"].(bool),
		WindowX:                   42,
		WindowY:                   84,
		ServerAddress:             "kms.example.com:9443",
		ServerProtocol:            "unix",
		ServerTLSEnabled:          overlay["gui.server_tls_enabled"].(bool),
		ServerTLSSkipVerify:       overlay["gui.server_tls_skip_verify"].(bool),
		ServerTLSCAFile:           "/tmp/ca.pem",
		ServerSPKIPin:             "deadbeef",
		ServerAutoConnect:         overlay["gui.server_auto_connect"].(bool),
		AutoUnsealEnabled:         overlay["gui.auto_unseal_enabled"].(bool),
		AutoUnsealBlobID:          "blob-123",
		AutoUnsealTPMPolicy:       "platform",
		AutoUnsealBackend:         "tpm2",
		FIDO2AuthenticatorEnabled: overlay["gui.fido2_authenticator_enabled"].(bool),
		ClipboardTimeout:          overlay["gui.clipboard_timeout"].(int),
		RequireAuth:               overlay["gui.require_auth"].(bool),
		AppAutoLockMinutes:        overlay["gui.app_auto_lock_minutes"].(int),
		AppLockOnScreenLock:       overlay["gui.app_lock_on_screen_lock"].(bool),
		SetupComplete:             overlay["gui.setup_complete"].(bool),
		BarrierAutoUnsealEnabled:  overlay["gui.barrier_auto_unseal_enabled"].(bool),
		SealerBackend:             "tpm2",
		APIExplorerSandboxPolicy:  "allow-forms",
		LocalAppAccessEnabled:     defaults.LocalAppAccessEnabled, // no viper overlay for this field
		DeveloperTools:            overlay["gui.developer_tools"].(bool),
		FIDO2RequireUserPresence:  overlay["gui.fido2_require_user_presence"].(bool),
		FIDO2UserIntentCheck:      overlay["gui.fido2_user_intent_check"].(bool),
	}
	assert.Equal(t, want, cfg)
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
