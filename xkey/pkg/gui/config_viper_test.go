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
