package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A relative XDG_CONFIG_HOME is rejected by os.UserConfigDir, so the GUI
// config falls back to ~/.config/xkey and still round-trips.
func TestGUIConfig_RelativeXDGConfigHomeFallsBackToHomeConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "relative/config")
	t.Setenv("HOME", home)

	dir, err := configDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".config", "xkey"), dir)

	cfg := DefaultGUIConfig()
	cfg.Theme = ThemeDark
	require.NoError(t, SaveGUIConfig(cfg))
	assert.FileExists(t, filepath.Join(home, ".config", "xkey", "gui.json"))

	loaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.Equal(t, ThemeDark, loaded.Theme)
}

// When the config directory cannot be created, LoadGUIConfig serves the
// defaults while SaveGUIConfig refuses with ErrConfigSave.
func TestGUIConfig_UncreatableConfigDirLoadsDefaultsAndRefusesSave(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv("XDG_CONFIG_HOME", blocker)

	loaded, err := LoadGUIConfig()
	require.NoError(t, err)
	assert.Equal(t, DefaultGUIConfig(), loaded)

	assert.ErrorIs(t, SaveGUIConfig(DefaultGUIConfig()), ErrConfigSave)
}
