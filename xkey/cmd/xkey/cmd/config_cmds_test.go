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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// isolateConfigFlags saves and restores the package-level config command
// state so tests cannot leak into one another.
func isolateConfigFlags(t *testing.T) {
	t.Helper()

	previousFile := cfgFile
	previousForce := configInitForce
	previousLoaded := loadedConfig

	cfgFile = ""
	configInitForce = false

	t.Cleanup(func() {
		cfgFile = previousFile
		configInitForce = previousForce
		loadedConfig = previousLoaded
	})
}

func runConfigCmd(t *testing.T, run func(*cobra.Command, []string) error) (string, error) {
	t.Helper()

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := run(cmd, nil)
	return buf.String(), err
}

// --- config show ---

func TestRunConfigShow_EmitsLoadedConfigAsYAML(t *testing.T) {
	isolateConfigFlags(t)
	dir := t.TempDir()
	cfgFile = filepath.Join(dir, "xkey.yaml")

	cfg := xkeyconfig.DefaultConfig()
	require.NoError(t, xkeyconfig.SaveToPath(cfg, cfgFile))
	loadedConfig = cfg

	out, err := runConfigCmd(t, runConfigShow)
	require.NoError(t, err)
	assert.Contains(t, out, "# Configuration loaded from: "+cfgFile)

	// The body must be valid YAML that round-trips back into the config type.
	var decoded xkeyconfig.Config
	require.NoError(t, yaml.Unmarshal([]byte(stripComments(out)), &decoded))
	assert.Equal(t, cfg.Log.Level, decoded.Log.Level)
}

func TestRunConfigShow_FallsBackToDefaultsWhenNothingLoaded(t *testing.T) {
	isolateConfigFlags(t)
	cfgFile = filepath.Join(t.TempDir(), "absent.yaml")
	loadedConfig = nil

	out, err := runConfigCmd(t, runConfigShow)
	require.NoError(t, err)
	assert.Contains(t, out, "# No configuration file loaded (using defaults and environment)")

	var decoded xkeyconfig.Config
	require.NoError(t, yaml.Unmarshal([]byte(stripComments(out)), &decoded))
	assert.Equal(t, xkeyconfig.DefaultConfig().Log.Level, decoded.Log.Level)
}

// stripComments removes the leading "#" annotation lines so the remainder
// can be parsed as YAML.
func stripComments(s string) string {
	var body []byte
	for _, line := range bytes.Split([]byte(s), []byte("\n")) {
		if len(line) > 0 && line[0] == '#' {
			continue
		}
		body = append(body, line...)
		body = append(body, '\n')
	}
	return string(body)
}

// --- config init ---

func TestRunConfigInit_CreatesFileAtFlagPath(t *testing.T) {
	isolateConfigFlags(t)
	// The global --config flag must be honoured; writing to the default XDG
	// path instead would silently ignore the operator's choice.
	cfgFile = filepath.Join(t.TempDir(), "nested", "xkey.yaml")

	out, err := runConfigCmd(t, runConfigInit)
	require.NoError(t, err)
	assert.Contains(t, out, "Created configuration file: "+cfgFile)
	assert.FileExists(t, cfgFile)

	loaded, err := xkeyconfig.LoadFromPath(cfgFile)
	require.NoError(t, err)
	assert.Equal(t, xkeyconfig.DefaultConfig().Log.Level, loaded.Log.Level)
}

func TestRunConfigInit_RefusesToOverwriteWithoutForce(t *testing.T) {
	isolateConfigFlags(t)
	cfgFile = filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("log:\n  level: debug\n"), 0600))

	out, err := runConfigCmd(t, runConfigInit)
	assert.ErrorIs(t, err, ErrConfigFileExists)
	assert.Contains(t, out, "Configuration file already exists: "+cfgFile)
	assert.Contains(t, out, "Use --force to overwrite.")

	// The original file must be untouched.
	data, readErr := os.ReadFile(cfgFile)
	require.NoError(t, readErr)
	assert.Equal(t, "log:\n  level: debug\n", string(data))
}

func TestRunConfigInit_ForceOverwrites(t *testing.T) {
	isolateConfigFlags(t)
	cfgFile = filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("log:\n  level: debug\n"), 0600))
	configInitForce = true

	out, err := runConfigCmd(t, runConfigInit)
	require.NoError(t, err)
	assert.Contains(t, out, "Overwriting existing configuration file: "+cfgFile)
	assert.Contains(t, out, "Created configuration file: "+cfgFile)

	loaded, err := xkeyconfig.LoadFromPath(cfgFile)
	require.NoError(t, err)
	assert.Equal(t, xkeyconfig.DefaultConfig().Log.Level, loaded.Log.Level)
}

func TestRunConfigInit_ReportsWriteFailure(t *testing.T) {
	isolateConfigFlags(t)
	// A path whose parent is a regular file cannot be created.
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	cfgFile = filepath.Join(blocker, "xkey.yaml")

	_, err := runConfigCmd(t, runConfigInit)
	require.Error(t, err)

	var initErr *ConfigInitError
	require.ErrorAs(t, err, &initErr)
	assert.Equal(t, cfgFile, initErr.Path)
}

// --- config path ---

func TestRunConfigPath_ShowsFlagPathFirst(t *testing.T) {
	isolateConfigFlags(t)
	cfgFile = filepath.Join(t.TempDir(), "custom.yaml")

	out, err := runConfigCmd(t, runConfigPath)
	require.NoError(t, err)
	assert.Contains(t, out, "Configuration search paths:")
	assert.Contains(t, out, cfgFile+" (from --config flag)")
	assert.Contains(t, out, "Currently using: "+cfgFile)
}

func TestRunConfigPath_MarksExistingFiles(t *testing.T) {
	isolateConfigFlags(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	userPath := xkeyconfig.ConfigPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(userPath), 0700))
	require.NoError(t, os.WriteFile(userPath, []byte("log:\n  level: info\n"), 0600))

	out, err := runConfigCmd(t, runConfigPath)
	require.NoError(t, err)
	assert.Contains(t, out, userPath+" (exists)")
	assert.Contains(t, out, "Currently using: "+userPath)
}

func TestRunConfigPath_ReportsNoConfigWhenNoneExist(t *testing.T) {
	isolateConfigFlags(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	out, err := runConfigCmd(t, runConfigPath)
	require.NoError(t, err)
	assert.Contains(t, out, xkeyconfig.ConfigPath())
	assert.Contains(t, out, xkeyconfig.SystemConfigPath())

	// The system path may genuinely exist on a machine with xkey installed;
	// only assert the "none found" line when neither path is present.
	if _, statErr := os.Stat(xkeyconfig.SystemConfigPath()); os.IsNotExist(statErr) {
		assert.Contains(t, out, "No configuration file currently loaded.")
	}
}

// --- error types ---

func TestConfigShowError(t *testing.T) {
	err := &ConfigShowError{Err: os.ErrPermission}
	assert.Equal(t, "config show failed: permission denied", err.Error())
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestConfigInitError(t *testing.T) {
	withPath := &ConfigInitError{Path: "/etc/xkey/xkey.yaml", Err: os.ErrPermission}
	assert.Equal(t, "config init failed for /etc/xkey/xkey.yaml: permission denied", withPath.Error())
	assert.ErrorIs(t, withPath, os.ErrPermission)

	withoutPath := &ConfigInitError{Err: os.ErrPermission}
	assert.Equal(t, "config init failed: permission denied", withoutPath.Error())
}

func TestConfigPathError(t *testing.T) {
	err := &ConfigPathError{Err: os.ErrPermission}
	assert.Equal(t, "config path failed: permission denied", err.Error())
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestConfigError_MessageAndUnwrap(t *testing.T) {
	withPath := &ConfigError{Operation: "load_config", Path: "/tmp/x.yaml", Err: os.ErrNotExist}
	assert.Equal(t, "config load_config failed for /tmp/x.yaml: file does not exist", withPath.Error())
	assert.ErrorIs(t, withPath, os.ErrNotExist)

	withoutPath := &ConfigError{Operation: "resolve_home", Err: os.ErrNotExist}
	assert.Equal(t, "config resolve_home failed: file does not exist", withoutPath.Error())
}
