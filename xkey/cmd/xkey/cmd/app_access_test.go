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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// isolateGUISettings points the xKey settings file at a fresh temporary
// config directory, so a test never reads or writes the host's settings.
func isolateGUISettings(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// enableLocalAppAccessForTest isolates the settings file and turns local
// app access on in it.
func enableLocalAppAccessForTest(t *testing.T) {
	t.Helper()
	isolateGUISettings(t)
	cfg := gui.DefaultGUIConfig()
	cfg.LocalAppAccessEnabled = true
	require.NoError(t, gui.SaveGUIConfig(cfg))
}

// writeGUISettings isolates the settings file and writes raw contents to it.
func writeGUISettings(t *testing.T, contents []byte) {
	t.Helper()
	isolateGUISettings(t)
	dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "xkey")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gui.json"), contents, 0o600))
}

// runAppAccess runs one app-access subcommand and returns its output.
func runAppAccess(t *testing.T, sub *cobra.Command) (string, error) {
	t.Helper()
	var out bytes.Buffer
	sub.SetOut(&out)
	t.Cleanup(func() { sub.SetOut(nil) })
	err := sub.RunE(sub, nil)
	return out.String(), err
}

func TestAppAccessCmd_Registered(t *testing.T) {
	names := make(map[string]bool)
	for _, sub := range appAccessCmd.Commands() {
		names[sub.Name()] = true
	}
	assert.Equal(t, map[string]bool{"status": true, "enable": true, "disable": true}, names)
	assert.Contains(t, RootCmd.Commands(), appAccessCmd)
}

func TestAppAccessStatus_DefaultsOff(t *testing.T) {
	isolateGUISettings(t)

	out, err := runAppAccess(t, appAccessStatusCmd)

	require.NoError(t, err)
	assert.Equal(t, "Local app access: off\n", out)
}

func TestAppAccess_EnableAndDisablePersist(t *testing.T) {
	isolateGUISettings(t)

	out, err := runAppAccess(t, appAccessEnableCmd)
	require.NoError(t, err)
	assert.Equal(t, "Local app access: on\n", out)
	cfg, err := gui.LoadGUIConfig()
	require.NoError(t, err)
	assert.True(t, cfg.LocalAppAccessEnabled)

	out, err = runAppAccess(t, appAccessDisableCmd)
	require.NoError(t, err)
	assert.Equal(t, "Local app access: off\n", out)
	cfg, err = gui.LoadGUIConfig()
	require.NoError(t, err)
	assert.False(t, cfg.LocalAppAccessEnabled)
}

func TestAppAccess_EnableKeepsOtherSettings(t *testing.T) {
	isolateGUISettings(t)
	cfg := gui.DefaultGUIConfig()
	cfg.Theme = "dark"
	require.NoError(t, gui.SaveGUIConfig(cfg))

	_, err := runAppAccess(t, appAccessEnableCmd)

	require.NoError(t, err)
	saved, err := gui.LoadGUIConfig()
	require.NoError(t, err)
	assert.Equal(t, "dark", saved.Theme)
}

func TestAppAccess_UnreadableSettings(t *testing.T) {
	for _, sub := range []*cobra.Command{appAccessStatusCmd, appAccessEnableCmd, appAccessDisableCmd} {
		t.Run(sub.Name(), func(t *testing.T) {
			writeGUISettings(t, []byte("{not json"))

			_, err := runAppAccess(t, sub)

			assert.ErrorIs(t, err, ErrAppAccessLoadFailed)
			assert.ErrorIs(t, err, gui.ErrConfigLoad)
		})
	}
}

func TestExtensionServe_RefusesWhenLocalAppAccessOff(t *testing.T) {
	isolateGUISettings(t)
	tmpDir := t.TempDir()
	xhome.SetRoot(tmpDir)
	t.Cleanup(xhome.ResetRoot)
	socketPath := filepath.Join(privateTempDir(t), "test.sock")

	cmd := newTestServeCmd()
	cmd.RunE = runExtensionServe
	require.NoError(t, cmd.Flags().Set("socket", socketPath))
	require.NoError(t, cmd.Flags().Set("no-barrier", "true"))

	err := cmd.Execute()

	require.ErrorIs(t, err, ErrServeLocalAppAccessDisabled)
	assert.Contains(t, err.Error(), "xkey app-access enable")
	_, statErr := os.Lstat(socketPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "no socket may be opened")
	entries, readErr := os.ReadDir(tmpDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "nothing may be created under the xKey home")
}

func TestExtensionServe_UnreadableSettings(t *testing.T) {
	writeGUISettings(t, []byte("{not json"))

	cmd := newTestServeCmd()
	cmd.RunE = runExtensionServe

	err := cmd.Execute()

	assert.ErrorIs(t, err, ErrAppAccessLoadFailed)
}
