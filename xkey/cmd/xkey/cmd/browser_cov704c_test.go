package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// c704cBrowserHome points the xKey home at a fresh directory, with the
// default trust-store location, and returns the home root.
func c704cBrowserHome(t *testing.T) string {
	t.Helper()
	isolateDataDirSources(t)
	root := t.TempDir()
	t.Setenv(xhome.EnvHome, root)
	viper.Set("trust.store_path", "")
	t.Cleanup(func() { viper.Set("trust.store_path", "") })
	return root
}

// c704cBrowserCmd returns a copy of the launch command with an explicit
// --binary, so no browser on the host is ever detected or started.
func c704cBrowserCmd(t *testing.T, binary string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	oldBinary := browserBinary
	browserBinary = binary
	t.Cleanup(func() { browserBinary = oldBinary })

	out := &bytes.Buffer{}
	cmd := *browserLaunchCmd
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	return &cmd, out
}

// TestC704cBrowserLaunch_CorruptConfigRefuses proves an unreadable browser
// configuration stops the launch rather than silently using defaults.
func TestC704cBrowserLaunch_CorruptConfigRefuses(t *testing.T) {
	root := c704cBrowserHome(t)
	configDir := filepath.Join(root, "config")
	require.NoError(t, os.MkdirAll(configDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "browser.json"), []byte("{not json"), 0600))

	cmd, out := c704cBrowserCmd(t, filepath.Join(t.TempDir(), "chrome"))
	err := runBrowserLaunch(cmd, []string{"https://example.test/"})
	require.ErrorIs(t, err, ErrBrowserLaunchFailed)
	require.ErrorIs(t, err, services.ErrBrowserConfigLoad)
	assert.Empty(t, out.String(), "nothing is reported launched")
}

// TestC704cBrowserLaunch_EmptyTrustStoreNeverLaunches proves an explicit
// --binary is still refused, before anything is executed, while the trust
// store holds no certificate to inject.
func TestC704cBrowserLaunch_EmptyTrustStoreNeverLaunches(t *testing.T) {
	c704cBrowserHome(t)

	cmd, out := c704cBrowserCmd(t, filepath.Join(t.TempDir(), "chrome"))
	err := runBrowserLaunch(cmd, []string{"https://example.test/"})
	require.ErrorIs(t, err, ErrBrowserLaunchFailed)
	require.ErrorIs(t, err, services.ErrSecureBrowserNoCerts)
	assert.NotContains(t, out.String(), "Auto-detected", "an explicit --binary skips detection")
	assert.NotContains(t, out.String(), "Launched")
}
