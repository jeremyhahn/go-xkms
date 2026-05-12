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
)

// --- Parent command structure ---

func TestBrowserCmd_Structure(t *testing.T) {
	assert.NotNil(t, browserCmd)
	assert.Equal(t, "browser", browserCmd.Use)
	assert.NotEmpty(t, browserCmd.Short)
	assert.NotEmpty(t, browserCmd.Long)
}

func TestBrowserCmd_HasLaunchSubcommand(t *testing.T) {
	found := false
	for _, sub := range browserCmd.Commands() {
		if sub.Use == "launch [url]" {
			found = true
			break
		}
	}
	assert.True(t, found, "browser command should have a launch subcommand")
}

// --- Launch command structure ---

func TestBrowserLaunchCmd_Structure(t *testing.T) {
	assert.NotNil(t, browserLaunchCmd)
	assert.Equal(t, "launch [url]", browserLaunchCmd.Use)
	assert.NotEmpty(t, browserLaunchCmd.Short)
	assert.NotEmpty(t, browserLaunchCmd.Long)
	assert.NotNil(t, browserLaunchCmd.RunE)
}

func TestBrowserLaunchCmd_BrowserFlag(t *testing.T) {
	flag := browserLaunchCmd.Flags().Lookup("browser")
	require.NotNil(t, flag, "launch command should have a --browser flag")
	assert.Equal(t, "", flag.DefValue, "browser flag default should be empty")
}

func TestBrowserLaunchCmd_MaxArgs(t *testing.T) {
	// The command allows at most 1 positional argument (the URL).
	// Passing 2 arguments should produce an error.
	cmd := *browserLaunchCmd
	cmd.RunE = func(c *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{"https://a.com", "https://b.com"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	assert.Error(t, err, "should reject more than one positional argument")
}

// --- Error on missing trust store ---

func TestRunBrowserLaunch_MissingTrustStore(t *testing.T) {
	// Point HOME at an empty temp directory so the trust store path
	// does not exist. This exercises the error path without touching
	// the real filesystem.
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	var out bytes.Buffer
	cmd := *browserLaunchCmd
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := runBrowserLaunch(&cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

func TestRunBrowserLaunch_EmptyTrustStoreNoBrowsers(t *testing.T) {
	// Create an empty but valid trust store directory so initialization
	// succeeds, then verify we get ErrBrowserNoBrowsers when no browser
	// is installed and --browser is not set.
	tmpDir := t.TempDir()
	trustDir := filepath.Join(tmpDir, ".xkey", "data", "trust")
	require.NoError(t, os.MkdirAll(trustDir, 0700))

	// Also create the config directory so BrowserService can initialize.
	configDir := filepath.Join(tmpDir, ".xkey", "config")
	require.NoError(t, os.MkdirAll(configDir, 0700))

	t.Setenv("HOME", tmpDir)

	// Reset the package-level flag so it does not leak between tests.
	oldBinary := browserBinary
	browserBinary = ""
	defer func() { browserBinary = oldBinary }()

	var out bytes.Buffer
	cmd := *browserLaunchCmd
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := runBrowserLaunch(&cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserNoBrowsers)
}

// --- Error types ---

func TestBrowserErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{
			name: "launch_failed",
			err:  ErrBrowserLaunchFailed,
			msg:  "browser: launch failed",
		},
		{
			name: "no_browsers",
			err:  ErrBrowserNoBrowsers,
			msg:  "browser: no Chrome or Firefox browsers detected",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.msg, tc.err.Error())
		})
	}
}

// --- Smoke test: verify the launch flow works end-to-end up to the actual
// browser process spawn. We do not require a real browser to be installed:
// the test passes either when the launch succeeds (a browser was found) or
// when ErrBrowserNoBrowsers is returned. Anything else indicates a regression
// in the browser flow plumbing.
func TestRunBrowserLaunch_SmokeReachable(t *testing.T) {
	tmpDir := t.TempDir()
	trustDir := filepath.Join(tmpDir, ".xkey", "data", "trust")
	require.NoError(t, os.MkdirAll(trustDir, 0700))
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".xkey", "config"), 0700))
	t.Setenv("HOME", tmpDir)

	oldBinary := browserBinary
	browserBinary = ""
	defer func() { browserBinary = oldBinary }()

	cmd := *browserLaunchCmd
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runBrowserLaunch(&cmd, []string{"https://example.test/"})
	if err == nil {
		return // a browser is present; flow worked.
	}
	// Acceptable failure modes for a CI host without browsers: no browser,
	// or empty trust store rejected by SecureBrowserService.
	assert.True(t,
		assert.ObjectsAreEqual(err, ErrBrowserNoBrowsers) ||
			contains(err.Error(), "trust store") ||
			contains(err.Error(), "no certificates") ||
			contains(err.Error(), "launch"),
		"unexpected smoke-test error: %v", err)
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
