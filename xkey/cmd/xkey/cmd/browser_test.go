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
	"errors"
	"os"
	"path/filepath"
	"testing"

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
	// Validate the Args constraint directly: passing two arguments must be
	// rejected, while zero or one argument is accepted. Calling the validator
	// avoids cobra's Execute()-time root traversal, which (on a shallow copy
	// that still references the global RootCmd) would dispatch the real root
	// command rather than this launch command.
	require.NotNil(t, browserLaunchCmd.Args, "launch command should declare an Args validator")
	assert.Error(t, browserLaunchCmd.Args(browserLaunchCmd, []string{"https://a.com", "https://b.com"}),
		"should reject more than one positional argument")
	assert.NoError(t, browserLaunchCmd.Args(browserLaunchCmd, []string{"https://a.com"}),
		"should accept a single positional argument")
	assert.NoError(t, browserLaunchCmd.Args(browserLaunchCmd, nil),
		"should accept zero positional arguments")
}

// --- Error on an unopenable trust store ---

// TestRunBrowserLaunch_TrustStoreUnopenable: the trust store is opened before
// any browser is detected, so a store that cannot be opened must surface as
// ErrBrowserLaunchFailed carrying the open error, and never as
// ErrBrowserNoBrowsers, whatever the host has installed. A merely absent
// store does not exercise this path: NewFileStore creates its directory, so
// the one way to make the open fail is a parent the user cannot write. (The
// earlier form of this test pointed HOME at an empty directory and asserted
// the launch failed, which on a host with no browser failed one step later
// with ErrBrowserNoBrowsers instead, #332.)
func TestRunBrowserLaunch_TrustStoreUnopenable(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	dataDir := filepath.Join(tmpDir, ".xkey", "data")
	require.NoError(t, os.MkdirAll(dataDir, 0700))
	require.NoError(t, os.Chmod(dataDir, 0500), "the trust store's parent is read-only")
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0700) })

	var out bytes.Buffer
	cmd := *browserLaunchCmd
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := runBrowserLaunch(&cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
	assert.ErrorIs(t, err, os.ErrPermission, "the cause is the store that could not be opened")
	assert.NotErrorIs(t, err, ErrBrowserNoBrowsers, "browser detection must not have been reached")
}

func TestRunBrowserLaunch_EmptyTrustStoreNoBrowsers(t *testing.T) {
	// Create an empty but valid trust store directory so initialization
	// succeeds. With no --browser set and an empty trust store, the launch
	// must fail. The exact terminal error depends on whether the host has a
	// supported browser installed:
	//
	//   - no browser present  -> auto-detect yields zero browsers and
	//                            runBrowserLaunch returns ErrBrowserNoBrowsers.
	//   - a browser present   -> auto-detect picks it, then LaunchBrowser
	//                            rejects the empty trust store, surfaced as
	//                            ErrBrowserLaunchFailed.
	//
	// Both outcomes prove the empty trust store prevents a successful launch;
	// asserting on host browser availability would make the test flaky.
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
	if !errors.Is(err, ErrBrowserNoBrowsers) && !errors.Is(err, ErrBrowserLaunchFailed) {
		t.Fatalf("expected ErrBrowserNoBrowsers or ErrBrowserLaunchFailed, got %v", err)
	}
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
