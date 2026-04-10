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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
)

// --- parseBrowser tests ---

func TestExtensionParseBrowser_Chrome(t *testing.T) {
	browsers, err := parseBrowser("chrome")
	require.NoError(t, err)
	require.Len(t, browsers, 1)
	assert.Equal(t, nativemsg.BrowserChrome, browsers[0])
}

func TestExtensionParseBrowser_Firefox(t *testing.T) {
	browsers, err := parseBrowser("firefox")
	require.NoError(t, err)
	require.Len(t, browsers, 1)
	assert.Equal(t, nativemsg.BrowserFirefox, browsers[0])
}

func TestExtensionParseBrowser_All(t *testing.T) {
	browsers, err := parseBrowser("all")
	require.NoError(t, err)
	require.Len(t, browsers, 2)
	assert.Equal(t, nativemsg.BrowserChrome, browsers[0])
	assert.Equal(t, nativemsg.BrowserFirefox, browsers[1])
}

func TestExtensionParseBrowser_EmptyDefaultsToAll(t *testing.T) {
	browsers, err := parseBrowser("")
	require.NoError(t, err)
	require.Len(t, browsers, 2)
	assert.Equal(t, nativemsg.BrowserChrome, browsers[0])
	assert.Equal(t, nativemsg.BrowserFirefox, browsers[1])
}

func TestExtensionParseBrowser_Invalid(t *testing.T) {
	browsers, err := parseBrowser("safari")
	assert.Nil(t, browsers)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExtensionInvalidBrowser)
}

func TestExtensionParseBrowser_InvalidCaseSensitive(t *testing.T) {
	browsers, err := parseBrowser("Chrome")
	assert.Nil(t, browsers)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExtensionInvalidBrowser)
}

func TestExtensionParseBrowser_BraveNotAccepted(t *testing.T) {
	// "brave" is no longer a separate browser; use "chrome" instead.
	browsers, err := parseBrowser("brave")
	assert.Nil(t, browsers)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExtensionInvalidBrowser)
}

func TestExtensionParseBrowser_ChromiumNotAccepted(t *testing.T) {
	// "chromium" is no longer a separate browser; use "chrome" instead.
	browsers, err := parseBrowser("chromium")
	assert.Nil(t, browsers)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExtensionInvalidBrowser)
}

// --- browserArg tests ---

func TestExtensionBrowserArg_WithArg(t *testing.T) {
	assert.Equal(t, "chrome", browserArg([]string{"chrome"}))
}

func TestExtensionBrowserArg_NoArgs(t *testing.T) {
	assert.Equal(t, "all", browserArg(nil))
}

func TestExtensionBrowserArg_EmptySlice(t *testing.T) {
	assert.Equal(t, "all", browserArg([]string{}))
}

func TestExtensionBrowserArg_MultipleArgs(t *testing.T) {
	// Only the first argument is used.
	assert.Equal(t, "firefox", browserArg([]string{"firefox", "chrome"}))
}

// --- Command registration tests ---

func TestExtensionCmd_Exists(t *testing.T) {
	assert.NotNil(t, extensionCmd)
}

func TestExtensionCmd_Properties(t *testing.T) {
	assert.Equal(t, "extension", extensionCmd.Use)
	assert.NotEmpty(t, extensionCmd.Short)
	assert.NotEmpty(t, extensionCmd.Long)
	assert.Contains(t, extensionCmd.Short, "Browser extension")
}

func TestExtensionCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Name() == "extension" {
			found = true
			break
		}
	}
	assert.True(t, found, "extension command should be registered on root")
}

func TestExtensionCmd_Subcommands(t *testing.T) {
	subcommands := extensionCmd.Commands()

	names := make(map[string]bool, len(subcommands))
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["install"], "extension should have install subcommand")
	assert.True(t, names["uninstall"], "extension should have uninstall subcommand")
	assert.True(t, names["status"], "extension should have status subcommand")
	assert.True(t, names["host"], "extension should have host subcommand")
	assert.True(t, names["serve"], "extension should have serve subcommand")
	assert.True(t, names["unpair"], "extension should have unpair subcommand")
	assert.True(t, names["pair-status"], "extension should have pair-status subcommand")
	assert.Len(t, subcommands, 7, "extension should have exactly 7 subcommands")
}

// --- Subcommand structure tests ---

func TestExtensionInstallCmd_Structure(t *testing.T) {
	assert.NotNil(t, extensionInstallCmd)
	assert.Equal(t, "install [chrome|firefox|all]", extensionInstallCmd.Use)
	assert.NotEmpty(t, extensionInstallCmd.Short)
	assert.NotEmpty(t, extensionInstallCmd.Long)
	assert.NotNil(t, extensionInstallCmd.RunE)
}

func TestExtensionUninstallCmd_Structure(t *testing.T) {
	assert.NotNil(t, extensionUninstallCmd)
	assert.Equal(t, "uninstall [chrome|firefox|all]", extensionUninstallCmd.Use)
	assert.NotEmpty(t, extensionUninstallCmd.Short)
	assert.NotEmpty(t, extensionUninstallCmd.Long)
	assert.NotNil(t, extensionUninstallCmd.RunE)
}

func TestExtensionStatusCmd_Structure(t *testing.T) {
	assert.NotNil(t, extensionStatusCmd)
	assert.Equal(t, "status", extensionStatusCmd.Use)
	assert.NotEmpty(t, extensionStatusCmd.Short)
	assert.NotEmpty(t, extensionStatusCmd.Long)
	assert.NotNil(t, extensionStatusCmd.RunE)
}

func TestExtensionHostCmd_Structure(t *testing.T) {
	assert.NotNil(t, extensionHostCmd)
	assert.Equal(t, "host", extensionHostCmd.Use)
	assert.NotEmpty(t, extensionHostCmd.Short)
	assert.NotEmpty(t, extensionHostCmd.Long)
	assert.NotNil(t, extensionHostCmd.RunE)
	assert.True(t, extensionHostCmd.Hidden, "host command should be hidden from user help")
}

func TestExtensionHostCmd_SocketFlag(t *testing.T) {
	flag := extensionHostCmd.Flags().Lookup("socket")
	require.NotNil(t, flag, "host command should have --socket flag")
	assert.Equal(t, "", flag.DefValue)
}

// --- Error sentinel tests ---

func TestExtensionErrors(t *testing.T) {
	tests := []struct {
		err      error
		contains string
	}{
		{ErrExtensionInstallFailed, "extension: install failed"},
		{ErrExtensionUninstallFailed, "extension: uninstall failed"},
		{ErrExtensionInvalidBrowser, "extension: invalid browser (use chrome, firefox, or all)"},
		{ErrExtensionHostFailed, "extension: host failed"},
	}

	for _, tc := range tests {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Equal(t, tc.contains, tc.err.Error())
			assert.True(t, strings.HasPrefix(tc.err.Error(), "extension:"))
		})
	}
}

func TestExtensionErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrExtensionInstallFailed,
		ErrExtensionUninstallFailed,
		ErrExtensionInvalidBrowser,
		ErrExtensionHostFailed,
	}

	seen := make(map[string]bool, len(errs))
	for _, err := range errs {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestExtensionErrors_Wrapping(t *testing.T) {
	innerErr := errors.New("permission denied")
	wrapped := errors.Join(ErrExtensionInstallFailed, innerErr)

	assert.ErrorIs(t, wrapped, ErrExtensionInstallFailed)
	assert.ErrorIs(t, wrapped, innerErr)
	assert.Contains(t, wrapped.Error(), "permission denied")
	assert.Contains(t, wrapped.Error(), "extension: install failed")
}

// --- Long description content tests ---

func TestExtensionInstallCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, extensionInstallCmd.Long, "chrome")
	assert.Contains(t, extensionInstallCmd.Long, "firefox")
	assert.Contains(t, extensionInstallCmd.Long, "all")
	assert.Contains(t, extensionInstallCmd.Long, "Chromium-based")
}

func TestExtensionUninstallCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, extensionUninstallCmd.Long, "chrome")
	assert.Contains(t, extensionUninstallCmd.Long, "firefox")
	assert.Contains(t, extensionUninstallCmd.Long, "all")
	assert.Contains(t, extensionUninstallCmd.Long, "Chromium-based")
}

func TestExtensionStatusCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, extensionStatusCmd.Long, "status")
	assert.Contains(t, extensionStatusCmd.Long, "xkey extension status")
}

func TestExtensionHostCmd_LongDescriptionContent(t *testing.T) {
	assert.Contains(t, extensionHostCmd.Long, "browser")
	assert.Contains(t, extensionHostCmd.Long, "not be run manually")
}
