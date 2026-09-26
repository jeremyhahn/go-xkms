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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// withIsolatedExtensionHome points xhome.Resolve (which runExtensionInstall
// calls directly) at a private temporary directory for the duration of the
// test, so a --profile-dir install never touches the developer's real
// ~/.xkey.
func withIsolatedExtensionHome(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)
	return root
}

func newExtensionInstallTestCmd(t *testing.T, profileDir string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "install"}
	cmd.Flags().String("allowed-origin", "", "")
	cmd.Flags().String("profile-dir", profileDir, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func newExtensionUninstallTestCmd(t *testing.T, profileDir string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "uninstall"}
	cmd.Flags().String("profile-dir", profileDir, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

// TestRunExtensionInstall_ProfileDirWritesManifestPinnedToInstance is the
// go-xkms #1033 acceptance test for part 2: a manifest installed for one
// Chrome profile launches a host bound to exactly the instance that installed
// it, via a generated launcher under that instance's home.
func TestRunExtensionInstall_ProfileDirWritesManifestPinnedToInstance(t *testing.T) {
	home := withIsolatedExtensionHome(t)
	profileDir := t.TempDir()

	cmd, out := newExtensionInstallTestCmd(t, profileDir)
	err := runExtensionInstall(cmd, []string{"chrome"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "chrome profile")

	manifestPath := filepath.Join(profileDir, "NativeMessagingHosts", nativemsg.NativeHostName+".json")
	data, readErr := os.ReadFile(manifestPath)
	require.NoError(t, readErr, "manifest must be written under the profile directory, not the OS-wide default")

	var m nativemsg.Manifest
	require.NoError(t, json.Unmarshal(data, &m))

	launcherPath := filepath.Join(home, "run", "extension-host-launcher.sh")
	assert.Equal(t, launcherPath, m.Path, "the manifest must launch this instance's launcher, not the raw binary")

	launcherContents, readErr := os.ReadFile(launcherPath)
	require.NoError(t, readErr)
	script := string(launcherContents)
	assert.Contains(t, script, "export XKEY_HOME=\""+home+"\"")
	assert.Contains(t, script, "extension host")
}

// TestRunExtensionInstall_ProfileDirRejectsNonChromeBrowser proves the
// "chrome only" guard: --profile-dir with any other browser selection is
// refused rather than silently installing into the shared default for one of
// the two families.
func TestRunExtensionInstall_ProfileDirRejectsNonChromeBrowser(t *testing.T) {
	withIsolatedExtensionHome(t)
	profileDir := t.TempDir()

	cmd, _ := newExtensionInstallTestCmd(t, profileDir)
	err := runExtensionInstall(cmd, []string{"firefox"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExtensionProfileDirChromeOnly)

	// The default ("all") selection is equally rejected: it resolves to two
	// browsers, not exactly chrome.
	cmd, _ = newExtensionInstallTestCmd(t, profileDir)
	err = runExtensionInstall(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExtensionProfileDirChromeOnly)

	// Nothing must have been written for the rejected attempts.
	_, statErr := os.Stat(filepath.Join(profileDir, "NativeMessagingHosts"))
	assert.True(t, os.IsNotExist(statErr))
}

// TestRunExtensionUninstall_ProfileDirRemovesManifest covers the successful
// removal path, symmetric with install.
func TestRunExtensionUninstall_ProfileDirRemovesManifest(t *testing.T) {
	withIsolatedExtensionHome(t)
	profileDir := t.TempDir()

	installCmd, _ := newExtensionInstallTestCmd(t, profileDir)
	require.NoError(t, runExtensionInstall(installCmd, []string{"chrome"}))

	uninstallCmd, out := newExtensionUninstallTestCmd(t, profileDir)
	err := runExtensionUninstall(uninstallCmd, []string{"chrome"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Uninstalled")

	_, statErr := os.Stat(filepath.Join(profileDir, "NativeMessagingHosts", nativemsg.NativeHostName+".json"))
	assert.True(t, os.IsNotExist(statErr))
}

// TestRunExtensionUninstall_ProfileDirRejectsNonChromeBrowser mirrors the
// install-side guard for uninstall.
func TestRunExtensionUninstall_ProfileDirRejectsNonChromeBrowser(t *testing.T) {
	withIsolatedExtensionHome(t)
	profileDir := t.TempDir()

	cmd, _ := newExtensionUninstallTestCmd(t, profileDir)
	err := runExtensionUninstall(cmd, []string{"firefox"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExtensionProfileDirChromeOnly)
}
