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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #442: the backup directory and the devices file are addressed under
// the resolved xKey home, so XKEY_HOME and portable mode are honoured, and
// an unresolvable home is an error rather than a path under $HOME.

func TestGetBackupDir_LivesUnderTheResolvedHome(t *testing.T) {
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)

	dir, err := getBackupDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "backups"), dir)
}

func TestGetBackupDir_RefusesWhenTheHomeCannotBeResolved(t *testing.T) {
	xhome.ResetRoot()
	// XKEY_HOME is authoritative and is created on demand; a path beneath a
	// regular file cannot be created, so resolution fails instead of
	// falling back to $HOME.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	t.Setenv(xhome.EnvHome, filepath.Join(blocker, "home"))

	dir, err := getBackupDir()
	require.Error(t, err, "an unresolvable home must not degrade to ~/.xkey/backups")
	var resolveErr *xhome.ResolveError
	assert.True(t, errors.As(err, &resolveErr), "the cause is the resolver's own error: %v", err)
	assert.Empty(t, dir)
}

func TestGetDevicesConfigPath_LivesUnderTheResolvedHome(t *testing.T) {
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)
	t.Setenv("SUDO_USER", "")

	path, err := getDevicesConfigPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, devicesConfigFileName), path)
}

// Under sudo the devices file is the invoking user's, so `sudo xkey device
// pair` and the user's own GUI session read the same file; the account
// database is stood in for, so the test touches no real home.
func TestGetDevicesConfigPath_UnderSudoUsesTheInvokingUsersHome(t *testing.T) {
	xhome.ResetRoot()
	t.Setenv(xhome.EnvHome, "")
	t.Setenv("HOME", filepath.Join(t.TempDir(), "root-home-must-not-be-used"))
	invokingHome := t.TempDir()
	t.Setenv("SUDO_USER", "operator")
	saved := lookupUserHome
	lookupUserHome = func(name string) (string, error) {
		require.Equal(t, "operator", name)
		return invokingHome, nil
	}
	t.Cleanup(func() { lookupUserHome = saved })

	path, err := getDevicesConfigPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(invokingHome, ".xkey", devicesConfigFileName), path)
}

// XKEY_HOME set through the sudo environment (sudo -E) still wins over the
// invoking user's home, exactly as it wins for every other command.
func TestGetDevicesConfigPath_UnderSudoEnvOverrideStillWins(t *testing.T) {
	xhome.ResetRoot()
	envHome := t.TempDir()
	t.Setenv(xhome.EnvHome, envHome)
	t.Setenv("SUDO_USER", "operator")
	saved := lookupUserHome
	lookupUserHome = func(string) (string, error) { return t.TempDir(), nil }
	t.Cleanup(func() { lookupUserHome = saved })

	path, err := getDevicesConfigPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(envHome, devicesConfigFileName), path)
}

// An account the database cannot answer for falls back to the process's
// own resolution rather than failing the command outright: SUDO_USER is
// advisory, the resolver is the authority.
func TestGetDevicesConfigPath_UnknownSudoUserFallsBackToProcessResolution(t *testing.T) {
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)
	t.Setenv("SUDO_USER", "nobody-such")
	saved := lookupUserHome
	lookupUserHome = func(string) (string, error) { return "", errors.New("unknown user") }
	t.Cleanup(func() { lookupUserHome = saved })

	path, err := getDevicesConfigPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, devicesConfigFileName), path)
}
