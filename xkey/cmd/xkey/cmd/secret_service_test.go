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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSecretServicePasswordTestCmd builds a bare *cobra.Command carrying just
// the two flags resolveSecretServicePassword reads, isolated from the
// package-level secretServiceCmd singleton.
func newSecretServicePasswordTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.Flags().String("barrier-password", "", "")
	c.Flags().String("barrier-password-file", "", "")
	return c
}

func TestResolveSecretServicePassword_Flag(t *testing.T) {
	c := newSecretServicePasswordTestCmd()
	require.NoError(t, c.Flags().Set("barrier-password", "flag-password"))

	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Equal(t, "flag-password", password)
}

func TestResolveSecretServicePassword_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password.txt")
	require.NoError(t, os.WriteFile(path, []byte("file-password\n"), 0600))

	c := newSecretServicePasswordTestCmd()
	require.NoError(t, c.Flags().Set("barrier-password-file", path))

	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Equal(t, "file-password", password)
}

func TestResolveSecretServicePassword_FileMissing(t *testing.T) {
	c := newSecretServicePasswordTestCmd()
	require.NoError(t, c.Flags().Set("barrier-password-file", filepath.Join(t.TempDir(), "nonexistent")))

	_, err := resolveSecretServicePassword(c)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretServiceUnlockFailed)
}

func TestResolveSecretServicePassword_Env(t *testing.T) {
	t.Setenv("XKEY_BARRIER_PASSWORD", "env-password")

	c := newSecretServicePasswordTestCmd()
	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Equal(t, "env-password", password)
}

func TestResolveSecretServicePassword_NoneConfiguredIsNotAnError(t *testing.T) {
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	c := newSecretServicePasswordTestCmd()
	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Empty(t, password)
}

func TestResolveSecretServicePassword_FlagTakesPrecedenceOverEnv(t *testing.T) {
	t.Setenv("XKEY_BARRIER_PASSWORD", "env-password")

	c := newSecretServicePasswordTestCmd()
	require.NoError(t, c.Flags().Set("barrier-password", "flag-password"))

	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Equal(t, "flag-password", password)
}

// TestSecretServiceCmd_Registered proves `xkey secret-service` is wired
// into the root command with the flags runSecretService depends on.
func TestSecretServiceCmd_Registered(t *testing.T) {
	found := false
	for _, c := range RootCmd.Commands() {
		if c.Name() == "secret-service" {
			found = true
			break
		}
	}
	require.True(t, found, "secret-service must be registered under the root command")

	for _, name := range []string{"bus", "data-dir", "strategy", "tpm-device", "tpm-simulator", "barrier-password", "barrier-password-file"} {
		assert.NotNil(t, secretServiceCmd.Flags().Lookup(name), "missing --%s flag", name)
	}
}
