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
// the flags resolveSecretServicePassword reads, isolated from the
// package-level secretServiceCmd singleton.
func newSecretServicePasswordTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "test"}
	addBarrierPasswordFlags(c)
	return c
}

// TestResolveSecretServicePassword_Stdin pins the top-precedence source:
// --barrier-password-stdin. There is no "--barrier-password" value flag
// (go-xkms#1209).
func TestResolveSecretServicePassword_Stdin(t *testing.T) {
	c := newSecretServicePasswordTestCmd()
	stubStdin(t, []byte("stdin-password\n"), nil)
	require.NoError(t, c.Flags().Set(barrierPasswordSource.stdinFlag, "true"))

	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Equal(t, "stdin-password", password)
}

// TestSecretServiceCmd_NoBarrierPasswordValueFlag pins go-xkms#1209: the
// daemon does not accept the barrier password as a flag value, which every
// other process on the host could read through 'ps'.
func TestSecretServiceCmd_NoBarrierPasswordValueFlag(t *testing.T) {
	assert.Nil(t, secretServiceCmd.Flags().Lookup("barrier-password"), "--barrier-password value flag must not exist")
}

func TestResolveSecretServicePassword_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password.txt")
	require.NoError(t, os.WriteFile(path, []byte("file-password\n"), 0600))

	c := newSecretServicePasswordTestCmd()
	require.NoError(t, setFlagForTest(t, c.Flags(), "barrier-password-file", path))

	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Equal(t, "file-password", password)
}

func TestResolveSecretServicePassword_FileMissing(t *testing.T) {
	c := newSecretServicePasswordTestCmd()
	require.NoError(t, setFlagForTest(t, c.Flags(), "barrier-password-file", filepath.Join(t.TempDir(), "nonexistent")))

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

// TestResolveSecretServicePassword_StdinTakesPrecedenceOverEnv pins that
// --barrier-password-stdin outranks XKEY_BARRIER_PASSWORD, the same
// precedence order resolveBarrierPassword uses.
func TestResolveSecretServicePassword_StdinTakesPrecedenceOverEnv(t *testing.T) {
	t.Setenv("XKEY_BARRIER_PASSWORD", "env-password")

	c := newSecretServicePasswordTestCmd()
	stubStdin(t, []byte("stdin-password\n"), nil)
	require.NoError(t, c.Flags().Set(barrierPasswordSource.stdinFlag, "true"))

	password, err := resolveSecretServicePassword(c)
	require.NoError(t, err)
	assert.Equal(t, "stdin-password", password)
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

	for _, name := range []string{"bus", "data-dir", "strategy", "tpm-device", "tpm-simulator", "barrier-password-stdin", "barrier-password-file"} {
		assert.NotNil(t, secretServiceCmd.Flags().Lookup(name), "missing --%s flag", name)
	}
}
