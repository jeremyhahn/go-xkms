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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// executePasswordAdd runs `xkey password add` through the root command with
// the given flags and returns its error and output.
func executePasswordAdd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetCommandFlagsForTest(t, RootCmd)
	resetPasswordFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs(append([]string{"password", "add"}, args...))
	err := RootCmd.Execute()
	return buf.String(), err
}

// unusablePasswordStore returns a store path below a regular file, which the
// file storage backend cannot create.
func unusablePasswordStore(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	return filepath.Join(file, "passwords")
}

// storedPasswordNames lists the names in the on-disk store.
func storedPasswordNames(t *testing.T, storePath string) []string {
	t.Helper()
	store, err := openPasswordStore(storePath)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	passwords, err := store.List()
	require.NoError(t, err)
	names := make([]string, 0, len(passwords))
	for _, pw := range passwords {
		names = append(names, pw.Name)
	}
	return names
}

func TestRunPasswordAdd_DuplicateNameKeepsTheStoredPassword(t *testing.T) {
	store := t.TempDir()
	addTestPassword(t, store, samplePassword("DatabaseProd"))
	t.Setenv("XKEY_STATIC_PASSWORD", "replacement")

	out, err := executePasswordAdd(t, "--name", "DatabaseProd", "--store", store)
	require.ErrorIs(t, err, ErrPasswordAddFailed)
	assert.NotContains(t, out, "Added password:")

	cmd, buf, _ := passwordTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "store", store))
	require.NoError(t, runPasswordGet(cmd, []string{"DatabaseProd"}))
	assert.Equal(t, "s3cr3t-value", buf.String(), "a refused add must not overwrite the entry")
}

func TestRunPasswordAdd_BlankNameIsRefused(t *testing.T) {
	store := t.TempDir()
	t.Setenv("XKEY_STATIC_PASSWORD", "s3cr3t")

	_, err := executePasswordAdd(t, "--name", "   ", "--store", store)
	require.ErrorIs(t, err, ErrPasswordAddFailed)
	assert.Empty(t, storedPasswordNames(t, store))
}

func TestRunPasswordAdd_GenerateRejectsTooShortLength(t *testing.T) {
	store := t.TempDir()

	out, err := executePasswordAdd(t, "--name", "Short", "--generate", "--length", "1", "--store", store)
	require.ErrorIs(t, err, ErrPasswordGenerateFailed)
	assert.NotContains(t, out, "Generated:")
	assert.Empty(t, storedPasswordNames(t, store))
}

func TestRunPasswordAdd_UnusableStoreIsAnError(t *testing.T) {
	t.Setenv("XKEY_STATIC_PASSWORD", "s3cr3t")

	_, err := executePasswordAdd(t, "--name", "Svc", "--store", unusablePasswordStore(t))
	require.ErrorIs(t, err, ErrPasswordStoreOpenFailed)
}

func TestRunPasswordRemove_UnusableStoreIsAnError(t *testing.T) {
	cmd, buf, _ := passwordTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "store", unusablePasswordStore(t)))

	require.ErrorIs(t, runPasswordRemove(cmd, []string{"DatabaseProd"}), ErrPasswordStoreOpenFailed)
	assert.Empty(t, buf.String())
}

func TestRunPasswordRemove_UnreadableConfirmationKeepsPassword(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	addTestPassword(t, store, samplePassword("DatabaseProd"))
	// EOF before a newline: the answer cannot be read, so nothing is removed.
	pipeStdin(t, "")

	require.NoError(t, runPasswordRemove(cmd, []string{"DatabaseProd"}))
	assert.NotContains(t, buf.String(), "Removed:")
	assert.Equal(t, []string{"DatabaseProd"}, storedPasswordNames(t, store))
}

func TestRunPasswordList_UnusableStoreIsAnError(t *testing.T) {
	cmd, buf, _ := passwordTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "store", unusablePasswordStore(t)))

	require.ErrorIs(t, runPasswordList(cmd, nil), ErrPasswordStoreOpenFailed)
	assert.NotContains(t, buf.String(), "No passwords found.",
		"a store that cannot be opened must not be reported as empty")
}
