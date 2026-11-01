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
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// corruptStoredDigits rewrites the digits of the named credential directly in
// the store file. FileStore.load does not validate, so this models a store
// edited by hand or written by an older build: the credential loads, but
// oath.NewGenerator refuses it.
func corruptStoredDigits(t *testing.T, storePath, name string) {
	t.Helper()

	data, err := os.ReadFile(storePath)
	require.NoError(t, err)
	var doc struct {
		Credentials []map[string]any `json:"credentials"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	found := false
	for _, cred := range doc.Credentials {
		if cred["name"] == name {
			cred["digits"] = 3
			found = true
		}
	}
	require.True(t, found, "credential %q must be in the store", name)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(storePath, out, 0o600))
}

// writeUnreadableOATHStore leaves a store file that is not JSON at all.
func writeUnreadableOATHStore(t *testing.T) string {
	t.Helper()

	store := oathStorePath(t)
	require.NoError(t, os.WriteFile(store, []byte("{not json"), 0o600))
	return store
}

func TestRunOATHGenerate_AllSkipsCredentialTheGeneratorRefuses(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))
	addTestCredential(t, store, totpCredential("Broken"))
	corruptStoredDigits(t, store, "Broken")

	cmd, buf := newOATHCmd(t, oathGenerateCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "all", "true"))
	require.NoError(t, runOATHGenerate(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "GitHub")
	assert.Regexp(t, sixDigits, out)
	assert.NotContains(t, out, "Broken", "a refused credential must not print a code line")
}

func TestRunOATHGenerate_NamedCredentialTheGeneratorRefusesIsSkipped(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))
	addTestCredential(t, store, totpCredential("Broken"))
	corruptStoredDigits(t, store, "Broken")

	cmd, buf := newOATHCmd(t, oathGenerateCmd, store)
	require.NoError(t, runOATHGenerate(cmd, []string{"broken", "github"}))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1, "only the valid credential produces a code")
	assert.Regexp(t, sixDigits, lines[0])
}

func TestRunOATHList_UnreadableStoreIsAnError(t *testing.T) {
	cmd, buf := newOATHCmd(t, oathListCmd, writeUnreadableOATHStore(t))

	require.Error(t, runOATHList(cmd, nil))
	assert.NotContains(t, buf.String(), "No OATH credentials found.",
		"a corrupt store must not be reported as an empty one")
}

func TestRunOATHRemove_UnreadableStoreIsAnError(t *testing.T) {
	cmd, buf := newOATHCmd(t, oathRemoveCmd, writeUnreadableOATHStore(t))

	require.Error(t, runOATHRemove(cmd, []string{"github"}))
	assert.Empty(t, buf.String())
}

func TestRunOATHRemove_UnreadableConfirmationKeepsCredential(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))
	// EOF before a newline: the answer cannot be read, so nothing is removed.
	pipeStdin(t, "")

	cmd, buf := newOATHCmd(t, oathRemoveCmd, store)
	require.NoError(t, runOATHRemove(cmd, []string{"github"}))

	assert.NotContains(t, buf.String(), "Removed:")
	list, listBuf := newOATHCmd(t, oathListCmd, store)
	require.NoError(t, runOATHList(list, nil))
	assert.Contains(t, listBuf.String(), "Name:      GitHub")
}
