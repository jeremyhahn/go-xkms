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

package nativemsg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveLocked_MkdirAllFails proves a state directory that cannot be
// created is reported as a typed error rather than a raw os error or a
// panic. Construction happens first, while the state directory does not
// exist yet (tolerated: load treats a missing file as an empty state); a
// regular file is then put where the directory needs to go, which MkdirAll
// can never turn into a directory.
func TestSaveLocked_MkdirAllFails(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "sub", "state.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err, "a not-yet-existing state directory is not fatal at construction")

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "sub"), []byte("x"), 0600))

	err = v.save()
	require.Error(t, err)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "nativemsg: failed to create pairing directory", wrapped.Msg)
}

// TestSaveLocked_RenameFails proves a failed atomic rename is reported as a
// typed error and cleans up the temp file rather than leaving it behind.
// Construction happens first, while the state path does not exist yet; an
// existing directory is then put at the state path, which a file can never
// be renamed onto.
func TestSaveLocked_RenameFails(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	require.NoError(t, os.Mkdir(statePath, 0700))

	err = v.save()
	require.Error(t, err)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "nativemsg: failed to rename pairing temp file", wrapped.Msg)

	_, statErr := os.Stat(statePath + ".tmp")
	assert.True(t, os.IsNotExist(statErr), "the temp file must be cleaned up after a failed rename")
}

// TestRemoveStateLocked_PermissionDenied proves a removal failure other than
// "does not exist" (here, a parent directory that denies unlink) is reported
// as a typed error via UnpairAll rather than silently treated like a
// missing file.
func TestRemoveStateLocked_PermissionDenied(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	v, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)

	// The state file now exists; deny write on its parent directory so
	// os.Remove cannot unlink it, without touching the file's own mode.
	require.NoError(t, os.Chmod(tmpDir, 0500))
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0700) })

	err = v.UnpairAll()
	require.Error(t, err)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "nativemsg: failed to remove pairing state", wrapped.Msg)
}
