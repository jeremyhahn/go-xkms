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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// linkContainer hard-links the container so its blocks can still be read
// after the wipe unlinks it: the link shows what was written over the data.
func linkContainer(t *testing.T, container string) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "container.link")
	require.NoError(t, os.Link(container, link))
	return link
}

// TestRunWipe_OverwritesThenRemovesTheContainer proves every standard
// overwrites the container's data in place before the file is removed,
// rather than only unlinking it.
func TestRunWipe_OverwritesThenRemovesTheContainer(t *testing.T) {
	tests := []struct {
		standard string
		force    bool
		stdin    string
	}{
		{standard: "nist", force: true},
		{standard: "dod3", force: true},
		{standard: "dod7", force: false, stdin: "DESTROY\n"},
	}
	for _, tt := range tests {
		t.Run(tt.standard, func(t *testing.T) {
			root := asLUKSRoot(t)
			wipeStandard, wipeForce = tt.standard, tt.force
			wipePath = filepath.Join(root, "xkey.luks")
			original := writeContainer(t, wipePath, 4096)
			link := linkContainer(t, wipePath)
			if !tt.force {
				pipeStdin(t, tt.stdin)
			}

			out, err := runLUKSCmd(t, runWipe)
			require.NoError(t, err)

			assert.NoFileExists(t, wipePath)
			wiped, readErr := os.ReadFile(link)
			require.NoError(t, readErr)
			assert.Len(t, wiped, len(original), "the wipe covers the whole container")
			assert.NotEqual(t, original, wiped, "the data is overwritten, not just unlinked")
			assert.Contains(t, out, "Wiping container ("+tt.standard+")...")
			assert.Contains(t, out, "Container securely destroyed.")
			assert.NotContains(t, out, "Locking container", "a closed container is not locked first")
		})
	}
}

// TestRunWipe_UnwritableContainerIsKept proves a container the wipe cannot
// overwrite is left in place: removing it unwiped would leave its data on
// disk behind a successful-looking delete.
func TestRunWipe_UnwritableContainerIsKept(t *testing.T) {
	root := asLUKSRoot(t)
	wipeStandard, wipeForce = "nist", true
	wipePath = filepath.Join(root, "xkey.luks")
	original := writeContainer(t, wipePath, 512)
	require.NoError(t, os.Chmod(wipePath, 0o400))

	out, err := runLUKSCmd(t, runWipe)
	var wipeErr *WipeError
	require.ErrorAs(t, err, &wipeErr)
	assert.Equal(t, "wipe", wipeErr.Operation)
	assert.NotContains(t, out, "Removing container file")

	kept, readErr := os.ReadFile(wipePath)
	require.NoError(t, readErr)
	assert.Equal(t, original, kept)
}

// TestRunWipe_RemoveFailureAfterOverwrite reports the file it could not
// remove once its data is already destroyed.
func TestRunWipe_RemoveFailureAfterOverwrite(t *testing.T) {
	asLUKSRoot(t)
	wipeStandard, wipeForce = "nist", true
	dir := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.Mkdir(dir, 0o755))
	wipePath = filepath.Join(dir, "xkey.luks")
	original := writeContainer(t, wipePath, 512)
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { require.NoError(t, os.Chmod(dir, 0o755)) })

	out, err := runLUKSCmd(t, runWipe)
	var wipeErr *WipeError
	require.ErrorAs(t, err, &wipeErr)
	assert.Equal(t, "remove_file", wipeErr.Operation)
	assert.Contains(t, out, "Removing container file...")

	wiped, readErr := os.ReadFile(wipePath)
	require.NoError(t, readErr)
	assert.NotEqual(t, original, wiped, "the data is overwritten before the remove is attempted")
}
