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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
)

// newExtensionHostTestCmd returns a command carrying the host's own flag,
// with --no-pairing set as given.
func newExtensionHostTestCmd(t *testing.T, noPairing bool) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().Bool("no-pairing", false, "")
	if noPairing {
		require.NoError(t, cmd.Flags().Set("no-pairing", "true"))
	}
	return cmd
}

// pipeNativeMessage feeds msg to the host's stdin in the browser's
// length-prefixed native messaging framing.
func pipeNativeMessage(t *testing.T, msg *nativemsg.NativeMessage) {
	t.Helper()
	var frame bytes.Buffer
	require.NoError(t, nativemsg.WriteMessage(&frame, msg))
	pipeStdin(t, frame.String())
}

// TestRunExtensionHost_RejectsNonHandshakeOpening proves the host refuses a
// browser whose first message is not the handshake, after creating the
// pairing directory it owns and logging its start to the user-visible log.
func TestRunExtensionHost_RejectsNonHandshakeOpening(t *testing.T) {
	root := withIsolatedExtensionHome(t)
	dataDir := filepath.Join(t.TempDir(), "data")
	t.Setenv("XKEY_DATA_DIR", dataDir)
	pipeNativeMessage(t, &nativemsg.NativeMessage{Type: "search"})

	err := runExtensionHost(newExtensionHostTestCmd(t, false), nil)
	require.ErrorIs(t, err, ErrExtensionHostFailed)
	assert.ErrorIs(t, err, nativemsg.ErrHandshakeFailed)

	info, statErr := os.Stat(filepath.Join(dataDir, extensionDataSubdir))
	require.NoError(t, statErr, "the host creates its pairing directory")
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())

	log, readErr := os.ReadFile(filepath.Join(root, "logs", "native-host.log"))
	require.NoError(t, readErr)
	assert.Contains(t, string(log), "native messaging host starting")
	assert.Contains(t, string(log), "native messaging host exited with error")
}

// TestRunExtensionHost_NoPairingLeavesNoPairingState proves --no-pairing
// runs the host without creating the pairing directory.
func TestRunExtensionHost_NoPairingLeavesNoPairingState(t *testing.T) {
	withIsolatedExtensionHome(t)
	dataDir := filepath.Join(t.TempDir(), "data")
	t.Setenv("XKEY_DATA_DIR", dataDir)
	pipeStdin(t, "")

	err := runExtensionHost(newExtensionHostTestCmd(t, true), nil)
	require.ErrorIs(t, err, ErrExtensionHostFailed)
	assert.NoDirExists(t, filepath.Join(dataDir, extensionDataSubdir))
}

// TestRunExtensionHost_UnusablePairingDirectory proves the host refuses to
// run when its pairing directory cannot be created, before reading stdin.
func TestRunExtensionHost_UnusablePairingDirectory(t *testing.T) {
	withIsolatedExtensionHome(t)
	blocker := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.WriteFile(blocker, []byte("a file, not a directory"), 0600))
	t.Setenv("XKEY_DATA_DIR", blocker)
	pipeNativeMessage(t, &nativemsg.NativeMessage{Type: nativemsg.MsgTypeHandshake})

	err := runExtensionHost(newExtensionHostTestCmd(t, false), nil)
	require.ErrorIs(t, err, ErrExtensionHostFailed)
	assert.ErrorContains(t, err, "cannot create pairing directory")
}
