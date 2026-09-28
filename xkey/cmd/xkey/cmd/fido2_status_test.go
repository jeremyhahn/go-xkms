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
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func fido2StatusTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("socket", "", "")
	return cmd
}

// TestRunFIDO2Status_DaemonNotRunning exercises the real IPC client against
// a socket path with nothing listening: the connect is refused immediately,
// so this never touches a real daemon.
func TestRunFIDO2Status_DaemonNotRunning(t *testing.T) {
	cmd := fido2StatusTestCmd()
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "socket", filepath.Join(t.TempDir(), "no-daemon.sock")))

	err := runFIDO2Status(cmd, nil)
	require.ErrorIs(t, err, ErrFIDO2StatusDaemonNotRunning)
}
