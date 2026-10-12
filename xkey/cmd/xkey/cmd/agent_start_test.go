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
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// TestRunAgentStart_InvalidListenAddressFailsValidation exercises the real
// config-validation guard before any listener is bound: an explicitly empty
// --listen fails cfg.Validate() immediately, so runAgentStart never claims
// run-state, opens an enrollment store, or binds a socket.
func TestRunAgentStart_InvalidListenAddressFailsValidation(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("listen", "", "")
	cmd.Flags().String("tls-cert", "", "")
	cmd.Flags().String("tls-key", "", "")
	cmd.Flags().String("tls-ca", "", "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "listen", ""))

	err := runAgentStart(cmd, nil)
	require.ErrorIs(t, err, agent.ErrInvalidAddress)
}

// newAgentStartTestCmd builds a command carrying the agent start flags,
// listening on listen.
func newAgentStartTestCmd(t *testing.T, listen string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("listen", "", "")
	cmd.Flags().String("tls-cert", "", "")
	cmd.Flags().String("tls-key", "", "")
	cmd.Flags().String("tls-ca", "", "")
	cmd.Flags().String("cert-profile", agentCertProfileDefault, "")
	cmd.Flags().Int("cert-validity-days", 0, "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "listen", listen))
	cmd.SetOut(&bytes.Buffer{})
	return cmd
}

// requireNoAgentServerRecord asserts a failed start left no run-state behind,
// so "agent status" does not report a server that never came up.
func requireNoAgentServerRecord(t *testing.T) {
	t.Helper()

	_, err := readAgentServerState()
	require.ErrorIs(t, err, ErrAgentServerNotRunning)
}

// TestRunAgentStart_RefusesWhileAnotherServerRuns proves a second start fails
// fast on the live run-state record and leaves that record in place.
func TestRunAgentStart_RefusesWhileAnotherServerRuns(t *testing.T) {
	withIsolatedAgentHome(t)
	useTestXKMSdEndpoint(t, "")

	executable := fakeAgentExecutable(t)
	running := seedAgentServerState(t, startFakeAgentServer(t, executable, false), executable)

	err := runAgentStart(newAgentStartTestCmd(t, "127.0.0.1:0"), nil)
	require.ErrorIs(t, err, ErrAgentServerAlreadyRunning)

	kept, err := readAgentServerState()
	require.NoError(t, err)
	assert.Equal(t, running.PID, kept.PID)
	assert.Equal(t, running.ListenAddr, kept.ListenAddr)
}

// TestRunAgentStart_FailsClosedWithoutACertificateAuthority proves the
// server never starts when no xkmsd authority is reachable, and releases the
// run-state it claimed.
func TestRunAgentStart_FailsClosedWithoutACertificateAuthority(t *testing.T) {
	withIsolatedAgentHome(t)

	t.Run("none configured", func(t *testing.T) {
		useTestXKMSdEndpoint(t, "")
		err := runAgentStart(newAgentStartTestCmd(t, "127.0.0.1:0"), nil)
		require.ErrorIs(t, err, ErrAgentCAUnavailable)
		require.ErrorIs(t, err, ErrXKMSdURLRequired)
		requireNoAgentServerRecord(t)
	})

	t.Run("unreachable", func(t *testing.T) {
		// Port 9 (discard) refuses connections.
		useTestXKMSdEndpoint(t, "http://127.0.0.1:9")
		err := runAgentStart(newAgentStartTestCmd(t, "127.0.0.1:0"), nil)
		require.ErrorIs(t, err, ErrAgentCAUnavailable)
		requireNoAgentServerRecord(t)
	})
}

// TestRunAgentStart_RefusesAnUnusableEnrollmentStore proves a store path that
// cannot be a directory stops the start before any CA or listener is used.
func TestRunAgentStart_RefusesAnUnusableEnrollmentStore(t *testing.T) {
	withIsolatedAgentHome(t)
	useTestXKMSdEndpoint(t, "")

	storeDir := mustAgentStoreDir(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(storeDir), 0o700))
	require.NoError(t, os.WriteFile(storeDir, []byte("not a directory"), 0o600))

	err := runAgentStart(newAgentStartTestCmd(t, "127.0.0.1:0"), nil)
	require.ErrorIs(t, err, ErrAgentStartFailed)
	requireNoAgentServerRecord(t)
}

// TestRunAgentStart_ReportsAnOccupiedListenAddress proves a bind failure
// surfaces as ErrAgentStartFailed once the CA is reachable, and the claimed
// run-state is released.
func TestRunAgentStart_ReportsAnOccupiedListenAddress(t *testing.T) {
	withIsolatedAgentHome(t)
	fake := newFakeXKMSd(t, newCATestFixture(t))
	useTestXKMSdEndpoint(t, fake.server.URL)

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, occupied.Close()) })

	err = runAgentStart(newAgentStartTestCmd(t, occupied.Addr().String()), nil)
	require.ErrorIs(t, err, ErrAgentStartFailed)
	requireNoAgentServerRecord(t)
}
