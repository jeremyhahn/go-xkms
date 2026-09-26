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
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// serveInstanceDaemon starts an IPC server bound to exactly socketPath (not
// an arbitrary temp path), so a test can prove routing against the same
// derivation resolvedSocketPath itself uses.
func serveInstanceDaemon(t *testing.T, socketPath string, handler ipc.Handler) {
	t.Helper()

	srv, err := ipc.NewServer(socketPath, handler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-served
	})
}

// TestTwoInstances_SameUID_EachCLICallReachesItsOwnInstance is the go-xkms
// #1033 acceptance test: two xkey instances under the same UID, distinguished
// only by XKEY_HOME, must resolve to distinct sockets, and a client that
// names one instance through its environment must never reach the other's
// daemon or see its data — a credential stored in instance A is invisible
// through instance B.
func TestTwoInstances_SameUID_EachCLICallReachesItsOwnInstance(t *testing.T) {
	t.Setenv("XKEY_IPC_SOCKET", "")
	homeA := t.TempDir()
	homeB := t.TempDir()

	// Resolve each instance's default socket the exact way every CLI command
	// does: resolvedSocketPath, with no --socket flag given, so only
	// XKEY_HOME distinguishes them.
	t.Setenv(xhome.EnvHome, homeA)
	sockA := resolvedSocketPath(nil)

	t.Setenv(xhome.EnvHome, homeB)
	sockB := resolvedSocketPath(nil)

	require.NotEqual(t, sockA, sockB, "two distinct instance homes must resolve to distinct sockets")

	// Instance A is "running" and holds one credential's metadata.
	handlerA := &stateTestHandler{
		passwordList: &ipc.PasswordListResult{
			Entries: []ipc.PasswordEntryInfo{{Name: "secret-in-instance-a"}},
		},
	}
	serveInstanceDaemon(t, sockA, handlerA)

	// A CLI call made while the environment names instance A reaches it and
	// sees the credential stored there.
	t.Setenv(xhome.EnvHome, homeA)
	clientA := ipc.NewClient(resolvedSocketPath(nil))
	resultA, err := clientA.StatePasswordList()
	require.NoError(t, err)
	require.Len(t, resultA.Entries, 1)
	assert.Equal(t, "secret-in-instance-a", resultA.Entries[0].Name)
	require.NoError(t, clientA.Close())

	// A CLI call made while the environment names instance B must not reach
	// instance A's daemon: no daemon is running at instance B's own socket,
	// so the credential stored under A is unreachable from B.
	t.Setenv(xhome.EnvHome, homeB)
	clientB := ipc.NewClient(resolvedSocketPath(nil))
	_, err = clientB.StatePasswordList()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrDaemonNotRunning),
		"instance B must see no daemon, not instance A's credential")
	require.NoError(t, clientB.Close())
}

// TestTwoInstances_SameUID_ExplicitSocketFlagOverridesHome proves --socket
// still wins over XKEY_HOME: an operator (or a generated extension launcher)
// naming a socket explicitly reaches exactly that instance even when the
// ambient XKEY_HOME names a different one.
func TestTwoInstances_SameUID_ExplicitSocketFlagOverridesHome(t *testing.T) {
	t.Setenv("XKEY_IPC_SOCKET", "")
	homeA := t.TempDir()
	homeB := t.TempDir()

	t.Setenv(xhome.EnvHome, homeA)
	sockA := resolvedSocketPath(nil)

	handlerA := &stateTestHandler{
		passwordList: &ipc.PasswordListResult{
			Entries: []ipc.PasswordEntryInfo{{Name: "secret-in-instance-a"}},
		},
	}
	serveInstanceDaemon(t, sockA, handlerA)

	// The ambient environment now names instance B, but an explicit --socket
	// flag pointing at A's socket must still reach A.
	t.Setenv(xhome.EnvHome, homeB)
	cmd := stateTestCmd(t, sockA, sourceAuto)

	got := resolvedSocketPath(cmd)
	assert.Equal(t, sockA, got, "--socket must win over XKEY_HOME")

	client := ipc.NewClient(got)
	result, err := client.StatePasswordList()
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)
	assert.Equal(t, "secret-in-instance-a", result.Entries[0].Name)
	require.NoError(t, client.Close())
}
