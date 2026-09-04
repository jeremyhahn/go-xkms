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
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// isolateDaemonSocket points daemon auto-detection at an empty directory, so
// a test can never reach a daemon that happens to be running on the host
// machine. Without it, `xkey pin status` unit tests would consult the
// developer's own live daemon and their results would depend on it.
func isolateDaemonSocket(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	return filepath.Join(dir, "xkey", "xkey.sock")
}

// stateTestHandler is a daemon that answers live-state queries with scripted
// values. It implements ipc.Handler and ipc.StateHandler.
type stateTestHandler struct {
	pin           *ipc.PINStateResult
	barrier       *ipc.BarrierStatusResult
	passwordStore *ipc.PasswordStoreStateResult
	passwordList  *ipc.PasswordListResult
	err           error
}

func (h *stateTestHandler) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionNoPending), nil
}

func (h *stateTestHandler) HandleTypePassword(string) (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionTypedPassword), nil
}

func (h *stateTestHandler) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

func (h *stateTestHandler) HandleStatePIN() (*ipc.PINStateResult, error) {
	return h.pin, h.err
}

func (h *stateTestHandler) HandleStateBarrier() (*ipc.BarrierStatusResult, error) {
	return h.barrier, h.err
}

func (h *stateTestHandler) HandleStatePasswordStore() (*ipc.PasswordStoreStateResult, error) {
	return h.passwordStore, h.err
}

func (h *stateTestHandler) HandleStatePasswordList() (*ipc.PasswordListResult, error) {
	return h.passwordList, h.err
}

// statelessTestHandler is a daemon that is alive but does not serve live
// state, like the FIDO2 foreground daemon or the extension host.
type statelessTestHandler struct{}

func (h *statelessTestHandler) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionNoPending), nil
}

func (h *statelessTestHandler) HandleTypePassword(string) (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionTypedPassword), nil
}

func (h *statelessTestHandler) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

// startTestDaemon runs an IPC server on a temp socket for the test's
// lifetime and returns its path. The listener is bound before Serve starts,
// so a client may dial as soon as this returns.
func startTestDaemon(t *testing.T, handler ipc.Handler) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "xkey.sock")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv, err := ipc.NewServer(socketPath, handler, logger)
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

	return socketPath
}

// stateTestCmd builds a detached command carrying the shared --socket and
// --source flags.
func stateTestCmd(t *testing.T, socketPath, selection string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{Use: "state-test"}
	cmd.Flags().String("socket", socketPath, "")
	cmd.Flags().String("source", selection, "")
	return cmd
}

// --- source labelling ---

func TestStateSource_StringDistinguishesAuthorities(t *testing.T) {
	// The whole point of the fix: a sealed barrier reported by a live daemon
	// and one inferred from a cold directory must not render identically.
	assert.Equal(t, "daemon (/run/user/1000/xkey/xkey.sock)",
		daemonSource("/run/user/1000/xkey/xkey.sock").String())
	assert.Equal(t, "data directory (/home/u/.xkey) — no daemon running",
		diskSource("/home/u/.xkey", reasonNoDaemon).String())
	assert.Equal(t, "xkmsd (https://xkms.example.com)",
		xkmsdSource("https://xkms.example.com").String())

	assert.NotEqual(t,
		daemonSource("/run/user/1000/xkey/xkey.sock").String(),
		diskSource("/home/u/.xkey", reasonNoDaemon).String())
}

func TestStateSource_FromDaemonOnlyForDaemonAnswers(t *testing.T) {
	assert.True(t, daemonSource("/tmp/x.sock").FromDaemon())
	assert.False(t, diskSource("/tmp/data", reasonNoDaemon).FromDaemon())
	assert.False(t, xkmsdSource("https://x").FromDaemon())
}

func TestStateSource_InfoCarriesLabelIntoJSON(t *testing.T) {
	info := diskSource("/home/u/.xkey", reasonUnsupported).info()
	assert.Equal(t, sourceLabelDisk, info.Source)
	assert.Equal(t, "/home/u/.xkey", info.SourceLocation)
	assert.Equal(t, reasonUnsupported, info.SourceReason)

	info = daemonSource("/tmp/x.sock").info()
	assert.Equal(t, sourceLabelDaemon, info.Source)
	assert.Empty(t, info.SourceReason)
}

// --- selector validation ---

func TestStateSourceSelection_DefaultsToAuto(t *testing.T) {
	selection, err := stateSourceSelection(&cobra.Command{}, stateSelectorsLocal)
	require.NoError(t, err)
	assert.Equal(t, sourceAuto, selection)
}

func TestStateSourceSelection_RejectsUnknownAndOutOfSetValues(t *testing.T) {
	cmd := stateTestCmd(t, "", "nonsense")
	_, err := stateSourceSelection(cmd, stateSelectorsLocal)
	require.ErrorIs(t, err, ErrStateInvalidSource)
	assert.Contains(t, err.Error(), "auto, daemon, disk")

	// xkmsd is a real selector, but not for a command whose store has only
	// two authorities.
	cmd = stateTestCmd(t, "", sourceXKMSd)
	_, err = stateSourceSelection(cmd, stateSelectorsLocal)
	require.ErrorIs(t, err, ErrStateInvalidSource)

	cmd = stateTestCmd(t, "", sourceXKMSd)
	selection, err := stateSourceSelection(cmd, stateSelectorsWithXKMSd)
	require.NoError(t, err)
	assert.Equal(t, sourceXKMSd, selection)
}

// --- socket resolution ---

func TestStateSocketPath_PrefersFlagThenAutoDetect(t *testing.T) {
	cmd := stateTestCmd(t, "/tmp/explicit.sock", sourceAuto)
	assert.Equal(t, "/tmp/explicit.sock", stateSocketPath(cmd))

	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	assert.Equal(t, filepath.Join(runtimeDir, "xkey", "xkey.sock"),
		stateSocketPath(stateTestCmd(t, "", sourceAuto)))
}

// --- askDaemon routing ---

func TestAskDaemon_LiveDaemonAnswers(t *testing.T) {
	socketPath := startTestDaemon(t, &stateTestHandler{
		barrier: &ipc.BarrierStatusResult{Initialized: true, Sealed: false},
	})

	result, gotSocket, answered, reason, err := askDaemon(
		stateTestCmd(t, socketPath, sourceAuto), sourceAuto,
		func(client *ipc.Client) (*ipc.BarrierStatusResult, error) {
			return client.StateBarrier()
		})

	require.NoError(t, err)
	assert.True(t, answered)
	assert.Empty(t, reason)
	assert.Equal(t, socketPath, gotSocket)
	require.NotNil(t, result)
	assert.False(t, result.Sealed)
}

func TestAskDaemon_NoDaemonFallsBackAndNamesReason(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "absent.sock")

	_, _, answered, reason, err := askDaemon(
		stateTestCmd(t, socketPath, sourceAuto), sourceAuto,
		func(client *ipc.Client) (*ipc.BarrierStatusResult, error) {
			return client.StateBarrier()
		})

	require.NoError(t, err)
	assert.False(t, answered)
	assert.Equal(t, reasonNoDaemon, reason)
}

func TestAskDaemon_StatelessDaemonFallsBackAndNamesReason(t *testing.T) {
	socketPath := startTestDaemon(t, &statelessTestHandler{})

	_, _, answered, reason, err := askDaemon(
		stateTestCmd(t, socketPath, sourceAuto), sourceAuto,
		func(client *ipc.Client) (*ipc.BarrierStatusResult, error) {
			return client.StateBarrier()
		})

	require.NoError(t, err)
	assert.False(t, answered)
	assert.Equal(t, reasonUnsupported, reason)
}

func TestAskDaemon_SourceDaemonRefusesToFallBack(t *testing.T) {
	// Falling back silently is what produced the false negative in the first
	// place; an operator who asked for the daemon must be told when it is
	// not there rather than handed the data directory's answer.
	socketPath := filepath.Join(t.TempDir(), "absent.sock")

	_, _, answered, _, err := askDaemon(
		stateTestCmd(t, socketPath, sourceDaemon), sourceDaemon,
		func(client *ipc.Client) (*ipc.BarrierStatusResult, error) {
			return client.StateBarrier()
		})

	require.ErrorIs(t, err, ErrStateDaemonRequired)
	assert.False(t, answered)
	assert.Contains(t, err.Error(), reasonNoDaemon)
}

func TestAskDaemon_SourceDiskSkipsTheDaemonEntirely(t *testing.T) {
	socketPath := startTestDaemon(t, &stateTestHandler{
		barrier: &ipc.BarrierStatusResult{Initialized: true, Sealed: false},
	})

	_, _, answered, reason, err := askDaemon(
		stateTestCmd(t, socketPath, sourceDisk), sourceDisk,
		func(client *ipc.Client) (*ipc.BarrierStatusResult, error) {
			return client.StateBarrier()
		})

	require.NoError(t, err)
	assert.False(t, answered)
	assert.Equal(t, reasonExplicit, reason)
}

func TestAskDaemon_DaemonErrorIsNotSilentlyDowngraded(t *testing.T) {
	// A daemon that is present and fails must surface the failure. Reporting
	// the data directory instead would reintroduce the defect: a stale answer
	// presented as the live one.
	socketPath := startTestDaemon(t, &stateTestHandler{err: assertError{}})

	_, _, answered, _, err := askDaemon(
		stateTestCmd(t, socketPath, sourceAuto), sourceAuto,
		func(client *ipc.Client) (*ipc.BarrierStatusResult, error) {
			return client.StateBarrier()
		})

	require.ErrorIs(t, err, ErrStateDaemonQueryFailed)
	assert.False(t, answered)
}

// assertError is a deterministic handler failure.
type assertError struct{}

func (assertError) Error() string { return "barrier subsystem offline" }
