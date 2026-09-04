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
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// unlockTestHandler is a daemon stand-in for the unlock CLI tests. It reports
// an unlock outcome and, separately, the lock state a later status query sees.
// The two are deliberately independent: the whole point of #250 defect 2 is
// that they can disagree.
type unlockTestHandler struct {
	unlockResult *ipc.UnlockResult
	statusAction string
}

func (h *unlockTestHandler) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionApprovedUP), nil
}

func (h *unlockTestHandler) HandleTypePassword(string) (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionTypedPassword), nil
}

func (h *unlockTestHandler) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(h.statusAction), nil
}

func (h *unlockTestHandler) HandleUnlock(string) (*ipc.UnlockResult, error) {
	return h.unlockResult, nil
}

// serveUnlockDaemon starts an IPC server backed by handler and returns its
// socket path. The server is torn down when the test ends.
func serveUnlockDaemon(t *testing.T, handler ipc.Handler) string {
	t.Helper()

	sockPath := filepath.Join(t.TempDir(), "xkey.sock")
	srv, err := ipc.NewServer(sockPath, handler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	// NewServer has already bound the listener, so a connection made before
	// Serve reaches Accept simply waits in the backlog. There is nothing to
	// wait for, and a timed sleep here would be both slower and racy.
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
	return sockPath
}

// newUnlockTestCmd builds an unlock command bound to the given socket and PIN,
// with its output captured.
func newUnlockTestCmd(socketPath, pin string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "unlock", RunE: runUnlock}
	cmd.Flags().String("pin", "", "")
	cmd.Flags().Bool("pin-stdin", false, "")
	cmd.Flags().String("socket", "", "")
	_ = cmd.Flags().Set("pin", pin)
	_ = cmd.Flags().Set("socket", socketPath)

	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd, out
}

// TestRunUnlock_RefusedUnlockIsNotReportedAsSuccess covers the plain fail-open:
// the daemon refused the unlock, and unlock printed "Unlocked" and exited zero.
func TestRunUnlock_RefusedUnlockIsNotReportedAsSuccess(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{
		unlockResult: &ipc.UnlockResult{Success: false, Error: "app lock: setup is incomplete"},
		statusAction: ipc.ActionLocked,
	})

	cmd, out := newUnlockTestCmd(sock, "1234")
	err := runUnlock(cmd, nil)

	require.Error(t, err, "a refused unlock must exit non-zero")
	assert.ErrorIs(t, err, ErrUnlockFailed)
	assert.Contains(t, err.Error(), "setup is incomplete",
		"the daemon's reason must reach the operator")
	assert.NotContains(t, out.String(), "Unlocked",
		"a refused unlock must not print a success line")
}

// TestRunUnlock_SuccessWithLockedDaemonIsReportedAsFailure is the heart of
// #250 defect 2. The daemon grants the unlock but is still locked afterwards —
// the degraded path where the PIN verifies but the barrier never unseals. The
// reported state must match the actual state, so unlock has to verify what it
// claims and exit non-zero when the two disagree. An exit-code-only assertion
// would pass against the bug; this asserts the daemon's own status agrees.
func TestRunUnlock_SuccessWithLockedDaemonIsReportedAsFailure(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{
		unlockResult: &ipc.UnlockResult{Success: true},
		statusAction: ipc.ActionLocked,
	})

	cmd, out := newUnlockTestCmd(sock, "1234")
	err := runUnlock(cmd, nil)

	require.Error(t, err, "unlock must not report success while the daemon is still locked")
	assert.ErrorIs(t, err, ErrUnlockStillLocked)
	assert.NotContains(t, out.String(), "Unlocked",
		"the success line must not be printed when the daemon is still locked")

	// The failure must name the lock, not something unrelated: an operator who
	// sees this message must not go looking at the authenticator.
	assert.Contains(t, strings.ToLower(err.Error()), "locked")
}

// TestRunUnlock_SuccessWithUnlockedDaemonReportsSuccess is the working path:
// the daemon granted the unlock and confirms it is unlocked.
func TestRunUnlock_SuccessWithUnlockedDaemonReportsSuccess(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{
		unlockResult: &ipc.UnlockResult{Success: true},
		statusAction: ipc.ActionUnlocked,
	})

	cmd, out := newUnlockTestCmd(sock, "1234")
	err := runUnlock(cmd, nil)

	require.NoError(t, err)
	assert.Contains(t, out.String(), "Unlocked")
}

// TestRunUnlock_DaemonWithoutAppLockReportsWhatItDid covers a daemon that owns
// no app lock (the FIDO2 device daemon reports daemon_ready). There is no lock
// state to confirm, so unlock reports the unlock it was granted and says the
// state could not be confirmed rather than claiming a lock it cannot see.
func TestRunUnlock_DaemonWithoutAppLockReportsWhatItDid(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{
		unlockResult: &ipc.UnlockResult{Success: true},
		statusAction: ipc.ActionDaemonReady,
	})

	cmd, out := newUnlockTestCmd(sock, "1234")
	err := runUnlock(cmd, nil)

	require.NoError(t, err)
	assert.Contains(t, out.String(), "Unlocked")
	assert.Contains(t, out.String(), "could not be confirmed",
		"an unverifiable state must be named, not reported as a confirmed unlock")
}

// TestRunUnlock_DaemonNotRunning covers the no-daemon case.
func TestRunUnlock_DaemonNotRunning(t *testing.T) {
	cmd, _ := newUnlockTestCmd(filepath.Join(t.TempDir(), "absent.sock"), "1234")
	err := runUnlock(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnlockDaemonNotRunning)
}

// TestRunUnlock_MissingPIN covers the input-validation path.
func TestRunUnlock_MissingPIN(t *testing.T) {
	t.Setenv("XKEY_PIN", "")

	cmd, _ := newUnlockTestCmd(filepath.Join(t.TempDir(), "absent.sock"), "")
	err := runUnlock(cmd, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnlockMissingPIN)
}

// --- per-subsystem reporting ---
//
// The daemon's status action reports the APP LOCK and nothing else, so it
// cannot express a PIN that released the app lock without unsealing the
// barrier: status answers "unlocked" and the confirmation above passes. That
// is the state the reported ceremony ran in. The unlock result carries the
// per-subsystem outcome so the CLI can catch it and say which half worked.

// A subsystem left locked is a failure even though the daemon granted the
// unlock and reports itself unlocked.
func TestRunUnlock_PartialUnlockIsAFailure(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{
		unlockResult: &ipc.UnlockResult{
			Success:     true,
			Unlocked:    []string{"app lock"},
			StillLocked: []string{"barrier"},
		},
		statusAction: ipc.ActionUnlocked,
	})

	cmd, out := newUnlockTestCmd(sock, "123456")
	err := runUnlock(cmd, nil)

	require.Error(t, err, "a sealed barrier must fail the unlock even when the app lock opened")
	assert.ErrorIs(t, err, ErrUnlockIncomplete)
	assert.Contains(t, err.Error(), "still locked: barrier")
	assert.Contains(t, err.Error(), "unlocked: app lock")
	assert.NotContains(t, out.String(), "Unlocked:")
}

// A full unlock names every subsystem it released rather than printing a
// blanket "Unlocked", which tells an operator nothing about what opened.
func TestRunUnlock_NamesTheSubsystemsItReleased(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{
		unlockResult: &ipc.UnlockResult{
			Success:  true,
			Unlocked: []string{"barrier", "app lock"},
		},
		statusAction: ipc.ActionUnlocked,
	})

	cmd, out := newUnlockTestCmd(sock, "123456")
	require.NoError(t, runUnlock(cmd, nil))

	// Rendered in a stable order so the line is diffable and scriptable.
	assert.Contains(t, out.String(), "Unlocked: app lock, barrier")
}

// A daemon that does not report subsystems still gets the bare success line:
// the richer report is additive, not a new requirement on the daemon.
func TestRunUnlock_UnnamedSubsystemsStillReportSuccess(t *testing.T) {
	sock := serveUnlockDaemon(t, &unlockTestHandler{
		unlockResult: &ipc.UnlockResult{Success: true},
		statusAction: ipc.ActionUnlocked,
	})

	cmd, out := newUnlockTestCmd(sock, "123456")
	require.NoError(t, runUnlock(cmd, nil))
	assert.Contains(t, out.String(), "Unlocked")
}

// joinSubsystems orders names so the output does not vary between runs.
func TestJoinSubsystems(t *testing.T) {
	assert.Equal(t, "app lock, barrier", joinSubsystems([]string{"barrier", "app lock"}))
	assert.Equal(t, "", joinSubsystems(nil))
}
