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
	"encoding/json"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// These cases reproduce the defect in #271 and pin the fix: on a running,
// unsealed, wizard-configured device the inspection commands reported the
// *on-disk data directory* — an unconfigured, sealed, empty device — while
// the daemon in the next process held the truth. Each case here fails
// against the pre-fix commands, which had no --socket, never opened the IPC
// socket, and printed no source.

// stateCmdWithBuffer builds a detached command with the shared live-state
// flags and a captured output buffer.
func stateCmdWithBuffer(t *testing.T, socketPath, selection string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := stateTestCmd(t, socketPath, selection)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

// --- pin status ---

func TestRunPINStatus_DaemonAnswersOverColdDataDirectory(t *testing.T) {
	// The data directory is empty: no PIN has ever been written to it. The
	// daemon holds a device whose SO and User PINs are both set. Reporting
	// "No" here is the false negative that sent an operator to `pin set-user`
	// on a device that already had a PIN.
	isolatePIN(t)

	socketPath := startTestDaemon(t, &stateTestHandler{
		pin: &ipc.PINStateResult{
			Initialized: true,
			SOPINSet:    true,
			UserPINSet:  true,
			Strategy:    "software",
			MaxAttempts: 5,
		},
	})

	cmd, buf := stateCmdWithBuffer(t, socketPath, sourceAuto)
	require.NoError(t, runPINStatus(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "Initialized:      Yes")
	assert.Contains(t, out, "SO PIN set:       Yes")
	assert.Contains(t, out, "User PIN set:     Yes")
	assert.Contains(t, out, "Strategy:         software")
	assert.Contains(t, out, "Source: daemon ("+socketPath+")")
}

func TestRunPINStatus_NoDaemonReportsDataDirectoryAndSaysSo(t *testing.T) {
	dataDir := isolatePIN(t)

	cmd, buf := stateCmdWithBuffer(t, noDaemonSocket(t), sourceAuto)
	require.NoError(t, runPINStatus(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "PIN store:        not found",
		"an empty data directory holds no store; that fact must be reported, not a confident No")
	assert.Contains(t, out, "Source: data directory ("+dataDir+") — no daemon running")
}

func TestRunPINStatus_JSONNamesTheAnsweringSource(t *testing.T) {
	isolatePIN(t)
	pinStatusJSON = true

	socketPath := startTestDaemon(t, &stateTestHandler{
		pin: &ipc.PINStateResult{Initialized: true, SOPINSet: true, UserPINSet: true},
	})

	cmd, buf := stateCmdWithBuffer(t, socketPath, sourceAuto)
	require.NoError(t, runPINStatus(cmd, nil))

	var info pinStatusInfo
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	assert.True(t, info.SOPINSet)
	assert.True(t, info.UserPINSet)
	assert.Equal(t, sourceLabelDaemon, info.Source)
	assert.Equal(t, socketPath, info.SourceLocation)
	assert.Empty(t, info.SourceReason)
}

func TestRunPINStatus_SourceDiskIgnoresALiveDaemon(t *testing.T) {
	// An operator inspecting the cold directory on purpose must still be
	// able to, and must be told that is what they got.
	dataDir := isolatePIN(t)

	socketPath := startTestDaemon(t, &stateTestHandler{
		pin: &ipc.PINStateResult{Initialized: true, SOPINSet: true, UserPINSet: true},
	})

	cmd, buf := stateCmdWithBuffer(t, socketPath, sourceDisk)
	require.NoError(t, runPINStatus(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "PIN store:        not found",
		"the cold directory holds no store; that fact must be reported, not a confident No")
	assert.Contains(t, out, "Source: data directory ("+dataDir+") — selected with --source disk")
}

func TestRunPINStatus_RejectsUnknownSource(t *testing.T) {
	isolatePIN(t)

	cmd, _ := stateCmdWithBuffer(t, noDaemonSocket(t), "elsewhere")
	require.ErrorIs(t, runPINStatus(cmd, nil), ErrStateInvalidSource)
}

// --- barrier status ---

func TestRunBarrierStatus_DaemonReportsUnsealed(t *testing.T) {
	// The data directory has no root key, so the on-disk path can only ever
	// say "Not Initialized" / sealed. The daemon holds it unsealed.
	isolateBarrier(t)

	socketPath := startTestDaemon(t, &stateTestHandler{
		barrier: &ipc.BarrierStatusResult{
			Initialized:    true,
			Sealed:         false,
			Strategy:       "tpm2",
			HardwareBacked: true,
		},
	})

	cmd, buf := stateCmdWithBuffer(t, socketPath, sourceAuto)
	require.NoError(t, runBarrierStatus(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "State:            Unsealed")
	assert.Contains(t, out, "Hardware-backed:  Yes")
	assert.Contains(t, out, "Source: daemon ("+socketPath+")")
}

func TestRunBarrierStatus_NoDaemonReportsSealedDataDirectoryAndSaysSo(t *testing.T) {
	dataDir := isolateBarrier(t)

	cmd, buf := stateCmdWithBuffer(t, noDaemonSocket(t), sourceAuto)
	require.NoError(t, runBarrierStatus(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "Barrier Status: Not Initialized")
	assert.Contains(t, out, "Source: data directory ("+dataDir+") — no daemon running")
}

func TestRunBarrierStatus_SealedFromDaemonAndFromDiskRenderDifferently(t *testing.T) {
	// This is the requirement the design calls out by name: the same word
	// "Sealed" from two authorities is two different facts.
	isolateBarrier(t)

	socketPath := startTestDaemon(t, &stateTestHandler{
		barrier: &ipc.BarrierStatusResult{Initialized: true, Sealed: true, Strategy: "software"},
	})

	daemonCmd, daemonBuf := stateCmdWithBuffer(t, socketPath, sourceAuto)
	require.NoError(t, runBarrierStatus(daemonCmd, nil))

	diskCmd, diskBuf := stateCmdWithBuffer(t, socketPath, sourceDisk)
	require.NoError(t, runBarrierStatus(diskCmd, nil))

	assert.Contains(t, daemonBuf.String(), "State:            Sealed")
	assert.Contains(t, daemonBuf.String(), "Source: daemon (")
	assert.Contains(t, diskBuf.String(), "Source: data directory (")
	assert.NotEqual(t, daemonBuf.String(), diskBuf.String())
}

func TestRunBarrierStatus_JSONNamesTheAnsweringSource(t *testing.T) {
	isolateBarrier(t)
	barrierStatusJSON = true

	socketPath := startTestDaemon(t, &stateTestHandler{
		barrier: &ipc.BarrierStatusResult{Initialized: true, Sealed: false, Strategy: "software"},
	})

	cmd, buf := stateCmdWithBuffer(t, socketPath, sourceAuto)
	require.NoError(t, runBarrierStatus(cmd, nil))

	var info barrierStatusInfo
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	assert.True(t, info.Initialized)
	assert.False(t, info.Sealed)
	assert.Equal(t, sourceLabelDaemon, info.Source)
	assert.Equal(t, socketPath, info.SourceLocation)
}

func TestRunBarrierStatus_SourceDaemonFailsWhenNoneIsRunning(t *testing.T) {
	isolateBarrier(t)

	cmd, _ := stateCmdWithBuffer(t, noDaemonSocket(t), sourceDaemon)
	require.ErrorIs(t, runBarrierStatus(cmd, nil), ErrStateDaemonRequired)
}

// --- password list ---

func TestRunPasswordList_DaemonListsEntriesTheStoreDirectoryCannotSee(t *testing.T) {
	// The store directory is empty; the daemon's barrier-backed store holds
	// the wizard's entries. Before the fix this printed "No passwords found."
	socketPath := startTestDaemon(t, &stateTestHandler{
		passwordList: &ipc.PasswordListResult{Entries: []ipc.PasswordEntryInfo{
			{Name: "SO PIN", Title: "Security Officer PIN", Username: "so", CreatedAt: "2026-09-03T10:00:00Z"},
		}},
	})

	cmd, buf, _ := passwordTestCmd(t)
	cmd.SetOut(buf)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "socket", socketPath))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "source", sourceAuto))

	require.NoError(t, runPasswordList(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "Static Passwords (1):")
	assert.Contains(t, out, "Name:       SO PIN")
	assert.Contains(t, out, "Password:   ********")
	assert.Contains(t, out, "Source: daemon ("+socketPath+")")
}

func TestRunPasswordList_ShowPasswordsIsRefusedOverIPC(t *testing.T) {
	// The socket is authenticated by filesystem permission alone. Handing
	// out stored secrets there would let any process running as this user
	// drain the store, so the command refuses and names the alternative.
	socketPath := startTestDaemon(t, &stateTestHandler{
		passwordList: &ipc.PasswordListResult{Entries: []ipc.PasswordEntryInfo{{Name: "DatabaseProd"}}},
	})

	cmd, _, _ := passwordTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "socket", socketPath))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "source", sourceAuto))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "show-passwords", "true"))

	require.ErrorIs(t, runPasswordList(cmd, nil), ErrPasswordValuesNotOverIPC)
}

func TestRunPasswordList_NoDaemonReportsStoreDirectoryAndSaysSo(t *testing.T) {
	cmd, buf, store := passwordTestCmd(t)
	cmd.SetOut(buf)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "socket", noDaemonSocket(t)))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "source", sourceAuto))

	require.NoError(t, runPasswordList(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "No passwords found.")
	assert.Contains(t, out, "Source: data directory ("+store+") — no daemon running")
}

// --- password status ---

func TestRunPasswordStatus_SucceedsWithoutAnXKMSdURL(t *testing.T) {
	// #271: `password status` demanded --xkmsd-url while `password list`
	// needed none. Both now answer from the same authority.
	socketPath := startTestDaemon(t, &stateTestHandler{
		passwordStore: &ipc.PasswordStoreStateResult{
			Available: true,
			Locked:    false,
			Backend:   "barrier",
			Count:     3,
		},
	})

	cmd, buf, _ := passwordTestCmd(t)
	cmd.SetOut(buf)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "socket", socketPath))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "source", sourceAuto))

	require.NoError(t, runPasswordStatus(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "Available:       Yes")
	assert.Contains(t, out, "Locked:          No")
	assert.Contains(t, out, "Backend:         barrier")
	assert.Contains(t, out, "Password Count:  3")
	assert.Contains(t, out, "Access Mode:     n/a (no xkmsd session server)")
	assert.Contains(t, out, "Source: daemon ("+socketPath+")")
}

func TestRunPasswordStatus_AgreesWithListAboutReachability(t *testing.T) {
	// The pair must tell one story: if list can answer without a server,
	// status can too, and both name the same source.
	socketPath := noDaemonSocket(t)

	listCmd, listBuf, store := passwordTestCmd(t)
	listCmd.SetOut(listBuf)
	require.NoError(t, setFlagForTest(t, listCmd.Flags(), "socket", socketPath))
	require.NoError(t, setFlagForTest(t, listCmd.Flags(), "source", sourceAuto))
	require.NoError(t, runPasswordList(listCmd, nil))

	statusCmd, statusBuf, _ := passwordTestCmd(t)
	statusCmd.SetOut(statusBuf)
	require.NoError(t, setFlagForTest(t, statusCmd.Flags(), "store", store))
	require.NoError(t, setFlagForTest(t, statusCmd.Flags(), "socket", socketPath))
	require.NoError(t, setFlagForTest(t, statusCmd.Flags(), "source", sourceAuto))
	require.NoError(t, runPasswordStatus(statusCmd, nil))

	expected := "Source: data directory (" + store + ") — no daemon running"
	assert.Contains(t, listBuf.String(), expected)
	assert.Contains(t, statusBuf.String(), expected)
	assert.Contains(t, statusBuf.String(), "Password Count:  0")
}

func TestRunPasswordStatus_ReportsALockedStoreRatherThanFailing(t *testing.T) {
	// A sealed barrier is a state, not an error: the operator still needs to
	// learn where the store is and why it cannot be read.
	socketPath := startTestDaemon(t, &stateTestHandler{
		passwordStore: &ipc.PasswordStoreStateResult{
			Available: true,
			Locked:    true,
			Backend:   "barrier",
		},
	})

	cmd, buf, _ := passwordTestCmd(t)
	cmd.SetOut(buf)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "socket", socketPath))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "source", sourceAuto))

	require.NoError(t, runPasswordStatus(cmd, nil))
	assert.Contains(t, buf.String(), "Locked:          Yes")
}

func TestRunPasswordStatus_RejectsUnknownSource(t *testing.T) {
	cmd, _, _ := passwordTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "source", "elsewhere"))

	require.ErrorIs(t, runPasswordStatus(cmd, nil), ErrStateInvalidSource)
}

// noDaemonSocket returns a socket path in a fresh temp directory where no
// daemon is listening.
func noDaemonSocket(t *testing.T) string {
	t.Helper()
	return privateTempDir(t) + "/absent.sock"
}

// privateTempDir returns a fresh temporary directory with mode 0700, for
// tests that bind or dial an xkey IPC socket inside it. The IPC server and
// client refuse a socket directory with group or other permission bits, and
// t.TempDir creates its directory 0777 &^ umask.
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if len(dir)+len("/test-barrier-serve.sock") > maxTestSocketPathLen {
		// A long TMPDIR (CI runner pools nest it under the job's work dir)
		// would push sockets under t.TempDir() past AF_UNIX's sun_path, so
		// bind/dial fail with EINVAL instead of the error under test.
		short, err := os.MkdirTemp("/tmp", "xk-")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(short) })
		dir = short
	}
	require.NoError(t, os.Chmod(dir, 0o700))
	return dir
}

// maxTestSocketPathLen keeps test socket paths within AF_UNIX's sun_path:
// 108 bytes on Linux and 104 on macOS, each including the trailing NUL.
const maxTestSocketPathLen = 103
