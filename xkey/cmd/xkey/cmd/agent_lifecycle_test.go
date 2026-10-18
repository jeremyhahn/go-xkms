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
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// withIsolatedAgentHome points the xKey home at a private temporary
// directory for the duration of the test. Agent paths resolve through the
// CLI's shared data-dir chain, so the override is installed with
// xhome.SetRoot after every other chain source is neutralised; the home
// resolved by the root command is aligned as well for the lifecycle code
// that consults it.
func withIsolatedAgentHome(t *testing.T) string {
	t.Helper()

	isolateDataDirSources(t)
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)
	previous := resolvedHome
	resolvedHome = &xhome.Home{Root: root}
	t.Cleanup(func() { resolvedHome = previous })
	t.Setenv("HOME", root)

	return root
}

// mustAgentDataDir resolves the agent data directory or fails the test.
func mustAgentDataDir(t *testing.T) string {
	t.Helper()
	dir, err := agentDataDir()
	if err != nil {
		t.Fatalf("agentDataDir: %v", err)
	}
	return dir
}

// mustAgentStoreDir resolves the agent enrollment store directory or
// fails the test.
func mustAgentStoreDir(t *testing.T) string {
	t.Helper()
	dir, err := agentStoreDir()
	if err != nil {
		t.Fatalf("agentStoreDir: %v", err)
	}
	return dir
}

// mustAgentCertDir resolves the agent certificate directory or fails the
// test.
func mustAgentCertDir(t *testing.T) string {
	t.Helper()
	dir, err := agentCertDir()
	if err != nil {
		t.Fatalf("agentCertDir: %v", err)
	}
	return dir
}

// mustAgentStateFile resolves the agent server state file or fails the
// test.
func mustAgentStateFile(t *testing.T) string {
	t.Helper()
	path, err := agentStateFile()
	if err != nil {
		t.Fatalf("agentStateFile: %v", err)
	}
	return path
}

// fakeAgentExecutable returns a path whose base name matches the xkey
// binary, used as the recorded executable of simulated agent servers.
func fakeAgentExecutable(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "xkey")
}

// startFakeAgentServer launches a real process whose kernel-recorded
// argument vector is indistinguishable from "xkey agent start": argv[0]
// is the given executable path and the remaining arguments include the
// "agent" and "start" tokens. The process blocks reading a pipe that the
// test holds open, so it consumes no CPU and exits as soon as the pipe is
// closed during cleanup. When ignoreTerm is set the process ignores
// SIGTERM, exercising the SIGKILL escalation path.
//
// The process announces readiness on stdout after installing its signal
// disposition, so callers never signal it before the trap is in place.
func startFakeAgentServer(t *testing.T, executable string, ignoreTerm bool) int {
	t.Helper()

	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("locate sh: %v", err)
	}

	// "read" is a shell builtin, so the shell never execs and its
	// argument vector is preserved for the lifetime of the process.
	script := "echo ready; read line"
	if ignoreTerm {
		script = `trap "" TERM; echo ready; read line`
	}

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}

	proc := &exec.Cmd{
		Path:   shell,
		Args:   []string{executable, "-c", script, "agent", "start"},
		Stdin:  stdinReader,
		Stdout: stdoutWriter,
	}
	if err := proc.Start(); err != nil {
		t.Fatalf("start fake agent server: %v", err)
	}

	// Close the child's ends in the parent so reads see EOF on exit.
	if err := stdinReader.Close(); err != nil {
		t.Fatalf("close stdin reader: %v", err)
	}
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}

	t.Cleanup(func() {
		// Closing the write end unblocks "read" so the process exits on
		// its own; SIGKILL is a backstop for the ignore-SIGTERM variant.
		if err := stdinWriter.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close stdin writer: %v", err)
		}
		if proc.Process != nil {
			if err := proc.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill fake agent server: %v", err)
			}
			// Reap so no zombie survives the test.
			if _, err := proc.Process.Wait(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Logf("wait for fake agent server: %v", err)
			}
		}
		if err := stdoutReader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close stdout reader: %v", err)
		}
	})

	ready := make(chan error, 1)
	go func() {
		announcement := make([]byte, len("ready\n"))
		_, readErr := io.ReadFull(stdoutReader, announcement)
		ready <- readErr
	}()

	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("fake agent server never announced readiness: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the fake agent server to announce readiness")
	}

	if argv, supported := processArgs(proc.Process.Pid); supported && !cmdlineIsAgentServer(argv, executable) {
		t.Fatalf("fake agent server command line %v does not identify an xkey agent", argv)
	}

	return proc.Process.Pid
}

// deadPID returns the process ID of a process that has already exited and
// been reaped, simulating the PID recorded by a crashed agent server.
func deadPID(t *testing.T) int {
	t.Helper()

	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("locate sh: %v", err)
	}

	proc := exec.Command(shell, "-c", "exit 0")
	if err := proc.Start(); err != nil {
		t.Fatalf("start throwaway process: %v", err)
	}
	pid := proc.Process.Pid
	if err := proc.Wait(); err != nil {
		t.Fatalf("wait for throwaway process: %v", err)
	}
	return pid
}

// seedAgentServerState claims the run-state file on behalf of a simulated
// server with the given PID and executable.
func seedAgentServerState(t *testing.T, pid int, executable string) *agentServerState {
	t.Helper()

	state := &agentServerState{
		PID:        pid,
		ListenAddr: "127.0.0.1:19443",
		Executable: executable,
		StartedAt:  time.Now().UTC(),
	}
	if err := claimAgentServerState(state); err != nil {
		t.Fatalf("claim agent server state: %v", err)
	}
	return state
}

func TestAgentStateFile_UsesResolvedHome(t *testing.T) {
	root := withIsolatedAgentHome(t)

	want := filepath.Join(root, "data", "agent", agentStateFileName)
	if got := mustAgentStateFile(t); got != want {
		t.Errorf("agentStateFile() = %q, want %q", got, want)
	}
	if dir := filepath.Dir(mustAgentStateFile(t)); dir != mustAgentDataDir(t) {
		t.Errorf("state file is not under the agent data dir: %q vs %q", dir, mustAgentDataDir(t))
	}
}

func TestClaimAgentServerState_WriteReadRelease(t *testing.T) {
	withIsolatedAgentHome(t)

	state, err := newAgentServerState("127.0.0.1:9443", true)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	if err := claimAgentServerState(state); err != nil {
		t.Fatalf("claimAgentServerState: %v", err)
	}

	info, err := os.Stat(mustAgentStateFile(t))
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file mode = %v, want 0600", perm)
	}

	loaded, err := readAgentServerState()
	if err != nil {
		t.Fatalf("readAgentServerState: %v", err)
	}
	if loaded.PID != state.PID {
		t.Errorf("PID = %d, want %d", loaded.PID, state.PID)
	}
	if loaded.ListenAddr != "127.0.0.1:9443" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:9443", loaded.ListenAddr)
	}
	if loaded.Executable != state.Executable {
		t.Errorf("Executable = %q, want %q", loaded.Executable, state.Executable)
	}
	if !loaded.TLS {
		t.Error("TLS = false, want true")
	}

	if err := releaseAgentServerState(state.PID); err != nil {
		t.Fatalf("releaseAgentServerState: %v", err)
	}
	if _, err := readAgentServerState(); !errors.Is(err, ErrAgentServerNotRunning) {
		t.Errorf("readAgentServerState after release = %v, want ErrAgentServerNotRunning", err)
	}
}

func TestReleaseAgentServerState_ForeignPIDIsPreserved(t *testing.T) {
	withIsolatedAgentHome(t)

	state := seedAgentServerState(t, os.Getpid(), fakeAgentExecutable(t))

	if err := releaseAgentServerState(state.PID + 1); err != nil {
		t.Fatalf("releaseAgentServerState: %v", err)
	}
	if _, err := readAgentServerState(); err != nil {
		t.Errorf("state claimed by another PID was removed: %v", err)
	}
}

func TestClaimAgentServerState_AlreadyRunning(t *testing.T) {
	withIsolatedAgentHome(t)

	executable := fakeAgentExecutable(t)
	pid := startFakeAgentServer(t, executable, false)
	seedAgentServerState(t, pid, executable)

	second, err := newAgentServerState("127.0.0.1:9443", false)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	err = claimAgentServerState(second)
	if !errors.Is(err, ErrAgentServerAlreadyRunning) {
		t.Fatalf("claimAgentServerState = %v, want ErrAgentServerAlreadyRunning", err)
	}

	loaded, readErr := readAgentServerState()
	if readErr != nil {
		t.Fatalf("readAgentServerState: %v", readErr)
	}
	if loaded.PID != pid {
		t.Errorf("state PID = %d, want the running server PID %d", loaded.PID, pid)
	}
}

func TestClaimAgentServerState_StalePIDIsReclaimed(t *testing.T) {
	withIsolatedAgentHome(t)

	seedAgentServerState(t, deadPID(t), fakeAgentExecutable(t))

	state, err := newAgentServerState("127.0.0.1:9443", false)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	if err := claimAgentServerState(state); err != nil {
		t.Fatalf("claimAgentServerState over stale record: %v", err)
	}

	loaded, err := readAgentServerState()
	if err != nil {
		t.Fatalf("readAgentServerState: %v", err)
	}
	if loaded.PID != os.Getpid() {
		t.Errorf("state PID = %d, want %d", loaded.PID, os.Getpid())
	}
}

func TestClaimAgentServerState_UnwritableDirectory(t *testing.T) {
	withIsolatedAgentHome(t)

	// A regular file where the agent data directory belongs makes both
	// MkdirAll and the state file creation fail deterministically,
	// regardless of the effective user.
	if err := os.MkdirAll(filepath.Dir(mustAgentDataDir(t)), 0o700); err != nil {
		t.Fatalf("prepare data dir: %v", err)
	}
	if err := os.WriteFile(mustAgentDataDir(t), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}

	state, err := newAgentServerState("127.0.0.1:9443", false)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	if err := claimAgentServerState(state); !errors.Is(err, ErrAgentStateWrite) {
		t.Fatalf("claimAgentServerState = %v, want ErrAgentStateWrite", err)
	}
}

func TestUpdateAgentServerState_RecordsBoundAddress(t *testing.T) {
	withIsolatedAgentHome(t)

	state, err := newAgentServerState("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	if err := claimAgentServerState(state); err != nil {
		t.Fatalf("claimAgentServerState: %v", err)
	}

	state.ListenAddr = "127.0.0.1:34567"
	if err := updateAgentServerState(state); err != nil {
		t.Fatalf("updateAgentServerState: %v", err)
	}

	loaded, err := readAgentServerState()
	if err != nil {
		t.Fatalf("readAgentServerState: %v", err)
	}
	if loaded.ListenAddr != "127.0.0.1:34567" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:34567", loaded.ListenAddr)
	}

	entries, err := os.ReadDir(mustAgentDataDir(t))
	if err != nil {
		t.Fatalf("read agent data dir: %v", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Errorf("temporary file %q was left behind", entry.Name())
		}
	}
}

func TestUpdateAgentServerState_UnwritableDirectory(t *testing.T) {
	withIsolatedAgentHome(t)

	state, err := newAgentServerState("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	// No directory has been created, so the temporary file cannot be made.
	if err := updateAgentServerState(state); !errors.Is(err, ErrAgentStateWrite) {
		t.Fatalf("updateAgentServerState = %v, want ErrAgentStateWrite", err)
	}
}

func TestReadAgentServerState_NoStateFile(t *testing.T) {
	withIsolatedAgentHome(t)

	if _, err := readAgentServerState(); !errors.Is(err, ErrAgentServerNotRunning) {
		t.Fatalf("readAgentServerState = %v, want ErrAgentServerNotRunning", err)
	}
}

func TestReadAgentServerState_UnreadablePath(t *testing.T) {
	withIsolatedAgentHome(t)

	// A directory at the state file path fails the read with EISDIR for
	// every user, including root.
	if err := os.MkdirAll(mustAgentStateFile(t), 0o700); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}

	_, err := readAgentServerState()
	if !errors.Is(err, ErrAgentStateRead) {
		t.Fatalf("readAgentServerState = %v, want ErrAgentStateRead", err)
	}
	if errors.Is(err, ErrAgentServerNotRunning) {
		t.Error("an unreadable state file must not be reported as not running")
	}
}

func TestReadAgentServerState_CorruptDocument(t *testing.T) {
	withIsolatedAgentHome(t)

	if err := os.MkdirAll(mustAgentDataDir(t), 0o700); err != nil {
		t.Fatalf("create agent data dir: %v", err)
	}

	tests := []struct {
		name     string
		contents string
	}{
		{name: "not json", contents: "{{{"},
		{name: "missing pid", contents: `{"listen_address":"127.0.0.1:9443"}`},
		{name: "negative pid", contents: `{"pid":-1}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(mustAgentStateFile(t), []byte(tc.contents), 0o600); err != nil {
				t.Fatalf("write state file: %v", err)
			}
			if _, err := readAgentServerState(); !errors.Is(err, ErrAgentStateCorrupt) {
				t.Fatalf("readAgentServerState = %v, want ErrAgentStateCorrupt", err)
			}
		})
	}
}

func TestAgentServerStatus_NotRunning(t *testing.T) {
	withIsolatedAgentHome(t)

	state, running, err := agentServerStatus()
	if err != nil {
		t.Fatalf("agentServerStatus: %v", err)
	}
	if running || state != nil {
		t.Fatalf("agentServerStatus reported running=%v state=%v, want not running", running, state)
	}
}

func TestAgentServerStatus_Running(t *testing.T) {
	withIsolatedAgentHome(t)

	executable := fakeAgentExecutable(t)
	pid := startFakeAgentServer(t, executable, false)
	seedAgentServerState(t, pid, executable)

	state, running, err := agentServerStatus()
	if err != nil {
		t.Fatalf("agentServerStatus: %v", err)
	}
	if !running {
		t.Fatal("agentServerStatus reported not running for a live agent process")
	}
	if state.PID != pid {
		t.Errorf("PID = %d, want %d", state.PID, pid)
	}
	if state.ListenAddr != "127.0.0.1:19443" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:19443", state.ListenAddr)
	}
}

func TestAgentServerStatus_StalePIDSelfHeals(t *testing.T) {
	withIsolatedAgentHome(t)

	seedAgentServerState(t, deadPID(t), fakeAgentExecutable(t))

	_, running, err := agentServerStatus()
	if err != nil {
		t.Fatalf("agentServerStatus: %v", err)
	}
	if running {
		t.Fatal("a state file naming a dead process must not be reported as running")
	}
	if _, err := os.Stat(mustAgentStateFile(t)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale state file was not removed: %v", err)
	}
}

func TestAgentServerStatus_RecycledPIDSelfHeals(t *testing.T) {
	withIsolatedAgentHome(t)

	// The PID is alive, but it belongs to this test binary rather than an
	// xkey agent server: a recycled PID must not be reported as running.
	seedAgentServerState(t, os.Getpid(), fakeAgentExecutable(t))

	_, running, err := agentServerStatus()
	if err != nil {
		t.Fatalf("agentServerStatus: %v", err)
	}
	if running {
		t.Fatal("a PID belonging to an unrelated process must not be reported as running")
	}
	if _, err := os.Stat(mustAgentStateFile(t)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale state file was not removed: %v", err)
	}
}

func TestAgentServerStatus_CorruptStateSelfHeals(t *testing.T) {
	withIsolatedAgentHome(t)

	if err := os.MkdirAll(mustAgentDataDir(t), 0o700); err != nil {
		t.Fatalf("create agent data dir: %v", err)
	}
	if err := os.WriteFile(mustAgentStateFile(t), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	_, running, err := agentServerStatus()
	if err != nil {
		t.Fatalf("agentServerStatus: %v", err)
	}
	if running {
		t.Fatal("a corrupt state file must not be reported as running")
	}
	if _, err := os.Stat(mustAgentStateFile(t)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("corrupt state file was not removed: %v", err)
	}
}

func TestAgentServerStatus_UnreadableStateIsAnError(t *testing.T) {
	withIsolatedAgentHome(t)

	if err := os.MkdirAll(mustAgentStateFile(t), 0o700); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}

	if _, _, err := agentServerStatus(); !errors.Is(err, ErrAgentStateRead) {
		t.Fatalf("agentServerStatus = %v, want ErrAgentStateRead", err)
	}
}

func TestStopAgentServer_NothingRunning(t *testing.T) {
	withIsolatedAgentHome(t)

	state, forced, err := stopAgentServer(time.Second, time.Second)
	if !errors.Is(err, ErrAgentServerNotRunning) {
		t.Fatalf("stopAgentServer = %v, want ErrAgentServerNotRunning", err)
	}
	if state != nil || forced {
		t.Errorf("stopAgentServer returned state=%v forced=%v, want nil/false", state, forced)
	}
}

func TestStopAgentServer_StalePIDReportsNotRunning(t *testing.T) {
	withIsolatedAgentHome(t)

	seedAgentServerState(t, deadPID(t), fakeAgentExecutable(t))

	if _, _, err := stopAgentServer(time.Second, time.Second); !errors.Is(err, ErrAgentServerNotRunning) {
		t.Fatalf("stopAgentServer = %v, want ErrAgentServerNotRunning", err)
	}
	if _, err := os.Stat(mustAgentStateFile(t)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale state file was not removed: %v", err)
	}
}

func TestStopAgentServer_GracefulTermination(t *testing.T) {
	withIsolatedAgentHome(t)

	executable := fakeAgentExecutable(t)
	pid := startFakeAgentServer(t, executable, false)
	seedAgentServerState(t, pid, executable)

	state, forced, err := stopAgentServer(10*time.Second, 2*time.Second)
	if err != nil {
		t.Fatalf("stopAgentServer: %v", err)
	}
	if forced {
		t.Error("SIGKILL escalation was used for a process that honors SIGTERM")
	}
	if state.PID != pid {
		t.Errorf("PID = %d, want %d", state.PID, pid)
	}
	if agentServerAlive(state) {
		t.Error("agent server is still alive after stopAgentServer returned")
	}
	if _, err := os.Stat(mustAgentStateFile(t)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file was not removed: %v", err)
	}
}

func TestStopAgentServer_EscalatesToSIGKILL(t *testing.T) {
	withIsolatedAgentHome(t)

	executable := fakeAgentExecutable(t)
	pid := startFakeAgentServer(t, executable, true)
	seedAgentServerState(t, pid, executable)

	state, forced, err := stopAgentServer(250*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("stopAgentServer: %v", err)
	}
	if !forced {
		t.Error("expected SIGKILL escalation for a process that ignores SIGTERM")
	}
	if agentServerAlive(state) {
		t.Error("agent server is still alive after SIGKILL")
	}
	if _, err := os.Stat(mustAgentStateFile(t)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file was not removed: %v", err)
	}
}

func TestProcessAlive(t *testing.T) {
	tests := []struct {
		name string
		pid  int
		want bool
	}{
		{name: "current process", pid: os.Getpid(), want: true},
		{name: "exited process", pid: deadPID(t), want: false},
		{name: "zero", pid: 0, want: false},
		{name: "negative", pid: -1, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := processAlive(tc.pid); got != tc.want {
				t.Errorf("processAlive(%d) = %v, want %v", tc.pid, got, tc.want)
			}
		})
	}
}

func TestProcessArgs_CurrentProcess(t *testing.T) {
	argv, supported := processArgs(os.Getpid())
	if supported {
		if len(argv) == 0 {
			t.Fatal("processArgs returned no arguments for the current process")
		}
		if filepath.Base(argv[0]) == "" {
			t.Errorf("processArgs returned an unusable argv[0]: %q", argv[0])
		}
		return
	}
	// A platform without a proc filesystem must report no argument
	// vector so callers fall back to signal-based liveness.
	if argv != nil {
		t.Errorf("processArgs returned %v on a platform without argument vectors", argv)
	}
}

func TestProcessArgs_ExitedProcess(t *testing.T) {
	argv, supported := processArgs(deadPID(t))
	if supported && len(argv) != 0 {
		t.Errorf("processArgs returned %v for an exited process, want none", argv)
	}
}

func TestCmdlineIsAgentServer(t *testing.T) {
	tests := []struct {
		name       string
		argv       []string
		executable string
		want       bool
	}{
		{
			name:       "agent start",
			argv:       []string{"/usr/local/bin/xkey", "agent", "start", "--listen", "127.0.0.1:0"},
			executable: "/opt/xkey/xkey",
			want:       true,
		},
		{
			name:       "different binary",
			argv:       []string{"/usr/bin/sshd", "agent", "start"},
			executable: "/usr/local/bin/xkey",
			want:       false,
		},
		{
			name:       "different subcommand",
			argv:       []string{"/usr/local/bin/xkey", "ssh", "connect"},
			executable: "/usr/local/bin/xkey",
			want:       false,
		},
		{
			name:       "agent without start",
			argv:       []string{"/usr/local/bin/xkey", "agent", "status"},
			executable: "/usr/local/bin/xkey",
			want:       false,
		},
		{
			name:       "empty argv",
			argv:       nil,
			executable: "/usr/local/bin/xkey",
			want:       false,
		},
		{
			name:       "empty executable",
			argv:       []string{"/usr/local/bin/xkey", "agent", "start"},
			executable: "",
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmdlineIsAgentServer(tc.argv, tc.executable); got != tc.want {
				t.Errorf("cmdlineIsAgentServer(%v, %q) = %v, want %v",
					tc.argv, tc.executable, got, tc.want)
			}
		})
	}
}

func TestSplitArgv(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{name: "trailing separator", data: []byte("xkey\x00agent\x00start\x00"), want: []string{"xkey", "agent", "start"}},
		{name: "no trailing separator", data: []byte("xkey\x00agent"), want: []string{"xkey", "agent"}},
		{name: "empty zombie vector", data: []byte{}, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitArgv(tc.data)
			if len(got) != len(tc.want) {
				t.Fatalf("splitArgv = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("splitArgv = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestAgentServerAlive_NilState(t *testing.T) {
	if agentServerAlive(nil) {
		t.Error("agentServerAlive(nil) = true, want false")
	}
}

func TestWaitForAgentExit_TimesOut(t *testing.T) {
	withIsolatedAgentHome(t)

	executable := fakeAgentExecutable(t)
	pid := startFakeAgentServer(t, executable, false)
	state := &agentServerState{PID: pid, Executable: executable}

	if waitForAgentExit(state, 100*time.Millisecond) {
		t.Error("waitForAgentExit reported exit for a process that is still running")
	}
}

// ---------------------------------------------------------------
// runAgentStop (thin RunE wrapper over stopAgentServer)
// ---------------------------------------------------------------

func TestRunAgentStop_NothingRunning(t *testing.T) {
	withIsolatedAgentHome(t)

	_, err := runDetached(t, runAgentStop)
	if !errors.Is(err, ErrAgentServerNotRunning) {
		t.Fatalf("runAgentStop error = %v, want %v", err, ErrAgentServerNotRunning)
	}
}

func TestRunAgentStop_ReportsGracefulTermination(t *testing.T) {
	withIsolatedAgentHome(t)

	executable := fakeAgentExecutable(t)
	pid := startFakeAgentServer(t, executable, false)
	seedAgentServerState(t, pid, executable)

	out, err := runDetached(t, runAgentStop)
	if err != nil {
		t.Fatalf("runAgentStop: %v", err)
	}
	if !strings.Contains(out, "Agent server stopped") {
		t.Errorf("output = %q, want it to report the server stopped", out)
	}
	if !strings.Contains(out, "Signal: SIGTERM") {
		t.Errorf("output = %q, want it to report SIGTERM (not SIGKILL) for a cooperative process", out)
	}
	if _, statErr := os.Stat(mustAgentStateFile(t)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("state file was not removed: %v", statErr)
	}
}

func TestRunAgentStatus_ReportsRunningServer(t *testing.T) {
	withIsolatedAgentHome(t)

	executable := fakeAgentExecutable(t)
	pid := startFakeAgentServer(t, executable, false)
	for _, tls := range []bool{true, false} {
		state := &agentServerState{
			PID:        pid,
			ListenAddr: "127.0.0.1:19443",
			Executable: executable,
			TLS:        tls,
			StartedAt:  time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
		}
		if err := claimAgentServerState(state); err != nil {
			t.Fatalf("claim agent server state: %v", err)
		}

		out, err := runDetached(t, runAgentStatus)
		if err != nil {
			t.Fatalf("runAgentStatus (tls=%v): %v", tls, err)
		}
		want := []string{
			"Agent server: running",
			"Listen:  127.0.0.1:19443",
			"Started: 2026-10-17T12:00:00Z",
			"No enrolled agents",
		}
		if tls {
			want = append(want, "TLS:     enabled (mTLS)")
		} else {
			want = append(want, "TLS:     disabled (development mode)")
		}
		for _, line := range want {
			if !strings.Contains(out, line) {
				t.Errorf("output (tls=%v) = %q, want it to contain %q", tls, out, line)
			}
		}
		if err := removeAgentServerState(); err != nil {
			t.Fatalf("remove agent server state: %v", err)
		}
	}
}

func TestRunAgentStatus_UnreadableStateIsAnError(t *testing.T) {
	withIsolatedAgentHome(t)

	if err := os.MkdirAll(mustAgentStateFile(t), 0o700); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}

	if _, err := runDetached(t, runAgentStatus); !errors.Is(err, ErrAgentStateRead) {
		t.Fatalf("runAgentStatus = %v, want ErrAgentStateRead", err)
	}
}

func TestRunAgentStatus_UnusableEnrollmentStoreIsAnError(t *testing.T) {
	withIsolatedAgentHome(t)

	storeDir := mustAgentStoreDir(t)
	if err := os.MkdirAll(filepath.Dir(storeDir), 0o700); err != nil {
		t.Fatalf("create agent data directory: %v", err)
	}
	// A regular file where the enrollment directory belongs stops the
	// store from creating its subdirectories.
	if err := os.WriteFile(storeDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}

	if _, err := runDetached(t, runAgentStatus); !errors.Is(err, ErrAgentStatusFailed) {
		t.Fatalf("runAgentStatus = %v, want ErrAgentStatusFailed", err)
	}
}
