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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Agent server lifecycle errors.
var (
	// ErrAgentServerNotRunning is returned when an operation requires a
	// live agent server but none is recorded (or the recorded process is
	// no longer alive).
	ErrAgentServerNotRunning = errors.New("agent: no agent server is running")

	// ErrAgentServerAlreadyRunning is returned when a second "agent start"
	// is attempted while a live server already owns the run-state file.
	ErrAgentServerAlreadyRunning = errors.New("agent: agent server is already running")

	// ErrAgentStateWrite is returned when the run-state file cannot be
	// created or updated.
	ErrAgentStateWrite = errors.New("agent: failed to write server state file")

	// ErrAgentStateRead is returned when the run-state file exists but
	// cannot be read (for example, insufficient permissions).
	ErrAgentStateRead = errors.New("agent: failed to read server state file")

	// ErrAgentStateCorrupt is returned when the run-state file exists but
	// does not contain a usable record.
	ErrAgentStateCorrupt = errors.New("agent: server state file is corrupt")

	// ErrAgentStateRemove is returned when the run-state file cannot be
	// removed.
	ErrAgentStateRemove = errors.New("agent: failed to remove server state file")

	// ErrAgentStopTimeout is returned when the server process is still
	// alive after SIGTERM and SIGKILL have both been delivered.
	ErrAgentStopTimeout = errors.New("agent: server process did not exit")
)

const (
	// agentStateFileName is the name of the agent server run-state file,
	// written under the agent data directory.
	agentStateFileName = "server.state.json"

	// agentStopGracePeriod bounds how long "agent stop" waits for the
	// server to exit after SIGTERM before escalating to SIGKILL.
	agentStopGracePeriod = 10 * time.Second

	// agentKillGracePeriod bounds how long "agent stop" waits for the
	// server to disappear after SIGKILL.
	agentKillGracePeriod = 2 * time.Second

	// agentLivenessPollInterval is the interval between liveness polls
	// while waiting for a signalled server process to exit.
	agentLivenessPollInterval = 25 * time.Millisecond

	// procRoot is the mount point of the Linux proc filesystem, used to
	// verify that a recorded PID still belongs to an xKey agent server.
	procRoot = "/proc"
)

// agentServerState is the on-disk record describing a running agent
// server process. It is created by "xkey agent start" before the listener
// binds, updated with the bound address once the listener is up, and
// removed on graceful shutdown. "xkey agent stop" and "xkey agent status"
// read it to locate the server.
type agentServerState struct {
	// PID is the process ID of the agent server.
	PID int `json:"pid"`

	// ListenAddr is the address the server is bound to. Before the
	// listener is up this holds the configured (possibly ephemeral)
	// address; afterwards it holds the resolved bound address.
	ListenAddr string `json:"listen_address"`

	// Executable is the absolute path of the binary running the server.
	// It anchors the PID-reuse sanity check.
	Executable string `json:"executable"`

	// TLS reports whether the server was started with mTLS credentials.
	TLS bool `json:"tls"`

	// StartedAt is the UTC time the server claimed the state file.
	StartedAt time.Time `json:"started_at"`
}

// agentStateFile returns the path of the agent server run-state file.
// It resolves under the same xKey home as the agent enrollment store so
// that start, stop, and status always agree on a single location.
func agentStateFile() (string, error) {
	dataDir, err := agentDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, agentStateFileName), nil
}

// newAgentServerState captures the run state of the current process for
// the given listen address and TLS mode.
func newAgentServerState(listenAddr string, tlsEnabled bool) (*agentServerState, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
	}
	return &agentServerState{
		PID:        os.Getpid(),
		ListenAddr: listenAddr,
		Executable: executable,
		TLS:        tlsEnabled,
		StartedAt:  time.Now().UTC(),
	}, nil
}

// encode renders the state as the JSON document stored on disk.
func (s *agentServerState) encode() ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
	}
	return append(data, '\n'), nil
}

// readAgentServerState loads the run-state file. It returns
// ErrAgentServerNotRunning when no state file exists, ErrAgentStateCorrupt
// when the file cannot be decoded, and ErrAgentStateRead for any other
// read failure (for example a permission error).
func readAgentServerState() (*agentServerState, error) {
	path, err := agentStateFile()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentStateRead, Cause: err}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrAgentServerNotRunning
		}
		return nil, &SentinelCauseError{Sentinel: ErrAgentStateRead, Cause: err}
	}

	var state agentServerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentStateCorrupt, Cause: err}
	}
	if state.PID <= 0 {
		return nil, &xkms.ErrsDetail{Err: ErrAgentStateCorrupt, Detail: "no valid process ID recorded"}
	}
	return &state, nil
}

// removeAgentServerState deletes the run-state file. A missing file is
// not an error.
func removeAgentServerState() error {
	path, err := agentStateFile()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStateRemove, Cause: err}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return &SentinelCauseError{Sentinel: ErrAgentStateRemove, Cause: err}
	}
	return nil
}

// releaseAgentServerState removes the run-state file when it still
// describes pid. State claimed by another process is left untouched so a
// shutting-down server never deletes its successor's record.
func releaseAgentServerState(pid int) error {
	state, err := readAgentServerState()
	switch {
	case errors.Is(err, ErrAgentServerNotRunning):
		return nil
	case errors.Is(err, ErrAgentStateCorrupt):
		return removeAgentServerState()
	case err != nil:
		return err
	}
	if state.PID != pid {
		return nil
	}
	return removeAgentServerState()
}

// claimAgentServerState atomically stakes the run-state file for the
// process described by state. The file is created with O_EXCL so two
// concurrent "agent start" invocations cannot both claim it: the loser
// observes the winner's record and receives ErrAgentServerAlreadyRunning.
// A record left behind by a crashed server is self-healed and the claim
// retried once.
func claimAgentServerState(state *agentServerState) error {
	payload, err := state.encode()
	if err != nil {
		return err
	}

	path, err := agentStateFile()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
	}

	// Two attempts: the first may lose to an existing record, which is
	// removed when stale so the second attempt can succeed.
	for attempt := 0; attempt < 2; attempt++ {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, writeErr := file.Write(payload)
			closeErr := file.Close()
			if writeErr == nil && closeErr == nil {
				return nil
			}
			cause := writeErr
			if cause == nil {
				cause = closeErr
			}
			if removeErr := removeAgentServerState(); removeErr != nil {
				return removeErr
			}
			return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: cause}
		}
		if !errors.Is(err, fs.ErrExist) {
			return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
		}

		existing, readErr := readAgentServerState()
		switch {
		case readErr == nil && agentServerAlive(existing):
			return &xkms.ErrsDetail{
				Err: ErrAgentServerAlreadyRunning,
				Detail: fmt.Sprintf("PID %d is listening on %s (run 'xkey agent stop' first)",
					existing.PID, existing.ListenAddr),
			}
		case readErr != nil && !errors.Is(readErr, ErrAgentServerNotRunning) &&
			!errors.Is(readErr, ErrAgentStateCorrupt):
			return readErr
		}

		if removeErr := removeAgentServerState(); removeErr != nil {
			return removeErr
		}
	}

	return &xkms.ErrsDetail{
		Err:    ErrAgentStateWrite,
		Detail: "state file is being recreated by a concurrent process",
	}
}

// updateAgentServerState rewrites the run-state file of an already
// claimed server, typically to record the resolved listen address. The
// replacement is atomic so concurrent readers never observe a partial
// document, and the path never disappears, preserving the claim.
func updateAgentServerState(state *agentServerState) error {
	payload, err := state.encode()
	if err != nil {
		return err
	}

	path, err := agentStateFile()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".server.state.*.tmp")
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
	}
	tempName := temp.Name()

	_, writeErr := temp.Write(payload)
	closeErr := temp.Close()
	if writeErr != nil || closeErr != nil {
		cause := writeErr
		if cause == nil {
			cause = closeErr
		}
		if removeErr := os.Remove(tempName); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return &SentinelCauseError{Sentinel: ErrAgentStateRemove, Cause: removeErr}
		}
		return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: cause}
	}

	if err := os.Rename(tempName, path); err != nil {
		if removeErr := os.Remove(tempName); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return &SentinelCauseError{Sentinel: ErrAgentStateRemove, Cause: removeErr}
		}
		return &SentinelCauseError{Sentinel: ErrAgentStateWrite, Cause: err}
	}
	return nil
}

// agentServerStatus reports the recorded run state and whether that
// server is actually running. A stale record - the process exited, was
// killed, or its PID was recycled by an unrelated program - is removed so
// subsequent commands start from a clean slate.
func agentServerStatus() (*agentServerState, bool, error) {
	state, err := readAgentServerState()
	switch {
	case errors.Is(err, ErrAgentServerNotRunning):
		return nil, false, nil
	case errors.Is(err, ErrAgentStateCorrupt):
		if removeErr := removeAgentServerState(); removeErr != nil {
			return nil, false, removeErr
		}
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}

	if agentServerAlive(state) {
		return state, true, nil
	}
	if err := removeAgentServerState(); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

// stopAgentServer terminates the recorded agent server. It sends SIGTERM,
// waits up to grace for the process to exit, escalates to SIGKILL when
// the process outlives that window, and finally removes the run-state
// file. The returned bool reports whether SIGKILL was required.
// ErrAgentServerNotRunning is returned when no live server is recorded.
func stopAgentServer(grace, killGrace time.Duration) (*agentServerState, bool, error) {
	state, running, err := agentServerStatus()
	if err != nil {
		return nil, false, err
	}
	if !running {
		return nil, false, ErrAgentServerNotRunning
	}

	process, err := os.FindProcess(state.PID)
	if err != nil {
		return nil, false, &SentinelCauseError{Sentinel: ErrAgentStopFailed, Cause: err}
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			return nil, false, &SentinelCauseError{Sentinel: ErrAgentStopFailed, Cause: err}
		}
		// The server exited between the liveness check and the signal;
		// nothing was stopped by this invocation.
		if removeErr := releaseAgentServerState(state.PID); removeErr != nil {
			return nil, false, removeErr
		}
		return nil, false, ErrAgentServerNotRunning
	}

	forced := false
	if !waitForAgentExit(state, grace) {
		forced = true
		if err := process.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return nil, false, &SentinelCauseError{Sentinel: ErrAgentStopFailed, Cause: err}
		}
		if !waitForAgentExit(state, killGrace) {
			return nil, false, &xkms.ErrsDetail{
				Err:    ErrAgentStopTimeout,
				Detail: fmt.Sprintf("PID %d is still alive after SIGKILL", state.PID),
			}
		}
	}

	if err := releaseAgentServerState(state.PID); err != nil {
		return nil, forced, err
	}
	return state, forced, nil
}

// waitForAgentExit polls until the server described by state is no longer
// alive, or until timeout elapses. It reports whether the process exited.
func waitForAgentExit(state *agentServerState, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !agentServerAlive(state) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(agentLivenessPollInterval)
	}
}

// agentServerAlive reports whether the process described by state is a
// live agent server. Liveness requires both that the PID is signalable
// and that the kernel-recorded argument vector still identifies an
// "xkey agent start" process launched from the recorded executable, so a
// recycled PID, an unrelated program, or a not-yet-reaped zombie is never
// mistaken for a running server.
func agentServerAlive(state *agentServerState) bool {
	if state == nil || !processAlive(state.PID) {
		return false
	}
	argv, supported := processArgs(state.PID)
	if !supported {
		// The platform does not expose argument vectors; signal-based
		// liveness is the strongest available check.
		return true
	}
	return cmdlineIsAgentServer(argv, state.Executable)
}

// processAlive reports whether pid names a process that this user can
// signal. A process owned by another user (EPERM) is reported as not
// alive: the agent run-state file is per-user, so such a PID cannot be
// this user's agent server.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// processArgs returns the kernel-recorded argument vector of pid. The
// second return value reports whether the running platform exposes
// argument vectors at all; when it does not, callers fall back to
// signal-based liveness alone. A process that exists but exposes an empty
// argument vector (a zombie awaiting reaping) yields a nil vector.
func processArgs(pid int) ([]string, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		if _, statErr := os.Stat(filepath.Join(procRoot, "self", "cmdline")); statErr != nil {
			return nil, false
		}
		return nil, true
	}
	return splitArgv(data), true
}

// splitArgv splits a NUL-separated /proc argument vector into fields,
// discarding the trailing empty element produced by the final separator.
func splitArgv(data []byte) []string {
	fields := strings.Split(string(data), "\x00")
	argv := make([]string, 0, len(fields))
	for _, field := range fields {
		if field != "" {
			argv = append(argv, field)
		}
	}
	if len(argv) == 0 {
		return nil
	}
	return argv
}

// cmdlineIsAgentServer reports whether argv identifies an "xkey agent
// start" process launched from executable.
func cmdlineIsAgentServer(argv []string, executable string) bool {
	if len(argv) == 0 || executable == "" {
		return false
	}
	if filepath.Base(argv[0]) != filepath.Base(executable) {
		return false
	}

	var sawAgent, sawStart bool
	for _, arg := range argv[1:] {
		switch arg {
		case "agent":
			sawAgent = true
		case "start":
			sawStart = true
		}
	}
	return sawAgent && sawStart
}
