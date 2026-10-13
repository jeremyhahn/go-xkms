package cmd

import (
	"errors"
	"os"
	"testing"
	"time"
)

// writeCorruptAgentState leaves a state file that does not decode.
func writeCorruptAgentState(t *testing.T) {
	t.Helper()

	if err := os.MkdirAll(mustAgentDataDir(t), 0o700); err != nil {
		t.Fatalf("create agent data dir: %v", err)
	}
	if err := os.WriteFile(mustAgentStateFile(t), []byte("{{{"), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}
}

// blockAgentStateFile puts a directory at the state file path, so every
// read of it fails with EISDIR.
func blockAgentStateFile(t *testing.T) {
	t.Helper()

	if err := os.MkdirAll(mustAgentStateFile(t), 0o700); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}
}

func TestReleaseAgentServerState_NoStateFile(t *testing.T) {
	withIsolatedAgentHome(t)

	if err := releaseAgentServerState(os.Getpid()); err != nil {
		t.Fatalf("releaseAgentServerState with no record = %v, want nil", err)
	}
}

func TestReleaseAgentServerState_CorruptStateIsRemoved(t *testing.T) {
	withIsolatedAgentHome(t)
	writeCorruptAgentState(t)

	if err := releaseAgentServerState(os.Getpid()); err != nil {
		t.Fatalf("releaseAgentServerState = %v", err)
	}
	if _, err := os.Stat(mustAgentStateFile(t)); !os.IsNotExist(err) {
		t.Fatalf("corrupt state file still present: stat err = %v", err)
	}
}

func TestReleaseAgentServerState_UnreadableStateIsAnError(t *testing.T) {
	withIsolatedAgentHome(t)
	blockAgentStateFile(t)

	if err := releaseAgentServerState(os.Getpid()); !errors.Is(err, ErrAgentStateRead) {
		t.Fatalf("releaseAgentServerState = %v, want ErrAgentStateRead", err)
	}
}

func TestClaimAgentServerState_CorruptRecordIsReclaimed(t *testing.T) {
	withIsolatedAgentHome(t)
	writeCorruptAgentState(t)

	state, err := newAgentServerState("127.0.0.1:9443", false)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	if err := claimAgentServerState(state); err != nil {
		t.Fatalf("claimAgentServerState over corrupt record: %v", err)
	}
	loaded, err := readAgentServerState()
	if err != nil {
		t.Fatalf("readAgentServerState: %v", err)
	}
	if loaded.PID != os.Getpid() {
		t.Errorf("state PID = %d, want %d", loaded.PID, os.Getpid())
	}
}

func TestClaimAgentServerState_UnreadableRecordIsNotClobbered(t *testing.T) {
	withIsolatedAgentHome(t)
	blockAgentStateFile(t)

	state, err := newAgentServerState("127.0.0.1:9443", false)
	if err != nil {
		t.Fatalf("newAgentServerState: %v", err)
	}
	if err := claimAgentServerState(state); !errors.Is(err, ErrAgentStateRead) {
		t.Fatalf("claimAgentServerState = %v, want ErrAgentStateRead", err)
	}
	info, err := os.Stat(mustAgentStateFile(t))
	if err != nil || !info.IsDir() {
		t.Fatalf("the unreadable record must be left in place: stat = %v, %v", info, err)
	}
}

func TestStopAgentServer_UnreadableStateIsAnError(t *testing.T) {
	withIsolatedAgentHome(t)
	blockAgentStateFile(t)

	_, _, err := stopAgentServer(time.Millisecond, time.Millisecond)
	if !errors.Is(err, ErrAgentStateRead) {
		t.Fatalf("stopAgentServer = %v, want ErrAgentStateRead", err)
	}
}
