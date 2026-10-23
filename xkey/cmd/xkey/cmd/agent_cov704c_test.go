package cmd

import (
	"bytes"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// c704cStopWithSIGTERM stops a command that blocks until SIGINT/SIGTERM.
// The test registers its own SIGTERM channel first, so the signal never
// takes the default action of killing the test binary while the command
// has not yet registered its handler; it is re-sent until the command
// returns.
func c704cStopWithSIGTERM(t *testing.T, done <-chan error) error {
	t.Helper()
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)

	deadline := time.After(10 * time.Second)
	for {
		require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
		select {
		case err := <-done:
			return err
		case <-deadline:
			t.Fatal("command did not stop on SIGTERM")
			return nil
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// TestC704cRunAgentStart_ServesUntilSignalled proves a started agent server
// records its bound address, accepts connections on it, and on SIGTERM
// stops and removes its run-state record.
func TestC704cRunAgentStart_ServesUntilSignalled(t *testing.T) {
	// Registered before the server starts so SIGTERM can never kill the
	// test binary, whichever goroutine is scheduled first.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(guard) })

	withIsolatedAgentHome(t)
	fake := newFakeXKMSd(t, newCATestFixture(t))
	useTestXKMSdEndpoint(t, fake.server.URL)

	cmd := newAgentStartTestCmd(t, "127.0.0.1:0")
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	done := make(chan error, 1)
	go func() { done <- runAgentStart(cmd, nil) }()

	var bound string
	deadline := time.Now().Add(10 * time.Second)
	for bound == "" {
		if state, err := readAgentServerState(); err == nil && !strings.HasSuffix(state.ListenAddr, ":0") {
			bound = state.ListenAddr
			break
		}
		select {
		case err := <-done:
			t.Fatalf("agent server exited before it was listening: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		require.False(t, time.Now().After(deadline), "agent server never recorded its bound address")
	}

	conn, err := net.Dial("tcp", bound)
	require.NoError(t, err, "the recorded address must accept connections")
	require.NoError(t, conn.Close())

	require.NoError(t, c704cStopWithSIGTERM(t, done))
	requireNoAgentServerRecord(t)

	assert.Contains(t, out.String(), "Agent server started")
	assert.Contains(t, out.String(), "Listen: "+bound)
	assert.Contains(t, out.String(), "TLS:    disabled (development mode)")
	assert.Contains(t, out.String(), "Shutting down agent server...")
}

// c704cAgentState returns a run-state record for this process and the
// path the record is claimed at, under an isolated agent home.
func c704cAgentState(t *testing.T) (*agentServerState, string) {
	t.Helper()
	withIsolatedAgentHome(t)
	state, err := newAgentServerState("127.0.0.1:1", false)
	require.NoError(t, err)
	path, err := agentStateFile()
	require.NoError(t, err)
	return state, path
}

// TestC704cClaimAgentServerState_UnusableStateDirRefuses proves the claim
// fails with ErrAgentStateWrite when the record's directory cannot exist.
func TestC704cClaimAgentServerState_UnusableStateDirRefuses(t *testing.T) {
	state, path := c704cAgentState(t)
	c704cOccupy(t, filepath.Dir(path))

	err := claimAgentServerState(state)
	require.ErrorIs(t, err, ErrAgentStateWrite)
}

// TestC704cClaimAgentServerState_UnreadableRecordIsNotReplaced proves a
// record that exists but cannot be read is reported, never deleted and
// claimed over: only a missing, stale or corrupt record may be replaced.
func TestC704cClaimAgentServerState_UnreadableRecordIsNotReplaced(t *testing.T) {
	state, path := c704cAgentState(t)
	require.NoError(t, os.MkdirAll(path, 0o700))

	err := claimAgentServerState(state)
	require.ErrorIs(t, err, ErrAgentStateRead)
	assert.DirExists(t, path, "the unreadable record is left in place")
}

// TestC704cClaimAgentServerState_ReplacesACorruptRecord proves a corrupt
// record left by a crashed server is replaced by this process's claim.
func TestC704cClaimAgentServerState_ReplacesACorruptRecord(t *testing.T) {
	state, path := c704cAgentState(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	require.NoError(t, claimAgentServerState(state))

	claimed, err := readAgentServerState()
	require.NoError(t, err)
	assert.Equal(t, os.Getpid(), claimed.PID)
	assert.Equal(t, "127.0.0.1:1", claimed.ListenAddr)
}
