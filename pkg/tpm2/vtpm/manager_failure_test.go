package vtpm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeScript writes an executable shell script standing in for swtpm, so a
// test can drive the manager through a process that misbehaves.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-swtpm")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700))
	return path
}

// newManagerWith builds a manager over the given binary and directories,
// closed when the test ends.
func newManagerWith(t *testing.T, cfg Config, keys StateKeyProvider) *Manager {
	t.Helper()
	if cfg.RunDir == "" {
		runDir, err := os.MkdirTemp("", "vtpm")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, os.RemoveAll(runDir)) })
		cfg.RunDir = runDir
	}
	if cfg.StateDir == "" {
		cfg.StateDir = t.TempDir()
	}
	m, err := NewManager(cfg, keys)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	return m
}

// countingKeys counts StateKey calls and fails them once failing is set, so
// a test can see the supervisor attempt a restart that cannot get its key.
type countingKeys struct {
	calls   atomic.Int64
	failing atomic.Bool
}

func (c *countingKeys) StateKey(string) ([]byte, error) {
	c.calls.Add(1)
	if c.failing.Load() {
		return nil, errors.New("sealed key unavailable")
	}
	return key(7), nil
}

func TestResolveBinary_AcceptsOnlyAnExecutableRegularFile(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "exe")
	require.NoError(t, os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o700))
	plain := filepath.Join(dir, "plain")
	require.NoError(t, os.WriteFile(plain, []byte("data"), 0o600))

	resolved, err := resolveBinary(exe)
	require.NoError(t, err)
	assert.Equal(t, exe, resolved)

	for _, bad := range []string{plain, dir} {
		_, err := resolveBinary(bad)
		var binErr *BinaryError
		require.True(t, errors.As(err, &binErr), "binary %q", bad)
		assert.Equal(t, bad, binErr.Binary)
		assert.ErrorIs(t, err, errBinaryNotExecutable)
	}
}

func TestManager_StartTwiceIsOneVTPMAndStopRefusesUnknownTenants(t *testing.T) {
	m := newTestManager(t, &fixedKeys{keys: map[string][]byte{"acme": key(1)}})
	ctx := context.Background()
	require.NoError(t, m.Start(ctx, "acme"))
	pid := m.Status("acme").PID
	require.NoError(t, m.Start(ctx, "acme"))
	assert.Equal(t, pid, m.Status("acme").PID, "a second Start must not spawn another vTPM")

	assert.ErrorIs(t, m.Stop("../acme"), ErrInvalidTenant)
	assert.ErrorIs(t, m.Stop("other"), ErrNotRunning)

	require.NoError(t, m.Stop("acme"))
	assert.False(t, m.Status("acme").Running)
	assert.ErrorIs(t, m.Stop("acme"), ErrNotRunning)
}

func TestManager_StartReportsDirectoriesItCannotCreate(t *testing.T) {
	keys := &fixedKeys{keys: map[string][]byte{"acme": key(1)}}
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	tests := []struct {
		name string
		cfg  Config
	}{
		{"state dir under a file", Config{StateDir: file}},
		{"run dir under a file", Config{RunDir: filepath.Join(file, "run")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newManagerWith(t, tt.cfg, keys)
			err := m.Start(context.Background(), "acme")
			var startErr *StartError
			require.True(t, errors.As(err, &startErr))
			assert.Equal(t, "acme", startErr.Tenant)
			assert.ErrorIs(t, err, syscall.ENOTDIR)
			assert.False(t, m.Status("acme").Running)
		})
	}
}

func TestManager_StartReportsAVTPMThatExitsBeforeItIsReady(t *testing.T) {
	m := newManagerWith(t, Config{Binary: writeScript(t, "exit 3")}, &fixedKeys{keys: map[string][]byte{"acme": key(1)}})

	err := m.Start(context.Background(), "acme")
	var startErr *StartError
	require.True(t, errors.As(err, &startErr))
	assert.ErrorIs(t, err, ErrNotRunning)
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr))
	assert.Equal(t, 3, exitErr.ExitCode())
	assert.ErrorIs(t, m.Stop("acme"), ErrNotRunning, "a vTPM that never became ready is not registered")
}

func TestManager_StartGivesUpWhenItsContextEnds(t *testing.T) {
	m := newManagerWith(t, Config{Binary: writeScript(t, "exec sleep 30")}, &fixedKeys{keys: map[string][]byte{"acme": key(1)}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := m.Start(ctx, "acme")
	var startErr *StartError
	require.True(t, errors.As(err, &startErr))
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, m.Status("acme").Running)
}

func TestManager_StopEndsASupervisorWhoseRestartsCannotGetTheKey(t *testing.T) {
	keys := &countingKeys{}
	m := newManagerWith(t, Config{}, keys)
	require.NoError(t, m.Start(context.Background(), "acme"))
	require.Equal(t, int64(1), keys.calls.Load())

	keys.failing.Store(true)
	require.NoError(t, syscall.Kill(m.Status("acme").PID, syscall.SIGKILL))
	require.Eventually(t, func() bool { return keys.calls.Load() >= 2 }, 10*time.Second, 10*time.Millisecond,
		"the supervisor did not attempt a restart")

	s := m.Status("acme")
	assert.False(t, s.Running)
	assert.Zero(t, s.Restarts)
	require.NoError(t, m.Stop("acme"))
}

func TestExitOfAndExitErr_TreatNoProcessAsExited(t *testing.T) {
	select {
	case <-exitOf(nil):
	default:
		t.Fatal("exitOf(nil) must be ready so the supervisor retries")
	}
	assert.ErrorIs(t, exitErr(nil), ErrNotRunning)

	proc := &process{done: make(chan struct{}), err: syscall.ECHILD}
	assert.Equal(t, (<-chan struct{})(proc.done), exitOf(proc))
	assert.ErrorIs(t, exitErr(proc), syscall.ECHILD)
}

func TestWaitIgnoringKill_IgnoresOnlyAnExitStatus(t *testing.T) {
	exited := exec.Command(writeScript(t, "exit 1"))
	require.NoError(t, exited.Start())
	assert.NoError(t, waitIgnoringKill(exited))

	notStarted := exec.Command(writeScript(t, "exit 0"))
	assert.Error(t, waitIgnoringKill(notStarted))
}

func TestStopContext_EndsWhenStopClosesOrOnCancel(t *testing.T) {
	stop := make(chan struct{})
	ctx, cancel := stopContext(stop)
	defer cancel()
	close(stop)
	<-ctx.Done()
	assert.ErrorIs(t, ctx.Err(), context.Canceled)

	ctx, cancel = stopContext(make(chan struct{}))
	cancel()
	<-ctx.Done()
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
}
