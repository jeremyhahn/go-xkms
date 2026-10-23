package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// c704cOccupy puts a regular file where the daemon expects a directory, so
// every attempt to create or open that directory fails.
func c704cOccupy(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte("not a directory"), 0600))
}

// TestC704cExtensionServe_WritesItsLogToTheLogFile proves --log-file
// redirects the daemon's structured log, including the --no-pairing warning,
// into the named file.
func TestC704cExtensionServe_WritesItsLogToTheLogFile(t *testing.T) {
	isolateServeHome(t)
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")
	logPath := filepath.Join(t.TempDir(), "serve.log")

	cmd := serveRunCmd(t, socketPath, true)
	require.NoError(t, cmd.Flags().Set("log-level", "info"))
	require.NoError(t, cmd.Flags().Set("log-file", logPath))
	require.NoError(t, cmd.Flags().Set("no-pairing", "true"))

	client, stop := startServe(t, cmd, socketPath)
	requireLockState(t, client, ipc.ActionUnlocked)
	stop()

	logged, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(logged), "starting headless autofill IPC server")
	assert.Contains(t, string(logged), "extension pairing verification DISABLED")
	assert.Contains(t, string(logged), "headless IPC server stopped")
}

// TestC704cExtensionServe_UnopenableLogFileRefuses proves a log file the
// daemon cannot open stops it before it listens.
func TestC704cExtensionServe_UnopenableLogFileRefuses(t *testing.T) {
	isolateServeHome(t)
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	cmd := serveRunCmd(t, socketPath, true)
	require.NoError(t, cmd.Flags().Set("log-file", filepath.Join(t.TempDir(), "missing", "serve.log")))

	err := cmd.Execute()
	require.ErrorIs(t, err, ErrServeLogFileOpenFailed)
	assert.NoFileExists(t, socketPath)
}

// TestC704cExtensionServe_UnusableDataDirRefuses proves the daemon refuses
// to start when its data directory cannot be created.
func TestC704cExtensionServe_UnusableDataDirRefuses(t *testing.T) {
	dataDir := isolateServeHome(t)
	c704cOccupy(t, dataDir)
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	err := serveRunCmd(t, socketPath, true).Execute()
	require.ErrorIs(t, err, ErrServeHomeResolveFailed)
	assert.NoFileExists(t, socketPath)
}

// TestC704cExtensionServe_UnusablePlainStoreRefuses proves a no-barrier
// daemon refuses to start when its password store cannot be opened.
func TestC704cExtensionServe_UnusablePlainStoreRefuses(t *testing.T) {
	dataDir := isolateServeHome(t)
	c704cOccupy(t, filepath.Join(dataDir, "staticpw"))
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	err := serveRunCmd(t, socketPath, true).Execute()
	require.ErrorIs(t, err, ErrServeStoreInitFailed)
	assert.NoFileExists(t, socketPath)
}

// TestC704cExtensionServe_FreshBarrierWithoutPasswordRefuses proves the
// first start of a barrier daemon refuses, rather than creating a barrier
// with an empty password, when no password source is given.
func TestC704cExtensionServe_FreshBarrierWithoutPasswordRefuses(t *testing.T) {
	isolateServeHome(t)
	t.Setenv(barrierPasswordSource.envVar, "")
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	err := serveRunCmd(t, socketPath, false).Execute()
	require.ErrorIs(t, err, ErrServeBarrierPasswordRequired)
	assert.NoFileExists(t, socketPath)
}

// TestC704cExtensionServe_UnreadablePasswordFileRefuses proves a
// --barrier-password-file that cannot be read is reported as a missing
// barrier password.
func TestC704cExtensionServe_UnreadablePasswordFileRefuses(t *testing.T) {
	isolateServeHome(t)
	t.Setenv(barrierPasswordSource.envVar, "")
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	cmd := serveRunCmd(t, socketPath, false)
	require.NoError(t, cmd.Flags().Set("barrier-password-file", filepath.Join(t.TempDir(), "absent")))

	err := cmd.Execute()
	require.ErrorIs(t, err, ErrServeBarrierPasswordRequired)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// TestC704cExtensionServe_PasswordFileUnlocksTheBarrier proves the first
// line of --barrier-password-file, trimmed, is the barrier password: a
// barrier created with it from the environment reopens from the file.
func TestC704cExtensionServe_PasswordFileUnlocksTheBarrier(t *testing.T) {
	isolateServeHome(t)
	t.Setenv(barrierPasswordSource.envVar, "file-barrier-password")
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")
	_, stop := startServe(t, serveRunCmd(t, socketPath, false), socketPath)
	stop()

	t.Setenv(barrierPasswordSource.envVar, "")
	pwFile := filepath.Join(t.TempDir(), "barrier.pw")
	require.NoError(t, os.WriteFile(pwFile, []byte("  file-barrier-password \nignored\n"), 0600))

	socketPath = filepath.Join(privateTempDir(t), "serve.sock")
	cmd := serveRunCmd(t, socketPath, false)
	require.NoError(t, cmd.Flags().Set("barrier-password-file", pwFile))
	client, _ := startServe(t, cmd, socketPath)
	requireLockState(t, client, ipc.ActionUnlocked)
}

// TestC704cExtensionServe_RefusesASocketAnotherDaemonOwns proves a second
// daemon never steals the socket of a live one.
func TestC704cExtensionServe_RefusesASocketAnotherDaemonOwns(t *testing.T) {
	isolateServeHome(t)
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")
	client, _ := startServe(t, serveRunCmd(t, socketPath, true), socketPath)

	err := serveRunCmd(t, socketPath, true).Execute()
	require.ErrorIs(t, err, ErrServeIPCStartFailed)
	require.ErrorIs(t, err, ipc.ErrSocketInUse)

	requireLockState(t, client, ipc.ActionUnlocked)
}

// TestC704cExtensionServe_UnusableFIDO2DirDegradesToNoAuth proves a FIDO2
// directory that cannot be created leaves the daemon serving, without CTAP2
// authentication, instead of refusing to start.
func TestC704cExtensionServe_UnusableFIDO2DirDegradesToNoAuth(t *testing.T) {
	dataDir := isolateServeHome(t)
	c704cOccupy(t, filepath.Join(dataDir, "fido2"))
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")
	logPath := filepath.Join(t.TempDir(), "serve.log")

	cmd := serveRunCmd(t, socketPath, true)
	require.NoError(t, cmd.Flags().Set("log-level", "warn"))
	require.NoError(t, cmd.Flags().Set("log-file", logPath))
	client, stop := startServe(t, cmd, socketPath)
	requireLockState(t, client, ipc.ActionUnlocked)
	stop()

	logged, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(logged), "failed to create FIDO2 directory")
}
