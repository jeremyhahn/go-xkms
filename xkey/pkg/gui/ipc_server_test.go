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

package gui

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// newIPCTestApp returns an App with just the fields startIPCServer uses.
func newIPCTestApp(t *testing.T) *App {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &App{
		ctx:            ctx,
		log:            stateTestLogger(),
		pairingService: services.NewPairingService(stateTestLogger()),
	}
}

// liveListener binds a listener at sockPath that accepts and drops
// connections, standing in for another process holding the socket.
func liveListener(t *testing.T, sockPath string) {
	t.Helper()
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
}

func TestStartIPCServer_TakesOverOwnLiveSocket(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	sockPath := filepath.Join(dir, "xkey.sock")
	t.Setenv(ipc.EnvSocketPath, sockPath)
	liveListener(t, sockPath)

	app := newIPCTestApp(t)
	app.startIPCServer()

	require.NotNil(t, app.ipcServer, "a socket this user owns in a private directory is taken over")
	t.Cleanup(func() {
		if err := app.ipcServer.Close(); err != nil && !errors.Is(err, ipc.ErrServerClosed) {
			t.Errorf("close: %v", err)
		}
	})
	assert.Equal(t, sockPath, app.ipcServer.SocketPath())
}

func TestStartIPCServer_RefusesInsecureDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))
	sockPath := filepath.Join(dir, "xkey.sock")
	t.Setenv(ipc.EnvSocketPath, sockPath)
	liveListener(t, sockPath)

	app := newIPCTestApp(t)
	app.startIPCServer()

	assert.Nil(t, app.ipcServer, "no server may start in a directory other users can enter")
	_, err := os.Lstat(sockPath)
	assert.NoError(t, err, "the existing socket must not be unlinked")
}

// setLocalAppAccess saves the setting through the same path the Settings
// view uses.
func setLocalAppAccess(t *testing.T, app *App, enabled bool) {
	t.Helper()
	data := *app.appService.GetConfig()
	data.LocalAppAccessEnabled = enabled
	require.NoError(t, app.appService.UpdateConfig(&data))
}

// unlockApp stands in for the user unlocking xKey after startup, which
// leaves the app locked.
func unlockApp(t *testing.T, app *App) {
	t.Helper()
	require.True(t, app.appLockService.IsLocked(), "precondition: startup leaves the app locked")
	app.appLockService.AutoUnlock()
}

func TestLocalAppAccess_OffNeverOpensSocket(t *testing.T) {
	app, sockPath := startReturningUserApp(t, false)
	assertNoSocket(t, sockPath)

	unlockApp(t, app)
	assertNoSocket(t, sockPath)

	setLocalAppAccess(t, app, false)
	assertNoSocket(t, sockPath)
}

func TestLocalAppAccess_SocketFollowsAppLock(t *testing.T) {
	app, sockPath := startReturningUserApp(t, true)
	assertNoSocket(t, sockPath)

	unlockApp(t, app)
	assertSocket(t, sockPath)

	app.appLockService.Lock()
	assertNoSocket(t, sockPath)

	app.appLockService.AutoUnlock()
	assertSocket(t, sockPath)
}

func TestLocalAppAccess_SocketFollowsBarrierSeal(t *testing.T) {
	app, sockPath := startReturningUserApp(t, true)
	unlockApp(t, app)

	require.NoError(t, app.barrierService.Initialize("lifecycle-test-password", "passphrase"))
	assertSocket(t, sockPath)

	require.NoError(t, app.barrierService.Seal())
	assertNoSocket(t, sockPath)

	require.NoError(t, app.barrierService.Unseal("lifecycle-test-password", ""))
	assertSocket(t, sockPath)
}

func TestLocalAppAccess_SocketFollowsSetting(t *testing.T) {
	app, sockPath := startReturningUserApp(t, false)
	unlockApp(t, app)

	setLocalAppAccess(t, app, true)
	assertSocket(t, sockPath)

	setLocalAppAccess(t, app, false)
	assertNoSocket(t, sockPath)
}

func TestLocalAppAccess_ShutdownClosesSocketForGood(t *testing.T) {
	app, sockPath := startReturningUserApp(t, true)
	unlockApp(t, app)
	assertSocket(t, sockPath)

	app.shutdown(app.ctx)
	assertNoSocket(t, sockPath)

	app.syncIPCServer()
	assertNoSocket(t, sockPath)
}

// extensionOffPolicy returns a verified enterprise policy section that turns
// the browser extension, and with it local app access, off. The Require*
// preconditions are relaxed so the test host satisfies them.
func extensionOffPolicy() *config.PolicySection {
	pol := config.DefaultPolicy()
	pol.RequireSOPIN = false
	pol.RequireUserPIN = false
	pol.RequireEncryptedStorage = false
	pol.ExtensionEnabled = false
	return pol
}

func TestLocalAppAccess_VerifiedPolicyClosesSocket(t *testing.T) {
	app, sockPath := startReturningUserApp(t, true)
	unlockApp(t, app)
	assertSocket(t, sockPath)

	require.NoError(t, app.applyVerifiedEnterprisePolicy(extensionOffPolicy()))
	assertNoSocket(t, sockPath)

	// A later lock or seal hook re-evaluates from the effective setting.
	app.syncIPCServer()
	assertNoSocket(t, sockPath)
}

func TestLocalAppAccess_SettingRefusedByPolicyKeepsSocketClosed(t *testing.T) {
	app, sockPath := startReturningUserApp(t, false)
	unlockApp(t, app)
	require.NoError(t, app.applyVerifiedEnterprisePolicy(extensionOffPolicy()))

	// The save succeeds, but the policy refuses the setting it asks for.
	setLocalAppAccess(t, app, true)
	assertNoSocket(t, sockPath)
	assert.False(t, app.autofillService.IsEnabled())
}

// blockingStatusHandler holds every status request until release is closed,
// so a test can shut down while an IPC handler is still in flight.
type blockingStatusHandler struct {
	*guiIPCHandler
	entered chan struct{}
	release chan struct{}
}

func (h *blockingStatusHandler) HandleStatus() (*ipc.Response, error) {
	close(h.entered)
	<-h.release
	return ipc.OKResponse(ipc.ActionUnlocked), nil
}

// TestCloseIPCServer_WaitsForHandlerOfStoppedServer covers shutdown's
// ordering hazard: a seal or lock hook has already stopped the server (and
// cleared ipcServer) while a handler is still running, and closeIPCServer must
// still wait for that handler before shutdown closes what it uses.
func TestCloseIPCServer_WaitsForHandlerOfStoppedServer(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	sockPath := filepath.Join(dir, "xkey.sock")

	app := newIPCTestApp(t)
	handler := &blockingStatusHandler{
		guiIPCHandler: &guiIPCHandler{app: app},
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	srv, err := ipc.NewServer(sockPath, handler, app.log)
	require.NoError(t, err)
	serveCtx, cancel := context.WithCancel(app.ctx)
	app.ipcServer, app.ipcCancel = srv, cancel
	served := make(chan error, 1)
	go func() { served <- srv.Serve(serveCtx) }()

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	require.NoError(t, json.NewEncoder(conn).Encode(ipc.Message{Type: ipc.MessageTypeStatus}))
	<-handler.entered

	// The seal hook stops the server: nothing wants it any more.
	app.syncIPCServer()
	require.Nil(t, app.ipcServer)

	closed := make(chan struct{})
	go func() {
		app.closeIPCServer()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("closeIPCServer returned while a handler was still in flight")
	case <-time.After(100 * time.Millisecond):
	}

	close(handler.release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("closeIPCServer did not return once the handler finished")
	}
	assert.ErrorIs(t, <-served, ipc.ErrServerClosed)
}

// TestShutdown_WaitsForSlowHandlerBeforeSealing covers a handler that runs
// longer than any shutdown step timeout and ignores cancellation, as hardware
// key generation can: shutdown must not seal the barrier or finish tearing
// down until that handler returns.
func TestShutdown_WaitsForSlowHandlerBeforeSealing(t *testing.T) {
	app, sockPath := startReturningUserApp(t, true)
	unlockApp(t, app)
	require.NoError(t, app.barrierService.Initialize("lifecycle-test-password", "passphrase"))
	assertSocket(t, sockPath)

	// Swap the running server for one whose status handler ignores its
	// context and returns only when released.
	handler := &blockingStatusHandler{
		guiIPCHandler: &guiIPCHandler{app: app},
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	app.ipcMu.Lock()
	app.stopIPCServer()
	srv, err := ipc.NewServer(sockPath, handler, app.log)
	require.NoError(t, err)
	serveCtx, cancel := context.WithCancel(app.ctx)
	app.ipcServer, app.ipcCancel = srv, cancel
	app.ipcMu.Unlock()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(serveCtx) }()

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	require.NoError(t, json.NewEncoder(conn).Encode(ipc.Message{Type: ipc.MessageTypeStatus}))
	<-handler.entered

	go app.shutdown(app.ctx)
	select {
	case <-app.shutdownDone:
		t.Fatal("shutdown finished while a handler was still in flight")
	case <-time.After(1500 * time.Millisecond):
	}
	assert.False(t, app.barrierService.IsSealed(), "the barrier must stay unsealed under a running handler")

	close(handler.release)
	select {
	case <-app.shutdownDone:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not finish once the handler returned")
	}
	assert.True(t, app.barrierService.IsSealed())
	assert.ErrorIs(t, <-served, ipc.ErrServerClosed)
}
