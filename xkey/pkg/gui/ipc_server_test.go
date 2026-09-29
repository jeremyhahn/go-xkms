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
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
