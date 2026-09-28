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

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dialPair returns both ends of a real Unix socket connection bound in a
// private temp directory.
func dialPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	sockPath := filepath.Join(privateDir(t), "peer.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	client, err = net.Dial("unix", sockPath)
	require.NoError(t, err)
	server, ok := <-accepted
	require.True(t, ok)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func TestPeerUID_ReportsListenerUID(t *testing.T) {
	client, _ := dialPair(t)

	uid, err := peerUID(client.(*net.UnixConn))
	require.NoError(t, err)
	assert.Equal(t, os.Geteuid(), uid)
}

func TestVerifyPeer_AcceptsTrustedPeer(t *testing.T) {
	client, _ := dialPair(t)
	assert.NoError(t, verifyPeer(client, trustedUIDs()))
}

func TestVerifyPeer_RefusesUntrustedPeer(t *testing.T) {
	// The listener runs as this uid; a trusted set without it is exactly
	// what a client sees when another user owns the listener.
	client, _ := dialPair(t)

	err := verifyPeer(client, foreignUIDs())
	require.ErrorIs(t, err, ErrPeerUntrusted)
	assert.ErrorContains(t, err, "peer uid")
}

func TestVerifyPeer_RefusesNonUnixConnection(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	assert.ErrorIs(t, verifyPeer(a, trustedUIDs()), ErrPeerCredentials)
}

// countingListener binds a raw listener and counts accepted connections, so a
// test can prove a refused client never reached it.
func countingListener(t *testing.T, sockPath string) *atomic.Int32 {
	t.Helper()
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return &accepted
}

func TestClient_RefusesWideSocketDirectoryBeforeSendingPIN(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))
	sockPath := filepath.Join(dir, "xkey.sock")
	accepted := countingListener(t, sockPath)

	client := NewClient(sockPath)
	resp, err := client.Unlock("123456")

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrSocketDirInsecure)
	assert.Zero(t, accepted.Load(), "the client must not connect through an insecure directory")
}

func TestClient_RefusesForeignOwnedSocketDirectory(t *testing.T) {
	sockPath := filepath.Join(privateDir(t), "xkey.sock")
	accepted := countingListener(t, sockPath)

	client := NewClient(sockPath)
	client.trusted = foreignUIDs()
	resp, err := client.Unlock("123456")

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrSocketDirInsecure)
	assert.Zero(t, accepted.Load())
}

func TestClient_RefusesSymlinkedSocketDirectory(t *testing.T) {
	target := privateDir(t)
	countingListener(t, filepath.Join(target, "xkey.sock"))
	link := filepath.Join(privateDir(t), "xkey")
	require.NoError(t, os.Symlink(target, link))

	_, err := NewClient(filepath.Join(link, "xkey.sock")).Touch()
	assert.ErrorIs(t, err, ErrSocketDirInsecure)
}

func TestClient_EmptyPathIsUnresolved(t *testing.T) {
	_, err := NewClient("").Status()
	assert.ErrorIs(t, err, ErrSocketPathUnresolved)
}

func TestDial_ReturnsVerifiedConnection(t *testing.T) {
	sockPath := filepath.Join(privateDir(t), "xkey.sock")
	accepted := countingListener(t, sockPath)

	conn, err := Dial(sockPath, DefaultTimeout)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	assert.Eventually(t, func() bool { return accepted.Load() == 1 }, DefaultTimeout, 10*time.Millisecond)
}

func TestDial_RefusesInsecureDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))
	sockPath := filepath.Join(dir, "xkey.sock")
	accepted := countingListener(t, sockPath)

	conn, err := Dial(sockPath, DefaultTimeout)
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, ErrSocketDirInsecure)
	assert.Zero(t, accepted.Load())
}

func TestDial_AbsentSocketIsDaemonNotRunning(t *testing.T) {
	conn, err := Dial(filepath.Join(privateDir(t), "absent.sock"), DefaultTimeout)
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, ErrDaemonNotRunning)
}
