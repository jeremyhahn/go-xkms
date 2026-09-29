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
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
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
	client, server := dialPair(t)

	uid, err := verifyPeer(client, trustedUIDs())
	require.NoError(t, err)
	assert.Equal(t, os.Geteuid(), uid)

	// The server end sees the client the same way.
	uid, err = verifyPeer(server, trustedUIDs())
	require.NoError(t, err)
	assert.Equal(t, os.Geteuid(), uid)
}

func TestVerifyPeer_RefusesUntrustedPeer(t *testing.T) {
	// The listener runs as this uid; a trusted set without it is exactly
	// what a client sees when another user owns the listener.
	client, _ := dialPair(t)

	uid, err := verifyPeer(client, foreignUIDs())
	require.ErrorIs(t, err, ErrPeerUntrusted)
	assert.ErrorContains(t, err, "peer uid")
	assert.Equal(t, os.Geteuid(), uid, "a refused peer's uid is reported so it can be logged")
}

func TestVerifyPeer_RefusesNonUnixConnection(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	_, err := verifyPeer(a, trustedUIDs())
	assert.ErrorIs(t, err, ErrPeerCredentials)
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

// logRecord is one captured slog record, flattened for assertions.
type logRecord struct {
	level slog.Level
	msg   string
	attrs map[string]slog.Value
}

// recordingHandler is a slog.Handler that hands every record to a channel, so
// a test can wait for a log line written by a server goroutine.
type recordingHandler struct {
	records chan logRecord
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{level: r.Level, msg: r.Message, attrs: map[string]slog.Value{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value
		return true
	})
	h.records <- rec
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// servePeerTest starts a server in a private directory that trusts trusted
// and returns its socket path, the log records it writes, and the handler it
// dispatches to.
func servePeerTest(t *testing.T, trusted []int) (string, <-chan logRecord, *mockHandler) {
	t.Helper()
	sockPath := filepath.Join(privateDir(t), "xkey.sock")
	logs := &recordingHandler{records: make(chan logRecord, 16)}
	handler := &mockHandler{statusResp: OKResponse(ActionDaemonReady)}

	srv, err := NewServer(sockPath, handler, slog.New(logs))
	require.NoError(t, err)
	srv.trusted = trusted

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		assert.ErrorIs(t, <-served, ErrServerClosed)
	})
	return sockPath, logs.records, handler
}

func TestServer_ServesTrustedPeer(t *testing.T) {
	sockPath, _, _ := servePeerTest(t, trustedUIDs())

	resp, err := NewClient(sockPath).Status()
	require.NoError(t, err)
	assert.Equal(t, StatusOK, resp.Status)
	assert.Equal(t, ActionDaemonReady, resp.Action)
}

func TestServer_DropsUntrustedPeerAndLogsUID(t *testing.T) {
	// The test process is both ends; a server trusted set without its uid
	// is exactly what the server sees when another local user connects.
	sockPath, records, _ := servePeerTest(t, foreignUIDs())

	// NewClient verifies the listener (this uid, trusted by the client) and
	// sends the request; the server must close without answering.
	resp, err := NewClient(sockPath).Status()
	assert.Nil(t, resp)
	require.Error(t, err)

	select {
	case rec := <-records:
		assert.Equal(t, slog.LevelWarn, rec.level)
		assert.Contains(t, rec.msg, "untrusted peer")
		require.Contains(t, rec.attrs, "peer_uid")
		assert.Equal(t, int64(os.Geteuid()), rec.attrs["peer_uid"].Int64())
		errAttr, ok := rec.attrs["error"].Any().(error)
		require.True(t, ok)
		assert.ErrorIs(t, errAttr, ErrPeerUntrusted)
	case <-time.After(DefaultTimeout):
		t.Fatal("the server did not log the dropped peer")
	}
}

func TestServer_DroppedPeerNeverReachesHandler(t *testing.T) {
	sockPath, records, handler := servePeerTest(t, foreignUIDs())

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// admitPeer runs immediately after Accept, so the server may close the
	// connection before the client finishes writing its request. A write
	// failure from that race (broken pipe or reset) is an acceptable
	// outcome, not a bug: the invariant under test is that the request
	// never reaches the handler, not that the write itself succeeds.
	if writeErr := json.NewEncoder(conn).Encode(Message{Type: MessageTypeTypePassword, Name: "github"}); writeErr != nil {
		assert.True(t, errors.Is(writeErr, syscall.EPIPE) || errors.Is(writeErr, syscall.ECONNRESET),
			"want broken pipe or reset from a dropped peer, got %v", writeErr)
	} else {
		// The write beat the close. The server still closes the connection
		// without writing a response. The close arrives as EOF, or as a
		// reset because the request was never read; either way nothing
		// comes back.
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(DefaultTimeout)))
		n, readErr := conn.Read(make([]byte, 1))
		assert.Zero(t, n)
		assert.True(t, errors.Is(readErr, io.EOF) || errors.Is(readErr, syscall.ECONNRESET), "want EOF or reset, got %v", readErr)
	}

	<-records
	assert.Empty(t, handler.getLastName(), "a dropped peer's request must not be dispatched")
}

func TestServer_AdmitPeerRefusesUnverifiablePeer(t *testing.T) {
	// Where peer credentials cannot be read the server fails closed, as the
	// client does: a non-unix connection stands in for such a platform.
	logs := &recordingHandler{records: make(chan logRecord, 1)}
	srv := &Server{logger: slog.New(logs), trusted: trustedUIDs()}
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	assert.False(t, srv.admitPeer(a))
	rec := <-logs.records
	assert.Equal(t, slog.LevelWarn, rec.level)
	assert.NotContains(t, rec.attrs, "peer_uid", "no uid is known, so none is logged")
	errAttr, ok := rec.attrs["error"].Any().(error)
	require.True(t, ok)
	assert.ErrorIs(t, errAttr, ErrPeerCredentials)
}
