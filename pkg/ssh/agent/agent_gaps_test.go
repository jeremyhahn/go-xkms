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

package agent

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// TestAgent_Signers verifies the raw signer list is returned.
func TestAgent_Signers(t *testing.T) {
	s1 := newEd25519Signer(t)
	s2 := newRSASigner(t)
	a := New(s1, s2)

	signers, err := a.Signers()
	require.NoError(t, err)
	require.Len(t, signers, 2)
}

// TestAgent_ListLabels exercises the itoa comment labelling across many signers,
// including the multi-digit index path.
func TestAgent_ListLabels(t *testing.T) {
	var ss []ssh.Signer
	for i := 0; i < 12; i++ {
		ss = append(ss, newEd25519Signer(t))
	}
	a := New(ss...)
	keys, err := a.List()
	require.NoError(t, err)
	require.Len(t, keys, 12)
	assert.True(t, strings.HasPrefix(keys[11].Comment, "xkey-"))
	assert.Equal(t, "xkey-11", keys[11].Comment)
}

// TestAgent_ServeListenError exercises the Serve() error path: a socket whose
// parent path is a regular file makes directory creation / listen fail.
func TestAgent_ServeListenError(t *testing.T) {
	tmp := privateDir(t)
	fileAsParent := filepath.Join(tmp, "notadir")
	require.NoError(t, os.WriteFile(fileAsParent, []byte("x"), 0o600))

	// The parent segment "notadir" is a regular file, so creating the socket
	// directory (or binding the socket) under it must fail.
	sock := filepath.Join(fileAsParent, "agent.sock")
	err := Serve(context.Background(), sock, New(newEd25519Signer(t)))
	require.Error(t, err)
}

// TestAgent_ServeRoundTrip exercises the happy path: a real SSH agent client
// connects over the unix socket, lists the served keys, and the server shuts
// down gracefully when the context is cancelled (returning nil).
func TestAgent_ServeRoundTrip(t *testing.T) {
	sock := SocketPath(privateDir(t))
	ctx, cancel := context.WithCancel(context.Background())

	srvErr := make(chan error, 1)
	go func() { srvErr <- Serve(ctx, sock, New(newEd25519Signer(t), newRSASigner(t))) }()

	// Wait for the listener to come up.
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("unix", sock)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("agent socket never became available: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	client := sshagent.NewClient(conn)
	keys, err := client.List()
	require.NoError(t, err)
	require.Len(t, keys, 2, "both served signers should be advertised")
	require.NoError(t, conn.Close())

	// Cancel triggers the ctx.Done goroutine to close the listener; Serve must
	// return nil on graceful shutdown.
	cancel()
	select {
	case err := <-srvErr:
		require.NoError(t, err, "graceful shutdown should return nil")
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

// TestAgent_ServeReturnsHandlerProtocolError verifies that a genuine
// per-connection protocol error is joined into Serve's returned error rather
// than being silently discarded (#701): the tracker records it, and Serve
// joins tracker.err() with its own listener-level result before returning.
func TestAgent_ServeReturnsHandlerProtocolError(t *testing.T) {
	sock := SocketPath(privateDir(t))
	ctx, cancel := context.WithCancel(context.Background())

	srvErr := make(chan error, 1)
	go func() { srvErr <- Serve(ctx, sock, New(newEd25519Signer(t))) }()

	var conn *net.UnixConn
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("unix", sock)
		if err == nil {
			var ok bool
			conn, ok = c.(*net.UnixConn)
			require.True(t, ok, "unix socket connection expected")
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("agent socket never became available: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A length-prefixed frame claiming 10 bytes, only 1 of which follows
	// before the write half closes: the server's io.ReadFull of the body
	// reports io.ErrUnexpectedEOF, a real error rather than an ordinary
	// disconnect.
	_, err := conn.Write([]byte{0, 0, 0, 10, 0xff})
	require.NoError(t, err)

	// Half-close the write side instead of fully closing: it still delivers
	// the EOF that turns the truncated body into io.ErrUnexpectedEOF, but
	// leaves the read side open so this goroutine can observe the *server*
	// closing its end. serveListener's handler records its error
	// (t.recordErr) before its own deferred Close runs, so an EOF read here
	// is proof the error has already been recorded -- deterministic, with no
	// head-start connection, no sleep, and no tracker accessor required.
	require.NoError(t, conn.CloseWrite())
	n, rerr := conn.Read(make([]byte, 1))
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, rerr, io.EOF, "server must close its end only after recording the handler error")
	require.NoError(t, conn.Close())

	cancel()
	select {
	case err := <-srvErr:
		require.Error(t, err, "a genuine protocol error on a served connection must not vanish")
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

// TestBytesEqual covers the length-mismatch and content-mismatch branches.
func TestBytesEqual(t *testing.T) {
	assert.True(t, bytesEqual([]byte("abc"), []byte("abc")))
	assert.False(t, bytesEqual([]byte("abc"), []byte("ab")), "length mismatch")
	assert.False(t, bytesEqual([]byte("abc"), []byte("abd")), "content mismatch")
	assert.True(t, bytesEqual(nil, nil))
}
