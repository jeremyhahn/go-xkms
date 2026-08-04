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
	"errors"
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

// TestItoa covers the int→string helper across single-digit, multi-digit, and
// zero.
func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 5: "5", 9: "9", 10: "10", 11: "11", 123: "123"}
	for in, want := range cases {
		assert.Equalf(t, want, itoa(in), "itoa(%d)", in)
	}
}

// TestAgent_ReadOnlyExtras covers the remaining read-only rejections (Remove,
// Unlock) and the unsupported Extension.
func TestAgent_ReadOnlyExtras(t *testing.T) {
	a := New(newEd25519Signer(t))

	require.ErrorIs(t, a.Remove(nil), ErrUnsupported)
	require.ErrorIs(t, a.Unlock(nil), ErrUnsupported)

	_, err := a.Extension("some@ext", nil)
	require.Error(t, err, "Extension must be unsupported")
}

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

// TestAgent_SignWithFlags512 exercises the RSA-SHA-512 flag branch.
func TestAgent_SignWithFlags512(t *testing.T) {
	rsa := newRSASigner(t)
	a := New(rsa)
	sig, err := a.SignWithFlags(rsa.PublicKey(), []byte("payload"), sshagent.SignatureFlagRsaSha512)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.Contains(t, sig.Format, "512")
}

// TestAgent_ServeListenError exercises the Serve() error path: a socket whose
// parent path is a regular file makes directory creation / listen fail.
func TestAgent_ServeListenError(t *testing.T) {
	tmp := t.TempDir()
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
	sock := filepath.Join(t.TempDir(), "agent.sock")
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

// TestBytesEqual covers the length-mismatch and content-mismatch branches.
func TestBytesEqual(t *testing.T) {
	assert.True(t, bytesEqual([]byte("abc"), []byte("abc")))
	assert.False(t, bytesEqual([]byte("abc"), []byte("ab")), "length mismatch")
	assert.False(t, bytesEqual([]byte("abc"), []byte("abd")), "content mismatch")
	assert.True(t, bytesEqual(nil, nil))
}

// TestErrorTypes covers Error() and Unwrap() on the wrapped error types.
func TestErrorTypes(t *testing.T) {
	inner := errors.New("boom")

	unknown := &UnknownKeyError{Format: "ssh-ed25519"}
	assert.Contains(t, unknown.Error(), "ssh-ed25519")

	le := &ListenError{Err: inner}
	assert.Contains(t, le.Error(), "listen")
	assert.ErrorIs(t, le, inner)

	ae := &AcceptError{Err: inner}
	assert.Contains(t, ae.Error(), "accept")
	assert.ErrorIs(t, ae, inner)
}
