// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package session_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/session"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ---------------------------------------------------------------------------
// Error type string/unwrap coverage
// ---------------------------------------------------------------------------

func TestNilInputError_Error(t *testing.T) {
	e := &session.NilInputError{Field: "Host"}
	want := "ssh/session: nil input: Host"
	if e.Error() != want {
		t.Fatalf("NilInputError.Error() = %q, want %q", e.Error(), want)
	}
}

func TestDialError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("connection refused")
	e := &session.DialError{Host: "example.com", Err: inner}
	if e.Error() == "" {
		t.Fatal("DialError.Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("DialError.Unwrap() should expose inner error")
	}
}

func TestHandshakeError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("bad handshake")
	e := &session.HandshakeError{Host: "h", User: "u", Err: inner}
	if e.Error() == "" {
		t.Fatal("HandshakeError.Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("HandshakeError.Unwrap() should expose inner error")
	}
}

func TestTimeoutError_ErrorAndUnwrap(t *testing.T) {
	inner := context.DeadlineExceeded
	e := &session.TimeoutError{Host: "h", Duration: 5 * time.Second, Err: inner}
	if e.Error() == "" {
		t.Fatal("TimeoutError.Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("TimeoutError.Unwrap() should expose inner error")
	}
}

func TestCommandError_WithStderr_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("exit status 1")
	e := &session.CommandError{Command: "ls", ExitCode: 1, Stderr: "permission denied", Err: inner}
	if e.Error() == "" {
		t.Fatal("CommandError.Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("CommandError.Unwrap() should expose inner error")
	}
}

func TestCommandError_WithoutStderr_Error(t *testing.T) {
	inner := errors.New("exit status 1")
	e := &session.CommandError{Command: "ls", ExitCode: 1, Stderr: "", Err: inner}
	if e.Error() == "" {
		t.Fatal("CommandError.Error() returned empty string")
	}
}

func TestSessionError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("channel open failed")
	e := &session.SessionError{Host: "h", Err: inner}
	if e.Error() == "" {
		t.Fatal("SessionError.Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("SessionError.Unwrap() should expose inner error")
	}
}

func TestClosedError_Error(t *testing.T) {
	e := &session.ClosedError{}
	want := "ssh/session: session is closed"
	if e.Error() != want {
		t.Fatalf("ClosedError.Error() = %q, want %q", e.Error(), want)
	}
}

// ---------------------------------------------------------------------------
// Run: non-zero exit code surfaces CommandError with ExitCode
// ---------------------------------------------------------------------------

func TestRun_NonZeroExitCode(t *testing.T) {
	hostSigner := generateHostSigner(t)
	failHandler := func(ch ssh.Channel, req *ssh.Request) {
		payload := req.Payload
		if len(payload) < 4 {
			req.Reply(false, nil)
			return
		}
		req.Reply(true, nil)
		ch.Stderr().Write([]byte("command not found")) //nolint:errcheck
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{2}))
	}
	srv := newTestServer(t, hostSigner, failHandler)
	defer srv.close()

	store, sc := pinHost(t, srv.host(), hostSigner, "alice")
	clientKey := generateClientKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := session.Dial(ctx, session.DialRequest{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    sc,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         3 * time.Second,
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return
	}
	defer sess.Close()

	_, _, runErr := sess.Run(ctx, "fail")
	var ce *session.CommandError
	if !errors.As(runErr, &ce) {
		t.Fatalf("expected CommandError for non-zero exit, got %T: %v", runErr, runErr)
	}
	if ce.ExitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", ce.ExitCode)
	}
}

// ---------------------------------------------------------------------------
// Run: context cancellation mid-execution surfaces TimeoutError
// ---------------------------------------------------------------------------

func TestRun_ContextCancellation(t *testing.T) {
	hostSigner := generateHostSigner(t)
	// Server handler that blocks indefinitely — it accepts the exec and then
	// waits on a done channel (the channel is held open until the client
	// cancels). When the client cancels, session.Run closes the ssh.Session,
	// which closes the underlying channel. The server-side handler unblocks
	// when done is closed at test teardown.
	done := make(chan struct{})
	blockHandler := func(ch ssh.Channel, req *ssh.Request) {
		req.Reply(true, nil)
		// Block until done is closed (test teardown) — never send exit-status.
		<-done
	}
	srv := newTestServer(t, hostSigner, blockHandler)
	defer func() {
		close(done)
		srv.close()
	}()

	store, sc := pinHost(t, srv.host(), hostSigner, "alice")
	clientKey := generateClientKey(t)

	connCtx, connCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connCancel()
	sess, err := session.Dial(connCtx, session.DialRequest{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    sc,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         3 * time.Second,
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return
	}
	defer sess.Close()

	// Cancel the context after a short delay — the server will still be
	// blocking, so the session.Run goroutine must close the SSH session
	// when ctx fires, causing Run to return with a TimeoutError.
	runCtx, runCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer runCancel()

	_, _, runErr := sess.Run(runCtx, "block")
	if runErr == nil {
		t.Fatal("expected error from cancelled run")
	}
	var te *session.TimeoutError
	if !errors.As(runErr, &te) {
		t.Fatalf("expected TimeoutError on context cancellation, got %T: %v", runErr, runErr)
	}

	// Cancellation races two Close calls against the same ssh.Session: the
	// watcher's abort Close (which genuinely tears the channel down) and
	// Run's own deferred cleanup Close. The second reports io.EOF per
	// x/crypto/ssh's documented "already closed" shape, and must be
	// filtered rather than joined in as extra noise (#701) -- so the
	// returned error must carry exactly the one TimeoutError, not a
	// two-element join.
	if joined, ok := runErr.(interface{ Unwrap() []error }); ok {
		if got := len(joined.Unwrap()); got != 1 {
			t.Fatalf("expected exactly 1 joined error (the redundant Close's io.EOF must be filtered), got %d: %v", got, runErr)
		}
	}
}

// ---------------------------------------------------------------------------
// Dial: destroyed key (Material=nil) surfaces NilInputError
// ---------------------------------------------------------------------------

func TestDial_DestroyedKey_MaterialNil(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	store, sc := pinHost(t, srv.host(), hostSigner, "alice")
	clientKey := generateClientKey(t)

	// Destroy the key so Material becomes nil.
	clientKey.Destroy()

	_, err := session.Dial(context.Background(), session.DialRequest{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    sc,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
	})
	if err == nil {
		t.Fatal("expected error for destroyed (nil Material) key")
	}
	var nie *session.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil Key.Material, got %T: %v", err, err)
	}
	if nie.Field != "Key.Material" {
		t.Fatalf("expected Field=Key.Material, got %q", nie.Field)
	}
}

// ---------------------------------------------------------------------------
// Dial: port 0 defaults to 22 — validation passes, TCP fails
// ---------------------------------------------------------------------------

func TestDial_ZeroPortDefaultsTo22_ThenFails(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	// Add any pin so validation passes.
	stub := generateHostSigner(t)
	if err := store.Add(context.Background(), &known_hosts.Pin{
		Host:        "127.0.0.1",
		Fingerprint: keys.Fingerprint(stub.PublicKey()),
		Algorithm:   stub.PublicKey().Type(),
		PublicKey:   stub.PublicKey().Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("add pin: %v", err)
	}

	clientKey := generateClientKey(t)
	defer clientKey.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, dialErr := session.Dial(ctx, session.DialRequest{
		Host:            "127.0.0.1",
		Port:            0, // should default to 22 internally
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         100 * time.Millisecond,
	})
	if dialErr == nil {
		t.Fatal("expected error (no SSH server on port 22)")
	}
	// Must NOT be a NilInputError — validation passed.
	var nie *session.NilInputError
	if errors.As(dialErr, &nie) {
		t.Fatalf("unexpected NilInputError (field=%s): port=0 should be accepted", nie.Field)
	}
}

// ---------------------------------------------------------------------------
// Dial: connection accepts but never finishes SSH handshake → HandshakeError/DialError
// ---------------------------------------------------------------------------

func TestDial_AcceptsButNoHandshake(t *testing.T) {
	// A listener that accepts but never speaks SSH.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		// Hold the conn open briefly, then close without writing.
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()

	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	stub := generateHostSigner(t)
	if err := store.Add(context.Background(), &known_hosts.Pin{
		Host:        "127.0.0.1",
		Fingerprint: keys.Fingerprint(stub.PublicKey()),
		Algorithm:   stub.PublicKey().Type(),
		PublicKey:   stub.PublicKey().Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("add pin: %v", err)
	}

	clientKey := generateClientKey(t)
	defer clientKey.Destroy()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, dialErr := session.Dial(ctx, session.DialRequest{
		Host:            "127.0.0.1",
		Port:            port,
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         500 * time.Millisecond,
	})
	if dialErr == nil {
		t.Fatal("expected Dial to fail when server closes without handshake")
	}
	var hs *session.HandshakeError
	var de *session.DialError
	if !errors.As(dialErr, &hs) && !errors.As(dialErr, &de) {
		t.Fatalf("expected HandshakeError or DialError, got %T: %v", dialErr, dialErr)
	}
}

// ---------------------------------------------------------------------------
// Shell: closed session returns ClosedError
// ---------------------------------------------------------------------------

func TestShell_AfterClose_ReturnsClosedError(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	store, sc := pinHost(t, srv.host(), hostSigner, "alice")
	clientKey := generateClientKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := session.Dial(ctx, session.DialRequest{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    sc,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         3 * time.Second,
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	shellErr := sess.Shell(ctx)
	var ce *session.ClosedError
	if !errors.As(shellErr, &ce) {
		t.Fatalf("expected ClosedError from Shell after Close, got %T: %v", shellErr, shellErr)
	}
}

// shellServer accepts one connection on ln, handles pty-req + shell, and
// immediately exits 0.
func shellServer(ln net.Listener, hostSigner ssh.Signer) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(hostSigner)
	sshConn, chans, reqs, hsErr := ssh.NewServerConn(conn, cfg)
	if hsErr != nil {
		conn.Close()
		return hsErr
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chanReqs, aerr := nc.Accept()
		if aerr != nil {
			continue
		}
		go func(ch ssh.Channel, rs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range rs {
				switch req.Type {
				case "pty-req":
					req.Reply(true, nil)
				case "shell":
					req.Reply(true, nil)
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})) //nolint:errcheck
					return
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(ch, chanReqs)
	}
	return nil
}

// TestShell_HappyPath drives an in-process server that accepts pty-req +
// shell and immediately exits with status 0.
func TestShell_HappyPath(t *testing.T) {
	hostSigner := generateHostSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- shellServer(ln, hostSigner) }()
	defer func() {
		ln.Close()
		<-serverDone
	}()

	backend, berr := storage.NewMemoryBackend()
	if berr != nil {
		t.Fatalf("backend: %v", berr)
	}
	store, serr := known_hosts.NewBackendStore(backend)
	if serr != nil {
		t.Fatalf("store: %v", serr)
	}
	if err := store.Add(context.Background(), &known_hosts.Pin{
		Host:        "127.0.0.1",
		Fingerprint: keys.Fingerprint(hostSigner.PublicKey()),
		Algorithm:   hostSigner.PublicKey().Type(),
		PublicKey:   hostSigner.PublicKey().Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("add pin: %v", err)
	}

	clientKey := generateClientKey(t)
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := session.Dial(ctx, session.DialRequest{
		Host:            "127.0.0.1",
		Port:            port,
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         3 * time.Second,
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return
	}
	defer sess.Close()

	shellCtx, shellCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shellCancel()
	if err := sess.Shell(shellCtx); err != nil {
		t.Fatalf("Shell: %v", err)
	}
}

// TestShell_ContextCancellation cancels the shell context and expects a TimeoutError.
func TestShell_ContextCancellation(t *testing.T) {
	hostSigner := generateHostSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	shutdown := make(chan struct{})
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		cfg := &ssh.ServerConfig{
			PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
				return nil, nil
			},
		}
		cfg.AddHostKey(hostSigner)
		sshConn, chans, reqs, hsErr := ssh.NewServerConn(conn, cfg)
		if hsErr != nil {
			conn.Close()
			return
		}
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			if nc.ChannelType() != "session" {
				nc.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			ch, chanReqs, aerr2 := nc.Accept()
			if aerr2 != nil {
				continue
			}
			go func(ch ssh.Channel, rs <-chan *ssh.Request) {
				defer ch.Close()
				for req := range rs {
					switch req.Type {
					case "pty-req":
						req.Reply(true, nil)
					case "shell":
						req.Reply(true, nil)
						<-shutdown
						return
					default:
						if req.WantReply {
							req.Reply(false, nil)
						}
					}
				}
			}(ch, chanReqs)
		}
	}()
	defer func() {
		close(shutdown)
		ln.Close()
	}()

	backend, berr := storage.NewMemoryBackend()
	if berr != nil {
		t.Fatalf("backend: %v", berr)
	}
	store, serr := known_hosts.NewBackendStore(backend)
	if serr != nil {
		t.Fatalf("store: %v", serr)
	}
	if err := store.Add(context.Background(), &known_hosts.Pin{
		Host:        "127.0.0.1",
		Fingerprint: keys.Fingerprint(hostSigner.PublicKey()),
		Algorithm:   hostSigner.PublicKey().Type(),
		PublicKey:   hostSigner.PublicKey().Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("add pin: %v", err)
	}

	clientKey := generateClientKey(t)
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	connCtx, connCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connCancel()
	sess, err := session.Dial(connCtx, session.DialRequest{
		Host:            "127.0.0.1",
		Port:            port,
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         3 * time.Second,
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return
	}
	defer sess.Close()

	shellCtx, shellCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shellCancel()
	shellErr := sess.Shell(shellCtx)
	if shellErr == nil {
		t.Fatal("expected error from cancelled shell")
	}
	var te *session.TimeoutError
	if !errors.As(shellErr, &te) {
		t.Fatalf("expected TimeoutError, got %T: %v", shellErr, shellErr)
	}
}
