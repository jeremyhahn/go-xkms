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

package console

import (
	"context"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// sessionServerOptions selects which SSH session requests the test server
// grants, so the console's session-setup failure paths can be driven against a
// real SSH server rather than a hand-rolled stub.
type sessionServerOptions struct {
	// rejectPTY makes the server refuse "pty-req".
	rejectPTY bool

	// rejectShell makes the server refuse "shell".
	rejectShell bool

	// rejectEnv makes the server refuse every "env" request, per RFC 4254
	// 6.4's allowance that a server may silently reject any environment
	// variable it does not accept.
	rejectEnv bool
}

// sessionTestServer is an in-process SSH server with configurable session
// behaviour. It records the environment variables the client requested.
type sessionTestServer struct {
	ln      net.Listener
	hostPub ssh.PublicKey
	host    string
	port    int

	mu  sync.Mutex
	env map[string]string
}

// recordedEnv returns a copy of the env vars the client sent.
func (s *sessionTestServer) recordedEnv() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.env))
	for k, v := range s.env {
		out[k] = v
	}
	return out
}

func startSessionServer(t *testing.T, opts sessionServerOptions) *sessionTestServer {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	_, _ = fmtSscan(portStr, &port)

	s := &sessionTestServer{
		ln:      ln,
		hostPub: hostSigner.PublicKey(),
		host:    host,
		port:    port,
		env:     map[string]string{},
	}

	go s.serve(cfg, opts)
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *sessionTestServer) serve(cfg *ssh.ServerConfig, opts sessionServerOptions) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn, cfg, opts)
	}
}

func (s *sessionTestServer) handle(conn net.Conn, cfg *ssh.ServerConfig, opts sessionServerOptions) {
	defer func() { _ = conn.Close() }()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		channel, requests, aerr := newChan.Accept()
		if aerr != nil {
			continue
		}
		go s.serveSession(channel, requests, opts)
	}
}

func (s *sessionTestServer) serveSession(ch ssh.Channel, in <-chan *ssh.Request, opts sessionServerOptions) {
	for req := range in {
		switch req.Type {
		case "env":
			if opts.rejectEnv {
				_ = req.Reply(false, nil)
				continue
			}
			var payload struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &payload) == nil {
				s.mu.Lock()
				s.env[payload.Name] = payload.Value
				s.mu.Unlock()
			}
			_ = req.Reply(true, nil)
		case "pty-req":
			_ = req.Reply(!opts.rejectPTY, nil)
		case "window-change":
			_ = req.Reply(true, nil)
		case "shell":
			if opts.rejectShell {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go func() {
				_, _ = io.Copy(ch, ch)
				_ = ch.Close()
			}()
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// dialSessionServer connects a console to the given test server.
func dialSessionServer(t *testing.T, srv *sessionTestServer, cfg Config) (Console, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	return Dial(ctx, DialRequest{
		Host:         srv.host,
		Port:         srv.port,
		User:         "tester",
		Signer:       clientSigner(t),
		KnownHosts:   pinnedHosts(t, srv.host, srv.hostPub),
		HostKeyScope: scope.User,
		HostKeyOwner: "tester",
	}, cfg)
}

// TestConsole_EnvIsSentToRemoteSession verifies configured environment
// variables reach the remote session. The console is used to run interactive
// shells whose behaviour (TERM, LANG, proxy settings) depends on this, so
// dropping the Env map silently changes what the user sees.
func TestConsole_EnvIsSentToRemoteSession(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	c, err := dialSessionServer(t, srv, Config{
		Term: "xterm-256color",
		Rows: 24,
		Cols: 80,
		Env:  map[string]string{"XKMS_CONSOLE": "1", "LANG": "C.UTF-8"},
	})
	if !requireHandshake(t, err) {
		return
	}
	defer func() { _ = c.Close() }()

	// The env requests are sent before the shell starts, so they have arrived
	// by the time Dial returns.
	got := srv.recordedEnv()
	if got["XKMS_CONSOLE"] != "1" {
		t.Errorf("XKMS_CONSOLE = %q, want %q (env must reach the remote session)", got["XKMS_CONSOLE"], "1")
	}
	if got["LANG"] != "C.UTF-8" {
		t.Errorf("LANG = %q, want %q", got["LANG"], "C.UTF-8")
	}
}

// TestConsole_EnvRejectionIsLoggedNotFatal verifies that a server rejecting
// an environment variable (RFC 4254 6.4 permits this silently) does not fail
// the console -- it is routine server policy, not a session-ending error --
// but is still logged so the rejection is not silently invisible.
func TestConsole_EnvRejectionIsLoggedNotFatal(t *testing.T) {
	handler := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := startSessionServer(t, sessionServerOptions{rejectEnv: true})

	c, err := dialSessionServer(t, srv, Config{Env: map[string]string{"XKMS_CONSOLE": "1"}})
	if !requireHandshake(t, err) {
		return
	}
	defer func() { _ = c.Close() }()

	if got := srv.recordedEnv(); len(got) != 0 {
		t.Fatalf("expected the rejected env var not to be recorded, got %v", got)
	}
	if !handler.hasMessage("ssh/console: remote rejected an environment variable") {
		t.Fatal("expected the env rejection to be logged")
	}
}

// TestConsole_DialFailsWhenPTYRefused verifies a server that refuses to grant a
// PTY produces a SessionError rather than a half-open console. The console
// contract is an interactive terminal; without a PTY there is nothing to
// present, so this must fail rather than degrade to a raw pipe.
func TestConsole_DialFailsWhenPTYRefused(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{rejectPTY: true})

	c, err := dialSessionServer(t, srv, Config{})
	if err == nil {
		_ = c.Close()
		t.Fatal("Dial must fail when the server refuses a PTY")
	}
	// Under GODEBUG=fips140=only the handshake itself is refused (see
	// requireHandshake) before the client ever reaches the PTY request this
	// test targets, so the error is a handshake failure, not *SessionError.
	if !fips140.Enforced() {
		var sessErr *SessionError
		if !errors.As(err, &sessErr) {
			t.Fatalf("error = %T (%v), want *SessionError", err, err)
		}
	}
	if c != nil {
		t.Error("no console may be returned when session setup fails")
	}
}

// TestConsole_DialFailsWhenShellRefused verifies a server that grants a PTY but
// refuses to start a shell also fails cleanly.
func TestConsole_DialFailsWhenShellRefused(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{rejectShell: true})

	c, err := dialSessionServer(t, srv, Config{})
	if err == nil {
		_ = c.Close()
		t.Fatal("Dial must fail when the server refuses to start a shell")
	}
	// Under GODEBUG=fips140=only the handshake itself is refused (see
	// requireHandshake) before the client ever reaches the shell request
	// this test targets, so the error is a handshake failure, not
	// *SessionError.
	if !fips140.Enforced() {
		var sessErr *SessionError
		if !errors.As(err, &sessErr) {
			t.Fatalf("error = %T (%v), want *SessionError", err, err)
		}
	}
}

// TestOpen_FailsOnClosedClient verifies opening a console over a client whose
// connection is already gone reports a SessionError instead of panicking on a
// nil session.
func TestOpen_FailsOnClosedClient(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	client, err := ssh.Dial("tcp", net.JoinHostPort(srv.host, strconv.Itoa(srv.port)), &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server key is generated per test
		Timeout:         10 * time.Second,
	})
	if !requireHandshake(t, err) {
		return
	}
	_ = client.Close()

	c, err := Open(client, Config{})
	if err == nil {
		_ = c.Close()
		t.Fatal("Open must fail on a closed client")
	}
	var sessErr *SessionError
	if !errors.As(err, &sessErr) {
		t.Fatalf("error = %T (%v), want *SessionError", err, err)
	}
}

// TestConsole_ResizeClampsNonPositiveDimensions verifies zero or negative
// window dimensions fall back to the defaults instead of being forwarded to the
// remote PTY. Browsers report 0x0 for a hidden or not-yet-laid-out terminal, and
// a 0-row PTY leaves the remote shell unusable for the rest of the session.
func TestConsole_ResizeClampsNonPositiveDimensions(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	c, err := dialSessionServer(t, srv, Config{Rows: 24, Cols: 80})
	if !requireHandshake(t, err) {
		return
	}
	defer func() { _ = c.Close() }()

	for _, tc := range []struct {
		name       string
		rows, cols int
	}{
		{"both zero", 0, 0},
		{"negative rows", -5, 100},
		{"negative cols", 40, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Resize(tc.rows, tc.cols); err != nil {
				t.Fatalf("Resize(%d, %d) = %v, want nil (dimensions must be clamped, not rejected)",
					tc.rows, tc.cols, err)
			}
		})
	}
}

// TestConsole_ResizeAfterCloseIsRejected verifies a resize arriving after
// teardown reports ClosedError rather than touching a nil session. A browser
// window-resize event can race the socket closing, so this is a real ordering.
func TestConsole_ResizeAfterCloseIsRejected(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	c, err := dialSessionServer(t, srv, Config{})
	if !requireHandshake(t, err) {
		return
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = c.Resize(30, 100)
	var closedErr *ClosedError
	if !errors.As(err, &closedErr) {
		t.Fatalf("Resize after Close = %T (%v), want *ClosedError", err, err)
	}
}

// TestConsole_CloseIsIdempotent verifies repeated Close calls stay safe and
// quiet. The handler closes via defer while the read pump may also be tearing
// down, so a second Close must not error or double-close the client.
func TestConsole_CloseIsIdempotent(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	c, err := dialSessionServer(t, srv, Config{})
	if !requireHandshake(t, err) {
		return
	}

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil", err)
	}

	// Writes after close must fail rather than silently succeed.
	if _, err := c.Write([]byte("x")); err == nil {
		t.Error("Write after Close must fail")
	}
}

// TestConsole_ConcurrentReadResizeAndClose exercises the access pattern the
// WebSocket bridge produces: an output pump reading and a control path
// resizing while teardown runs concurrently. Run under -race this guards the
// console's lock-free teardown.
//
// Concurrent Write + Close is covered by
// TestConsole_ConcurrentWriteReadAndClose in console_lifecycle_test.go: Close
// now tears the SESSION down instead of closing stdin, so it no longer reaches
// channel.CloseWrite() while a write sits in channel.WriteExtended(). The
// writer below still runs to completion first only to keep this test focused
// on the read/resize/close trio.
func TestConsole_ConcurrentReadResizeAndClose(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	c, err := dialSessionServer(t, srv, Config{Rows: 24, Cols: 80})
	if !requireHandshake(t, err) {
		return
	}

	// Writer runs to completion first (see the note above).
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; i < 50; i++ {
			if _, werr := c.Write([]byte("ping\n")); werr != nil {
				return
			}
		}
	}()
	writers.Wait()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() { // output pump
		defer wg.Done()
		buf := make([]byte, 256)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, rerr := c.Read(buf); rerr != nil {
				return
			}
		}
	}()

	wg.Add(1)
	go func() { // control path
		defer wg.Done()
		for i := 0; i < 200; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = c.Resize(20+i%10, 80+i%10)
		}
	}()

	// Tear down while the pumps above are live.
	time.Sleep(10 * time.Millisecond)
	closeErr := c.Close()
	close(stop)
	wg.Wait()

	if closeErr != nil {
		t.Fatalf("Close under concurrency: %v", closeErr)
	}

	// After teardown the guarded operations report closed rather than racing.
	var closedErr *ClosedError
	if err := c.Resize(30, 100); !errors.As(err, &closedErr) {
		t.Fatalf("Resize after concurrent Close = %T (%v), want *ClosedError", err, err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close after concurrency: %v, want nil", err)
	}
}
