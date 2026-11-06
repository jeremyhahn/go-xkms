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
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// ---------------------------------------------------------------------------
// Test servers for the console lifecycle (Close / CloseWrite) contract.
// ---------------------------------------------------------------------------

// lifecycleServerMode selects how the test server's "shell" behaves.
type lifecycleServerMode int

const (
	// modeEcho echoes stdin back to stdout (an interactive shell).
	modeEcho lifecycleServerMode = iota

	// modeStalled accepts the shell request but never reads the channel,
	// so the client's SSH flow-control window fills and Write blocks.
	modeStalled

	// modeDrainUntilEOF reads stdin to EOF, then writes a marker and keeps
	// the channel open. It proves CloseWrite reached the remote as a real
	// SSH channel EOF rather than a channel teardown.
	modeDrainUntilEOF
)

// eofMarker is what modeDrainUntilEOF writes once the remote end of the
// session has observed EOF on its stdin.
const eofMarker = "REMOTE-SAW-EOF\n"

// lifecycleServer is an in-process SSH server whose shell behaviour is
// selected by mode. It also records whether the session channel was ever
// closed by the client, so a test can prove teardown reached the remote.
type lifecycleServer struct {
	ln      net.Listener
	hostPub ssh.PublicKey
	host    string
	port    int
	mode    lifecycleServerMode

	// channelClosed is closed once the server's session channel read loop
	// ends, i.e. the client tore the channel (or the connection) down.
	channelClosed chan struct{}
	closeOnce     sync.Once
}

func startLifecycleServer(t *testing.T, mode lifecycleServerMode) *lifecycleServer {
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

	s := &lifecycleServer{
		ln:            ln,
		hostPub:       hostSigner.PublicKey(),
		host:          host,
		port:          port,
		mode:          mode,
		channelClosed: make(chan struct{}),
	}
	go s.serve(cfg)
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *lifecycleServer) serve(cfg *ssh.ServerConfig) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn, cfg)
	}
}

func (s *lifecycleServer) handle(conn net.Conn, cfg *ssh.ServerConfig) {
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
		go s.serveSession(channel, requests)
	}
}

func (s *lifecycleServer) serveSession(ch ssh.Channel, in <-chan *ssh.Request) {
	defer s.closeOnce.Do(func() { close(s.channelClosed) })

	for req := range in {
		switch req.Type {
		case "pty-req", "window-change", "env":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			go s.runShell(ch)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (s *lifecycleServer) runShell(ch ssh.Channel) {
	switch s.mode {
	case modeEcho:
		_, _ = io.Copy(ch, ch)
		_ = ch.Close()
	case modeStalled:
		// Deliberately never read from ch: the client's remote window is
		// never replenished, so a large Write blocks in flow control.
		<-s.channelClosed
	case modeDrainUntilEOF:
		_, _ = io.Copy(io.Discard, ch) // returns when the client sends EOF
		_, _ = ch.Write([]byte(eofMarker))
		// Keep the channel open: the console's Close must still tear it
		// down after the half-close.
		<-s.channelClosed
	}
}

// dialLifecycleServer opens a console against the lifecycle server. The
// bool return is false when the handshake was refused for the expected
// GODEBUG=fips140=only reason (see requireHandshake); the caller must
// return immediately in that case.
func dialLifecycleServer(t *testing.T, srv *lifecycleServer) (Console, bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	c, err := Dial(ctx, DialRequest{
		Host:         srv.host,
		Port:         srv.port,
		User:         "tester",
		Signer:       clientSigner(t),
		KnownHosts:   pinnedHosts(t, srv.host, srv.hostPub),
		HostKeyScope: scope.User,
		HostKeyOwner: "tester",
	}, Config{Rows: 24, Cols: 80})
	if !requireHandshake(t, err) {
		return nil, false
	}
	return c, true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestConsole_ConcurrentWriteReadAndClose is the regression guard for the
// production data race between Write/Read and Close. A GUI "disconnect"
// closes the console from the UI goroutine while the terminal pump is still
// feeding keystrokes, which is exactly the interleaving below.
//
// Against the pre-fix console (Close called stdin.Close(), reaching
// ssh.(*channel).CloseWrite() while Write was inside
// ssh.(*channel).WriteExtended()) this test fails under -race. Close must
// tear the SESSION down instead, so the EOF flag the writer reads is never
// mutated concurrently.
func TestConsole_ConcurrentWriteReadAndClose(t *testing.T) {
	srv := startLifecycleServer(t, modeEcho)
	c, ok := dialLifecycleServer(t, srv)
	if !ok {
		return
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() { // keystroke pump
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if _, err := c.Write([]byte("ping\n")); err != nil {
				return
			}
		}
	}()

	go func() { // output pump
		defer wg.Done()
		buf := make([]byte, 256)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()

	go func() { // window-size pump
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if err := c.Resize(20+i%10, 80+i%10); err != nil {
				return
			}
		}
	}()

	time.Sleep(5 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatalf("Close during concurrent I/O: %v", err)
	}
	wg.Wait()

	// Every operation must now report the typed closed error.
	var closedErr *ClosedError
	if _, err := c.Write([]byte("x")); !errors.As(err, &closedErr) {
		t.Errorf("Write after Close = %T (%v), want *ClosedError", err, err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.As(err, &closedErr) {
		t.Errorf("Read after Close = %T (%v), want *ClosedError", err, err)
	}
	if err := c.Resize(30, 100); !errors.As(err, &closedErr) {
		t.Errorf("Resize after Close = %T (%v), want *ClosedError", err, err)
	}
	if err := c.CloseWrite(); !errors.As(err, &closedErr) {
		t.Errorf("CloseWrite after Close = %T (%v), want *ClosedError", err, err)
	}
}

// TestConsole_CloseReturnsWhileWriteIsBlocked verifies Close never waits on a
// write that is stuck in SSH flow control against a remote that stopped
// reading. This is why Write must not take the console's lock: a hung remote
// would otherwise turn "disconnect" into a permanent hang.
func TestConsole_CloseReturnsWhileWriteIsBlocked(t *testing.T) {
	srv := startLifecycleServer(t, modeStalled)
	c, ok := dialLifecycleServer(t, srv)
	if !ok {
		return
	}

	writeDone := make(chan error, 1)
	go func() {
		// Far more than one SSH window (64 KiB): the remote never reads,
		// so this blocks partway through.
		_, err := c.Write(make([]byte, 4<<20))
		writeDone <- err
	}()

	// Give the writer time to fill the window and block.
	time.Sleep(100 * time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close while a write is blocked: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked behind a stalled write; teardown must never wait on the remote")
	}

	// The blocked write must be released by the teardown, not left hanging.
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("the blocked Write must fail once the console is closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock the in-flight Write")
	}
}

// TestConsole_CloseIsIdempotentAndTearsDownSession verifies repeated Close
// calls are safe and that the first one really terminated the remote session.
func TestConsole_CloseIsIdempotentAndTearsDownSession(t *testing.T) {
	srv := startLifecycleServer(t, modeEcho)
	c, ok := dialLifecycleServer(t, srv)
	if !ok {
		return
	}

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Close(); err != nil {
			t.Fatalf("Close #%d: %v, want nil", i+2, err)
		}
	}

	// Writes after close must fail rather than silently succeed.
	if _, err := c.Write([]byte("x")); err == nil {
		t.Error("Write after Close must fail")
	}

	select {
	case <-srv.channelClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not tear the session channel down on the remote")
	}
}

// TestConsole_CloseWriteSignalsEOFAndSessionSurvives verifies CloseWrite
// delivers a real SSH channel EOF to the remote (its stdin reader returns)
// while leaving the session readable, and that Close still tears the session
// down afterwards. This is the behaviour Close used to provide implicitly;
// it is now an explicit, deliberate call.
func TestConsole_CloseWriteSignalsEOFAndSessionSurvives(t *testing.T) {
	srv := startLifecycleServer(t, modeDrainUntilEOF)
	c, ok := dialLifecycleServer(t, srv)
	if !ok {
		return
	}

	if _, err := c.Write([]byte("some input\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The remote only emits the marker after its stdin reader saw EOF.
	type readResult struct {
		line string
		err  error
	}
	lines := make(chan readResult, 1)
	go func() {
		line, err := bufio.NewReader(c).ReadString('\n')
		lines <- readResult{line: line, err: err}
	}()

	select {
	case got := <-lines:
		if got.err != nil {
			t.Fatalf("reading after CloseWrite: %v", got.err)
		}
		if !strings.Contains(got.line, strings.TrimSpace(eofMarker)) {
			t.Fatalf("remote output = %q, want the post-EOF marker %q", got.line, eofMarker)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote never observed EOF: CloseWrite must send an SSH channel EOF")
	}

	// The write half is shut: further writes are rejected with the typed
	// error instead of racing the EOF flag inside x/crypto/ssh.
	var writeClosed *WriteClosedError
	if _, err := c.Write([]byte("more\n")); !errors.As(err, &writeClosed) {
		t.Fatalf("Write after CloseWrite = %T (%v), want *WriteClosedError", err, err)
	}

	// CloseWrite is idempotent.
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite: %v, want nil", err)
	}

	// And the session still tears down cleanly.
	if err := c.Close(); err != nil {
		t.Fatalf("Close after CloseWrite: %v", err)
	}
	select {
	case <-srv.channelClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close after CloseWrite did not tear the session down")
	}
}

// TestConsole_CloseWriteOnClosedConsole verifies the half-close path reports
// the typed closed error rather than touching a torn-down channel.
func TestConsole_CloseWriteOnClosedConsole(t *testing.T) {
	srv := startLifecycleServer(t, modeEcho)
	c, ok := dialLifecycleServer(t, srv)
	if !ok {
		return
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var closedErr *ClosedError
	if err := c.CloseWrite(); !errors.As(err, &closedErr) {
		t.Fatalf("CloseWrite after Close = %T (%v), want *ClosedError", err, err)
	}
}

// TestConsole_OpenDoesNotCloseCallerClient verifies Console.Close on a console
// created by Open tears down only the session, leaving the caller's client
// usable for a second console. Close now closes the session rather than the
// stdin pipe, so this ownership boundary is worth pinning.
func TestConsole_OpenLeavesClientUsable(t *testing.T) {
	srv := startLifecycleServer(t, modeEcho)

	client, err := ssh.Dial("tcp", net.JoinHostPort(srv.host, itoa(srv.port)), &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner(t))},
		HostKeyCallback: ssh.FixedHostKey(srv.hostPub),
		Timeout:         10 * time.Second,
	})
	if !requireSSHHandshake(t, err) {
		return
	}
	defer func() { _ = client.Close() }()

	first, err := Open(client, Config{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close first console: %v", err)
	}

	second, err := Open(client, Config{})
	if err != nil {
		t.Fatalf("Open after closing the first console: %v (Close must not close the caller's client)", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close second console: %v", err)
	}
}

// itoa renders a port without pulling strconv into this file's import set for
// a single call site.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
