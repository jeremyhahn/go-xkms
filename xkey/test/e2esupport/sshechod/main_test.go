package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

var errListenerClosed = errors.New("listener closed")

// memListener hands out in-memory net.Pipe connections, so the server runs
// end to end without a socket.
type memListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, errListenerClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 9), Port: 2222}
}

// dial connects a client end to the server.
func (l *memListener) dial(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client
	case <-l.closed:
		t.Fatal("dial on a closed listener")
		return nil
	}
}

// queuedConn queues its writes for a pump goroutine. net.Pipe writes block
// until the peer reads, and both SSH peers send their version first, so one
// side must not block on write.
type queuedConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
	queue  chan []byte
}

func newQueuedConn(c net.Conn) *queuedConn {
	q := &queuedConn{Conn: c, queue: make(chan []byte, 1024)}
	go q.pump()
	return q
}

func (q *queuedConn) pump() {
	for b := range q.queue {
		if _, err := q.Conn.Write(b); err != nil {
			for range q.queue {
			}
			return
		}
	}
}

func (q *queuedConn) Write(b []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0, net.ErrClosed
	}
	q.queue <- append([]byte(nil), b...)
	return len(b), nil
}

func (q *queuedConn) Close() error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.queue)
	}
	q.mu.Unlock()
	return q.Conn.Close()
}

// startServer runs the server on a memListener and returns the listener,
// the address run asked to listen on and a channel carrying run's result.
func startServer(t *testing.T, args []string, out io.Writer) (*memListener, <-chan string, <-chan error) {
	t.Helper()
	ln := newMemListener()
	asked := make(chan string, 1)
	listen := func(network, address string) (net.Listener, error) {
		asked <- network + " " + address
		return ln, nil
	}
	done := make(chan error, 1)
	go func() { done <- run(args, listen, out) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln, asked, done
}

// sshClient completes an SSH handshake with the server listening on ln.
//
// It reports false when the calling test must return: x/crypto/ssh's default
// key exchange is curve25519, whose X25519 crypto/ecdh refuses under
// GODEBUG=fips140=only (owner ruling 116: refuse what the stdlib refuses).
// There the refusal is asserted and the test re-run under fips140=off.
func sshClient(t *testing.T, ln *memListener) (*ssh.Client, bool) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	var hostKey ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "tester",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
	}
	conn, chans, reqs, err := ssh.NewClientConn(newQueuedConn(ln.dial(t)), "127.0.0.9:2222", cfg)
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	if hostKey == nil || hostKey.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("host key = %v, want an ed25519 key", hostKey)
	}
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client, true
}

// shell opens a session with a PTY and a shell, as the embedded console does.
func shell(t *testing.T, client *ssh.Client) (*ssh.Session, io.WriteCloser, io.Reader) {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if err := session.Setenv("LANG", "C"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("pty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	if err := session.WindowChange(40, 120); err != nil {
		t.Fatalf("window change: %v", err)
	}
	return session, stdin, stdout
}

func TestRun_EchoesTheSessionUntilExit(t *testing.T) {
	var out bytes.Buffer
	ln, asked, done := startServer(t, []string{"127.0.0.9"}, &out)
	// A client that hangs up mid-handshake must not stop the server.
	if err := ln.dial(t).Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	client, ok := sshClient(t, ln)
	if !ok {
		return
	}
	_, stdin, stdout := shell(t, client)

	// Longer than the 16-byte window the server scans for "exit".
	line := "hello from the embedded console\n"
	if _, err := io.WriteString(stdin, line); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(line))
	if _, err := io.ReadFull(stdout, echo); err != nil || string(echo) != line {
		t.Fatalf("echo = %q, %v; want hello", echo, err)
	}
	if _, err := io.WriteString(stdin, "exit"); err != nil {
		t.Fatalf("write exit: %v", err)
	}
	rest, err := io.ReadAll(stdout)
	if err != nil || string(rest) != "exit" {
		t.Fatalf("after exit = %q, %v; want the echo then end of stream", rest, err)
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := <-asked; got != "tcp 127.0.0.9:0" {
		t.Fatalf("listened on %q, want tcp 127.0.0.9:0", got)
	}
	if out.String() != "SSHECHO LISTEN 127.0.0.9 2222\n" {
		t.Fatalf("announcement = %q", out.String())
	}
}

func TestRun_EndsTheSessionWhenTheClientStopsSending(t *testing.T) {
	ln, asked, _ := startServer(t, nil, io.Discard)
	client, ok := sshClient(t, ln)
	if !ok {
		return
	}
	_, stdin, stdout := shell(t, client)

	if _, err := io.WriteString(stdin, "bye"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	rest, err := io.ReadAll(stdout)
	if err != nil || string(rest) != "bye" {
		t.Fatalf("output = %q, %v; want the echo then end of stream", rest, err)
	}
	if got := <-asked; got != "tcp 127.0.0.1:0" {
		t.Fatalf("listened on %q, want the loopback default", got)
	}
}

func TestRun_RefusesExecAndNonSessionChannels(t *testing.T) {
	ln, _, _ := startServer(t, []string{""}, io.Discard)
	client, ok := sshClient(t, ln)
	if !ok {
		return
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if err := session.Start("id"); err == nil {
		t.Fatal("exec was accepted, want it refused")
	}

	_, _, err = client.OpenChannel("direct-tcpip", nil)
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) || openErr.Reason != ssh.UnknownChannelType {
		t.Fatalf("open direct-tcpip = %v, want UnknownChannelType", err)
	}
	if !strings.Contains(openErr.Message, "only session channels") {
		t.Fatalf("rejection message = %q", openErr.Message)
	}
}

func TestRun_FailsWhenItCannotListen(t *testing.T) {
	errInUse := errors.New("address in use")
	listen := func(string, string) (net.Listener, error) { return nil, errInUse }

	err := run(nil, listen, io.Discard)

	var se *startError
	if !errors.As(err, &se) || se.what != "listen" || !errors.Is(err, errInUse) {
		t.Fatalf("run = %v, want a listen startError wrapping the cause", err)
	}
	if err.Error() != "listen: address in use" {
		t.Fatalf("error text = %q", err.Error())
	}
}

// failingWriter fails every write, as a closed stdout does.
type failingWriter struct{}

var errFailingWriter = errors.New("write failed")

func (failingWriter) Write([]byte) (int, error) { return 0, errFailingWriter }

func TestRun_FailsWhenItCannotAnnounce(t *testing.T) {
	ln := newMemListener()
	listen := func(string, string) (net.Listener, error) { return ln, nil }

	err := run(nil, listen, failingWriter{})

	var se *startError
	if !errors.As(err, &se) || se.what != "announce" || !errors.Is(err, errFailingWriter) {
		t.Fatalf("run = %v, want an announce startError", err)
	}
	select {
	case <-ln.closed:
	default:
		t.Fatal("run left the listener open")
	}
}
