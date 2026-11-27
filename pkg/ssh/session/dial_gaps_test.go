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

package session

import (
	"bufio"
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// TestDialClient_InputGuards covers the four nil/empty parameter guards.
func TestDialClient_InputGuards(t *testing.T) {
	signer := testSigner(t)
	cb := ssh.InsecureIgnoreHostKey()
	ctx := context.Background()

	cases := []struct {
		name  string
		p     ClientParams
		field string
	}{
		{"host", ClientParams{User: "u", Signer: signer, HostKeyCallback: cb}, "Host"},
		{"user", ClientParams{Host: "h", Signer: signer, HostKeyCallback: cb}, "User"},
		{"signer", ClientParams{Host: "h", User: "u", HostKeyCallback: cb}, "Signer"},
		{"callback", ClientParams{Host: "h", User: "u", Signer: signer}, "HostKeyCallback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DialClient(ctx, tc.p)
			var nie *NilInputError
			if !errors.As(err, &nie) {
				t.Fatalf("expected NilInputError, got %v", err)
			}
			if nie.Field != tc.field {
				t.Fatalf("expected field %q, got %q", tc.field, nie.Field)
			}
		})
	}
}

// TestDialClient_DialError covers a TCP connection refused (no listener).
func TestDialClient_DialError(t *testing.T) {
	// Bind then close to obtain a definitely-free port that will refuse.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close() // port now refuses connections

	_, err = DialClient(context.Background(), ClientParams{
		Host:            "127.0.0.1",
		Port:            addr.Port,
		User:            "u",
		Signer:          testSigner(t),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	var de *DialError
	if !errors.As(err, &de) {
		t.Fatalf("expected DialError, got %v", err)
	}
}

// TestDialClient_Timeout covers the cancelled-context branch: the dial fails
// with ctx.Err() set, producing a TimeoutError.
func TestDialClient_Timeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	_, err := DialClient(ctx, ClientParams{
		Host:            "10.255.255.1", // unroutable; dial will not complete
		Port:            22,
		User:            "u",
		Signer:          testSigner(t),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("expected TimeoutError, got %v", err)
	}
}

// TestDialClient_HandshakeError covers a TCP peer that accepts but is not an
// SSH server, so the client handshake fails.
func TestDialClient_HandshakeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		// Send a non-SSH banner then close, forcing a handshake failure.
		_, _ = conn.Write([]byte("NOT-SSH\r\n"))
		_ = conn.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	_, err = DialClient(context.Background(), ClientParams{
		Host:            "127.0.0.1",
		Port:            addr.Port,
		User:            "u",
		Signer:          testSigner(t),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	})
	var he *HandshakeError
	if !errors.As(err, &he) {
		t.Fatalf("expected HandshakeError, got %v", err)
	}
	// ssh.NewClientConn closed the connection itself; closing it again must
	// not join a "use of closed network connection" error to the refusal.
	if errors.Is(err, net.ErrClosed) {
		t.Fatalf("handshake error carries a stray closed-connection error: %v", err)
	}
}

// TestDialClient_CancelDuringHandshakeClosesConn cancels a context that has
// no deadline while the peer has accepted but never sends a banner: the
// handshake deadline alone would hold the socket open for the full Timeout.
func TestDialClient_CancelDuringHandshakeClosesConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialErr := make(chan error, 1)
	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		_, derr := DialClient(ctx, ClientParams{
			Host:            "127.0.0.1",
			Port:            addr.Port,
			User:            "u",
			Signer:          testSigner(t),
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		})
		dialErr <- derr
	}()

	var peer net.Conn
	select {
	case peer = <-accepted:
		if peer == nil {
			t.Fatal("Accept failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer never accepted the connection")
	}
	defer peer.Close()

	// DialContext has returned once the client's version line arrives, so
	// cancelling now can only be seen by the handshake watcher around
	// ssh.NewClientConn. The server banner is withheld throughout.
	if derr := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); derr != nil {
		t.Fatalf("SetReadDeadline: %v", derr)
	}
	banner, rerr := bufio.NewReader(peer).ReadString('\n')
	if rerr != nil {
		t.Fatalf("reading the client version line: %v", rerr)
	}
	if !strings.HasPrefix(banner, "SSH-2.0-") {
		t.Fatalf("client version line = %q, want an SSH-2.0- prefix", banner)
	}

	cancel()

	select {
	case err = <-dialErr:
	case <-time.After(2 * time.Second):
		t.Fatal("DialClient did not return within 2s of cancellation")
	}
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("expected TimeoutError, got %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the error to wrap context.Canceled, got %v", err)
	}

	// The client wrote its version banner; drain until the close shows.
	if derr := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); derr != nil {
		t.Fatalf("SetReadDeadline: %v", derr)
	}
	buf := make([]byte, 256)
	for {
		_, rerr := peer.Read(buf)
		if rerr == nil {
			continue
		}
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			t.Fatal("peer did not observe the close within 2s")
		}
		return
	}
}

// TestDialClient_CancelAfterAuthWithQueuedRequestsLeavesNoGoroutine covers
// a cancellation that wins just after ssh.NewClientConn has succeeded while
// the peer has queued more global requests and channel opens than the
// client mux buffers (16 each). The mux goroutine is then blocked on a
// channel send, and DialClient must still release it.
func TestDialClient_CancelAfterAuthWithQueuedRequestsLeavesNoGoroutine(t *testing.T) {
	const queued = 20

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverCfg.AddHostKey(testSigner(t))
	clientSigner := testSigner(t)

	baseline := runtime.NumGoroutine()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		nc, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer nc.Close()
		sc, chans, reqs, serr := ssh.NewServerConn(nc, serverCfg)
		if serr != nil {
			return
		}
		defer sc.Close()
		var peer sync.WaitGroup
		peer.Add(2)
		go func() { defer peer.Done(); ssh.DiscardRequests(reqs) }()
		go func() {
			defer peer.Done()
			for nch := range chans {
				_ = nch.Reject(ssh.Prohibited, "test")
			}
		}()
		for i := 0; i < queued; i++ {
			peer.Add(1)
			go func() {
				defer peer.Done()
				ch, creqs, oerr := sc.OpenChannel("session", nil)
				if oerr != nil {
					return
				}
				_ = ch.Close()
				for range creqs {
				}
			}()
		}
		for i := 0; i < queued; i++ {
			if _, _, rerr := sc.SendRequest("queued@test", false, nil); rerr != nil {
				break
			}
		}
		_ = sc.Wait()
		_ = sc.Close()
		peer.Wait()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A failed handshake is left to DialClient and judged below, on the
	// test goroutine: under GODEBUG=fips140=only the default key exchange
	// is refused, and the test then re-runs outside FIPS enforcement.
	var handshakeErr error
	afterHandshakeHook = func(hsErr error) {
		if hsErr != nil {
			handshakeErr = hsErr
			return
		}
		defer cancel()
		if !waitForBlockedClientMux(5 * time.Second) {
			t.Error("the client mux never blocked on the queued peer traffic")
		}
	}
	t.Cleanup(func() { afterHandshakeHook = nil })

	addr := ln.Addr().(*net.TCPAddr)
	_, err = DialClient(ctx, ClientParams{
		Host:            "127.0.0.1",
		Port:            addr.Port,
		User:            "u",
		Signer:          clientSigner,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	})
	if handshakeErr != nil {
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Fatal("the test server did not end within 5s of the failed handshake")
		}
		if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
			return
		}
		t.Fatalf("handshake failed: %v (DialClient: %v)", handshakeErr, err)
	}
	var te *TimeoutError
	if !errors.As(err, &te) || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected a TimeoutError wrapping context.Canceled, got %v", err)
	}

	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the test server did not end within 5s of DialClient returning")
	}

	deadline := time.Now().Add(5 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines left behind after DialClient returned", runtime.NumGoroutine()-baseline)
		}
		<-tick.C
	}
}

// TestDialClient_CancelAfterSuccessfulDialLeavesClientUsable pins that the
// dial context only bounds the dial: once DialClient has returned a client,
// cancelling that context must not close the connection under it.
func TestDialClient_CancelAfterSuccessfulDialLeavesClientUsable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverCfg.AddHostKey(testSigner(t))

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		nc, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer nc.Close()
		sc, chans, reqs, serr := ssh.NewServerConn(nc, serverCfg)
		if serr != nil {
			return
		}
		defer sc.Close()
		go func() {
			for nch := range chans {
				_ = nch.Reject(ssh.Prohibited, "test")
			}
		}()
		go func() {
			for req := range reqs {
				if req.WantReply {
					_ = req.Reply(req.Type == "ping@test", nil)
				}
			}
		}()
		_ = sc.Wait()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := ln.Addr().(*net.TCPAddr)
	client, err := DialClient(ctx, ClientParams{
		Host:            "127.0.0.1",
		Port:            addr.Port,
		User:            "u",
		Signer:          testSigner(t),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	})
	if err != nil {
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Fatal("the test server did not end within 5s of the failed dial")
		}
		if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
			return
		}
		t.Fatalf("DialClient: %v", err)
	}
	defer client.Close()

	cancel()
	<-ctx.Done()

	// Several round trips after the cancel: a watcher left armed closes
	// the socket from its own goroutine, which fails one of them.
	for i := 0; i < 3; i++ {
		ok, _, rerr := client.SendRequest("ping@test", true, nil)
		if rerr != nil {
			t.Fatalf("global request %d after cancelling the dial context: %v", i, rerr)
		}
		if !ok {
			t.Fatalf("global request %d after cancelling the dial context was refused", i)
		}
	}

	if cerr := client.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the test server did not end within 5s of the client closing")
	}
}

// waitForBlockedClientMux reports whether, within d, a goroutine of the
// x/crypto ssh mux is blocked on a channel send.
func waitForBlockedClientMux(d time.Duration) bool {
	deadline := time.Now().Add(d)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "[chan send") && strings.Contains(g, "golang.org/x/crypto/ssh.(*mux).") {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		<-tick.C
	}
}

// closeFailConn is a net.Conn whose Close returns err.
type closeFailConn struct {
	net.Conn
	err error
}

func (c closeFailConn) Close() error { return c.err }

// closeFailure is a Close failure other than net.ErrClosed.
type closeFailure struct{}

func (closeFailure) Error() string { return "close failed" }

func TestCloseAfterFailedHandshake_ReturnsOtherCloseErrors(t *testing.T) {
	conn := closeFailConn{err: &net.OpError{Op: "close", Net: "tcp", Err: closeFailure{}}}
	err := closeAfterFailedHandshake(conn)
	var failure closeFailure
	if !errors.As(err, &failure) {
		t.Fatalf("closeAfterFailedHandshake returned %v, want the close failure", err)
	}
}
