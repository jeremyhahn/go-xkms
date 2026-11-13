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
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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

// closeFailConn is a net.Conn whose Close returns err.
type closeFailConn struct {
	net.Conn
	err error
}

func (c closeFailConn) Close() error { return c.err }

// closeFailure is a Close failure other than net.ErrClosed.
type closeFailure struct{}

func (closeFailure) Error() string { return "close failed" }

func TestCloseAfterFailedHandshake_DropsErrClosed(t *testing.T) {
	conn := closeFailConn{err: &net.OpError{Op: "close", Net: "tcp", Err: net.ErrClosed}}
	if err := closeAfterFailedHandshake(conn); err != nil {
		t.Fatalf("closeAfterFailedHandshake returned %v, want nil for net.ErrClosed", err)
	}
}

func TestCloseAfterFailedHandshake_ReturnsOtherCloseErrors(t *testing.T) {
	conn := closeFailConn{err: &net.OpError{Op: "close", Net: "tcp", Err: closeFailure{}}}
	err := closeAfterFailedHandshake(conn)
	var failure closeFailure
	if !errors.As(err, &failure) {
		t.Fatalf("closeAfterFailedHandshake returned %v, want the close failure", err)
	}
}
