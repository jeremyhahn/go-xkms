// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"context"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// sshDialOwner is the known-hosts owner every dial test pins under.
const sshDialOwner = "alice"

// sshEchoServer is a single-purpose in-process SSH server: it accepts any
// public key and answers each exec request by echoing the command back
// with exit status 0.
type sshEchoServer struct {
	listener net.Listener
	cfg      *ssh.ServerConfig
	wg       sync.WaitGroup
}

func newSSHEchoServer(t *testing.T, hostSigner ssh.Signer) *sshEchoServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &sshEchoServer{listener: ln, cfg: cfg}
	srv.wg.Add(1)
	go srv.serve()
	t.Cleanup(func() {
		srv.listener.Close()
		srv.wg.Wait()
	})
	return srv
}

func (s *sshEchoServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *sshEchoServer) handleConn(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go echoExec(ch, requests)
	}
}

// echoExec answers the first exec request on ch by writing the command
// back and reporting exit status 0.
func echoExec(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer ch.Close()
	for req := range requests {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}
		var exec struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &exec); err != nil {
			req.Reply(false, nil)
			return
		}
		req.Reply(true, nil)
		io.WriteString(ch, exec.Command)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

func (s *sshEchoServer) host() string {
	return s.listener.Addr().(*net.TCPAddr).IP.String()
}

func (s *sshEchoServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

// newSSHTestSigner returns a fresh ed25519 ssh.Signer.
func newSSHTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

// newSSHKnownHosts returns an in-memory known-hosts store holding a pin
// of pinned for host, or an empty store when pinned is nil.
func newSSHKnownHosts(t *testing.T, host string, pinned ssh.PublicKey) SSHKnownHostsStore {
	t.Helper()
	store, err := NewSSHKnownHostsStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("known-hosts store: %v", err)
	}
	if pinned != nil {
		pin := SSHPinFromPublicKey(host, SSHScopeUser, sshDialOwner, pinned, "")
		if err := store.Add(t.Context(), pin); err != nil {
			t.Fatalf("add pin: %v", err)
		}
	}
	return store
}

// dialSSHTestClient dials srv through the re-exported SSHSessionDialClient,
// verifying the host key against store.
func dialSSHTestClient(t *testing.T, srv *sshEchoServer, store SSHKnownHostsStore, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	return SSHSessionDialClient(ctx, SSHSessionClientParams{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Signer:          signer,
		HostKeyCallback: SSHKnownHostsCallback(t.Context(), store, SSHScopeUser, sshDialOwner),
		Timeout:         3 * time.Second,
	})
}

// handshakeBlockedByFIPS reports whether err is the expected outcome of an
// in-process SSH handshake under GODEBUG=fips140=only: x/crypto/ssh's
// preferred curve25519 key exchange fails before host-key verification or
// authentication runs (see pkg/ssh/session requireHandshake). Any other
// error fails the test.
func handshakeBlockedByFIPS(t *testing.T, err error) bool {
	t.Helper()
	if !fips140.Enforced() {
		return false
	}
	var hs *SSHSessionHandshakeError
	if !errors.As(err, &hs) {
		t.Fatalf("expected *SSHSessionHandshakeError under fips140=only, got %T: %v", err, err)
	}
	return true
}

// TestSSHSessionDialClient_RunsCommand dials a pinned server through the
// re-exported primitives, wraps the client with SSHNewSession, and runs a
// command over it.
func TestSSHSessionDialClient_RunsCommand(t *testing.T) {
	hostSigner := newSSHTestSigner(t)
	srv := newSSHEchoServer(t, hostSigner)
	store := newSSHKnownHosts(t, srv.host(), hostSigner.PublicKey())

	client, err := dialSSHTestClient(t, srv, store, newSSHTestSigner(t))
	if err != nil {
		if handshakeBlockedByFIPS(t, err) {
			return
		}
		t.Fatalf("SSHSessionDialClient: %v", err)
	}

	closed := false
	sess := SSHNewSession(srv.host(), "testuser", client, func() { closed = true })
	stdout, _, err := sess.Run(t.Context(), "hello world")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(stdout) != "hello world" {
		t.Fatalf("stdout = %q, want %q", stdout, "hello world")
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Fatal("SSHNewSession closer did not run on Close")
	}
}

// TestSSHSessionDialClient_UnknownHost asserts an unpinned host fails
// closed with *SSHKnownHostsNotFoundError inside *SSHSessionHandshakeError.
func TestSSHSessionDialClient_UnknownHost(t *testing.T) {
	srv := newSSHEchoServer(t, newSSHTestSigner(t))
	store := newSSHKnownHosts(t, srv.host(), nil)

	client, err := dialSSHTestClient(t, srv, store, newSSHTestSigner(t))
	if err == nil {
		client.Close()
		t.Fatal("expected dial to an unpinned host to fail")
	}
	if handshakeBlockedByFIPS(t, err) {
		return
	}
	var hs *SSHSessionHandshakeError
	if !errors.As(err, &hs) {
		t.Fatalf("expected *SSHSessionHandshakeError, got %T: %v", err, err)
	}
	var nf *SSHKnownHostsNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *SSHKnownHostsNotFoundError, got %T: %v", err, err)
	}
	if nf.Host != srv.host() {
		t.Fatalf("NotFoundError.Host = %q, want %q", nf.Host, srv.host())
	}
}

// TestSSHSessionDialClient_HostKeyMismatch pins a different key than the
// server presents and asserts *SSHKnownHostsMismatchError.
func TestSSHSessionDialClient_HostKeyMismatch(t *testing.T) {
	srv := newSSHEchoServer(t, newSSHTestSigner(t))
	store := newSSHKnownHosts(t, "127.0.0.1", newSSHTestSigner(t).PublicKey())

	client, err := dialSSHTestClient(t, srv, store, newSSHTestSigner(t))
	if err == nil {
		client.Close()
		t.Fatal("expected dial with a mismatched pin to fail")
	}
	if handshakeBlockedByFIPS(t, err) {
		return
	}
	var mm *SSHKnownHostsMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected *SSHKnownHostsMismatchError, got %T: %v", err, err)
	}
	if mm.Expected == mm.Received {
		t.Fatalf("mismatch reports identical fingerprints: %q", mm.Expected)
	}
}

// signFailedError is the typed error failingSSHSigner returns from Sign.
type signFailedError struct{}

func (signFailedError) Error() string { return "test signer: sign failed" }

// failingSSHSigner offers a real public key but fails every signature, as
// a hardware or remote signer does when its device or proxy is gone.
type failingSSHSigner struct {
	pub ssh.PublicKey
}

func (s failingSSHSigner) PublicKey() ssh.PublicKey { return s.pub }

func (failingSSHSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, signFailedError{}
}

// TestSSHSessionDialClient_SignerError asserts a signer failure surfaces
// as *SSHSessionHandshakeError with the signer's own error reachable.
func TestSSHSessionDialClient_SignerError(t *testing.T) {
	hostSigner := newSSHTestSigner(t)
	srv := newSSHEchoServer(t, hostSigner)
	store := newSSHKnownHosts(t, srv.host(), hostSigner.PublicKey())
	signer := failingSSHSigner{pub: newSSHTestSigner(t).PublicKey()}

	client, err := dialSSHTestClient(t, srv, store, signer)
	if err == nil {
		client.Close()
		t.Fatal("expected dial with a failing signer to fail")
	}
	if handshakeBlockedByFIPS(t, err) {
		return
	}
	var hs *SSHSessionHandshakeError
	if !errors.As(err, &hs) {
		t.Fatalf("expected *SSHSessionHandshakeError, got %T: %v", err, err)
	}
	var sf signFailedError
	if !errors.As(err, &sf) {
		t.Fatalf("expected the signer's error to be wrapped, got %v", err)
	}
}

// TestSSHSessionDialClient_InputErrors asserts missing inputs and an
// unreachable port surface the re-exported typed errors.
func TestSSHSessionDialClient_InputErrors(t *testing.T) {
	t.Run("nil signer", func(t *testing.T) {
		_, err := SSHSessionDialClient(t.Context(), SSHSessionClientParams{
			Host:            "127.0.0.1",
			User:            "testuser",
			HostKeyCallback: ssh.FixedHostKey(newSSHTestSigner(t).PublicKey()),
		})
		var ni *SSHSessionNilInputError
		if !errors.As(err, &ni) || ni.Field != "Signer" {
			t.Fatalf("expected *SSHSessionNilInputError{Signer}, got %T: %v", err, err)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()

		_, err = SSHSessionDialClient(t.Context(), SSHSessionClientParams{
			Host:            "127.0.0.1",
			Port:            port,
			User:            "testuser",
			Signer:          newSSHTestSigner(t),
			HostKeyCallback: ssh.FixedHostKey(newSSHTestSigner(t).PublicKey()),
			Timeout:         time.Second,
		})
		var de *SSHSessionDialError
		if !errors.As(err, &de) {
			t.Fatalf("expected *SSHSessionDialError for 127.0.0.1:%d, got %T: %v", port, err, err)
		}
	})
}
