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
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/session"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// testServer is a minimal single-connection SSH server used by the
// session tests. It runs until close() is invoked; each test that
// constructs one should defer close().
type testServer struct {
	listener net.Listener
	cfg      *ssh.ServerConfig
	signer   ssh.Signer
	handler  func(ch ssh.Channel, req *ssh.Request)
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// newTestServer spins up a server with the given host signer and an
// exec-request handler. Password-less (publickey-only) auth.
func newTestServer(t *testing.T, hostSigner ssh.Signer, handler func(ch ssh.Channel, req *ssh.Request)) *testServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &testServer{
		listener: ln,
		cfg:      cfg,
		signer:   hostSigner,
		handler:  handler,
		shutdown: make(chan struct{}),
	}
	srv.wg.Add(1)
	go srv.serve()
	return srv
}

func (s *testServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				return
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *testServer) handleConn(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, requests, aerr := nc.Accept()
		if aerr != nil {
			continue
		}
		go func(ch ssh.Channel, rs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range rs {
				if req.Type == "exec" {
					s.handler(ch, req)
					return
				}
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}

func (s *testServer) close() {
	close(s.shutdown)
	s.listener.Close()
	s.wg.Wait()
}

func (s *testServer) host() string {
	host, _, _ := net.SplitHostPort(s.listener.Addr().String())
	return host
}

func (s *testServer) port() int {
	_, portStr, _ := net.SplitHostPort(s.listener.Addr().String())
	var p int
	fmt.Sscanf(portStr, "%d", &p)
	return p
}

// echoHandler writes the command bytes back and sets exit 0.
func echoHandler(ch ssh.Channel, req *ssh.Request) {
	payload := req.Payload
	if len(payload) < 4 {
		req.Reply(false, nil)
		return
	}
	cmdLen := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	cmd := string(payload[4 : 4+cmdLen])
	req.Reply(true, nil)
	ch.Write([]byte(cmd))
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
}

// generateHostSigner produces a fresh ed25519 ssh.Signer.
func generateHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sig, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return sig
}

// generateClientKey returns an enclave-backed *keys.Key for auth.
func generateClientKey(t *testing.T) *keys.Key {
	t.Helper()
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519, Comment: "test"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return k
}

// pinHost registers hostSigner's public key in a fresh BackendStore
// scoped to (user, owner).
func pinHost(t *testing.T, host string, hostSigner ssh.Signer, owner string) (*known_hosts.BackendStore, scope.Scope) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := store.Add(context.Background(), &known_hosts.Pin{
		Host:        host,
		Fingerprint: keys.Fingerprint(hostSigner.PublicKey()),
		Algorithm:   hostSigner.PublicKey().Type(),
		PublicKey:   hostSigner.PublicKey().Marshal(),
		Scope:       scope.User,
		Owner:       owner,
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("add pin: %v", err)
	}
	return store, scope.User
}

// TestDial_EchoRoundtrip dials a pinned server and runs a command.
func TestDial_EchoRoundtrip(t *testing.T) {
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
	defer sess.Close()

	stdout, _, err := sess.Run(ctx, "hello world")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(stdout) != "hello world" {
		t.Fatalf("stdout %q", stdout)
	}
}

// TestDial_MITMRejected swaps the pin so the server's real key looks
// wrong, and asserts Dial surfaces a MismatchError.
func TestDial_MITMRejected(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	// Pin a DIFFERENT host key than the server actually uses.
	attacker := generateHostSigner(t)

	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := store.Add(context.Background(), &known_hosts.Pin{
		Host:        srv.host(),
		Fingerprint: keys.Fingerprint(attacker.PublicKey()),
		Algorithm:   attacker.PublicKey().Type(),
		PublicKey:   attacker.PublicKey().Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("add pin: %v", err)
	}

	clientKey := generateClientKey(t)
	defer clientKey.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = session.Dial(ctx, session.DialRequest{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         3 * time.Second,
	})
	if err == nil {
		t.Fatal("expected MITM dial to fail")
	}
	// Under GODEBUG=fips140=only, the handshake's key exchange fails (see
	// requireHandshake) before the server's host key is ever checked
	// against the (deliberately wrong) pin this test targets, so the error
	// is a handshake failure, not *known_hosts.MismatchError.
	if !fips140.Enforced() {
		var mm *known_hosts.MismatchError
		if !errors.As(err, &mm) {
			t.Fatalf("expected MismatchError via errors.As, got %T: %v", err, err)
		}
	}
}

// TestDial_MissingKnownHost asserts Dial surfaces NotFoundError when
// no pin exists — no TOFU fallback.
func TestDial_MissingKnownHost(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	clientKey := generateClientKey(t)
	defer clientKey.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = session.Dial(ctx, session.DialRequest{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected dial without pin to fail")
	}
	// Under GODEBUG=fips140=only, the handshake's key exchange fails (see
	// requireHandshake) before the missing-pin check this test targets is
	// ever reached, so the error is a handshake failure, not
	// *known_hosts.NotFoundError.
	if !fips140.Enforced() {
		var nf *known_hosts.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("expected NotFoundError, got %T: %v", err, err)
		}
	}
}

// TestDial_ValidationFailures covers each required DialRequest field.
func TestDial_ValidationFailures(t *testing.T) {
	validKey := generateClientKey(t)
	defer validKey.Destroy()

	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	base := session.DialRequest{
		Host:            "127.0.0.1",
		User:            "x",
		Key:             validKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
	}
	cases := []struct {
		name    string
		mutate  func(*session.DialRequest)
		wantVal string
	}{
		{"no host", func(r *session.DialRequest) { r.Host = "" }, "Host"},
		{"no user", func(r *session.DialRequest) { r.User = "" }, "User"},
		{"no key", func(r *session.DialRequest) { r.Key = nil }, "Key"},
		{"no owner", func(r *session.DialRequest) { r.HostKeyOwner = "" }, "HostKeyOwner"},
		{"bad scope", func(r *session.DialRequest) { r.HostKeyScope = "bogus" }, "HostKeyScope"},
		{"no store", func(r *session.DialRequest) { r.KnownHostsStore = nil }, "KnownHostsStore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			_, err := session.Dial(context.Background(), r)
			var nie *session.NilInputError
			if !errors.As(err, &nie) {
				t.Fatalf("expected NilInputError, got %T: %v", err, err)
			}
			if nie.Field != tc.wantVal {
				t.Fatalf("wrong field: want %s, got %s", tc.wantVal, nie.Field)
			}
		})
	}
}

// TestClose_IsIdempotent asserts Close does not panic on a second call.
func TestClose_IsIdempotent(t *testing.T) {
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
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Key enclave should be destroyed — subsequent Open must fail.
	if _, oerr := clientKey.Material.Open(t.Context()); oerr == nil {
		// Material is nilled out after Destroy, so Open returns a
		// NilSecretError; the fact that we got an error at all
		// confirms the enclave was destroyed.
		t.Fatal("expected Open after Close to fail")
	}
}

// TestRunAfterClose rejects commands on a closed session.
func TestRunAfterClose(t *testing.T) {
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
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, err = sess.Run(ctx, "echo")
	var ce *session.ClosedError
	if !errors.As(err, &ce) {
		t.Fatalf("expected ClosedError, got %T: %v", err, err)
	}
}

// TestDial_ContextCancelledMidDial cancels a dial targeting a
// never-accepting listener — asserts we do not leak the enclave and
// do return a TimeoutError.
func TestDial_ContextCancelledMidDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// Pin a plausible key so we pass the known_hosts contract check —
	// the dial will fail before verification runs, so the pin never
	// matters.
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

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = session.Dial(ctx, session.DialRequest{
		Host:            "127.0.0.1",
		Port:            port,
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    scope.User,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected dial to fail")
	}
	// Accept either TimeoutError (context) or HandshakeError (deadline).
	var to *session.TimeoutError
	var hs *session.HandshakeError
	var de *session.DialError
	if !errors.As(err, &to) && !errors.As(err, &hs) && !errors.As(err, &de) {
		t.Fatalf("expected timeout/handshake/dial error, got %T: %v", err, err)
	}
}
