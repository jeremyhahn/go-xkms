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

package console

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// echoSSHServer is an in-process SSH server that grants a PTY and echoes
// everything typed back to the terminal — a stand-in for a remote shell.
type echoSSHServer struct {
	ln      net.Listener
	hostPub ssh.PublicKey
	host    string
	port    int
}

func startEchoSSHServer(t *testing.T) *echoSSHServer {
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
			return &ssh.Permissions{}, nil // accept any key for the test
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

	s := &echoSSHServer{ln: ln, hostPub: hostSigner.PublicKey(), host: host, port: port}
	go s.serve(cfg)
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *echoSSHServer) serve(cfg *ssh.ServerConfig) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn, cfg)
	}
}

func (s *echoSSHServer) handle(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
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
		go func(ch ssh.Channel, in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "pty-req", "window-change", "env":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					go func() {
						_, _ = io.Copy(ch, ch) // echo stdin → stdout
						_ = ch.Close()
					}()
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(channel, requests)
	}
}

// fmtSscan is a tiny wrapper to avoid importing fmt just for Sscan.
func fmtSscan(s string, p *int) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	*p = n
	return 1, nil
}

func clientSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	return signer
}

func pinnedHosts(t *testing.T, host string, hostPub ssh.PublicKey) known_hosts.Store {
	t.Helper()
	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}
	if err := store.Add(context.Background(), known_hosts.PinFromPublicKey(host, scope.User, "tester", hostPub, known_hosts.SourceManual)); err != nil {
		t.Fatalf("pin host: %v", err)
	}
	return store
}

func TestConsole_DialEchoResizeClose(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := pinnedHosts(t, srv.host, srv.hostPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := Dial(ctx, DialRequest{
		Host:         srv.host,
		Port:         srv.port,
		User:         "tester",
		Signer:       clientSigner(t),
		KnownHosts:   store,
		HostKeyScope: scope.User,
		HostKeyOwner: "tester",
	}, Config{Term: "xterm-256color", Rows: 30, Cols: 100})
	if !requireHandshake(t, err) {
		return
	}
	defer c.Close()

	// Resize must succeed against a live PTY.
	if err := c.Resize(40, 120); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	// Type a line; the echo server returns it.
	if _, err := c.Write([]byte("hello world\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reader := bufio.NewReader(c)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !strings.Contains(line, "hello world") {
		t.Fatalf("echo mismatch: %q", line)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Resize after close must fail cleanly.
	if err := c.Resize(10, 10); err == nil {
		t.Fatal("expected error resizing a closed console")
	}
}

func TestConsole_DialValidation(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())
	if _, err := Dial(ctx, DialRequest{Host: "h", KnownHosts: store}, Config{}); err == nil {
		t.Fatal("expected error for missing signer")
	}
	if _, err := Dial(ctx, DialRequest{Host: "h", Signer: clientSigner(t)}, Config{}); err == nil {
		t.Fatal("expected error for missing known_hosts")
	}
}

func TestConsole_HostKeyMismatchRejected(t *testing.T) {
	srv := startEchoSSHServer(t)
	// Pin a DIFFERENT host key so verification must fail.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)
	store := pinnedHosts(t, srv.host, otherSigner.PublicKey())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, DialRequest{
		Host: srv.host, Port: srv.port, User: "tester",
		Signer: clientSigner(t), KnownHosts: store,
		HostKeyScope: scope.User, HostKeyOwner: "tester",
	}, Config{}); err == nil {
		t.Fatal("expected host-key verification failure")
	}
}
