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

package services

// End-to-end tests for the embedded SSH console exactly as the GUI drives
// it: a FRESH SSHConsoleService (default policies, empty pin store),
// OpenConsole, then a real WebSocket client bridging to a real in-process
// SSH server. These exist because unit tests that pre-pinned the host (or
// set policies explicitly) missed the first-contact regression where the
// service's strict default hard-failed every connection on a fresh install.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// echoSSHTestServer is a minimal in-process SSH server accepting any public
// key and echoing session stdin back to stdout.
type echoSSHTestServer struct {
	ln   net.Listener
	host string
	port int
}

func startEchoSSHTestServer(t *testing.T) *echoSSHTestServer {
	return startEchoSSHTestServerOn(t, "127.0.0.1")
}

// startEchoSSHTestServerOn binds a specific loopback IP. Concurrent-session
// tests give each server its own IP: host-key pins are keyed by host (not
// host:port), so two servers with fresh keys on one IP would be a pin
// MISMATCH — a hard failure by design, not a test-ordering quirk.
func startEchoSSHTestServerOn(t *testing.T, ip string) *echoSSHTestServer {
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

	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)

	s := &echoSSHTestServer{ln: ln, host: addr.IP.String(), port: addr.Port}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go s.handle(conn, cfg)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *echoSSHTestServer) handle(conn net.Conn, cfg *ssh.ServerConfig) {
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
			defer ch.Close()
			for req := range in {
				switch req.Type {
				case "pty-req", "shell", "window-change":
					_ = req.Reply(true, nil)
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(channel, requests)
		go func(ch ssh.Channel) {
			buf := make([]byte, 1024)
			for {
				n, rerr := ch.Read(buf)
				if n > 0 {
					if _, werr := ch.Write(buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					return
				}
			}
		}(channel)
	}
}

// wsFrame is a decoded control TEXT frame from the console WebSocket.
type wsFrame struct {
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	Message     string `json:"message"`
	Fingerprint string `json:"fingerprint"`
}

// dialConsoleWS connects a WebSocket client to an OpenConsole endpoint URL.
func dialConsoleWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("ws dial %s: %v", url, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	return conn
}

// readTextFrame reads WebSocket messages until the next TEXT control frame.
func readTextFrame(t *testing.T, conn *websocket.Conn) wsFrame {
	t.Helper()
	for i := 0; i < 50; i++ {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("ws read: %v", err)
		}
		if mt != websocket.TextMessage {
			continue
		}
		var f wsFrame
		if jerr := json.Unmarshal(data, &f); jerr != nil {
			t.Fatalf("bad control frame %q: %v", data, jerr)
		}
		return f
	}
	t.Fatal("no TEXT control frame received")
	return wsFrame{}
}

// expectEcho writes marker over the console and reads until it echoes back.
func expectEcho(t *testing.T, conn *websocket.Conn, marker string) {
	t.Helper()
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte(marker+"\n")); err != nil {
		t.Fatalf("ws write: %v", err)
	}
	var got strings.Builder
	for i := 0; i < 50; i++ {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("ws read echo: %v (so far %q)", err, got.String())
		}
		if mt == websocket.BinaryMessage {
			got.Write(data)
			if strings.Contains(got.String(), marker) {
				return
			}
		}
	}
	t.Fatalf("echo %q not received, got %q", marker, got.String())
}

// TestSSHConsoleE2E_FirstContact_ManagedKey_AskAcceptFlow drives the exact
// GUI flow on a FRESH install: default policies, empty pin store, an
// xkey-managed key, an unknown host. The service must raise the TOFU
// "hostkey" confirm prompt (NOT hard-fail), and accepting it must yield a
// live shell. A second connection then verifies silently against the pin
// recorded on accept.
func TestSSHConsoleE2E_FirstContact_ManagedKey_AskAcceptFlow(t *testing.T) {
	srv := startEchoSSHTestServer(t)
	svc := setupConsole(t) // fresh service — deliberately no policy overrides
	defer svc.Shutdown()

	ep, err := svc.OpenConsole(SSHConnectParams{
		Host: srv.host, Port: srv.port, User: "tester", KeyName: "laptop",
	})
	if err != nil {
		t.Fatalf("OpenConsole: %v", err)
	}

	conn := dialConsoleWS(t, ep.URL)
	frame := readTextFrame(t, conn)
	if frame.Type != "hostkey" || frame.Mode != "confirm" {
		t.Fatalf("expected first-contact hostkey confirm prompt, got %+v", frame)
	}
	if frame.Fingerprint == "" {
		t.Fatalf("hostkey prompt missing fingerprint: %+v", frame)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"hostkey-response","accept":true}`)); err != nil {
		t.Fatalf("write hostkey-response: %v", err)
	}
	expectEcho(t, conn, "xkey-e2e-first-contact")

	// Second connection: the accepted key is pinned, so the session opens
	// with no prompt at all.
	ep2, err := svc.OpenConsole(SSHConnectParams{
		Host: srv.host, Port: srv.port, User: "tester", KeyName: "laptop",
	})
	if err != nil {
		t.Fatalf("OpenConsole (pinned): %v", err)
	}
	conn2 := dialConsoleWS(t, ep2.URL)
	expectEcho(t, conn2, "xkey-e2e-pinned-reconnect")
}

// TestSSHConsoleE2E_FirstContact_Reject verifies rejecting the fingerprint
// prompt fails the session with an error frame instead of connecting.
func TestSSHConsoleE2E_FirstContact_Reject(t *testing.T) {
	srv := startEchoSSHTestServer(t)
	svc := setupConsole(t)
	defer svc.Shutdown()

	ep, err := svc.OpenConsole(SSHConnectParams{
		Host: srv.host, Port: srv.port, User: "tester", KeyName: "laptop",
	})
	if err != nil {
		t.Fatalf("OpenConsole: %v", err)
	}
	conn := dialConsoleWS(t, ep.URL)
	frame := readTextFrame(t, conn)
	if frame.Type != "hostkey" || frame.Mode != "confirm" {
		t.Fatalf("expected hostkey confirm prompt, got %+v", frame)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"hostkey-response","accept":false}`)); err != nil {
		t.Fatalf("write hostkey-response: %v", err)
	}
	errFrame := readTextFrame(t, conn)
	if errFrame.Type != "error" {
		t.Fatalf("expected error frame after reject, got %+v", errFrame)
	}
}

// TestSSHConsoleE2E_StrictPolicy_FirstContactFails documents the strict
// ("yes") policy: an unpinned host fails with an error frame and no prompt.
func TestSSHConsoleE2E_StrictPolicy_FirstContactFails(t *testing.T) {
	srv := startEchoSSHTestServer(t)
	svc := setupConsole(t)
	defer svc.Shutdown()
	svc.SetHostKeyPolicy("yes")

	ep, err := svc.OpenConsole(SSHConnectParams{
		Host: srv.host, Port: srv.port, User: "tester", KeyName: "laptop",
	})
	if err != nil {
		t.Fatalf("OpenConsole: %v", err)
	}
	conn := dialConsoleWS(t, ep.URL)
	frame := readTextFrame(t, conn)
	if frame.Type != "error" {
		t.Fatalf("expected strict-policy error frame, got %+v", frame)
	}
}

// TestSSHConsoleE2E_NoKey_AgentSigner_AskAcceptFlow drives the full
// "No key" GUI flow: no managed key, identities resolved from the system
// agent, first-contact prompt accepted, live shell echo.
func TestSSHConsoleE2E_NoKey_AgentSigner_AskAcceptFlow(t *testing.T) {
	srv := startEchoSSHTestServer(t)
	svc := setupConsole(t)
	defer svc.Shutdown()

	t.Setenv("HOME", t.TempDir()) // no ~/.ssh — the agent is the only source
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, keyring))

	ep, err := svc.OpenConsole(SSHConnectParams{Host: srv.host, Port: srv.port, User: "tester"})
	if err != nil {
		t.Fatalf("OpenConsole (no key): %v", err)
	}
	conn := dialConsoleWS(t, ep.URL)
	frame := readTextFrame(t, conn)
	if frame.Type != "hostkey" || frame.Mode != "confirm" {
		t.Fatalf("expected hostkey confirm prompt, got %+v", frame)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"hostkey-response","accept":true}`)); err != nil {
		t.Fatalf("write hostkey-response: %v", err)
	}
	expectEcho(t, conn, "xkey-e2e-no-key-agent")
}

// TestSSHConsoleE2E_ConcurrentSessions proves the service supports multiple
// simultaneous embedded sessions — the backend contract behind the GUI's
// console tabs: two independent WebSocket sessions to two servers, both live
// at once, each echoing only its own bytes, and closing one leaves the
// other running.
func TestSSHConsoleE2E_ConcurrentSessions(t *testing.T) {
	srvA := startEchoSSHTestServerOn(t, "127.0.0.1")
	srvB := startEchoSSHTestServerOn(t, "127.0.0.2")
	svc := setupConsole(t)
	defer svc.Shutdown()
	svc.SetHostKeyPolicy("accept-new") // exercise concurrency, not TOFU

	open := func(srv *echoSSHTestServer) *websocket.Conn {
		ep, err := svc.OpenConsole(SSHConnectParams{
			Host: srv.host, Port: srv.port, User: "tester", KeyName: "laptop",
		})
		if err != nil {
			t.Fatalf("OpenConsole: %v", err)
		}
		return dialConsoleWS(t, ep.URL)
	}

	connA := open(srvA)
	connB := open(srvB)

	// Both sessions are live simultaneously and independent.
	expectEcho(t, connA, "tab-a-first")
	expectEcho(t, connB, "tab-b-first")
	expectEcho(t, connA, "tab-a-second")

	// Closing A must not disturb B.
	_ = connA.Close()
	expectEcho(t, connB, "tab-b-after-a-closed")
}

// TestSSHConsole_TicketTTLPurge verifies abandoned (issued but never
// connected) tickets are purged after consoleTicketTTL, while fresh tickets
// survive.
func TestSSHConsole_TicketTTLPurge(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	stale, err := svc.OpenConsole(SSHConnectParams{Host: "h", User: "u", KeyName: "laptop"})
	if err != nil {
		t.Fatalf("OpenConsole (stale): %v", err)
	}
	svc.mu.Lock()
	svc.tickets[stale.Token].created = time.Now().Add(-consoleTicketTTL - time.Second)
	svc.mu.Unlock()

	fresh, err := svc.OpenConsole(SSHConnectParams{Host: "h", User: "u", KeyName: "laptop"})
	if err != nil {
		t.Fatalf("OpenConsole (fresh): %v", err)
	}

	svc.mu.Lock()
	_, staleOK := svc.tickets[stale.Token]
	_, freshOK := svc.tickets[fresh.Token]
	svc.mu.Unlock()
	if staleOK {
		t.Fatal("stale ticket should have been purged on the next issue")
	}
	if !freshOK {
		t.Fatal("fresh ticket must survive the purge")
	}
}
