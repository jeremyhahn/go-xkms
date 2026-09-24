// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// targetSSHServer is a minimal in-process SSH server used as the dial
// target for Session.Dial integration tests across every network
// transport (REST/QUIC, gRPC/unix, MCP). It authenticates any presented
// public key — the property under test is that the SDK's remote-signer
// proxy produces a genuine, verifiable signature over the auth challenge,
// not server-side authorization policy — and answers every "exec" request
// by echoing the command back on stdout with a zero exit status.
type targetSSHServer struct {
	listener net.Listener
	signer   gossh.Signer
	wg       sync.WaitGroup
}

// newTargetSSHServer starts the server on an ephemeral loopback port and
// registers its teardown with t.Cleanup.
func newTargetSSHServer(t *testing.T) *targetSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &targetSSHServer{listener: ln, signer: hostSigner}
	srv.wg.Add(1)
	go srv.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		srv.wg.Wait()
	})
	return srv
}

func (s *targetSSHServer) serve() {
	defer s.wg.Done()
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(s.signer)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn, cfg)
		}()
	}
}

func (s *targetSSHServer) handleConn(conn net.Conn, cfg *gossh.ServerConfig) {
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()
	go gossh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, requests, aerr := nc.Accept()
		if aerr != nil {
			continue
		}
		go func(ch gossh.Channel, rs <-chan *gossh.Request) {
			defer func() { _ = ch.Close() }()
			for req := range rs {
				if req.Type != "exec" {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					continue
				}
				cmd := parseExecPayload(req.Payload)
				_ = req.Reply(true, nil)
				_, _ = ch.Write([]byte("ran: " + cmd))
				_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}(ch, requests)
	}
}

// parseExecPayload decodes the SSH "exec" request payload: a uint32
// length prefix followed by the command string.
func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || 4+n > len(payload) {
		return ""
	}
	return string(payload[4 : 4+n])
}

// hostPort splits the listener address into (host, port) for
// SessionDialRequest.
func (s *targetSSHServer) hostPort() (string, int) {
	host, portStr, _ := net.SplitHostPort(s.listener.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

// authorizedKeyLine renders pub as an authorized_keys-format line, the
// wire form KnownHostsClient.Add expects.
func authorizedKeyLine(pub gossh.PublicKey) string {
	return strings.TrimRight(string(gossh.MarshalAuthorizedKey(pub)), "\n")
}

// decoyHostKeyLine returns a freshly generated, unrelated host public key
// line — used to pin the "wrong" host key for host-key-mismatch tests.
func decoyHostKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return authorizedKeyLine(sshPub)
}
