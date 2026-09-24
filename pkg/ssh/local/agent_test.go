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

package local_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/local"
)

// newTestEd25519Key generates a fresh ed25519 key pair, returning both the
// ssh.PublicKey (for match/mismatch assertions) and the raw private key
// (for adding to an x/crypto/ssh/agent.Keyring).
func newTestEd25519Key(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub, priv
}

// serveTestAgent serves keyring on a fresh unix socket under t.TempDir()
// until the test ends, mirroring pkg/ssh/agent/agent_test.go's harness but
// against the reference golang.org/x/crypto/ssh/agent.Keyring rather than
// this repo's own read-only agent.Agent (DialAgent is a generic ssh-agent
// client and must work against any RFC-conformant agent implementation).
func serveTestAgent(t *testing.T, keyring sshagent.Agent) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = sshagent.ServeAgent(keyring, c)
			}(conn)
		}
	}()

	return sock
}

// TestSignerForPublicKey_Match covers the success path: the agent holds a
// signer for the requested public key, and that signer produces a
// signature verifiable against the same public key.
func TestSignerForPublicKey_Match(t *testing.T) {
	pub, priv := newTestEd25519Key(t)
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	sock := serveTestAgent(t, keyring)

	signer, err := local.SignerForPublicKey(sock, pub)
	if err != nil {
		t.Fatalf("SignerForPublicKey: %v", err)
	}
	if signer.PublicKey().Type() != pub.Type() {
		t.Fatalf("signer public key type = %q, want %q", signer.PublicKey().Type(), pub.Type())
	}

	msg := []byte("authenticate me")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := pub.Verify(msg, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

// TestSignerForPublicKey_NotFound covers the branch where the agent is
// reachable but does not hold the requested key.
func TestSignerForPublicKey_NotFound(t *testing.T) {
	_, servedPriv := newTestEd25519Key(t)
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: servedPriv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	sock := serveTestAgent(t, keyring)

	requested, _ := newTestEd25519Key(t)
	_, err := local.SignerForPublicKey(sock, requested)
	var notFound *local.AgentKeyNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *AgentKeyNotFoundError, got %T: %v", err, err)
	}
}

// TestDialAgent_EmptyPath covers the empty-socket-path AgentUnavailableError
// branch.
func TestDialAgent_EmptyPath(t *testing.T) {
	_, err := local.DialAgent("")
	var unavailable *local.AgentUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *AgentUnavailableError, got %T: %v", err, err)
	}
	if !errors.Is(err, local.ErrNoAgentSocket) {
		t.Fatalf("expected err to wrap ErrNoAgentSocket, got %v", err)
	}
}

// TestDialAgent_BadPath covers the dial-failure AgentUnavailableError
// branch: a socket path with nothing listening on it.
func TestDialAgent_BadPath(t *testing.T) {
	_, err := local.DialAgent(filepath.Join(t.TempDir(), "no-such-agent.sock"))
	var unavailable *local.AgentUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *AgentUnavailableError, got %T: %v", err, err)
	}
}

// TestDialAgent_ProtocolFailure covers the branch distinct from a dial
// failure: the socket is listening, but the peer does not speak the
// ssh-agent protocol, so the client's initial Signers() request fails.
func TestDialAgent_ProtocolFailure(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "not-an-agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		// Garbage instead of a valid agent-protocol response — the
		// client's Signers() request will fail to parse it.
		_, _ = conn.Write([]byte{0xff, 0xff, 0xff, 0xff})
		time.Sleep(10 * time.Millisecond)
	}()

	_, err = local.DialAgent(sock)
	var unavailable *local.AgentUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *AgentUnavailableError, got %T: %v", err, err)
	}
}

// TestSignerForPublicKey_NilPublicKey covers the nil-input guard.
func TestSignerForPublicKey_NilPublicKey(t *testing.T) {
	_, err := local.SignerForPublicKey("irrelevant", nil)
	var nilErr *local.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T: %v", err, err)
	}
}
