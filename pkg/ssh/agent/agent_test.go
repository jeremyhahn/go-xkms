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

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func newEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return s
}

func newRSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return s
}

// serveTestAgent starts the agent on a temp socket and returns a connected
// agent client plus a cleanup func.
func serveTestAgent(t *testing.T, signers ...ssh.Signer) (sshagent.ExtendedAgent, func()) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = Serve(ctx, sock, New(signers...)) }()

	// Wait for the socket to come up.
	var conn net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("unix", sock)
		if err == nil {
			conn = c
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn == nil {
		cancel()
		t.Fatal("agent socket never came up")
	}
	return sshagent.NewClient(conn), func() { _ = conn.Close(); cancel() }
}

func TestAgent_ListAndSign(t *testing.T) {
	signer := newEd25519Signer(t)
	client, cleanup := serveTestAgent(t, signer)
	defer cleanup()

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Type() != signer.PublicKey().Type() {
		t.Fatalf("key type mismatch: %s vs %s", keys[0].Type(), signer.PublicKey().Type())
	}

	msg := []byte("authenticate me")
	sig, err := client.Sign(signer.PublicKey(), msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

func TestAgent_RSASignWithFlags(t *testing.T) {
	signer := newRSASigner(t)
	client, cleanup := serveTestAgent(t, signer)
	defer cleanup()

	msg := []byte("rsa-sha2 please")
	sig, err := client.SignWithFlags(signer.PublicKey(), msg, sshagent.SignatureFlagRsaSha256)
	if err != nil {
		t.Fatalf("SignWithFlags: %v", err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("expected rsa-sha2-256 signature, got %s", sig.Format)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Fatalf("rsa-sha2-256 signature did not verify: %v", err)
	}
}

func TestAgent_ReadOnly(t *testing.T) {
	a := New(newEd25519Signer(t))
	if err := a.Add(sshagent.AddedKey{}); err != ErrUnsupported {
		t.Fatalf("Add should be unsupported, got %v", err)
	}
	if err := a.RemoveAll(); err != ErrUnsupported {
		t.Fatalf("RemoveAll should be unsupported, got %v", err)
	}
	if err := a.Lock(nil); err != ErrUnsupported {
		t.Fatalf("Lock should be unsupported, got %v", err)
	}
}

func TestAgent_SignUnknownKey(t *testing.T) {
	a := New(newEd25519Signer(t))
	other := newEd25519Signer(t)
	if _, err := a.Sign(other.PublicKey(), []byte("x")); err == nil {
		t.Fatal("expected error signing with an unknown key")
	}
}
