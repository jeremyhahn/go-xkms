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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/local"
)

// generatePEM produces a fresh, unencrypted OpenSSH private-key PEM plus
// its ssh.PublicKey.
func generatePEM(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return pem.EncodeToMemory(block), sshPub
}

// generateEncryptedPEM produces a fresh, passphrase-encrypted OpenSSH
// private-key PEM.
func generateEncryptedPEM(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", passphrase)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// TestResolveSigner_AgentPreferred proves the agent path wins over the
// file path when both are available: the on-disk file is deliberately
// corrupt, so a successful, verifiable signature can only have come from
// the agent.
func TestResolveSigner_AgentPreferred(t *testing.T) {
	agentPub, agentPriv := newTestEd25519Key(t)
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: agentPriv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	sock := serveTestAgent(t, keyring)

	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, []byte("not a real PEM file"), 0o600); err != nil {
		t.Fatalf("write corrupt key file: %v", err)
	}

	identity := &local.Identity{Path: path, PublicKey: agentPub}
	signer, err := local.ResolveSigner(context.Background(), identity, sock)
	if err != nil {
		t.Fatalf("ResolveSigner: %v", err)
	}

	msg := []byte("authenticate me")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := agentPub.Verify(msg, sig); err != nil {
		t.Fatalf("signature did not verify against the agent's key: %v", err)
	}
}

// TestResolveSigner_AgentMissesFallsBackToFile proves that when the agent
// is reachable but does not hold the requested key, ResolveSigner falls
// back to the (valid, unencrypted) file instead of failing outright, and
// the file's signer produces signatures that verify against its key.
func TestResolveSigner_AgentMissesFallsBackToFile(t *testing.T) {
	_, otherPriv := newTestEd25519Key(t)
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: otherPriv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	sock := serveTestAgent(t, keyring)

	dir := t.TempDir()
	pemBytes, pub := generatePEM(t)
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	identity := &local.Identity{Path: path, PublicKey: pub}
	signer, err := local.ResolveSigner(context.Background(), identity, sock)
	if err != nil {
		t.Fatalf("ResolveSigner: %v", err)
	}
	if string(signer.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Fatal("signer public key does not match the on-disk key")
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

// TestResolveSigner_EncryptedWithoutAgent verifies keys.ParsePEM's
// *keys.PassphraseRequiredError passes through ResolveSigner unchanged
// when the identity is encrypted and no agent is configured.
func TestResolveSigner_EncryptedWithoutAgent(t *testing.T) {
	dir := t.TempDir()
	pemBytes := generateEncryptedPEM(t, []byte("hunter2"))
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	identity := &local.Identity{Path: path}
	_, err := local.ResolveSigner(context.Background(), identity, "")
	var passReq *keys.PassphraseRequiredError
	if !errors.As(err, &passReq) {
		t.Fatalf("expected *keys.PassphraseRequiredError, got %T: %v", err, err)
	}
}

// TestResolveSigner_NilIdentity covers the nil-input guard.
func TestResolveSigner_NilIdentity(t *testing.T) {
	_, err := local.ResolveSigner(context.Background(), nil, "")
	var nilErr *local.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T: %v", err, err)
	}
}

// TestResolveSigner_MissingFile covers the *IdentityReadError branch when
// the private-key file cannot be read.
func TestResolveSigner_MissingFile(t *testing.T) {
	identity := &local.Identity{Path: filepath.Join(t.TempDir(), "does-not-exist")}
	_, err := local.ResolveSigner(context.Background(), identity, "")
	var readErr *local.IdentityReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("expected *IdentityReadError, got %T: %v", err, err)
	}
}
