// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package sshlocal

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// newTestEd25519Key generates a fresh ed25519 key pair.
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
// until the test ends, mirroring pkg/ssh/local/agent_test.go's harness
// against the reference golang.org/x/crypto/ssh/agent implementation.
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

// writeIdentity writes a dummy private-key file (never parsed by
// ListLocalKeys) and a paired ".pub" file carrying pub with the given
// comment, under home/.ssh/name.
func writeIdentity(t *testing.T, home, name string, pub ssh.PublicKey, comment string) string {
	t.Helper()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	path := filepath.Join(sshDir, name)
	if err := os.WriteFile(path, []byte("dummy private key material"), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	line := string(ssh.MarshalAuthorizedKey(pub))
	line = line[:len(line)-1] + " " + comment + "\n"
	if err := os.WriteFile(path+".pub", []byte(line), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return path
}

func TestListLocalKeys_FileOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")

	pub, _ := newTestEd25519Key(t)
	writeIdentity(t, home, "id_ed25519", pub, "test@host")

	keys, err := ListLocalKeys()
	if err != nil {
		t.Fatalf("ListLocalKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %+v", keys)
	}
	k := keys[0]
	if k.Source != SourceFile {
		t.Fatalf("Source = %q, want %q", k.Source, SourceFile)
	}
	if filepath.Base(k.Path) != "id_ed25519" {
		t.Fatalf("Path = %q", k.Path)
	}
	if k.KeyType != "ssh-ed25519" {
		t.Fatalf("KeyType = %q", k.KeyType)
	}
	if k.Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if k.Comment != "test@host" {
		t.Fatalf("Comment = %q", k.Comment)
	}
}

func TestListLocalKeys_AgentDedupeAndAgentOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// sharedPub is discoverable both on disk (as an identity file) and via
	// the agent — it must be reported exactly once, as source "agent", with
	// Path/Comment filled in from the identity file.
	sharedPub, sharedPriv := newTestEd25519Key(t)
	writeIdentity(t, home, "id_ed25519", sharedPub, "shared@host")

	// agentOnlyPub has no identity file on disk at all.
	agentOnlyPub, agentOnlyPriv := newTestEd25519Key(t)

	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: sharedPriv}); err != nil {
		t.Fatalf("keyring.Add shared: %v", err)
	}
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: agentOnlyPriv}); err != nil {
		t.Fatalf("keyring.Add agent-only: %v", err)
	}
	sock := serveTestAgent(t, keyring)
	t.Setenv("SSH_AUTH_SOCK", sock)

	keys, err := ListLocalKeys()
	if err != nil {
		t.Fatalf("ListLocalKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (deduped), got %+v", keys)
	}

	byFingerprint := make(map[string]LocalKeyInfo, len(keys))
	for _, k := range keys {
		byFingerprint[k.Fingerprint] = k
	}

	shared, ok := byFingerprint[ssh.FingerprintSHA256(sharedPub)]
	if !ok {
		t.Fatalf("shared key missing from %+v", keys)
	}
	if shared.Source != SourceAgent {
		t.Fatalf("shared key Source = %q, want %q", shared.Source, SourceAgent)
	}
	if filepath.Base(shared.Path) != "id_ed25519" || shared.Comment != "shared@host" {
		t.Fatalf("shared key missing file metadata: %+v", shared)
	}

	agentOnly, ok := byFingerprint[ssh.FingerprintSHA256(agentOnlyPub)]
	if !ok {
		t.Fatalf("agent-only key missing from %+v", keys)
	}
	if agentOnly.Source != SourceAgent || agentOnly.Path != "" {
		t.Fatalf("unexpected agent-only entry: %+v", agentOnly)
	}
}

func TestListLocalKeys_NoAgentNoHome(t *testing.T) {
	// An empty HOME makes os.UserHomeDir() fail — both sources contribute
	// nothing, and that must not be an error.
	t.Setenv("HOME", "")
	t.Setenv("SSH_AUTH_SOCK", "")

	keys, err := ListLocalKeys()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no keys, got %+v", keys)
	}
}
