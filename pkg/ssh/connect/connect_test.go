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

package connect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func testHostPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	return sshPub
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestStart_ArgsEnvAndSeed(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())
	// Pre-pin the target so it is seeded into the known_hosts file.
	if err := store.Add(ctx, known_hosts.PinFromPublicKey("server.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceManual)); err != nil {
		t.Fatalf("Add pin: %v", err)
	}

	sess, err := Start(ctx, Request{
		Host:            "server.example.com",
		Port:            2222,
		User:            "deploy",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.SyncAndStop()

	if !contains(sess.Args, "deploy@server.example.com") {
		t.Fatalf("args missing target: %v", sess.Args)
	}
	if !contains(sess.Args, "IdentitiesOnly=yes") {
		t.Fatalf("args missing IdentitiesOnly: %v", sess.Args)
	}
	if !contains(sess.Args, "-p") || !contains(sess.Args, "2222") {
		t.Fatalf("args missing port: %v", sess.Args)
	}
	var hasKH bool
	for _, a := range sess.Args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			hasKH = true
		}
	}
	if !hasKH {
		t.Fatalf("args missing UserKnownHostsFile: %v", sess.Args)
	}
	if len(sess.Env) != 1 || !strings.HasPrefix(sess.Env[0], "SSH_AUTH_SOCK=") {
		t.Fatalf("unexpected env: %v", sess.Env)
	}

	// The agent socket exists and the seeded known_hosts holds the pin.
	sock := strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")
	if _, statErr := os.Stat(sock); statErr != nil {
		t.Fatalf("agent socket not present: %v", statErr)
	}
	body, _ := os.ReadFile(sess.knownHostsFile)
	if !strings.Contains(string(body), "server.example.com ssh-ed25519 ") {
		t.Fatalf("known_hosts not seeded: %q", body)
	}
}

func TestStart_SyncBackImportsNewHost(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())

	sess, err := Start(ctx, Request{
		Host:            "fresh.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Simulate the native ssh client accepting a new host and appending it.
	line, _ := known_hosts.Emit(known_hosts.PinFromPublicKey("fresh.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceFirstContact))
	f, _ := os.OpenFile(sess.knownHostsFile, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(line + "\n")
	_ = f.Close()

	added, err := sess.SyncAndStop()
	if err != nil {
		t.Fatalf("SyncAndStop: %v", err)
	}
	if added != 1 {
		t.Fatalf("expected 1 host pinned back, got %d", added)
	}
	if _, gerr := store.Get(ctx, scope.User, "alice", "fresh.example.com"); gerr != nil {
		t.Fatalf("host not pinned after sync: %v", gerr)
	}
}

func TestStart_Validation(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())
	if _, err := Start(ctx, Request{Signer: testSigner(t), KnownHostsStore: store}); err == nil {
		t.Fatal("expected error for missing host")
	}
	if _, err := Start(ctx, Request{Host: "h", KnownHostsStore: store}); err == nil {
		t.Fatal("expected error for missing signer")
	}
	if _, err := Start(ctx, Request{Host: "h", Signer: testSigner(t)}); err == nil {
		t.Fatal("expected error for missing known_hosts store")
	}
}
