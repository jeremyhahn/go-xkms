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

package known_hosts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return sshPub
}

func TestEmit_RoundTripThroughStore(t *testing.T) {
	ctx := context.Background()
	store, err := NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	hostPub := testHostKey(t)

	pin := PinFromPublicKey("bastion.example.com", scope.User, "alice", hostPub, SourceManual)
	if err := store.Add(ctx, pin); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Pin reloaded from storage retains the public key and emits a line.
	got, err := store.Get(ctx, scope.User, "alice", "bastion.example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.PublicKey) == 0 {
		t.Fatal("reloaded pin lost its public key")
	}
	line, err := Emit(got)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !strings.HasPrefix(line, "bastion.example.com ssh-ed25519 ") {
		t.Fatalf("unexpected known_hosts line: %q", line)
	}
	// The emitted line must parse back to the same key.
	_, hosts, parsed, _, _, perr := ssh.ParseKnownHosts([]byte(line))
	if perr != nil {
		t.Fatalf("ParseKnownHosts(emitted): %v", perr)
	}
	if hosts[0] != "bastion.example.com" || ssh.FingerprintSHA256(parsed) != ssh.FingerprintSHA256(hostPub) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestEmitAll_AndImport_SyncBack(t *testing.T) {
	ctx := context.Background()
	src, _ := NewBackendStore(storage.New())
	for _, h := range []string{"a.example.com", "b.example.com"} {
		if err := src.Add(ctx, PinFromPublicKey(h, scope.User, "alice", testHostKey(t), SourceManual)); err != nil {
			t.Fatalf("Add %s: %v", h, err)
		}
	}

	// EmitAll → temp known_hosts file (simulating what we seed for ssh).
	body, err := EmitAll(ctx, src, scope.User, "alice")
	if err != nil {
		t.Fatalf("EmitAll: %v", err)
	}
	if strings.Count(string(body), "\n") != 2 {
		t.Fatalf("expected 2 lines, got: %q", body)
	}
	khFile := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(khFile, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// ImportKnownHostsFile into a fresh store (simulating sync-back).
	dst, _ := NewBackendStore(storage.New())
	added, err := ImportKnownHostsFile(ctx, dst, scope.User, "alice", khFile, SourceFirstContact)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if added != 2 {
		t.Fatalf("expected 2 imported, got %d", added)
	}
	// Re-import is idempotent (already pinned).
	again, err := ImportKnownHostsFile(ctx, dst, scope.User, "alice", khFile, SourceFirstContact)
	if err != nil {
		t.Fatalf("Import (2nd): %v", err)
	}
	if again != 0 {
		t.Fatalf("re-import should add 0, added %d", again)
	}
}

func TestEmit_FingerprintOnlyPinErrors(t *testing.T) {
	pin := &Pin{Host: "h", Fingerprint: "SHA256:abc", Scope: scope.User, Owner: "alice"}
	if _, err := Emit(pin); err == nil {
		t.Fatal("expected NoPublicKeyError for fingerprint-only pin")
	}
}

// failingGetStore answers every pin lookup with a non-NotFound error, standing
// in for a store that has stopped working rather than one that simply has no
// pin yet.
type failingGetStore struct {
	Store
	err error
}

func (f *failingGetStore) Get(context.Context, scope.Scope, string, string) (*Pin, error) {
	return nil, f.err
}

// TestImportKnownHostsFile_FailsClosedOnStoreError covers the fail-open this
// loop used to have: any Get error read as "not pinned yet", any Add error read
// as "nothing to do". A broken store therefore reported a clean import of zero
// hosts — and these are first-contact host keys, so silently dropping them
// leaves the next connection unpinned, which is what the pin store exists to
// prevent.
func TestImportKnownHostsFile_FailsClosedOnStoreError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	line, _ := Emit(PinFromPublicKey("host.example.com", scope.User, "alice", testHostKey(t), SourceFirstContact))
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	base, _ := NewBackendStore(storage.New())
	broken := &failingGetStore{Store: base, err: errors.New("store is down")}

	added, err := ImportKnownHostsFile(context.Background(), broken, scope.User, "alice", path, SourceFirstContact)
	if err == nil {
		t.Fatal("a broken store must fail the import, not report a clean zero")
	}
	if added != 0 {
		t.Fatalf("nothing should have been pinned, got %d", added)
	}
}

// TestImportKnownHostsFile_CancelledContextIsNotAnEmptyStore is the same
// property for the case this branch made reachable: Sync now runs under a
// deadline, and a context error must never read as "no pin exists".
func TestImportKnownHostsFile_CancelledContextIsNotAnEmptyStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	line, _ := Emit(PinFromPublicKey("host.example.com", scope.User, "alice", testHostKey(t), SourceFirstContact))
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	base, _ := NewBackendStore(storage.New())
	broken := &failingGetStore{Store: base, err: context.DeadlineExceeded}

	added, err := ImportKnownHostsFile(context.Background(), broken, scope.User, "alice", path, SourceFirstContact)
	if err == nil {
		t.Fatal("an expired context must fail the import, not report a clean zero")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the cause must stay reachable, got %v", err)
	}
	if added != 0 {
		t.Fatalf("nothing should have been pinned, got %d", added)
	}
}
