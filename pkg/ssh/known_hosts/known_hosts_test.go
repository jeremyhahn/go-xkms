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

package known_hosts_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newStore returns a BackendStore wired to an in-memory storage.Backend.
func newStore(t *testing.T) *known_hosts.BackendStore {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	s, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s
}

// newEd25519PublicKey returns a random ed25519 ssh.PublicKey for tests.
func newEd25519PublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}

// newECDSAP256PublicKey returns a random ecdsa-p256 ssh.PublicKey.
func newECDSAP256PublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}

// TestStore_AddGetListRemove is the happy-path round-trip table test.
func TestStore_AddGetListRemove(t *testing.T) {
	cases := []struct {
		name  string
		scope scope.Scope
		owner string
		host  string
		pubFn func(t *testing.T) ssh.PublicKey
	}{
		{"user-ed25519", scope.User, "alice", "bastion.example.com", newEd25519PublicKey},
		{"tenant-ecdsa", scope.Tenant, "acme-corp", "build-01.internal", newECDSAP256PublicKey},
		{"service-ipv4", scope.Service, "ci-runner", "10.0.0.5", newEd25519PublicKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			ctx := context.Background()
			pub := tc.pubFn(t)
			pin := &known_hosts.Pin{
				Host:        tc.host,
				Fingerprint: keys.Fingerprint(pub),
				Algorithm:   pub.Type(),
				PublicKey:   pub.Marshal(),
				Scope:       tc.scope,
				Owner:       tc.owner,
				AddedAt:     time.Now().UTC(),
				Source:      known_hosts.SourceManual,
			}
			if err := store.Add(ctx, pin); err != nil {
				t.Fatalf("Add: %v", err)
			}

			got, err := store.Get(ctx, tc.scope, tc.owner, tc.host)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Fingerprint != pin.Fingerprint {
				t.Fatalf("fingerprint mismatch: want %s, got %s", pin.Fingerprint, got.Fingerprint)
			}
			if got.Algorithm != pin.Algorithm {
				t.Fatalf("algorithm mismatch: want %s, got %s", pin.Algorithm, got.Algorithm)
			}
			if got.Source != pin.Source {
				t.Fatalf("source mismatch: want %s, got %s", pin.Source, got.Source)
			}

			list, err := store.List(ctx, tc.scope, tc.owner)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(list) != 1 {
				t.Fatalf("expected 1 pin, got %d", len(list))
			}

			if err := store.Remove(ctx, tc.scope, tc.owner, tc.host); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			_, err = store.Get(ctx, tc.scope, tc.owner, tc.host)
			var notFound *known_hosts.NotFoundError
			if !errors.As(err, &notFound) {
				t.Fatalf("expected NotFoundError after Remove, got %T: %v", err, err)
			}
		})
	}
}

// TestStore_DuplicateAdd verifies the non-idempotent Add contract.
func TestStore_DuplicateAdd(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)
	pin := &known_hosts.Pin{
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		Algorithm:   pub.Type(),
		PublicKey:   pub.Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
		Source:      known_hosts.SourceManual,
	}
	if err := store.Add(ctx, pin); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err := store.Add(ctx, pin)
	var dup *known_hosts.DuplicateError
	if !errors.As(err, &dup) {
		t.Fatalf("expected DuplicateError, got %T: %v", err, err)
	}
}

// TestStore_RemoveMissing confirms Remove surfaces NotFoundError.
func TestStore_RemoveMissing(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	err := store.Remove(ctx, scope.User, "alice", "ghost.example.com")
	var notFound *known_hosts.NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected NotFoundError, got %T: %v", err, err)
	}
}

// TestValidateHost_Rejections documents the full set of rejection cases
// in one place — additions must keep this table exhaustive.
func TestValidateHost_Rejections(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{"empty", ""},
		{"path separator", "a/b"},
		{"nul byte", "host\x00"},
		{"single dot", "."},
		{"double dot", ".."},
		{"traversal segment", "foo/../etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := known_hosts.ValidateHost(tc.host)
			var inv *known_hosts.InvalidHostError
			if !errors.As(err, &inv) {
				t.Fatalf("expected InvalidHostError for %q, got %T: %v", tc.host, err, err)
			}
		})
	}
}

// TestValidateFingerprint rejects well-known malformed inputs.
func TestValidateFingerprint(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", keys.Fingerprint(newEd25519PublicKey(t)), false},
		{"valid ssh-keygen form", "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", false},
		{"empty", "", true},
		{"no prefix", "abcdef", true},
		{"prefix only", "SHA256:", true},
		{"not base64", "SHA256:***not-base64***", true},
		// A body that decodes cleanly but to something other than a
		// 32-byte digest cannot be a SHA-256 host-key fingerprint.
		{"three-byte digest", "SHA256:AAAA", true},
		{"one-byte digest", "SHA256:AA", true},
		{"31-byte digest", "SHA256:" + strings.Repeat("A", 41) + "Q", true},
		{"33-byte digest", "SHA256:" + strings.Repeat("A", 44), true},
		{"41-byte digest", "SHA256:" + strings.Repeat("A", 55), true},
		// OpenSSH strips padding and uses the standard alphabet; a
		// padded or URL-safe body is not the form it prints.
		{"padded body", "SHA256:" + strings.Repeat("A", 42) + "E=", true},
		{"url-safe alphabet", "SHA256:" + strings.Repeat("-", 42) + "E", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := known_hosts.ValidateFingerprint(tc.input)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			var inv *known_hosts.InvalidFingerprintError
			if !errors.As(err, &inv) {
				t.Fatalf("expected InvalidFingerprintError for %q, got %T: %v", tc.input, err, err)
			}
		})
	}
}

// TestStoreAdd_RejectsShortFingerprint proves the store refuses a
// hand-built pin whose fingerprint decodes to fewer than 32 bytes.
func TestStoreAdd_RejectsShortFingerprint(t *testing.T) {
	store := newStore(t)
	err := store.Add(context.Background(), &known_hosts.Pin{
		Host:        "bastion.example.com",
		Fingerprint: "SHA256:AAAA",
		Algorithm:   "ssh-ed25519",
		Scope:       scope.Tenant,
		Owner:       "tenant-1",
	})
	if err == nil {
		t.Fatal("expected Add to reject a 3-byte digest fingerprint")
	}
	var inv *known_hosts.InvalidFingerprintError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidFingerprintError, got %T: %v", err, err)
	}
}

// TestVerify_Match returns nil when the received key matches the pin.
func TestVerify_Match(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)
	if err := store.Add(ctx, &known_hosts.Pin{
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		Algorithm:   pub.Type(),
		PublicKey:   pub.Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := known_hosts.Verify(ctx, store, scope.User, "alice", "bastion.example.com", pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerify_Mismatch is the MITM detection path.
func TestVerify_Mismatch(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	legit := newEd25519PublicKey(t)
	mitm := newEd25519PublicKey(t)
	if err := store.Add(ctx, &known_hosts.Pin{
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(legit),
		Algorithm:   legit.Type(),
		PublicKey:   legit.Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	err := known_hosts.Verify(ctx, store, scope.User, "alice", "bastion.example.com", mitm)
	var mm *known_hosts.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected MismatchError, got %T: %v", err, err)
	}
	if mm.Expected != keys.Fingerprint(legit) {
		t.Fatalf("expected field wrong: %s", mm.Expected)
	}
	if mm.Received != keys.Fingerprint(mitm) {
		t.Fatalf("received field wrong: %s", mm.Received)
	}
}

// TestVerify_NotFound returns NotFoundError when no pin exists.
func TestVerify_NotFound(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)
	err := known_hosts.Verify(ctx, store, scope.User, "alice", "ghost.example.com", pub)
	var nf *known_hosts.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError, got %T: %v", err, err)
	}
}

// TestCallback_Match installs the callback and confirms it returns nil.
func TestCallback_Match(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	pub := newEd25519PublicKey(t)
	if err := store.Add(ctx, &known_hosts.Pin{
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(pub),
		Algorithm:   pub.Type(),
		PublicKey:   pub.Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	cb := known_hosts.Callback(ctx, store, scope.User, "alice")
	// x/crypto/ssh passes "<host>:<port>" as hostname.
	if err := cb("bastion.example.com:22", &net.TCPAddr{}, pub); err != nil {
		t.Fatalf("callback: %v", err)
	}
}

// TestCallback_Mismatch confirms the callback surfaces MismatchError.
func TestCallback_Mismatch(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	legit := newEd25519PublicKey(t)
	mitm := newEd25519PublicKey(t)
	if err := store.Add(ctx, &known_hosts.Pin{
		Host:        "bastion.example.com",
		Fingerprint: keys.Fingerprint(legit),
		Algorithm:   legit.Type(),
		PublicKey:   legit.Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	cb := known_hosts.Callback(ctx, store, scope.User, "alice")
	err := cb("bastion.example.com:22", &net.TCPAddr{}, mitm)
	var mm *known_hosts.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected MismatchError, got %T: %v", err, err)
	}
}

// TestCallback_WithinSSHServerHandshake is an integration check that
// drives an in-process ssh.Server handshake through the Callback —
// asserts the handshake fails on mismatch and succeeds on match.
func TestCallback_WithinSSHServerHandshake(t *testing.T) {
	// Server-side ed25519 host key.
	hostPriv, err := generateED25519Signer(t)
	if err != nil {
		t.Fatalf("generate host signer: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Spawn the server. It accepts exactly one connection, runs the
	// SSH handshake, and returns.
	done := make(chan error, 1)
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			done <- aerr
			return
		}
		defer conn.Close()
		cfg := &ssh.ServerConfig{
			NoClientAuth: true,
		}
		cfg.AddHostKey(hostPriv)
		sshConn, chans, reqs, serr := ssh.NewServerConn(conn, cfg)
		if serr != nil {
			done <- serr
			return
		}
		go ssh.DiscardRequests(reqs)
		// Immediately drain and close — the test only cares about the
		// handshake.
		go func() {
			for ch := range chans {
				ch.Reject(ssh.UnknownChannelType, "test server")
			}
		}()
		sshConn.Close()
		done <- nil
	}()

	// Pin the real host key.
	store := newStore(t)
	ctx := context.Background()
	if err := store.Add(ctx, &known_hosts.Pin{
		Host:        "127.0.0.1",
		Fingerprint: keys.Fingerprint(hostPriv.PublicKey()),
		Algorithm:   hostPriv.PublicKey().Type(),
		PublicKey:   hostPriv.PublicKey().Marshal(),
		Scope:       scope.User,
		Owner:       "alice",
		AddedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("")}, // NoClientAuth accepts any
		HostKeyCallback: known_hosts.Callback(ctx, store, scope.User, "alice"),
		Timeout:         2 * time.Second,
	}
	client, err := ssh.Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client.Close()

	select {
	case srvErr := <-done:
		// Server-side errors are expected (immediate close). We only
		// care the handshake completed before the close.
		_ = srvErr
	case <-time.After(3 * time.Second):
		t.Fatal("server goroutine did not exit")
	}
}

// generateED25519Signer returns an ssh.Signer over a fresh ed25519 key.
func generateED25519Signer(t *testing.T) (ssh.Signer, error) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
