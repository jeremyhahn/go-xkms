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

package authorized_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// generateKey produces a fresh *keys.Key with public material for the
// requested algorithm. Tests close the key via defer.
func generateKey(t *testing.T, algo keys.Algorithm) *keys.Key {
	t.Helper()
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: algo, Comment: "test@host"})
	if err != nil {
		t.Fatalf("generate %s: %v", algo, err)
	}
	return k
}

// TestEmitParseRoundtrip_Algorithms covers the three OpenSSH algorithm
// families supported by keys.Generate.
func TestEmitParseRoundtrip_Algorithms(t *testing.T) {
	cases := []struct {
		name string
		algo keys.Algorithm
	}{
		{"ed25519", keys.AlgorithmEd25519},
		{"rsa-2048", keys.AlgorithmRSA},
		{"ecdsa-p256", keys.AlgorithmECDSAP256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use 2048-bit RSA to keep tests fast.
			var k *keys.Key
			if tc.algo == keys.AlgorithmRSA {
				var err error
				k, err = keys.Generate(t.Context(), keys.GenerateOptions{
					Algorithm: keys.AlgorithmRSA,
					RSABits:   2048,
					Comment:   "test@host",
				})
				if err != nil {
					t.Fatalf("generate rsa: %v", err)
				}
			} else {
				k = generateKey(t, tc.algo)
			}
			defer k.Destroy()

			entry := &authorized.Entry{
				Key:     k,
				Options: []string{"no-port-forwarding", `command="/bin/echo"`},
				Comment: "alice@workstation",
			}
			line, err := authorized.Emit(entry)
			if err != nil {
				t.Fatalf("Emit: %v", err)
			}

			parsed, err := authorized.ParseLine(line)
			if err != nil {
				t.Fatalf("ParseLine: %v", err)
			}
			if keys.Fingerprint(parsed.Key.PublicKey) != k.Fingerprint {
				t.Fatalf("fingerprint mismatch: want %s, got %s",
					k.Fingerprint, keys.Fingerprint(parsed.Key.PublicKey))
			}
			if parsed.Comment != "alice@workstation" {
				t.Fatalf("comment lost: %q", parsed.Comment)
			}
			if len(parsed.Options) != 2 {
				t.Fatalf("expected 2 options, got %d: %v", len(parsed.Options), parsed.Options)
			}
		})
	}
}

// TestEmit_NilKey confirms emission rejects malformed entries.
func TestEmit_NilKey(t *testing.T) {
	_, err := authorized.Emit(nil)
	var nilErr *authorized.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected NilInputError, got %T: %v", err, err)
	}
}

// TestParseAll_MultiLineFile covers comments and blank-line handling.
func TestParseAll_MultiLineFile(t *testing.T) {
	k1 := generateKey(t, keys.AlgorithmEd25519)
	defer k1.Destroy()
	k2 := generateKey(t, keys.AlgorithmEd25519)
	defer k2.Destroy()

	line1, err := authorized.Emit(&authorized.Entry{Key: k1, Comment: "one"})
	if err != nil {
		t.Fatalf("emit 1: %v", err)
	}
	line2, err := authorized.Emit(&authorized.Entry{Key: k2, Comment: "two"})
	if err != nil {
		t.Fatalf("emit 2: %v", err)
	}

	file := strings.Join([]string{
		"# This is a comment",
		"",
		line1,
		"   # indented comment",
		line2,
		"",
	}, "\n")

	entries, err := authorized.ParseAll([]byte(file))
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Key.Fingerprint != k1.Fingerprint {
		t.Fatalf("first entry fingerprint mismatch")
	}
	if entries[1].Key.Fingerprint != k2.Fingerprint {
		t.Fatalf("second entry fingerprint mismatch")
	}
}

// TestParseLine_Malformed rejects garbage input with MalformedLineError.
func TestParseLine_Malformed(t *testing.T) {
	_, err := authorized.ParseLine("not-an-authorized-keys-line")
	var m *authorized.MalformedLineError
	if !errors.As(err, &m) {
		t.Fatalf("expected MalformedLineError, got %T: %v", err, err)
	}
}

// TestEmitAll_RoundTrip verifies EmitAll + ParseAll are inverses.
func TestEmitAll_RoundTrip(t *testing.T) {
	k1 := generateKey(t, keys.AlgorithmEd25519)
	defer k1.Destroy()
	k2 := generateKey(t, keys.AlgorithmECDSAP256)
	defer k2.Destroy()

	entries := []*authorized.Entry{
		{Key: k1, Comment: "first", Options: []string{"no-pty"}},
		{Key: k2, Comment: "second"},
	}
	block, err := authorized.EmitAll(entries)
	if err != nil {
		t.Fatalf("EmitAll: %v", err)
	}
	parsed, err := authorized.ParseAll([]byte(block))
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed))
	}
}

// TestStore_AddGetListRemove is the happy-path storage flow.
func TestStore_AddGetListRemove(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()

	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	entry := &authorized.Entry{Key: k, Comment: "alice@workstation"}
	if err := store.Add(ctx, scope.User, "alice", "laptop", entry); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := store.Get(ctx, scope.User, "alice", "laptop")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Entry.Key.Fingerprint != k.Fingerprint {
		t.Fatalf("fingerprint mismatch after store")
	}
	if got.Scope != scope.User || got.Owner != "alice" || got.Name != "laptop" {
		t.Fatalf("Get coordinates = %s/%s/%s, want user/alice/laptop", got.Scope, got.Owner, got.Name)
	}

	list, err := store.List(ctx, scope.User, "alice")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
	if list[0].Name != "laptop" {
		t.Fatalf("List dropped the stored name: got %q, want %q", list[0].Name, "laptop")
	}

	if err := store.Remove(ctx, scope.User, "alice", "laptop"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	_, err = store.Get(ctx, scope.User, "alice", "laptop")
	var nf *authorized.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError, got %T: %v", err, err)
	}
}

// TestStore_Duplicate confirms Add is non-idempotent.
func TestStore_Duplicate(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()

	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	entry := &authorized.Entry{Key: k}
	if err := store.Add(ctx, scope.User, "alice", "laptop", entry); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err = store.Add(ctx, scope.User, "alice", "laptop", entry)
	var dup *authorized.DuplicateError
	if !errors.As(err, &dup) {
		t.Fatalf("expected DuplicateError, got %T: %v", err, err)
	}
}

// TestVerify_Match locates a stored Entry by fingerprint.
func TestVerify_Match(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()

	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	entry := &authorized.Entry{Key: k, Options: []string{"no-pty"}}
	if err := store.Add(ctx, scope.User, "alice", "laptop", entry); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Fabricate a fresh ssh.PublicKey from the same material via
	// ParseAuthorizedKey; Verify should match by fingerprint.
	line, err := authorized.Emit(entry)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}

	got, err := authorized.Verify(ctx, store, scope.User, "alice", pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Entry.Key.Fingerprint != k.Fingerprint {
		t.Fatalf("verify returned wrong entry")
	}
	// Verify must name the record that granted access so the caller can
	// log or revoke it.
	if got.Name != "laptop" {
		t.Fatalf("Verify record name = %q, want %q", got.Name, "laptop")
	}
}

// TestVerify_NotFound returns NotFoundError for a non-matching key.
func TestVerify_NotFound(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := authorized.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()

	stored := generateKey(t, keys.AlgorithmEd25519)
	defer stored.Destroy()
	if err := store.Add(ctx, scope.User, "alice", "laptop", &authorized.Entry{Key: stored}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	other := generateKey(t, keys.AlgorithmEd25519)
	defer other.Destroy()
	_, err = authorized.Verify(ctx, store, scope.User, "alice", other.PublicKey)
	var nf *authorized.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFoundError, got %T: %v", err, err)
	}
}
