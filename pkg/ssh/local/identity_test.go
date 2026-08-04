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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/local"
)

// writeKeyPair writes a throwaway private-key placeholder (its content is
// irrelevant to DiscoverIdentities, which never reads it) at path, plus a
// real, parseable public key at path+".pub" when withPub is true.
func writeKeyPair(t *testing.T, path string, withPub bool) ssh.PublicKey {
	t.Helper()
	if err := os.WriteFile(path, []byte("placeholder private key contents"), 0o600); err != nil {
		t.Fatalf("write private key placeholder: %v", err)
	}
	if !withPub {
		return nil
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	line := ssh.MarshalAuthorizedKey(sshPub)
	line = append(append([]byte{}, line[:len(line)-1]...), []byte(" test-comment\n")...)
	if err := os.WriteFile(path+".pub", line, 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return sshPub
}

// TestDiscoverIdentities_OrderAndDedup covers the candidate ordering rule
// (host.IdentityFiles first, then DefaultIdentityFiles under homeDir/.ssh)
// and dedup-by-absolute-path when an explicit IdentityFile happens to
// equal one of the default candidates.
func TestDiscoverIdentities_OrderAndDedup(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}

	// id_ed25519 is a DEFAULT candidate, but also explicitly listed on the
	// host — it must appear exactly once, at the position of its first
	// occurrence (the explicit one).
	dup := filepath.Join(sshDir, "id_ed25519")
	writeKeyPair(t, dup, true)

	custom := filepath.Join(home, "custom_key")
	writeKeyPair(t, custom, false)

	// id_rsa is a default candidate that is never explicitly listed.
	writeKeyPair(t, filepath.Join(sshDir, "id_rsa"), true)

	// id_ecdsa is a default candidate that never gets created on disk —
	// it must be silently skipped, not reported as missing.

	host := &local.HostConfig{IdentityFiles: []string{custom, dup}}

	identities, err := local.DiscoverIdentities(host, home)
	if err != nil {
		t.Fatalf("DiscoverIdentities: %v", err)
	}

	var paths []string
	for _, id := range identities {
		paths = append(paths, id.Path)
	}
	want := []string{custom, dup, filepath.Join(sshDir, "id_rsa")}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths = %v, want %v", paths, want)
		}
	}
}

// TestDiscoverIdentities_PubKeyParsing covers the three .pub outcomes: a
// present and parseable .pub populates PublicKey/Comment/Fingerprint; a
// missing .pub and an unparsable .pub both leave those fields at zero
// values without producing an error.
func TestDiscoverIdentities_PubKeyParsing(t *testing.T) {
	home := t.TempDir()

	withPub := filepath.Join(home, "with_pub")
	wantPub := writeKeyPair(t, withPub, true)

	withoutPub := filepath.Join(home, "without_pub")
	writeKeyPair(t, withoutPub, false)

	unparsable := filepath.Join(home, "unparsable")
	writeKeyPair(t, unparsable, false)
	if err := os.WriteFile(unparsable+".pub", []byte("not a valid public key\n"), 0o600); err != nil {
		t.Fatalf("write unparsable pub: %v", err)
	}

	host := &local.HostConfig{IdentityFiles: []string{withPub, withoutPub, unparsable}}
	identities, err := local.DiscoverIdentities(host, home)
	if err != nil {
		t.Fatalf("DiscoverIdentities: %v", err)
	}
	if len(identities) != 3 {
		t.Fatalf("got %d identities, want 3", len(identities))
	}

	if identities[0].PublicKey == nil {
		t.Fatal("identities[0].PublicKey is nil, want the parsed key")
	}
	if string(identities[0].PublicKey.Marshal()) != string(wantPub.Marshal()) {
		t.Error("identities[0].PublicKey does not match the written key")
	}
	if identities[0].Comment != "test-comment" {
		t.Errorf("identities[0].Comment = %q, want %q", identities[0].Comment, "test-comment")
	}
	if identities[0].Fingerprint == "" {
		t.Error("identities[0].Fingerprint is empty")
	}

	for i, name := range []string{"withoutPub", "unparsable"} {
		id := identities[i+1]
		if id.PublicKey != nil {
			t.Errorf("%s: PublicKey = %v, want nil", name, id.PublicKey)
		}
		if id.Comment != "" {
			t.Errorf("%s: Comment = %q, want empty", name, id.Comment)
		}
		if id.Fingerprint != "" {
			t.Errorf("%s: Fingerprint = %q, want empty", name, id.Fingerprint)
		}
	}
}

// TestDiscoverIdentities_NilHost verifies a nil HostConfig degrades
// gracefully to only the default candidates rather than panicking.
func TestDiscoverIdentities_NilHost(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	writeKeyPair(t, filepath.Join(sshDir, "id_rsa"), false)

	identities, err := local.DiscoverIdentities(nil, home)
	if err != nil {
		t.Fatalf("DiscoverIdentities(nil host): %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("got %d identities, want 1", len(identities))
	}
}

// TestDiscoverIdentities_StatError covers the branch where stat fails for
// a reason other than "does not exist" — an embedded NUL byte in the path
// makes stat fail deterministically without depending on filesystem
// permission semantics.
func TestDiscoverIdentities_StatError(t *testing.T) {
	home := t.TempDir()
	host := &local.HostConfig{IdentityFiles: []string{filepath.Join(home, "bad\x00name")}}

	_, err := local.DiscoverIdentities(host, home)
	var readErr *local.IdentityReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("expected *IdentityReadError, got %T: %v", err, err)
	}
}

// TestDiscoverIdentities_SkipsDirectories covers the defensive branch that
// ignores a candidate path which happens to be a directory rather than a
// regular file.
func TestDiscoverIdentities_SkipsDirectories(t *testing.T) {
	home := t.TempDir()
	asDir := filepath.Join(home, "a_directory")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	host := &local.HostConfig{IdentityFiles: []string{asDir}}
	identities, err := local.DiscoverIdentities(host, home)
	if err != nil {
		t.Fatalf("DiscoverIdentities: %v", err)
	}
	if len(identities) != 0 {
		t.Fatalf("got %d identities, want 0 (directory should be skipped)", len(identities))
	}
}
