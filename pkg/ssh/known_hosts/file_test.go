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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

func emitLine(t *testing.T, host string, pub ssh.PublicKey) string {
	t.Helper()
	line, err := known_hosts.Emit(known_hosts.PinFromPublicKey(host, scope.User, "alice", pub, known_hosts.SourceManual))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	return line
}

// TestAppendMissing_DedupAndMissingDst covers appending only the not-yet-
// present entries, and treating a missing dstPath as an empty file.
func TestAppendMissing_DedupAndMissingDst(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "known_hosts")

	lineA := emitLine(t, "a.example.com", newEd25519PublicKey(t))
	lineB := emitLine(t, "b.example.com", newEd25519PublicKey(t))
	src := []byte(lineA + "\n" + lineB + "\n")

	// dst does not exist yet.
	if err := known_hosts.AppendMissing(src, dst); err != nil {
		t.Fatalf("AppendMissing (missing dst): %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !strings.Contains(string(data), "a.example.com") || !strings.Contains(string(data), "b.example.com") {
		t.Fatalf("both hosts must be appended to a fresh file: %q", data)
	}

	// Second pass: src unchanged, everything already present => no-op.
	before, _ := os.ReadFile(dst)
	if err := known_hosts.AppendMissing(src, dst); err != nil {
		t.Fatalf("AppendMissing (2nd pass): %v", err)
	}
	after, _ := os.ReadFile(dst)
	if len(before) != len(after) {
		t.Fatalf("idempotent AppendMissing changed dst: before=%d after=%d", len(before), len(after))
	}

	// Third pass: a new host in src must be appended alongside the existing ones.
	lineC := emitLine(t, "c.example.com", newEd25519PublicKey(t))
	if err := known_hosts.AppendMissing([]byte(lineC+"\n"), dst); err != nil {
		t.Fatalf("AppendMissing (new host): %v", err)
	}
	final, _ := os.ReadFile(dst)
	if !strings.Contains(string(final), "c.example.com") {
		t.Fatalf("new host not appended: %q", final)
	}
	if strings.Count(string(final), "a.example.com") != 1 {
		t.Fatalf("existing host duplicated: %q", final)
	}
}

// TestLookupFile_FoundNotFoundDifferentKey covers the found / not-found /
// missing-file branches of LookupFile.
func TestLookupFile_FoundNotFoundDifferentKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	pub := newEd25519PublicKey(t)
	line := emitLine(t, "bastion.example.com", pub)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Found: the returned key matches what was written.
	found, ok, err := known_hosts.LookupFile(path, "bastion.example.com")
	if err != nil {
		t.Fatalf("LookupFile (found): %v", err)
	}
	if !ok {
		t.Fatal("expected LookupFile to report found=true")
	}
	if ssh.FingerprintSHA256(found) != ssh.FingerprintSHA256(pub) {
		t.Fatal("LookupFile returned a different key than what was stored")
	}

	// Not found: a host absent from the file.
	_, ok, err = known_hosts.LookupFile(path, "ghost.example.com")
	if err != nil {
		t.Fatalf("LookupFile (not found): %v", err)
	}
	if ok {
		t.Fatal("expected LookupFile to report found=false for an absent host")
	}

	// Missing file entirely: not an error, found=false.
	missing, ok, err := known_hosts.LookupFile(filepath.Join(dir, "does-not-exist"), "bastion.example.com")
	if err != nil {
		t.Fatalf("LookupFile (missing file): %v", err)
	}
	if ok || missing != nil {
		t.Fatalf("expected (nil, false, nil) for a missing file, got (%v, %v, nil)", missing, ok)
	}
}

// TestLookupFile_BracketedPortDecoration covers the "[host]:port" matching
// branch (a non-default-port OpenSSH known_hosts entry).
func TestLookupFile_BracketedPortDecoration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	pub := newEd25519PublicKey(t)
	line := emitLine(t, "[bastion.example.com]:2222", pub)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	found, ok, err := known_hosts.LookupFile(path, "bastion.example.com")
	if err != nil {
		t.Fatalf("LookupFile: %v", err)
	}
	if !ok {
		t.Fatal("expected a bracketed [host]:port entry to match the bare host")
	}
	if ssh.FingerprintSHA256(found) != ssh.FingerprintSHA256(pub) {
		t.Fatal("LookupFile returned a different key for the bracketed entry")
	}
}

// TestAppendMissing_OpenFileError covers the append-failure branch: a
// pre-existing directory at dstPath makes the append OpenFile call fail.
func TestAppendMissing_OpenFileError(t *testing.T) {
	dir := t.TempDir()
	dstDir := filepath.Join(dir, "known_hosts")
	if err := os.Mkdir(dstDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	line := emitLine(t, "a.example.com", newEd25519PublicKey(t))
	err := known_hosts.AppendMissing([]byte(line+"\n"), dstDir)
	if err == nil {
		t.Fatal("expected error when dstPath is a directory")
	}
}
