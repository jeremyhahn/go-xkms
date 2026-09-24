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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// faultScanBackend wraps an in-memory backend and forces Scan to fail, so a
// known_hosts store built over it makes EmitAll error (its List iterates via
// Scan).
type faultScanBackend struct {
	storage.Backend
}

func (faultScanBackend) Scan(context.Context, string, func(string, []byte) error) error {
	return errors.New("injected scan failure")
}

// TestTarget covers both the bare-host and user@host rendering branches.
// privateDir returns a temp directory private to this user. t.TempDir gives
// 0775, and the agent session refuses a group-writable work directory: a
// socket's own mode does not protect its pathname, and the seeded known_hosts
// lives in the same directory, where group-writability is a host-verification
// hazard in its own right.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return dir
}

func TestTarget(t *testing.T) {
	if got := target("", "example.com"); got != "example.com" {
		t.Fatalf("bare host: got %q", got)
	}
	if got := target("alice", "example.com"); got != "alice@example.com" {
		t.Fatalf("user@host: got %q", got)
	}
}

// TestErrorTypes covers the error String/Unwrap methods.
func TestErrorTypes(t *testing.T) {
	ie := &InputError{Field: "Host"}
	if !strings.Contains(ie.Error(), "Host") {
		t.Fatalf("InputError.Error missing field: %q", ie.Error())
	}

	inner := errors.New("boom")
	le := &LaunchError{Op: "tempdir", Err: inner}
	if !strings.Contains(le.Error(), "tempdir") {
		t.Fatalf("LaunchError.Error missing op: %q", le.Error())
	}
	if !errors.Is(le, inner) {
		t.Fatalf("LaunchError.Unwrap did not expose inner error")
	}
}

// TestMirrorKnownHosts covers mirrorKnownHosts and forEachKnownHost: only host
// keys present in src but absent from dst are appended, and a second pass is a
// no-op (dedup by host + fingerprint).
func TestMirrorKnownHosts(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	lineA, _ := known_hosts.Emit(known_hosts.PinFromPublicKey("a.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceManual))
	lineB, _ := known_hosts.Emit(known_hosts.PinFromPublicKey("b.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceManual))

	// src has both hosts; dst already holds only A (plus a comment + blank line
	// to exercise the skip branches in forEachKnownHost).
	if err := os.WriteFile(src, []byte(lineA+"\n"+lineB+"\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := os.WriteFile(dst, []byte("# comment\n\n"+lineA+"\n"), 0o600); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := mirrorKnownHosts(src, dst); err != nil {
		t.Fatalf("mirrorKnownHosts: %v", err)
	}
	data, _ := os.ReadFile(dst)
	if !strings.Contains(string(data), "b.example.com") {
		t.Fatalf("new host not mirrored: %q", data)
	}
	if strings.Count(string(data), "a.example.com") != 1 {
		t.Fatalf("existing host duplicated: %q", data)
	}

	// Second pass appends nothing new.
	before, _ := os.ReadFile(dst)
	if err := mirrorKnownHosts(src, dst); err != nil {
		t.Fatalf("mirrorKnownHosts (2nd): %v", err)
	}
	after, _ := os.ReadFile(dst)
	if len(before) != len(after) {
		t.Fatalf("idempotent mirror changed dst: before=%d after=%d", len(before), len(after))
	}
}

// TestStart_WriteKnownHostsError covers the write-known_hosts failure branch:
// a pre-existing directory at the known_hosts path makes os.WriteFile fail
// after the agent is already up.
func TestStart_WriteKnownHostsError(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())

	workDir := privateDir(t)
	// Occupy the known_hosts path with a directory so WriteFile fails.
	if err := os.Mkdir(filepath.Join(workDir, "known_hosts"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := Start(ctx, Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
		SkipStore:       true, // avoid the EmitAll path; isolate the write failure
		WorkDir:         workDir,
	})
	var le *LaunchError
	if !errors.As(err, &le) {
		t.Fatalf("expected LaunchError, got %v", err)
	}
	if le.Op != "write known_hosts" {
		t.Fatalf("expected write known_hosts op, got %q", le.Op)
	}
}

// TestStart_EmitKnownHostsError covers the emit-known_hosts failure branch: a
// store whose List fails makes EmitAll error during seeding.
func TestStart_EmitKnownHostsError(t *testing.T) {
	ctx := context.Background()
	store, err := known_hosts.NewBackendStore(faultScanBackend{Backend: storage.New()})
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}

	_, err = Start(ctx, Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	var le *LaunchError
	if !errors.As(err, &le) {
		t.Fatalf("expected LaunchError, got %v", err)
	}
	if le.Op != "emit known_hosts" {
		t.Fatalf("expected emit known_hosts op, got %q", le.Op)
	}
}

// TestMirrorKnownHosts_MissingSource returns the read error for an absent src.
func TestMirrorKnownHosts_MissingSource(t *testing.T) {
	dir := t.TempDir()
	err := mirrorKnownHosts(filepath.Join(dir, "nope"), filepath.Join(dir, "dst"))
	if err == nil {
		t.Fatalf("expected error for missing source file")
	}
}

// TestStart_ExtraFilesAndOptions exercises the ExtraKnownHosts / ExtraOptions /
// SkipStore branches in Start plus KnownHostsFile(), and drives Sync's
// extraFiles mirror loop.
func TestStart_ExtraFilesAndOptions(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())

	// An external known_hosts file that will be seeded and mirrored to.
	extDir := t.TempDir()
	extFile := filepath.Join(extDir, "known_hosts")
	extLine, _ := known_hosts.Emit(known_hosts.PinFromPublicKey("ext.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceManual))
	if err := os.WriteFile(extFile, []byte(extLine+"\n"), 0o600); err != nil {
		t.Fatalf("write ext file: %v", err)
	}

	sess, err := Start(ctx, Request{
		Host:                  "host.example.com",
		User:                  "root",
		Signer:                testSigner(t),
		KnownHostsStore:       store,
		Scope:                 scope.User,
		Owner:                 "alice",
		SkipStore:             true,
		StrictHostKeyChecking: "accept-new",
		ExtraOptions:          []string{"ServerAliveInterval=30"},
		ExtraKnownHosts:       []string{extFile},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.Stop(context.Background())

	if !contains(sess.Args, "ServerAliveInterval=30") {
		t.Fatalf("ExtraOptions not appended: %v", sess.Args)
	}
	if !contains(sess.Args, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("strict override not applied: %v", sess.Args)
	}
	if sess.KnownHostsFile() == "" {
		t.Fatalf("KnownHostsFile should be set while live")
	}
	// Seed included the external file's host.
	body, _ := os.ReadFile(sess.knownHostsFile)
	if !strings.Contains(string(body), "ext.example.com") {
		t.Fatalf("external known_hosts not seeded: %q", body)
	}

	// Simulate the native client accepting a new host into the temp file, then
	// Sync mirrors it back into the external file (SkipStore => store untouched).
	newLine, _ := known_hosts.Emit(known_hosts.PinFromPublicKey("mirrored.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceFirstContact))
	f, _ := os.OpenFile(sess.knownHostsFile, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(newLine + "\n")
	_ = f.Close()

	added, err := sess.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if added != 0 {
		t.Fatalf("SkipStore set: expected 0 store imports, got %d", added)
	}
	extData, _ := os.ReadFile(extFile)
	if !strings.Contains(string(extData), "mirrored.example.com") {
		t.Fatalf("accepted host not mirrored into external file: %q", extData)
	}

	// After Stop the known_hosts file handle is cleared.
	sess.Stop(context.Background())
	if sess.KnownHostsFile() != "" {
		t.Fatalf("KnownHostsFile should be empty after Stop")
	}
}

// TestSyncAndStop_WorkDirCleanupFailureSurfacesViaErr verifies that a failure
// removing the owned work directory during teardown is reported -- via both
// SyncAndStop's own error return and Session.Err() -- rather than being
// silently discarded (#701). Before, cleanupDir dropped os.RemoveAll's error
// unconditionally, so a work directory that could not be removed (permission
// denied, a stray open handle) was reported as a perfectly clean shutdown.
func TestSyncAndStop_WorkDirCleanupFailureSurfacesViaErr(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())

	sess, err := Start(ctx, Request{
		Host:            "cleanup-fail.example.com",
		Signer:          testSigner(t),
		KnownHostsStore: store,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !sess.ownsWorkDir {
		t.Fatal("test requires an owned (auto-created) work directory")
	}

	// Fail the work-directory removal through the seam: permission bits
	// cannot make os.RemoveAll fail when the tests run as root.
	errCleanup := errors.New("injected cleanup failure")
	orig := removeAll
	removeAll = func(string) error { return errCleanup }
	t.Cleanup(func() { removeAll = orig; _ = os.RemoveAll(sess.workDir) })

	if _, _, err := sess.SyncAndStop(ctx); err == nil {
		t.Fatal("expected SyncAndStop to surface the work-directory cleanup failure")
	}
	if sessErr := sess.Err(); !errors.Is(sessErr, errCleanup) {
		t.Fatalf("expected Session.Err() to report the cleanup failure, got %v", sessErr)
	}
}
