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

package file

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestPut_MkdirAllFailure verifies Put returns an error when directory creation fails.
// This covers the os.MkdirAll error branch in Put (line 113-114 in storage.go).
// The scenario: the *parent* of the required directory exists but is read-only,
// so creating a new child directory inside it fails with permission denied.
func TestPut_MkdirAllFailure(t *testing.T) {
	skipIfRoot(t)

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Create a read-only parent directory.
	roParent := filepath.Join(dir, "ro-parent")
	if err := os.MkdirAll(roParent, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Chmod(roParent, 0500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer func() { _ = os.Chmod(roParent, 0700) }()

	// Attempt to write to a key whose parent directory requires creating a NEW
	// subdirectory inside ro-parent. MkdirAll will fail trying to create
	// ro-parent/new-child because ro-parent is not writable.
	key := "ro-parent/new-child/deep/file"
	err = store.Put(ctx, key, []byte("data"))
	if err == nil {
		t.Error("Put() should return error when MkdirAll fails")
	}
}

// TestList_WalkEntryError verifies List returns an error when WalkDir
// passes a non-nil error into the walk callback for a specific entry.
// This covers the "if err != nil { return err }" branch at the top of
// the walk callback in List.
func TestList_WalkEntryError(t *testing.T) {
	skipIfRoot(t)

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Put a real key so the walk has something to traverse.
	if err := store.Put(ctx, "visible/key", []byte("data")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Create a directory that WalkDir will attempt to descend into,
	// then make it inaccessible. WalkDir passes the OS error into the callback.
	badDir := filepath.Join(dir, "bad-dir")
	if err := os.MkdirAll(badDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	// Place a file inside so WalkDir must enter the directory.
	if err := os.WriteFile(filepath.Join(badDir, "entry"), []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(badDir, 0000); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer func() { _ = os.Chmod(badDir, 0700) }()

	_, err = store.List(ctx, "")
	if err == nil {
		t.Error("List() should return error when WalkDir encounters an inaccessible entry")
	}
}

// TestScan_WalkEntryError verifies Scan returns an error when WalkDir
// passes a non-nil error into the walk callback for a specific entry.
// This covers the "if err != nil { return err }" branch at the top of
// the walk callback in Scan.
func TestScan_WalkEntryError(t *testing.T) {
	skipIfRoot(t)

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Put(ctx, "visible/key", []byte("data")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Same strategy as TestList_WalkEntryError.
	badDir := filepath.Join(dir, "bad-dir-scan")
	if err := os.MkdirAll(badDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "entry"), []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(badDir, 0000); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer func() { _ = os.Chmod(badDir, 0700) }()

	err = store.Scan(ctx, "", func(_ string, _ []byte) error { return nil })
	if err == nil {
		t.Error("Scan() should return error when WalkDir encounters an inaccessible entry")
	}
}

// TestNew_AbsPathFailure verifies New wraps a filepath.Abs failure. Abs calls
// os.Getwd() when given a relative path; Getwd fails once the process's
// current working directory has been removed out from under it. The test
// chdir's into a scratch directory, deletes it, then calls New with a
// relative path — Abs cannot resolve the (now nonexistent) cwd and returns
// an error, which New must wrap rather than panic or silently pass through.
func TestNew_AbsPathFailure(t *testing.T) {
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	scratch, err := os.MkdirTemp("", "abscheck-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	if err := os.Chdir(scratch); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}

	_, err = New("relative-dir")
	if err == nil {
		t.Fatal("New() with a deleted cwd should return an error from filepath.Abs")
	}
}

// TestPut_ChmodFailure verifies Put returns an error when the post-write
// os.Chmod call fails. The write itself (via the underlying engine's
// os.WriteFile) follows symlinks, so pre-creating a dangling symlink to
// /dev/null at the key's on-disk path lets the write succeed (data is
// discarded by the kernel) while the subsequent os.Chmod — which also
// follows the symlink — fails with EPERM because the test process does not
// own /dev/null. This exercises the chmod-error branch without corrupting
// any real data.
func TestPut_ChmodFailure(t *testing.T) {
	skipIfRoot(t) // root owns everything, including /dev/null; chmod would succeed.

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// certs/ prefix so Put actually attempts the widen-permission Chmod
	// (keys/ maps to 0600, which equals defaultPerms, so no chmod happens).
	key := "certs/devnull-target"
	path := filepath.Join(dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err = store.Put(ctx, key, []byte("data"))
	if err == nil {
		t.Fatal("Put() through a dangling symlink to /dev/null should fail on chmod")
	}
}

// TestPutIfAbsent_BackendError verifies PutIfAbsent propagates a genuine
// backend failure (as opposed to validation or chmod failures). The
// underlying engine's Set (called after Exists finds the key absent) fails
// when the parent directory lacks write permission, exercising the
// "backend.PutIfAbsent returned an error" branch distinct from the
// stored=false "already exists" branch.
func TestPutIfAbsent_BackendError(t *testing.T) {
	skipIfRoot(t)

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	roDir := filepath.Join(dir, "ro-putifabsent")
	if err := os.MkdirAll(roDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Chmod(roDir, 0500); err != nil { // r-x: Stat succeeds, WriteFile does not.
		t.Fatalf("Chmod() error = %v", err)
	}
	defer func() { _ = os.Chmod(roDir, 0700) }()

	stored, err := store.PutIfAbsent(ctx, "ro-putifabsent/new-key", []byte("data"))
	if err == nil {
		t.Fatal("PutIfAbsent() should return the backend's write error")
	}
	if stored {
		t.Error("PutIfAbsent() reported stored=true despite a write failure")
	}
}

// TestPutIfAbsent_WidensCertsPermission verifies PutIfAbsent applies the same
// prefix-based permission widening as Put: a fresh key under certs/ is
// written 0600 by the engine and then chmod'd to 0644.
//
// Note: the analogous "chmod itself fails" branch cannot be exercised the
// way TestPut_ChmodFailure does — PutIfAbsent's Exists() pre-check follows
// symlinks, so a dangling symlink to /dev/null resolves as "already exists"
// and PutIfAbsent short-circuits with stored=false before ever writing or
// chmod'ing. Forcing the chmod call itself to fail on a file this process
// just created and therefore owns would require either a genuine data race
// (a concurrent process altering the file between Set and Chmod) or root-only
// mechanisms (immutable inode attributes, foreign ownership) — both outside
// what a deterministic, non-destructive unit test may do.
func TestPutIfAbsent_WidensCertsPermission(t *testing.T) {
	skipIfRoot(t)

	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	key := "certs/putifabsent-widen.pem"
	value := []byte("cert-data")

	stored, err := store.PutIfAbsent(ctx, key, value)
	if err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}
	if !stored {
		t.Fatal("PutIfAbsent() on a fresh key should report stored=true")
	}

	info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(key)))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("file permissions = %o, want 0644 (certs/ widened)", info.Mode().Perm())
	}

	got, err := store.Get(ctx, key)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatalf("Get() = (%q, %v), want (%q, nil)", got, err, value)
	}
}
