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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestPut_MkdirAllFailure verifies Put returns an error when directory creation
// fails. A regular file where the key needs a directory makes os.MkdirAll fail
// with ENOTDIR, which the kernel enforces for every user including root — a
// read-only parent directory would not, because root ignores permission bits.
func TestPut_MkdirAllFailure(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := os.WriteFile(filepath.Join(dir, "blocker"), []byte("not a directory"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := store.Put(ctx, "blocker/new-child/deep/file", []byte("data")); err == nil {
		t.Error("Put() should return error when MkdirAll fails")
	}
}

// walkErrorStore returns a store whose root directory has been removed, so any
// directory walk fails with ENOENT. The kernel reports that to every user,
// unlike an unreadable directory, which root traverses regardless of its mode.
func walkErrorStore(t *testing.T, ctx context.Context) storage.Backend {
	t.Helper()

	parent := setupTestDir(t)
	dir := filepath.Join(parent, "root")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.Put(ctx, "visible/key", []byte("data")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}

	return store
}

// TestList_WalkEntryError verifies List returns an error when WalkDir passes a
// non-nil error into the walk callback. This covers the
// "if err != nil { return err }" branch at the top of the callback in List.
func TestList_WalkEntryError(t *testing.T) {
	ctx := context.Background()
	store := walkErrorStore(t, ctx)

	if _, err := store.List(ctx, ""); err == nil {
		t.Error("List() should return error when WalkDir reports a failure")
	}
}

// TestScan_WalkEntryError verifies Scan returns an error when WalkDir passes a
// non-nil error into the walk callback. This covers the
// "if err != nil { return err }" branch at the top of the callback in Scan.
func TestScan_WalkEntryError(t *testing.T) {
	ctx := context.Background()
	store := walkErrorStore(t, ctx)

	err := store.Scan(ctx, "", func(_ string, _ []byte) error { return nil })
	if err == nil {
		t.Error("Scan() should return error when WalkDir reports a failure")
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
// os.Chmod call fails.
//
// The fault is injected through FileStorage's own fields rather than through
// file ownership: the engine writes into one directory while rootDir — the
// path Put chmods — resolves through a regular file, so the write succeeds and
// the chmod fails with ENOTDIR. Ownership-based setups (chmod'ing a file the
// process does not own) cannot fail for root, which is exactly where CI runs.
func TestPut_ChmodFailure(t *testing.T) {
	ctx := context.Background()

	engineDir := setupTestDir(t)
	engine, err := storage.OpenEngine(storage.EngineConfig{Kind: storage.EngineFile, Path: engineDir})
	if err != nil {
		t.Fatalf("OpenEngine() error = %v", err)
	}
	defer func() { _ = engine.Close() }()

	chmodDir := setupTestDir(t)
	if err := os.WriteFile(filepath.Join(chmodDir, "certs"), []byte("not a directory"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store := &FileStorage{backend: engine, rootDir: chmodDir, lockPath: filepath.Join(chmodDir, lockFileName)}

	// certs/ is the prefix whose permissions Put widens, so the chmod runs.
	if err := store.Put(ctx, "certs/widened.pem", []byte("data")); err == nil {
		t.Fatal("Put() should return an error when the permission chmod fails")
	}

	// The write itself succeeded: the failure reported is the chmod, not the write.
	if _, err := engine.Get(ctx, "certs/widened.pem"); err != nil {
		t.Fatalf("the engine write must have succeeded before the chmod failed: %v", err)
	}
}

// TestPutIfAbsent_BackendError verifies PutIfAbsent propagates a genuine
// backend failure (as opposed to validation or chmod failures). The
// underlying engine's Set (called after Exists finds the key absent) fails
// when the parent directory lacks write permission, exercising the
// "backend.PutIfAbsent returned an error" branch distinct from the
// stored=false "already exists" branch.
func TestPutIfAbsent_BackendError(t *testing.T) {
	ctx := context.Background()
	dir := setupTestDir(t)
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// A regular file where a directory is required: Exists reports absent, the
	// write then fails with ENOTDIR for every user including root.
	if err := os.WriteFile(filepath.Join(dir, "blocker"), []byte("not a directory"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	stored, err := store.PutIfAbsent(ctx, "blocker/new-key", []byte("data"))
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
