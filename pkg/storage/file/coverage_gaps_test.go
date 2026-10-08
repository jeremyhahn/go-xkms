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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// fileRootStore returns a store whose root directory has been replaced by a
// regular file after New, so every path beneath it fails with ENOTDIR. The
// kernel enforces that for every user, including root, unlike a chmod-based
// setup that silently stops testing anything when the suite runs as uid 0 in
// a container, which is exactly where CI runs it.
func fileRootStore(t *testing.T) storage.Backend {
	t.Helper()

	parent := setupTestDir(t)
	dir := filepath.Join(parent, "root")
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return store
}

// TestOperations_UnreachableRoot verifies an I/O failure under the store root
// surfaces as an error on every operation and is never mistaken for an absent
// key, which would let a caller overwrite or recreate state it cannot see.
func TestOperations_UnreachableRoot(t *testing.T) {
	ctx := context.Background()

	t.Run("get", func(t *testing.T) {
		_, err := fileRootStore(t).Get(ctx, "test-key")
		if err == nil {
			t.Fatal("Get() should return the read error")
		}
		if errors.Is(err, storage.ErrNotFound) {
			t.Error("Get() must not report a read error as ErrNotFound")
		}
	})

	t.Run("exists", func(t *testing.T) {
		exists, err := fileRootStore(t).Exists(ctx, "test-key")
		if err == nil {
			t.Error("Exists() should return the stat error")
		}
		if exists {
			t.Error("Exists() must not report a key behind a stat error as present")
		}
	})

	t.Run("put", func(t *testing.T) {
		if err := fileRootStore(t).Put(ctx, "test-key", []byte("data")); err == nil {
			t.Error("Put() should return the write error")
		}
	})

	t.Run("delete", func(t *testing.T) {
		err := fileRootStore(t).Delete(ctx, "test-key")
		if err == nil {
			t.Fatal("Delete() should return the I/O error")
		}
		if errors.Is(err, storage.ErrNotFound) {
			t.Error("Delete() must not report an I/O error as ErrNotFound")
		}
	})
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

// TestPutIfAbsent_BackendError verifies PutIfAbsent propagates a genuine
// write failure, distinct from the stored=false "already exists" outcome, and
// never reports a value it could not write as stored.
func TestPutIfAbsent_BackendError(t *testing.T) {
	ctx := context.Background()

	stored, err := fileRootStore(t).PutIfAbsent(ctx, "new-key", []byte("data"))
	if err == nil {
		t.Fatal("PutIfAbsent() should return the write error")
	}
	if stored {
		t.Error("PutIfAbsent() reported stored=true despite a write failure")
	}
}
