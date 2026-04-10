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
