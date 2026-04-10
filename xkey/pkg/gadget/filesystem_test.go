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

package gadget

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOSFileSystem_MkdirAll(t *testing.T) {
	dir := t.TempDir()
	fs := &OSFileSystem{}

	target := filepath.Join(dir, "a", "b", "c")
	if err := fs.MkdirAll(target, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
}

func TestOSFileSystem_MkdirAll_InvalidPath(t *testing.T) {
	fs := &OSFileSystem{}
	// Attempt to create a directory under a non-writable path
	err := fs.MkdirAll("/proc/nonexistent/path", 0755)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestOSFileSystem_WriteReadFile(t *testing.T) {
	dir := t.TempDir()
	fs := &OSFileSystem{}

	path := filepath.Join(dir, "testfile.txt")
	content := []byte("hello gadget")

	if err := fs.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	data, err := fs.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("ReadFile = %q, want %q", string(data), string(content))
	}
}

func TestOSFileSystem_WriteFile_InvalidPath(t *testing.T) {
	fs := &OSFileSystem{}
	err := fs.WriteFile("/proc/nonexistent/file.txt", []byte("data"), 0644)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestOSFileSystem_ReadFile_NotFound(t *testing.T) {
	fs := &OSFileSystem{}
	_, err := fs.ReadFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestOSFileSystem_Symlink(t *testing.T) {
	dir := t.TempDir()
	fs := &OSFileSystem{}

	target := filepath.Join(dir, "target.txt")
	if err := fs.WriteFile(target, []byte("target"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	linkPath := filepath.Join(dir, "link.txt")
	if err := fs.Symlink(target, linkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	resolved, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink failed: %v", err)
	}
	if resolved != target {
		t.Errorf("symlink points to %q, want %q", resolved, target)
	}
}

func TestOSFileSystem_Symlink_InvalidPath(t *testing.T) {
	fs := &OSFileSystem{}
	err := fs.Symlink("/nonexistent/target", "/proc/nonexistent/link")
	if err == nil {
		t.Error("expected error for invalid symlink path")
	}
}

func TestOSFileSystem_RemoveAll(t *testing.T) {
	dir := t.TempDir()
	fs := &OSFileSystem{}

	target := filepath.Join(dir, "removeme")
	if err := fs.MkdirAll(target, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create a file inside to verify recursive removal
	innerFile := filepath.Join(target, "inner.txt")
	if err := fs.WriteFile(innerFile, []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.RemoveAll(target); err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("directory still exists after RemoveAll")
	}
}

func TestOSFileSystem_ReadDir(t *testing.T) {
	dir := t.TempDir()
	fs := &OSFileSystem{}

	// Create files
	names := []string{"alpha.txt", "beta.txt", "gamma.txt"}
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := fs.WriteFile(path, []byte(name), 0644); err != nil {
			t.Fatalf("WriteFile(%s) failed: %v", name, err)
		}
	}

	entries, err := fs.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != len(names) {
		t.Errorf("ReadDir returned %d entries, want %d", len(entries), len(names))
	}

	entryNames := make(map[string]bool)
	for _, e := range entries {
		entryNames[e.Name()] = true
	}
	for _, name := range names {
		if !entryNames[name] {
			t.Errorf("ReadDir missing entry %q", name)
		}
	}
}

func TestOSFileSystem_ReadDir_NotFound(t *testing.T) {
	fs := &OSFileSystem{}
	_, err := fs.ReadDir("/nonexistent/directory")
	if err == nil {
		t.Error("expected error for missing directory")
	}
}
