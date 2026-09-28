// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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

package services

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCopyTree_MissingSourceReturnsStatError covers the os.Stat failure
// branch: the source path does not exist.
func TestCopyTree_MissingSourceReturnsStatError(t *testing.T) {
	tmp := t.TempDir()
	err := copyTree(filepath.Join(tmp, "does-not-exist"), filepath.Join(tmp, "dst"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

// TestCopyTree_SingleFileSourceDelegatesToCopyFile covers the branch where
// the source is a regular file rather than a directory.
func TestCopyTree_SingleFileSourceDelegatesToCopyFile(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "file.txt")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0600))

	dst := filepath.Join(tmp, "copy.txt")
	require.NoError(t, copyTree(src, dst))

	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

// TestCopyTree_DirectoryTreeIsCopiedRecursively covers the directory-walk
// branch, including a nested subdirectory.
func TestCopyTree_DirectoryTreeIsCopiedRecursively(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	require.NoError(t, os.MkdirAll(filepath.Join(src, "sub"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "sub", "nested.txt"), []byte("nested"), 0600))

	dst := filepath.Join(tmp, "dst")
	require.NoError(t, copyTree(src, dst))

	top, err := os.ReadFile(filepath.Join(dst, "top.txt"))
	require.NoError(t, err)
	assert.Equal(t, "top", string(top))

	nested, err := os.ReadFile(filepath.Join(dst, "sub", "nested.txt"))
	require.NoError(t, err)
	assert.Equal(t, "nested", string(nested))
}

// TestCopyTree_RecursiveSubdirectoryFailurePropagates covers the branch
// where copying a nested subdirectory fails: the destination already has a
// regular file where the subdirectory needs to go, so the recursive
// MkdirAll call collides with it.
func TestCopyTree_RecursiveSubdirectoryFailurePropagates(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	require.NoError(t, os.MkdirAll(filepath.Join(src, "sub"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "sub", "nested.txt"), []byte("nested"), 0600))

	dst := filepath.Join(tmp, "dst")
	require.NoError(t, os.MkdirAll(dst, 0700))
	// Block the "sub" subdirectory with a regular file at the destination.
	require.NoError(t, os.WriteFile(filepath.Join(dst, "sub"), []byte("blocker"), 0600))

	err := copyTree(src, dst)
	require.Error(t, err)
}

// TestCopyFile_MissingSourceReturnsOpenError covers copyFile's os.Open
// failure branch.
func TestCopyFile_MissingSourceReturnsOpenError(t *testing.T) {
	tmp := t.TempDir()
	err := copyFile(filepath.Join(tmp, "missing"), filepath.Join(tmp, "dst"), 0600)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

// TestCopyFile_MissingDestinationDirReturnsOpenFileError covers copyFile's
// destination os.OpenFile failure branch: the parent directory of dst does
// not exist.
func TestCopyFile_MissingDestinationDirReturnsOpenFileError(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.txt")
	require.NoError(t, os.WriteFile(src, []byte("data"), 0600))

	dst := filepath.Join(tmp, "no-such-dir", "dst.txt")
	err := copyFile(src, dst, 0600)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

// TestCopyFile_CopiesContentsAndMode covers the success path, including
// that the requested file mode is applied to the destination.
func TestCopyFile_CopiesContentsAndMode(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.txt")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0600))

	dst := filepath.Join(tmp, "dst.txt")
	require.NoError(t, copyFile(src, dst, 0640))

	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), info.Mode().Perm())
}

// TestDirExists covers both branches of dirExists.
func TestDirExists(t *testing.T) {
	tmp := t.TempDir()

	assert.False(t, dirExists(filepath.Join(tmp, "nope")))

	dir := filepath.Join(tmp, "adir")
	require.NoError(t, os.MkdirAll(dir, 0700))
	assert.True(t, dirExists(dir))

	file := filepath.Join(tmp, "afile")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	assert.False(t, dirExists(file), "a regular file is not a directory")
}
