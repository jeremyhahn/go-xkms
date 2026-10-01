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

package luks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVolume_Unlock_AlreadyMounted uses the root filesystem, which is always a
// mount point, to verify Unlock refuses to stack a second mount.
func TestVolume_Unlock_AlreadyMounted(t *testing.T) {
	luksPath := filepath.Join(t.TempDir(), "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))

	v := NewVolumeWithPaths(luksPath, "/")
	mounted, err := v.IsMounted()
	require.NoError(t, err)
	require.True(t, mounted, "/ must be reported as mounted")

	assert.ErrorIs(t, v.Unlock("passphrase"), ErrVolumeAlreadyMounted)
}

func TestVolume_GetMountPoint(t *testing.T) {
	t.Parallel()

	v := NewVolumeWithPaths("/tmp/vault.luks", "/tmp/mnt")
	assert.Equal(t, "/tmp/mnt", v.GetMountPoint())
	assert.Equal(t, v.MountPoint, v.GetMountPoint())
}

func TestNewVolumeFromHome(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	xhome.SetRoot(base)
	t.Cleanup(xhome.ResetRoot)

	home, err := xhome.Resolve()
	require.NoError(t, err)

	v := NewVolumeFromHome(home)
	require.NotNil(t, v)
	assert.Equal(t, home.LUKSPath(), v.LUKSPath)
	assert.Equal(t, home.MountPoint(), v.MountPoint)
	assert.Equal(t, MapperName, v.MapperName)
}

// TestNewVolume_WithoutHomeDirectory covers the error branch of NewVolume
// when xhome cannot resolve a home directory (no XKEY_HOME, no per-user
// home, no system-wide fallback). NewVolume resolves its paths through
// xhome.Resolve (BREAKING, go-xkms compat cleanup PR5: the deprecated
// GetDefaultLUKSPath/GetDefaultDataDir/DefaultLUKSFile/DefaultDataDir home
// -relative defaults were deleted), so the error it returns is whatever
// xhome.Resolve returns.
func TestNewVolume_WithoutHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(xhome.EnvHome, "")

	volume, err := NewVolume()
	require.Error(t, err)
	assert.Nil(t, volume)

	// ExpandPath must degrade gracefully rather than panic or drop the path.
	assert.Equal(t, "~/vault.luks", ExpandPath("~/vault.luks"))
	assert.Equal(t, "/abs/vault.luks", ExpandPath("/abs/vault.luks"))
}

func TestCopyFile_SourceIsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	require.NoError(t, os.Mkdir(srcDir, 0700))

	err := copyFile(srcDir, filepath.Join(dir, "dst"))
	assert.Error(t, err, "copying a directory as a file must fail rather than create an empty file")
}

func TestCopyDir_NestedTreeAndFailurePropagation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	require.NoError(t, os.MkdirAll(filepath.Join(src, "a", "b"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "a", "mid.txt"), []byte("mid"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "a", "b", "leaf.txt"), []byte("leaf"), 0640))
	require.NoError(t, os.MkdirAll(dst, 0700))

	require.NoError(t, copyDir(src, dst))

	for path, want := range map[string]string{
		"top.txt":      "top",
		"a/mid.txt":    "mid",
		"a/b/leaf.txt": "leaf",
	} {
		got, err := os.ReadFile(filepath.Join(dst, path))
		require.NoError(t, err, path)
		assert.Equal(t, want, string(got), path)
	}

	info, err := os.Stat(filepath.Join(dst, "a", "b", "leaf.txt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), info.Mode().Perm(), "file permissions must be preserved")

	// A missing nested source directory must surface as an error rather than
	// silently copying a partial tree.
	assert.Error(t, copyDir(filepath.Join(src, "does-not-exist"), dst))
}

func TestWrappedAndMessageErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying failure")

	wrapped := &WrappedError{Msg: "failed to stat file", Err: cause}
	assert.Equal(t, "failed to stat file: underlying failure", wrapped.Error())
	assert.ErrorIs(t, wrapped, cause)

	msg := &MessageError{Msg: "unknown pattern: 9"}
	assert.Equal(t, "unknown pattern: 9", msg.Error())
	assert.NotErrorIs(t, msg, cause)
}

func TestCopyDir_DestinationBlockedByFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	require.NoError(t, os.MkdirAll(filepath.Join(src, "sub"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "sub", "file.txt"), []byte("x"), 0600))
	require.NoError(t, os.MkdirAll(dst, 0700))

	// A regular file occupies the path where the sub-directory must go.
	require.NoError(t, os.WriteFile(filepath.Join(dst, "sub"), []byte("blocker"), 0600))

	assert.Error(t, copyDir(src, dst), "a blocked destination directory must abort the copy")
}

func TestCopyDir_FileCopyFailurePropagates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	require.NoError(t, os.MkdirAll(src, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "entry"), []byte("payload"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(dst, "entry"), 0700))

	assert.Error(t, copyDir(src, dst), "a file that cannot be written must abort the copy")
}

// TestChownHelpers_NoopWhenNotElevated verifies the best-effort ownership
// helpers do nothing (and never error) when the process was not elevated via
// sudo or pkexec, which is the case for the unprivileged GUI process.
func TestChownHelpers_NoopWhenNotElevated(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))

	before, err := os.Stat(file)
	require.NoError(t, err)

	// No SUDO_UID / PKEXEC_UID: the calling user cannot be resolved, so both
	// helpers must return without touching the tree.
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("PKEXEC_UID", "")

	ChownToCallingUser(file)
	chownTreeToCallingUser(dir)

	after, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, before.Mode(), after.Mode())
}
