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

package ipc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// foreignUIDs stands in for "the directory belongs to another user". A test
// cannot chown a directory to another user without root, so instead of
// changing the owner it changes who is trusted: validation against a set
// that excludes this process's uid sees this process's directory exactly as
// it would see another user's.
func foreignUIDs() []int {
	return []int{os.Geteuid() + 100000}
}

func TestValidateSocketDir_AcceptsPrivateDirectory(t *testing.T) {
	assert.NoError(t, validateSocketDir(privateDir(t), trustedUIDs()))
}

func TestValidateSocketDir_RefusesForeignOwner(t *testing.T) {
	err := validateSocketDir(privateDir(t), foreignUIDs())
	require.ErrorIs(t, err, ErrSocketDirInsecure)
	assert.ErrorContains(t, err, "owned by uid")
}

func TestValidateSocketDir_RefusesGroupOrOtherBits(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o750, 0o701, 0o770, 0o500} {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, mode))

		err := validateSocketDir(dir, trustedUIDs())
		assert.ErrorIs(t, err, ErrSocketDirInsecure, "mode %04o", mode)
	}
}

func TestValidateSocketDir_RefusesSymlink(t *testing.T) {
	target := privateDir(t)
	link := filepath.Join(privateDir(t), "link")
	require.NoError(t, os.Symlink(target, link))

	err := validateSocketDir(link, trustedUIDs())
	require.ErrorIs(t, err, ErrSocketDirInsecure)
	assert.ErrorContains(t, err, "symbolic link")
}

func TestValidateSocketDir_RefusesNonDirectory(t *testing.T) {
	file := filepath.Join(privateDir(t), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o700))

	assert.ErrorIs(t, validateSocketDir(file, trustedUIDs()), ErrSocketDirInsecure)
}

func TestValidateSocketDir_MissingDirectoryIsNotExist(t *testing.T) {
	err := validateSocketDir(filepath.Join(privateDir(t), "absent"), trustedUIDs())
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.NotErrorIs(t, err, ErrSocketDirInsecure)
}

func TestEnsureSocketDir_CreatesEveryComponentPrivate(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b")

	require.NoError(t, ensureSocketDir(dir, trustedUIDs()))

	for _, created := range []string{filepath.Join(base, "a"), dir} {
		info, err := os.Lstat(created)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(socketDirMode), info.Mode().Perm(), created)
	}
}

func TestEnsureSocketDir_RefusesExistingWideDirectoryWithoutRepairingIt(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))

	require.ErrorIs(t, ensureSocketDir(dir, trustedUIDs()), ErrSocketDirInsecure)

	info, err := os.Lstat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "a refused directory must not be chmoded")
}

func TestEnsureSocketDir_RefusesForeignOwnedDirectory(t *testing.T) {
	assert.ErrorIs(t, ensureSocketDir(privateDir(t), foreignUIDs()), ErrSocketDirInsecure)
}

func TestEnsureSocketDir_MkdirFailureUnderARegularFileIsReported(t *testing.T) {
	// blocker is a regular file standing where a parent directory needs to
	// be created; every path below it -- at any depth -- resolves to
	// ENOTDIR, not ENOENT, so Mkdir's own failure (not fs.ErrExist) must be
	// reported as ErrSocketCreateFailed rather than swallowed or mistaken
	// for the "someone else already created it" race.
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))

	dir := filepath.Join(blocker, "child", "grandchild")
	err := ensureSocketDir(dir, trustedUIDs())
	require.ErrorIs(t, err, ErrSocketCreateFailed)

	_, statErr := os.Lstat(dir)
	assert.True(t, os.IsNotExist(statErr) || errors.Is(statErr, syscall.ENOTDIR),
		"grandchild must not exist: %v", statErr)
}

func TestEnsureSocketDir_RefusesSymlinkedDirectory(t *testing.T) {
	link := filepath.Join(privateDir(t), "xkey")
	require.NoError(t, os.Symlink(privateDir(t), link))

	assert.ErrorIs(t, ensureSocketDir(link, trustedUIDs()), ErrSocketDirInsecure)
}

func TestNewServer_RefusesInsecureDirectories(t *testing.T) {
	wide := t.TempDir()
	require.NoError(t, os.Chmod(wide, 0o755))

	link := filepath.Join(privateDir(t), "link")
	require.NoError(t, os.Symlink(privateDir(t), link))

	for name, dir := range map[string]string{"0755": wide, "symlink": link} {
		t.Run(name, func(t *testing.T) {
			srv, err := NewServer(filepath.Join(dir, "xkey.sock"), &mockHandler{}, testLogger())
			assert.Nil(t, srv)
			assert.ErrorIs(t, err, ErrSocketDirInsecure)
			_, statErr := os.Lstat(filepath.Join(dir, "xkey.sock"))
			assert.ErrorIs(t, statErr, os.ErrNotExist, "no socket may be bound in a refused directory")
		})
	}
}

func TestNewServer_EmptyPathIsUnresolved(t *testing.T) {
	srv, err := NewServer("", &mockHandler{}, testLogger())
	assert.Nil(t, srv)
	assert.ErrorIs(t, err, ErrSocketPathUnresolved)
}

func TestReclaimSocket_RemovesOwnStaleSocket(t *testing.T) {
	sockPath := testSocketPath(t)
	staleSocket(t, sockPath)

	require.NoError(t, ReclaimSocket(sockPath))

	_, err := os.Lstat(sockPath)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestReclaimSocket_MissingSocketIsNotAnError(t *testing.T) {
	assert.NoError(t, ReclaimSocket(testSocketPath(t)))
}

func TestReclaimSocket_RefusesForeignOwnedSocket(t *testing.T) {
	sockPath := testSocketPath(t)
	staleSocket(t, sockPath)
	// Against a trusted set that excludes this uid, the socket itself reads
	// as another user's (checkOwner) and so does its directory, which
	// reclaimSocket checks first; either way nothing is removed.
	info, err := os.Lstat(sockPath)
	require.NoError(t, err)
	assert.ErrorIs(t, checkOwner(sockPath, info, foreignUIDs(), ErrSocketNotOwned), ErrSocketNotOwned)

	assert.ErrorIs(t, reclaimSocket(sockPath, foreignUIDs()), ErrSocketDirInsecure)
	_, err = os.Lstat(sockPath)
	assert.NoError(t, err, "a refused socket must not be removed")
}

func TestReclaimSocket_RefusesNonSocket(t *testing.T) {
	sockPath := testSocketPath(t)
	require.NoError(t, os.WriteFile(sockPath, []byte("keep"), 0o600))

	assert.ErrorIs(t, ReclaimSocket(sockPath), ErrSocketNotOwned)
	_, err := os.Lstat(sockPath)
	assert.NoError(t, err)
}

func TestReclaimSocket_RefusesInsecureDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))
	sockPath := filepath.Join(dir, "xkey.sock")
	staleSocket(t, sockPath)

	assert.ErrorIs(t, ReclaimSocket(sockPath), ErrSocketDirInsecure)
	_, err := os.Lstat(sockPath)
	assert.NoError(t, err)
}

func TestTrustedUIDs_IncludesSelfAndRoot(t *testing.T) {
	uids := trustedUIDs()
	assert.Contains(t, uids, os.Geteuid())
	assert.Contains(t, uids, 0)
}

// noSysFileInfo is an fs.FileInfo whose Sys() does not return a
// *syscall.Stat_t, standing in for a platform or filesystem where the owning
// uid cannot be recovered from stat information.
type noSysFileInfo struct{ fakeDir }

func (noSysFileInfo) Sys() any { return nil }

func TestCheckOwner_RefusesWhenOwnerIsUnavailable(t *testing.T) {
	info := noSysFileInfo{fakeDir{name: "/x", mode: 0o700}}

	err := checkOwner("/x", info, trustedUIDs(), ErrSocketNotOwned)

	require.ErrorIs(t, err, ErrSocketNotOwned)
	assert.ErrorContains(t, err, "file owner is unavailable")
}

func TestEnsureSocketDir_PropagatesParentCreationFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Fatal("unit tests must not run as root")
	}
	blocked := filepath.Join(t.TempDir(), "blocked")
	require.NoError(t, os.Mkdir(blocked, 0o500))
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	dir := filepath.Join(blocked, "a", "b")
	err := ensureSocketDir(dir, trustedUIDs())

	require.ErrorIs(t, err, ErrSocketCreateFailed)
	_, statErr := os.Lstat(filepath.Join(blocked, "a"))
	assert.True(t, os.IsNotExist(statErr), "a parent creation failure must not leave a partial component behind")
}

func TestReclaimSocket_LstatFailureOtherThanNotExistIsReported(t *testing.T) {
	// A path component longer than NAME_MAX fails Lstat with ENAMETOOLONG,
	// a real stat error distinct from "socket not present yet".
	sockPath := filepath.Join(privateDir(t), strings.Repeat("a", 300))

	err := reclaimSocket(sockPath, trustedUIDs())

	require.ErrorIs(t, err, ErrSocketNotOwned)
	assert.NotErrorIs(t, err, ErrSocketDirInsecure)
}
