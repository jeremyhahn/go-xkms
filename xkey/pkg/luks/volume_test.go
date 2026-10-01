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
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	sdkluks "github.com/jeremyhahn/go-xkms/sdk/go/luks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// fakeExecutor is a sdkluks.Executor double driven entirely by the function
// fields a test sets. Every method panics if called without its function
// set, so a test that expects Volume to short-circuit before reaching the
// Executor fails loudly if that assumption is wrong.
type fakeExecutor struct {
	createFn  func(ctx context.Context, cfg *sdkluks.VolumeConfig, size int64, pass string) error
	unlockFn  func(ctx context.Context, cfg *sdkluks.VolumeConfig, pass string) error
	lockFn    func(ctx context.Context, cfg *sdkluks.VolumeConfig) error
	mountFn   func(ctx context.Context, cfg *sdkluks.VolumeConfig) error
	unmountFn func(ctx context.Context, cfg *sdkluks.VolumeConfig) error
}

func (f *fakeExecutor) Create(ctx context.Context, cfg *sdkluks.VolumeConfig, size int64, pass string) error {
	return f.createFn(ctx, cfg, size, pass)
}
func (f *fakeExecutor) Unlock(ctx context.Context, cfg *sdkluks.VolumeConfig, pass string) error {
	return f.unlockFn(ctx, cfg, pass)
}
func (f *fakeExecutor) Lock(ctx context.Context, cfg *sdkluks.VolumeConfig) error {
	return f.lockFn(ctx, cfg)
}
func (f *fakeExecutor) Mount(ctx context.Context, cfg *sdkluks.VolumeConfig) error {
	return f.mountFn(ctx, cfg)
}
func (f *fakeExecutor) Unmount(ctx context.Context, cfg *sdkluks.VolumeConfig) error {
	return f.unmountFn(ctx, cfg)
}
func (f *fakeExecutor) IsMounted(cfg *sdkluks.VolumeConfig) bool {
	panic("fakeExecutor: IsMounted not expected to be called by Volume")
}
func (f *fakeExecutor) IsUnlocked(cfg *sdkluks.VolumeConfig) bool {
	panic("fakeExecutor: IsUnlocked not expected to be called by Volume")
}

// withFakeExecutor substitutes the package-level volumeExecutor for the
// duration of the test.
func withFakeExecutor(t *testing.T, fake *fakeExecutor) {
	t.Helper()
	previous := volumeExecutor
	volumeExecutor = fake
	t.Cleanup(func() { volumeExecutor = previous })
}

// withMountChecks substitutes the package-level checkMounted / checkUnlocked
// seams Volume.IsMounted and Volume.IsOpen read through, for the duration of
// the test.
func withMountChecks(t *testing.T, mounted func(string) (bool, error), unlocked func(string) bool) {
	t.Helper()
	origMounted, origUnlocked := checkMounted, checkUnlocked
	checkMounted = mounted
	checkUnlocked = unlocked
	t.Cleanup(func() {
		checkMounted = origMounted
		checkUnlocked = origUnlocked
	})
}

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"expand tilde", "~/test/path", filepath.Join(home, "test/path")},
		{"absolute path unchanged", "/absolute/path", "/absolute/path"},
		{"relative path unchanged", "relative/path", "relative/path"},
		{"tilde only", "~", "~"},
		{"tilde in middle unchanged", "/path/~/file", "/path/~/file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExpandPath(tt.input))
		})
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "xkey", MapperName)
}

// TestNewVolume resolves its paths through xhome.Resolve, not a legacy
// home-relative default.
func TestNewVolume(t *testing.T) {
	dir := t.TempDir()
	xhome.SetRoot(dir)
	defer xhome.ResetRoot()

	vol, err := NewVolume()
	require.NoError(t, err)
	require.NotNil(t, vol)

	h, err := xhome.Resolve()
	require.NoError(t, err)

	assert.Equal(t, h.LUKSPath(), vol.LUKSPath)
	assert.Equal(t, h.MountPoint(), vol.MountPoint)
	assert.Equal(t, MapperName, vol.MapperName)
}

func TestNewVolumeWithPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name          string
		luksPath      string
		mountPoint    string
		expectedLuks  string
		expectedMount string
	}{
		{"absolute paths", "/tmp/test.luks", "/tmp/testmount", "/tmp/test.luks", "/tmp/testmount"},
		{"paths with tilde", "~/custom.luks", "~/customdir", filepath.Join(home, "custom.luks"), filepath.Join(home, "customdir")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vol := NewVolumeWithPaths(tt.luksPath, tt.mountPoint)
			require.NotNil(t, vol)
			assert.Equal(t, tt.expectedLuks, vol.LUKSPath)
			assert.Equal(t, tt.expectedMount, vol.MountPoint)
			assert.Equal(t, MapperName, vol.MapperName)
		})
	}
}

func TestVolume_Exists(t *testing.T) {
	t.Run("file does not exist", func(t *testing.T) {
		vol := NewVolumeWithPaths("/nonexistent/path.luks", "/tmp/mount")
		assert.False(t, vol.Exists())
	})

	t.Run("file exists", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test*.luks")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		vol := NewVolumeWithPaths(tmpFile.Name(), "/tmp/mount")
		assert.True(t, vol.Exists())
	})
}

func TestVolume_StateChecks(t *testing.T) {
	vol := &Volume{
		LUKSPath:   "/nonexistent.luks",
		MountPoint: "/nonexistent/mount",
		MapperName: "xkey_test_nonexistent_12345",
	}

	assert.False(t, vol.Exists())
	assert.False(t, vol.IsLUKS())
	mounted, err := vol.IsMounted()
	require.NoError(t, err)
	assert.False(t, mounted)
	assert.False(t, vol.IsOpen())
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestVolume_Create_AlreadyExists(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test*.luks")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	vol := NewVolumeWithPaths(tmpFile.Name(), "/tmp/mount")
	err = vol.Create(1024*1024, "testpass")
	assert.ErrorIs(t, err, ErrVolumeAlreadyExists)
	assert.ErrorIs(t, err, sdkluks.ErrVolumeAlreadyExists)
}

// TestVolume_Create_TranslatesExecutorAlreadyExists proves the rare TOCTOU
// race -- the pre-check passes but the Executor itself reports the
// container already exists -- is still translated to xkey's own sentinel.
func TestVolume_Create_TranslatesExecutorAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	vol := NewVolumeWithPaths(filepath.Join(dir, "vault.luks"), filepath.Join(dir, "mnt"))

	withFakeExecutor(t, &fakeExecutor{
		createFn: func(context.Context, *sdkluks.VolumeConfig, int64, string) error {
			return sdkluks.ErrVolumeAlreadyExists
		},
	})

	err := vol.Create(1024, "passphrase")
	assert.ErrorIs(t, err, ErrVolumeAlreadyExists)
}

func TestVolume_Create_DelegatesToExecutor(t *testing.T) {
	dir := t.TempDir()
	vol := NewVolumeWithPaths(filepath.Join(dir, "vault.luks"), filepath.Join(dir, "mnt"))

	var gotSize int64
	var gotPass string
	withFakeExecutor(t, &fakeExecutor{
		createFn: func(_ context.Context, cfg *sdkluks.VolumeConfig, size int64, pass string) error {
			assert.Equal(t, vol.LUKSPath, cfg.LUKSPath)
			assert.Equal(t, vol.MountPoint, cfg.MountPoint)
			assert.Equal(t, vol.MapperName, cfg.MapperName)
			gotSize = size
			gotPass = pass
			return nil
		},
	})

	require.NoError(t, vol.Create(2048, "s3cret"))
	assert.Equal(t, int64(2048), gotSize)
	assert.Equal(t, "s3cret", gotPass)
}

func TestVolume_Create_ExecutorErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	vol := NewVolumeWithPaths(filepath.Join(dir, "vault.luks"), filepath.Join(dir, "mnt"))

	wantErr := errors.New("format rejected")
	withFakeExecutor(t, &fakeExecutor{
		createFn: func(context.Context, *sdkluks.VolumeConfig, int64, string) error { return wantErr },
	})

	assert.ErrorIs(t, vol.Create(2048, "s3cret"), wantErr)
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

func TestVolume_Unlock_NotFound(t *testing.T) {
	vol := NewVolumeWithPaths("/nonexistent.luks", "/tmp/mount")
	err := vol.Unlock("testpass")
	assert.ErrorIs(t, err, ErrVolumeNotFound)
}

func TestVolume_Unlock_TranslatesExecutorNotFound(t *testing.T) {
	luksPath := filepath.Join(t.TempDir(), "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	vol := NewVolumeWithPaths(luksPath, filepath.Join(t.TempDir(), "mnt"))

	withFakeExecutor(t, &fakeExecutor{
		unlockFn: func(context.Context, *sdkluks.VolumeConfig, string) error { return sdkluks.ErrVolumeNotFound },
	})

	assert.ErrorIs(t, vol.Unlock("passphrase"), ErrVolumeNotFound)
}

func TestVolume_Unlock_UnlockFails(t *testing.T) {
	luksPath := filepath.Join(t.TempDir(), "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	vol := NewVolumeWithPaths(luksPath, filepath.Join(t.TempDir(), "mnt"))

	wantErr := errors.New("wrong passphrase")
	withFakeExecutor(t, &fakeExecutor{
		unlockFn: func(context.Context, *sdkluks.VolumeConfig, string) error { return wantErr },
	})

	assert.ErrorIs(t, vol.Unlock("passphrase"), wantErr)
}

// TestVolume_Unlock_MountFailureLocksBack proves a failed Mount after a
// successful Unlock is unwound: Lock is called so Unlock stays
// all-or-nothing from the caller's perspective.
func TestVolume_Unlock_MountFailureLocksBack(t *testing.T) {
	luksPath := filepath.Join(t.TempDir(), "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	vol := NewVolumeWithPaths(luksPath, filepath.Join(t.TempDir(), "mnt"))

	mountErr := errors.New("mount failed")
	lockCalls := 0
	withFakeExecutor(t, &fakeExecutor{
		unlockFn: func(context.Context, *sdkluks.VolumeConfig, string) error { return nil },
		mountFn:  func(context.Context, *sdkluks.VolumeConfig) error { return mountErr },
		lockFn:   func(context.Context, *sdkluks.VolumeConfig) error { lockCalls++; return nil },
	})

	err := vol.Unlock("passphrase")
	assert.ErrorIs(t, err, mountErr)
	assert.Equal(t, 1, lockCalls, "a failed mount must lock the volume back")
}

// TestVolume_Unlock_MountFailureJoinsLockCleanupError proves a Lock failure
// during Unlock's own rollback is joined into the returned error, not
// swallowed.
func TestVolume_Unlock_MountFailureJoinsLockCleanupError(t *testing.T) {
	luksPath := filepath.Join(t.TempDir(), "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	vol := NewVolumeWithPaths(luksPath, filepath.Join(t.TempDir(), "mnt"))

	mountErr := errors.New("mount failed")
	lockErr := errors.New("lock cleanup failed")
	withFakeExecutor(t, &fakeExecutor{
		unlockFn: func(context.Context, *sdkluks.VolumeConfig, string) error { return nil },
		mountFn:  func(context.Context, *sdkluks.VolumeConfig) error { return mountErr },
		lockFn:   func(context.Context, *sdkluks.VolumeConfig) error { return lockErr },
	})

	err := vol.Unlock("passphrase")
	assert.ErrorIs(t, err, mountErr)
	assert.ErrorIs(t, err, lockErr)
}

func TestVolume_Unlock_Success(t *testing.T) {
	luksPath := filepath.Join(t.TempDir(), "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	vol := NewVolumeWithPaths(luksPath, filepath.Join(t.TempDir(), "mnt"))

	unlockCalls, mountCalls := 0, 0
	withFakeExecutor(t, &fakeExecutor{
		unlockFn: func(context.Context, *sdkluks.VolumeConfig, string) error { unlockCalls++; return nil },
		mountFn:  func(context.Context, *sdkluks.VolumeConfig) error { mountCalls++; return nil },
	})

	require.NoError(t, vol.Unlock("passphrase"))
	assert.Equal(t, 1, unlockCalls)
	assert.Equal(t, 1, mountCalls)
}

// ---------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------

func TestVolume_Lock_NotMounted(t *testing.T) {
	vol := &Volume{
		LUKSPath:   "/test.luks",
		MountPoint: "/nonexistent/mount",
		MapperName: "xkey_test_nonexistent_12345",
	}
	assert.ErrorIs(t, vol.Lock(), ErrVolumeNotMounted)
}

func TestVolume_Lock_Success(t *testing.T) {
	vol := &Volume{
		LUKSPath:   filepath.Join(t.TempDir(), "vault.luks"),
		MountPoint: t.TempDir(),
		MapperName: MapperName,
	}

	withMountChecks(t,
		func(string) (bool, error) { return true, nil },
		func(string) bool { return true },
	)

	unmountCalls, lockCalls := 0, 0
	withFakeExecutor(t, &fakeExecutor{
		unmountFn: func(context.Context, *sdkluks.VolumeConfig) error { unmountCalls++; return nil },
		lockFn:    func(context.Context, *sdkluks.VolumeConfig) error { lockCalls++; return nil },
	})

	require.NoError(t, vol.Lock())
	assert.Equal(t, 1, unmountCalls)
	assert.Equal(t, 1, lockCalls)
}

func TestVolume_Lock_UnmountFails(t *testing.T) {
	vol := &Volume{
		LUKSPath:   filepath.Join(t.TempDir(), "vault.luks"),
		MountPoint: t.TempDir(),
		MapperName: MapperName,
	}

	withMountChecks(t,
		func(string) (bool, error) { return true, nil },
		func(string) bool { return true },
	)

	wantErr := errors.New("target is busy")
	lockCalls := 0
	withFakeExecutor(t, &fakeExecutor{
		unmountFn: func(context.Context, *sdkluks.VolumeConfig) error { return wantErr },
		lockFn:    func(context.Context, *sdkluks.VolumeConfig) error { lockCalls++; return nil },
	})

	assert.ErrorIs(t, vol.Lock(), wantErr)
	assert.Equal(t, 0, lockCalls, "a failed unmount must not proceed to lock")
}

// ---------------------------------------------------------------------------
// CopyDataToVolume
// ---------------------------------------------------------------------------

func TestVolume_CopyDataToVolume_NotMounted(t *testing.T) {
	vol := NewVolumeWithPaths("/test.luks", "/tmp/notmounted")
	err := vol.CopyDataToVolume("/tmp/source")
	assert.ErrorIs(t, err, ErrVolumeNotMounted)
}

func TestVolume_CopyDataToVolume_Success(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	require.NoError(t, os.MkdirAll(src, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "secret.txt"), []byte("payload"), 0600))

	mnt := filepath.Join(dir, "mnt")
	require.NoError(t, os.MkdirAll(mnt, 0700))

	vol := NewVolumeWithPaths(filepath.Join(dir, "vault.luks"), mnt)
	withMountChecks(t, func(string) (bool, error) { return true, nil }, func(string) bool { return false })

	require.NoError(t, vol.CopyDataToVolume(src))

	got, err := os.ReadFile(filepath.Join(mnt, "secret.txt"))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
}

// ---------------------------------------------------------------------------
// copyFile / copyDir
// ---------------------------------------------------------------------------

func TestCopyFile(t *testing.T) {
	srcDir, err := os.MkdirTemp("", "copy_src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "copy_dst")
	require.NoError(t, err)
	defer os.RemoveAll(dstDir)

	srcFile := filepath.Join(srcDir, "testfile.txt")
	dstFile := filepath.Join(dstDir, "testfile.txt")
	content := "test content for copy"

	require.NoError(t, os.WriteFile(srcFile, []byte(content), 0644))
	require.NoError(t, copyFile(srcFile, dstFile))

	data, err := os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))
}

func TestCopyFile_NonExistentSource(t *testing.T) {
	err := copyFile("/nonexistent/source.txt", "/tmp/dest.txt")
	assert.Error(t, err)
}

func TestCopyDir(t *testing.T) {
	srcDir, err := os.MkdirTemp("", "copydir_src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "copydir_dst")
	require.NoError(t, err)
	defer os.RemoveAll(dstDir)

	subDir := filepath.Join(srcDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))

	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("content2"), 0644))

	require.NoError(t, copyDir(srcDir, dstDir))

	data1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content1", string(data1))

	data2, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file2.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content2", string(data2))
}

func TestCopyDir_NonExistentSource(t *testing.T) {
	err := copyDir("/nonexistent/source", "/tmp/dest")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Privilege / chown
// ---------------------------------------------------------------------------

func TestChownToCallingUser_NonRoot(t *testing.T) {
	origGeteuid := geteuid
	geteuid = func() int { return 1000 }
	t.Cleanup(func() { geteuid = origGeteuid })

	tmpDir := t.TempDir()
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1000")

	ChownToCallingUser(tmpDir)

	info, err := os.Stat(tmpDir)
	require.NoError(t, err)
	assert.NotNil(t, info)

	testFile := filepath.Join(tmpDir, "probe")
	assert.NoError(t, os.WriteFile(testFile, []byte("ok"), 0600))
}

func TestChownToCallingUser_RootWithoutSudoEnv(t *testing.T) {
	origGeteuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = origGeteuid })

	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("PKEXEC_UID", "")

	tmpDir := t.TempDir()
	before, err := os.Stat(tmpDir)
	require.NoError(t, err)

	ChownToCallingUser(tmpDir)

	after, err := os.Stat(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, before.Mode(), after.Mode(),
		"directory must be left untouched when the calling user is unresolvable")
}

func TestResolveCallingUser(t *testing.T) {
	clearEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("SUDO_UID", "")
		t.Setenv("SUDO_GID", "")
		t.Setenv("PKEXEC_UID", "")
	}

	t.Run("no elevation env vars set", func(t *testing.T) {
		clearEnv(t)
		uid, gid, ok := resolveCallingUser()
		assert.False(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)
	})

	t.Run("invalid SUDO_UID", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SUDO_UID", "not-a-number")
		t.Setenv("SUDO_GID", "1000")
		uid, gid, ok := resolveCallingUser()
		assert.False(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)
	})

	t.Run("valid SUDO_UID with invalid SUDO_GID falls back to passwd lookup", func(t *testing.T) {
		clearEnv(t)
		currentUser, err := user.Current()
		require.NoError(t, err)
		t.Setenv("SUDO_UID", currentUser.Uid)
		t.Setenv("SUDO_GID", "not-a-number")

		uid, gid, ok := resolveCallingUser()
		expectedUID, err := strconv.Atoi(currentUser.Uid)
		require.NoError(t, err)
		expectedGID, err := strconv.Atoi(currentUser.Gid)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, expectedUID, uid)
		assert.Equal(t, expectedGID, gid)
	})

	t.Run("valid SUDO_UID and SUDO_GID", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SUDO_UID", "1000")
		t.Setenv("SUDO_GID", "1000")
		uid, gid, ok := resolveCallingUser()
		assert.True(t, ok)
		assert.Equal(t, 1000, uid)
		assert.Equal(t, 1000, gid)
	})

	t.Run("invalid PKEXEC_UID", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("PKEXEC_UID", "garbage")
		uid, gid, ok := resolveCallingUser()
		assert.False(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)
	})

	t.Run("valid PKEXEC_UID resolves GID from passwd", func(t *testing.T) {
		clearEnv(t)
		currentUser, err := user.Current()
		require.NoError(t, err)
		t.Setenv("PKEXEC_UID", currentUser.Uid)

		uid, gid, ok := resolveCallingUser()
		expectedUID, err := strconv.Atoi(currentUser.Uid)
		require.NoError(t, err)
		expectedGID, err := strconv.Atoi(currentUser.Gid)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, expectedUID, uid)
		assert.Equal(t, expectedGID, gid)
	})

	t.Run("PKEXEC_UID with nonexistent user", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("PKEXEC_UID", "99999")
		_, _, _ = resolveCallingUser() // must not panic
	})

	t.Run("SUDO_UID takes precedence over PKEXEC_UID", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SUDO_UID", "1001")
		t.Setenv("SUDO_GID", "1001")
		t.Setenv("PKEXEC_UID", "2002")
		uid, gid, ok := resolveCallingUser()
		assert.True(t, ok)
		assert.Equal(t, 1001, uid)
		assert.Equal(t, 1001, gid)
	})

	t.Run("empty string values treated as unset", func(t *testing.T) {
		clearEnv(t)
		uid, gid, ok := resolveCallingUser()
		assert.False(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)
	})

	t.Run("zero UID is valid", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SUDO_UID", "0")
		t.Setenv("SUDO_GID", "0")
		uid, gid, ok := resolveCallingUser()
		assert.True(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)
	})
}

func TestLookupGIDForUID(t *testing.T) {
	t.Run("valid current user", func(t *testing.T) {
		currentUser, err := user.Current()
		require.NoError(t, err)
		gid, err := lookupGIDForUID(currentUser.Uid)
		require.NoError(t, err)
		expectedGID, err := strconv.Atoi(currentUser.Gid)
		require.NoError(t, err)
		assert.Equal(t, expectedGID, gid)
	})

	t.Run("root user", func(t *testing.T) {
		gid, err := lookupGIDForUID("0")
		require.NoError(t, err)
		assert.Equal(t, 0, gid)
	})

	t.Run("nonexistent UID", func(t *testing.T) {
		_, err := lookupGIDForUID("4294967294")
		assert.Error(t, err)
	})

	t.Run("invalid UID string", func(t *testing.T) {
		_, err := lookupGIDForUID("not-a-uid")
		assert.Error(t, err)
	})
}

// TestChownToCallingUser_InvalidPath verifies graceful handling when chown
// targets a nonexistent path while running as root.
func TestChownToCallingUser_InvalidPath(t *testing.T) {
	origGeteuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = origGeteuid })

	t.Setenv("SUDO_UID", "0")
	t.Setenv("SUDO_GID", "0")

	// Must not panic despite the path not existing.
	ChownToCallingUser(filepath.Join("/nonexistent/path", "probe"))
}

// TestChownTreeToCallingUser_LchownFailureIsLogged verifies that a chown
// failure on an individual entry (target uid the unprivileged test process
// cannot assign) is logged and the walk continues rather than panicking.
func TestChownTreeToCallingUser_LchownFailureIsLogged(t *testing.T) {
	origGeteuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = origGeteuid })

	// UID 1 (daemon) is never the uid of the unprivileged test process, so
	// os.Lchown to it fails with EPERM without any real elevation.
	t.Setenv("SUDO_UID", "1")
	t.Setenv("SUDO_GID", "1")

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0600))

	chownTreeToCallingUser(root)

	data, err := os.ReadFile(filepath.Join(root, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "x", string(data))
}

func TestChownTreeToCallingUser_RootChownsTree(t *testing.T) {
	origGeteuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = origGeteuid })

	t.Setenv("SUDO_UID", "0")
	t.Setenv("SUDO_GID", "0")

	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	require.NoError(t, os.MkdirAll(sub, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "file.txt"), []byte("x"), 0600))

	chownTreeToCallingUser(root)

	data, err := os.ReadFile(filepath.Join(sub, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "x", string(data))
}
