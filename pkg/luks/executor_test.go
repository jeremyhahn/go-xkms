// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubLoopSeams replaces every go-luks2 kernel-facing primitive LibExecutor
// uses with a deterministic fake and restores the originals on cleanup.
// Every test that drives LibExecutor past its filesystem-only checks must
// call this first: the defaults point at the real kernel and would try to
// attach a loop device, format a filesystem or mount a device on the host.
func stubLoopSeams(t *testing.T) {
	t.Helper()

	origSetup := setupLoopDevice
	origDetach := detachLoopDevice
	origFind := findLoopDeviceFn
	origFormat := formatLUKS
	origUnlock := unlockLUKS
	origLock := lockLUKS
	origMakeFS := makeFilesystem
	origMount := mountLUKS
	origUnmount := unmountLUKS
	origIsMounted := isMountedFn
	origIsUnlocked := isUnlockedFn
	origChmod := chmodFn
	t.Cleanup(func() {
		setupLoopDevice = origSetup
		detachLoopDevice = origDetach
		findLoopDeviceFn = origFind
		formatLUKS = origFormat
		unlockLUKS = origUnlock
		lockLUKS = origLock
		makeFilesystem = origMakeFS
		mountLUKS = origMount
		unmountLUKS = origUnmount
		isMountedFn = origIsMounted
		isUnlockedFn = origIsUnlocked
		chmodFn = origChmod
	})

	setupLoopDevice = func(string) (string, error) { return "/dev/loop-test0", nil }
	detachLoopDevice = func(string) error { return nil }
	findLoopDeviceFn = func(string) (string, error) { return "/dev/loop-test0", nil }
	formatLUKS = func(luks2.FormatOptions) error { return nil }
	unlockLUKS = func(string, []byte, string) error { return nil }
	lockLUKS = func(string) error { return nil }
	makeFilesystem = func(string, string, string) error { return nil }
	mountLUKS = func(luks2.MountOptions) error { return nil }
	unmountLUKS = func(string, int) error { return nil }
	isMountedFn = func(string) (bool, error) { return false, nil }
	isUnlockedFn = func(string) bool { return false }
}

func testConfig(dir string) *VolumeConfig {
	return &VolumeConfig{
		LUKSPath:   filepath.Join(dir, "vault.luks"),
		MountPoint: filepath.Join(dir, "mnt"),
		MapperName: "xkms-test",
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestLibExecutor_Create_RefusesBeforeCreatingTheContainer(t *testing.T) {
	withKeyringCheck(t, func() error { return luks2.ErrKeyringUnsupported })
	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyringUnavailable)
	assert.ErrorIs(t, err, luks2.ErrKeyringUnsupported)
	assert.NoFileExists(t, cfg.LUKSPath)
}

func TestLibExecutor_Create_AlreadyExists(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, []byte("x"), 0600))

	e := NewLibExecutor()
	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	assert.ErrorIs(t, err, ErrVolumeAlreadyExists)
}

// TestLibExecutor_Create_CreateFileFails covers the create_file error
// branch: the parent directory exists and is writable, but the container
// file itself cannot be created. The container's basename is longer than
// NAME_MAX (255 bytes) rather than blocked by a permission bit, so the case
// still holds when tests run as root.
func TestLibExecutor_Create_CreateFileFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })

	dir := t.TempDir()
	tooLong := strings.Repeat("a", 300) + ".luks"
	cfg := &VolumeConfig{LUKSPath: filepath.Join(dir, tooLong), MountPoint: filepath.Join(dir, "mnt"), MapperName: "xkms-test"}

	e := NewLibExecutor()
	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "create_file", execErr.Operation)
}

// TestLibExecutor_Create_CreateDirFails verifies Create reports a typed
// create_dir error when the container's parent path is not a directory.
func TestLibExecutor_Create_CreateDirFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })

	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	cfg := &VolumeConfig{LUKSPath: filepath.Join(blocker, "vault.luks"), MountPoint: filepath.Join(dir, "mnt"), MapperName: "xkms-test"}

	e := NewLibExecutor()
	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "create_dir", execErr.Operation)
	assert.Equal(t, blocker, execErr.Path)
	assert.NotNil(t, execErr.Unwrap())
}

// TestLibExecutor_Create_TruncateFails verifies that a failed truncate (a
// negative size) does not leave a partially created container file behind.
// A leftover zero-byte file would make every later Create return
// ErrVolumeAlreadyExists.
func TestLibExecutor_Create_TruncateFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })

	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	err := e.Create(context.Background(), cfg, -1, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "truncate", execErr.Operation)

	_, statErr := os.Stat(cfg.LUKSPath)
	assert.True(t, os.IsNotExist(statErr), "the partially created container must be removed")
}

func TestLibExecutor_Create_SetupLoopDeviceFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	setupLoopDevice = func(string) (string, error) { return "", errors.New("no free loop devices") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "setup_loop", execErr.Operation)
	assert.NoFileExists(t, cfg.LUKSPath, "the container file must be removed on loop setup failure")
}

func TestLibExecutor_Create_FormatFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }
	formatLUKS = func(luks2.FormatOptions) error { return errors.New("format rejected") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_format", execErr.Operation)
	assert.Equal(t, 1, detachCalls)
	assert.NoFileExists(t, cfg.LUKSPath)
}

func TestLibExecutor_Create_FormatFails_JoinsCleanupError(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachErr := errors.New("detach failed")
	detachLoopDevice = func(string) error { return detachErr }
	formatLUKS = func(luks2.FormatOptions) error { return errors.New("format rejected") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, detachErr, "a detach failure during format cleanup must not be swallowed")
}

func TestLibExecutor_Create_UnlockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	unlockLUKS = func(string, []byte, string) error { return errors.New("wrong key") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_unlock", execErr.Operation)
	assert.NoFileExists(t, cfg.LUKSPath)
}

func TestLibExecutor_Create_MakeFilesystemFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	lockCalls := 0
	lockLUKS = func(string) error { lockCalls++; return nil }
	makeFilesystem = func(string, string, string) error { return errors.New("mkfs failed") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "create_fs", execErr.Operation)
	assert.Equal(t, 1, lockCalls)
	assert.NoFileExists(t, cfg.LUKSPath)
}

func TestLibExecutor_Create_LockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }
	lockLUKS = func(string) error { return errors.New("busy") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_lock", execErr.Operation)
	assert.Equal(t, 1, detachCalls)
}

func TestLibExecutor_Create_DetachFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	detachLoopDevice = func(string) error { return errors.New("device busy") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "detach_loop", execErr.Operation)
	assert.FileExists(t, cfg.LUKSPath, "a container whose format succeeded must not be removed for a detach failure")
}

func TestLibExecutor_Create_Success(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	require.NoError(t, e.Create(context.Background(), cfg, 1<<20, "passphrase"))

	info, err := os.Stat(cfg.LUKSPath)
	require.NoError(t, err)
	assert.Equal(t, int64(1<<20), info.Size())
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "container file must not be group/world readable")
}

func TestLibExecutor_Create_ContextCanceled(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := NewLibExecutor()
	err := e.Create(ctx, cfg, 1<<20, "passphrase")
	assert.ErrorIs(t, err, context.Canceled)
	assert.NoFileExists(t, cfg.LUKSPath)
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

func TestLibExecutor_Unlock_NotFound(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Unlock(context.Background(), cfg, "passphrase")
	assert.ErrorIs(t, err, ErrVolumeNotFound)
}

func TestLibExecutor_Unlock_RefusesBeforeTouchingTheLoopDevice(t *testing.T) {
	withKeyringCheck(t, func() error { return luks2.ErrKeyringBlocked })
	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, make([]byte, 4096), 0600))

	e := NewLibExecutor()
	err := e.Unlock(context.Background(), cfg, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyringUnavailable)
	var execErr *ExecutorError
	assert.False(t, errors.As(err, &execErr), "no loop device may have been attempted: %v", err)
}

func TestLibExecutor_Unlock_SetupLoopDeviceFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	setupLoopDevice = func(string) (string, error) { return "", errors.New("no free loop devices") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, []byte("container"), 0600))

	e := NewLibExecutor()
	err := e.Unlock(context.Background(), cfg, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "setup_loop", execErr.Operation)
}

func TestLibExecutor_Unlock_UnlockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }
	unlockLUKS = func(string, []byte, string) error { return errors.New("wrong passphrase") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, []byte("container"), 0600))

	e := NewLibExecutor()
	err := e.Unlock(context.Background(), cfg, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_unlock", execErr.Operation)
	assert.Equal(t, 1, detachCalls)
}

func TestLibExecutor_Unlock_Success(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, []byte("container"), 0600))

	e := NewLibExecutor()
	require.NoError(t, e.Unlock(context.Background(), cfg, "passphrase"))
}

// ---------------------------------------------------------------------------
// Mount / Unmount
// ---------------------------------------------------------------------------

func TestLibExecutor_Mount_MkdirMountpointFails(t *testing.T) {
	stubLoopSeams(t)

	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	cfg := &VolumeConfig{LUKSPath: filepath.Join(dir, "vault.luks"), MountPoint: filepath.Join(blocker, "mnt"), MapperName: "xkms-test"}

	e := NewLibExecutor()
	err := e.Mount(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "create_mountpoint", execErr.Operation)
}

func TestLibExecutor_Mount_MountFails(t *testing.T) {
	stubLoopSeams(t)
	mountLUKS = func(luks2.MountOptions) error { return errors.New("mount failed") }

	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	err := e.Mount(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "mount", execErr.Operation)
}

func TestLibExecutor_Mount_Success(t *testing.T) {
	stubLoopSeams(t)

	var mountedOpts luks2.MountOptions
	mountLUKS = func(opts luks2.MountOptions) error { mountedOpts = opts; return nil }

	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	require.NoError(t, e.Mount(context.Background(), cfg))

	info, err := os.Stat(cfg.MountPoint)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, cfg.MapperName, mountedOpts.Device)
	assert.Equal(t, cfg.MountPoint, mountedOpts.MountPoint)
}

func TestLibExecutor_Mount_ChmodsMountPointAfterMount(t *testing.T) {
	stubLoopSeams(t)

	// Simulate the ext4 root inode's default permissions replacing the
	// mount point's mode as part of the mount call itself.
	mountLUKS = func(opts luks2.MountOptions) error {
		return os.Chmod(opts.MountPoint, 0755)
	}

	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	require.NoError(t, e.Mount(context.Background(), cfg))

	info, err := os.Stat(cfg.MountPoint)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), "mount point must be re-asserted to 0700 after mount")
}

func TestLibExecutor_Mount_ChmodMountPointFails(t *testing.T) {
	stubLoopSeams(t)

	unmountCalls := 0
	unmountLUKS = func(string, int) error { unmountCalls++; return nil }
	chmodErr := errors.New("chmod failed")
	chmodFn = func(string, os.FileMode) error { return chmodErr }

	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	err := e.Mount(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "chmod_mountpoint", execErr.Operation)
	assert.ErrorIs(t, err, chmodErr)
	assert.Equal(t, 1, unmountCalls, "a failed chmod must unmount the volume")
}

func TestLibExecutor_Unmount_Fails(t *testing.T) {
	stubLoopSeams(t)
	unmountLUKS = func(string, int) error { return errors.New("target is busy") }

	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	err := e.Unmount(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "unmount", execErr.Operation)
}

func TestLibExecutor_Unmount_Success(t *testing.T) {
	stubLoopSeams(t)
	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	require.NoError(t, e.Unmount(context.Background(), cfg))
}

// ---------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------

func TestLibExecutor_Lock_LockFails(t *testing.T) {
	stubLoopSeams(t)
	lockLUKS = func(string) error { return errors.New("device or resource busy") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Lock(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_lock", execErr.Operation)
}

func TestLibExecutor_Lock_DetachFails(t *testing.T) {
	stubLoopSeams(t)
	findLoopDeviceFn = func(string) (string, error) { return "/dev/loop-test0", nil }
	detachLoopDevice = func(string) error { return errors.New("device busy") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Lock(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "detach_loop", execErr.Operation)
}

func TestLibExecutor_Lock_NoLoopDeviceFound(t *testing.T) {
	stubLoopSeams(t)
	findLoopDeviceFn = func(string) (string, error) { return "", errors.New("not found") }
	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	require.NoError(t, e.Lock(context.Background(), cfg))
	assert.Equal(t, 0, detachCalls, "detach must not run when no loop device is found")
}

func TestLibExecutor_Lock_Success(t *testing.T) {
	stubLoopSeams(t)

	lockCalls, detachCalls := 0, 0
	lockLUKS = func(string) error { lockCalls++; return nil }
	findLoopDeviceFn = func(string) (string, error) { return "/dev/loop-test0", nil }
	detachLoopDevice = func(string) error { detachCalls++; return nil }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	require.NoError(t, e.Lock(context.Background(), cfg))
	assert.Equal(t, 1, lockCalls)
	assert.Equal(t, 1, detachCalls)
}

// ---------------------------------------------------------------------------
// IsMounted / IsUnlocked
// ---------------------------------------------------------------------------

func TestLibExecutor_IsMounted_DelegatesAndSwallowsError(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(string) (bool, error) { return false, errors.New("unreadable mountinfo") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()
	assert.False(t, e.IsMounted(cfg), "an undeterminable mount state must not report true")

	isMountedFn = func(string) (bool, error) { return true, nil }
	assert.True(t, e.IsMounted(cfg))
}

func TestLibExecutor_IsUnlocked_Delegates(t *testing.T) {
	stubLoopSeams(t)
	isUnlockedFn = func(string) bool { return true }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()
	assert.True(t, e.IsUnlocked(cfg))
}

// ---------------------------------------------------------------------------
// IsLUKSVolume / IsMounted / IsUnlocked free functions
// ---------------------------------------------------------------------------

func TestIsLUKSVolume_NonExistent(t *testing.T) {
	assert.False(t, IsLUKSVolume("/nonexistent/file.luks"))
}

func TestIsLUKSVolume_RegularFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.luks")
	require.NoError(t, os.WriteFile(tmpFile, []byte("not a luks volume"), 0600))
	assert.False(t, IsLUKSVolume(tmpFile))
}

func TestIsLUKSVolume_ValidMagic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.luks")
	magic := []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	require.NoError(t, os.WriteFile(tmpFile, magic, 0600))
	assert.True(t, IsLUKSVolume(tmpFile))
}

func TestIsLUKSVolume_PartialMagic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.luks")
	require.NoError(t, os.WriteFile(tmpFile, []byte{'L', 'U', 'K', 'S'}, 0600))
	assert.False(t, IsLUKSVolume(tmpFile))
}

func TestIsMounted_NotMounted(t *testing.T) {
	result, err := IsMounted("/nonexistent/mount/point")
	require.NoError(t, err)
	assert.False(t, result)
}

func TestIsMounted_KnownMount(t *testing.T) {
	// Root is always mounted on Linux.
	result, err := IsMounted("/")
	require.NoError(t, err)
	assert.True(t, result)
}

func TestIsUnlocked_NotOpen(t *testing.T) {
	assert.False(t, IsUnlocked("nonexistent_mapper_name_12345"))
}
