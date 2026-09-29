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
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubLoopSeams replaces every go-luks2 kernel-facing primitive used by
// Volume with a deterministic fake and restores the originals on cleanup.
// Every test that drives Volume past its filesystem-only checks must call
// this first: the defaults point at the real kernel and would try to attach
// a loop device, format a filesystem or mount a device on the host.
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

// TestVolume_Create_CreateFileFails covers the create_file error branch: the
// parent directory exists and is writable, but os.Create still fails on the
// container file itself.
//
// The container's basename is longer than NAME_MAX (255 bytes on ext4,
// tmpfs and every other filesystem this suite runs on) rather than blocked
// by a permission bit: the kernel refuses to create it with ENAMETOOLONG
// independent of the caller's privilege level, so the case still holds when
// tests run as root. It also leaves Exists() false beforehand (os.Stat on
// an over-long name fails the same way, not with "not exist"), so Create
// reaches the create_file step exactly as a permission failure would have.
func TestVolume_Create_CreateFileFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })

	dir := t.TempDir()
	tooLong := strings.Repeat("a", 300) + ".luks"
	luksPath := filepath.Join(dir, tooLong)

	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "create_file", volErr.Operation)
}

// TestVolume_Create_SetupLoopDeviceFails proves a failed loop attach is
// reported with the container file already removed: a half-created
// container must not linger as a false ErrVolumeAlreadyExists later.
func TestVolume_Create_SetupLoopDeviceFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	setupLoopDevice = func(string) (string, error) { return "", errors.New("no free loop devices") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "setup_loop", volErr.Operation)
	assert.False(t, v.Exists(), "the container file must be removed on loop setup failure")
}

// TestVolume_Create_FormatFails proves a failed LUKS format detaches the
// loop device and removes the container before returning.
func TestVolume_Create_FormatFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }
	formatLUKS = func(luks2.FormatOptions) error { return errors.New("format rejected") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "luks_format", volErr.Operation)
	assert.Equal(t, 1, detachCalls)
	assert.False(t, v.Exists())
}

// TestVolume_Create_FormatFails_JoinsCleanupError proves that when the loop
// detach performed while unwinding a failed format itself fails, that
// cleanup error is joined into the returned error rather than discarded.
func TestVolume_Create_FormatFails_JoinsCleanupError(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachErr := errors.New("detach failed")
	detachLoopDevice = func(string) error { return detachErr }
	formatLUKS = func(luks2.FormatOptions) error { return errors.New("format rejected") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "luks_format", volErr.Operation)
	assert.ErrorIs(t, err, detachErr, "a detach failure during format cleanup must not be swallowed")
}

// TestVolume_Create_UnlockFails proves a failed post-format unlock cleans up
// the loop device and container the same way a format failure does.
func TestVolume_Create_UnlockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	unlockLUKS = func(string, []byte, string) error { return errors.New("wrong key") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "luks_unlock", volErr.Operation)
	assert.False(t, v.Exists())
}

// TestVolume_Create_MakeFilesystemFails proves a failed mkfs locks the
// volume back and detaches the loop device before reporting create_fs.
func TestVolume_Create_MakeFilesystemFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	lockCalls := 0
	lockLUKS = func(string) error { lockCalls++; return nil }
	makeFilesystem = func(string, string, string) error { return errors.New("mkfs failed") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "create_fs", volErr.Operation)
	assert.Equal(t, 1, lockCalls)
	assert.False(t, v.Exists())
}

// TestVolume_Create_LockFails proves the final re-lock's failure is reported
// distinctly from the earlier locks, and still detaches the loop device.
func TestVolume_Create_LockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }
	lockLUKS = func(string) error { return errors.New("busy") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "luks_lock", volErr.Operation)
	assert.Equal(t, 1, detachCalls)
}

// TestVolume_Create_DetachFails proves the container is left on disk (the
// LUKS format itself succeeded) when only the final loop detach fails.
func TestVolume_Create_DetachFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	detachLoopDevice = func(string) error { return errors.New("device busy") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Create(1<<20, "passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "detach_loop", volErr.Operation)
	assert.True(t, v.Exists(), "a container whose format succeeded must not be removed for a detach failure")
}

// TestVolume_Create_Success drives the full happy path with every kernel
// primitive faked, verifying the container file is created at the requested
// size and the loop device field is cleared on return.
func TestVolume_Create_Success(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	require.NoError(t, v.Create(1<<20, "passphrase"))

	assert.Empty(t, v.LoopDevice)
	info, err := os.Stat(luksPath)
	require.NoError(t, err)
	assert.Equal(t, int64(1<<20), info.Size())
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "container file must not be group/world readable")
}

// TestVolume_Unlock_SetupLoopDeviceFails proves a failed loop attach is
// reported without ever reaching the LUKS unlock step.
func TestVolume_Unlock_SetupLoopDeviceFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	setupLoopDevice = func(string) (string, error) { return "", errors.New("no free loop devices") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Unlock("passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "setup_loop", volErr.Operation)
}

// TestVolume_Unlock_UnlockFails proves a wrong passphrase detaches the loop
// device it had just attached.
func TestVolume_Unlock_UnlockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }
	unlockLUKS = func(string, []byte, string) error { return errors.New("wrong passphrase") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Unlock("passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "luks_unlock", volErr.Operation)
	assert.Equal(t, 1, detachCalls)
}

// TestVolume_Unlock_MkdirMountpointFails proves a mount point that cannot be
// created locks the volume back and detaches the loop device.
func TestVolume_Unlock_MkdirMountpointFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	lockCalls, detachCalls := 0, 0
	lockLUKS = func(string) error { lockCalls++; return nil }
	detachLoopDevice = func(string) error { detachCalls++; return nil }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))

	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	mountPoint := filepath.Join(blocker, "mnt")

	v := NewVolumeWithPaths(luksPath, mountPoint)

	err := v.Unlock("passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "create_mountpoint", volErr.Operation)
	assert.Equal(t, 1, lockCalls)
	assert.Equal(t, 1, detachCalls)
}

// TestVolume_Unlock_MountFails proves a failed mount locks the volume back
// and detaches the loop device rather than leaving it attached and unlocked.
func TestVolume_Unlock_MountFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	lockCalls, detachCalls := 0, 0
	lockLUKS = func(string) error { lockCalls++; return nil }
	detachLoopDevice = func(string) error { detachCalls++; return nil }
	mountLUKS = func(luks2.MountOptions) error { return errors.New("mount failed") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Unlock("passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "mount", volErr.Operation)
	assert.Equal(t, 1, lockCalls)
	assert.Equal(t, 1, detachCalls)
}

// TestVolume_Unlock_MountFails_JoinsCleanupError proves that when the
// LUKS re-lock performed while unwinding a failed mount itself fails, that
// cleanup error is joined into the returned error rather than discarded.
func TestVolume_Unlock_MountFails_JoinsCleanupError(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	lockErr := errors.New("lock cleanup failed")
	lockLUKS = func(string) error { return lockErr }
	mountLUKS = func(luks2.MountOptions) error { return errors.New("mount failed") }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Unlock("passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "mount", volErr.Operation)
	assert.ErrorIs(t, err, lockErr, "a lock cleanup failure during mount rollback must not be swallowed")
}

// TestVolume_Unlock_Success drives the full happy path with every kernel
// primitive faked, verifying the mount point directory is created.
func TestVolume_Unlock_Success(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	var mountedOpts luks2.MountOptions
	mountLUKS = func(opts luks2.MountOptions) error { mountedOpts = opts; return nil }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	mountPoint := filepath.Join(dir, "mnt")
	v := NewVolumeWithPaths(luksPath, mountPoint)

	require.NoError(t, v.Unlock("passphrase"))

	info, err := os.Stat(mountPoint)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, MapperName, mountedOpts.Device)
	assert.Equal(t, mountPoint, mountedOpts.MountPoint)
}

// TestVolume_Unlock_ChmodsMountPointAfterMount proves the mount point is
// re-asserted to 0700 only after the mount call, undoing whatever mode a
// freshly formatted ext4 root (mkfs.ext4 defaults to 0755) left behind when
// mounted over the 0700 directory MkdirAll created.
func TestVolume_Unlock_ChmodsMountPointAfterMount(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	// Simulate the ext4 root inode's default permissions replacing the
	// mount point's mode as part of the mount call itself.
	mountLUKS = func(opts luks2.MountOptions) error {
		return os.Chmod(opts.MountPoint, 0755)
	}

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	mountPoint := filepath.Join(dir, "mnt")
	v := NewVolumeWithPaths(luksPath, mountPoint)

	require.NoError(t, v.Unlock("passphrase"))

	info, err := os.Stat(mountPoint)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), "mount point must be re-asserted to 0700 after mount")
}

// TestVolume_Unlock_ChmodMountPointFails proves a failed post-mount chmod
// unmounts, re-locks and detaches rather than leaving a world-listable
// volume mounted and unlocked.
func TestVolume_Unlock_ChmodMountPointFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)

	unmountCalls, lockCalls, detachCalls := 0, 0, 0
	unmountLUKS = func(string, int) error { unmountCalls++; return nil }
	lockLUKS = func(string) error { lockCalls++; return nil }
	detachLoopDevice = func(string) error { detachCalls++; return nil }

	chmodErr := errors.New("chmod failed")
	chmodFn = func(string, os.FileMode) error { return chmodErr }

	dir := t.TempDir()
	luksPath := filepath.Join(dir, "vault.luks")
	require.NoError(t, os.WriteFile(luksPath, []byte("container"), 0600))
	v := NewVolumeWithPaths(luksPath, filepath.Join(dir, "mnt"))

	err := v.Unlock("passphrase")
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "chmod_mountpoint", volErr.Operation)
	assert.ErrorIs(t, err, chmodErr)
	assert.Equal(t, 1, unmountCalls, "a failed chmod must unmount the volume")
	assert.Equal(t, 1, lockCalls)
	assert.Equal(t, 1, detachCalls)
}

// TestVolume_Lock_UnmountFails proves an unmount failure is reported without
// attempting to close the LUKS mapping or detach the loop device.
func TestVolume_Lock_UnmountFails(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(string) (bool, error) { return true, nil }
	unmountLUKS = func(string, int) error { return errors.New("target is busy") }

	v := &Volume{
		LUKSPath:   filepath.Join(t.TempDir(), "vault.luks"),
		MountPoint: t.TempDir(),
		MapperName: MapperName,
	}

	err := v.Lock()
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "unmount", volErr.Operation)
}

// TestVolume_Lock_LockFails proves a failed LUKS close is reported after a
// successful unmount.
func TestVolume_Lock_LockFails(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(string) (bool, error) { return false, nil }
	isUnlockedFn = func(string) bool { return true }
	lockLUKS = func(string) error { return errors.New("device or resource busy") }

	v := &Volume{
		LUKSPath:   filepath.Join(t.TempDir(), "vault.luks"),
		MountPoint: t.TempDir(),
		MapperName: MapperName,
	}

	err := v.Lock()
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "luks_lock", volErr.Operation)
}

// TestVolume_Lock_DetachFails proves a failed loop detach is reported after
// the LUKS mapping has already been closed.
func TestVolume_Lock_DetachFails(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(string) (bool, error) { return false, nil }
	isUnlockedFn = func(string) bool { return true }
	findLoopDeviceFn = func(string) (string, error) { return "/dev/loop-test0", nil }
	detachLoopDevice = func(string) error { return errors.New("device busy") }

	v := &Volume{
		LUKSPath:   filepath.Join(t.TempDir(), "vault.luks"),
		MountPoint: t.TempDir(),
		MapperName: MapperName,
	}

	err := v.Lock()
	require.Error(t, err)

	var volErr *VolumeError
	require.ErrorAs(t, err, &volErr)
	assert.Equal(t, "detach_loop", volErr.Operation)
}

// TestVolume_Lock_NoLoopDeviceFound proves Lock succeeds and clears
// LoopDevice when no loop device can be found for the container (already
// detached), skipping the detach step entirely.
func TestVolume_Lock_NoLoopDeviceFound(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(string) (bool, error) { return false, nil }
	isUnlockedFn = func(string) bool { return true }
	findLoopDeviceFn = func(string) (string, error) { return "", errors.New("not found") }
	detachCalls := 0
	detachLoopDevice = func(string) error { detachCalls++; return nil }

	v := &Volume{
		LUKSPath:   filepath.Join(t.TempDir(), "vault.luks"),
		MountPoint: t.TempDir(),
		MapperName: MapperName,
		LoopDevice: "/dev/loop-test0",
	}

	require.NoError(t, v.Lock())
	assert.Empty(t, v.LoopDevice)
	assert.Equal(t, 0, detachCalls, "detach must not run when no loop device is found")
}

// TestVolume_Lock_Success drives the full happy path (mounted and open),
// verifying every step runs and LoopDevice is cleared.
func TestVolume_Lock_Success(t *testing.T) {
	stubLoopSeams(t)

	unmountCalls, lockCalls, detachCalls := 0, 0, 0
	isMountedFn = func(string) (bool, error) { return true, nil }
	isUnlockedFn = func(string) bool { return true }
	unmountLUKS = func(string, int) error { unmountCalls++; return nil }
	lockLUKS = func(string) error { lockCalls++; return nil }
	findLoopDeviceFn = func(string) (string, error) { return "/dev/loop-test0", nil }
	detachLoopDevice = func(string) error { detachCalls++; return nil }

	v := &Volume{
		LUKSPath:   filepath.Join(t.TempDir(), "vault.luks"),
		MountPoint: t.TempDir(),
		MapperName: MapperName,
		LoopDevice: "/dev/loop-test0",
	}

	require.NoError(t, v.Lock())
	assert.Empty(t, v.LoopDevice)
	assert.Equal(t, 1, unmountCalls)
	assert.Equal(t, 1, lockCalls)
	assert.Equal(t, 1, detachCalls)
}

// TestVolume_CopyDataToVolume_Mounted_Success proves data is copied into a
// mounted volume's mount point.
func TestVolume_CopyDataToVolume_Mounted_Success(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(string) (bool, error) { return true, nil }

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	require.NoError(t, os.MkdirAll(src, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "secret.txt"), []byte("payload"), 0600))

	mnt := filepath.Join(dir, "mnt")
	require.NoError(t, os.MkdirAll(mnt, 0700))

	v := NewVolumeWithPaths(filepath.Join(dir, "vault.luks"), mnt)

	require.NoError(t, v.CopyDataToVolume(src))

	got, err := os.ReadFile(filepath.Join(mnt, "secret.txt"))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
}

// TestVolume_CopyDataToVolume_Mounted_CopyDirFails proves a copy failure on a
// mounted volume propagates the underlying error rather than a typed one:
// CopyDataToVolume delegates directly to copyDir's own error.
func TestVolume_CopyDataToVolume_Mounted_CopyDirFails(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(string) (bool, error) { return true, nil }

	dir := t.TempDir()
	mnt := filepath.Join(dir, "mnt")
	require.NoError(t, os.MkdirAll(mnt, 0700))

	v := NewVolumeWithPaths(filepath.Join(dir, "vault.luks"), mnt)

	err := v.CopyDataToVolume(filepath.Join(dir, "does-not-exist"))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrVolumeNotMounted)
}

// TestChownTreeToCallingUser_RootChownsTree verifies that, when running as
// root with a resolvable calling user, chownTreeToCallingUser walks the
// whole tree and chowns every entry without error (chowning to the process's
// own uid/gid is permitted even without real root, so this exercises the
// success path deterministically).
func TestChownTreeToCallingUser_RootChownsTree(t *testing.T) {
	origGeteuid := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = origGeteuid })

	currentUser, err := user.Current()
	require.NoError(t, err)
	t.Setenv("SUDO_UID", currentUser.Uid)
	t.Setenv("SUDO_GID", currentUser.Gid)

	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	require.NoError(t, os.MkdirAll(sub, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "file.txt"), []byte("x"), 0600))

	// Must not panic and must leave the tree readable.
	chownTreeToCallingUser(root)

	data, err := os.ReadFile(filepath.Join(sub, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "x", string(data))
}

// TestChownTreeToCallingUser_WalkErrorIsSkipped previously drove the
// walk-error-continues branch with a subdirectory made unreadable via
// os.Mkdir(..., 0000). That is a permission check, which a process running
// as root bypasses entirely (root's directory listing succeeds regardless
// of mode bits), so the branch went silently unexercised — not merely
// under-covered — under a root test runner. Unlike the create_file and
// store-removal cases elsewhere in this package, filepath.Walk's
// readDirNames has no non-permission failure mode to substitute: it is not
// reachable via ENOTDIR (Walk already knows the entry is a directory from
// Lstat before attempting to list it), ENAMETOOLONG (the directory's own
// name is short and valid) or a busy/non-empty condition (listing, unlike
// removal, does not care whether the directory is empty). Deleted rather
// than kept flaky-under-root; the walkErr branch itself is exercised
// nowhere else in this file.

// TestChownTreeToCallingUser_LchownFailureIsLogged verifies that a chown
// failure on an individual entry (target uid the unprivileged test process
// cannot assign) is logged and the walk continues rather than panicking or
// returning an error the caller would have to handle.
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

	// Must not panic despite every chown failing.
	chownTreeToCallingUser(root)

	data, err := os.ReadFile(filepath.Join(root, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "x", string(data))
}
