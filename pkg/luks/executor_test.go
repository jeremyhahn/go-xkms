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
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLoop is a loop device that records its detaches and fails them with
// err when set.
type fakeLoop struct {
	detaches int
	err      error
}

func (l *fakeLoop) Path() string { return "/dev/loop-test0" }

func (l *fakeLoop) Detach(context.Context) (loop.DetachState, error) {
	l.detaches++
	return loop.Released, l.err
}

// stubLoopSeams replaces every go-luks2 kernel-facing primitive LibExecutor
// uses with a deterministic fake and restores the originals on cleanup.
// Every test that drives LibExecutor past its filesystem-only checks must
// call this first: the defaults point at the real kernel and would try to
// attach a loop device, format a filesystem or mount a device on the host.
// It returns the loop device every attach and find hands out.
func stubLoopSeams(t *testing.T) *fakeLoop {
	t.Helper()

	origSetup := setupLoopDevice
	origFind := findLoopDeviceFn
	origFormat := formatLUKS
	origUnlock := unlockLUKS
	origLock := lockLUKS
	origLookup := lookupMapping
	origMakeFS := makeFilesystem
	origMount := mountLUKS
	origUnmount := unmountLUKS
	origIsMounted := isMountedFn
	origChmod := chmodFn
	t.Cleanup(func() {
		setupLoopDevice = origSetup
		findLoopDeviceFn = origFind
		formatLUKS = origFormat
		unlockLUKS = origUnlock
		lockLUKS = origLock
		lookupMapping = origLookup
		makeFilesystem = origMakeFS
		mountLUKS = origMount
		unmountLUKS = origUnmount
		isMountedFn = origIsMounted
		chmodFn = origChmod
	})

	dev := &fakeLoop{}
	setupLoopDevice = func(context.Context, string) (loopDevice, error) { return dev, nil }
	findLoopDeviceFn = func(context.Context, string) (loopDevice, error) { return dev, nil }
	formatLUKS = func(context.Context, string, enclave.ByteAccess, luks2.FormatParams) error { return nil }
	unlockLUKS = func(_ context.Context, _ string, _ enclave.ByteAccess, name string) (*dmcrypt.Mapping, error) {
		return &dmcrypt.Mapping{Name: name}, nil
	}
	lockLUKS = func(context.Context, string) error { return nil }
	lookupMapping = func(_ context.Context, name string) (*dmcrypt.Mapping, error) {
		return &dmcrypt.Mapping{Name: name}, nil
	}
	makeFilesystem = func(context.Context, string, filesystem.Type, filesystem.MakeParams) error { return nil }
	mountLUKS = func(context.Context, filesystem.MountParams) error { return nil }
	unmountLUKS = func(context.Context, string, filesystem.UnmountFlags) error { return nil }
	isMountedFn = func(context.Context, string) (bool, error) { return false, nil }
	return dev
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
	withKeyringCheck(t, func() error { return dmcrypt.ErrKeyringUnsupported })
	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyringUnavailable)
	assert.ErrorIs(t, err, dmcrypt.ErrKeyringUnsupported)
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

// TestLibExecutor_Create_EmptyPassphrase verifies an empty passphrase is
// refused before a container file exists: go-luks2 takes credentials only as
// enclaves, and there is no enclave over empty material.
func TestLibExecutor_Create_EmptyPassphrase(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	dir := t.TempDir()
	cfg := testConfig(dir)

	err := NewLibExecutor().Create(context.Background(), cfg, 1<<20, "")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "protect_passphrase", execErr.Operation)
	assert.ErrorIs(t, err, enclave.ErrEmptyEnclave)
	assert.NoFileExists(t, cfg.LUKSPath)
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
	setupLoopDevice = func(context.Context, string) (loopDevice, error) { return nil, errors.New("no free loop devices") }

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
	dev := stubLoopSeams(t)
	formatLUKS = func(context.Context, string, enclave.ByteAccess, luks2.FormatParams) error {
		return errors.New("format rejected")
	}

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_format", execErr.Operation)
	assert.Equal(t, 1, dev.detaches)
	assert.NoFileExists(t, cfg.LUKSPath)
}

func TestLibExecutor_Create_FormatFails_JoinsCleanupError(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dev := stubLoopSeams(t)

	detachErr := errors.New("detach failed")
	dev.err = detachErr
	formatLUKS = func(context.Context, string, enclave.ByteAccess, luks2.FormatParams) error {
		return errors.New("format rejected")
	}

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, detachErr, "a detach failure during format cleanup must not be swallowed")
}

func TestLibExecutor_Create_UnlockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dev := stubLoopSeams(t)
	unlockLUKS = func(context.Context, string, enclave.ByteAccess, string) (*dmcrypt.Mapping, error) {
		return nil, errors.New("wrong key")
	}

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_unlock", execErr.Operation)
	assert.Equal(t, 1, dev.detaches)
	assert.NoFileExists(t, cfg.LUKSPath)
}

func TestLibExecutor_Create_MakeFilesystemFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dev := stubLoopSeams(t)

	lockCalls := 0
	lockLUKS = func(context.Context, string) error { lockCalls++; return nil }
	makeFilesystem = func(context.Context, string, filesystem.Type, filesystem.MakeParams) error {
		return errors.New("mkfs failed")
	}

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "create_fs", execErr.Operation)
	assert.Equal(t, 1, lockCalls)
	assert.Equal(t, 1, dev.detaches)
	assert.NoFileExists(t, cfg.LUKSPath)
}

func TestLibExecutor_Create_LockFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dev := stubLoopSeams(t)
	lockLUKS = func(context.Context, string) error { return errors.New("busy") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	err := e.Create(context.Background(), cfg, 1<<20, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_lock", execErr.Operation)
	assert.Equal(t, 1, dev.detaches)
}

func TestLibExecutor_Create_DetachFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dev := stubLoopSeams(t)
	dev.err = errors.New("device busy")

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

// TestLibExecutor_Create_Success verifies the whole sequence reaches
// go-luks2 with what it needs: the loop device to format and unlock, the
// configured KDF, the passphrase as a live enclave, and the mapping's device
// path (never its bare name) for mkfs.
func TestLibExecutor_Create_Success(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dev := stubLoopSeams(t)

	var formatDevice string
	var params luks2.FormatParams
	formatLUKS = func(_ context.Context, device string, pass enclave.ByteAccess, p luks2.FormatParams) error {
		formatDevice, params = device, p
		return pass.WithBytes(func(b []byte) error {
			assert.Equal(t, "passphrase", string(b))
			return nil
		})
	}
	var unlockDevice string
	unlockLUKS = func(_ context.Context, device string, _ enclave.ByteAccess, name string) (*dmcrypt.Mapping, error) {
		unlockDevice = device
		return &dmcrypt.Mapping{Name: name}, nil
	}
	var mkfsDevice string
	var mkfsType filesystem.Type
	var mkfsParams filesystem.MakeParams
	makeFilesystem = func(_ context.Context, device string, fs filesystem.Type, p filesystem.MakeParams) error {
		mkfsDevice, mkfsType, mkfsParams = device, fs, p
		return nil
	}

	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.KDF = KDFPBKDF2
	cfg.PBKDFIterTime = 1500
	e := NewLibExecutor()

	require.NoError(t, e.Create(context.Background(), cfg, 1<<20, "passphrase"))

	info, err := os.Stat(cfg.LUKSPath)
	require.NoError(t, err)
	assert.Equal(t, int64(1<<20), info.Size())
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "container file must not be group/world readable")

	assert.Equal(t, dev.Path(), formatDevice)
	assert.Equal(t, dev.Path(), unlockDevice)
	assert.Equal(t, luks2.KDFPBKDF2, params.KDF.Type)
	assert.Equal(t, 1500*time.Millisecond, params.KDF.IterTime)
	assert.Equal(t, "/dev/mapper/"+cfg.MapperName, mkfsDevice)
	assert.Equal(t, filesystem.Ext4, mkfsType)
	assert.Equal(t, filesystemLabel, mkfsParams.Label)
	assert.Equal(t, 1, dev.detaches)
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
	withKeyringCheck(t, func() error { return dmcrypt.ErrKeyringBlocked })
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

func TestLibExecutor_Unlock_EmptyPassphrase(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	attached := false
	setupLoopDevice = func(context.Context, string) (loopDevice, error) { attached = true; return &fakeLoop{}, nil }

	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, []byte("container"), 0600))

	err := NewLibExecutor().Unlock(context.Background(), cfg, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, enclave.ErrEmptyEnclave)
	assert.False(t, attached, "no loop device may be attached for a passphrase that cannot be used")
}

func TestLibExecutor_Unlock_SetupLoopDeviceFails(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	stubLoopSeams(t)
	setupLoopDevice = func(context.Context, string) (loopDevice, error) { return nil, errors.New("no free loop devices") }

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
	dev := stubLoopSeams(t)
	unlockLUKS = func(context.Context, string, enclave.ByteAccess, string) (*dmcrypt.Mapping, error) {
		return nil, errors.New("wrong passphrase")
	}

	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, []byte("container"), 0600))

	e := NewLibExecutor()
	err := e.Unlock(context.Background(), cfg, "passphrase")
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "luks_unlock", execErr.Operation)
	assert.Equal(t, 1, dev.detaches)
}

func TestLibExecutor_Unlock_Success(t *testing.T) {
	withKeyringCheck(t, func() error { return nil })
	dev := stubLoopSeams(t)
	var unlockDevice, unlockName string
	unlockLUKS = func(_ context.Context, device string, _ enclave.ByteAccess, name string) (*dmcrypt.Mapping, error) {
		unlockDevice, unlockName = device, name
		return &dmcrypt.Mapping{Name: name}, nil
	}

	dir := t.TempDir()
	cfg := testConfig(dir)
	require.NoError(t, os.WriteFile(cfg.LUKSPath, []byte("container"), 0600))

	e := NewLibExecutor()
	require.NoError(t, e.Unlock(context.Background(), cfg, "passphrase"))
	assert.Equal(t, dev.Path(), unlockDevice)
	assert.Equal(t, cfg.MapperName, unlockName)
	assert.Equal(t, 0, dev.detaches, "an unlocked volume keeps its loop device")
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

// TestLibExecutor_Mount_MappingNotActive verifies Mount refuses a volume
// whose mapping does not exist instead of handing mount a guessed path.
func TestLibExecutor_Mount_MappingNotActive(t *testing.T) {
	stubLoopSeams(t)
	mounted := false
	lookupMapping = func(context.Context, string) (*dmcrypt.Mapping, error) { return nil, dmcrypt.ErrNotActive }
	mountLUKS = func(context.Context, filesystem.MountParams) error { mounted = true; return nil }

	cfg := testConfig(t.TempDir())
	err := NewLibExecutor().Mount(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "lookup_mapping", execErr.Operation)
	assert.ErrorIs(t, err, dmcrypt.ErrNotActive)
	assert.False(t, mounted)
}

func TestLibExecutor_Mount_MountFails(t *testing.T) {
	stubLoopSeams(t)
	mountLUKS = func(context.Context, filesystem.MountParams) error { return errors.New("mount failed") }

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

	var mounted filesystem.MountParams
	mountLUKS = func(_ context.Context, p filesystem.MountParams) error { mounted = p; return nil }

	dir := t.TempDir()
	cfg := testConfig(dir)

	e := NewLibExecutor()
	require.NoError(t, e.Mount(context.Background(), cfg))

	info, err := os.Stat(cfg.MountPoint)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, "/dev/mapper/"+cfg.MapperName, mounted.Source)
	assert.Equal(t, cfg.MountPoint, mounted.Target)
	assert.Equal(t, filesystem.Ext4, mounted.Type)
}

func TestLibExecutor_Mount_ChmodsMountPointAfterMount(t *testing.T) {
	stubLoopSeams(t)

	// Simulate the ext4 root inode's default permissions replacing the
	// mount point's mode as part of the mount call itself.
	mountLUKS = func(_ context.Context, p filesystem.MountParams) error {
		return os.Chmod(p.Target, 0755)
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
	unmountLUKS = func(context.Context, string, filesystem.UnmountFlags) error { unmountCalls++; return nil }
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
	unmountLUKS = func(context.Context, string, filesystem.UnmountFlags) error { return errors.New("target is busy") }

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
	lockLUKS = func(context.Context, string) error { return errors.New("device or resource busy") }

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
	dev := stubLoopSeams(t)
	dev.err = errors.New("device busy")

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
	dev := stubLoopSeams(t)
	findLoopDeviceFn = func(context.Context, string) (loopDevice, error) { return nil, loop.ErrNotFound }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	require.NoError(t, e.Lock(context.Background(), cfg))
	assert.Equal(t, 0, dev.detaches, "detach must not run when no loop device is found")
}

// TestLibExecutor_Lock_FindFails verifies a loop lookup that fails for any
// reason other than "none attached" is reported, not read as nothing to do:
// treating it as success would leave the container's loop device attached.
func TestLibExecutor_Lock_FindFails(t *testing.T) {
	dev := stubLoopSeams(t)
	findErr := errors.New("permission denied")
	findLoopDeviceFn = func(context.Context, string) (loopDevice, error) { return nil, findErr }

	cfg := testConfig(t.TempDir())
	err := NewLibExecutor().Lock(context.Background(), cfg)
	require.Error(t, err)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "find_loop", execErr.Operation)
	assert.ErrorIs(t, err, findErr)
	assert.Equal(t, 0, dev.detaches)
}

func TestLibExecutor_Lock_Success(t *testing.T) {
	dev := stubLoopSeams(t)

	lockCalls := 0
	lockLUKS = func(context.Context, string) error { lockCalls++; return nil }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()

	require.NoError(t, e.Lock(context.Background(), cfg))
	assert.Equal(t, 1, lockCalls)
	assert.Equal(t, 1, dev.detaches)
}

// ---------------------------------------------------------------------------
// IsMounted / IsUnlocked
// ---------------------------------------------------------------------------

func TestLibExecutor_IsMounted_DelegatesAndSwallowsError(t *testing.T) {
	stubLoopSeams(t)
	isMountedFn = func(context.Context, string) (bool, error) { return false, errors.New("unreadable mountinfo") }

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()
	assert.False(t, e.IsMounted(cfg), "an undeterminable mount state must not report true")

	isMountedFn = func(context.Context, string) (bool, error) { return true, nil }
	assert.True(t, e.IsMounted(cfg))
}

func TestLibExecutor_IsUnlocked_Delegates(t *testing.T) {
	stubLoopSeams(t)

	dir := t.TempDir()
	cfg := testConfig(dir)
	e := NewLibExecutor()
	assert.True(t, e.IsUnlocked(cfg))

	lookupMapping = func(context.Context, string) (*dmcrypt.Mapping, error) { return nil, dmcrypt.ErrNotActive }
	assert.False(t, e.IsUnlocked(cfg))
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

// TestLibExecutor_RefusesCanceledContext pins that every lifecycle operation
// checks its context before touching a seam, so a cancelled request never
// attaches, maps, mounts or unmounts anything.
func TestLibExecutor_RefusesCanceledContext(t *testing.T) {
	ops := map[string]func(*LibExecutor, context.Context, *VolumeConfig) error{
		"unlock": func(e *LibExecutor, ctx context.Context, cfg *VolumeConfig) error {
			return e.Unlock(ctx, cfg, "passphrase")
		},
		"lock":    (*LibExecutor).Lock,
		"mount":   (*LibExecutor).Mount,
		"unmount": (*LibExecutor).Unmount,
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			stubLoopSeams(t)
			touched := false
			setupLoopDevice = func(context.Context, string) (loopDevice, error) { touched = true; return &fakeLoop{}, nil }
			lockLUKS = func(context.Context, string) error { touched = true; return nil }
			lookupMapping = func(_ context.Context, name string) (*dmcrypt.Mapping, error) {
				touched = true
				return &dmcrypt.Mapping{Name: name}, nil
			}
			unmountLUKS = func(context.Context, string, filesystem.UnmountFlags) error { touched = true; return nil }

			cfg := testConfig(t.TempDir())
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			err := op(NewLibExecutor(), ctx, cfg)
			assert.ErrorIs(t, err, context.Canceled)
			assert.False(t, touched, "a cancelled %s must not reach a kernel seam", name)
			assert.NoDirExists(t, cfg.MountPoint)
		})
	}
}

// TestLibExecutor_Unlock_StatFails distinguishes an unreadable container path
// from a missing one: only ENOENT means "no volume", anything else is an
// operational failure naming the path.
func TestLibExecutor_Unlock_StatFails(t *testing.T) {
	stubLoopSeams(t)

	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0600))
	cfg := testConfig(dir)
	cfg.LUKSPath = filepath.Join(blocker, "vault.luks")

	err := NewLibExecutor().Unlock(context.Background(), cfg, "passphrase")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrVolumeNotFound)

	var execErr *ExecutorError
	require.ErrorAs(t, err, &execErr)
	assert.Equal(t, "stat", execErr.Operation)
	assert.Equal(t, cfg.LUKSPath, execErr.Path)
}

// TestLibExecutor_Mount_UsesConfiguredFilesystem pins that a non-default
// Filesystem reaches the mount call instead of the ext4 default.
func TestLibExecutor_Mount_UsesConfiguredFilesystem(t *testing.T) {
	stubLoopSeams(t)

	var mounted filesystem.MountParams
	mountLUKS = func(_ context.Context, p filesystem.MountParams) error { mounted = p; return nil }

	e := &LibExecutor{Filesystem: "xfs"}
	require.NoError(t, e.Mount(context.Background(), testConfig(t.TempDir())))
	assert.Equal(t, filesystem.Type("xfs"), mounted.Type)
}

// TestFormatVolume_MissingDevice proves the production format seam reports a
// device it cannot open rather than writing anywhere else.
func TestFormatVolume_MissingDevice(t *testing.T) {
	pass, err := protectPassphrase("passphrase")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, destroyPassphrase(pass)) })

	missing := filepath.Join(t.TempDir(), "absent")
	err = formatVolume(context.Background(), missing, pass, luks2.FormatParams{})
	require.Error(t, err)
	assert.NoFileExists(t, missing)
}

// TestActivateVolume_NotALUKSVolume proves the production unlock seam refuses
// a device with no LUKS2 header and returns no mapping.
func TestActivateVolume_NotALUKSVolume(t *testing.T) {
	pass, err := protectPassphrase("passphrase")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, destroyPassphrase(pass)) })

	device := filepath.Join(t.TempDir(), "zeros")
	require.NoError(t, os.WriteFile(device, make([]byte, 1<<16), 0600))

	mapping, err := activateVolume(context.Background(), device, pass, "xkms-test")
	require.Error(t, err)
	assert.Nil(t, mapping)
}

// TestActivateVolume_MissingDevice covers the open failure ahead of any
// header parsing.
func TestActivateVolume_MissingDevice(t *testing.T) {
	pass, err := protectPassphrase("passphrase")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, destroyPassphrase(pass)) })

	mapping, err := activateVolume(context.Background(), filepath.Join(t.TempDir(), "absent"), pass, "xkms-test")
	require.Error(t, err)
	assert.Nil(t, mapping)
}
