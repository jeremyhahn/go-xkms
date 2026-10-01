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

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// defaultFilesystem is the filesystem LibExecutor formats new volumes with
// when Filesystem is empty.
const defaultFilesystem = "ext4"

// The following are go-luks2's kernel-facing primitives. Each is a package
// variable so tests can stand in for the kernel instead of requiring a real
// loop device, dm-crypt mapping or mount. Every LUKS implementation in
// go-xkms drives the kernel through these, and only these — see
// docs/luks/architecture.md.
var (
	setupLoopDevice  = luks2.SetupLoopDevice
	detachLoopDevice = luks2.DetachLoopDevice
	findLoopDeviceFn = luks2.FindLoopDevice
	formatLUKS       = luks2.Format
	unlockLUKS       = luks2.Unlock
	lockLUKS         = luks2.Lock
	makeFilesystem   = luks2.MakeFilesystem
	mountLUKS        = luks2.Mount
	unmountLUKS      = luks2.Unmount
	isMountedFn      = luks2.IsMounted
	isUnlockedFn     = luks2.IsUnlocked
	chmodFn          = os.Chmod
)

// IsLUKSVolume reports whether the file at path begins with the LUKS2 magic
// bytes ("LUKS" followed by 0xba 0xbe). A file that cannot be opened or is
// shorter than the magic reports false rather than an error: this is a
// best-effort classification, not a header parse.
func IsLUKSVolume(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- caller-supplied container path
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, 6)
	n, err := f.Read(magic)
	if err != nil || n < 6 {
		return false
	}
	want := []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	for i := range want {
		if magic[i] != want[i] {
			return false
		}
	}
	return true
}

// IsMounted reports whether mountPoint is currently a mount point. It
// returns an error when the mount state could not be determined; callers
// must not treat that as "not mounted".
func IsMounted(mountPoint string) (bool, error) {
	return isMountedFn(mountPoint)
}

// IsUnlocked reports whether a LUKS device-mapper mapping named mapperName
// currently exists.
func IsUnlocked(mapperName string) bool {
	return isUnlockedFn(mapperName)
}

// LibExecutor is the canonical production Executor, implemented on
// go-luks2. It is the single implementation of LUKS volume lifecycle
// management in go-xkms (go-xkms#917); xkmsd and xkey both reach it through
// this package (xkey via sdk/go/luks).
//
// go-luks2.Unlock needs a block device, so a file-backed volume has none
// until one is attached: LibExecutor attaches a loop device to the
// container file in Create and Unlock, and detaches it in Lock. The loop
// device is not tracked in memory between calls — Lock resolves it fresh
// with go-luks2.FindLoopDevice — so a LibExecutor is safe to use from a
// freshly constructed Manager on every call, matching a CLI's one-call-
// per-process lifecycle as well as a daemon's long-lived one.
type LibExecutor struct {
	// Filesystem is the filesystem newly formatted volumes are created
	// with. Empty selects ext4.
	Filesystem string
}

// Ensure LibExecutor implements Executor.
var _ Executor = (*LibExecutor)(nil)

// NewLibExecutor constructs the production Executor with its default
// filesystem (ext4).
func NewLibExecutor() *LibExecutor {
	return &LibExecutor{}
}

func (e *LibExecutor) filesystem() string {
	if e.Filesystem == "" {
		return defaultFilesystem
	}
	return e.Filesystem
}

// Create formats a new LUKS2 container at config.LUKSPath, unlocks it long
// enough to create a filesystem, then locks and detaches it. The container
// is left locked: callers that want it ready for use call Unlock afterward.
func (e *LibExecutor) Create(ctx context.Context, config *VolumeConfig, sizeBytes int64, passphrase string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Stat(config.LUKSPath); err == nil {
		return ErrVolumeAlreadyExists
	}

	// The unlock below needs the kernel keyring; refuse before a container
	// file exists rather than after a format that cannot be opened.
	if err := EnsureKeyringAvailable(); err != nil {
		return err
	}

	dir := filepath.Dir(config.LUKSPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &ExecutorError{Operation: "create_dir", Path: dir, Err: err}
	}

	// O_EXCL makes the existence check atomic with creation, closing the
	// race window between the Stat above and this call.
	f, err := os.OpenFile(config.LUKSPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- caller-supplied container path
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrVolumeAlreadyExists
		}
		return &ExecutorError{Operation: "create_file", Path: config.LUKSPath, Err: err}
	}
	if err := f.Truncate(sizeBytes); err != nil {
		cleanup := errors.Join(f.Close(), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "truncate", Path: config.LUKSPath, Err: errors.Join(err, cleanup)}
	}
	if err := f.Close(); err != nil {
		return &ExecutorError{Operation: "close_file", Path: config.LUKSPath, Err: errors.Join(err, os.Remove(config.LUKSPath))}
	}

	loopDev, err := setupLoopDevice(config.LUKSPath)
	if err != nil {
		return &ExecutorError{Operation: "setup_loop", Path: config.LUKSPath, Err: errors.Join(err, os.Remove(config.LUKSPath))}
	}

	formatOpts := luks2.FormatOptions{
		Device:        loopDev,
		Passphrase:    []byte(passphrase),
		KDFType:       string(config.KDF),
		PBKDFIterTime: config.PBKDFIterTime,
	}
	if err := formatLUKS(formatOpts); err != nil {
		cleanup := errors.Join(detachLoopDevice(loopDev), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "luks_format", Path: loopDev, Err: errors.Join(err, cleanup)}
	}

	if err := unlockLUKS(loopDev, []byte(passphrase), config.MapperName); err != nil {
		cleanup := errors.Join(detachLoopDevice(loopDev), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "luks_unlock", Path: loopDev, Err: errors.Join(err, cleanup)}
	}

	if err := makeFilesystem(config.MapperName, e.filesystem(), "xkms"); err != nil {
		cleanup := errors.Join(lockLUKS(config.MapperName), detachLoopDevice(loopDev), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "create_fs", Path: config.MapperName, Err: errors.Join(err, cleanup)}
	}

	if err := lockLUKS(config.MapperName); err != nil {
		return &ExecutorError{Operation: "luks_lock", Path: config.MapperName, Err: errors.Join(err, detachLoopDevice(loopDev))}
	}

	if err := detachLoopDevice(loopDev); err != nil {
		return &ExecutorError{Operation: "detach_loop", Path: loopDev, Err: err}
	}

	return nil
}

// Unlock attaches a loop device to config.LUKSPath and opens the LUKS
// container, mapping it to config.MapperName.
func (e *LibExecutor) Unlock(ctx context.Context, config *VolumeConfig, passphrase string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Stat(config.LUKSPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrVolumeNotFound
		}
		return &ExecutorError{Operation: "stat", Path: config.LUKSPath, Err: err}
	}

	// Refuse before a loop device is attached: an unlock that cannot place
	// the volume key in the kernel keyring must not leave one behind.
	if err := EnsureKeyringAvailable(); err != nil {
		return err
	}

	loopDev, err := setupLoopDevice(config.LUKSPath)
	if err != nil {
		return &ExecutorError{Operation: "setup_loop", Path: config.LUKSPath, Err: err}
	}

	if err := unlockLUKS(loopDev, []byte(passphrase), config.MapperName); err != nil {
		return &ExecutorError{Operation: "luks_unlock", Path: loopDev, Err: errors.Join(err, detachLoopDevice(loopDev))}
	}

	return nil
}

// Lock closes the LUKS device-mapper mapping and detaches its loop device.
// The loop device is resolved fresh via go-luks2.FindLoopDevice rather than
// cached, so Lock works correctly even when called from a different
// LibExecutor instance (or process) than the one that ran Unlock.
func (e *LibExecutor) Lock(ctx context.Context, config *VolumeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := lockLUKS(config.MapperName); err != nil {
		return &ExecutorError{Operation: "luks_lock", Path: config.MapperName, Err: err}
	}

	loopDev, err := findLoopDeviceFn(config.LUKSPath)
	if err == nil && loopDev != "" {
		if err := detachLoopDevice(loopDev); err != nil {
			return &ExecutorError{Operation: "detach_loop", Path: loopDev, Err: err}
		}
	}

	return nil
}

// Mount creates the mount point directory if needed and mounts the unlocked
// device-mapper mapping at config.MountPoint.
func (e *LibExecutor) Mount(ctx context.Context, config *VolumeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(config.MountPoint, 0700); err != nil {
		return &ExecutorError{Operation: "create_mountpoint", Path: config.MountPoint, Err: err}
	}

	mountOpts := luks2.MountOptions{
		Device:     config.MapperName,
		MountPoint: config.MountPoint,
		FSType:     e.filesystem(),
		Flags:      0,
	}
	if err := mountLUKS(mountOpts); err != nil {
		return &ExecutorError{Operation: "mount", Path: config.MountPoint, Err: err}
	}

	// go-luks2 creates the filesystem with mkfs's default root permissions
	// (0755 for ext4), and mounting it replaces whatever mode MkdirAll gave
	// the mount point directory. Re-assert 0700 here so the unlocked volume
	// is never left world-listable.
	if err := chmodFn(config.MountPoint, 0700); err != nil {
		return &ExecutorError{Operation: "chmod_mountpoint", Path: config.MountPoint, Err: errors.Join(err, unmountLUKS(config.MountPoint, 0))}
	}

	return nil
}

// Unmount unmounts config.MountPoint.
func (e *LibExecutor) Unmount(ctx context.Context, config *VolumeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unmountLUKS(config.MountPoint, 0); err != nil {
		return &ExecutorError{Operation: "unmount", Path: config.MountPoint, Err: err}
	}
	return nil
}

// IsMounted reports whether config.MountPoint is currently mounted. A mount
// state that cannot be determined reports false rather than propagating an
// error: the Executor interface's IsMounted has no error return, matching
// Manager's atomic state tracking, which is itself a best-effort cache over
// the kernel's ground truth.
func (e *LibExecutor) IsMounted(config *VolumeConfig) bool {
	mounted, err := isMountedFn(config.MountPoint)
	if err != nil {
		return false
	}
	return mounted
}

// IsUnlocked reports whether config.MapperName currently has a device-mapper
// mapping.
func (e *LibExecutor) IsUnlocked(config *VolumeConfig) bool {
	return isUnlockedFn(config.MapperName)
}
