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
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// Volume represents a LUKS encrypted volume.
type Volume struct {
	LUKSPath   string // Path to the .luks file
	MountPoint string // Where to mount the volume
	MapperName string // device-mapper name
	LoopDevice string // Loop device path (set after setup)
}

// The following are go-luks2's kernel-facing primitives. Each is a variable,
// following the same pattern as checkKeyringAvailable, so tests can stand in
// for the kernel instead of requiring a real loop device, dm-crypt mapping
// or mount.
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

// NewVolume creates a new Volume instance with paths resolved through
// xhome.Resolve.
func NewVolume() (*Volume, error) {
	h, err := xhome.Resolve()
	if err != nil {
		return nil, err
	}
	return NewVolumeFromHome(h), nil
}

// NewVolumeWithPaths creates a Volume with custom paths.
func NewVolumeWithPaths(luksPath, mountPoint string) *Volume {
	return &Volume{
		LUKSPath:   ExpandPath(luksPath),
		MountPoint: ExpandPath(mountPoint),
		MapperName: MapperName,
	}
}

// GetMountPoint returns the path where the volume is mounted.
func (v *Volume) GetMountPoint() string {
	return v.MountPoint
}

// Exists checks if the LUKS file exists.
func (v *Volume) Exists() bool {
	_, err := os.Stat(v.LUKSPath)
	return err == nil
}

// IsLUKS checks if the file is a valid LUKS volume.
func (v *Volume) IsLUKS() bool {
	return IsLUKSVolume(v.LUKSPath)
}

// IsMounted checks if the volume is mounted.
func (v *Volume) IsMounted() bool {
	mounted, _ := isMountedFn(v.MountPoint)
	return mounted
}

// IsOpen checks if the LUKS volume is unlocked.
func (v *Volume) IsOpen() bool {
	return isUnlockedFn(v.MapperName)
}

// Create creates a new LUKS volume using go-luks2 library.
func (v *Volume) Create(sizeBytes int64, passphrase string) error {
	if v.Exists() {
		return ErrVolumeAlreadyExists
	}

	// The unlock below needs the kernel keyring; refuse before a container
	// file exists rather than after a format that cannot be opened.
	if err := EnsureKeyringAvailable(); err != nil {
		return err
	}

	// Create parent directory
	dir := filepath.Dir(v.LUKSPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &VolumeError{Operation: "create_dir", Path: dir, Err: err}
	}

	// Create sparse file. O_EXCL makes the existence check atomic with
	// creation, closing the race window between the Exists check above
	// and this call.
	f, err := os.OpenFile(v.LUKSPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrVolumeAlreadyExists
		}
		return &VolumeError{Operation: "create_file", Path: v.LUKSPath, Err: err}
	}
	if err := f.Truncate(sizeBytes); err != nil {
		cleanupErr := errors.Join(f.Close(), os.Remove(v.LUKSPath))
		return &VolumeError{Operation: "truncate", Path: v.LUKSPath, Err: errors.Join(err, cleanupErr)}
	}
	if err := f.Close(); err != nil {
		return &VolumeError{Operation: "close_file", Path: v.LUKSPath, Err: errors.Join(err, os.Remove(v.LUKSPath))}
	}

	// Setup loop device using go-luks2
	loopDev, err := setupLoopDevice(v.LUKSPath)
	if err != nil {
		return &VolumeError{Operation: "setup_loop", Path: v.LUKSPath, Err: errors.Join(err, os.Remove(v.LUKSPath))}
	}
	v.LoopDevice = loopDev

	// Format with LUKS2 using go-luks2
	formatOpts := luks2.FormatOptions{
		Device:     loopDev,
		Passphrase: []byte(passphrase),
	}
	if err := formatLUKS(formatOpts); err != nil {
		cleanupErr := errors.Join(detachLoopDevice(loopDev), os.Remove(v.LUKSPath))
		return &VolumeError{Operation: "luks_format", Path: loopDev, Err: errors.Join(err, cleanupErr)}
	}

	// Unlock the volume
	if err := unlockLUKS(loopDev, []byte(passphrase), v.MapperName); err != nil {
		cleanupErr := errors.Join(detachLoopDevice(loopDev), os.Remove(v.LUKSPath))
		return &VolumeError{Operation: "luks_unlock", Path: loopDev, Err: errors.Join(err, cleanupErr)}
	}

	// Create ext4 filesystem using go-luks2
	if err := makeFilesystem(v.MapperName, "ext4", "xkey"); err != nil {
		cleanupErr := errors.Join(lockLUKS(v.MapperName), detachLoopDevice(loopDev), os.Remove(v.LUKSPath))
		return &VolumeError{Operation: "create_fs", Path: v.MapperName, Err: errors.Join(err, cleanupErr)}
	}

	// Lock it back
	if err := lockLUKS(v.MapperName); err != nil {
		return &VolumeError{Operation: "luks_lock", Path: v.MapperName, Err: errors.Join(err, detachLoopDevice(loopDev))}
	}

	// Detach loop device
	if err := detachLoopDevice(loopDev); err != nil {
		return &VolumeError{Operation: "detach_loop", Path: loopDev, Err: err}
	}
	v.LoopDevice = ""

	return nil
}

// Unlock opens and mounts the LUKS volume.
func (v *Volume) Unlock(passphrase string) error {
	if !v.Exists() {
		return ErrVolumeNotFound
	}

	if v.IsMounted() {
		return ErrVolumeAlreadyMounted
	}

	// Refuse before a loop device is attached: an unlock that cannot place
	// the volume key in the kernel keyring must not leave one behind.
	if err := EnsureKeyringAvailable(); err != nil {
		return err
	}

	// Setup loop device
	loopDev, err := setupLoopDevice(v.LUKSPath)
	if err != nil {
		return &VolumeError{Operation: "setup_loop", Path: v.LUKSPath, Err: err}
	}
	v.LoopDevice = loopDev

	// Unlock LUKS
	if err := unlockLUKS(loopDev, []byte(passphrase), v.MapperName); err != nil {
		return &VolumeError{Operation: "luks_unlock", Path: loopDev, Err: errors.Join(err, detachLoopDevice(loopDev))}
	}

	// Create mount point
	if err := os.MkdirAll(v.MountPoint, 0700); err != nil {
		cleanupErr := errors.Join(lockLUKS(v.MapperName), detachLoopDevice(loopDev))
		return &VolumeError{Operation: "create_mountpoint", Path: v.MountPoint, Err: errors.Join(err, cleanupErr)}
	}

	// Mount using go-luks2
	mountOpts := luks2.MountOptions{
		Device:     v.MapperName,
		MountPoint: v.MountPoint,
		FSType:     "ext4",
		Flags:      0,
	}
	if err := mountLUKS(mountOpts); err != nil {
		cleanupErr := errors.Join(lockLUKS(v.MapperName), detachLoopDevice(loopDev))
		return &VolumeError{Operation: "mount", Path: v.MountPoint, Err: errors.Join(err, cleanupErr)}
	}

	// go-luks2 creates the ext4 filesystem with mkfs.ext4's default root
	// permissions (0755), and mounting it replaces whatever mode the
	// MkdirAll above gave the mount point directory. Re-assert 0700 here so
	// the unlocked volume is never left world-listable.
	if err := chmodFn(v.MountPoint, 0700); err != nil {
		cleanupErr := errors.Join(unmountLUKS(v.MountPoint, 0), lockLUKS(v.MapperName), detachLoopDevice(loopDev))
		return &VolumeError{Operation: "chmod_mountpoint", Path: v.MountPoint, Err: errors.Join(err, cleanupErr)}
	}

	// Chown the entire mount tree to the real (non-elevated) user when
	// running under sudo or pkexec so that the unprivileged GUI process
	// can read and write all files (e.g. ~/.xkey/data/, lost+found).
	chownTreeToCallingUser(v.MountPoint)

	return nil
}

// Lock unmounts and closes the LUKS volume.
func (v *Volume) Lock() error {
	if !v.IsOpen() && !v.IsMounted() {
		return ErrVolumeNotMounted
	}

	// Unmount if mounted
	if v.IsMounted() {
		if err := unmountLUKS(v.MountPoint, 0); err != nil {
			return &VolumeError{Operation: "unmount", Path: v.MountPoint, Err: err}
		}
	}

	// Close LUKS if open
	if v.IsOpen() {
		if err := lockLUKS(v.MapperName); err != nil {
			return &VolumeError{Operation: "luks_lock", Path: v.MapperName, Err: err}
		}
	}

	// Find and detach loop device
	loopDev, err := findLoopDeviceFn(v.LUKSPath)
	if err == nil && loopDev != "" {
		if err := detachLoopDevice(loopDev); err != nil {
			return &VolumeError{Operation: "detach_loop", Path: loopDev, Err: err}
		}
	}
	v.LoopDevice = ""

	return nil
}

// CopyDataToVolume copies data from source directory to the mounted volume.
// After copying, all files and directories are chowned to the real
// (non-elevated) calling user so that the unprivileged GUI process can
// access them.
func (v *Volume) CopyDataToVolume(sourceDir string) error {
	if !v.IsMounted() {
		return ErrVolumeNotMounted
	}

	// Copy all files from source to mount point.
	if err := copyDir(sourceDir, v.MountPoint); err != nil {
		return err
	}

	// Fix ownership of everything we just copied. The copy runs as root
	// (via pkexec / sudo), so all new inodes are owned by root:root.
	// The unprivileged GUI process needs to read and write these files.
	chownTreeToCallingUser(v.MountPoint)

	return nil
}

// ChownToCallingUser changes ownership of the given path to the real
// (non-elevated) user when the process is running as root via sudo or
// pkexec. This ensures that the unprivileged user can access files
// inside the LUKS mount point after it is mounted by the elevated
// process.
//
// The function is intentionally best-effort: if the chown fails or the
// calling user cannot be determined, it logs a warning and returns
// without error so that the unlock operation is not disrupted.
func ChownToCallingUser(path string) {
	if geteuid() != 0 {
		return
	}

	uid, gid, ok := resolveCallingUser()
	if !ok {
		return
	}

	if err := os.Chown(path, uid, gid); err != nil {
		slog.Warn("failed to chown path to calling user",
			"path", path,
			"uid", uid,
			"gid", gid,
			"error", err,
		)
	}
}

// chownTreeToCallingUser recursively changes ownership of a directory
// tree to the real (non-elevated) calling user. This is used after
// mounting a freshly-created ext4 filesystem (whose root inode is
// root:root) and after copying data into it. lost+found is included
// so that the entire volume is accessible to the unprivileged user.
//
// Best-effort: individual file chown errors are logged but do not
// abort the walk.
func chownTreeToCallingUser(root string) {
	if geteuid() != 0 {
		return
	}

	uid, gid, ok := resolveCallingUser()
	if !ok {
		return
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			slog.Warn("chown walk: access error", "path", path, "error", walkErr)
			return nil // best-effort: skip inaccessible entries
		}
		if chownErr := os.Lchown(path, uid, gid); chownErr != nil {
			slog.Warn("chown walk: failed to chown",
				"path", path,
				"uid", uid,
				"gid", gid,
				"error", chownErr,
			)
		}
		return nil
	})
	if err != nil {
		slog.Warn("chown walk: walk failed", "root", root, "error", err)
	}
}

// resolveCallingUser determines the UID and GID of the real (non-root)
// user who invoked the current process via sudo or pkexec.
//
// Resolution order:
//  1. SUDO_UID / SUDO_GID environment variables (set by sudo).
//  2. PKEXEC_UID environment variable (set by pkexec); the GID is
//     looked up from /etc/passwd via os/user.LookupId.
//
// Returns (uid, gid, true) on success or (0, 0, false) when the
// calling user cannot be determined.
func resolveCallingUser() (int, int, bool) {
	// Try sudo first: both UID and GID are available.
	if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
		uid, err := strconv.Atoi(sudoUID)
		if err != nil {
			slog.Warn("invalid SUDO_UID value", "SUDO_UID", sudoUID, "error", err)
			return 0, 0, false
		}

		sudoGID := os.Getenv("SUDO_GID")
		gid, err := strconv.Atoi(sudoGID)
		if err != nil {
			slog.Warn("invalid SUDO_GID value, looking up from passwd", "SUDO_GID", sudoGID, "error", err)
			gid, err = lookupGIDForUID(sudoUID)
			if err != nil {
				slog.Warn("failed to look up GID for SUDO_UID", "uid", sudoUID, "error", err)
				return 0, 0, false
			}
		}

		return uid, gid, true
	}

	// Try pkexec: only UID is available; look up GID from passwd.
	if pkexecUID := os.Getenv("PKEXEC_UID"); pkexecUID != "" {
		uid, err := strconv.Atoi(pkexecUID)
		if err != nil {
			slog.Warn("invalid PKEXEC_UID value", "PKEXEC_UID", pkexecUID, "error", err)
			return 0, 0, false
		}

		gid, err := lookupGIDForUID(pkexecUID)
		if err != nil {
			slog.Warn("failed to look up GID for PKEXEC_UID", "uid", pkexecUID, "error", err)
			return 0, 0, false
		}

		return uid, gid, true
	}

	return 0, 0, false
}

// lookupGIDForUID resolves the primary GID for the given numeric UID
// string by consulting the system user database.
func lookupGIDForUID(uidStr string) (int, error) {
	u, err := user.LookupId(uidStr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Gid)
}

// copyDir recursively copies a directory.
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := os.MkdirAll(dstPath, 0700); err != nil {
				return err
			}
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// copyFile copies a single file.
func copyFile(src, dst string) (err error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := srcFile.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}

	if _, copyErr := io.Copy(dstFile, srcFile); copyErr != nil {
		return errors.Join(copyErr, dstFile.Close())
	}

	// Surface any flush error from closing the destination file.
	return dstFile.Close()
}
