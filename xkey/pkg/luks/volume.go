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
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Volume represents a LUKS encrypted volume.
type Volume struct {
	LUKSPath   string // Path to the .luks file
	MountPoint string // Where to mount the volume
	MapperName string // device-mapper name
	LoopDevice string // Loop device path (set after setup)
}

// NewVolume creates a new Volume instance with default paths.
func NewVolume() (*Volume, error) {
	luksPath, err := GetDefaultLUKSPath()
	if err != nil {
		return nil, err
	}

	dataDir, err := GetDefaultDataDir()
	if err != nil {
		return nil, err
	}

	return &Volume{
		LUKSPath:   luksPath,
		MountPoint: dataDir,
		MapperName: MapperName,
	}, nil
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
	mounted, _ := luks2.IsMounted(v.MountPoint)
	return mounted
}

// IsOpen checks if the LUKS volume is unlocked.
func (v *Volume) IsOpen() bool {
	return luks2.IsUnlocked(v.MapperName)
}

// Create creates a new LUKS volume using go-luks2 library.
func (v *Volume) Create(sizeBytes int64, passphrase string) error {
	if v.Exists() {
		return ErrVolumeAlreadyExists
	}

	// Create parent directory
	dir := filepath.Dir(v.LUKSPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &VolumeError{Operation: "create_dir", Path: dir, Err: err}
	}

	// Create sparse file
	f, err := os.Create(v.LUKSPath)
	if err != nil {
		return &VolumeError{Operation: "create_file", Path: v.LUKSPath, Err: err}
	}
	if err := f.Truncate(sizeBytes); err != nil {
		f.Close()
		os.Remove(v.LUKSPath)
		return &VolumeError{Operation: "truncate", Path: v.LUKSPath, Err: err}
	}
	f.Close()

	// Setup loop device using go-luks2
	loopDev, err := luks2.SetupLoopDevice(v.LUKSPath)
	if err != nil {
		os.Remove(v.LUKSPath)
		return &VolumeError{Operation: "setup_loop", Path: v.LUKSPath, Err: err}
	}
	v.LoopDevice = loopDev

	// Format with LUKS2 using go-luks2
	formatOpts := luks2.FormatOptions{
		Device:     loopDev,
		Passphrase: []byte(passphrase),
	}
	if err := luks2.Format(formatOpts); err != nil {
		luks2.DetachLoopDevice(loopDev)
		os.Remove(v.LUKSPath)
		return &VolumeError{Operation: "luks_format", Path: loopDev, Err: err}
	}

	// Unlock the volume
	if err := luks2.Unlock(loopDev, []byte(passphrase), v.MapperName); err != nil {
		luks2.DetachLoopDevice(loopDev)
		os.Remove(v.LUKSPath)
		return &VolumeError{Operation: "luks_unlock", Path: loopDev, Err: err}
	}

	// Create ext4 filesystem using go-luks2
	if err := luks2.MakeFilesystem(v.MapperName, "ext4", "xkey"); err != nil {
		luks2.Lock(v.MapperName)
		luks2.DetachLoopDevice(loopDev)
		os.Remove(v.LUKSPath)
		return &VolumeError{Operation: "create_fs", Path: v.MapperName, Err: err}
	}

	// Lock it back
	if err := luks2.Lock(v.MapperName); err != nil {
		luks2.DetachLoopDevice(loopDev)
		return &VolumeError{Operation: "luks_lock", Path: v.MapperName, Err: err}
	}

	// Detach loop device
	if err := luks2.DetachLoopDevice(loopDev); err != nil {
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

	// Setup loop device
	loopDev, err := luks2.SetupLoopDevice(v.LUKSPath)
	if err != nil {
		return &VolumeError{Operation: "setup_loop", Path: v.LUKSPath, Err: err}
	}
	v.LoopDevice = loopDev

	// Unlock LUKS
	if err := luks2.Unlock(loopDev, []byte(passphrase), v.MapperName); err != nil {
		luks2.DetachLoopDevice(loopDev)
		return &VolumeError{Operation: "luks_unlock", Path: loopDev, Err: err}
	}

	// Create mount point
	if err := os.MkdirAll(v.MountPoint, 0700); err != nil {
		luks2.Lock(v.MapperName)
		luks2.DetachLoopDevice(loopDev)
		return &VolumeError{Operation: "create_mountpoint", Path: v.MountPoint, Err: err}
	}

	// Mount using go-luks2
	mountOpts := luks2.MountOptions{
		Device:     v.MapperName,
		MountPoint: v.MountPoint,
		FSType:     "ext4",
		Flags:      0,
	}
	if err := luks2.Mount(mountOpts); err != nil {
		luks2.Lock(v.MapperName)
		luks2.DetachLoopDevice(loopDev)
		return &VolumeError{Operation: "mount", Path: v.MountPoint, Err: err}
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
		if err := luks2.Unmount(v.MountPoint, 0); err != nil {
			return &VolumeError{Operation: "unmount", Path: v.MountPoint, Err: err}
		}
	}

	// Close LUKS if open
	if v.IsOpen() {
		if err := luks2.Lock(v.MapperName); err != nil {
			return &VolumeError{Operation: "luks_lock", Path: v.MapperName, Err: err}
		}
	}

	// Find and detach loop device
	loopDev, err := luks2.FindLoopDevice(v.LUKSPath)
	if err == nil && loopDev != "" {
		if err := luks2.DetachLoopDevice(loopDev); err != nil {
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
	if os.Geteuid() != 0 {
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
	if os.Geteuid() != 0 {
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
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
