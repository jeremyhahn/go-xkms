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

// Package luks provides xkey's desktop/CLI-facing LUKS volume glue: a thin
// Volume wrapper around go-xkms's canonical LUKS implementation
// (sdk/go/luks, backed by pkg/luks's go-luks2 Executor), plus the
// privilege-drop (sudo/pkexec chown) and secure-wipe behavior that is
// genuinely specific to xkey's desktop UX. The LUKS lifecycle itself --
// loop device attach/detach, format, unlock, mount -- lives once, in
// go-xkms/pkg/luks (go-xkms#917); this package never duplicates it.
package luks

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	sdkluks "github.com/jeremyhahn/go-xkms/sdk/go/luks"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// volumeExecutor is the shared, production LUKS Executor every Volume
// operation drives the kernel through. It is a package variable so unit
// tests can substitute a fake instead of requiring a real loop device,
// dm-crypt mapping or mount; the fault-injection coverage of the
// production implementation itself lives in go-xkms/pkg/luks's own test
// suite.
var volumeExecutor sdkluks.Executor = sdkluks.NewLibExecutor()

// Volume represents a LUKS encrypted volume.
type Volume struct {
	LUKSPath   string // Path to the .luks file
	MountPoint string // Where to mount the volume
	MapperName string // device-mapper name
}

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

// config builds the sdk/go/luks VolumeConfig that drives the shared
// Executor for this Volume's paths.
func (v *Volume) config() *sdkluks.VolumeConfig {
	cfg := &sdkluks.VolumeConfig{
		LUKSPath:   v.LUKSPath,
		MountPoint: v.MountPoint,
		MapperName: v.MapperName,
	}
	cfg.SetDefaults()
	return cfg
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

// IsMounted checks if the volume is mounted. It returns an error when the
// mount state could not be determined; callers must not treat that as
// "not mounted".
func (v *Volume) IsMounted() (bool, error) {
	return IsMounted(v.MountPoint)
}

// IsOpen checks if the LUKS volume is unlocked.
func (v *Volume) IsOpen() bool {
	return IsLUKSOpen(v.MapperName)
}

// Create creates a new LUKS volume through the shared production Executor.
func (v *Volume) Create(sizeBytes int64, passphrase string) error {
	if v.Exists() {
		return ErrVolumeAlreadyExists
	}

	if err := volumeExecutor.Create(context.Background(), v.config(), sizeBytes, passphrase); err != nil {
		if errors.Is(err, sdkluks.ErrVolumeAlreadyExists) {
			return ErrVolumeAlreadyExists
		}
		return err
	}
	return nil
}

// Unlock opens and mounts the LUKS volume. A failed Mount after a
// successful Unlock is unwound by locking the volume back, so Unlock is
// all-or-nothing from the caller's perspective.
func (v *Volume) Unlock(passphrase string) error {
	if !v.Exists() {
		return ErrVolumeNotFound
	}

	mounted, err := v.IsMounted()
	if err != nil {
		return err
	}
	if mounted {
		return ErrVolumeAlreadyMounted
	}

	ctx := context.Background()
	cfg := v.config()

	if err := volumeExecutor.Unlock(ctx, cfg, passphrase); err != nil {
		if errors.Is(err, sdkluks.ErrVolumeNotFound) {
			return ErrVolumeNotFound
		}
		return err
	}

	if err := volumeExecutor.Mount(ctx, cfg); err != nil {
		if lockErr := volumeExecutor.Lock(ctx, cfg); lockErr != nil {
			return errors.Join(err, lockErr)
		}
		return err
	}

	// Chown the entire mount tree to the real (non-elevated) user when
	// running under sudo or pkexec so that the unprivileged GUI process
	// can read and write all files (e.g. ~/.xkey/data/, lost+found).
	chownTreeToCallingUser(v.MountPoint)

	return nil
}

// Lock unmounts and closes the LUKS volume.
func (v *Volume) Lock() error {
	mounted, err := v.IsMounted()
	if err != nil {
		return err
	}
	if !v.IsOpen() && !mounted {
		return ErrVolumeNotMounted
	}

	ctx := context.Background()
	cfg := v.config()

	if mounted {
		if err := volumeExecutor.Unmount(ctx, cfg); err != nil {
			return err
		}
	}

	if v.IsOpen() {
		if err := volumeExecutor.Lock(ctx, cfg); err != nil {
			return err
		}
	}

	return nil
}

// CopyDataToVolume copies data from source directory to the mounted volume.
// After copying, all files and directories are chowned to the real
// (non-elevated) calling user so that the unprivileged GUI process can
// access them.
func (v *Volume) CopyDataToVolume(sourceDir string) error {
	mounted, err := v.IsMounted()
	if err != nil {
		return err
	}
	if !mounted {
		return ErrVolumeNotMounted
	}

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
