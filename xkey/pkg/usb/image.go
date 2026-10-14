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

package usb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

const (
	// fat32Label is the volume label for the FAT32 boot partition.
	fat32Label = "XKEY"

	// luksLabel is the label for the LUKS2 encrypted data partition.
	luksLabel = "xkey-data"

	// luksMapperName is the device-mapper name for the USB LUKS partition.
	luksMapperName = "xkey-usb-data"
)

// ImageConfig holds parameters for creating a USB disk image.
type ImageConfig struct {
	// Path is the output path (file or block device).
	Path string

	// SizeBytes is the total image size. Ignored for block devices
	// (the full device size is used).
	SizeBytes int64

	// Passphrase is the LUKS passphrase for the data partition, held in
	// protected memory. Nil means no passphrase, which CreateImage rejects.
	Passphrase *secure.Secret

	// Binaries is a list of paths to xkey binaries to copy onto the
	// FAT32 partition.
	Binaries []string
}

// ImageStatus describes the state of an existing image or device.
type ImageStatus struct {
	Path          string   // Path to image or device
	IsBlockDevice bool     // True if path is a block device
	TotalSize     int64    // Total size in bytes
	FAT32Size     int64    // FAT32 partition size in bytes
	LUKSSize      int64    // LUKS partition size in bytes
	LUKSMounted   bool     // True if LUKS partition is mounted
	Binaries      []string // Binaries found on the FAT32 partition
}

// CreateImage creates a two-partition disk image or prepares a block
// device for xKey portable use.
//
// Partition layout:
//
//	Partition 1: FAT32, 512MB, label "XKEY" - contains binaries,
//	             .xkey-home marker, launcher script, and README.
//	Partition 2: LUKS2, remainder, label "xkey-data" - encrypted
//	             data partition.
//
// This function requires root privileges for partitioning and
// filesystem creation.
func CreateImage(ctx context.Context, cfg ImageConfig) error {
	if getEUID() != 0 {
		return ErrPermissionDenied
	}

	if cfg.Passphrase == nil {
		return &USBError{
			Operation: "validate_config",
			Err:       &DetailError{Err: ErrInvalidSize, Detail: ": passphrase is required"},
		}
	}

	// The LUKS format and every later unlock need the kernel keyring. Refuse
	// here, before the image file, the partition table or either filesystem
	// exists, rather than after a real device has been partitioned for a
	// container that could never be opened.
	if err := luksCheckKeyring(); err != nil {
		return &USBError{Operation: "keyring_preflight", Path: cfg.Path, Err: err}
	}

	isBlock := IsBlockDevice(cfg.Path)

	if isBlock {
		if err := ValidateBlockDevice(cfg.Path); err != nil {
			return err
		}
		return createOnBlockDevice(ctx, cfg)
	}

	return createOnImageFile(ctx, cfg)
}

// createOnImageFile creates a sparse image file and partitions it.
func createOnImageFile(ctx context.Context, cfg ImageConfig) error {
	if cfg.SizeBytes < MinImageSize {
		return &USBError{
			Operation: "validate_size",
			Path:      cfg.Path,
			Err:       &DetailError{Err: ErrInvalidSize, Detail: fmt.Sprintf(": minimum size is %s, got %s", FormatSize(MinImageSize), FormatSize(cfg.SizeBytes))},
		}
	}

	// Create parent directory.
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &USBError{Operation: "create_dir", Path: dir, Err: err}
	}

	// Create sparse file. O_EXCL makes the existence check atomic with
	// creation, closing the race window between a separate Stat check
	// and a later create call.
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return &USBError{
				Operation: "check_existing",
				Path:      cfg.Path,
				Err:       ErrImageExists,
			}
		}
		return &USBError{Operation: "create_file", Path: cfg.Path, Err: err}
	}
	if err := f.Truncate(cfg.SizeBytes); err != nil {
		closeErr := f.Close()
		removeErr := os.Remove(cfg.Path)
		return &USBError{Operation: "truncate", Path: cfg.Path, Err: errors.Join(err, closeErr, removeErr)}
	}
	if err := f.Close(); err != nil {
		return &USBError{Operation: "close_file", Path: cfg.Path, Err: errors.Join(err, os.Remove(cfg.Path))}
	}

	// Set up loop device.
	loopDev, err := luksSetupLoopDevice(ctx, cfg.Path)
	if err != nil {
		return &USBError{Operation: "setup_loop", Path: cfg.Path, Err: errors.Join(err, os.Remove(cfg.Path))}
	}

	slog.Info("loop device attached", "device", loopDev, "image", cfg.Path)

	if err := partitionAndFormat(ctx, loopDev, cfg); err != nil {
		detachErr := luksDetachLoopDevice(ctx, loopDev)
		removeErr := os.Remove(cfg.Path)
		return errors.Join(err, detachErr, removeErr)
	}

	if err := luksDetachLoopDevice(ctx, loopDev); err != nil {
		slog.Warn("failed to detach loop device", "device", loopDev, "error", err)
	}

	return nil
}

// createOnBlockDevice partitions and formats a block device directly.
func createOnBlockDevice(ctx context.Context, cfg ImageConfig) error {
	return partitionAndFormat(ctx, cfg.Path, cfg)
}

// partitionAndFormat creates the GPT partition table, formats both
// partitions, and populates the FAT32 partition with binaries.
func partitionAndFormat(ctx context.Context, device string, cfg ImageConfig) error {
	// Step 1: Create GPT partition table with sgdisk.
	if err := createPartitionTable(device); err != nil {
		return err
	}

	// Determine partition device names.
	part1, part2 := partitionDevices(device)

	// Ensure the kernel re-reads the partition table.
	if err := execCommand("partprobe", device); err != nil {
		slog.Warn("partprobe failed, trying partx", "error", err)
		if partxErr := execCommand("partx", "-u", device); partxErr != nil {
			slog.Warn("partx fallback failed", "device", device, "error", partxErr)
		}
	}

	// Step 2: Format partition 1 as FAT32.
	if err := formatFAT32(part1); err != nil {
		return err
	}

	// Step 3: Format partition 2 as LUKS2.
	if err := formatLUKS(ctx, part2, cfg.Passphrase); err != nil {
		return err
	}

	// Step 4: Mount FAT32 and copy binaries.
	if err := populateFAT32(part1, cfg.Binaries); err != nil {
		return err
	}

	return nil
}

// createPartitionTable creates a GPT partition table with two
// partitions using sgdisk:
//
//	Partition 1: 512 MB, type EF00 (EFI System), label "XKEY"
//	Partition 2: Remaining space, type 8300 (Linux), label "xkey-data"
func createPartitionTable(device string) error {
	// Zap existing partition tables.
	if err := execCommand("sgdisk", "--zap-all", device); err != nil {
		return &USBError{
			Operation: "zap_partitions",
			Path:      device,
			Err:       &SentinelCauseError{Sentinel: ErrPartitionFailed, Cause: err},
		}
	}

	// Create partition 1: 512 MB FAT32.
	fat32SizeSectors := FAT32PartitionSize / 512
	part1End := fmt.Sprintf("+%d", fat32SizeSectors)

	if err := execCommand("sgdisk",
		"--new=1:2048:"+part1End,
		"--typecode=1:EF00",
		"--change-name=1:"+fat32Label,
		device,
	); err != nil {
		return &USBError{
			Operation: "create_partition_1",
			Path:      device,
			Err:       &SentinelCauseError{Sentinel: ErrPartitionFailed, Cause: err},
		}
	}

	// Create partition 2: remaining space.
	if err := execCommand("sgdisk",
		"--new=2:0:0",
		"--typecode=2:8300",
		"--change-name=2:"+luksLabel,
		device,
	); err != nil {
		return &USBError{
			Operation: "create_partition_2",
			Path:      device,
			Err:       &SentinelCauseError{Sentinel: ErrPartitionFailed, Cause: err},
		}
	}

	return nil
}

// formatFAT32 formats a partition as FAT32 with the XKEY label.
func formatFAT32(partition string) error {
	if err := execCommand("mkfs.vfat", "-F", "32", "-n", fat32Label, partition); err != nil {
		return &USBError{
			Operation: "format_fat32",
			Path:      partition,
			Err:       &SentinelCauseError{Sentinel: ErrFormatFailed, Cause: err},
		}
	}
	return nil
}

// formatLUKS formats a partition as LUKS2 using the go-luks2 library. The
// passphrase is opened into protected memory for the duration of the call
// and never copied to the ordinary heap.
func formatLUKS(ctx context.Context, partition string, passphrase *secure.Secret) error {
	buf, err := passphrase.Open(ctx)
	if err != nil {
		return &USBError{
			Operation: "open_passphrase",
			Path:      partition,
			Err:       err,
		}
	}
	defer buf.Destroy()

	pass, err := admitPassphraseCopy(buf)
	if err != nil {
		return &USBError{
			Operation: "protect_passphrase",
			Path:      partition,
			Err:       err,
		}
	}

	err = formatAndInitLUKS(ctx, partition, pass)
	if destroyErr := pass.Destroy(); destroyErr != nil {
		err = errors.Join(err, &USBError{Operation: "destroy_passphrase", Path: partition, Err: destroyErr})
	}
	return err
}

// admitPassphraseCopy copies buf into a frozen enclave for go-luks2, admitted
// against the process locked-memory budget. The copy goes from locked page to
// locked page; a refusal is returned, never bypassed.
func admitPassphraseCopy(buf *secure.Buffer) (*enclave.MemoryEnclave, error) {
	alloc, err := enclave.ProcessAllocator()
	if err != nil {
		return nil, err
	}
	var pass *enclave.MemoryEnclave
	err = buf.WithBytes(func(src []byte) error {
		var sizeErr error
		pass, sizeErr = alloc.NewSized(len(src))
		if sizeErr != nil {
			return sizeErr
		}
		return pass.WithBytes(func(dst []byte) error {
			copy(dst, src)
			return nil
		})
	})
	if err == nil {
		err = pass.Freeze()
	}
	if err != nil {
		if pass != nil {
			err = errors.Join(err, pass.Destroy())
		}
		return nil, err
	}
	return pass, nil
}

// formatAndInitLUKS formats partition as LUKS2 under pass, then unlocks it
// long enough to create the ext4 data filesystem and locks it again.
func formatAndInitLUKS(ctx context.Context, partition string, pass *enclave.MemoryEnclave) error {
	if err := luksFormat(ctx, partition, pass, luks2.FormatParams{}); err != nil {
		return &USBError{
			Operation: "format_luks",
			Path:      partition,
			Err:       &SentinelCauseError{Sentinel: ErrFormatFailed, Cause: err},
		}
	}

	mapping, err := luksUnlock(ctx, partition, pass, luksMapperName)
	if err != nil {
		return &USBError{
			Operation: "unlock_luks",
			Path:      partition,
			Err:       err,
		}
	}

	if err := luksMakeFilesystem(ctx, mapping.Path(), filesystem.Ext4, filesystem.MakeParams{Label: luksLabel}); err != nil {
		lockErr := luksLock(ctx, luksMapperName)
		return &USBError{
			Operation: "create_ext4",
			Path:      partition,
			Err:       &SentinelCauseError{Sentinel: ErrFormatFailed, Cause: errors.Join(err, lockErr)},
		}
	}

	if err := luksLock(ctx, luksMapperName); err != nil {
		return &USBError{
			Operation: "lock_luks",
			Path:      partition,
			Err:       err,
		}
	}

	return nil
}

// populateFAT32 mounts the FAT32 partition, copies binaries and
// support files, then unmounts.
func populateFAT32(partition string, binaries []string) error {
	mountDir, err := os.MkdirTemp("", "xkey-fat32-")
	if err != nil {
		return &USBError{Operation: "create_mount_dir", Err: err}
	}
	defer func() {
		if removeErr := os.RemoveAll(mountDir); removeErr != nil {
			slog.Warn("failed to remove temp mount dir", "path", mountDir, "error", removeErr)
		}
	}()

	// Mount the FAT32 partition.
	if err := execCommand("mount", "-t", "vfat", partition, mountDir); err != nil {
		return &USBError{
			Operation: "mount_fat32",
			Path:      partition,
			Err:       &SentinelCauseError{Sentinel: ErrMountFailed, Cause: err},
		}
	}
	defer func() {
		if umountErr := execCommand("umount", mountDir); umountErr != nil {
			slog.Warn("failed to unmount FAT32", "path", mountDir, "error", umountErr)
		}
	}()

	// Create the .xkey-home marker file.
	markerPath := filepath.Join(mountDir, xhome.MarkerFile)
	if err := os.WriteFile(markerPath, []byte("xkey portable home\n"), 0644); err != nil {
		return &USBError{Operation: "create_marker", Path: markerPath, Err: err}
	}

	// Write the launcher script.
	launcherPath := filepath.Join(mountDir, "xkey.sh")
	if err := os.WriteFile(launcherPath, []byte(GenerateLauncher()), 0755); err != nil {
		return &USBError{Operation: "write_launcher", Path: launcherPath, Err: err}
	}

	// Write the README.
	readmePath := filepath.Join(mountDir, "README.txt")
	if err := os.WriteFile(readmePath, []byte(GenerateReadme()), 0644); err != nil {
		return &USBError{Operation: "write_readme", Path: readmePath, Err: err}
	}

	// Copy binaries.
	for _, binPath := range binaries {
		if err := copyBinary(binPath, mountDir); err != nil {
			return err
		}
	}

	return nil
}

// copyBinary copies a single binary file to the destination directory,
// preserving the filename and setting executable permissions.
func copyBinary(srcPath, dstDir string) (err error) {
	info, err := os.Stat(srcPath)
	if err != nil {
		return &USBError{
			Operation: "stat_binary",
			Path:      srcPath,
			Err:       &SentinelCauseError{Sentinel: ErrBinaryNotFound, Cause: err},
		}
	}
	if info.IsDir() {
		return &USBError{
			Operation: "validate_binary",
			Path:      srcPath,
			Err:       &DetailError{Err: ErrBinaryNotFound, Detail: ": path is a directory"},
		}
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return &USBError{Operation: "open_binary", Path: srcPath, Err: err}
	}
	defer func() {
		if closeErr := src.Close(); closeErr != nil {
			err = errors.Join(err, &USBError{Operation: "close_source", Path: srcPath, Err: closeErr})
		}
	}()

	dstPath := filepath.Join(dstDir, filepath.Base(srcPath))
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return &USBError{Operation: "create_dest", Path: dstPath, Err: err}
	}
	defer func() {
		if closeErr := dst.Close(); closeErr != nil {
			err = errors.Join(err, &USBError{Operation: "close_dest", Path: dstPath, Err: closeErr})
		}
	}()

	if _, copyErr := io.Copy(dst, src); copyErr != nil {
		return &USBError{
			Operation: "copy_binary",
			Path:      srcPath,
			Err:       &SentinelCauseError{Sentinel: ErrCopyFailed, Cause: copyErr},
		}
	}

	return nil
}

// Status returns the status of an existing image or block device.
func Status(ctx context.Context, path string) (*ImageStatus, error) {
	info, err := statPath(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &USBError{
				Operation: "status",
				Path:      path,
				Err:       ErrImageNotFound,
			}
		}
		return nil, &USBError{Operation: "stat", Path: path, Err: err}
	}

	status := &ImageStatus{
		Path:          path,
		IsBlockDevice: IsBlockDevice(path),
	}

	if status.IsBlockDevice {
		size, sizeErr := BlockDeviceSize(path)
		if sizeErr != nil {
			return nil, sizeErr
		}
		status.TotalSize = size
	} else {
		status.TotalSize = info.Size()
	}

	// Calculate partition sizes based on the image layout.
	status.FAT32Size = FAT32PartitionSize
	if status.TotalSize > FAT32PartitionSize {
		status.LUKSSize = status.TotalSize - FAT32PartitionSize
	}

	// Check if the LUKS partition is mounted.
	status.LUKSMounted = luksIsUnlocked(ctx, luksMapperName)

	// Try to detect binaries on the FAT32 partition.
	status.Binaries = detectBinaries(path)

	return status, nil
}

// UpdateBinaries updates xkey binaries on the FAT32 partition of an
// existing image or device.
func UpdateBinaries(ctx context.Context, path string, binaries []string) (err error) {
	if getEUID() != 0 {
		return ErrPermissionDenied
	}

	if _, statErr := statPath(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return &USBError{Operation: "update", Path: path, Err: ErrImageNotFound}
		}
		return &USBError{Operation: "stat", Path: path, Err: statErr}
	}

	isBlock := IsBlockDevice(path)
	var part1 string

	if isBlock {
		part1, _ = partitionDevices(path)
	} else {
		// For image files, set up a loop device.
		loopDev, loopErr := luksSetupLoopDevice(ctx, path)
		if loopErr != nil {
			return &USBError{Operation: "setup_loop", Path: path, Err: loopErr}
		}
		defer func() {
			if detachErr := luksDetachLoopDevice(ctx, loopDev); detachErr != nil {
				err = errors.Join(err, &USBError{Operation: "detach_loop", Path: loopDev, Err: detachErr})
			}
		}()

		// Re-read partition table on loop device.
		if partprobeErr := execCommand("partprobe", loopDev); partprobeErr != nil {
			slog.Warn("partprobe failed on loop device", "device", loopDev, "error", partprobeErr)
		}
		part1, _ = partitionDevices(loopDev)
	}

	// Mount, copy binaries, unmount.
	mountDir, err := os.MkdirTemp("", "xkey-update-")
	if err != nil {
		return &USBError{Operation: "create_mount_dir", Err: err}
	}
	defer func() {
		if removeErr := os.RemoveAll(mountDir); removeErr != nil {
			slog.Warn("failed to remove temp mount dir", "path", mountDir, "error", removeErr)
		}
	}()

	if err := execCommand("mount", "-t", "vfat", part1, mountDir); err != nil {
		return &USBError{
			Operation: "mount_fat32",
			Path:      part1,
			Err:       &SentinelCauseError{Sentinel: ErrMountFailed, Cause: err},
		}
	}
	defer func() {
		if umountErr := execCommand("umount", mountDir); umountErr != nil {
			slog.Warn("failed to unmount FAT32", "path", mountDir, "error", umountErr)
		}
	}()

	for _, binPath := range binaries {
		if err := copyBinary(binPath, mountDir); err != nil {
			return err
		}
	}

	// Update the launcher script in case it has changed.
	launcherPath := filepath.Join(mountDir, "xkey.sh")
	if err := os.WriteFile(launcherPath, []byte(GenerateLauncher()), 0755); err != nil {
		return &USBError{Operation: "update_launcher", Path: launcherPath, Err: err}
	}

	return nil
}

// partitionDevices returns the device paths for partition 1 and
// partition 2 given a base device path. Handles both /dev/sdX and
// /dev/loopN naming conventions.
func partitionDevices(device string) (string, string) {
	base := filepath.Base(device)
	// Loop devices and NVMe use a "p" separator (e.g., /dev/loop0p1).
	if strings.HasPrefix(base, "loop") || strings.HasPrefix(base, "nvme") {
		return device + "p1", device + "p2"
	}
	// Standard disk devices (e.g., /dev/sdb1, /dev/sdb2).
	return device + "1", device + "2"
}

// detectBinaries scans the FAT32 partition of an image for xkey binaries.
// This is best-effort and returns nil on any error.
func detectBinaries(path string) []string {
	// For block devices, we would need to mount, which requires root.
	// For image files, we can use a loop device. This is best-effort only.

	if IsBlockDevice(path) {
		part1, _ := partitionDevices(path)
		return scanMountedBinaries(part1)
	}

	// For files, try to find a loop device already attached.
	return nil
}

// scanMountedBinaries checks if a partition is mounted somewhere and
// looks for xkey binaries. This is best-effort.
func scanMountedBinaries(partition string) []string {
	data, err := readMountsFile()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == partition {
			return findXKeyBinaries(fields[1])
		}
	}
	return nil
}

// findXKeyBinaries scans a directory for files matching the xkey
// binary naming pattern.
func findXKeyBinaries(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var binaries []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "xkey-") || name == "xkey" {
			binaries = append(binaries, name)
		}
	}
	return binaries
}

// runCommand executes a command and returns an error if it fails.
// This delegates to the execCommand hook for testability.
func runCommand(name string, args ...string) error {
	return execCommand(name, args...)
}
