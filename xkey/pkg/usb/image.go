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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

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

	// Passphrase is the LUKS passphrase for the data partition.
	Passphrase string

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
func CreateImage(cfg ImageConfig) error {
	if getEUID() != 0 {
		return ErrPermissionDenied
	}

	if cfg.Passphrase == "" {
		return &USBError{
			Operation: "validate_config",
			Err:       fmt.Errorf("%w: passphrase is required", ErrInvalidSize),
		}
	}

	isBlock := IsBlockDevice(cfg.Path)

	if isBlock {
		if err := ValidateBlockDevice(cfg.Path); err != nil {
			return err
		}
		return createOnBlockDevice(cfg)
	}

	return createOnImageFile(cfg)
}

// createOnImageFile creates a sparse image file and partitions it.
func createOnImageFile(cfg ImageConfig) error {
	if cfg.SizeBytes < MinImageSize {
		return &USBError{
			Operation: "validate_size",
			Path:      cfg.Path,
			Err:       fmt.Errorf("%w: minimum size is %s, got %s", ErrInvalidSize, FormatSize(MinImageSize), FormatSize(cfg.SizeBytes)),
		}
	}

	// Check if file already exists.
	if _, err := os.Stat(cfg.Path); err == nil {
		return &USBError{
			Operation: "check_existing",
			Path:      cfg.Path,
			Err:       ErrImageExists,
		}
	}

	// Create parent directory.
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &USBError{Operation: "create_dir", Path: dir, Err: err}
	}

	// Create sparse file.
	f, err := os.Create(cfg.Path)
	if err != nil {
		return &USBError{Operation: "create_file", Path: cfg.Path, Err: err}
	}
	if err := f.Truncate(cfg.SizeBytes); err != nil {
		f.Close()
		os.Remove(cfg.Path)
		return &USBError{Operation: "truncate", Path: cfg.Path, Err: err}
	}
	f.Close()

	// Set up loop device.
	loopDev, err := luksSetupLoopDevice(cfg.Path)
	if err != nil {
		os.Remove(cfg.Path)
		return &USBError{Operation: "setup_loop", Path: cfg.Path, Err: err}
	}

	slog.Info("loop device attached", "device", loopDev, "image", cfg.Path)

	if err := partitionAndFormat(loopDev, cfg); err != nil {
		luksDetachLoopDevice(loopDev)
		os.Remove(cfg.Path)
		return err
	}

	if err := luksDetachLoopDevice(loopDev); err != nil {
		slog.Warn("failed to detach loop device", "device", loopDev, "error", err)
	}

	return nil
}

// createOnBlockDevice partitions and formats a block device directly.
func createOnBlockDevice(cfg ImageConfig) error {
	return partitionAndFormat(cfg.Path, cfg)
}

// partitionAndFormat creates the GPT partition table, formats both
// partitions, and populates the FAT32 partition with binaries.
func partitionAndFormat(device string, cfg ImageConfig) error {
	// Step 1: Create GPT partition table with sgdisk.
	if err := createPartitionTable(device); err != nil {
		return err
	}

	// Determine partition device names.
	part1, part2 := partitionDevices(device)

	// Ensure the kernel re-reads the partition table.
	if err := execCommand("partprobe", device); err != nil {
		slog.Warn("partprobe failed, trying partx", "error", err)
		_ = execCommand("partx", "-u", device)
	}

	// Step 2: Format partition 1 as FAT32.
	if err := formatFAT32(part1); err != nil {
		return err
	}

	// Step 3: Format partition 2 as LUKS2.
	if err := formatLUKS(part2, cfg.Passphrase); err != nil {
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
			Err:       fmt.Errorf("%w: %v", ErrPartitionFailed, err),
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
			Err:       fmt.Errorf("%w: %v", ErrPartitionFailed, err),
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
			Err:       fmt.Errorf("%w: %v", ErrPartitionFailed, err),
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
			Err:       fmt.Errorf("%w: %v", ErrFormatFailed, err),
		}
	}
	return nil
}

// formatLUKS formats a partition as LUKS2 using the go-luks2 library.
func formatLUKS(partition, passphrase string) error {
	opts := luks2.FormatOptions{
		Device:     partition,
		Passphrase: []byte(passphrase),
	}
	if err := luksFormat(opts); err != nil {
		return &USBError{
			Operation: "format_luks",
			Path:      partition,
			Err:       fmt.Errorf("%w: %v", ErrFormatFailed, err),
		}
	}

	// Unlock, create ext4 filesystem, then lock.
	if err := luksUnlock(partition, []byte(passphrase), luksMapperName); err != nil {
		return &USBError{
			Operation: "unlock_luks",
			Path:      partition,
			Err:       err,
		}
	}

	if err := luksMakeFilesystem(luksMapperName, "ext4", luksLabel); err != nil {
		luksLock(luksMapperName)
		return &USBError{
			Operation: "create_ext4",
			Path:      partition,
			Err:       fmt.Errorf("%w: %v", ErrFormatFailed, err),
		}
	}

	if err := luksLock(luksMapperName); err != nil {
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
	defer os.RemoveAll(mountDir)

	// Mount the FAT32 partition.
	if err := execCommand("mount", "-t", "vfat", partition, mountDir); err != nil {
		return &USBError{
			Operation: "mount_fat32",
			Path:      partition,
			Err:       fmt.Errorf("%w: %v", ErrMountFailed, err),
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
func copyBinary(srcPath, dstDir string) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return &USBError{
			Operation: "stat_binary",
			Path:      srcPath,
			Err:       fmt.Errorf("%w: %v", ErrBinaryNotFound, err),
		}
	}
	if info.IsDir() {
		return &USBError{
			Operation: "validate_binary",
			Path:      srcPath,
			Err:       fmt.Errorf("%w: path is a directory", ErrBinaryNotFound),
		}
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return &USBError{Operation: "open_binary", Path: srcPath, Err: err}
	}
	defer src.Close()

	dstPath := filepath.Join(dstDir, filepath.Base(srcPath))
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return &USBError{Operation: "create_dest", Path: dstPath, Err: err}
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return &USBError{
			Operation: "copy_binary",
			Path:      srcPath,
			Err:       fmt.Errorf("%w: %v", ErrCopyFailed, err),
		}
	}

	return nil
}

// Status returns the status of an existing image or block device.
func Status(path string) (*ImageStatus, error) {
	info, err := os.Stat(path)
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
	status.LUKSMounted = luksIsUnlocked(luksMapperName)

	// Try to detect binaries on the FAT32 partition.
	status.Binaries = detectBinaries(path)

	return status, nil
}

// UpdateBinaries updates xkey binaries on the FAT32 partition of an
// existing image or device.
func UpdateBinaries(path string, binaries []string) error {
	if getEUID() != 0 {
		return ErrPermissionDenied
	}

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return &USBError{Operation: "update", Path: path, Err: ErrImageNotFound}
		}
		return &USBError{Operation: "stat", Path: path, Err: err}
	}

	isBlock := IsBlockDevice(path)
	var part1 string

	if isBlock {
		part1, _ = partitionDevices(path)
	} else {
		// For image files, set up a loop device.
		loopDev, err := luksSetupLoopDevice(path)
		if err != nil {
			return &USBError{Operation: "setup_loop", Path: path, Err: err}
		}
		defer luksDetachLoopDevice(loopDev)

		// Re-read partition table on loop device.
		_ = execCommand("partprobe", loopDev)
		part1, _ = partitionDevices(loopDev)
	}

	// Mount, copy binaries, unmount.
	mountDir, err := os.MkdirTemp("", "xkey-update-")
	if err != nil {
		return &USBError{Operation: "create_mount_dir", Err: err}
	}
	defer os.RemoveAll(mountDir)

	if err := execCommand("mount", "-t", "vfat", part1, mountDir); err != nil {
		return &USBError{
			Operation: "mount_fat32",
			Path:      part1,
			Err:       fmt.Errorf("%w: %v", ErrMountFailed, err),
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
