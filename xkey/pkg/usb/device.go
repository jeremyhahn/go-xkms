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
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// USBDevice represents a detected USB mass storage device.
type USBDevice struct {
	Path   string // Block device path (e.g., /dev/sdb)
	Model  string // Device model name
	Size   int64  // Size in bytes
	Vendor string // Device vendor name
}

// IsBlockDevice returns true if the path is a block device.
func IsBlockDevice(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeDevice != 0
}

// ValidateBlockDevice checks if a block device is safe to write to.
// It returns an error if the device appears to be a system disk
// (mounted as /, /boot, /home, or contains active partitions mounted
// at critical paths).
func ValidateBlockDevice(path string) error {
	if !IsBlockDevice(path) {
		return &USBError{
			Operation: "validate",
			Path:      path,
			Err:       ErrDeviceNotFound,
		}
	}

	// Read /proc/mounts to find mounted partitions.
	data, err := readMountsFile()
	if err != nil {
		return &USBError{
			Operation: "read_mounts",
			Path:      "/proc/mounts",
			Err:       err,
		}
	}

	// Resolve symlinks for the target device so comparisons are reliable.
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolvedPath = path
	}

	baseDev := filepath.Base(resolvedPath)
	criticalMounts := []string{"/", "/boot", "/boot/efi", "/home", "/var", "/usr", "/tmp"}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		mountDev := fields[0]
		mountPoint := fields[1]

		// Check if the mounted device is a partition of our target device.
		// For example, if path is /dev/sdb, check for /dev/sdb1, /dev/sdb2, etc.
		mountBase := filepath.Base(mountDev)
		if !strings.HasPrefix(mountBase, baseDev) {
			continue
		}

		for _, critical := range criticalMounts {
			if mountPoint == critical {
				return &USBError{
					Operation: "validate",
					Path:      path,
					Err:       ErrSystemDisk,
				}
			}
		}
	}

	return nil
}

// DetectUSBDevices returns a list of USB mass storage devices by
// scanning /sys/block for removable devices with a USB transport.
func DetectUSBDevices() ([]USBDevice, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, &USBError{
			Operation: "scan_devices",
			Path:      "/sys/block",
			Err:       err,
		}
	}

	var devices []USBDevice
	for _, entry := range entries {
		name := entry.Name()
		sysPath := filepath.Join("/sys/block", name)

		// Skip non-removable devices.
		if !isRemovable(sysPath) {
			continue
		}

		// Verify it is a USB device by checking the device path for "usb".
		deviceLink, err := filepath.EvalSymlinks(filepath.Join(sysPath, "device"))
		if err != nil {
			continue
		}
		if !strings.Contains(deviceLink, "usb") {
			continue
		}

		dev := USBDevice{
			Path:   filepath.Join("/dev", name),
			Model:  readSysAttr(sysPath, "device/model"),
			Vendor: readSysAttr(sysPath, "device/vendor"),
			Size:   readBlockSize(sysPath),
		}
		devices = append(devices, dev)
	}

	return devices, nil
}

// BlockDeviceSize returns the size in bytes of a block device by
// reading /sys/block/<dev>/size. Falls back to os.Stat for regular
// files.
func BlockDeviceSize(path string) (int64, error) {
	// For block devices, read size from sysfs.
	devName := filepath.Base(path)
	sysPath := filepath.Join("/sys/block", devName)
	if size := readBlockSize(sysPath); size > 0 {
		return size, nil
	}

	// Fallback: use stat for regular files or partitions.
	info, err := os.Stat(path)
	if err != nil {
		return 0, &USBError{Operation: "get_size", Path: path, Err: err}
	}
	return info.Size(), nil
}

// isRemovable checks if a block device is removable by reading
// /sys/block/<dev>/removable.
func isRemovable(sysPath string) bool {
	data, err := os.ReadFile(filepath.Join(sysPath, "removable"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// readSysAttr reads a sysfs attribute file and returns the trimmed content.
func readSysAttr(sysPath, attr string) string {
	data, err := os.ReadFile(filepath.Join(sysPath, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readBlockSize reads the block device size in bytes from sysfs.
// The "size" file reports the number of 512-byte sectors.
func readBlockSize(sysPath string) int64 {
	data, err := os.ReadFile(filepath.Join(sysPath, "size"))
	if err != nil {
		return 0
	}
	sectors, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return sectors * 512
}
