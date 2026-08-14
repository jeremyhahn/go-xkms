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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// IsBlockDevice tests
// ---------------------------------------------------------------------------

func TestIsBlockDevice_RegularFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-block-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	assert.False(t, IsBlockDevice(tmpFile.Name()),
		"regular file should not be a block device")
}

func TestIsBlockDevice_NonExistent(t *testing.T) {
	assert.False(t, IsBlockDevice("/nonexistent/path/device"),
		"non-existent path should not be a block device")
}

func TestIsBlockDevice_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	assert.False(t, IsBlockDevice(tmpDir),
		"directory should not be a block device")
}

func TestIsBlockDevice_DeviceNode(t *testing.T) {
	// IsBlockDevice checks os.ModeDevice, which is set for both block and
	// character device nodes. Drive it through the statPath seam so the
	// assertion is exact and does not depend on any host device existing.
	restore := saveHooks(t)
	defer restore()

	mockDeviceNode(testDevicePath)

	assert.True(t, IsBlockDevice(testDevicePath),
		"a device node must be reported as a block device")
	assert.False(t, IsBlockDevice("/dev/some-other-node"),
		"a path that does not stat must not be reported as a block device")
}

// ---------------------------------------------------------------------------
// ValidateBlockDevice tests
// ---------------------------------------------------------------------------

func TestValidateBlockDevice_NonExistent(t *testing.T) {
	err := ValidateBlockDevice("/nonexistent/device")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceNotFound))
}

func TestValidateBlockDevice_RegularFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-validate-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = ValidateBlockDevice(tmpFile.Name())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceNotFound))
}

// TestValidateBlockDevice_DevNull_NoSystemMounts verifies that
// ValidateBlockDevice succeeds when the device has no critical mounts.
// The device node is synthesized through the statPath seam.
func TestValidateBlockDevice_Device_NoSystemMounts(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	mockDeviceNode(testDevicePath)

	// Provide mount data that does NOT reference /dev/null on critical paths.
	readMountsFile = func() ([]byte, error) {
		return []byte("/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /home ext4 rw 0 0\n"), nil
	}

	err := ValidateBlockDevice(testDevicePath)
	assert.NoError(t, err)
}

// TestValidateBlockDevice_DevNull_SystemDiskDetected verifies that
// ValidateBlockDevice detects a device mounted at a critical path.
func TestValidateBlockDevice_Device_SystemDiskDetected(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	mockDeviceNode(testDevicePath)

	// The basename of /dev/null is "null". Mount data shows "null1" on /.
	readMountsFile = func() ([]byte, error) {
		return []byte(testDevicePath + "1 / ext4 rw 0 0\n"), nil
	}

	err := ValidateBlockDevice(testDevicePath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSystemDisk))
}

// TestValidateBlockDevice_DevNull_MountsReadError verifies that
// ValidateBlockDevice returns an error when mounts cannot be read.
func TestValidateBlockDevice_Device_MountsReadError(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	mockDeviceNode(testDevicePath)

	readMountsFile = func() ([]byte, error) {
		return nil, errors.New("permission denied")
	}

	err := ValidateBlockDevice(testDevicePath)
	require.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "read_mounts", usbErr.Operation)
}

// TestValidateBlockDevice_DevNull_NonCriticalMount verifies that a
// device partition mounted at a non-critical path passes validation.
func TestValidateBlockDevice_Device_NonCriticalMount(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	mockDeviceNode(testDevicePath)

	// "null1" is mounted at /mnt/usb which is NOT a critical mount.
	readMountsFile = func() ([]byte, error) {
		return []byte(testDevicePath + "1 /mnt/usb vfat rw 0 0\n"), nil
	}

	err := ValidateBlockDevice(testDevicePath)
	assert.NoError(t, err)
}

// TestValidateBlockDevice_DevNull_MultipleCriticalMounts tests all
// critical mount points for detection.
func TestValidateBlockDevice_Device_MultipleCriticalMounts(t *testing.T) {
	criticalPaths := []string{"/", "/boot", "/boot/efi", "/home", "/var", "/usr", "/tmp"}

	for _, critical := range criticalPaths {
		t.Run(critical, func(t *testing.T) {
			restore := saveHooks(t)
			defer restore()

			mockDeviceNode(testDevicePath)

			readMountsFile = func() ([]byte, error) {
				return []byte(testDevicePath + "1 " + critical + " ext4 rw 0 0\n"), nil
			}

			err := ValidateBlockDevice(testDevicePath)
			require.Error(t, err, "should detect system disk for mount at %s", critical)
			assert.True(t, errors.Is(err, ErrSystemDisk))
		})
	}
}

// TestValidateBlockDevice_DevNull_EmptyMounts verifies that empty
// mount data passes validation (no critical mounts found).
func TestValidateBlockDevice_Device_EmptyMounts(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	mockDeviceNode(testDevicePath)

	readMountsFile = func() ([]byte, error) {
		return []byte(""), nil
	}

	err := ValidateBlockDevice(testDevicePath)
	assert.NoError(t, err)
}

// TestValidateBlockDevice_DevNull_ShortLines verifies that lines
// with fewer than 2 fields are skipped.
func TestValidateBlockDevice_Device_ShortLines(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	mockDeviceNode(testDevicePath)

	readMountsFile = func() ([]byte, error) {
		return []byte("onlyonefield\n\n" + testDevicePath + "1\n"), nil
	}

	err := ValidateBlockDevice(testDevicePath)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// DetectUSBDevices tests
// ---------------------------------------------------------------------------

func TestDetectUSBDevices_RunsWithoutError(t *testing.T) {
	devices, err := DetectUSBDevices()
	if err != nil {
		var usbErr *USBError
		if errors.As(err, &usbErr) {
			assert.Equal(t, "scan_devices", usbErr.Operation)
		}
		return
	}
	for _, dev := range devices {
		assert.NotEmpty(t, dev.Path)
	}
}

// ---------------------------------------------------------------------------
// BlockDeviceSize tests
// ---------------------------------------------------------------------------

func TestBlockDeviceSize_RegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.img")

	f, err := os.Create(filePath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(100*MB))
	f.Close()

	size, err := BlockDeviceSize(filePath)
	require.NoError(t, err)
	assert.Equal(t, 100*MB, size)
}

func TestBlockDeviceSize_NonExistent(t *testing.T) {
	_, err := BlockDeviceSize("/nonexistent/device")
	assert.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "get_size", usbErr.Operation)
}

func TestBlockDeviceSize_ZeroSizeFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "empty.img")
	require.NoError(t, os.WriteFile(filePath, nil, 0600))

	size, err := BlockDeviceSize(filePath)
	require.NoError(t, err)
	assert.Equal(t, int64(0), size)
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestIsRemovable_NonExistent(t *testing.T) {
	assert.False(t, isRemovable("/nonexistent/sys/path"))
}

func TestIsRemovable_WithFile(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "removable"), []byte("1\n"), 0644))
	assert.True(t, isRemovable(tmpDir))
}

func TestIsRemovable_NotRemovable(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "removable"), []byte("0\n"), 0644))
	assert.False(t, isRemovable(tmpDir))
}

func TestReadSysAttr_NonExistent(t *testing.T) {
	result := readSysAttr("/nonexistent/sys/path", "model")
	assert.Empty(t, result)
}

func TestReadSysAttr_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	attrDir := filepath.Join(tmpDir, "device")
	require.NoError(t, os.MkdirAll(attrDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(attrDir, "model"), []byte("  USB Flash Drive  \n"), 0644))

	result := readSysAttr(tmpDir, "device/model")
	assert.Equal(t, "USB Flash Drive", result)
}

func TestReadBlockSize_NonExistent(t *testing.T) {
	result := readBlockSize("/nonexistent/sys/path")
	assert.Equal(t, int64(0), result)
}

func TestReadBlockSize_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "size"), []byte("1000\n"), 0644))

	result := readBlockSize(tmpDir)
	assert.Equal(t, int64(512000), result)
}

func TestReadBlockSize_InvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "size"), []byte("not-a-number\n"), 0644))

	result := readBlockSize(tmpDir)
	assert.Equal(t, int64(0), result)
}

func TestReadBlockSize_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "size"), []byte(""), 0644))

	result := readBlockSize(tmpDir)
	assert.Equal(t, int64(0), result)
}

func TestScanMountedBinaries_NoMatchFromDevice(t *testing.T) {
	result := scanMountedBinaries("/dev/nonexistent99")
	assert.Nil(t, result)
}

func TestUSBDevice_Struct(t *testing.T) {
	dev := USBDevice{
		Path:   "/dev/sdb",
		Model:  "USB Flash Drive",
		Size:   4 * GB,
		Vendor: "SanDisk",
	}
	assert.Equal(t, "/dev/sdb", dev.Path)
	assert.Equal(t, "USB Flash Drive", dev.Model)
	assert.Equal(t, 4*GB, dev.Size)
	assert.Equal(t, "SanDisk", dev.Vendor)
}
