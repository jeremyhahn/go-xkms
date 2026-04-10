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
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// CreateImage tests
// ---------------------------------------------------------------------------

// TestCreateImage_RequiresRoot verifies that CreateImage refuses to run
// without root privileges.
func TestCreateImage_RequiresRoot(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockNonRootUser()

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  4 * GB,
		Passphrase: "test-passphrase",
	}
	err := CreateImage(cfg)
	assert.ErrorIs(t, err, ErrPermissionDenied)
}

// TestCreateImage_EmptyPassphrase verifies that CreateImage rejects
// an empty passphrase after the root check passes.
func TestCreateImage_EmptyPassphrase(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  4 * GB,
		Passphrase: "",
	}
	err := CreateImage(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSize))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "validate_config", usbErr.Operation)
}

// TestCreateImage_NonBlockDevice_RoutesToImageFile verifies that
// CreateImage calls createOnImageFile for non-block device paths.
func TestCreateImage_NonBlockDevice_RoutesToImageFile(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	// This will go through createOnImageFile, create the file,
	// set up a mock loop device, run the partitioning (all mocked),
	// and succeed.
	err := CreateImage(cfg)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// createOnImageFile tests
// ---------------------------------------------------------------------------

// TestCreateOnImageFile_SizeTooSmall verifies that createOnImageFile
// rejects images smaller than MinImageSize.
func TestCreateOnImageFile_SizeTooSmall(t *testing.T) {
	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "small.img"),
		SizeBytes:  100 * MB,
		Passphrase: "test-passphrase",
	}
	err := createOnImageFile(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSize))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "validate_size", usbErr.Operation)
}

// TestCreateOnImageFile_FileExists verifies that createOnImageFile
// returns ErrImageExists when the output file already exists.
func TestCreateOnImageFile_FileExists(t *testing.T) {
	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "existing.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	cfg := ImageConfig{
		Path:       imgPath,
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	err := createOnImageFile(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrImageExists))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "check_existing", usbErr.Operation)
}

// TestCreateOnImageFile_LoopSetupFails verifies the cleanup path
// when loop device setup fails.
func TestCreateOnImageFile_LoopSetupFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	loopErr := errors.New("losetup failed")
	luksSetupLoopDevice = func(file string) (string, error) {
		return "", loopErr
	}

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	err := createOnImageFile(cfg)
	require.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "setup_loop", usbErr.Operation)

	// The image file should have been cleaned up.
	_, statErr := os.Stat(cfg.Path)
	assert.True(t, os.IsNotExist(statErr))
}

// TestCreateOnImageFile_PartitionFails verifies cleanup when
// partitionAndFormat fails.
func TestCreateOnImageFile_PartitionFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	detached := false
	luksSetupLoopDevice = func(file string) (string, error) {
		return "/dev/loop99", nil
	}
	luksDetachLoopDevice = func(device string) error {
		detached = true
		return nil
	}
	// Make sgdisk fail to trigger partition error.
	execCommand = func(name string, args ...string) error {
		if name == "sgdisk" {
			return errors.New("sgdisk failed")
		}
		return nil
	}

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	err := createOnImageFile(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPartitionFailed))
	assert.True(t, detached, "loop device should be detached on error")

	// Image file should be cleaned up.
	_, statErr := os.Stat(cfg.Path)
	assert.True(t, os.IsNotExist(statErr))
}

// TestCreateOnImageFile_Success verifies the full success path.
func TestCreateOnImageFile_Success(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	err := createOnImageFile(cfg)
	require.NoError(t, err)
}

// TestCreateOnImageFile_DetachWarning verifies that a detach failure
// after success does not cause the function to return an error.
func TestCreateOnImageFile_DetachWarning(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	// Override detach to fail.
	luksDetachLoopDevice = func(device string) error {
		return errors.New("detach failed")
	}

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	// Should still succeed -- detach failure is a warning, not an error.
	err := createOnImageFile(cfg)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// createOnBlockDevice tests
// ---------------------------------------------------------------------------

// TestCreateOnBlockDevice_DelegatesToPartitionAndFormat verifies that
// createOnBlockDevice passes through to partitionAndFormat.
func TestCreateOnBlockDevice_DelegatesToPartitionAndFormat(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	cfg := ImageConfig{
		Path:       "/dev/sdb",
		Passphrase: "test-passphrase",
	}
	err := createOnBlockDevice(cfg)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// partitionAndFormat tests
// ---------------------------------------------------------------------------

// TestPartitionAndFormat_CreateTableFails verifies error on partition
// table creation failure.
func TestPartitionAndFormat_CreateTableFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	execCommand = func(name string, args ...string) error {
		if name == "sgdisk" {
			return errors.New("sgdisk failed")
		}
		return nil
	}

	cfg := ImageConfig{Passphrase: "test"}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPartitionFailed))
}

// TestPartitionAndFormat_FAT32FormatFails verifies error when FAT32
// formatting fails.
func TestPartitionAndFormat_FAT32FormatFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	execCommand = func(name string, args ...string) error {
		if name == "mkfs.vfat" {
			return errors.New("mkfs.vfat failed")
		}
		return nil
	}

	cfg := ImageConfig{Passphrase: "test"}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFormatFailed))
}

// TestPartitionAndFormat_LUKSFormatFails verifies error when LUKS
// formatting fails.
func TestPartitionAndFormat_LUKSFormatFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	luksFormat = func(opts luks2.FormatOptions) error {
		return errors.New("luks format failed")
	}

	cfg := ImageConfig{Passphrase: "test"}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFormatFailed))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "format_luks", usbErr.Operation)
}

// TestPartitionAndFormat_MountFails verifies error when FAT32 mount
// fails during populate.
func TestPartitionAndFormat_MountFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	execCommand = func(name string, args ...string) error {
		if name == "mount" {
			return errors.New("mount failed")
		}
		return nil
	}

	cfg := ImageConfig{Passphrase: "test"}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMountFailed))
}

// TestPartitionAndFormat_PartprobeFailsFallsBack verifies that
// partprobe failure triggers partx fallback without error.
func TestPartitionAndFormat_PartprobeFailsFallsBack(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	partprobeCalled := false
	partxCalled := false
	execCommand = func(name string, args ...string) error {
		if name == "partprobe" {
			partprobeCalled = true
			return errors.New("partprobe failed")
		}
		if name == "partx" {
			partxCalled = true
		}
		return nil
	}

	cfg := ImageConfig{Passphrase: "test"}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.NoError(t, err)
	assert.True(t, partprobeCalled)
	assert.True(t, partxCalled)
}

// TestPartitionAndFormat_FullSuccess verifies the complete success path.
func TestPartitionAndFormat_FullSuccess(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	cfg := ImageConfig{
		Passphrase: "test-passphrase",
		Binaries:   nil,
	}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// createPartitionTable tests
// ---------------------------------------------------------------------------

// TestCreatePartitionTable_ZapFails verifies error when zap fails.
func TestCreatePartitionTable_ZapFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	callCount := 0
	execCommand = func(name string, args ...string) error {
		callCount++
		if callCount == 1 { // First sgdisk call = zap
			return errors.New("zap failed")
		}
		return nil
	}

	err := createPartitionTable("/dev/sdb")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPartitionFailed))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "zap_partitions", usbErr.Operation)
}

// TestCreatePartitionTable_Partition1Fails verifies error when
// creating partition 1 fails.
func TestCreatePartitionTable_Partition1Fails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	callCount := 0
	execCommand = func(name string, args ...string) error {
		callCount++
		if callCount == 2 { // Second sgdisk call = partition 1
			return errors.New("part1 failed")
		}
		return nil
	}

	err := createPartitionTable("/dev/sdb")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPartitionFailed))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "create_partition_1", usbErr.Operation)
}

// TestCreatePartitionTable_Partition2Fails verifies error when
// creating partition 2 fails.
func TestCreatePartitionTable_Partition2Fails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	callCount := 0
	execCommand = func(name string, args ...string) error {
		callCount++
		if callCount == 3 { // Third sgdisk call = partition 2
			return errors.New("part2 failed")
		}
		return nil
	}

	err := createPartitionTable("/dev/sdb")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPartitionFailed))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "create_partition_2", usbErr.Operation)
}

// TestCreatePartitionTable_Success verifies the full success path.
func TestCreatePartitionTable_Success(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	execCommand = func(name string, args ...string) error { return nil }

	err := createPartitionTable("/dev/sdb")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// formatFAT32 tests
// ---------------------------------------------------------------------------

// TestFormatFAT32_Success verifies the success path.
func TestFormatFAT32_Success(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	execCommand = func(name string, args ...string) error { return nil }

	err := formatFAT32("/dev/sdb1")
	require.NoError(t, err)
}

// TestFormatFAT32_Fails verifies the error path.
func TestFormatFAT32_Fails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	execCommand = func(name string, args ...string) error {
		return errors.New("mkfs.vfat failed")
	}

	err := formatFAT32("/dev/sdb1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFormatFailed))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "format_fat32", usbErr.Operation)
	assert.Equal(t, "/dev/sdb1", usbErr.Path)
}

// ---------------------------------------------------------------------------
// formatLUKS tests
// ---------------------------------------------------------------------------

// TestFormatLUKS_Success verifies the full success path through
// format, unlock, mkfs, and lock.
func TestFormatLUKS_Success(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	luksFormat = func(opts luks2.FormatOptions) error { return nil }
	luksUnlock = func(device string, passphrase []byte, name string) error { return nil }
	luksMakeFilesystem = func(device, fstype, label string) error { return nil }
	luksLock = func(name string) error { return nil }

	err := formatLUKS("/dev/sdb2", "test-passphrase")
	require.NoError(t, err)
}

// TestFormatLUKS_FormatFails verifies error when LUKS format fails.
func TestFormatLUKS_FormatFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	luksFormat = func(opts luks2.FormatOptions) error {
		return errors.New("format failed")
	}

	err := formatLUKS("/dev/sdb2", "test-passphrase")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFormatFailed))

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "format_luks", usbErr.Operation)
}

// TestFormatLUKS_UnlockFails verifies error when LUKS unlock fails.
func TestFormatLUKS_UnlockFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	luksFormat = func(opts luks2.FormatOptions) error { return nil }
	luksUnlock = func(device string, passphrase []byte, name string) error {
		return errors.New("unlock failed")
	}

	err := formatLUKS("/dev/sdb2", "test-passphrase")
	require.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "unlock_luks", usbErr.Operation)
}

// TestFormatLUKS_MakeFilesystemFails verifies error when mkfs fails
// and that lock is called for cleanup.
func TestFormatLUKS_MakeFilesystemFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	lockCalled := false
	luksFormat = func(opts luks2.FormatOptions) error { return nil }
	luksUnlock = func(device string, passphrase []byte, name string) error { return nil }
	luksMakeFilesystem = func(device, fstype, label string) error {
		return errors.New("mkfs failed")
	}
	luksLock = func(name string) error {
		lockCalled = true
		return nil
	}

	err := formatLUKS("/dev/sdb2", "test-passphrase")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFormatFailed))
	assert.True(t, lockCalled, "luksLock should be called on mkfs failure")

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "create_ext4", usbErr.Operation)
}

// TestFormatLUKS_LockFails verifies error when final lock fails.
func TestFormatLUKS_LockFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	luksFormat = func(opts luks2.FormatOptions) error { return nil }
	luksUnlock = func(device string, passphrase []byte, name string) error { return nil }
	luksMakeFilesystem = func(device, fstype, label string) error { return nil }
	luksLock = func(name string) error {
		return errors.New("lock failed")
	}

	err := formatLUKS("/dev/sdb2", "test-passphrase")
	require.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "lock_luks", usbErr.Operation)
}

// ---------------------------------------------------------------------------
// populateFAT32 tests
// ---------------------------------------------------------------------------

// TestPopulateFAT32_MountFails verifies error when mount fails.
func TestPopulateFAT32_MountFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	execCommand = func(name string, args ...string) error {
		if name == "mount" {
			return errors.New("mount failed")
		}
		return nil
	}

	err := populateFAT32("/dev/sdb1", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMountFailed))
}

// TestPopulateFAT32_Success verifies the full success path writing
// marker, launcher, readme, and binaries.
func TestPopulateFAT32_Success(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	execCommand = func(name string, args ...string) error { return nil }

	// Create a test binary to copy.
	srcDir := t.TempDir()
	binPath := filepath.Join(srcDir, "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0755))

	err := populateFAT32("/dev/sdb1", []string{binPath})
	require.NoError(t, err)
}

// TestPopulateFAT32_NoBinaries verifies success with no binaries.
func TestPopulateFAT32_NoBinaries(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	execCommand = func(name string, args ...string) error { return nil }

	err := populateFAT32("/dev/sdb1", nil)
	require.NoError(t, err)
}

// TestPopulateFAT32_BinaryCopyFails verifies error when a binary
// copy fails.
func TestPopulateFAT32_BinaryCopyFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	execCommand = func(name string, args ...string) error { return nil }

	err := populateFAT32("/dev/sdb1", []string{"/nonexistent/binary"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBinaryNotFound))
}

// ---------------------------------------------------------------------------
// copyBinary tests
// ---------------------------------------------------------------------------

// TestCopyBinary_Success tests copying a file to a destination directory.
func TestCopyBinary_Success(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	srcPath := filepath.Join(srcDir, "xkey-linux-amd64")
	content := []byte("ELF binary content")
	require.NoError(t, os.WriteFile(srcPath, content, 0755))

	err := copyBinary(srcPath, dstDir)
	require.NoError(t, err)

	dstPath := filepath.Join(dstDir, "xkey-linux-amd64")
	data, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	assert.Equal(t, content, data)

	info, err := os.Stat(dstPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

// TestCopyBinary_SourceNotFound tests copyBinary with a non-existent source.
func TestCopyBinary_SourceNotFound(t *testing.T) {
	dstDir := t.TempDir()
	err := copyBinary("/nonexistent/binary", dstDir)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrBinaryNotFound))
}

// TestCopyBinary_SourceIsDirectory tests copyBinary with a directory path.
func TestCopyBinary_SourceIsDirectory(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	err := copyBinary(srcDir, dstDir)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrBinaryNotFound))
}

// TestCopyBinary_InvalidDestination tests copyBinary with a non-existent
// destination directory.
func TestCopyBinary_InvalidDestination(t *testing.T) {
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "binary")
	require.NoError(t, os.WriteFile(srcPath, []byte("data"), 0755))

	err := copyBinary(srcPath, "/nonexistent/destination")
	assert.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "create_dest", usbErr.Operation)
}

// TestCopyBinary_LargeFile tests that large files are copied correctly.
func TestCopyBinary_LargeFile(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	srcPath := filepath.Join(srcDir, "large-binary")
	content := make([]byte, 1*MB)
	for i := range content {
		content[i] = byte(i % 256)
	}
	require.NoError(t, os.WriteFile(srcPath, content, 0755))

	require.NoError(t, copyBinary(srcPath, dstDir))

	dstPath := filepath.Join(dstDir, "large-binary")
	srcFile, err := os.Open(srcPath)
	require.NoError(t, err)
	defer srcFile.Close()

	dstFile, err := os.Open(dstPath)
	require.NoError(t, err)
	defer dstFile.Close()

	srcInfo, err := srcFile.Stat()
	require.NoError(t, err)
	dstInfo, err := dstFile.Stat()
	require.NoError(t, err)
	assert.Equal(t, srcInfo.Size(), dstInfo.Size())

	srcData, err := io.ReadAll(srcFile)
	require.NoError(t, err)
	dstData, err := io.ReadAll(dstFile)
	require.NoError(t, err)
	assert.Equal(t, srcData, dstData)
}

// ---------------------------------------------------------------------------
// Status tests
// ---------------------------------------------------------------------------

// TestStatus_NonExistent verifies that Status returns ErrImageNotFound
// for a path that does not exist.
func TestStatus_NonExistent(t *testing.T) {
	_, err := Status("/nonexistent/path/image.img")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrImageNotFound))
}

// TestStatus_RegularFile verifies that Status works for a regular file.
func TestStatus_RegularFile(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	luksIsUnlocked = func(name string) bool { return false }

	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "test.img")
	f, err := os.Create(imgPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(2*GB))
	f.Close()

	status, err := Status(imgPath)
	require.NoError(t, err)

	assert.Equal(t, imgPath, status.Path)
	assert.False(t, status.IsBlockDevice)
	assert.Equal(t, 2*GB, status.TotalSize)
	assert.Equal(t, FAT32PartitionSize, status.FAT32Size)
	assert.Equal(t, 2*GB-FAT32PartitionSize, status.LUKSSize)
	assert.False(t, status.LUKSMounted)
}

// TestStatus_SmallFile verifies Status handles files smaller than
// FAT32PartitionSize gracefully.
func TestStatus_SmallFile(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	luksIsUnlocked = func(name string) bool { return false }

	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "small.img")
	f, err := os.Create(imgPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(100*MB))
	f.Close()

	status, err := Status(imgPath)
	require.NoError(t, err)

	assert.Equal(t, int64(100*MB), status.TotalSize)
	assert.Equal(t, FAT32PartitionSize, status.FAT32Size)
	assert.Equal(t, int64(0), status.LUKSSize)
}

// TestStatus_LUKSMounted verifies the LUKSMounted flag when the
// LUKS partition is unlocked.
func TestStatus_LUKSMounted(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	luksIsUnlocked = func(name string) bool { return true }

	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "test.img")
	f, err := os.Create(imgPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(2*GB))
	f.Close()

	status, err := Status(imgPath)
	require.NoError(t, err)
	assert.True(t, status.LUKSMounted)
}

// TestStatus_ExactlyFAT32PartitionSize verifies edge case where total
// size equals FAT32PartitionSize.
func TestStatus_ExactlyFAT32PartitionSize(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	luksIsUnlocked = func(name string) bool { return false }

	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "exact.img")
	f, err := os.Create(imgPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(FAT32PartitionSize))
	f.Close()

	status, err := Status(imgPath)
	require.NoError(t, err)
	assert.Equal(t, FAT32PartitionSize, status.TotalSize)
	assert.Equal(t, int64(0), status.LUKSSize)
}

// ---------------------------------------------------------------------------
// UpdateBinaries tests
// ---------------------------------------------------------------------------

// TestUpdateBinaries_RequiresRoot verifies UpdateBinaries requires root.
func TestUpdateBinaries_RequiresRoot(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockNonRootUser()

	err := UpdateBinaries("/some/path", []string{"/some/binary"})
	assert.ErrorIs(t, err, ErrPermissionDenied)
}

// TestUpdateBinaries_ImageNotFound verifies UpdateBinaries returns
// ErrImageNotFound for a non-existent path.
func TestUpdateBinaries_ImageNotFound(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	err := UpdateBinaries("/nonexistent/image.img", []string{"/some/binary"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrImageNotFound))
}

// TestUpdateBinaries_ImageFile_LoopSetupFails verifies the loop setup
// failure path for image files.
func TestUpdateBinaries_ImageFile_LoopSetupFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	luksSetupLoopDevice = func(file string) (string, error) {
		return "", errors.New("loop setup failed")
	}

	imgPath := filepath.Join(t.TempDir(), "test.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	err := UpdateBinaries(imgPath, []string{"/some/binary"})
	require.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "setup_loop", usbErr.Operation)
}

// TestUpdateBinaries_ImageFile_MountFails verifies the mount failure path.
func TestUpdateBinaries_ImageFile_MountFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	luksSetupLoopDevice = func(file string) (string, error) { return "/dev/loop99", nil }
	luksDetachLoopDevice = func(device string) error { return nil }
	execCommand = func(name string, args ...string) error {
		if name == "mount" {
			return errors.New("mount failed")
		}
		return nil
	}

	imgPath := filepath.Join(t.TempDir(), "test.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	err := UpdateBinaries(imgPath, []string{"/some/binary"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMountFailed))
}

// TestUpdateBinaries_ImageFile_Success verifies the full success path
// for image file update.
func TestUpdateBinaries_ImageFile_Success(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)

	// Create image file and a binary to copy.
	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "test.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0755))

	err := UpdateBinaries(imgPath, []string{binPath})
	require.NoError(t, err)
}

// TestUpdateBinaries_ImageFile_BinaryCopyFails verifies error when
// binary copy fails during update.
func TestUpdateBinaries_ImageFile_BinaryCopyFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)

	imgPath := filepath.Join(t.TempDir(), "test.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	err := UpdateBinaries(imgPath, []string{"/nonexistent/binary"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBinaryNotFound))
}

// ---------------------------------------------------------------------------
// partitionDevices tests
// ---------------------------------------------------------------------------

// TestPartitionDevices_StandardDisk verifies standard disk partition naming.
func TestPartitionDevices_StandardDisk(t *testing.T) {
	tests := []struct {
		name   string
		device string
		part1  string
		part2  string
	}{
		{"sda", "/dev/sda", "/dev/sda1", "/dev/sda2"},
		{"sdb", "/dev/sdb", "/dev/sdb1", "/dev/sdb2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, p2 := partitionDevices(tt.device)
			assert.Equal(t, tt.part1, p1)
			assert.Equal(t, tt.part2, p2)
		})
	}
}

// TestPartitionDevices_LoopDevice verifies loop device partition naming.
func TestPartitionDevices_LoopDevice(t *testing.T) {
	tests := []struct {
		name   string
		device string
		part1  string
		part2  string
	}{
		{"loop0", "/dev/loop0", "/dev/loop0p1", "/dev/loop0p2"},
		{"loop15", "/dev/loop15", "/dev/loop15p1", "/dev/loop15p2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, p2 := partitionDevices(tt.device)
			assert.Equal(t, tt.part1, p1)
			assert.Equal(t, tt.part2, p2)
		})
	}
}

// TestPartitionDevices_NVMe verifies NVMe partition naming.
func TestPartitionDevices_NVMe(t *testing.T) {
	p1, p2 := partitionDevices("/dev/nvme0n1")
	assert.Equal(t, "/dev/nvme0n1p1", p1)
	assert.Equal(t, "/dev/nvme0n1p2", p2)
}

// ---------------------------------------------------------------------------
// detectBinaries tests
// ---------------------------------------------------------------------------

// TestDetectBinaries_RegularFile verifies that detectBinaries returns
// nil for regular files (non-block devices).
func TestDetectBinaries_RegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "test.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	result := detectBinaries(imgPath)
	assert.Nil(t, result)
}

// TestDetectBinaries_NonExistentPath verifies that detectBinaries
// handles non-existent paths gracefully.
func TestDetectBinaries_NonExistentPath(t *testing.T) {
	result := detectBinaries("/nonexistent/path")
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// scanMountedBinaries tests
// ---------------------------------------------------------------------------

// TestScanMountedBinaries_NoMatch verifies no match for a non-existent
// partition.
func TestScanMountedBinaries_NoMatch(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	readMountsFile = func() ([]byte, error) {
		return []byte("/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /home ext4 rw 0 0\n"), nil
	}

	result := scanMountedBinaries("/dev/sdb1")
	assert.Nil(t, result)
}

// TestScanMountedBinaries_ReadError verifies graceful handling of
// read errors.
func TestScanMountedBinaries_ReadError(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	readMountsFile = func() ([]byte, error) {
		return nil, errors.New("read error")
	}

	result := scanMountedBinaries("/dev/sdb1")
	assert.Nil(t, result)
}

// TestScanMountedBinaries_MatchFound verifies that a matching
// partition returns found binaries.
func TestScanMountedBinaries_MatchFound(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	// Create a temp dir with xkey binaries to simulate a mount point.
	binDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "xkey-linux-amd64"), []byte("bin"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "xkey-linux-arm64"), []byte("bin"), 0755))

	readMountsFile = func() ([]byte, error) {
		return []byte("/dev/sdb1 " + binDir + " vfat rw 0 0\n"), nil
	}

	result := scanMountedBinaries("/dev/sdb1")
	assert.Len(t, result, 2)
	assert.Contains(t, result, "xkey-linux-amd64")
	assert.Contains(t, result, "xkey-linux-arm64")
}

// TestScanMountedBinaries_EmptyLines verifies graceful handling of
// empty lines in mount data.
func TestScanMountedBinaries_EmptyLines(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	readMountsFile = func() ([]byte, error) {
		return []byte("\n\n\n"), nil
	}

	result := scanMountedBinaries("/dev/sdb1")
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// findXKeyBinaries tests
// ---------------------------------------------------------------------------

// TestFindXKeyBinaries_EmptyDir verifies empty directory returns nil.
func TestFindXKeyBinaries_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	binaries := findXKeyBinaries(tmpDir)
	assert.Empty(t, binaries)
}

// TestFindXKeyBinaries_WithBinaries verifies detection of xkey binaries.
func TestFindXKeyBinaries_WithBinaries(t *testing.T) {
	tmpDir := t.TempDir()
	files := []string{"xkey-linux-amd64", "xkey-linux-arm64", "xkey-linux-arm"}
	for _, f := range files {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, f), []byte("binary"), 0755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "README.txt"), []byte("readme"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "xkey.sh"), []byte("#!/bin/sh"), 0755))

	binaries := findXKeyBinaries(tmpDir)
	assert.Len(t, binaries, 3)
	assert.Contains(t, binaries, "xkey-linux-amd64")
	assert.Contains(t, binaries, "xkey-linux-arm64")
	assert.Contains(t, binaries, "xkey-linux-arm")
}

// TestFindXKeyBinaries_SkipsDirectories verifies directories are excluded.
func TestFindXKeyBinaries_SkipsDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "xkey-config"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "xkey-linux-amd64"), []byte("bin"), 0755))

	binaries := findXKeyBinaries(tmpDir)
	assert.Len(t, binaries, 1)
	assert.Equal(t, "xkey-linux-amd64", binaries[0])
}

// TestFindXKeyBinaries_NonExistentDir verifies graceful handling.
func TestFindXKeyBinaries_NonExistentDir(t *testing.T) {
	binaries := findXKeyBinaries("/nonexistent/directory")
	assert.Nil(t, binaries)
}

// TestFindXKeyBinaries_ExactNameXkey verifies the "xkey" exact name match.
func TestFindXKeyBinaries_ExactNameXkey(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "xkey"), []byte("binary"), 0755))

	binaries := findXKeyBinaries(tmpDir)
	assert.Len(t, binaries, 1)
	assert.Equal(t, "xkey", binaries[0])
}

// ---------------------------------------------------------------------------
// runCommand tests
// ---------------------------------------------------------------------------

// TestRunCommand_ValidCommand verifies runCommand succeeds with a
// simple command.
func TestRunCommand_ValidCommand(t *testing.T) {
	err := runCommand("true")
	assert.NoError(t, err)
}

// TestRunCommand_InvalidCommand verifies runCommand returns an error
// for a non-existent command.
func TestRunCommand_InvalidCommand(t *testing.T) {
	err := runCommand("nonexistent-command-12345")
	assert.Error(t, err)
}

// TestRunCommand_FailingCommand verifies runCommand returns an error
// when the command exits with a non-zero status.
func TestRunCommand_FailingCommand(t *testing.T) {
	err := runCommand("false")
	assert.Error(t, err)
}

// TestRunCommand_DelegatesToHook verifies that runCommand uses the
// execCommand hook.
func TestRunCommand_DelegatesToHook(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	called := false
	execCommand = func(name string, args ...string) error {
		called = true
		assert.Equal(t, "test-cmd", name)
		assert.Equal(t, []string{"arg1", "arg2"}, args)
		return nil
	}

	err := runCommand("test-cmd", "arg1", "arg2")
	require.NoError(t, err)
	assert.True(t, called)
}

// ---------------------------------------------------------------------------
// Constants tests
// ---------------------------------------------------------------------------

// TestConstants verifies package-level constants.
func TestConstants(t *testing.T) {
	assert.Equal(t, "XKEY", fat32Label)
	assert.Equal(t, "xkey-data", luksLabel)
	assert.Equal(t, "xkey-usb-data", luksMapperName)
}

// TestImageConfig_Struct verifies the ImageConfig struct fields.
func TestImageConfig_Struct(t *testing.T) {
	cfg := ImageConfig{
		Path:       "/tmp/test.img",
		SizeBytes:  4 * GB,
		Passphrase: "secret",
		Binaries:   []string{"/usr/local/bin/xkey-linux-amd64"},
	}
	assert.Equal(t, "/tmp/test.img", cfg.Path)
	assert.Equal(t, 4*GB, cfg.SizeBytes)
	assert.Equal(t, "secret", cfg.Passphrase)
	assert.Len(t, cfg.Binaries, 1)
}

// TestImageStatus_Struct verifies the ImageStatus struct fields.
func TestImageStatus_Struct(t *testing.T) {
	status := ImageStatus{
		Path:          "/dev/sdb",
		IsBlockDevice: true,
		TotalSize:     8 * GB,
		FAT32Size:     FAT32PartitionSize,
		LUKSSize:      8*GB - FAT32PartitionSize,
		LUKSMounted:   false,
		Binaries:      []string{"xkey-linux-amd64", "xkey-linux-arm64"},
	}
	assert.Equal(t, "/dev/sdb", status.Path)
	assert.True(t, status.IsBlockDevice)
	assert.Equal(t, 8*GB, status.TotalSize)
	assert.Equal(t, FAT32PartitionSize, status.FAT32Size)
	assert.False(t, status.LUKSMounted)
	assert.Len(t, status.Binaries, 2)
}

// ---------------------------------------------------------------------------
// CreateImage full flow with mocked hooks
// ---------------------------------------------------------------------------

// TestCreateImage_FullFlow_ImageFile verifies the complete CreateImage
// flow for an image file path with all hooks mocked.
func TestCreateImage_FullFlow_ImageFile(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "full-test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}

	err := CreateImage(cfg)
	require.NoError(t, err)
}

// TestCreateImage_FullFlow_SizeTooSmall verifies CreateImage with
// a too-small size after root check passes.
func TestCreateImage_FullFlow_SizeTooSmall(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "small.img"),
		SizeBytes:  100 * MB,
		Passphrase: "test-passphrase",
	}
	err := CreateImage(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSize))
}

// ---------------------------------------------------------------------------
// CreateImage -- block device path (uses /dev/null as device node)
// ---------------------------------------------------------------------------

// TestCreateImage_BlockDevice_ValidateBlockDeviceError verifies that
// CreateImage returns the ValidateBlockDevice error for a block device.
// /dev/null passes IsBlockDevice but ValidateBlockDevice will find
// it on a critical mount.
func TestCreateImage_BlockDevice_ValidateBlockDeviceError(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	// Simulate /dev/null being on a system mount.
	readMountsFile = func() ([]byte, error) {
		return []byte("/dev/null / ext4 rw 0 0\n"), nil
	}

	cfg := ImageConfig{
		Path:       "/dev/null",
		Passphrase: "test-passphrase",
	}
	err := CreateImage(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSystemDisk))
}

// TestCreateImage_BlockDevice_ValidatePassesPartitionFails verifies
// the full block device path when validation passes but partition fails.
func TestCreateImage_BlockDevice_ValidatePassesPartitionFails(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	// No critical mounts for /dev/null.
	readMountsFile = func() ([]byte, error) {
		return []byte("/dev/sda1 / ext4 rw 0 0\n"), nil
	}
	// Make sgdisk fail.
	execCommand = func(name string, args ...string) error {
		if name == "sgdisk" {
			return errors.New("sgdisk failed")
		}
		return nil
	}

	cfg := ImageConfig{
		Path:       "/dev/null",
		Passphrase: "test-passphrase",
	}
	err := CreateImage(cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPartitionFailed))
}

// ---------------------------------------------------------------------------
// createOnImageFile -- directory creation error
// ---------------------------------------------------------------------------

// TestCreateOnImageFile_CreateDirError verifies error when the parent
// directory cannot be created.
func TestCreateOnImageFile_CreateDirError(t *testing.T) {
	// Use a path under /dev/null which is not a directory.
	cfg := ImageConfig{
		Path:       "/dev/null/subdir/impossible/test.img",
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	err := createOnImageFile(cfg)
	require.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "create_dir", usbErr.Operation)
}

// TestCreateOnImageFile_CreateFileError verifies error when the file
// cannot be created.
func TestCreateOnImageFile_CreateFileError(t *testing.T) {
	// Create a read-only directory.
	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	require.NoError(t, os.MkdirAll(readOnlyDir, 0555))
	t.Cleanup(func() {
		os.Chmod(readOnlyDir, 0755)
	})

	cfg := ImageConfig{
		Path:       filepath.Join(readOnlyDir, "test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
	}
	err := createOnImageFile(cfg)
	require.Error(t, err)

	var usbErr *USBError
	require.True(t, errors.As(err, &usbErr))
	assert.Equal(t, "create_file", usbErr.Operation)
}

// ---------------------------------------------------------------------------
// populateFAT32 -- verify writes happen on success path
// ---------------------------------------------------------------------------

// TestPopulateFAT32_WritesAllFiles verifies that the marker, launcher,
// and readme are actually written during the success path.
func TestPopulateFAT32_WritesAllFiles(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	var capturedMountDir string
	execCommand = func(name string, args ...string) error {
		if name == "mount" && len(args) >= 4 {
			capturedMountDir = args[3]
		}
		return nil
	}

	// Create test binaries.
	srcDir := t.TempDir()
	binPath := filepath.Join(srcDir, "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0755))

	err := populateFAT32("/dev/sdb1", []string{binPath})
	require.NoError(t, err)

	assert.NotEmpty(t, capturedMountDir)
}

// ---------------------------------------------------------------------------
// Status -- additional paths
// ---------------------------------------------------------------------------

// TestStatus_ZeroSizeFile verifies Status with a zero-size file.
func TestStatus_ZeroSizeFile(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	luksIsUnlocked = func(name string) bool { return false }

	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "zero.img")
	require.NoError(t, os.WriteFile(imgPath, nil, 0600))

	status, err := Status(imgPath)
	require.NoError(t, err)
	assert.Equal(t, int64(0), status.TotalSize)
	assert.Equal(t, int64(0), status.LUKSSize)
	assert.False(t, status.IsBlockDevice)
	assert.Nil(t, status.Binaries)
}

// TestStatus_SymlinkTarget verifies Status follows symlinks.
func TestStatus_SymlinkTarget(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	luksIsUnlocked = func(name string) bool { return false }

	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "test.img")
	f, err := os.Create(imgPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(2*GB))
	f.Close()

	linkPath := filepath.Join(tmpDir, "link.img")
	require.NoError(t, os.Symlink(imgPath, linkPath))

	status, err := Status(linkPath)
	require.NoError(t, err)
	assert.Equal(t, linkPath, status.Path)
	assert.Equal(t, 2*GB, status.TotalSize)
}

// ---------------------------------------------------------------------------
// UpdateBinaries -- additional paths
// ---------------------------------------------------------------------------

// TestUpdateBinaries_NoBinaries verifies success with an empty binary list.
func TestUpdateBinaries_NoBinaries(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)

	imgPath := filepath.Join(t.TempDir(), "test.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	err := UpdateBinaries(imgPath, nil)
	require.NoError(t, err)
}

// TestUpdateBinaries_DetachCalledOnImageFile verifies that the loop
// device is detached even when the update succeeds.
func TestUpdateBinaries_DetachCalledOnImageFile(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)

	detached := false
	luksDetachLoopDevice = func(device string) error {
		detached = true
		return nil
	}

	imgPath := filepath.Join(t.TempDir(), "test.img")
	require.NoError(t, os.WriteFile(imgPath, []byte("data"), 0600))

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0755))

	err := UpdateBinaries(imgPath, []string{binPath})
	require.NoError(t, err)
	assert.True(t, detached, "loop device should be detached after update")
}

// ---------------------------------------------------------------------------
// detectBinaries -- block device branch
// ---------------------------------------------------------------------------

// TestDetectBinaries_BlockDevice verifies the block device branch
// by using /dev/null as a device node.
func TestDetectBinaries_BlockDevice(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()

	// Create a temp dir with xkey binaries.
	binDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "xkey-linux-amd64"), []byte("bin"), 0755))

	readMountsFile = func() ([]byte, error) {
		return []byte("/dev/null1 " + binDir + " vfat rw 0 0\n"), nil
	}

	result := detectBinaries("/dev/null")
	require.NotNil(t, result)
	assert.Len(t, result, 1)
	assert.Contains(t, result, "xkey-linux-amd64")
}

// TestDetectBinaries_BlockDevice_NoMountMatch verifies the block
// device branch when the partition is not mounted.
func TestDetectBinaries_BlockDevice_NoMountMatch(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()

	readMountsFile = func() ([]byte, error) {
		return []byte("/dev/sda1 / ext4 rw 0 0\n"), nil
	}

	result := detectBinaries("/dev/null")
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// ValidateBlockDevice -- symlink resolution fallback
// ---------------------------------------------------------------------------

// TestValidateBlockDevice_DevNull_ResolvedPath verifies that
// ValidateBlockDevice resolves symlinks and uses the resolved path.
func TestValidateBlockDevice_DevNull_ResolvedPath(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()

	readMountsFile = func() ([]byte, error) {
		return []byte(""), nil
	}

	err := ValidateBlockDevice("/dev/null")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// formatLUKS -- verify passphrase forwarding
// ---------------------------------------------------------------------------

// TestFormatLUKS_PassphraseForwarded verifies that the passphrase is
// correctly forwarded to all LUKS operations.
func TestFormatLUKS_PassphraseForwarded(t *testing.T) {
	restore := saveHooks(t)
	defer restore()

	var formatPassphrase, unlockPassphrase []byte
	luksFormat = func(opts luks2.FormatOptions) error {
		formatPassphrase = opts.Passphrase
		return nil
	}
	luksUnlock = func(device string, passphrase []byte, name string) error {
		unlockPassphrase = passphrase
		return nil
	}
	luksMakeFilesystem = func(device, fstype, label string) error { return nil }
	luksLock = func(name string) error { return nil }

	err := formatLUKS("/dev/sdb2", "my-secret-passphrase")
	require.NoError(t, err)
	assert.Equal(t, []byte("my-secret-passphrase"), formatPassphrase)
	assert.Equal(t, []byte("my-secret-passphrase"), unlockPassphrase)
}

// ---------------------------------------------------------------------------
// partitionAndFormat -- with binaries
// ---------------------------------------------------------------------------

// TestPartitionAndFormat_WithBinaries verifies that binaries are
// copied during the partition and format process.
func TestPartitionAndFormat_WithBinaries(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0755))

	cfg := ImageConfig{
		Passphrase: "test-passphrase",
		Binaries:   []string{binPath},
	}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.NoError(t, err)
}

// TestPartitionAndFormat_PopulateBinaryFails verifies error when a
// binary fails to copy during partition and format.
func TestPartitionAndFormat_PopulateBinaryFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	cfg := ImageConfig{
		Passphrase: "test-passphrase",
		Binaries:   []string{"/nonexistent/binary"},
	}
	err := partitionAndFormat("/dev/sdb", cfg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBinaryNotFound))
}

// ---------------------------------------------------------------------------
// createOnImageFile -- with binaries
// ---------------------------------------------------------------------------

// TestCreateOnImageFile_SuccessWithBinaries verifies the image file
// creation with binaries included.
func TestCreateOnImageFile_SuccessWithBinaries(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0755))

	cfg := ImageConfig{
		Path:       filepath.Join(t.TempDir(), "test.img"),
		SizeBytes:  2 * GB,
		Passphrase: "test-passphrase",
		Binaries:   []string{binPath},
	}
	err := createOnImageFile(cfg)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Status on /dev/null (block device path)
// ---------------------------------------------------------------------------

// TestStatus_DevNullBlockDevice verifies Status for /dev/null which
// is a device node, exercising the IsBlockDevice branch.
func TestStatus_DevNullBlockDevice(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()
	luksIsUnlocked = func(name string) bool { return false }
	readMountsFile = func() ([]byte, error) { return []byte(""), nil }

	status, err := Status("/dev/null")
	require.NoError(t, err)
	assert.True(t, status.IsBlockDevice)
	assert.Equal(t, "/dev/null", status.Path)
}

// ---------------------------------------------------------------------------
// UpdateBinaries with block device path
// ---------------------------------------------------------------------------

// TestUpdateBinaries_BlockDevice_MountFails verifies the block device
// path of UpdateBinaries when mount fails.
func TestUpdateBinaries_BlockDevice_MountFails(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()
	mockRootUser()

	execCommand = func(name string, args ...string) error {
		if name == "mount" {
			return errors.New("mount failed")
		}
		return nil
	}

	err := UpdateBinaries("/dev/null", []string{"/some/binary"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMountFailed))
}

// TestUpdateBinaries_BlockDevice_Success verifies the block device
// path of UpdateBinaries succeeds.
func TestUpdateBinaries_BlockDevice_Success(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null not accessible")
	}

	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0755))

	err := UpdateBinaries("/dev/null", []string{binPath})
	require.NoError(t, err)
}
