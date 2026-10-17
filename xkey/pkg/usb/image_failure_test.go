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
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateTempDir points os.MkdirTemp at a per-test directory so the mount
// directories populateFAT32 and UpdateBinaries create stay inside t.TempDir.
func isolateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

// missingTempDir points os.MkdirTemp at a directory that does not exist.
func missingTempDir(t *testing.T) {
	t.Helper()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
}

// requireOperation asserts err carries a USBError for the given operation.
func requireOperation(t *testing.T, err error, operation string) *USBError {
	t.Helper()
	var usbErr *USBError
	require.ErrorAs(t, err, &usbErr)
	assert.Equal(t, operation, usbErr.Operation)
	return usbErr
}

// testBinary writes a fake xkey binary and returns its path.
func testBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xkey-linux-amd64")
	require.NoError(t, os.WriteFile(path, []byte("binary"), 0755))
	return path
}

// testImage writes a small image file and returns its path.
func testImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.img")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0600))
	return path
}

// mountWithEntry makes the mocked mount create a directory named entry in
// the mount point, so writing a file of that name fails.
func mountWithEntry(t *testing.T, entry string) {
	t.Helper()
	execCommand = func(name string, args ...string) error {
		if name == "mount" {
			return os.Mkdir(filepath.Join(args[len(args)-1], entry), 0700)
		}
		return nil
	}
}

// failCommand makes execCommand fail for the named command only.
func failCommand(failing string, calls *[]string) {
	execCommand = func(name string, args ...string) error {
		*calls = append(*calls, name)
		if name == failing {
			return &CommandError{Name: name, Err: errors.New("exit status 1")}
		}
		return nil
	}
}

func TestPartitionAndFormat_PartxFallbackFailsContinues(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockAllCommandsSuccess(t)
	isolateTempDir(t)

	var calls []string
	execCommand = func(name string, args ...string) error {
		calls = append(calls, name)
		if name == "partprobe" || name == "partx" {
			return errors.New(name + " failed")
		}
		return nil
	}

	cfg := ImageConfig{Passphrase: testSecret(t, "test")}
	require.NoError(t, partitionAndFormat(t.Context(), "/dev/sdb", cfg))
	assert.Contains(t, calls, "partx")
	assert.Contains(t, calls, "mkfs.vfat", "FAT32 formatting must still run after both re-reads fail")
}

func TestPopulateFAT32_WritesMarkerLauncherAndReadme(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	isolateTempDir(t)

	var mountDir string
	execCommand = func(name string, args ...string) error {
		if name == "mount" {
			mountDir = args[len(args)-1]
		}
		if name == "umount" {
			for _, file := range []string{xhome.MarkerFile, "xkey.sh", "README.txt", "xkey-linux-amd64"} {
				assert.FileExists(t, filepath.Join(mountDir, file))
			}
		}
		return nil
	}

	require.NoError(t, populateFAT32("/dev/sdb1", []string{testBinary(t)}))
	assert.NoDirExists(t, mountDir, "the temporary mount point must be removed")
}

func TestPopulateFAT32_MountDirFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	missingTempDir(t)
	execCommand = func(name string, args ...string) error {
		t.Errorf("no command may run without a mount point, ran %s", name)
		return nil
	}

	err := populateFAT32("/dev/sdb1", nil)
	requireOperation(t, err, "create_mount_dir")
}

func TestPopulateFAT32_UmountFailureIsNotFatal(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	isolateTempDir(t)

	var calls []string
	failCommand("umount", &calls)

	require.NoError(t, populateFAT32("/dev/sdb1", nil))
	assert.Equal(t, []string{"mount", "umount"}, calls)
}

func TestPopulateFAT32_WriteFailures(t *testing.T) {
	tests := []struct {
		entry     string
		operation string
	}{
		{entry: xhome.MarkerFile, operation: "create_marker"},
		{entry: "xkey.sh", operation: "write_launcher"},
		{entry: "README.txt", operation: "write_readme"},
	}
	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			restore := saveHooks(t)
			defer restore()
			isolateTempDir(t)
			mountWithEntry(t, tt.entry)

			err := populateFAT32("/dev/sdb1", nil)
			usbErr := requireOperation(t, err, tt.operation)
			assert.Equal(t, tt.entry, filepath.Base(usbErr.Path))
		})
	}
}

func TestStatus_StatFailureOtherThanNotExist(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	statPath = func(string) (os.FileInfo, error) { return nil, fs.ErrPermission }

	status, err := Status(t.Context(), "/dev/sdb")
	assert.Nil(t, status)
	requireOperation(t, err, "stat")
	assert.ErrorIs(t, err, fs.ErrPermission)
	assert.NotErrorIs(t, err, ErrImageNotFound)
}

func TestUpdateBinaries_StatFailureOtherThanNotExist(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	statPath = func(string) (os.FileInfo, error) { return nil, fs.ErrPermission }

	err := UpdateBinaries(t.Context(), "/dev/sdb", nil)
	requireOperation(t, err, "stat")
	assert.ErrorIs(t, err, fs.ErrPermission)
	assert.NotErrorIs(t, err, ErrImageNotFound)
}

func TestUpdateBinaries_DetachFailureIsReported(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)
	isolateTempDir(t)

	detachErr := errors.New("loop busy")
	luksDetachLoopDevice = func(context.Context, string) error { return detachErr }

	err := UpdateBinaries(t.Context(), testImage(t), []string{testBinary(t)})
	usbErr := requireOperation(t, err, "detach_loop")
	assert.Equal(t, "/dev/loop99", usbErr.Path)
	assert.ErrorIs(t, err, detachErr)
}

func TestUpdateBinaries_PartprobeFailureIsNotFatal(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)
	isolateTempDir(t)

	var calls []string
	failCommand("partprobe", &calls)

	require.NoError(t, UpdateBinaries(t.Context(), testImage(t), []string{testBinary(t)}))
	assert.Equal(t, []string{"partprobe", "mount", "umount"}, calls)
}

func TestUpdateBinaries_MountDirFailsDetachesLoop(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)
	missingTempDir(t)

	detached := false
	luksDetachLoopDevice = func(context.Context, string) error {
		detached = true
		return nil
	}

	err := UpdateBinaries(t.Context(), testImage(t), nil)
	requireOperation(t, err, "create_mount_dir")
	assert.True(t, detached, "the loop device must be detached on failure")
}

func TestUpdateBinaries_UmountFailureIsNotFatal(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)
	isolateTempDir(t)

	var calls []string
	failCommand("umount", &calls)

	require.NoError(t, UpdateBinaries(t.Context(), testImage(t), []string{testBinary(t)}))
	assert.Contains(t, calls, "umount")
}

func TestUpdateBinaries_LauncherWriteFails(t *testing.T) {
	restore := saveHooks(t)
	defer restore()
	mockRootUser()
	mockAllCommandsSuccess(t)
	isolateTempDir(t)
	mountWithEntry(t, "xkey.sh")

	err := UpdateBinaries(t.Context(), testImage(t), []string{testBinary(t)})
	usbErr := requireOperation(t, err, "update_launcher")
	assert.Equal(t, "xkey.sh", filepath.Base(usbErr.Path))
}
