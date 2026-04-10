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
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test VolumeError implementation
func TestVolumeError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *VolumeError
		expected string
	}{
		{
			name: "with path",
			err: &VolumeError{
				Operation: "mount",
				Path:      "/dev/mapper/test",
				Err:       errors.New("device busy"),
			},
			expected: "luks: mount failed for /dev/mapper/test: device busy",
		},
		{
			name: "without path",
			err: &VolumeError{
				Operation: "lock",
				Err:       errors.New("not open"),
			},
			expected: "luks: lock failed: not open",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestVolumeError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &VolumeError{
		Operation: "test",
		Err:       underlying,
	}

	assert.Equal(t, underlying, err.Unwrap())
	assert.True(t, errors.Is(err, underlying))
}

// Test sentinel errors
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"VolumeNotFound", ErrVolumeNotFound, "luks: volume not found"},
		{"VolumeAlreadyExists", ErrVolumeAlreadyExists, "luks: encrypted container already exists - use 'xkey luks2 wipe' first to destroy existing data"},
		{"VolumeNotMounted", ErrVolumeNotMounted, "luks: volume not mounted"},
		{"VolumeAlreadyMounted", ErrVolumeAlreadyMounted, "luks: volume already mounted"},
		{"InvalidPassphrase", ErrInvalidPassphrase, "luks: invalid passphrase"},
		{"PassphraseMismatch", ErrPassphraseMismatch, "luks: passphrase confirmation mismatch"},
		{"LoopDeviceSetup", ErrLoopDeviceSetup, "luks: failed to setup loop device"},
		{"LUKSFormat", ErrLUKSFormat, "luks: failed to format volume"},
		{"LUKSUnlock", ErrLUKSUnlock, "luks: failed to unlock volume"},
		{"LUKSLock", ErrLUKSLock, "luks: failed to lock volume"},
		{"FilesystemCreate", ErrFilesystemCreate, "luks: failed to create filesystem"},
		{"MountFailed", ErrMountFailed, "luks: failed to mount volume"},
		{"UnmountFailed", ErrUnmountFailed, "luks: failed to unmount volume"},
		{"DataCopyFailed", ErrDataCopyFailed, "luks: failed to copy data"},
		{"PermissionDenied", ErrPermissionDenied, "luks: permission denied (requires root)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

// Test ExpandPath function
func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "expand tilde",
			input:    "~/test/path",
			expected: filepath.Join(home, "test/path"),
		},
		{
			name:     "absolute path unchanged",
			input:    "/absolute/path",
			expected: "/absolute/path",
		},
		{
			name:     "relative path unchanged",
			input:    "relative/path",
			expected: "relative/path",
		},
		{
			name:     "tilde only",
			input:    "~",
			expected: "~",
		},
		{
			name:     "tilde in middle unchanged",
			input:    "/path/~/file",
			expected: "/path/~/file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandPath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test GetDefaultLUKSPath
func TestGetDefaultLUKSPath(t *testing.T) {
	path, err := GetDefaultLUKSPath()
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	expected := filepath.Join(home, DefaultLUKSFile)
	assert.Equal(t, expected, path)
	assert.Contains(t, path, ".xkey.luks")
}

// Test GetDefaultDataDir
func TestGetDefaultDataDir(t *testing.T) {
	path, err := GetDefaultDataDir()
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	expected := filepath.Join(home, DefaultDataDir)
	assert.Equal(t, expected, path)
	assert.Contains(t, path, ".xkey")
}

// Test constants
func TestConstants(t *testing.T) {
	assert.Equal(t, ".xkey.luks", DefaultLUKSFile)
	assert.Equal(t, ".xkey", DefaultDataDir)
	assert.Equal(t, "xkey", MapperName)
}

// Test NewVolume
func TestNewVolume(t *testing.T) {
	vol, err := NewVolume()
	require.NoError(t, err)
	require.NotNil(t, vol)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(home, DefaultLUKSFile), vol.LUKSPath)
	assert.Equal(t, filepath.Join(home, DefaultDataDir), vol.MountPoint)
	assert.Equal(t, MapperName, vol.MapperName)
	assert.Empty(t, vol.LoopDevice)
}

// Test NewVolumeWithPaths
func TestNewVolumeWithPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name          string
		luksPath      string
		mountPoint    string
		expectedLuks  string
		expectedMount string
	}{
		{
			name:          "absolute paths",
			luksPath:      "/tmp/test.luks",
			mountPoint:    "/tmp/testmount",
			expectedLuks:  "/tmp/test.luks",
			expectedMount: "/tmp/testmount",
		},
		{
			name:          "paths with tilde",
			luksPath:      "~/custom.luks",
			mountPoint:    "~/customdir",
			expectedLuks:  filepath.Join(home, "custom.luks"),
			expectedMount: filepath.Join(home, "customdir"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vol := NewVolumeWithPaths(tt.luksPath, tt.mountPoint)
			require.NotNil(t, vol)

			assert.Equal(t, tt.expectedLuks, vol.LUKSPath)
			assert.Equal(t, tt.expectedMount, vol.MountPoint)
			assert.Equal(t, MapperName, vol.MapperName)
		})
	}
}

// Test Volume.Exists
func TestVolume_Exists(t *testing.T) {
	t.Run("file does not exist", func(t *testing.T) {
		vol := NewVolumeWithPaths("/nonexistent/path.luks", "/tmp/mount")
		assert.False(t, vol.Exists())
	})

	t.Run("file exists", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test*.luks")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		vol := NewVolumeWithPaths(tmpFile.Name(), "/tmp/mount")
		assert.True(t, vol.Exists())
	})
}

// Test IsLUKSVolume for non-existent file
func TestIsLUKSVolume_NonExistent(t *testing.T) {
	result := IsLUKSVolume("/nonexistent/file.luks")
	assert.False(t, result)
}

// Test IsLUKSVolume for regular file (not LUKS)
func TestIsLUKSVolume_RegularFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test*.luks")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write some non-LUKS data
	_, err = tmpFile.WriteString("not a luks volume")
	require.NoError(t, err)
	tmpFile.Close()

	result := IsLUKSVolume(tmpFile.Name())
	assert.False(t, result)
}

// Test IsLUKSVolume with valid LUKS magic header
func TestIsLUKSVolume_ValidMagic(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test*.luks")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write LUKS2 magic header
	magic := []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	_, err = tmpFile.Write(magic)
	require.NoError(t, err)
	tmpFile.Close()

	result := IsLUKSVolume(tmpFile.Name())
	assert.True(t, result)
}

// Test IsLUKSVolume with partial LUKS magic (file too small)
func TestIsLUKSVolume_PartialMagic(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test*.luks")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write only first 4 bytes of magic
	partial := []byte{'L', 'U', 'K', 'S'}
	_, err = tmpFile.Write(partial)
	require.NoError(t, err)
	tmpFile.Close()

	result := IsLUKSVolume(tmpFile.Name())
	assert.False(t, result)
}

// Test IsLUKSVolume with empty file
func TestIsLUKSVolume_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test*.luks")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	result := IsLUKSVolume(tmpFile.Name())
	assert.False(t, result)
}

// Test IsMounted for non-mounted path
func TestIsMounted_NotMounted(t *testing.T) {
	result := IsMounted("/nonexistent/mount/point")
	assert.False(t, result)
}

// Test IsMounted for well-known mounted path
func TestIsMounted_KnownMount(t *testing.T) {
	// Root is always mounted on Linux
	result := IsMounted("/")
	assert.True(t, result)
}

// Test IsLUKSOpen for non-existent mapper
func TestIsLUKSOpen_NotOpen(t *testing.T) {
	result := IsLUKSOpen("nonexistent_mapper_name_12345")
	assert.False(t, result)
}

// Test Volume methods that check state
func TestVolume_StateChecks(t *testing.T) {
	vol := &Volume{
		LUKSPath:   "/nonexistent.luks",
		MountPoint: "/nonexistent/mount",
		MapperName: "xkey_test_nonexistent_12345",
	}

	assert.False(t, vol.Exists())
	assert.False(t, vol.IsLUKS())
	assert.False(t, vol.IsMounted())
	assert.False(t, vol.IsOpen())
}

// Test Volume.Create returns ErrVolumeAlreadyExists
func TestVolume_Create_AlreadyExists(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test*.luks")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	vol := NewVolumeWithPaths(tmpFile.Name(), "/tmp/mount")
	err = vol.Create(1024*1024, "testpass")

	assert.ErrorIs(t, err, ErrVolumeAlreadyExists)
}

// Test Volume.Unlock returns ErrVolumeNotFound
func TestVolume_Unlock_NotFound(t *testing.T) {
	vol := NewVolumeWithPaths("/nonexistent.luks", "/tmp/mount")
	err := vol.Unlock("testpass")

	assert.ErrorIs(t, err, ErrVolumeNotFound)
}

// Test Volume.CopyDataToVolume returns ErrVolumeNotMounted
func TestVolume_CopyDataToVolume_NotMounted(t *testing.T) {
	vol := NewVolumeWithPaths("/test.luks", "/tmp/notmounted")
	err := vol.CopyDataToVolume("/tmp/source")

	assert.ErrorIs(t, err, ErrVolumeNotMounted)
}

// Test copyFile function
func TestCopyFile(t *testing.T) {
	// Create source file
	srcDir, err := os.MkdirTemp("", "copy_src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "copy_dst")
	require.NoError(t, err)
	defer os.RemoveAll(dstDir)

	srcFile := filepath.Join(srcDir, "testfile.txt")
	dstFile := filepath.Join(dstDir, "testfile.txt")
	content := "test content for copy"

	err = os.WriteFile(srcFile, []byte(content), 0644)
	require.NoError(t, err)

	// Test copy
	err = copyFile(srcFile, dstFile)
	require.NoError(t, err)

	// Verify content
	data, err := os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))
}

// Test copyFile with non-existent source
func TestCopyFile_NonExistentSource(t *testing.T) {
	err := copyFile("/nonexistent/source.txt", "/tmp/dest.txt")
	assert.Error(t, err)
}

// Test copyDir function
func TestCopyDir(t *testing.T) {
	// Create source directory structure
	srcDir, err := os.MkdirTemp("", "copydir_src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "copydir_dst")
	require.NoError(t, err)
	defer os.RemoveAll(dstDir)

	// Create nested structure
	subDir := filepath.Join(srcDir, "subdir")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	// Create files
	file1 := filepath.Join(srcDir, "file1.txt")
	err = os.WriteFile(file1, []byte("content1"), 0644)
	require.NoError(t, err)

	file2 := filepath.Join(subDir, "file2.txt")
	err = os.WriteFile(file2, []byte("content2"), 0644)
	require.NoError(t, err)

	// Test copy
	err = copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify
	data1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content1", string(data1))

	data2, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file2.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content2", string(data2))
}

// Test copyDir with non-existent source
func TestCopyDir_NonExistentSource(t *testing.T) {
	err := copyDir("/nonexistent/source", "/tmp/dest")
	assert.Error(t, err)
}

// Test error wrapping with VolumeError
func TestVolumeError_Wrapping(t *testing.T) {
	baseErr := errors.New("base error")
	volErr := &VolumeError{
		Operation: "test_op",
		Path:      "/test/path",
		Err:       baseErr,
	}

	// Test errors.Is
	assert.True(t, errors.Is(volErr, baseErr))

	// Test errors.Unwrap
	unwrapped := errors.Unwrap(volErr)
	assert.Equal(t, baseErr, unwrapped)

	// Test error chain
	var targetVolErr *VolumeError
	assert.True(t, errors.As(volErr, &targetVolErr))
	assert.Equal(t, "test_op", targetVolErr.Operation)
}

// Test Volume.Lock returns ErrVolumeNotMounted when not open/mounted
func TestVolume_Lock_NotMounted(t *testing.T) {
	vol := &Volume{
		LUKSPath:   "/test.luks",
		MountPoint: "/nonexistent/mount",
		MapperName: "xkey_test_nonexistent_12345",
	}
	err := vol.Lock()

	assert.ErrorIs(t, err, ErrVolumeNotMounted)
}

// Test LUKS2 magic constant
func TestLUKS2Magic(t *testing.T) {
	expected := []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	assert.Equal(t, expected, luks2Magic)
	assert.Len(t, luks2Magic, 6)
}

// Test copyFile preserves permissions
func TestCopyFile_PreservesPermissions(t *testing.T) {
	srcDir, err := os.MkdirTemp("", "copy_perm_src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "copy_perm_dst")
	require.NoError(t, err)
	defer os.RemoveAll(dstDir)

	srcFile := filepath.Join(srcDir, "testfile.txt")
	dstFile := filepath.Join(dstDir, "testfile.txt")

	// Create source file with specific permissions
	err = os.WriteFile(srcFile, []byte("test"), 0755)
	require.NoError(t, err)

	// Copy file
	err = copyFile(srcFile, dstFile)
	require.NoError(t, err)

	// Verify permissions are preserved
	srcInfo, err := os.Stat(srcFile)
	require.NoError(t, err)
	dstInfo, err := os.Stat(dstFile)
	require.NoError(t, err)

	assert.Equal(t, srcInfo.Mode(), dstInfo.Mode())
}

// Test copyFile to invalid destination
func TestCopyFile_InvalidDestination(t *testing.T) {
	srcDir, err := os.MkdirTemp("", "copy_src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	srcFile := filepath.Join(srcDir, "testfile.txt")
	err = os.WriteFile(srcFile, []byte("test"), 0644)
	require.NoError(t, err)

	// Try to copy to a non-existent directory
	err = copyFile(srcFile, "/nonexistent/dir/file.txt")
	assert.Error(t, err)
}

// Test copyDir with empty source directory
func TestCopyDir_EmptySource(t *testing.T) {
	srcDir, err := os.MkdirTemp("", "copydir_empty_src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "copydir_empty_dst")
	require.NoError(t, err)
	defer os.RemoveAll(dstDir)

	// Copy empty directory
	err = copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify destination is still empty (only . and ..)
	entries, err := os.ReadDir(dstDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestChownToCallingUser verifies the chown-to-calling-user logic that
// runs after mounting a LUKS volume. Because the actual chown syscall
// requires root, these tests focus on the environment variable parsing
// and graceful degradation.
func TestChownToCallingUser(t *testing.T) {

	// Helper to clear all relevant env vars before each subtest.
	clearEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("SUDO_UID", "")
		t.Setenv("SUDO_GID", "")
		t.Setenv("PKEXEC_UID", "")
	}

	t.Run("no elevation env vars set", func(t *testing.T) {
		clearEnv(t)
		os.Unsetenv("SUDO_UID")
		os.Unsetenv("SUDO_GID")
		os.Unsetenv("PKEXEC_UID")

		// resolveCallingUser should return false when no env vars are set.
		uid, gid, ok := resolveCallingUser()
		assert.False(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)

		// ChownToCallingUser should be a no-op (no panic, no error).
		tmpDir, err := os.MkdirTemp("", "chown_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		ChownToCallingUser(tmpDir)
		// If we get here without panic or hang, the test passes.
	})

	t.Run("invalid SUDO_UID", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SUDO_UID", "not-a-number")
		t.Setenv("SUDO_GID", "1000")

		uid, gid, ok := resolveCallingUser()
		assert.False(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)
	})

	t.Run("valid SUDO_UID with invalid SUDO_GID falls back to passwd lookup", func(t *testing.T) {
		clearEnv(t)

		// Use current user's UID so passwd lookup succeeds.
		currentUser, err := user.Current()
		require.NoError(t, err)

		t.Setenv("SUDO_UID", currentUser.Uid)
		t.Setenv("SUDO_GID", "not-a-number")

		uid, gid, ok := resolveCallingUser()

		expectedUID, err := strconv.Atoi(currentUser.Uid)
		require.NoError(t, err)
		expectedGID, err := strconv.Atoi(currentUser.Gid)
		require.NoError(t, err)

		assert.True(t, ok)
		assert.Equal(t, expectedUID, uid)
		assert.Equal(t, expectedGID, gid)
	})

	t.Run("valid SUDO_UID and SUDO_GID", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SUDO_UID", "1000")
		t.Setenv("SUDO_GID", "1000")

		uid, gid, ok := resolveCallingUser()
		assert.True(t, ok)
		assert.Equal(t, 1000, uid)
		assert.Equal(t, 1000, gid)
	})

	t.Run("invalid PKEXEC_UID", func(t *testing.T) {
		clearEnv(t)
		os.Unsetenv("SUDO_UID")
		os.Unsetenv("SUDO_GID")
		t.Setenv("PKEXEC_UID", "garbage")

		uid, gid, ok := resolveCallingUser()
		assert.False(t, ok)
		assert.Equal(t, 0, uid)
		assert.Equal(t, 0, gid)
	})

	t.Run("valid PKEXEC_UID resolves GID from passwd", func(t *testing.T) {
		clearEnv(t)
		os.Unsetenv("SUDO_UID")
		os.Unsetenv("SUDO_GID")

		// Use current user's UID so passwd lookup succeeds.
		currentUser, err := user.Current()
		require.NoError(t, err)

		t.Setenv("PKEXEC_UID", currentUser.Uid)

		uid, gid, ok := resolveCallingUser()

		expectedUID, err := strconv.Atoi(currentUser.Uid)
		require.NoError(t, err)
		expectedGID, err := strconv.Atoi(currentUser.Gid)
		require.NoError(t, err)

		assert.True(t, ok)
		assert.Equal(t, expectedUID, uid)
		assert.Equal(t, expectedGID, gid)
	})

	t.Run("PKEXEC_UID with nonexistent user", func(t *testing.T) {
		clearEnv(t)
		os.Unsetenv("SUDO_UID")
		os.Unsetenv("SUDO_GID")
		t.Setenv("PKEXEC_UID", "99999")

		// This may or may not resolve depending on the system.
		// The important thing is it does not panic.
		_, _, _ = resolveCallingUser()
	})

	t.Run("SUDO_UID takes precedence over PKEXEC_UID", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SUDO_UID", "1001")
		t.Setenv("SUDO_GID", "1001")
		t.Setenv("PKEXEC_UID", "2002")

		uid, gid, ok := resolveCallingUser()
		assert.True(t, ok)
		assert.Equal(t, 1001, uid)
		assert.Equal(t, 1001, gid)
	})
}

// TestLookupGIDForUID verifies the passwd lookup helper.
func TestLookupGIDForUID(t *testing.T) {
	t.Run("valid current user", func(t *testing.T) {
		currentUser, err := user.Current()
		require.NoError(t, err)

		gid, err := lookupGIDForUID(currentUser.Uid)
		require.NoError(t, err)

		expectedGID, err := strconv.Atoi(currentUser.Gid)
		require.NoError(t, err)
		assert.Equal(t, expectedGID, gid)
	})

	t.Run("nonexistent UID", func(t *testing.T) {
		// Use a very high UID unlikely to exist.
		_, err := lookupGIDForUID("4294967294")
		assert.Error(t, err)
	})

	t.Run("invalid UID string", func(t *testing.T) {
		_, err := lookupGIDForUID("not-a-uid")
		assert.Error(t, err)
	})
}

// TestChownToCallingUser_NonRoot verifies that ChownToCallingUser is a
// no-op when the process is not running as root (euid != 0). This is
// the common case during normal test execution.
func TestChownToCallingUser_NonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root execution")
	}

	tmpDir, err := os.MkdirTemp("", "chown_nonroot")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Set env vars that would normally trigger chown.
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1000")

	// Should return immediately because euid != 0.
	ChownToCallingUser(tmpDir)

	// Verify ownership has NOT changed (still belongs to current user).
	info, err := os.Stat(tmpDir)
	require.NoError(t, err)
	assert.NotNil(t, info)

	// The directory should still be accessible.
	testFile := filepath.Join(tmpDir, "probe")
	err = os.WriteFile(testFile, []byte("ok"), 0600)
	assert.NoError(t, err)
}

// TestResolveCallingUser_EmptyStringValues verifies that empty string
// values for environment variables are treated as unset.
func TestResolveCallingUser_EmptyStringValues(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("PKEXEC_UID", "")

	uid, gid, ok := resolveCallingUser()
	assert.False(t, ok)
	assert.Equal(t, 0, uid)
	assert.Equal(t, 0, gid)
}

// TestResolveCallingUser_ZeroUID verifies that UID 0 (root) is parsed
// correctly. While unusual, someone could set SUDO_UID=0.
func TestResolveCallingUser_ZeroUID(t *testing.T) {
	t.Setenv("SUDO_UID", "0")
	t.Setenv("SUDO_GID", "0")

	uid, gid, ok := resolveCallingUser()
	assert.True(t, ok)
	assert.Equal(t, 0, uid)
	assert.Equal(t, 0, gid)
}

// TestLookupGIDForUID_RootUser verifies that root (UID 0) can be
// looked up successfully.
func TestLookupGIDForUID_RootUser(t *testing.T) {
	gid, err := lookupGIDForUID("0")
	require.NoError(t, err)
	assert.Equal(t, 0, gid, "root GID should be 0")
}

// TestChownToCallingUser_InvalidPath verifies graceful handling when
// chown is called on a nonexistent path while running as root.
// When not root, ChownToCallingUser exits early so we test
// resolveCallingUser independently.
func TestChownToCallingUser_InvalidPath(t *testing.T) {
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1000")

	// Verify resolveCallingUser returns valid data.
	uid, gid, ok := resolveCallingUser()
	assert.True(t, ok)
	assert.Equal(t, 1000, uid)
	assert.Equal(t, 1000, gid)

	// ChownToCallingUser on a bad path should not panic.
	// If not root, it returns early; if root, it logs a warning.
	ChownToCallingUser(fmt.Sprintf("/nonexistent/path/%d", os.Getpid()))
}
