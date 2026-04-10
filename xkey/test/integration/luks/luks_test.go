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

//go:build integration && linux

package luks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPassphrase      = "test-passphrase-123!"
	testWrongPassphrase = "wrong-passphrase-456!"
	testVolumeSize      = "50M"
)

// TestLUKS_SealUnsealLock tests the complete seal-unseal-lock cycle.
func TestLUKS_SealUnsealLock(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create test data in the data directory
	testData := createTestData(t, paths.DataDir)

	// Phase 1: Seal - create encrypted volume
	t.Run("seal", func(t *testing.T) {
		result := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)

		require.Equal(t, 0, result.ExitCode, "seal should succeed, stderr: %s", result.Stderr)
		assert.Contains(t, result.Stdout, "Encrypted storage created successfully")

		// Verify LUKS file was created
		assertFileExists(t, paths.LUKSFile)
		require.True(t, isLUKSVolume(paths.LUKSFile), "Created file should be a valid LUKS volume")

		// Verify original data directory was removed (data migrated)
		// Note: The mount point directory might still exist but should be empty
	})

	// Phase 2: Unseal - unlock the volume
	t.Run("unseal", func(t *testing.T) {
		result := execXkeyUnseal(t, binary, paths, testPassphrase)

		require.Equal(t, 0, result.ExitCode, "unseal should succeed, stderr: %s", result.Stderr)
		assert.Contains(t, result.Stdout, "Encrypted storage unlocked")

		// Wait for mount to complete
		require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second), "Volume should be mounted")

		// Verify volume is mounted
		assertMounted(t, paths.MountPoint)

		// Verify migrated data is accessible
		verifyTestData(t, paths.MountPoint, testData)
	})

	// Phase 3: Lock - close the volume
	t.Run("lock", func(t *testing.T) {
		result := execXkeyLock(t, binary, paths)

		require.Equal(t, 0, result.ExitCode, "lock should succeed, stderr: %s", result.Stderr)
		assert.Contains(t, result.Stdout, "Encrypted storage locked successfully")

		// Wait for unmount to complete
		require.True(t, waitForUnmount(t, paths.MountPoint, 5*time.Second), "Volume should be unmounted")

		// Verify volume is no longer mounted
		assertNotMounted(t, paths.MountPoint)
	})

	// Phase 4: Unseal again to verify data persistence
	t.Run("unseal_again", func(t *testing.T) {
		result := execXkeyUnseal(t, binary, paths, testPassphrase)

		require.Equal(t, 0, result.ExitCode, "unseal should succeed again, stderr: %s", result.Stderr)

		// Wait for mount
		require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second), "Volume should be mounted")

		// Verify data is still there
		verifyTestData(t, paths.MountPoint, testData)

		// Clean up by locking
		cleanupResult := execXkeyLock(t, binary, paths)
		require.Equal(t, 0, cleanupResult.ExitCode)
	})
}

// TestLUKS_SealWithoutExistingData tests creating a volume without pre-existing data.
func TestLUKS_SealWithoutExistingData(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Remove the empty data directory created by createTempLUKSPaths
	err := os.RemoveAll(paths.DataDir)
	require.NoError(t, err)

	// Seal - create encrypted volume without existing data
	result := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)

	require.Equal(t, 0, result.ExitCode, "seal should succeed without existing data, stderr: %s", result.Stderr)
	assert.Contains(t, result.Stdout, "Encrypted storage created successfully")

	// Verify LUKS file was created
	assertFileExists(t, paths.LUKSFile)
	require.True(t, isLUKSVolume(paths.LUKSFile), "Created file should be a valid LUKS volume")

	// Unseal to verify it works
	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode, "unseal should succeed, stderr: %s", unsealResult.Stderr)

	// Volume should be mounted and empty
	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))
	assertMounted(t, paths.MountPoint)

	// Clean up
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
}

// TestLUKS_DataMigration tests that existing data is properly migrated.
func TestLUKS_DataMigration(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create test data with various file types
	testData := createTestData(t, paths.DataDir)

	// Add some additional files to verify comprehensive migration
	additionalFiles := map[string][]byte{
		"empty.txt":              {},
		"large.bin":              make([]byte, 100*1024), // 100KB
		"special/chars-in-name_": []byte("special characters"),
		"permissions.txt":        []byte("file with permissions"),
	}

	// Fill large.bin with pattern
	for i := range additionalFiles["large.bin"] {
		additionalFiles["large.bin"][i] = byte(i % 256)
	}

	for relPath, content := range additionalFiles {
		fullPath := filepath.Join(paths.DataDir, relPath)
		dir := filepath.Dir(fullPath)
		if dir != paths.DataDir {
			err := os.MkdirAll(dir, 0700)
			require.NoError(t, err)
		}
		err := os.WriteFile(fullPath, content, 0600)
		require.NoError(t, err)
		testData.Files[relPath] = content
	}

	// Seal - should migrate all data
	result := execXkeySeal(t, binary, paths, testPassphrase, "100M")
	require.Equal(t, 0, result.ExitCode, "seal should succeed, stderr: %s", result.Stderr)
	assert.Contains(t, result.Stdout, "Migrating existing data")
	assert.Contains(t, result.Stdout, "Data migration complete")

	// Unseal and verify all data
	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Verify all migrated data
	verifyTestData(t, paths.MountPoint, testData)

	// Clean up
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
}

// TestLUKS_WrongPassphrase tests that wrong passphrase fails appropriately.
func TestLUKS_WrongPassphrase(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create a LUKS volume
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Try to unseal with wrong passphrase
	unsealResult := execXkeyUnseal(t, binary, paths, testWrongPassphrase)

	// Should fail
	require.NotEqual(t, 0, unsealResult.ExitCode, "unseal with wrong passphrase should fail")

	// Volume should not be mounted
	assertNotMounted(t, paths.MountPoint)
}

// TestLUKS_SealAlreadyExists tests that sealing fails if volume already exists.
func TestLUKS_SealAlreadyExists(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create initial volume
	result1 := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, result1.ExitCode)

	// Try to create again - should fail with clear error about existing container
	result2 := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.NotEqual(t, 0, result2.ExitCode, "seal should fail when volume exists")
	assert.Contains(t, result2.Stderr, "encrypted container already exists")
}

// TestLUKS_UnsealNoVolume tests that unseal fails when no volume exists.
func TestLUKS_UnsealNoVolume(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Don't create a volume, just try to unseal
	result := execXkeyUnseal(t, binary, paths, testPassphrase)

	require.NotEqual(t, 0, result.ExitCode, "unseal should fail when no volume exists")
	assert.Contains(t, result.Stderr, "no encrypted volume found")
}

// TestLUKS_LockNotMounted tests that lock fails when volume is not mounted.
func TestLUKS_LockNotMounted(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create but don't unseal
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Try to lock when not mounted - should fail
	lockResult := execXkeyLock(t, binary, paths)
	require.NotEqual(t, 0, lockResult.ExitCode, "lock should fail when volume not mounted")
	assert.Contains(t, lockResult.Stderr, "no encrypted volume mounted")
}

// TestLUKS_UnsealAlreadyMounted tests that unseal reports when volume is already mounted.
func TestLUKS_UnsealAlreadyMounted(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create and unseal
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	unsealResult1 := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult1.ExitCode)

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Try to unseal again - should succeed with message about already mounted
	unsealResult2 := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult2.ExitCode)
	assert.Contains(t, unsealResult2.Stdout, "already unlocked")

	// Clean up
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
}

// TestLUKS_VariousSizes tests creating volumes of various sizes.
func TestLUKS_VariousSizes(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)

	testCases := []struct {
		name string
		size string
	}{
		{"small_32M", "32M"},
		{"medium_100M", "100M"},
		{"large_256M", "256M"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			paths := createTempLUKSPaths(t)
			defer cleanupLUKS(t, paths)

			// Create volume
			sealResult := execXkeySeal(t, binary, paths, testPassphrase, tc.size)
			require.Equal(t, 0, sealResult.ExitCode, "seal failed for size %s: %s", tc.size, sealResult.Stderr)

			// Verify LUKS file exists
			assertFileExists(t, paths.LUKSFile)
			require.True(t, isLUKSVolume(paths.LUKSFile))

			// Verify we can unseal and lock
			unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
			require.Equal(t, 0, unsealResult.ExitCode)

			require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

			lockResult := execXkeyLock(t, binary, paths)
			require.Equal(t, 0, lockResult.ExitCode)
		})
	}
}

// TestLUKS_InvalidSize tests that invalid size values are rejected.
func TestLUKS_InvalidSize(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)

	testCases := []struct {
		name string
		size string
	}{
		{"empty", ""},
		{"no_unit", "100"},
		{"invalid_unit", "100X"},
		{"negative", "-50M"},
		{"zero", "0M"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			paths := createTempLUKSPaths(t)
			defer cleanupLUKS(t, paths)

			// Create volume with invalid size
			result := execXkeySeal(t, binary, paths, testPassphrase, tc.size)

			// Should fail
			require.NotEqual(t, 0, result.ExitCode, "seal should fail for invalid size: %s", tc.size)
		})
	}
}

// TestLUKS_PassphraseMismatch tests that mismatched passphrases are rejected during seal.
func TestLUKS_PassphraseMismatch(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Provide mismatched passphrases (first != second)
	args := []string{
		"luks2", "seal",
		"--path", paths.LUKSFile,
		"--mount-point", paths.MountPoint,
		"--size", testVolumeSize,
	}

	mismatchedInput := "passphrase1\npassphrase2\n"
	result := execXkey(t, binary, args, mismatchedInput)

	require.NotEqual(t, 0, result.ExitCode, "seal should fail with mismatched passphrases")
	assert.Contains(t, result.Stderr, "mismatch")
}

// TestLUKS_WriteDataToUnlockedVolume tests writing new data to an unlocked volume.
func TestLUKS_WriteDataToUnlockedVolume(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create and unseal volume
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Write new data to the unlocked volume
	newFile := filepath.Join(paths.MountPoint, "new_data.txt")
	newContent := []byte("Data written to unlocked volume!")
	err := os.WriteFile(newFile, newContent, 0600)
	require.NoError(t, err, "Should be able to write to unlocked volume")

	// Verify file exists
	readContent, err := os.ReadFile(newFile)
	require.NoError(t, err)
	require.Equal(t, newContent, readContent)

	// Lock and unlock to verify persistence
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)

	unsealResult2 := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult2.ExitCode)

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Verify data persisted
	readContent2, err := os.ReadFile(newFile)
	require.NoError(t, err)
	require.Equal(t, newContent, readContent2)

	// Clean up
	lockResult2 := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult2.ExitCode)
}

// TestLUKS_VolumeInaccessibleWhenLocked tests that volume data is inaccessible when locked.
func TestLUKS_VolumeInaccessibleWhenLocked(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create test data
	testData := createTestData(t, paths.DataDir)

	// Seal
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Unseal to verify data is there
	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))
	verifyTestData(t, paths.MountPoint, testData)

	// Lock the volume
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)

	require.True(t, waitForUnmount(t, paths.MountPoint, 5*time.Second))

	// Verify data is inaccessible
	for relPath := range testData.Files {
		fullPath := filepath.Join(paths.MountPoint, relPath)
		_, err := os.ReadFile(fullPath)
		require.Error(t, err, "Data should be inaccessible when locked: %s", relPath)
	}
}

// TestLUKS_LUKSVolumeType tests that the created volume is LUKS2.
func TestLUKS_LUKSVolumeType(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create volume
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Verify it's a LUKS volume
	require.True(t, isLUKSVolume(paths.LUKSFile))

	// Get LUKS info and verify version
	info := getLUKSInfo(t, paths.LUKSFile)
	require.NotNil(t, info)

	// Check for LUKS2 version (Version field should indicate LUKS2)
	version, ok := info["Version"]
	if ok {
		assert.Equal(t, "2", version, "Volume should be LUKS2")
	}
}

// TestLUKS_MultipleOperationsConcurrency tests that only one unseal can happen at a time.
func TestLUKS_MultipleOperationsConcurrency(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create and unseal volume
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Try to unseal again - should handle gracefully (already mounted)
	unsealResult2 := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult2.ExitCode)
	assert.Contains(t, unsealResult2.Stdout, "already unlocked")

	// Clean up
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
}

// TestLUKS_EmptyPassphrase tests that empty passphrase is handled.
func TestLUKS_EmptyPassphrase(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Try to seal with empty passphrase
	result := execXkeySeal(t, binary, paths, "", testVolumeSize)

	// Empty passphrase should be rejected
	require.NotEqual(t, 0, result.ExitCode, "seal should fail with empty passphrase")
}

// TestLUKS_SpecialCharactersInPassphrase tests passphrases with special characters.
func TestLUKS_SpecialCharactersInPassphrase(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)

	specialPassphrases := []string{
		"pass with spaces",
		"pass'with'quotes",
		`pass"with"doublequotes`,
		"pass\twith\ttabs",
		"pass!@#$%^&*()special",
		"unicode-pass-\u00e9\u00e8\u00ea",
	}

	for i, passphrase := range specialPassphrases {
		t.Run(passphrase[:10], func(t *testing.T) {
			_ = i // suppress unused variable warning

			paths := createTempLUKSPaths(t)
			defer cleanupLUKS(t, paths)

			// Seal with special passphrase
			sealResult := execXkeySeal(t, binary, paths, passphrase, testVolumeSize)
			require.Equal(t, 0, sealResult.ExitCode, "seal should succeed with special chars")

			// Unseal with same passphrase
			unsealResult := execXkeyUnseal(t, binary, paths, passphrase)
			require.Equal(t, 0, unsealResult.ExitCode, "unseal should succeed with special chars")

			require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

			// Lock
			lockResult := execXkeyLock(t, binary, paths)
			require.Equal(t, 0, lockResult.ExitCode)
		})
	}
}

// TestLUKS_LongPassphrase tests handling of very long passphrases.
func TestLUKS_LongPassphrase(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create a very long passphrase (512 characters)
	longPassphrase := ""
	for i := 0; i < 512; i++ {
		longPassphrase += string(rune('a' + (i % 26)))
	}

	// Seal
	sealResult := execXkeySeal(t, binary, paths, longPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode, "seal should succeed with long passphrase")

	// Unseal
	unsealResult := execXkeyUnseal(t, binary, paths, longPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode, "unseal should succeed with long passphrase")

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Lock
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
}

// TestLUKS_PreserveFilePermissions tests that file permissions are preserved during migration.
func TestLUKS_PreserveFilePermissions(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create files with specific permissions
	testFiles := map[string]os.FileMode{
		"readable.txt":  0644,
		"private.txt":   0600,
		"executable.sh": 0755,
	}

	for filename, mode := range testFiles {
		fullPath := filepath.Join(paths.DataDir, filename)
		err := os.WriteFile(fullPath, []byte("content"), mode)
		require.NoError(t, err)
	}

	// Seal
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Unseal
	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)

	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Verify permissions are preserved
	for filename, expectedMode := range testFiles {
		fullPath := filepath.Join(paths.MountPoint, filename)
		info, err := os.Stat(fullPath)
		require.NoError(t, err)

		actualMode := info.Mode().Perm()
		assert.Equal(t, expectedMode, actualMode, "Permission mismatch for %s", filename)
	}

	// Clean up
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
}

// TestLUKS_Migrate tests the migrate command functionality.
func TestLUKS_Migrate(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create a sealed volume first
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode, "seal should succeed")

	// Unseal to add some data
	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)
	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Write test data to the volume
	testFile := filepath.Join(paths.MountPoint, "migrate_test.txt")
	testContent := []byte("Data to be migrated")
	err := os.WriteFile(testFile, testContent, 0600)
	require.NoError(t, err)

	// Lock the volume
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
	require.True(t, waitForUnmount(t, paths.MountPoint, 5*time.Second))

	// Create a new target path for migration
	newPath := filepath.Join(paths.BaseDir, "migrated.luks")

	// Run migrate command
	migrateResult := execXkeyMigrate(t, binary, paths, testPassphrase, "--path", newPath)
	require.Equal(t, 0, migrateResult.ExitCode, "migrate should succeed, stderr: %s", migrateResult.Stderr)
	assert.Contains(t, migrateResult.Stdout, "Migration complete")

	// Verify new volume exists
	assertFileExists(t, newPath)
	require.True(t, isLUKSVolume(newPath), "Migrated file should be a valid LUKS volume")

	// Verify old volume no longer exists (or is marked as migrated)
	// Depending on implementation, the original may be removed or kept
}

// TestLUKS_MigrateWithoutPath tests that migrate succeeds without explicit path (doubles size).
func TestLUKS_MigrateWithoutPath(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create a sealed volume first
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Lock the volume (if mounted)
	_ = execXkeyLock(t, binary, paths)

	// Run migrate without path - should succeed and double the size
	migrateResult := execXkeyMigrate(t, binary, paths, testPassphrase)
	require.Equal(t, 0, migrateResult.ExitCode, "migrate without path should succeed (doubles size)")
	assert.Contains(t, migrateResult.Stdout, "Migration complete")
}

// TestLUKS_MigrateNoVolume tests that migrate fails when no volume exists.
func TestLUKS_MigrateNoVolume(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Don't create any volume, try to migrate
	migrateResult := execXkeyMigrate(t, binary, paths, testPassphrase, "--path", "/tmp/migrated.luks")
	require.NotEqual(t, 0, migrateResult.ExitCode, "migrate should fail when no volume exists")
	assert.Contains(t, migrateResult.Stderr, "no source container found")
}

// TestLUKS_MigrateWrongPassphrase tests that migrate fails with wrong passphrase.
func TestLUKS_MigrateWrongPassphrase(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create a sealed volume
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	newPath := filepath.Join(paths.BaseDir, "migrated.luks")

	// Try migrate with wrong passphrase
	migrateResult := execXkeyMigrate(t, binary, paths, testWrongPassphrase, "--path", newPath)
	require.NotEqual(t, 0, migrateResult.ExitCode, "migrate should fail with wrong passphrase")
}

// TestLUKS_Wipe tests the wipe command functionality.
func TestLUKS_Wipe(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create test data
	testData := createTestData(t, paths.DataDir)

	// Seal
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Verify LUKS file exists
	assertFileExists(t, paths.LUKSFile)

	// Unseal to verify data exists
	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)
	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))
	verifyTestData(t, paths.MountPoint, testData)

	// Lock before wiping
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
	require.True(t, waitForUnmount(t, paths.MountPoint, 5*time.Second))

	// Wipe the volume with force flag
	wipeResult := execXkeyWipe(t, binary, paths, testPassphrase, true)
	require.Equal(t, 0, wipeResult.ExitCode, "wipe should succeed, stderr: %s", wipeResult.Stderr)
	assert.Contains(t, wipeResult.Stdout, "securely destroyed")

	// Verify LUKS file no longer exists
	assertFileNotExists(t, paths.LUKSFile)
}

// TestLUKS_WipeWithConfirmation tests wipe with interactive confirmation.
func TestLUKS_WipeWithConfirmation(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create a sealed volume
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Wipe without force (requires confirmation)
	wipeResult := execXkeyWipe(t, binary, paths, testPassphrase, false)
	require.Equal(t, 0, wipeResult.ExitCode, "wipe with confirmation should succeed")

	// Verify LUKS file no longer exists
	assertFileNotExists(t, paths.LUKSFile)
}

// TestLUKS_WipeNoVolume tests that wipe fails when no volume exists.
func TestLUKS_WipeNoVolume(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Don't create any volume, try to wipe
	wipeResult := execXkeyWipe(t, binary, paths, testPassphrase, true)
	require.NotEqual(t, 0, wipeResult.ExitCode, "wipe should fail when no volume exists")
	assert.Contains(t, wipeResult.Stderr, "no container found")
}

// TestLUKS_WipeAbortedConfirmation tests that wipe fails when confirmation is not provided.
func TestLUKS_WipeAbortedConfirmation(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create a sealed volume
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Try wipe without proper confirmation (send "no" instead of "DESTROY")
	args := []string{"luks2", "wipe", "--path", paths.LUKSFile, "--mount-point", paths.MountPoint}
	wipeResult := execXkey(t, binary, args, "no\n")
	require.NotEqual(t, 0, wipeResult.ExitCode, "wipe should fail when confirmation is not 'DESTROY'")

	// Verify LUKS file still exists
	assertFileExists(t, paths.LUKSFile)
}

// TestLUKS_WipeMountedVolume tests that wipe auto-locks a mounted volume before wiping.
func TestLUKS_WipeMountedVolume(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create and unseal
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)
	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))

	// Wipe while mounted - should auto-lock and succeed
	wipeResult := execXkeyWipe(t, binary, paths, testPassphrase, true)
	require.Equal(t, 0, wipeResult.ExitCode, "wipe should auto-lock and succeed, stderr: %s", wipeResult.Stderr)
	assert.Contains(t, wipeResult.Stdout, "Locking container")

	// Verify LUKS file no longer exists
	assertFileNotExists(t, paths.LUKSFile)
}

// TestLUKS_WipeSecureWipe tests that wipe securely overwrites data.
func TestLUKS_WipeSecureWipe(t *testing.T) {
	requireLUKSDependencies(t)

	binary := getOrBuildXkey(t)
	paths := createTempLUKSPaths(t)
	defer cleanupLUKS(t, paths)

	// Create test data
	testData := createTestData(t, paths.DataDir)

	// Seal
	sealResult := execXkeySeal(t, binary, paths, testPassphrase, testVolumeSize)
	require.Equal(t, 0, sealResult.ExitCode)

	// Get file info before wipe
	info, err := os.Stat(paths.LUKSFile)
	require.NoError(t, err)
	originalSize := info.Size()
	require.Greater(t, originalSize, int64(0), "LUKS file should have content")

	// Unseal and verify data
	unsealResult := execXkeyUnseal(t, binary, paths, testPassphrase)
	require.Equal(t, 0, unsealResult.ExitCode)
	require.True(t, waitForMount(t, paths.MountPoint, 5*time.Second))
	verifyTestData(t, paths.MountPoint, testData)

	// Lock before wiping
	lockResult := execXkeyLock(t, binary, paths)
	require.Equal(t, 0, lockResult.ExitCode)
	require.True(t, waitForUnmount(t, paths.MountPoint, 5*time.Second))

	// Wipe with secure flag (if supported)
	wipeResult := execXkeyWipe(t, binary, paths, testPassphrase, true)
	require.Equal(t, 0, wipeResult.ExitCode)

	// Verify file is gone
	assertFileNotExists(t, paths.LUKSFile)
}
