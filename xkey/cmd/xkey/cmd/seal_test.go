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

package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extractStagingPath pulls the staging directory path out of the
// "staged copy preserved at <path>" message migrateExistingData writes on
// failure, so tests can assert the directory really is still there.
func extractStagingPath(t *testing.T, output string) string {
	t.Helper()
	const marker = "staged copy preserved at "
	idx := strings.Index(output, marker)
	require.GreaterOrEqual(t, idx, 0, "output must report the staging path: %q", output)
	rest := output[idx+len(marker):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	return strings.TrimSpace(rest)
}

// fakeMigrateVolume stands in for *luks.Volume in migrateExistingData tests.
// By default every operation succeeds and touches no disk state beyond
// what the test itself sets up, so a source directory that migrateExistingData
// never deletes still has its original content at the end of a test.
type fakeMigrateVolume struct {
	mountPoint string
	unlockFn   func(passphrase string) error
	copyFn     func(sourceDir string) error
	lockFn     func() error

	unlockCalls int
	copyCalls   int
	lockCalls   int
}

func (f *fakeMigrateVolume) GetMountPoint() string { return f.mountPoint }

func (f *fakeMigrateVolume) Unlock(passphrase string) error {
	f.unlockCalls++
	if f.unlockFn != nil {
		return f.unlockFn(passphrase)
	}
	return nil
}

func (f *fakeMigrateVolume) CopyDataToVolume(sourceDir string) error {
	f.copyCalls++
	if f.copyFn != nil {
		return f.copyFn(sourceDir)
	}
	return nil
}

func (f *fakeMigrateVolume) Lock() error {
	f.lockCalls++
	if f.lockFn != nil {
		return f.lockFn()
	}
	return nil
}

// writeTestFile creates a file with the given content, failing the test on
// error.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
}

// TestMigrateExistingData_Success verifies the happy path: the source is
// staged, "copied" into the volume, verified, the volume is locked, and
// only then is the plaintext source removed along with the now-redundant
// staging copy.
func TestMigrateExistingData_Success(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")

	fake := &fakeMigrateVolume{mountPoint: dataDir}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "correct-horse")
	require.NoError(t, err)

	assert.Equal(t, 1, fake.unlockCalls)
	assert.Equal(t, 1, fake.copyCalls)
	assert.Equal(t, 1, fake.lockCalls)

	assert.NoDirExists(t, dataDir, "plaintext source must be removed after a verified migration")
	assert.Contains(t, out.String(), "Data migration complete.")
}

// TestMigrateExistingData_UnlockFailure_PreservesSourceAndStaging verifies
// that when Unlock fails, the plaintext source is untouched and the staged
// copy is kept and reported rather than deleted.
func TestMigrateExistingData_UnlockFailure_PreservesSourceAndStaging(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")

	unlockErr := errors.New("wrong passphrase")
	fake := &fakeMigrateVolume{
		mountPoint: dataDir,
		unlockFn:   func(string) error { return unlockErr },
	}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "wrong-passphrase")
	require.Error(t, err)
	assert.ErrorIs(t, err, unlockErr)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "unlock_for_migration", sealErr.Operation)

	assert.Equal(t, 0, fake.copyCalls, "copy must not run after a failed unlock")
	assert.Equal(t, 0, fake.lockCalls, "there is nothing to lock after a failed unlock")

	// The source must survive untouched.
	data, readErr := os.ReadFile(filepath.Join(dataDir, "secret.txt"))
	require.NoError(t, readErr)
	assert.Equal(t, "top secret", string(data))

	stagingDir := extractStagingPath(t, out.String())
	staged, stagedErr := os.ReadFile(filepath.Join(stagingDir, "secret.txt"))
	require.NoError(t, stagedErr, "the staging copy must still be on disk")
	assert.Equal(t, "top secret", string(staged))
}

// TestMigrateExistingData_CopyFailure_PreservesSourceAndStaging verifies
// that when CopyDataToVolume fails, the plaintext source is untouched, the
// volume is locked best-effort, and the staged copy is kept and reported.
func TestMigrateExistingData_CopyFailure_PreservesSourceAndStaging(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")

	copyErr := errors.New("disk full")
	fake := &fakeMigrateVolume{
		mountPoint: dataDir,
		copyFn:     func(string) error { return copyErr },
	}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "correct-horse")
	require.Error(t, err)
	assert.ErrorIs(t, err, copyErr)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "migrate_data", sealErr.Operation)

	assert.Equal(t, 1, fake.lockCalls, "a best-effort lock must be attempted after a copy failure")

	data, readErr := os.ReadFile(filepath.Join(dataDir, "secret.txt"))
	require.NoError(t, readErr)
	assert.Equal(t, "top secret", string(data))

	stagingDir := extractStagingPath(t, out.String())
	staged, stagedErr := os.ReadFile(filepath.Join(stagingDir, "secret.txt"))
	require.NoError(t, stagedErr, "the staging copy must still be on disk")
	assert.Equal(t, "top secret", string(staged))
}

// TestMigrateExistingData_LockFailure_PreservesSourceAndStaging verifies
// that when the final Lock fails, the plaintext source is never removed
// and the staged copy is kept and reported. This is the exact scenario
// #1012 was filed against: a failure here must never leave the staging
// copy as the only surviving copy of the data.
func TestMigrateExistingData_LockFailure_PreservesSourceAndStaging(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")

	lockErr := errors.New("device or resource busy")
	fake := &fakeMigrateVolume{
		mountPoint: dataDir,
		lockFn:     func() error { return lockErr },
	}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "correct-horse")
	require.Error(t, err)
	assert.ErrorIs(t, err, lockErr)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "lock_after_migration", sealErr.Operation)

	// The source must never be removed when locking fails.
	data, readErr := os.ReadFile(filepath.Join(dataDir, "secret.txt"))
	require.NoError(t, readErr)
	assert.Equal(t, "top secret", string(data))

	stagingDir := extractStagingPath(t, out.String())
	staged, stagedErr := os.ReadFile(filepath.Join(stagingDir, "secret.txt"))
	require.NoError(t, stagedErr, "the staging copy must still be on disk")
	assert.Equal(t, "top secret", string(staged))
}

// TestMigrateExistingData_VerifyFailure_PreservesSourceAndStaging verifies
// that when the post-copy verification fails, the plaintext source is
// never removed, the volume is locked best-effort, and the staged copy is
// kept and reported.
func TestMigrateExistingData_VerifyFailure_PreservesSourceAndStaging(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")

	fake := &fakeMigrateVolume{
		mountPoint: dataDir,
		// Simulate a copy that silently truncates the file: CopyDataToVolume
		// reports success, but the destination doesn't match the staged data.
		copyFn: func(string) error {
			return os.WriteFile(filepath.Join(dataDir, "secret.txt"), []byte("truncated"), 0600)
		},
	}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "correct-horse")
	require.Error(t, err)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "verify_migration", sealErr.Operation)

	assert.Equal(t, 1, fake.lockCalls, "a best-effort lock must be attempted after a verify failure")
	assert.DirExists(t, dataDir, "the source must never be removed when verification fails")

	stagingDir := extractStagingPath(t, out.String())
	staged, stagedErr := os.ReadFile(filepath.Join(stagingDir, "secret.txt"))
	require.NoError(t, stagedErr, "the staging copy must still be on disk")
	assert.Equal(t, "top secret", string(staged))
}

// TestVerifyDirCopy_MatchingTrees verifies verifyDirCopy accepts a
// destination that mirrors the source's files, sizes and directory tree.
func TestVerifyDirCopy_MatchingTrees(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(src, "nested"), 0700))
	writeTestFile(t, filepath.Join(src, "top.txt"), "top")
	writeTestFile(t, filepath.Join(src, "nested", "leaf.txt"), "leaf")

	require.NoError(t, os.MkdirAll(filepath.Join(dst, "nested"), 0700))
	writeTestFile(t, filepath.Join(dst, "top.txt"), "top")
	writeTestFile(t, filepath.Join(dst, "nested", "leaf.txt"), "leaf")

	assert.NoError(t, verifyDirCopy(src, dst))
}

// TestVerifyDirCopy_SizeMismatchIsError verifies verifyDirCopy rejects a
// destination file whose size doesn't match the source.
func TestVerifyDirCopy_SizeMismatchIsError(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	writeTestFile(t, filepath.Join(src, "data.txt"), "the full original content")
	writeTestFile(t, filepath.Join(dst, "data.txt"), "short")

	err := verifyDirCopy(src, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size mismatch")
}

// TestVerifyDirCopy_MissingFileIsError verifies verifyDirCopy rejects a
// destination that is missing a file present in the source.
func TestVerifyDirCopy_MissingFileIsError(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	writeTestFile(t, filepath.Join(src, "data.txt"), "content")

	err := verifyDirCopy(src, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing file")
}
