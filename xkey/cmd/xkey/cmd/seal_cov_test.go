// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateExistingData_StagingUnavailableTouchesNothing(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))

	fake := &fakeMigrateVolume{mountPoint: dataDir}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "correct-horse")

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "create_temp", sealErr.Operation)
	assert.Zero(t, fake.unlockCalls, "the volume must not be unlocked without a staged copy")

	data, readErr := os.ReadFile(filepath.Join(dataDir, "secret.txt"))
	require.NoError(t, readErr)
	assert.Equal(t, "top secret", string(data))
}

func TestMigrateExistingData_CopyFailureReportsFailedLock(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")
	t.Setenv("TMPDIR", t.TempDir())

	copyErr := errors.New("disk full")
	lockErr := errors.New("device busy")
	fake := &fakeMigrateVolume{
		mountPoint: dataDir,
		copyFn:     func(string) error { return copyErr },
		lockFn:     func() error { return lockErr },
	}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "correct-horse")
	require.ErrorIs(t, err, copyErr)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "migrate_data", sealErr.Operation)
	assert.Contains(t, out.String(), "Warning: could not lock volume: device busy")
	assert.FileExists(t, filepath.Join(extractStagingPath(t, out.String()), "secret.txt"))
}

func TestMigrateExistingData_VerifyFailureReportsFailedLock(t *testing.T) {
	dataDir := t.TempDir()
	writeTestFile(t, filepath.Join(dataDir, "secret.txt"), "top secret")
	t.Setenv("TMPDIR", t.TempDir())

	fake := &fakeMigrateVolume{
		mountPoint: dataDir,
		copyFn: func(string) error {
			return os.WriteFile(filepath.Join(dataDir, "secret.txt"), []byte("truncated"), 0o600)
		},
		lockFn: func() error { return errors.New("device busy") },
	}

	var out bytes.Buffer
	err := migrateExistingData(&out, fake, "correct-horse")

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "verify_migration", sealErr.Operation)
	assert.Contains(t, out.String(), "Warning: could not lock volume: device busy")
	assert.FileExists(t, filepath.Join(extractStagingPath(t, out.String()), "secret.txt"))
}

func TestReadPassphraseFromStdin_ReadFailureIsSealError(t *testing.T) {
	closeStdin(t)

	var out bytes.Buffer
	got, err := readPassphraseFromStdin(&out)
	require.ErrorIs(t, err, os.ErrClosed)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "read_passphrase", sealErr.Operation)
	assert.Empty(t, got)
}

func TestCreateSealVolume_FallsBackToXKeyHome(t *testing.T) {
	assertVolumeFallsBackToXKeyHome(t, createSealVolume)
}

func TestCreateSealVolume_UnresolvableHomeIsError(t *testing.T) {
	assertVolumeReportsUnresolvableHome(t, createSealVolume)
}

func TestVerifyDirCopy_ReportsDirectoryMismatch(t *testing.T) {
	tests := []struct {
		name    string
		dst     func(t *testing.T, dst string)
		path    string
		message string
	}{
		{
			name:    "missing directory",
			dst:     func(*testing.T, string) {},
			path:    "keys",
			message: "missing directory in destination",
		},
		{
			name: "directory replaced by a file",
			dst: func(t *testing.T, dst string) {
				writeTestFile(t, filepath.Join(dst, "keys"), "not a directory")
			},
			path:    "keys",
			message: "expected a directory in destination",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(src, "keys"), 0o700))
			writeTestFile(t, filepath.Join(src, "keys", "a.key"), "key material")
			tt.dst(t, dst)

			var verr *DataVerificationError
			require.ErrorAs(t, verifyDirCopy(src, dst), &verr)
			assert.Equal(t, tt.path, verr.Path)
			assert.Equal(t, tt.message, verr.Message)
		})
	}
}

func TestVerifyDirCopy_MissingSourceIsWalkError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")

	var verr *DataVerificationError
	require.ErrorAs(t, verifyDirCopy(missing, t.TempDir()), &verr)
	assert.Equal(t, "failed to walk source", verr.Message)
	assert.ErrorIs(t, verr, os.ErrNotExist)
}
