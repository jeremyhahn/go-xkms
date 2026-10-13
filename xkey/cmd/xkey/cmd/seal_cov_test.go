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
