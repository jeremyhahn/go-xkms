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

package backup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plantOutsideMetadata writes a metadata file one directory above base,
// where a "../" backup ID would resolve, and returns that ID.
func plantOutsideMetadata(t *testing.T, base string) string {
	t.Helper()
	outside, err := json.Marshal(&BackupMetadata{ID: "outside", Checksum: "x"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(base), "outside.metadata.json"), outside, 0600))
	return "../outside"
}

func TestGetBackup_TraversalIDRefused(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "backups")
	adapter, err := NewFileBackupAdapter(base)
	require.NoError(t, err)
	id := plantOutsideMetadata(t, base)

	_, err = adapter.GetBackup(context.Background(), id)
	assert.ErrorIs(t, err, ErrInvalidBackupID)

	_, err = adapter.RestoreBackup(context.Background(), id, &RestoreOptions{DryRun: true})
	assert.ErrorIs(t, err, ErrInvalidBackupID)

	result, err := adapter.VerifyBackup(context.Background(), id, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	require.NotEmpty(t, result.Errors)
	assert.ErrorIs(t, result.Errors[0], ErrInvalidBackupID)
}

func TestGetBackup_UUIDStillResolvesFromDisk(t *testing.T) {
	base := t.TempDir()
	adapter, err := NewFileBackupAdapter(base)
	require.NoError(t, err)

	// A metadata file written after the index was loaded is still found by
	// its (valid) ID.
	const id = "8d4f1c2a-6b3e-4f7d-9e0a-1c5b2d3e4f60"
	data, err := json.Marshal(&BackupMetadata{ID: id})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(adapter.getMetadataPath(id), data, 0600))

	got, err := adapter.GetBackup(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)
}

func TestLoadIndex_SkipsNonUUIDRecords(t *testing.T) {
	base := t.TempDir()
	const valid = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	for name, id := range map[string]string{
		valid + ".metadata.json": valid,
		"evil.metadata.json":     "../../etc/cron.d/evil",
	} {
		data, err := json.Marshal(&BackupMetadata{ID: id})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(base, name), data, 0600))
	}

	adapter, err := NewFileBackupAdapter(base)
	require.NoError(t, err)

	assert.Contains(t, adapter.index, valid)
	assert.NotContains(t, adapter.index, "../../etc/cron.d/evil")

	// DeleteBackup trusts index membership, so the skipped record can never
	// steer its os.Remove outside the backup directory.
	assert.ErrorIs(t, adapter.DeleteBackup(context.Background(), "../../etc/cron.d/evil"), ErrBackupNotFound)
}
