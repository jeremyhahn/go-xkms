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
	"crypto/rand"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileBackupAdapter_NewFileBackupAdapter_LoadIndexPermissionError exercises
// the loadIndex error-propagation path in NewFileBackupAdapter. Unlike a
// missing directory (which loadIndex tolerates), a directory that exists but
// cannot be read must surface as a wrapped error from NewFileBackupAdapter.
func TestFileBackupAdapter_NewFileBackupAdapter_LoadIndexPermissionError(t *testing.T) {
	skipIfRoot(t)

	tempDir := t.TempDir()
	restrictedDir := filepath.Join(tempDir, "restricted")
	require.NoError(t, os.Mkdir(restrictedDir, 0755))

	// Remove read+execute permission so os.ReadDir fails with a permission
	// error (not os.IsNotExist) inside loadIndex.
	require.NoError(t, os.Chmod(restrictedDir, 0300))
	defer func() { _ = os.Chmod(restrictedDir, 0755) }()

	_, err := NewFileBackupAdapter(restrictedDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load backup index")
}

// TestFileBackupAdapter_CreateBackup_VersionDefaultWithExistingMetadata verifies
// that a caller-supplied BackupMetadata with an empty Version field is
// defaulted to DefaultBackupVersion rather than left blank.
func TestFileBackupAdapter_CreateBackup_VersionDefaultWithExistingMetadata(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	data := createTestBackupData(t, 1)
	data.Metadata = &BackupMetadata{
		// Version intentionally left blank.
	}

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)
	require.NotNil(t, metadata)
	assert.Equal(t, DefaultBackupVersion, metadata.Version)
}

// TestFileBackupAdapter_CreateBackup_RestoresTPMSessionCloserOnError exercises
// the SessionCloser clear/restore closures in CreateBackup. encoding/json
// rejects a struct containing a func-typed field based on its static type
// regardless of whether the value is nil, so once any key carries a non-nil
// TPMAttributes, serialization always fails - but the clear-then-restore
// defer must still run, leaving the caller's in-memory SessionCloser intact
// and uninvoked.
func TestFileBackupAdapter_CreateBackup_RestoresTPMSessionCloserOnError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	data := createTestBackupData(t, 2)

	closed := make([]bool, len(data.Keys))
	for i, key := range data.Keys {
		idx := i
		key.Attributes.TPMAttributes = &types.TPMAttributes{
			SessionCloser: func() error {
				closed[idx] = true
				return nil
			},
		}
	}

	_, err = adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to serialize backup")

	for i, key := range data.Keys {
		require.NotNil(t, key.Attributes.TPMAttributes.SessionCloser)
		assert.False(t, closed[i], "SessionCloser must not be invoked by CreateBackup")
	}
}

// TestFileBackupAdapter_CreateBackup_SerializationError forces json.Marshal to
// fail on the backup payload by embedding a value that JSON cannot encode
// (+Inf), verifying the wrapped serialization error is returned.
func TestFileBackupAdapter_CreateBackup_SerializationError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	data := createTestBackupData(t, 1)
	data.Metadata = &BackupMetadata{
		Metadata: map[string]interface{}{
			"bad": math.Inf(1),
		},
	}

	_, err = adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to serialize backup")
}

// TestFileBackupAdapter_ListBackups_StartTimeExcludesBackup exercises the
// StartTime exclusion branch, which is distinct from the EndTime exclusion
// branch already covered elsewhere.
func TestFileBackupAdapter_ListBackups_StartTimeExcludesBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	data := createTestBackupData(t, 1)
	_, err = adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	// A StartTime in the future must exclude the backup just created.
	future := time.Now().Add(1 * time.Hour)
	backups, err := adapter.ListBackups(ctx, &ListOptions{StartTime: &future})
	require.NoError(t, err)
	assert.Empty(t, backups)
}

// TestFileBackupAdapter_DeleteBackup_MetadataRemoveErrorNonEmptyDir replaces
// the metadata file with a non-empty directory at the exact same path so
// that the backup payload file is removed successfully but the metadata
// removal fails, exercising the metadata-removal error branch in isolation.
func TestFileBackupAdapter_DeleteBackup_MetadataRemoveErrorNonEmptyDir(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	data := createTestBackupData(t, 1)
	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	metadataPath := adapter.getMetadataPath(metadata.ID)
	require.NoError(t, os.Remove(metadataPath))
	require.NoError(t, os.Mkdir(metadataPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPath, "occupied"), []byte("x"), 0600))

	err = adapter.DeleteBackup(ctx, metadata.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove metadata file")

	// The backup payload file was removed before the metadata removal failed.
	assert.NoFileExists(t, adapter.getBackupPath(metadata.ID))
}

// TestFileBackupAdapter_ExportBackup_DestDirCreationError places a regular
// file where a destination subdirectory needs to be created, forcing
// os.MkdirAll to fail with ENOTDIR rather than the later WriteFile call.
func TestFileBackupAdapter_ExportBackup_DestDirCreationError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	data := createTestBackupData(t, 1)
	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	destination := filepath.Join(blocker, "sub", "export.backup")
	_, err = adapter.ExportBackup(ctx, metadata.ID, destination)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create destination directory")
}

// TestFileBackupAdapter_ImportBackup_MetadataFileWriteError pre-creates a
// non-empty directory at the exact metadata path that ImportBackup will
// attempt to write to (using a caller-supplied, predictable backup ID),
// forcing the metadata os.WriteFile call to fail with EISDIR after the
// backup payload file has already been written successfully.
func TestFileBackupAdapter_ImportBackup_MetadataFileWriteError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	const backupID = "predictable-import-id"

	metadataPath := adapter.getMetadataPath(backupID)
	require.NoError(t, os.Mkdir(metadataPath, 0700))

	backupData := &BackupData{
		Metadata: &BackupMetadata{ID: backupID, Format: BackupFormatJSON},
		Keys:     []*BackupKey{{ID: "key-1"}},
	}
	sourceBytes, err := json.Marshal(backupData)
	require.NoError(t, err)

	sourcePath := filepath.Join(t.TempDir(), "source.backup")
	require.NoError(t, os.WriteFile(sourcePath, sourceBytes, 0600))

	_, err = adapter.ImportBackup(ctx, sourcePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write metadata file")

	// The backup payload file must be cleaned up after the metadata write
	// failure.
	assert.NoFileExists(t, adapter.getBackupPath(backupID))
}

// TestFileBackupAdapter_GetBackupMetadata_ReadPermissionDenied writes a
// metadata file directly to disk (bypassing the in-memory index) and
// removes all permissions from it, forcing os.ReadFile to fail with a
// permission error distinct from the "does not exist" case.
func TestFileBackupAdapter_GetBackupMetadata_ReadPermissionDenied(t *testing.T) {
	skipIfRoot(t)

	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	const backupID = "perm-denied-id"
	metadataPath := adapter.getMetadataPath(backupID)
	require.NoError(t, os.WriteFile(metadataPath, []byte("{}"), 0600))
	require.NoError(t, os.Chmod(metadataPath, 0000))
	defer func() { _ = os.Chmod(metadataPath, 0600) }()

	_, err = adapter.getBackupMetadata(backupID)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrBackupNotFound)
	assert.Contains(t, err.Error(), "failed to read metadata file")
}

// errorReader always fails, used to simulate crypto/rand.Reader exhaustion.
type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) {
	return 0, os.ErrClosed
}

// TestFileBackupAdapter_EncryptData_NonceGenerationFailure swaps out
// crypto/rand.Reader with a reader that always fails, exercising the nonce
// generation error branch in encryptData.
func TestFileBackupAdapter_EncryptData_NonceGenerationFailure(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	originalReader := rand.Reader
	rand.Reader = errorReader{}
	defer func() { rand.Reader = originalReader }()

	key := make([]byte, 32)
	_, err = adapter.encryptData([]byte("plaintext"), key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate nonce")
}
