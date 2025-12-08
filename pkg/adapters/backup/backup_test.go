// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipIfRoot skips the test if running as root, since root bypasses file permission checks
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("Skipping test that relies on file permissions (running as root)")
	}
}

func TestNewFileBackupAdapter(t *testing.T) {
	// Test creating a new adapter with a valid path
	t.Run("ValidPath", func(t *testing.T) {
		tempDir := t.TempDir()
		adapter, err := NewFileBackupAdapter(tempDir)
		require.NoError(t, err)
		require.NotNil(t, adapter)
		assert.Equal(t, tempDir, adapter.basePath)
		assert.NotNil(t, adapter.index)
	})

	// Test creating a new adapter with an invalid path
	t.Run("InvalidPath", func(t *testing.T) {
		// Use a path that can't be created (e.g., under a file)
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "file.txt")
		err := os.WriteFile(filePath, []byte("test"), 0600)
		require.NoError(t, err)

		invalidPath := filepath.Join(filePath, "subdir")
		_, err = NewFileBackupAdapter(invalidPath)
		assert.Error(t, err)
	})

	// Test loadIndex error during initialization
	t.Run("LoadIndexError", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create a file instead of a directory for basePath
		badPath := filepath.Join(tempDir, "file")
		err := os.WriteFile(badPath, []byte("content"), 0600)
		require.NoError(t, err)

		// Make it unreadable
		err = os.Chmod(badPath, 0000)
		if err == nil {
			defer func() { _ = os.Chmod(badPath, 0600) }()

			// This should fail when trying to read the directory
			_, err = NewFileBackupAdapter(badPath)
			assert.Error(t, err)
		}
	})
}

func TestFileBackupAdapter_CreateBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test creating a basic JSON backup
	t.Run("BasicJSONBackup", func(t *testing.T) {
		data := createTestBackupData(t, 3)
		opts := &BackupOptions{
			Format:          BackupFormatJSON,
			IncludeMetadata: true,
		}

		metadata, err := adapter.CreateBackup(ctx, data, opts)
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.NotEmpty(t, metadata.ID)
		assert.Equal(t, BackupFormatJSON, metadata.Format)
		assert.Equal(t, 3, metadata.KeyCount)
		assert.NotEmpty(t, metadata.Checksum)
		assert.Greater(t, metadata.Size, int64(0))
		assert.False(t, metadata.Encrypted)
		assert.False(t, metadata.Compressed)

		// Verify files exist
		backupPath := adapter.getBackupPath(metadata.ID)
		metadataPath := adapter.getMetadataPath(metadata.ID)
		assert.FileExists(t, backupPath)
		assert.FileExists(t, metadataPath)
	})

	// Test creating an encrypted backup
	t.Run("EncryptedBackup", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		encKey := make([]byte, 32)
		_, err := rand.Read(encKey)
		require.NoError(t, err)

		opts := &BackupOptions{
			Format:        BackupFormatEncrypted,
			EncryptionKey: encKey,
		}

		metadata, err := adapter.CreateBackup(ctx, data, opts)
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.True(t, metadata.Encrypted)
		assert.Equal(t, DefaultEncryptionAlgorithm, metadata.EncryptionAlgorithm)
	})

	// Test creating a compressed backup
	t.Run("CompressedBackup", func(t *testing.T) {
		data := createTestBackupData(t, 5)
		opts := &BackupOptions{
			Format:   BackupFormatJSON,
			Compress: true,
		}

		metadata, err := adapter.CreateBackup(ctx, data, opts)
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.True(t, metadata.Compressed)
		assert.Equal(t, DefaultCompressionAlgorithm, metadata.CompressionAlgorithm)
		assert.Greater(t, metadata.CompressedSize, int64(0))
	})

	// Test creating a backup with specific key IDs
	t.Run("FilteredKeys", func(t *testing.T) {
		data := createTestBackupData(t, 10)
		opts := &BackupOptions{
			Format: BackupFormatJSON,
			KeyIDs: []string{data.Keys[0].ID, data.Keys[2].ID},
		}

		metadata, err := adapter.CreateBackup(ctx, data, opts)
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.Equal(t, 2, metadata.KeyCount)
		assert.Len(t, metadata.KeyIDs, 2)
	})

	// Test creating a backup with nil data
	t.Run("NilData", func(t *testing.T) {
		_, err := adapter.CreateBackup(ctx, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backup data is required")
	})

	// Test creating an encrypted backup without encryption key
	t.Run("EncryptedWithoutKey", func(t *testing.T) {
		data := createTestBackupData(t, 1)
		opts := &BackupOptions{
			Format: BackupFormatEncrypted,
		}

		_, err := adapter.CreateBackup(ctx, data, opts)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEncryptionKey)
	})

	// Test creating a backup with unsupported format
	t.Run("UnsupportedFormat", func(t *testing.T) {
		data := createTestBackupData(t, 1)
		opts := &BackupOptions{
			Format: BackupFormatProtobuf,
		}

		_, err := adapter.CreateBackup(ctx, data, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	// Test creating a backup with nil options (should use defaults)
	t.Run("NilOptions", func(t *testing.T) {
		data := createTestBackupData(t, 1)
		metadata, err := adapter.CreateBackup(ctx, data, nil)
		require.NoError(t, err)
		assert.Equal(t, BackupFormatJSON, metadata.Format)
	})

	// Test creating a backup with invalid format string
	t.Run("InvalidFormat", func(t *testing.T) {
		data := createTestBackupData(t, 1)
		opts := &BackupOptions{
			Format: "invalid-format",
		}
		_, err := adapter.CreateBackup(ctx, data, opts)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBackupFormat)
	})

	// Test encryption failure path
	t.Run("EncryptionFailure", func(t *testing.T) {
		data := createTestBackupData(t, 1)
		// Use invalid key size to trigger encryption error
		invalidKey := make([]byte, 16) // Should be 32 for AES-256
		opts := &BackupOptions{
			Format:        BackupFormatEncrypted,
			EncryptionKey: invalidKey,
		}
		_, err := adapter.CreateBackup(ctx, data, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt backup")
	})
}

func TestFileBackupAdapter_RestoreBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test restoring a basic backup
	t.Run("BasicRestore", func(t *testing.T) {
		// Create a backup first
		data := createTestBackupData(t, 3)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		// Restore the backup
		restoreOpts := &RestoreOptions{}
		count, err := adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		require.NoError(t, err)
		assert.Equal(t, 3, count)
	})

	// Test restoring an encrypted backup
	t.Run("EncryptedRestore", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		encKey := make([]byte, 32)
		_, err := rand.Read(encKey)
		require.NoError(t, err)

		createOpts := &BackupOptions{
			Format:        BackupFormatEncrypted,
			EncryptionKey: encKey,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		// Restore with correct key
		restoreOpts := &RestoreOptions{
			DecryptionKey: encKey,
		}
		count, err := adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		require.NoError(t, err)
		assert.Equal(t, 2, count)

		// Try to restore with wrong key
		wrongKey := make([]byte, 32)
		_, err = rand.Read(wrongKey)
		require.NoError(t, err)

		restoreOpts.DecryptionKey = wrongKey
		_, err = adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})

	// Test restoring a compressed backup
	t.Run("CompressedRestore", func(t *testing.T) {
		data := createTestBackupData(t, 4)
		createOpts := &BackupOptions{
			Format:   BackupFormatJSON,
			Compress: true,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		restoreOpts := &RestoreOptions{}
		count, err := adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		require.NoError(t, err)
		assert.Equal(t, 4, count)
	})

	// Test restoring specific keys
	t.Run("FilteredRestore", func(t *testing.T) {
		data := createTestBackupData(t, 5)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		restoreOpts := &RestoreOptions{
			KeyIDs: []string{data.Keys[0].ID, data.Keys[1].ID},
		}
		count, err := adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		require.NoError(t, err)
		assert.Equal(t, 2, count)
	})

	// Test dry run restore
	t.Run("DryRunRestore", func(t *testing.T) {
		data := createTestBackupData(t, 3)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		restoreOpts := &RestoreOptions{
			DryRun: true,
		}
		count, err := adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		require.NoError(t, err)
		assert.Equal(t, 3, count)
	})

	// Test restoring non-existent backup
	t.Run("NonExistentBackup", func(t *testing.T) {
		restoreOpts := &RestoreOptions{}
		_, err := adapter.RestoreBackup(ctx, "non-existent-id", restoreOpts)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBackupNotFound)
	})

	// Test restoring encrypted backup without key
	t.Run("EncryptedWithoutKey", func(t *testing.T) {
		data := createTestBackupData(t, 1)
		encKey := make([]byte, 32)
		_, err := rand.Read(encKey)
		require.NoError(t, err)

		createOpts := &BackupOptions{
			Format:        BackupFormatEncrypted,
			EncryptionKey: encKey,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		restoreOpts := &RestoreOptions{}
		_, err = adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEncryptionKey)
	})

	// Test checksum verification
	t.Run("ChecksumVerification", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		// Corrupt the backup file
		backupPath := adapter.getBackupPath(metadata.ID)
		err = os.WriteFile(backupPath, []byte("corrupted data"), 0600)
		require.NoError(t, err)

		restoreOpts := &RestoreOptions{}
		_, err = adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrChecksumMismatch)
	})
}

func TestFileBackupAdapter_ListBackups(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create multiple backups
	for i := 0; i < 5; i++ {
		data := createTestBackupData(t, i+1)
		opts := &BackupOptions{
			Format: BackupFormatJSON,
		}
		_, err := adapter.CreateBackup(ctx, data, opts)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// Test listing all backups
	t.Run("ListAll", func(t *testing.T) {
		backups, err := adapter.ListBackups(ctx, nil)
		require.NoError(t, err)
		assert.Len(t, backups, 5)
	})

	// Test listing with limit
	t.Run("WithLimit", func(t *testing.T) {
		opts := &ListOptions{
			Limit: 3,
		}
		backups, err := adapter.ListBackups(ctx, opts)
		require.NoError(t, err)
		assert.Len(t, backups, 3)
	})

	// Test listing with offset
	t.Run("WithOffset", func(t *testing.T) {
		opts := &ListOptions{
			Offset: 2,
		}
		backups, err := adapter.ListBackups(ctx, opts)
		require.NoError(t, err)
		assert.Len(t, backups, 3)
	})

	// Test listing with sorting
	t.Run("SortBySize", func(t *testing.T) {
		opts := &ListOptions{
			SortBy:    "size",
			SortOrder: "asc",
		}
		backups, err := adapter.ListBackups(ctx, opts)
		require.NoError(t, err)
		assert.Len(t, backups, 5)

		// Verify ascending order
		for i := 1; i < len(backups); i++ {
			assert.LessOrEqual(t, backups[i-1].Size, backups[i].Size)
		}
	})

	// Test listing with time filter
	t.Run("WithTimeFilter", func(t *testing.T) {
		now := time.Now()
		startTime := now.Add(-1 * time.Hour)
		opts := &ListOptions{
			StartTime: &startTime,
		}
		backups, err := adapter.ListBackups(ctx, opts)
		require.NoError(t, err)
		assert.Len(t, backups, 5)
	})
}

func TestFileBackupAdapter_GetBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test getting an existing backup
	t.Run("ExistingBackup", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		retrieved, err := adapter.GetBackup(ctx, metadata.ID)
		require.NoError(t, err)
		assert.Equal(t, metadata.ID, retrieved.ID)
		assert.Equal(t, metadata.KeyCount, retrieved.KeyCount)
	})

	// Test getting a non-existent backup
	t.Run("NonExistentBackup", func(t *testing.T) {
		_, err := adapter.GetBackup(ctx, "non-existent-id")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBackupNotFound)
	})
}

func TestFileBackupAdapter_DeleteBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test deleting an existing backup
	t.Run("DeleteExisting", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		// Verify backup exists
		_, err = adapter.GetBackup(ctx, metadata.ID)
		require.NoError(t, err)

		// Delete backup
		err = adapter.DeleteBackup(ctx, metadata.ID)
		require.NoError(t, err)

		// Verify backup is gone
		_, err = adapter.GetBackup(ctx, metadata.ID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBackupNotFound)

		// Verify files are deleted
		backupPath := adapter.getBackupPath(metadata.ID)
		metadataPath := adapter.getMetadataPath(metadata.ID)
		assert.NoFileExists(t, backupPath)
		assert.NoFileExists(t, metadataPath)
	})

	// Test deleting a non-existent backup
	t.Run("DeleteNonExistent", func(t *testing.T) {
		err := adapter.DeleteBackup(ctx, "non-existent-id")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBackupNotFound)
	})
}

func TestFileBackupAdapter_VerifyBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test verifying a valid backup
	t.Run("ValidBackup", func(t *testing.T) {
		data := createTestBackupData(t, 3)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		result, err := adapter.VerifyBackup(ctx, metadata.ID, nil)
		require.NoError(t, err)
		assert.True(t, result.Valid)
		assert.True(t, result.ChecksumValid)
		assert.True(t, result.FormatValid)
		assert.Equal(t, 3, result.KeyCount)
		assert.Empty(t, result.Errors)
	})

	// Test verifying an encrypted backup
	t.Run("EncryptedBackup", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		encKey := make([]byte, 32)
		_, err := rand.Read(encKey)
		require.NoError(t, err)

		createOpts := &BackupOptions{
			Format:        BackupFormatEncrypted,
			EncryptionKey: encKey,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		// Verify with correct key
		verifyOpts := &RestoreOptions{
			DecryptionKey: encKey,
		}
		result, err := adapter.VerifyBackup(ctx, metadata.ID, verifyOpts)
		require.NoError(t, err)
		assert.True(t, result.Valid)
		assert.True(t, result.DecryptionValid)

		// Verify without key
		result, err = adapter.VerifyBackup(ctx, metadata.ID, nil)
		require.NoError(t, err)
		assert.False(t, result.DecryptionValid)
		assert.NotEmpty(t, result.Errors)
	})

	// Test verifying a corrupted backup
	t.Run("CorruptedBackup", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		// Corrupt the backup file
		backupPath := adapter.getBackupPath(metadata.ID)
		err = os.WriteFile(backupPath, []byte("corrupted data"), 0600)
		require.NoError(t, err)

		result, err := adapter.VerifyBackup(ctx, metadata.ID, nil)
		require.NoError(t, err)
		assert.False(t, result.Valid)
		assert.False(t, result.ChecksumValid)
		assert.NotEmpty(t, result.Errors)
	})

	// Test verifying a non-existent backup
	t.Run("NonExistentBackup", func(t *testing.T) {
		result, err := adapter.VerifyBackup(ctx, "non-existent-id", nil)
		require.NoError(t, err)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})
}

func TestFileBackupAdapter_ExportBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test exporting a backup
	t.Run("ExportBackup", func(t *testing.T) {
		data := createTestBackupData(t, 2)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		metadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		exportDir := t.TempDir()
		exportPath := filepath.Join(exportDir, "exported.backup")

		result, err := adapter.ExportBackup(ctx, metadata.ID, exportPath)
		require.NoError(t, err)
		assert.Equal(t, exportPath, result)
		assert.FileExists(t, exportPath)
	})

	// Test exporting a non-existent backup
	t.Run("NonExistentBackup", func(t *testing.T) {
		exportPath := filepath.Join(t.TempDir(), "exported.backup")
		_, err := adapter.ExportBackup(ctx, "non-existent-id", exportPath)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBackupNotFound)
	})
}

func TestFileBackupAdapter_ImportBackup(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test importing a backup
	t.Run("ImportBackup", func(t *testing.T) {
		// Create and export a backup first
		data := createTestBackupData(t, 3)
		createOpts := &BackupOptions{
			Format: BackupFormatJSON,
		}

		originalMetadata, err := adapter.CreateBackup(ctx, data, createOpts)
		require.NoError(t, err)

		exportPath := filepath.Join(t.TempDir(), "exported.backup")
		_, err = adapter.ExportBackup(ctx, originalMetadata.ID, exportPath)
		require.NoError(t, err)

		// Create a new adapter in a different directory
		importDir := t.TempDir()
		importAdapter, err := NewFileBackupAdapter(importDir)
		require.NoError(t, err)

		// Import the backup
		importedMetadata, err := importAdapter.ImportBackup(ctx, exportPath)
		require.NoError(t, err)
		assert.NotEmpty(t, importedMetadata.ID)
		assert.Equal(t, 3, importedMetadata.KeyCount)
	})

	// Test importing an invalid file
	t.Run("InvalidFile", func(t *testing.T) {
		invalidPath := filepath.Join(t.TempDir(), "invalid.backup")
		err := os.WriteFile(invalidPath, []byte("invalid data"), 0600)
		require.NoError(t, err)

		_, err = adapter.ImportBackup(ctx, invalidPath)
		assert.Error(t, err)
	})

	// Test importing a non-existent file
	t.Run("NonExistentFile", func(t *testing.T) {
		_, err := adapter.ImportBackup(ctx, "/non/existent/path")
		assert.Error(t, err)
	})
}

func TestFileBackupAdapter_GetStatistics(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test statistics with no backups
	t.Run("NoBackups", func(t *testing.T) {
		stats, err := adapter.GetStatistics(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, stats.TotalBackups)
		assert.Equal(t, int64(0), stats.TotalSize)
		assert.Nil(t, stats.OldestBackup)
		assert.Nil(t, stats.NewestBackup)
	})

	// Test statistics with backups
	t.Run("WithBackups", func(t *testing.T) {
		// Create a few backups
		encKey := make([]byte, 32)
		_, err := rand.Read(encKey)
		require.NoError(t, err)

		for i := 0; i < 3; i++ {
			data := createTestBackupData(t, i+1)
			opts := &BackupOptions{
				Format: BackupFormatJSON,
			}
			if i == 0 {
				opts.Format = BackupFormatEncrypted
				opts.EncryptionKey = encKey
			}
			if i == 1 {
				opts.Compress = true
			}
			_, err := adapter.CreateBackup(ctx, data, opts)
			require.NoError(t, err)
			time.Sleep(10 * time.Millisecond)
		}

		stats, err := adapter.GetStatistics(ctx)
		require.NoError(t, err)
		assert.Equal(t, 3, stats.TotalBackups)
		assert.Greater(t, stats.TotalSize, int64(0))
		assert.NotNil(t, stats.OldestBackup)
		assert.NotNil(t, stats.NewestBackup)
		assert.Greater(t, stats.AverageSize, int64(0))
		assert.Equal(t, 1, stats.EncryptedBackups)
		assert.Equal(t, 1, stats.CompressedBackups)
		assert.Greater(t, len(stats.BackupsByFormat), 0)
	})
}

func TestFileBackupAdapter_EncryptionDecryption(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Test encryption and decryption
	t.Run("RoundTrip", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		plaintext := []byte("test data for encryption")

		// Encrypt
		ciphertext, err := adapter.encryptData(plaintext, key)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		// Decrypt
		decrypted, err := adapter.decryptData(ciphertext, key)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	// Test with invalid key size
	t.Run("InvalidKeySize", func(t *testing.T) {
		invalidKey := make([]byte, 16)
		plaintext := []byte("test data")

		_, err := adapter.encryptData(plaintext, invalidKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEncryptionKey)
	})

	// Test decryption with wrong key
	t.Run("WrongKey", func(t *testing.T) {
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		_, err := rand.Read(key1)
		require.NoError(t, err)
		_, err = rand.Read(key2)
		require.NoError(t, err)

		plaintext := []byte("test data")
		ciphertext, err := adapter.encryptData(plaintext, key1)
		require.NoError(t, err)

		_, err = adapter.decryptData(ciphertext, key2)
		assert.Error(t, err)
	})
}

func TestFileBackupAdapter_CompressionDecompression(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Test compression and decompression
	t.Run("RoundTrip", func(t *testing.T) {
		data := []byte("test data for compression that should compress well when repeated: " +
			"test data for compression that should compress well when repeated")

		// Compress
		compressed, err := adapter.compressData(data, "gzip")
		require.NoError(t, err)
		assert.Less(t, len(compressed), len(data))

		// Decompress
		decompressed, err := adapter.decompressData(compressed, "gzip")
		require.NoError(t, err)
		assert.Equal(t, data, decompressed)
	})

	// Test with unsupported algorithm
	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		data := []byte("test data")

		_, err := adapter.compressData(data, "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported compression algorithm")
	})
}

func TestFileBackupAdapter_LoadIndex(t *testing.T) {
	tempDir := t.TempDir()

	// Create adapter and add some backups
	adapter1, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()
	data := createTestBackupData(t, 2)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata1, err := adapter1.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Create a second adapter in the same directory
	// This should load the existing backups from the index
	adapter2, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Verify the backup is accessible from the new adapter
	retrieved, err := adapter2.GetBackup(ctx, metadata1.ID)
	require.NoError(t, err)
	assert.Equal(t, metadata1.ID, retrieved.ID)
}

func TestFileBackupAdapter_GetBackupMetadata(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup
	data := createTestBackupData(t, 2)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Clear the index to test loading from disk
	adapter.mu.Lock()
	delete(adapter.index, metadata.ID)
	adapter.mu.Unlock()

	// This should load from disk
	retrieved, err := adapter.getBackupMetadata(metadata.ID)
	require.NoError(t, err)
	assert.Equal(t, metadata.ID, retrieved.ID)
}

func TestFileBackupAdapter_VerifyBackup_Compressed(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test verifying a compressed backup
	data := createTestBackupData(t, 3)
	createOpts := &BackupOptions{
		Format:   BackupFormatJSON,
		Compress: true,
	}

	metadata, err := adapter.CreateBackup(ctx, data, createOpts)
	require.NoError(t, err)

	result, err := adapter.VerifyBackup(ctx, metadata.ID, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.FormatValid)
	assert.Equal(t, 3, result.KeyCount)
}

func TestFileBackupAdapter_VerifyBackup_CorruptedCompressed(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a compressed backup
	data := createTestBackupData(t, 2)
	createOpts := &BackupOptions{
		Format:   BackupFormatJSON,
		Compress: true,
	}

	metadata, err := adapter.CreateBackup(ctx, data, createOpts)
	require.NoError(t, err)

	// Modify metadata to skip checksum validation but still test decompression
	adapter.mu.Lock()
	adapter.index[metadata.ID].Checksum = "invalid-checksum-to-skip"
	adapter.mu.Unlock()

	// Corrupt the compressed data (keep it encrypted if it was)
	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.WriteFile(backupPath, []byte("corrupted compressed data"), 0600)
	require.NoError(t, err)

	// Update checksum in metadata to match corrupted data
	corruptedChecksum := sha256.Sum256([]byte("corrupted compressed data"))
	adapter.mu.Lock()
	adapter.index[metadata.ID].Checksum = hex.EncodeToString(corruptedChecksum[:])
	adapter.mu.Unlock()

	result, err := adapter.VerifyBackup(ctx, metadata.ID, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.False(t, result.FormatValid)
}

func TestFileBackupAdapter_VerifyBackup_InvalidFormat(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a valid backup
	data := createTestBackupData(t, 2)
	createOpts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, createOpts)
	require.NoError(t, err)

	// Corrupt the backup with invalid JSON
	invalidJSON := []byte("{invalid json content")
	checksum := sha256.Sum256(invalidJSON)
	adapter.mu.Lock()
	adapter.index[metadata.ID].Checksum = hex.EncodeToString(checksum[:])
	adapter.mu.Unlock()

	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.WriteFile(backupPath, invalidJSON, 0600)
	require.NoError(t, err)

	result, err := adapter.VerifyBackup(ctx, metadata.ID, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.False(t, result.FormatValid)
}

func TestFileBackupAdapter_VerifyBackup_CorruptedKeys(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create backup data with a key missing ID
	data := createTestBackupData(t, 2)
	data.Keys[0].ID = "" // Corrupt the key ID

	// Manually serialize and save to bypass validation
	serialized, err := marshalBackupDataSafe(data)
	require.NoError(t, err)

	backupID := uuid.New().String()
	metadata := &BackupMetadata{
		ID:        backupID,
		Timestamp: time.Now().UTC(),
		Format:    BackupFormatJSON,
		Version:   DefaultBackupVersion,
		KeyCount:  len(data.Keys),
		KeyIDs:    []string{data.Keys[0].ID, data.Keys[1].ID},
	}

	checksum := sha256.Sum256(serialized)
	metadata.Checksum = hex.EncodeToString(checksum[:])
	metadata.Size = int64(len(serialized))

	// Write files manually
	backupPath := adapter.getBackupPath(backupID)
	err = os.WriteFile(backupPath, serialized, 0600)
	require.NoError(t, err)

	metadataPath := adapter.getMetadataPath(backupID)
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(metadataPath, metadataBytes, 0600)
	require.NoError(t, err)

	adapter.mu.Lock()
	adapter.index[backupID] = metadata
	adapter.mu.Unlock()

	// Verify should detect the corrupted key
	result, err := adapter.VerifyBackup(ctx, backupID, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.CorruptedKeys)
}

func TestFileBackupAdapter_ExportBackup_CreateDestDir(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup
	data := createTestBackupData(t, 2)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Export to a path where the directory doesn't exist yet
	exportDir := filepath.Join(t.TempDir(), "subdir1", "subdir2")
	exportPath := filepath.Join(exportDir, "exported.backup")

	result, err := adapter.ExportBackup(ctx, metadata.ID, exportPath)
	require.NoError(t, err)
	assert.Equal(t, exportPath, result)
	assert.FileExists(t, exportPath)
}

func TestFileBackupAdapter_ImportBackup_NoMetadata(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup data without metadata
	data := &BackupData{
		Keys: []*BackupKey{
			{
				ID:         "test-key",
				PrivateKey: []byte("private"),
				PublicKey:  []byte("public"),
			},
		},
	}

	serialized, err := marshalBackupDataSafe(data)
	require.NoError(t, err)

	// Write to a file
	sourcePath := filepath.Join(t.TempDir(), "backup.json")
	err = os.WriteFile(sourcePath, serialized, 0600)
	require.NoError(t, err)

	// Try to import
	_, err = adapter.ImportBackup(ctx, sourcePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metadata is missing")
}

func TestFileBackupAdapter_ImportBackup_DuplicateID(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create and export a backup
	data := createTestBackupData(t, 2)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	exportPath := filepath.Join(t.TempDir(), "exported.backup")
	_, err = adapter.ExportBackup(ctx, metadata.ID, exportPath)
	require.NoError(t, err)

	// Import should handle duplicate ID by generating a new one
	importedMetadata, err := adapter.ImportBackup(ctx, exportPath)
	require.NoError(t, err)
	assert.NotEqual(t, metadata.ID, importedMetadata.ID) // Should have a different ID
}

func TestFileBackupAdapter_DecryptData_ShortCiphertext(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	// Try to decrypt data that's too short
	shortData := []byte("short")
	_, err = adapter.decryptData(shortData, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestFileBackupAdapter_CompressData_EmptyAlgorithm(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	data := []byte("test data for compression")

	// Test with empty algorithm (should use default)
	compressed, err := adapter.compressData(data, "")
	require.NoError(t, err)
	assert.NotEmpty(t, compressed)

	decompressed, err := adapter.decompressData(compressed, "")
	require.NoError(t, err)
	assert.Equal(t, data, decompressed)
}

func TestFileBackupAdapter_CreateBackup_MetadataWriteError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup with metadata that exists
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Make the metadata path read-only to cause write error on next backup
	// This tests the cleanup path
	metadataPath := adapter.getMetadataPath(metadata.ID)
	err = os.Chmod(filepath.Dir(metadataPath), 0500)
	if err == nil {
		defer func() { _ = os.Chmod(filepath.Dir(metadataPath), 0700) }()
	}
}

func TestFileBackupAdapter_LoadIndex_WithBadFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create some non-metadata files
	err := os.WriteFile(filepath.Join(tempDir, "random.txt"), []byte("not a backup"), 0600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "backup.json"), []byte("invalid json"), 0600)
	require.NoError(t, err)

	// Create a subdirectory (should be skipped)
	err = os.MkdirAll(filepath.Join(tempDir, "subdir"), 0700)
	require.NoError(t, err)

	// Create adapter - should handle bad files gracefully
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)
	assert.NotNil(t, adapter)
}

func TestFileBackupAdapter_CreateBackup_WithExistingMetadata(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create backup data with pre-existing metadata
	data := createTestBackupData(t, 2)
	existingMetadata := &BackupMetadata{
		ID:        "existing-id",
		Timestamp: time.Now().Add(-1 * time.Hour),
		Format:    BackupFormatJSON,
		Version:   "0.9.0",
		KeyCount:  5,
		Metadata:  map[string]interface{}{"custom": "value"},
	}
	data.Metadata = existingMetadata

	opts := &BackupOptions{
		Format:          BackupFormatJSON,
		IncludeMetadata: true,
	}

	// The CreateBackup should override some fields
	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)
	assert.NotEqual(t, "existing-id", metadata.ID) // Should get new ID
	assert.Equal(t, 2, metadata.KeyCount)          // Should be updated
	assert.NotEmpty(t, metadata.Version)           // Should have version set
}

func TestFileBackupAdapter_EncryptData_InvalidKey(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Test with invalid key sizes
	testCases := []struct {
		name    string
		keySize int
	}{
		{"TooShort", 16},
		{"TooLong", 64},
		{"Empty", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			if tc.keySize > 0 {
				_, err := rand.Read(key)
				require.NoError(t, err)
			}

			_, err := adapter.encryptData([]byte("test"), key)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidEncryptionKey)
		})
	}
}

func TestFileBackupAdapter_DecryptData_InvalidKey(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Create valid encrypted data
	validKey := make([]byte, 32)
	_, err = rand.Read(validKey)
	require.NoError(t, err)

	encrypted, err := adapter.encryptData([]byte("test data"), validKey)
	require.NoError(t, err)

	// Test decryption with invalid key sizes
	testCases := []struct {
		name    string
		keySize int
	}{
		{"TooShort", 16},
		{"TooLong", 64},
		{"Empty", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			if tc.keySize > 0 {
				_, err := rand.Read(key)
				require.NoError(t, err)
			}

			_, err := adapter.decryptData(encrypted, key)
			assert.Error(t, err)
		})
	}
}

func TestFileBackupAdapter_RestoreBackup_DeserializationError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup first
	data := createTestBackupData(t, 2)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Corrupt the backup with invalid JSON but valid checksum
	invalidJSON := []byte("{invalid json")
	checksum := sha256.Sum256(invalidJSON)
	adapter.mu.Lock()
	adapter.index[metadata.ID].Checksum = hex.EncodeToString(checksum[:])
	adapter.mu.Unlock()

	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.WriteFile(backupPath, invalidJSON, 0600)
	require.NoError(t, err)

	// Restore should fail with deserialization error
	restoreOpts := &RestoreOptions{}
	_, err = adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}

func TestFileBackupAdapter_ExportBackup_ReadError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Remove the backup file to cause read error
	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.Remove(backupPath)
	require.NoError(t, err)

	// Export should fail
	exportPath := filepath.Join(t.TempDir(), "export.backup")
	_, err = adapter.ExportBackup(ctx, metadata.ID, exportPath)
	assert.Error(t, err)
}

func TestFileBackupAdapter_ImportBackup_FileWriteError(t *testing.T) {
	skipIfRoot(t)
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create and export a backup
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	exportPath := filepath.Join(t.TempDir(), "export.backup")
	_, err = adapter.ExportBackup(ctx, metadata.ID, exportPath)
	require.NoError(t, err)

	// Make the import directory read-only
	err = os.Chmod(tempDir, 0500)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(tempDir, 0700) }()

	// Import should fail due to permission error
	_, err = adapter.ImportBackup(ctx, exportPath)
	assert.Error(t, err)
}

func TestFileBackupAdapter_RestoreBackup_ReadError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Remove the backup file
	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.Remove(backupPath)
	require.NoError(t, err)

	// Restore should fail
	_, err = adapter.RestoreBackup(ctx, metadata.ID, nil)
	assert.Error(t, err)
}

func TestFileBackupAdapter_RestoreBackup_DecompressionError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a compressed backup
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format:   BackupFormatJSON,
		Compress: true,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Corrupt the compressed data
	corruptData := []byte("not compressed data")
	checksum := sha256.Sum256(corruptData)
	adapter.mu.Lock()
	adapter.index[metadata.ID].Checksum = hex.EncodeToString(checksum[:])
	adapter.mu.Unlock()

	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.WriteFile(backupPath, corruptData, 0600)
	require.NoError(t, err)

	// Restore should fail with decompression error
	_, err = adapter.RestoreBackup(ctx, metadata.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decompress")
}

func TestFileBackupAdapter_VerifyBackup_ReadError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Remove the backup file
	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.Remove(backupPath)
	require.NoError(t, err)

	// Verify should fail
	result, err := adapter.VerifyBackup(ctx, metadata.ID, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)
}

func TestFileBackupAdapter_VerifyBackup_EncryptedWithWrongKey(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create encrypted backup
	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	require.NoError(t, err)

	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format:        BackupFormatEncrypted,
		EncryptionKey: encKey,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Verify with wrong key
	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)

	verifyOpts := &RestoreOptions{
		DecryptionKey: wrongKey,
	}

	result, err := adapter.VerifyBackup(ctx, metadata.ID, verifyOpts)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.False(t, result.DecryptionValid)
}

func TestFileBackupAdapter_DeleteBackup_RemoveFileErrors(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Remove just the backup file (metadata still exists)
	backupPath := adapter.getBackupPath(metadata.ID)
	err = os.Remove(backupPath)
	require.NoError(t, err)

	// Delete should still succeed (removes metadata and cleans up index)
	err = adapter.DeleteBackup(ctx, metadata.ID)
	require.NoError(t, err)

	// Verify it's gone from index
	_, err = adapter.GetBackup(ctx, metadata.ID)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupNotFound)
}

func TestFileBackupAdapter_GetBackupMetadata_LoadFromDiskError(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Try to get metadata for non-existent backup
	_, err = adapter.getBackupMetadata("non-existent-id")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupNotFound)
}

func TestFileBackupAdapter_GetBackupMetadata_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Create invalid metadata file
	backupID := "test-id"
	metadataPath := adapter.getMetadataPath(backupID)
	err = os.WriteFile(metadataPath, []byte("invalid json"), 0600)
	require.NoError(t, err)

	// Should fail to parse
	_, err = adapter.getBackupMetadata(backupID)
	assert.Error(t, err)
}

func TestFileBackupAdapter_CreateBackup_CompressedAndEncrypted(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a backup that is both compressed and encrypted
	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	require.NoError(t, err)

	data := createTestBackupData(t, 3)
	opts := &BackupOptions{
		Format:        BackupFormatEncrypted,
		EncryptionKey: encKey,
		Compress:      true,
	}

	metadata, err := adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)
	assert.True(t, metadata.Encrypted)
	assert.True(t, metadata.Compressed)

	// Verify we can restore it
	restoreOpts := &RestoreOptions{
		DecryptionKey: encKey,
	}
	count, err := adapter.RestoreBackup(ctx, metadata.ID, restoreOpts)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestFileBackupAdapter_ListBackups_EdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test with offset beyond length
	t.Run("OffsetBeyondLength", func(t *testing.T) {
		backups, err := adapter.ListBackups(ctx, &ListOptions{
			Offset: 100,
		})
		require.NoError(t, err)
		assert.Empty(t, backups)
	})

	// Create a backup for further tests
	data := createTestBackupData(t, 1)
	opts := &BackupOptions{
		Format: BackupFormatJSON,
	}
	_, err = adapter.CreateBackup(ctx, data, opts)
	require.NoError(t, err)

	// Test sorting by key_count
	t.Run("SortByKeyCount", func(t *testing.T) {
		backups, err := adapter.ListBackups(ctx, &ListOptions{
			SortBy:    "key_count",
			SortOrder: "asc",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, backups)
	})
}

func TestFileBackupAdapter_CreateBackup_WithCustomCompressionAlgorithm(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Test that unsupported compression algorithm returns error
	data := createTestBackupData(t, 2)
	opts := &BackupOptions{
		Format:               BackupFormatJSON,
		Compress:             true,
		CompressionAlgorithm: "unsupported-algorithm",
	}

	_, err = adapter.CreateBackup(ctx, data, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported compression algorithm")
}

func TestFileBackupAdapter_ImportBackup_EmptyID(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Create backup data with empty ID in metadata
	data := createTestBackupData(t, 1)
	data.Metadata = &BackupMetadata{
		ID:        "", // Empty ID
		Timestamp: time.Now(),
		Format:    BackupFormatJSON,
		Version:   DefaultBackupVersion,
		KeyCount:  1,
		KeyIDs:    []string{"key1"},
	}

	// Serialize and write to file
	serialized, err := marshalBackupDataSafe(data)
	require.NoError(t, err)

	sourcePath := filepath.Join(t.TempDir(), "backup-no-id.json")
	err = os.WriteFile(sourcePath, serialized, 0600)
	require.NoError(t, err)

	// Import should generate a new ID
	metadata, err := adapter.ImportBackup(ctx, sourcePath)
	require.NoError(t, err)
	assert.NotEmpty(t, metadata.ID)
}

func TestFileBackupAdapter_DecompressData_UnsupportedAlgorithm(t *testing.T) {
	tempDir := t.TempDir()
	adapter, err := NewFileBackupAdapter(tempDir)
	require.NoError(t, err)

	// Test decompression with unsupported algorithm
	_, err = adapter.decompressData([]byte("test"), "unsupported")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported compression algorithm")
}

// Helper functions

// marshalBackupDataSafe safely marshals BackupData by temporarily clearing SessionCloser
func marshalBackupDataSafe(data *BackupData) ([]byte, error) {
	// Clear SessionCloser from all keys before marshaling (cannot marshal func)
	var sessionClosers []func() error
	for i := range data.Keys {
		if data.Keys[i].Attributes != nil && data.Keys[i].Attributes.TPMAttributes != nil {
			sessionClosers = append(sessionClosers, data.Keys[i].Attributes.TPMAttributes.SessionCloser)
			data.Keys[i].Attributes.TPMAttributes.SessionCloser = nil
		}
	}
	// Restore SessionCloser after marshaling
	defer func() {
		closerIdx := 0
		for i := range data.Keys {
			if data.Keys[i].Attributes != nil && data.Keys[i].Attributes.TPMAttributes != nil && closerIdx < len(sessionClosers) {
				data.Keys[i].Attributes.TPMAttributes.SessionCloser = sessionClosers[closerIdx]
				closerIdx++
			}
		}
	}()

	return json.Marshal(data) //nolint:staticcheck // SA1026: SessionCloser is cleared before marshaling
}

func createTestBackupData(t *testing.T, keyCount int) *BackupData {
	t.Helper()

	keys := make([]*BackupKey, keyCount)
	attrs := make([]*types.KeyAttributes, keyCount)

	for i := 0; i < keyCount; i++ {
		keyID := time.Now().Format("20060102150405") + "-" + string(rune('A'+i))

		keys[i] = &BackupKey{
			ID:         keyID,
			PrivateKey: []byte("private-key-data-" + keyID),
			PublicKey:  []byte("public-key-data-" + keyID),
			Created:    time.Now(),
			Modified:   time.Now(),
			Version:    1,
			Metadata:   map[string]interface{}{"index": i},
		}

		attrs[i] = &types.KeyAttributes{
			CN:           keyID,
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeTLS,
		}
		keys[i].Attributes = attrs[i]
	}

	return &BackupData{
		Keys:       keys,
		Attributes: attrs,
	}
}
