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

package gui

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSealedBlobFile creates a minimal sealed blob JSON file that the
// SealService can load. The blob has the given id and label.
func writeSealedBlobFile(t *testing.T, dir, id, label string) {
	t.Helper()
	blob := map[string]interface{}{
		"id":         id,
		"label":      label,
		"size_bytes": 32,
		"pcr_bound":  false,
		"sealed_data": map[string]interface{}{
			"ciphertext": "dGVzdA==",
			"backend":    "software",
		},
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	path := filepath.Join(dir, id+".sealed.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func TestMigratePINArtifacts_RemovesPINStateJSON(t *testing.T) {
	dataDir := t.TempDir()
	pinStatePath := filepath.Join(dataDir, legacyPINStateFile)
	require.NoError(t, os.WriteFile(pinStatePath, []byte(`{"version":1}`), 0600))

	app := &App{
		log:     slog.Default(),
		dataDir: dataDir,
	}

	app.migratePINArtifacts()

	_, err := os.Stat(pinStatePath)
	assert.True(t, os.IsNotExist(err), "pin-state.json should have been removed")
}

func TestMigratePINArtifacts_RemovesTPMPINStateJSON(t *testing.T) {
	dataDir := t.TempDir()
	tpmDir := filepath.Join(dataDir, "tpm")
	require.NoError(t, os.MkdirAll(tpmDir, 0700))
	tpmPinStatePath := filepath.Join(tpmDir, legacyTPMPINStateFile)
	require.NoError(t, os.WriteFile(tpmPinStatePath, []byte(`{"version":1}`), 0600))

	app := &App{
		log:     slog.Default(),
		dataDir: dataDir,
	}

	app.migratePINArtifacts()

	_, err := os.Stat(tpmPinStatePath)
	assert.True(t, os.IsNotExist(err), "tpm/pin_state.json should have been removed")
}

func TestMigratePINArtifacts_NoopWhenFilesAbsent(t *testing.T) {
	dataDir := t.TempDir()

	app := &App{
		log:     slog.Default(),
		dataDir: dataDir,
	}

	// Should not panic or error when files don't exist.
	app.migratePINArtifacts()

	// Verify nothing was created.
	entries, err := os.ReadDir(dataDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "data directory should remain empty")
}

func TestMigratePINArtifacts_NoopWhenDataDirEmpty(t *testing.T) {
	app := &App{
		log:     slog.Default(),
		dataDir: "",
	}

	// Should not panic when dataDir is empty.
	app.migratePINArtifacts()
}

func TestMigratePINArtifacts_RemovesUserPINBlob(t *testing.T) {
	dataDir := t.TempDir()
	sealDir := filepath.Join(dataDir, "sealed")
	require.NoError(t, os.MkdirAll(sealDir, 0700))

	// Create a user_pin sealed blob.
	writeSealedBlobFile(t, sealDir, "blob-user-pin-001", legacyUserPINLabel)

	// Create another blob that should NOT be removed.
	writeSealedBlobFile(t, sealDir, "blob-other-001", "my_secret")

	sealSvc := services.NewSealService(sealDir)

	app := &App{
		log:         slog.Default(),
		dataDir:     dataDir,
		sealService: sealSvc,
	}

	app.migratePINArtifacts()

	// user_pin blob should be gone.
	_, err := os.Stat(filepath.Join(sealDir, "blob-user-pin-001.sealed.json"))
	assert.True(t, os.IsNotExist(err), "user_pin blob should have been removed")

	// Other blob should still exist.
	_, err = os.Stat(filepath.Join(sealDir, "blob-other-001.sealed.json"))
	assert.NoError(t, err, "non-user_pin blob should still exist")
}

func TestMigratePINArtifacts_NoopWhenNoUserPINBlobs(t *testing.T) {
	dataDir := t.TempDir()
	sealDir := filepath.Join(dataDir, "sealed")
	require.NoError(t, os.MkdirAll(sealDir, 0700))

	// Create a blob with a different label.
	writeSealedBlobFile(t, sealDir, "blob-barrier-001", "barrier_password")

	sealSvc := services.NewSealService(sealDir)

	app := &App{
		log:         slog.Default(),
		dataDir:     dataDir,
		sealService: sealSvc,
	}

	app.migratePINArtifacts()

	// barrier_password blob should still exist.
	_, err := os.Stat(filepath.Join(sealDir, "blob-barrier-001.sealed.json"))
	assert.NoError(t, err, "non-user_pin blob should not be removed")
}

func TestMigratePINArtifacts_NilSealService(t *testing.T) {
	dataDir := t.TempDir()
	pinStatePath := filepath.Join(dataDir, legacyPINStateFile)
	require.NoError(t, os.WriteFile(pinStatePath, []byte(`{"version":1}`), 0600))

	app := &App{
		log:         slog.Default(),
		dataDir:     dataDir,
		sealService: nil,
	}

	// Should still remove pin-state.json even without a seal service.
	app.migratePINArtifacts()

	_, err := os.Stat(pinStatePath)
	assert.True(t, os.IsNotExist(err), "pin-state.json should be removed even without seal service")
}

func TestMigratePINArtifacts_RemovesAllArtifactsTogether(t *testing.T) {
	dataDir := t.TempDir()

	// Create both pin state files.
	pinStatePath := filepath.Join(dataDir, legacyPINStateFile)
	require.NoError(t, os.WriteFile(pinStatePath, []byte(`{"version":1}`), 0600))

	tpmDir := filepath.Join(dataDir, "tpm")
	require.NoError(t, os.MkdirAll(tpmDir, 0700))
	tpmPinStatePath := filepath.Join(tpmDir, legacyTPMPINStateFile)
	require.NoError(t, os.WriteFile(tpmPinStatePath, []byte(`{"version":1}`), 0600))

	// Create a user_pin sealed blob.
	sealDir := filepath.Join(dataDir, "sealed")
	require.NoError(t, os.MkdirAll(sealDir, 0700))
	writeSealedBlobFile(t, sealDir, "blob-user-pin-all", legacyUserPINLabel)

	sealSvc := services.NewSealService(sealDir)

	app := &App{
		log:         slog.Default(),
		dataDir:     dataDir,
		sealService: sealSvc,
	}

	app.migratePINArtifacts()

	_, err := os.Stat(pinStatePath)
	assert.True(t, os.IsNotExist(err), "pin-state.json should be removed")

	_, err = os.Stat(tpmPinStatePath)
	assert.True(t, os.IsNotExist(err), "tpm/pin_state.json should be removed")

	_, err = os.Stat(filepath.Join(sealDir, "blob-user-pin-all.sealed.json"))
	assert.True(t, os.IsNotExist(err), "user_pin blob should be removed")
}

func TestMigratePINArtifacts_MultipleUserPINBlobs(t *testing.T) {
	dataDir := t.TempDir()
	sealDir := filepath.Join(dataDir, "sealed")
	require.NoError(t, os.MkdirAll(sealDir, 0700))

	// Create multiple user_pin blobs (edge case).
	writeSealedBlobFile(t, sealDir, "blob-user-pin-a", legacyUserPINLabel)
	writeSealedBlobFile(t, sealDir, "blob-user-pin-b", legacyUserPINLabel)

	// Create a non-user_pin blob.
	writeSealedBlobFile(t, sealDir, "blob-keep", "password_master_key")

	sealSvc := services.NewSealService(sealDir)

	app := &App{
		log:         slog.Default(),
		dataDir:     dataDir,
		sealService: sealSvc,
	}

	app.migratePINArtifacts()

	_, err := os.Stat(filepath.Join(sealDir, "blob-user-pin-a.sealed.json"))
	assert.True(t, os.IsNotExist(err), "first user_pin blob should be removed")

	_, err = os.Stat(filepath.Join(sealDir, "blob-user-pin-b.sealed.json"))
	assert.True(t, os.IsNotExist(err), "second user_pin blob should be removed")

	_, err = os.Stat(filepath.Join(sealDir, "blob-keep.sealed.json"))
	assert.NoError(t, err, "password_master_key blob should be preserved")
}

func TestMigratePINArtifacts_Idempotent(t *testing.T) {
	dataDir := t.TempDir()
	pinStatePath := filepath.Join(dataDir, legacyPINStateFile)
	require.NoError(t, os.WriteFile(pinStatePath, []byte(`{"version":1}`), 0600))

	sealDir := filepath.Join(dataDir, "sealed")
	require.NoError(t, os.MkdirAll(sealDir, 0700))
	writeSealedBlobFile(t, sealDir, "blob-user-pin-idem", legacyUserPINLabel)

	sealSvc := services.NewSealService(sealDir)

	app := &App{
		log:         slog.Default(),
		dataDir:     dataDir,
		sealService: sealSvc,
	}

	// Run twice: should not panic or error on second invocation.
	app.migratePINArtifacts()
	app.migratePINArtifacts()

	_, err := os.Stat(pinStatePath)
	assert.True(t, os.IsNotExist(err), "pin-state.json should be removed")

	_, err = os.Stat(filepath.Join(sealDir, "blob-user-pin-idem.sealed.json"))
	assert.True(t, os.IsNotExist(err), "user_pin blob should be removed")
}

func TestRemoveLegacyFile_FileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-file.json")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0600))

	app := &App{log: slog.Default()}
	count := app.removeLegacyFile(path)

	assert.Equal(t, 1, count)
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestRemoveLegacyFile_FileNotExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	app := &App{log: slog.Default()}
	count := app.removeLegacyFile(path)

	assert.Equal(t, 0, count)
}

func TestRemoveLegacyFile_PermissionError(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(subDir, 0700))
	path := filepath.Join(subDir, "protected.json")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0600))

	// Make the directory read-only so removal fails.
	require.NoError(t, os.Chmod(subDir, 0500))
	t.Cleanup(func() {
		// Restore permissions for cleanup.
		_ = os.Chmod(subDir, 0700)
	})

	app := &App{log: slog.Default()}
	count := app.removeLegacyFile(path)

	assert.Equal(t, 0, count)

	// File should still exist.
	_ = os.Chmod(subDir, 0700) // restore for stat
	_, err := os.Stat(path)
	assert.NoError(t, err, "file should still exist after permission error")
}

func TestRemoveLegacyUserPINBlobs_NilSealService(t *testing.T) {
	app := &App{
		log:         slog.Default(),
		sealService: nil,
	}
	count := app.removeLegacyUserPINBlobs()
	assert.Equal(t, 0, count)
}

func TestRemoveLegacyUserPINBlobs_EmptyStorage(t *testing.T) {
	sealDir := t.TempDir()
	sealSvc := services.NewSealService(sealDir)

	app := &App{
		log:         slog.Default(),
		sealService: sealSvc,
	}
	count := app.removeLegacyUserPINBlobs()
	assert.Equal(t, 0, count)
}

func TestRemoveLegacyUserPINBlobs_OnlyMatchingBlobs(t *testing.T) {
	sealDir := t.TempDir()
	writeSealedBlobFile(t, sealDir, "pin-blob-1", legacyUserPINLabel)
	writeSealedBlobFile(t, sealDir, "other-blob-1", "barrier_password")

	sealSvc := services.NewSealService(sealDir)

	app := &App{
		log:         slog.Default(),
		sealService: sealSvc,
	}
	count := app.removeLegacyUserPINBlobs()
	assert.Equal(t, 1, count)

	// Verify matching blob removed, other preserved.
	_, err := os.Stat(filepath.Join(sealDir, "pin-blob-1.sealed.json"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(sealDir, "other-blob-1.sealed.json"))
	assert.NoError(t, err)
}

func TestLegacyPINConstants(t *testing.T) {
	assert.Equal(t, "pin-state.json", legacyPINStateFile)
	assert.Equal(t, "pin_state.json", legacyTPMPINStateFile)
	assert.Equal(t, "user_pin", legacyUserPINLabel)
}
