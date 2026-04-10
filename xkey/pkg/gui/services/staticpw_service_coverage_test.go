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

package services

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// BackupPasswords
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_BackupPasswords_Plaintext(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a password to back up.
	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "backup-entry",
		Password: "secret123",
		Notes:    "test notes",
	})
	require.NoError(t, err)

	outFile := filepath.Join(t.TempDir(), "backup.json")
	err = svc.BackupPasswords(outFile, false, "", "")
	require.NoError(t, err)

	// Verify the file was created and contains valid JSON.
	data, readErr := os.ReadFile(outFile)
	require.NoError(t, readErr)

	var entries []StaticPasswordEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	assert.Len(t, entries, 1)
	assert.Equal(t, "backup-entry", entries[0].Name)
}

func TestStaticPWService_Coverage_BackupPasswords_Encrypted_AES256(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "encrypted-entry",
		Password: "pw",
	})
	require.NoError(t, err)

	outFile := filepath.Join(t.TempDir(), "backup.enc")
	err = svc.BackupPasswords(outFile, true, "aes-256", "my-backup-password")
	require.NoError(t, err)

	// Verify the file exists and is NOT valid JSON (it is encrypted).
	data, readErr := os.ReadFile(outFile)
	require.NoError(t, readErr)
	assert.True(t, len(data) > 0)
	var check []StaticPasswordEntry
	assert.Error(t, json.Unmarshal(data, &check), "encrypted data should not be valid JSON")
}

func TestStaticPWService_Coverage_BackupPasswords_Encrypted_AES128(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.AddPasswordV2(AddPasswordParams{Name: "e128", Password: "p"})
	require.NoError(t, err)

	outFile := filepath.Join(t.TempDir(), "backup128.enc")
	err = svc.BackupPasswords(outFile, true, "aes-128", "pass")
	require.NoError(t, err)
	info, statErr := os.Stat(outFile)
	require.NoError(t, statErr)
	assert.True(t, info.Size() > 0)
}

func TestStaticPWService_Coverage_BackupPasswords_Encrypted_AES192(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.AddPasswordV2(AddPasswordParams{Name: "e192", Password: "p"})
	require.NoError(t, err)

	outFile := filepath.Join(t.TempDir(), "backup192.enc")
	err = svc.BackupPasswords(outFile, true, "aes-192", "pass")
	require.NoError(t, err)
	info, statErr := os.Stat(outFile)
	require.NoError(t, statErr)
	assert.True(t, info.Size() > 0)
}

func TestStaticPWService_Coverage_BackupPasswords_EmptyPath(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.BackupPasswords("", false, "", "")
	assert.ErrorIs(t, err, ErrBackupInvalidPath)
}

func TestStaticPWService_Coverage_BackupPasswords_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.BackupPasswords("/tmp/backup.json", false, "", "")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestStaticPWService_Coverage_BackupPasswords_EncryptedNoPassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.BackupPasswords("/tmp/backup.enc", true, "aes-256", "")
	assert.ErrorIs(t, err, ErrBackupPasswordRequired)
}

func TestStaticPWService_Coverage_BackupPasswords_InvalidAlgorithm(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.BackupPasswords("/tmp/backup.enc", true, "blowfish", "password")
	assert.ErrorIs(t, err, ErrBackupInvalidAlgorithm)
}

func TestStaticPWService_Coverage_BackupPasswords_EmptyStore(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	outFile := filepath.Join(t.TempDir(), "empty-backup.json")
	err := svc.BackupPasswords(outFile, false, "", "")
	require.NoError(t, err)

	data, readErr := os.ReadFile(outFile)
	require.NoError(t, readErr)

	var entries []StaticPasswordEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	assert.Len(t, entries, 0)
}

// ---------------------------------------------------------------------------
// RestorePasswords
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_RestorePasswords_Plaintext(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Create a backup file manually.
	entries := []StaticPasswordEntry{
		{Name: "restored-1", Password: "pw1", Notes: "notes1"},
		{Name: "restored-2", Password: "pw2", Username: "user2"},
	}
	data, marshalErr := json.Marshal(entries)
	require.NoError(t, marshalErr)

	filePath := filepath.Join(t.TempDir(), "restore.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	imported, err := svc.RestorePasswords(filePath, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, 2, imported)

	// Verify the passwords were imported.
	list, listErr := svc.ListPasswords()
	require.NoError(t, listErr)
	assert.Len(t, list, 2)
}

func TestStaticPWService_Coverage_RestorePasswords_Encrypted(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a password and backup encrypted.
	_, err := svc.AddPasswordV2(AddPasswordParams{Name: "round-trip", Password: "rt-pw"})
	require.NoError(t, err)

	backupFile := filepath.Join(t.TempDir(), "rt-backup.enc")
	err = svc.BackupPasswords(backupFile, true, "aes-256", "roundtrip-key")
	require.NoError(t, err)

	// Create a new service (empty store) and restore.
	svc2, _ := newTestStaticPWService(t)
	imported, err := svc2.RestorePasswords(backupFile, true, "aes-256", "roundtrip-key")
	require.NoError(t, err)
	assert.Equal(t, 1, imported)

	list, listErr := svc2.ListPasswords()
	require.NoError(t, listErr)
	assert.Len(t, list, 1)
	assert.Equal(t, "round-trip", list[0].Name)
}

func TestStaticPWService_Coverage_RestorePasswords_SkipsDuplicates(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Pre-populate with an entry.
	_, err := svc.AddPasswordV2(AddPasswordParams{Name: "existing", Password: "pw1"})
	require.NoError(t, err)

	// Create a backup containing the same name plus a new one.
	entries := []StaticPasswordEntry{
		{Name: "existing", Password: "duplicate"},
		{Name: "new-entry", Password: "new-pw"},
	}
	data, marshalErr := json.Marshal(entries)
	require.NoError(t, marshalErr)

	filePath := filepath.Join(t.TempDir(), "restore.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	imported, err := svc.RestorePasswords(filePath, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, 1, imported) // Only "new-entry" imported.
}

func TestStaticPWService_Coverage_RestorePasswords_SkipsEmptyName(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entries := []StaticPasswordEntry{
		{Name: "", Password: "no-name"},
		{Name: "valid", Password: "pw"},
	}
	data, marshalErr := json.Marshal(entries)
	require.NoError(t, marshalErr)

	filePath := filepath.Join(t.TempDir(), "restore.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	imported, err := svc.RestorePasswords(filePath, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, 1, imported) // Only "valid" imported.
}

func TestStaticPWService_Coverage_RestorePasswords_WithExpiresAt(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	expiry := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	entries := []StaticPasswordEntry{
		{Name: "with-expiry", Password: "pw", ExpiresAt: expiry},
		{Name: "bad-expiry", Password: "pw", ExpiresAt: "not-a-date"},
	}
	data, marshalErr := json.Marshal(entries)
	require.NoError(t, marshalErr)

	filePath := filepath.Join(t.TempDir(), "restore.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	imported, err := svc.RestorePasswords(filePath, false, "", "")
	require.NoError(t, err)
	// Both should be imported - bad expiry is silently ignored.
	assert.Equal(t, 2, imported)
}

func TestStaticPWService_Coverage_RestorePasswords_EmptyPath(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.RestorePasswords("", false, "", "")
	assert.ErrorIs(t, err, ErrRestoreInvalidPath)
}

func TestStaticPWService_Coverage_RestorePasswords_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.RestorePasswords("/tmp/restore.json", false, "", "")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestStaticPWService_Coverage_RestorePasswords_EncryptedNoPassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.RestorePasswords("/tmp/restore.enc", true, "aes-256", "")
	assert.ErrorIs(t, err, ErrBackupPasswordRequired)
}

func TestStaticPWService_Coverage_RestorePasswords_InvalidAlgorithm(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.RestorePasswords("/tmp/restore.enc", true, "des", "password")
	assert.ErrorIs(t, err, ErrBackupInvalidAlgorithm)
}

func TestStaticPWService_Coverage_RestorePasswords_NonExistentFile(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.RestorePasswords("/nonexistent/restore.json", false, "", "")
	assert.ErrorIs(t, err, ErrRestoreInvalidPath)
}

func TestStaticPWService_Coverage_RestorePasswords_InvalidJSON(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	filePath := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(filePath, []byte("not json"), 0600))

	_, err := svc.RestorePasswords(filePath, false, "", "")
	assert.ErrorIs(t, err, ErrRestoreParseFailed)
}

func TestStaticPWService_Coverage_RestorePasswords_WrongDecryptionPassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.AddPasswordV2(AddPasswordParams{Name: "decrypt-test", Password: "pw"})
	require.NoError(t, err)

	backupFile := filepath.Join(t.TempDir(), "encrypted.enc")
	err = svc.BackupPasswords(backupFile, true, "aes-256", "correct-password")
	require.NoError(t, err)

	svc2, _ := newTestStaticPWService(t)
	_, err = svc2.RestorePasswords(backupFile, true, "aes-256", "wrong-password")
	assert.ErrorIs(t, err, ErrRestoreDecryptFailed)
}

// ---------------------------------------------------------------------------
// decryptBackup
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_DecryptBackup_InvalidAlgorithm(t *testing.T) {
	_, err := decryptBackup([]byte("data"), "invalid", "password")
	assert.ErrorIs(t, err, ErrBackupInvalidAlgorithm)
}

func TestStaticPWService_Coverage_DecryptBackup_TooShort(t *testing.T) {
	// AES-256 GCM nonce is 12 bytes; provide data shorter than that.
	_, err := decryptBackup([]byte("short"), "aes-256", "password")
	assert.ErrorIs(t, err, ErrRestoreDecryptFailed)
}

func TestStaticPWService_Coverage_DecryptBackup_CorruptCiphertext(t *testing.T) {
	// Create a blob with a valid-length "nonce" but garbage ciphertext.
	fakeData := make([]byte, 50) // enough for nonce + some garbage
	_, err := decryptBackup(fakeData, "aes-256", "password")
	assert.ErrorIs(t, err, ErrRestoreDecryptFailed)
}

// ---------------------------------------------------------------------------
// ListPasswords barrier sealed detection
// ---------------------------------------------------------------------------

// barrierSealedStore is a mock store that returns a barrier sealed error from List.
type barrierSealedStore struct {
	staticpw.Store
}

func (s *barrierSealedStore) List() ([]*staticpw.StaticPassword, error) {
	return nil, errors.New("seal: barrier is sealed")
}

func (s *barrierSealedStore) Add(_ *staticpw.StaticPassword) error           { return nil }
func (s *barrierSealedStore) Get(_ string) (*staticpw.StaticPassword, error) { return nil, nil }
func (s *barrierSealedStore) Update(_ *staticpw.StaticPassword) error        { return nil }
func (s *barrierSealedStore) Delete(_ string) error                          { return nil }
func (s *barrierSealedStore) ForceDelete(_ string) error                     { return nil }
func (s *barrierSealedStore) ListFolders() ([]string, error)                 { return nil, nil }
func (s *barrierSealedStore) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (s *barrierSealedStore) MoveToFolder(_, _ string) error { return nil }

func TestStaticPWService_Coverage_ListPasswords_BarrierSealed(t *testing.T) {
	svc := NewStaticPasswordService(&barrierSealedStore{})
	svc.SetContext(context.Background())

	_, err := svc.ListPasswords()
	assert.ErrorIs(t, err, ErrStaticPWBarrierSealed)
}

// storeListError is a mock store that returns a generic error from List.
type storeListError struct {
	staticpw.Store
}

func (s *storeListError) List() ([]*staticpw.StaticPassword, error) {
	return nil, errors.New("database error")
}
func (s *storeListError) Add(_ *staticpw.StaticPassword) error           { return nil }
func (s *storeListError) Get(_ string) (*staticpw.StaticPassword, error) { return nil, nil }
func (s *storeListError) Update(_ *staticpw.StaticPassword) error        { return nil }
func (s *storeListError) Delete(_ string) error                          { return nil }
func (s *storeListError) ForceDelete(_ string) error                     { return nil }
func (s *storeListError) ListFolders() ([]string, error)                 { return nil, nil }
func (s *storeListError) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (s *storeListError) MoveToFolder(_, _ string) error { return nil }

func TestStaticPWService_Coverage_ListPasswords_GenericError(t *testing.T) {
	svc := NewStaticPasswordService(&storeListError{})
	svc.SetContext(context.Background())

	_, err := svc.ListPasswords()
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrStaticPWBarrierSealed)
}

// ---------------------------------------------------------------------------
// paramsToImportOptions
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_ParamsToImportOptions(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	params := ImportParams{
		FilePath:            "/path/to/file.csv",
		Format:              "csv",
		Password:            "kdbx-pw",
		TargetFolder:        "Imported",
		SkipDuplicates:      true,
		OverwriteDuplicates: false,
		ImportTOTP:          true,
	}

	opts := svc.paramsToImportOptions(params)

	assert.Equal(t, "/path/to/file.csv", opts.FilePath)
	assert.Equal(t, "csv", opts.Format)
	assert.Equal(t, "kdbx-pw", opts.Password)
	assert.Equal(t, "Imported", opts.TargetFolder)
	assert.True(t, opts.SkipDuplicates)
	assert.False(t, opts.OverwriteDuplicates)
	assert.True(t, opts.ImportTOTP)
}

func TestStaticPWService_Coverage_ParamsToImportOptions_Empty(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	opts := svc.paramsToImportOptions(ImportParams{})
	assert.Equal(t, "", opts.FilePath)
	assert.Equal(t, "", opts.Format)
	assert.False(t, opts.SkipDuplicates)
}

// ---------------------------------------------------------------------------
// newImporter
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_NewImporter(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	importer := svc.newImporter()
	assert.NotNil(t, importer)
}

// ---------------------------------------------------------------------------
// PreviewImport error paths
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_PreviewImport_EmptyPath(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.PreviewImport(ImportParams{})
	assert.ErrorIs(t, err, ErrRestoreInvalidPath)
}

func TestStaticPWService_Coverage_PreviewImport_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.PreviewImport(ImportParams{FilePath: "/some/file.csv"})
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// ---------------------------------------------------------------------------
// ImportPasswords error paths
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_ImportPasswords_EmptyPath(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.ImportPasswords(ImportParams{})
	assert.ErrorIs(t, err, ErrRestoreInvalidPath)
}

func TestStaticPWService_Coverage_ImportPasswords_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.ImportPasswords(ImportParams{FilePath: "/file.csv"})
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// ---------------------------------------------------------------------------
// staticPWToEntry edge cases
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_StaticPWToEntry_FutureExpiry(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:        "id-future",
		Name:      "future",
		Password:  "pw",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days from now
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	entry := staticPWToEntry(pw)
	assert.False(t, entry.IsExpired)
	assert.True(t, entry.DaysUntilExpiry > 0)
	assert.True(t, entry.DaysUntilExpiry <= 31)
	assert.NotEmpty(t, entry.ExpiresAt)
}

func TestStaticPWService_Coverage_StaticPWToEntry_PastExpiry(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:        "id-past",
		Name:      "past",
		Password:  "pw",
		ExpiresAt: time.Now().Add(-48 * time.Hour), // 2 days ago
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	entry := staticPWToEntry(pw)
	assert.True(t, entry.IsExpired)
	assert.Equal(t, 0, entry.DaysUntilExpiry)
}

func TestStaticPWService_Coverage_StaticPWToEntry_MatchPatterns(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:            "id-match",
		Name:          "matcher",
		Password:      "pw",
		MatchPatterns: []string{"*.example.com", "login.test.org"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	entry := staticPWToEntry(pw)
	assert.Equal(t, []string{"*.example.com", "login.test.org"}, entry.MatchPatterns)
}

func TestStaticPWService_Coverage_StaticPWToEntry_AllFieldsPopulated(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:         "full-id",
		Name:       "full-name",
		Title:      "Full Title",
		Username:   "fulluser",
		Password:   "fullpw",
		URL:        "https://full.example.com",
		Notes:      "full notes",
		FolderPath: "full/folder",
		ReadOnly:   true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	entry := staticPWToEntry(pw)
	assert.Equal(t, "full-id", entry.ID)
	assert.Equal(t, "full-name", entry.Name)
	assert.Equal(t, "Full Title", entry.Title) // DisplayTitle() returns Title when set
	assert.Equal(t, "fulluser", entry.Username)
	assert.Equal(t, "fullpw", entry.Password)
	assert.Equal(t, "https://full.example.com", entry.URL)
	assert.Equal(t, "full notes", entry.Notes)
	assert.Equal(t, "full/folder", entry.FolderPath)
	assert.True(t, entry.ReadOnly)
	assert.Equal(t, -1, entry.DaysUntilExpiry) // No expiry set
}

// ---------------------------------------------------------------------------
// Backup then Restore round trip with all algorithms
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_BackupRestore_RoundTrip_AES128(t *testing.T) {
	backupRestoreRoundTrip(t, "aes-128")
}

func TestStaticPWService_Coverage_BackupRestore_RoundTrip_AES192(t *testing.T) {
	backupRestoreRoundTrip(t, "aes-192")
}

func TestStaticPWService_Coverage_BackupRestore_RoundTrip_AES256(t *testing.T) {
	backupRestoreRoundTrip(t, "aes-256")
}

func backupRestoreRoundTrip(t *testing.T, algorithm string) {
	t.Helper()

	svc, _ := newTestStaticPWService(t)
	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "rt-" + algorithm,
		Password: "secret",
		Title:    "Title-" + algorithm,
		Username: "user",
		URL:      "https://example.com",
		Notes:    "some notes",
	})
	require.NoError(t, err)

	outFile := filepath.Join(t.TempDir(), "backup-"+algorithm+".enc")
	err = svc.BackupPasswords(outFile, true, algorithm, "test-key-123")
	require.NoError(t, err)

	svc2, _ := newTestStaticPWService(t)
	imported, err := svc2.RestorePasswords(outFile, true, algorithm, "test-key-123")
	require.NoError(t, err)
	assert.Equal(t, 1, imported)

	list, listErr := svc2.ListPasswords()
	require.NoError(t, listErr)
	require.Len(t, list, 1)
	assert.Equal(t, "rt-"+algorithm, list[0].Name)
}

// ---------------------------------------------------------------------------
// RestorePasswords with ReadOnly entries
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_RestorePasswords_ReadOnlyFlag(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entries := []StaticPasswordEntry{
		{Name: "readonly-entry", Password: "pw", ReadOnly: true},
		{Name: "writable-entry", Password: "pw", ReadOnly: false},
	}
	data, marshalErr := json.Marshal(entries)
	require.NoError(t, marshalErr)

	filePath := filepath.Join(t.TempDir(), "restore-ro.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	imported, err := svc.RestorePasswords(filePath, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, 2, imported)
}

// ---------------------------------------------------------------------------
// RestorePasswords with MatchPatterns, URL, FolderPath
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_RestorePasswords_AllFields(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entries := []StaticPasswordEntry{
		{
			Name:          "full-restore",
			Title:         "Full Title",
			Username:      "user1",
			Password:      "pw1",
			URL:           "https://example.com",
			MatchPatterns: []string{"*.example.com"},
			Notes:         "important",
			FolderPath:    "work/projects",
		},
	}
	data, marshalErr := json.Marshal(entries)
	require.NoError(t, marshalErr)

	filePath := filepath.Join(t.TempDir(), "full-restore.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	imported, err := svc.RestorePasswords(filePath, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, 1, imported)

	list, listErr := svc.ListPasswords()
	require.NoError(t, listErr)
	require.Len(t, list, 1)
	assert.Equal(t, "work/projects", list[0].FolderPath)
}

// ---------------------------------------------------------------------------
// BackupPasswords encrypted validation: store not set comes after path check
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_BackupPasswords_EncryptedNilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.BackupPasswords("/tmp/backup.enc", true, "aes-256", "password")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// ---------------------------------------------------------------------------
// GetSupportedImportFormats
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_GetSupportedImportFormats(t *testing.T) {
	svc := NewStaticPasswordService(nil) // No store needed
	formats := svc.GetSupportedImportFormats()

	assert.Len(t, formats, 3)
	assert.Contains(t, formats, "csv")
	assert.Contains(t, formats, "xml")
	assert.Contains(t, formats, "kdbx")
}

// ---------------------------------------------------------------------------
// algorithmKeySize map validation
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_AlgorithmKeySize(t *testing.T) {
	assert.Equal(t, 16, algorithmKeySize["aes-128"])
	assert.Equal(t, 24, algorithmKeySize["aes-192"])
	assert.Equal(t, 32, algorithmKeySize["aes-256"])

	_, exists := algorithmKeySize["invalid"]
	assert.False(t, exists)
}

// ---------------------------------------------------------------------------
// Error sentinel uniqueness
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_ErrorSentinels(t *testing.T) {
	sentinels := []error{
		ErrStaticPWStoreNotSet,
		ErrStaticPWInvalidID,
		ErrStaticPWInvalidName,
		ErrStaticPWInvalidFolderPath,
		ErrStaticPWInvalidExpiresAt,
		ErrStaticPWReadOnly,
		ErrStaticPWNoClient,
		ErrStaticPWInvalidAccessMode,
		ErrStaticPWInvalidGenerateLength,
		ErrStaticPWBarrierSealed,
		ErrBackupInvalidPath,
		ErrBackupPasswordRequired,
		ErrBackupInvalidAlgorithm,
		ErrBackupFailed,
		ErrRestoreInvalidPath,
		ErrRestoreDecryptFailed,
		ErrRestoreParseFailed,
	}

	// Verify each sentinel is distinct.
	seen := make(map[string]bool, len(sentinels))
	for _, s := range sentinels {
		msg := s.Error()
		assert.False(t, seen[msg], "duplicate sentinel error: %s", msg)
		seen[msg] = true
	}
}

// ---------------------------------------------------------------------------
// BackupPasswords multiple entries
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_BackupPasswords_MultipleEntries(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	for i := 0; i < 5; i++ {
		_, err := svc.AddPasswordV2(AddPasswordParams{
			Name:       "entry-" + string(rune('A'+i)),
			Password:   "pw",
			FolderPath: "folder",
		})
		require.NoError(t, err)
	}

	outFile := filepath.Join(t.TempDir(), "multi-backup.json")
	err := svc.BackupPasswords(outFile, false, "", "")
	require.NoError(t, err)

	data, readErr := os.ReadFile(outFile)
	require.NoError(t, readErr)

	var entries []StaticPasswordEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	assert.Len(t, entries, 5)
}

// ---------------------------------------------------------------------------
// ListPasswordsByFolder error from store
// ---------------------------------------------------------------------------

// storeListByFolderError returns an error from ListByFolder.
type storeListByFolderError struct {
	staticpw.Store
}

func (s *storeListByFolderError) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, errors.New("list by folder error")
}

func TestStaticPWService_Coverage_ListPasswordsByFolder_Error(t *testing.T) {
	svc := NewStaticPasswordService(&storeListByFolderError{})
	svc.SetContext(context.Background())

	_, err := svc.ListPasswordsByFolder("folder")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list by folder error")
}

// ---------------------------------------------------------------------------
// SearchPasswords error from store
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_SearchPasswords_StoreError(t *testing.T) {
	svc := NewStaticPasswordService(&storeListError{})
	svc.SetContext(context.Background())

	_, err := svc.SearchPasswords("query")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// RenameFolder error on store list
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_RenameFolder_StoreListError(t *testing.T) {
	svc := NewStaticPasswordService(&storeListError{})
	svc.SetContext(context.Background())

	err := svc.RenameFolder("old", "new")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// DeleteFolder error on store list
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_DeleteFolder_StoreListError(t *testing.T) {
	svc := NewStaticPasswordService(&storeListError{})
	svc.SetContext(context.Background())

	err := svc.DeleteFolder("folder")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// BackupPasswords error from store list
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_BackupPasswords_StoreListError(t *testing.T) {
	svc := NewStaticPasswordService(&storeListError{})
	svc.SetContext(context.Background())

	err := svc.BackupPasswords(filepath.Join(t.TempDir(), "backup.json"), false, "", "")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// RestorePasswords error from store list (during dedup)
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_RestorePasswords_StoreListError(t *testing.T) {
	svc := NewStaticPasswordService(&storeListError{})
	svc.SetContext(context.Background())

	entries := []StaticPasswordEntry{{Name: "entry", Password: "pw"}}
	data, marshalErr := json.Marshal(entries)
	require.NoError(t, marshalErr)

	filePath := filepath.Join(t.TempDir(), "restore.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	_, err := svc.RestorePasswords(filePath, false, "", "")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// AddPasswordV2 with all optional fields (URL, Username, Title, MatchPatterns)
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_AddPasswordV2_AllOptionalFields(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	expiry := time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)

	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:          "full-entry",
		Title:         "My Service",
		Username:      "admin",
		Password:      "supersecret",
		URL:           "https://service.example.com",
		MatchPatterns: []string{"service.example.com", "*.service.example.com"},
		Notes:         "Admin credentials",
		FolderPath:    "production/services",
		ExpiresAt:     expiry,
		ReadOnly:      true,
	})
	require.NoError(t, err)
	assert.Equal(t, "full-entry", entry.Name)
	assert.Equal(t, "My Service", entry.Title)
	assert.Equal(t, "admin", entry.Username)
	assert.Equal(t, "https://service.example.com", entry.URL)
	assert.Len(t, entry.MatchPatterns, 2)
	assert.True(t, entry.ReadOnly)
	assert.NotEmpty(t, entry.ExpiresAt)
}

// ---------------------------------------------------------------------------
// UpdatePasswordV2 with all optional fields
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_UpdatePasswordV2_AllOptionalFields(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Create first.
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "update-all",
		Password: "oldpw",
	})
	require.NoError(t, err)

	expiry := time.Now().Add(14 * 24 * time.Hour).Format(time.RFC3339)

	err = svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:            entry.ID,
		Name:          "update-all-renamed",
		Title:         "Updated Title",
		Username:      "newuser",
		Password:      "newpw",
		URL:           "https://updated.example.com",
		MatchPatterns: []string{"updated.example.com"},
		Notes:         "updated notes",
		FolderPath:    "updated/folder",
		ExpiresAt:     expiry,
	})
	require.NoError(t, err)

	got, getErr := svc.GetPassword("update-all-renamed")
	require.NoError(t, getErr)
	assert.Equal(t, "update-all-renamed", got.Name)
	assert.Equal(t, "Updated Title", got.Title)
	assert.Equal(t, "newuser", got.Username)
	assert.NotEmpty(t, got.ExpiresAt)
}

// ---------------------------------------------------------------------------
// MovePassword not found
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_MovePassword_NotFound(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.MovePassword("nonexistent-id", "new-folder")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// AddPassword (v1 compat) delegates to AddPasswordV2
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_AddPassword_DelegatesToV2(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entry, err := svc.AddPassword("compat-name", "compat-pw", "compat-notes")
	require.NoError(t, err)
	assert.Equal(t, "compat-name", entry.Name)
	assert.Equal(t, "compat-pw", entry.Password)
	assert.Equal(t, "compat-notes", entry.Notes)
}

// ---------------------------------------------------------------------------
// UpdatePassword (v1 compat) delegates to UpdatePasswordV2
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_UpdatePassword_DelegatesToV2(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entry, err := svc.AddPassword("compat-update", "pw1", "notes1")
	require.NoError(t, err)

	err = svc.UpdatePassword(entry.ID, "renamed", "pw2", "notes2")
	require.NoError(t, err)

	got, getErr := svc.GetPassword("renamed")
	require.NoError(t, getErr)
	assert.Equal(t, "renamed", got.Name)
	assert.Equal(t, "pw2", got.Password)
}

// ---------------------------------------------------------------------------
// Backup with encrypted store having multiple entries
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_BackupPasswords_MultipleEncrypted(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	for i := 0; i < 3; i++ {
		_, err := svc.AddPasswordV2(AddPasswordParams{
			Name:     "multi-" + string(rune('A'+i)),
			Password: "pw",
		})
		require.NoError(t, err)
	}

	outFile := filepath.Join(t.TempDir(), "multi.enc")
	err := svc.BackupPasswords(outFile, true, "aes-256", "key123")
	require.NoError(t, err)

	svc2, _ := newTestStaticPWService(t)
	imported, err := svc2.RestorePasswords(outFile, true, "aes-256", "key123")
	require.NoError(t, err)
	assert.Equal(t, 3, imported)
}

// ---------------------------------------------------------------------------
// GetPassword with store.Get error
// ---------------------------------------------------------------------------

// storeGetError is a mock store that returns an error from Get.
type storeGetError struct {
	staticpw.Store
}

func (s *storeGetError) Get(_ string) (*staticpw.StaticPassword, error) {
	return nil, errors.New("get failed")
}
func (s *storeGetError) List() ([]*staticpw.StaticPassword, error) { return nil, nil }
func (s *storeGetError) Add(_ *staticpw.StaticPassword) error      { return nil }
func (s *storeGetError) Update(_ *staticpw.StaticPassword) error   { return nil }
func (s *storeGetError) Delete(_ string) error                     { return nil }
func (s *storeGetError) ForceDelete(_ string) error                { return nil }
func (s *storeGetError) ListFolders() ([]string, error)            { return nil, nil }
func (s *storeGetError) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (s *storeGetError) MoveToFolder(_, _ string) error { return nil }

func TestStaticPWService_Coverage_GetPassword_StoreError(t *testing.T) {
	svc := NewStaticPasswordService(&storeGetError{})
	svc.SetContext(context.Background())

	_, err := svc.GetPassword("some-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get failed")
}

// ---------------------------------------------------------------------------
// UpdatePasswordV2 with store.Get error
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_UpdatePasswordV2_StoreGetError(t *testing.T) {
	svc := NewStaticPasswordService(&storeGetError{})
	svc.SetContext(context.Background())

	err := svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:   "some-id",
		Name: "test",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get failed")
}

// ---------------------------------------------------------------------------
// DeletePassword with store.Get error
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_DeletePassword_StoreGetError(t *testing.T) {
	svc := NewStaticPasswordService(&storeGetError{})
	svc.SetContext(context.Background())

	err := svc.DeletePassword("some-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get failed")
}

// ---------------------------------------------------------------------------
// PasswordStoreStatus types
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_PasswordStoreStatus_Fields(t *testing.T) {
	status := PasswordStoreStatus{
		AccessMode:    "pin",
		IsLocked:      true,
		AutoUnsealed:  false,
		PasswordCount: 10,
	}
	assert.Equal(t, "pin", status.AccessMode)
	assert.True(t, status.IsLocked)
	assert.False(t, status.AutoUnsealed)
	assert.Equal(t, 10, status.PasswordCount)
}

// ---------------------------------------------------------------------------
// ImportPreviewEntry and ImportPreviewResult types
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_ImportPreviewEntryFields(t *testing.T) {
	entry := ImportPreviewEntry{
		Title:      "Test",
		Username:   "user",
		URL:        "https://test.com",
		FolderPath: "folder",
		HasTOTP:    true,
		Tags:       []string{"tag1", "tag2"},
	}
	assert.Equal(t, "Test", entry.Title)
	assert.True(t, entry.HasTOTP)
	assert.Len(t, entry.Tags, 2)
}

func TestStaticPWService_Coverage_ImportResultFields(t *testing.T) {
	result := ImportResult{
		Imported:     5,
		Skipped:      2,
		Failed:       1,
		TOTPImported: 3,
		DurationMs:   150,
		Errors: []ImportError{
			{EntryName: "bad-entry", Error: "parse error"},
		},
	}
	assert.Equal(t, 5, result.Imported)
	assert.Equal(t, 2, result.Skipped)
	assert.Equal(t, 1, result.Failed)
	assert.Equal(t, 3, result.TOTPImported)
	assert.Equal(t, int64(150), result.DurationMs)
	assert.Len(t, result.Errors, 1)
}

// ---------------------------------------------------------------------------
// AddPasswordParams and UpdatePasswordParams types
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_AddPasswordParams_Fields(t *testing.T) {
	p := AddPasswordParams{
		Name:          "name",
		Title:         "title",
		Username:      "user",
		Password:      "pw",
		URL:           "url",
		MatchPatterns: []string{"p1"},
		Notes:         "notes",
		FolderPath:    "folder",
		ExpiresAt:     "2025-12-31T00:00:00Z",
		ReadOnly:      true,
	}
	assert.Equal(t, "name", p.Name)
	assert.True(t, p.ReadOnly)
}

func TestStaticPWService_Coverage_UpdatePasswordParams_Fields(t *testing.T) {
	p := UpdatePasswordParams{
		ID:            "id",
		Name:          "name",
		Title:         "title",
		Username:      "user",
		Password:      "pw",
		URL:           "url",
		MatchPatterns: []string{"p1"},
		Notes:         "notes",
		FolderPath:    "folder",
		ExpiresAt:     "2025-12-31T00:00:00Z",
	}
	assert.Equal(t, "id", p.ID)
	assert.Equal(t, "name", p.Name)
}

// ---------------------------------------------------------------------------
// ImportError fields
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_ImportError_Fields(t *testing.T) {
	e := ImportError{
		EntryName: "entry1",
		Error:     "bad format",
	}
	assert.Equal(t, "entry1", e.EntryName)
	assert.Equal(t, "bad format", e.Error)
}

// ---------------------------------------------------------------------------
// StaticPasswordEntry JSON marshaling
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_StaticPasswordEntry_JSON(t *testing.T) {
	entry := StaticPasswordEntry{
		ID:              "test-id",
		Name:            "test-name",
		Title:           "test-title",
		Username:        "test-user",
		Password:        "test-pw",
		URL:             "https://test.com",
		MatchPatterns:   []string{"*.test.com"},
		Notes:           "test notes",
		FolderPath:      "test/folder",
		ExpiresAt:       "2025-12-31T00:00:00Z",
		CreatedAt:       "2025-01-01T00:00:00Z",
		UpdatedAt:       "2025-06-01T00:00:00Z",
		IsExpired:       false,
		DaysUntilExpiry: 30,
		ReadOnly:        true,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded StaticPasswordEntry
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, entry, decoded)
}

// ---------------------------------------------------------------------------
// ImportParams JSON marshaling
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_ImportParams_JSON(t *testing.T) {
	params := ImportParams{
		FilePath:            "/path/to/file",
		Format:              "csv",
		Password:            "pw",
		TargetFolder:        "imported",
		SkipDuplicates:      true,
		OverwriteDuplicates: false,
		ImportTOTP:          true,
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var decoded ImportParams
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, params, decoded)
}

// ---------------------------------------------------------------------------
// DeletePasswordForce success with store get error
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_DeletePasswordForce_StoreError(t *testing.T) {
	store := &storeForceDeleteError{}
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())

	err := svc.DeletePasswordForce("some-id")
	assert.Error(t, err)
}

// storeForceDeleteError returns an error from ForceDelete.
type storeForceDeleteError struct {
	staticpw.Store
}

func (s *storeForceDeleteError) ForceDelete(_ string) error {
	return errors.New("force delete failed")
}
func (s *storeForceDeleteError) List() ([]*staticpw.StaticPassword, error) { return nil, nil }
func (s *storeForceDeleteError) Add(_ *staticpw.StaticPassword) error      { return nil }
func (s *storeForceDeleteError) Get(_ string) (*staticpw.StaticPassword, error) {
	return nil, nil
}
func (s *storeForceDeleteError) Update(_ *staticpw.StaticPassword) error { return nil }
func (s *storeForceDeleteError) Delete(_ string) error                   { return nil }
func (s *storeForceDeleteError) ListFolders() ([]string, error)          { return nil, nil }
func (s *storeForceDeleteError) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (s *storeForceDeleteError) MoveToFolder(_, _ string) error { return nil }

// ---------------------------------------------------------------------------
// AddPasswordV2 store.Add error
// ---------------------------------------------------------------------------

// storeAddError returns an error from Add.
type storeAddError struct {
	staticpw.Store
}

func (s *storeAddError) Add(_ *staticpw.StaticPassword) error      { return errors.New("add failed") }
func (s *storeAddError) List() ([]*staticpw.StaticPassword, error) { return nil, nil }
func (s *storeAddError) Get(_ string) (*staticpw.StaticPassword, error) {
	return nil, nil
}
func (s *storeAddError) Update(_ *staticpw.StaticPassword) error { return nil }
func (s *storeAddError) Delete(_ string) error                   { return nil }
func (s *storeAddError) ForceDelete(_ string) error              { return nil }
func (s *storeAddError) ListFolders() ([]string, error)          { return nil, nil }
func (s *storeAddError) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (s *storeAddError) MoveToFolder(_, _ string) error { return nil }

func TestStaticPWService_Coverage_AddPasswordV2_StoreAddError(t *testing.T) {
	svc := NewStaticPasswordService(&storeAddError{})
	svc.SetContext(context.Background())

	_, err := svc.AddPasswordV2(AddPasswordParams{Name: "test", Password: "pw"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "add failed")
}

// ---------------------------------------------------------------------------
// SetStore replaces the store
// ---------------------------------------------------------------------------

func TestStaticPWService_Coverage_SetStore_ReplaceStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())

	// Initially no store.
	_, err := svc.ListPasswords()
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)

	// Set a store.
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	svc.SetStore(store)

	// Now it should work.
	list, listErr := svc.ListPasswords()
	assert.NoError(t, listErr)
	assert.Empty(t, list)
}
