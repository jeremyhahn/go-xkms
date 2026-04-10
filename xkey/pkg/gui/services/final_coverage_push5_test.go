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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// ---------------------------------------------------------------------------
// Mock types for Part 7 tests
// ---------------------------------------------------------------------------

// p7MockStaticPWStore implements staticpw.Store with configurable Add errors.
type p7MockStaticPWStore struct {
	passwords []*staticpw.StaticPassword
	addErr    error
}

func (m *p7MockStaticPWStore) Add(pw *staticpw.StaticPassword) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.passwords = append(m.passwords, pw)
	return nil
}
func (m *p7MockStaticPWStore) Get(string) (*staticpw.StaticPassword, error) {
	return nil, errors.New("not found")
}
func (m *p7MockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	return m.passwords, nil
}
func (m *p7MockStaticPWStore) Update(*staticpw.StaticPassword) error { return nil }
func (m *p7MockStaticPWStore) Delete(string) error                   { return nil }
func (m *p7MockStaticPWStore) ForceDelete(string) error              { return nil }
func (m *p7MockStaticPWStore) ListByFolder(string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *p7MockStaticPWStore) ListByFolderDirect(string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *p7MockStaticPWStore) ListFolders() ([]string, error)    { return nil, nil }
func (m *p7MockStaticPWStore) MoveToFolder(string, string) error { return nil }
func (m *p7MockStaticPWStore) Close() error                      { return nil }
func (m *p7MockStaticPWStore) CreateFolder(string) error         { return nil }
func (m *p7MockStaticPWStore) RemoveFolder(string) error         { return nil }

// p7EventCapture captures emitted events for verification.
type p7EventCapture struct {
	events []events.Event
}

func (c *p7EventCapture) emit(ev events.Event) {
	c.events = append(c.events, ev)
}

// ---------------------------------------------------------------------------
// Trust Service - GetBrowserBundleStatus fingerprint mismatch (lines 461-464)
//
// This branch fires when the manifest has the same cert count as the
// current eligible set, but the fingerprints differ.
// ---------------------------------------------------------------------------

func TestP7_TrustService_GetBrowserBundleStatus_FingerprintMismatch(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add a cert tagged for export.
	cert1 := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert1))
	fp1 := truststore.Fingerprint(cert1)
	require.NoError(t, store.SetTags(fp1, []string{TagBrowserExport}))

	// Export the bundle to create the manifest.
	bundleDir := t.TempDir()
	bundlePath := filepath.Join(bundleDir, "trust-bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Replace the cert: remove old, add new. Count stays 1 but fingerprint changes.
	require.NoError(t, store.RemoveCertificate(fp1))
	cert2 := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert2))
	fp2 := truststore.Fingerprint(cert2)
	require.NoError(t, store.SetTags(fp2, []string{TagBrowserExport}))

	status := svc.GetBrowserBundleStatus(bundlePath)
	assert.True(t, status.Exists, "bundle file should exist")
	assert.True(t, status.Stale, "bundle should be stale when fingerprints differ but count matches")
}

// ---------------------------------------------------------------------------
// Trust Service - ExportBrowserTrustBundle MkdirAll error (lines 390-392)
// ---------------------------------------------------------------------------

func TestP7_TrustService_ExportBrowserTrustBundle_MkdirAllError(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)
	require.NoError(t, store.SetTags(fp, []string{TagBrowserExport}))

	// Path under /dev/null cannot have directories created.
	badPath := "/dev/null/impossible/trust-bundle.pem"
	_, err := svc.ExportBrowserTrustBundle(badPath)
	assert.Error(t, err, "ExportBrowserTrustBundle should fail with invalid directory")
	assert.True(t, errors.Is(err, ErrBrowserTrustBundleExport),
		"error should wrap ErrBrowserTrustBundleExport")
}

// ---------------------------------------------------------------------------
// Trust Service - ExportBrowserTrustBundle WriteFile error (lines 394-396)
// ---------------------------------------------------------------------------

func TestP7_TrustService_ExportBrowserTrustBundle_WriteFileError(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)
	require.NoError(t, store.SetTags(fp, []string{TagBrowserExport}))

	// Create the directory as read-only so WriteFile fails.
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(roDir, 0o500))
	defer func() { _ = os.Chmod(roDir, 0o700) }()

	bundlePath := filepath.Join(roDir, "trust-bundle.pem")
	_, err := svc.ExportBrowserTrustBundle(bundlePath)
	assert.Error(t, err, "ExportBrowserTrustBundle should fail on read-only directory")
	assert.True(t, errors.Is(err, ErrBrowserTrustBundleExport),
		"error should wrap ErrBrowserTrustBundleExport")
}

// ---------------------------------------------------------------------------
// Trust Service - ExportBrowserTrustBundle Certificates() error (line 345)
// ---------------------------------------------------------------------------

func TestP7_TrustService_ExportBrowserTrustBundle_CertificatesError(t *testing.T) {
	store := newTestFileStore(t)
	svc := NewTrustService(store)

	// Close the store to force Certificates() to return an error.
	store.Close()

	bundlePath := filepath.Join(t.TempDir(), "trust-bundle.pem")
	_, err := svc.ExportBrowserTrustBundle(bundlePath)
	assert.Error(t, err, "ExportBrowserTrustBundle should fail when store is closed")
}

// ---------------------------------------------------------------------------
// Trust Service - eligibleFingerprints returns nil when store is closed (line 596-598)
// ---------------------------------------------------------------------------

func TestP7_TrustService_EligibleFingerprintsError(t *testing.T) {
	store := newTestFileStore(t)
	svc := NewTrustService(store)

	store.Close()

	// Create a bundle file so we pass the Stat check.
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trust-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("dummy"), 0o644))

	// Write a manifest with one fingerprint.
	manifest := bundleManifest{
		Fingerprints: []string{"abc123"},
		GeneratedAt:  time.Now().UTC(),
		CertCount:    1,
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, browserBundleManifestFile), manifestData, 0o644))

	// eligibleFingerprints returns nil due to closed store => len mismatch => stale.
	status := svc.GetBrowserBundleStatus(bundlePath)
	assert.True(t, status.Exists)
	assert.True(t, status.Stale, "should be stale when eligibleFingerprints returns nil")
}

// ---------------------------------------------------------------------------
// Trust Service - ExportBrowserTrustBundle no tagged certs (count==0, remove stale bundle)
// This exercises the count==0 path (lines 383-386) and the os.Remove call.
// ---------------------------------------------------------------------------

func TestP7_TrustService_ExportBrowserTrustBundle_RemovesStaleBundle(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add a cert WITHOUT the browser-export tag.
	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))

	// Pre-create a stale bundle file.
	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("old data"), 0o644))

	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "should export 0 certs")

	// Verify the stale bundle was removed.
	_, statErr := os.Stat(bundlePath)
	assert.True(t, os.IsNotExist(statErr), "stale bundle should be removed")
}

// ---------------------------------------------------------------------------
// Custodian Service - getClient nil returns ErrCustodianServiceNoClient
// (5 uncovered statements across GetGroup, ListGroups, DeleteGroup,
//  AddMember, RemoveMember, DistributeShares)
// ---------------------------------------------------------------------------

func TestP7_CustodianService_GetGroup_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())
	_, err := svc.GetGroup("some-id")
	assert.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

func TestP7_CustodianService_ListGroups_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())
	_, err := svc.ListGroups()
	assert.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

func TestP7_CustodianService_DeleteGroup_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())
	err := svc.DeleteGroup("some-id")
	assert.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

func TestP7_CustodianService_AddMember_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())
	_, err := svc.AddMember("group-1", "user-1", "test-user", "admin_approval")
	assert.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

func TestP7_CustodianService_RemoveMember_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())
	err := svc.RemoveMember("group-1", "user-1")
	assert.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

func TestP7_CustodianService_DistributeShares_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())
	_, err := svc.DistributeShares("group-1")
	assert.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

// ---------------------------------------------------------------------------
// Agent Service - error paths
// ---------------------------------------------------------------------------

func TestP7_AgentService_StartServer_NilEnrollment(t *testing.T) {
	svc := NewAgentService()
	svc.SetContext(context.Background())
	err := svc.StartServer(":0")
	assert.ErrorIs(t, err, ErrAgentServiceNotReady)
}

func TestP7_AgentService_StartServer_EmptyAddress(t *testing.T) {
	svc := NewAgentService()
	svc.SetContext(context.Background())
	err := svc.StartServer("")
	assert.ErrorIs(t, err, ErrAgentInvalidAddress)
}

func TestP7_AgentService_StopServer_NotRunning(t *testing.T) {
	svc := NewAgentService()
	svc.SetContext(context.Background())
	err := svc.StopServer()
	assert.ErrorIs(t, err, ErrAgentServerNotStarted)
}

func TestP7_AgentService_GenerateEnrollmentCode_NilEnrollment(t *testing.T) {
	svc := NewAgentService()
	svc.SetContext(context.Background())
	_, err := svc.GenerateEnrollmentCode()
	assert.ErrorIs(t, err, ErrAgentServiceNotReady)
}

func TestP7_AgentService_ListPendingEnrollments_NilEnrollment(t *testing.T) {
	svc := NewAgentService()
	svc.SetContext(context.Background())
	_, err := svc.ListPendingEnrollments()
	assert.ErrorIs(t, err, ErrAgentServiceNotReady)
}

func TestP7_AgentService_ListAgents_NilStore(t *testing.T) {
	svc := NewAgentService()
	svc.SetContext(context.Background())
	_, err := svc.ListAgents()
	assert.ErrorIs(t, err, ErrAgentNilStore)
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom source does not exist (line 515-517)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_SourceNotExist(t *testing.T) {
	svc := NewSealService(t.TempDir())
	count, err := svc.MigrateFrom("/nonexistent/path")
	require.NoError(t, err)
	assert.Equal(t, 0, count, "should return 0 when source doesn't exist")
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom empty source (line 520-522)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_EmptySource(t *testing.T) {
	srcDir := t.TempDir()
	svc := NewSealService(t.TempDir())
	count, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "should return 0 for empty source")
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom ensureStorageDir error (line 527-529)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_EnsureStorageDirError(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "legacy")
	require.NoError(t, os.MkdirAll(srcDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "test.json"), []byte(`{}`), 0o644))

	// Point storageDir to an impossible path.
	svc := NewSealService("/dev/null/impossible/dir")
	_, err := svc.MigrateFrom(srcDir)
	assert.ErrorIs(t, err, ErrSealMigrationFailed)
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom read error on unreadable source (line 546-549)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_ReadError(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "legacy")
	require.NoError(t, os.MkdirAll(srcDir, 0o700))

	srcFile := filepath.Join(srcDir, "blob.json")
	require.NoError(t, os.WriteFile(srcFile, []byte(`{}`), 0o000))
	defer func() { _ = os.Chmod(srcFile, 0o644) }()

	svc := NewSealService(filepath.Join(dir, "dest"))
	count, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "should skip unreadable files")
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom write error to read-only dest (line 551-554)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_WriteError(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "legacy")
	dstDir := filepath.Join(dir, "dest")

	require.NoError(t, os.MkdirAll(srcDir, 0o700))
	require.NoError(t, os.MkdirAll(dstDir, 0o500))
	defer func() { _ = os.Chmod(dstDir, 0o700) }()

	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "blob.json"), []byte(`{}`), 0o644))

	svc := NewSealService(dstDir)
	count, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "should skip files that can't be written to dest")
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom skips existing destination files (line 540-542)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_SkipsExisting(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "legacy")
	dstDir := filepath.Join(dir, "dest")

	require.NoError(t, os.MkdirAll(srcDir, 0o700))
	require.NoError(t, os.MkdirAll(dstDir, 0o700))

	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "existing.json"), []byte(`{"src":"new"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "fresh.json"), []byte(`{"src":"new"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, "existing.json"), []byte(`{"src":"old"}`), 0o644))

	svc := NewSealService(dstDir)
	count, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "should migrate only the fresh file")

	// Verify existing file was not overwritten.
	data, readErr := os.ReadFile(filepath.Join(dstDir, "existing.json"))
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "old", "existing file should not be overwritten")
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom skips non-JSON and directories (line 533-535)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_SkipsNonJSON(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "legacy")
	require.NoError(t, os.MkdirAll(srcDir, 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "readme.txt"), []byte("text"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "valid.json"), []byte(`{}`), 0o644))

	svc := NewSealService(filepath.Join(dir, "dest"))
	count, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "should migrate only the .json file")
}

// ---------------------------------------------------------------------------
// Seal Service - MigrateFrom ReadDir error (line 518)
// ---------------------------------------------------------------------------

func TestP7_SealService_MigrateFrom_ReadDirError(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "unreadable")
	require.NoError(t, os.MkdirAll(srcDir, 0o000))
	defer func() { _ = os.Chmod(srcDir, 0o700) }()

	svc := NewSealService(filepath.Join(dir, "dest"))
	_, err := svc.MigrateFrom(srcDir)
	assert.ErrorIs(t, err, ErrSealMigrationFailed)
}

// ---------------------------------------------------------------------------
// Seal Service - hashPassword and verifyPassword (lines 1209-1211)
// ---------------------------------------------------------------------------

func TestP7_SealService_VerifyPassword_InvalidFormats(t *testing.T) {
	assert.False(t, verifyPassword("test", "no-colon-separator"),
		"invalid hash format should not verify")
	assert.False(t, verifyPassword("test", "invalid-hex:invalid-hex"),
		"invalid hex should not verify")

	hash, err := hashPassword("correct-password")
	require.NoError(t, err)
	assert.True(t, verifyPassword("correct-password", hash))
	assert.False(t, verifyPassword("wrong-password", hash))
}

// ---------------------------------------------------------------------------
// Seal Service - ListBlobs with invalid JSON (lines 603-607 panic recovery)
// ---------------------------------------------------------------------------

func TestP7_SealService_ListBlobs_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	// Write an invalid JSON file with the .sealed.json extension.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.sealed.json"), []byte(`not json`), 0o644))

	entries, err := svc.ListBlobs()
	// Either returns an error or empty list but should not panic.
	if err != nil {
		assert.NotEmpty(t, err.Error())
	} else {
		_ = entries
	}
}

// ---------------------------------------------------------------------------
// StaticPasswordService - RestorePasswords with store.Add error (line 680-681)
// ---------------------------------------------------------------------------

func TestP7_StaticPW_RestorePasswords_AddError(t *testing.T) {
	dir := t.TempDir()
	backupFile := filepath.Join(dir, "backup.json")

	entries := []StaticPasswordEntry{
		{Name: "entry1", Password: "pass1"},
		{Name: "entry2", Password: "pass2"},
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(backupFile, data, 0o644))

	store := &p7MockStaticPWStore{addErr: errors.New("store full")}
	svc := NewStaticPasswordService(store)

	imported, err := svc.RestorePasswords(backupFile, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, 0, imported, "should import 0 when Add fails")
}

// ---------------------------------------------------------------------------
// StaticPasswordService - RestorePasswords with ExpiresAt parsing (line 673-678)
// ---------------------------------------------------------------------------

func TestP7_StaticPW_RestorePasswords_WithExpiresAt(t *testing.T) {
	dir := t.TempDir()
	backupFile := filepath.Join(dir, "backup.json")

	expires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	entries := []StaticPasswordEntry{
		{Name: "entry1", Password: "pass1", ExpiresAt: expires},
		{Name: "entry2", Password: "pass2", ExpiresAt: "invalid-date"},
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(backupFile, data, 0o644))

	store := &p7MockStaticPWStore{}
	svc := NewStaticPasswordService(store)

	imported, err := svc.RestorePasswords(backupFile, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, 2, imported)
	require.Len(t, store.passwords, 2)
	assert.False(t, store.passwords[0].ExpiresAt.IsZero(), "valid date should be parsed")
	assert.True(t, store.passwords[1].ExpiresAt.IsZero(), "invalid date should yield zero time")
}

// ---------------------------------------------------------------------------
// StaticPasswordService - decryptBackup error paths
// ---------------------------------------------------------------------------

func TestP7_StaticPW_DecryptBackup_TooShortData(t *testing.T) {
	_, err := decryptBackup([]byte{0x01, 0x02, 0x03}, "aes-256", "test")
	assert.ErrorIs(t, err, ErrRestoreDecryptFailed)
}

func TestP7_StaticPW_DecryptBackup_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	backupFile := filepath.Join(dir, "enc.json")

	store := &p7MockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{Name: "test", Password: "secret"},
		},
	}
	svc := NewStaticPasswordService(store)
	require.NoError(t, svc.BackupPasswords(backupFile, true, "aes-256", "correct"))

	data, err := os.ReadFile(backupFile)
	require.NoError(t, err)

	_, err = decryptBackup(data, "aes-256", "wrong-password")
	assert.ErrorIs(t, err, ErrRestoreDecryptFailed)
}

func TestP7_StaticPW_DecryptBackup_InvalidAlgorithm(t *testing.T) {
	_, err := decryptBackup([]byte("dummy"), "invalid-algo", "password")
	assert.ErrorIs(t, err, ErrBackupInvalidAlgorithm)
}

// ---------------------------------------------------------------------------
// StaticPasswordService - RestorePasswords encrypted round-trip
// ---------------------------------------------------------------------------

func TestP7_StaticPW_RestorePasswords_EncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	backupFile := filepath.Join(dir, "backup.enc")

	store := &p7MockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{Name: "pw1", Password: "secret1"},
			{Name: "pw2", Password: "secret2"},
		},
	}
	svc := NewStaticPasswordService(store)
	require.NoError(t, svc.BackupPasswords(backupFile, true, "aes-256", "backup-password"))

	store2 := &p7MockStaticPWStore{}
	svc2 := NewStaticPasswordService(store2)
	imported, err := svc2.RestorePasswords(backupFile, true, "aes-256", "backup-password")
	require.NoError(t, err)
	assert.Equal(t, 2, imported)
}

func TestP7_StaticPW_RestorePasswords_EncryptedMissingPassword(t *testing.T) {
	svc := NewStaticPasswordService(&p7MockStaticPWStore{})
	_, err := svc.RestorePasswords("/some/file", true, "aes-256", "")
	assert.ErrorIs(t, err, ErrBackupPasswordRequired)
}

// ---------------------------------------------------------------------------
// StaticPasswordService - PreviewImport file not found (line 938-940)
// ---------------------------------------------------------------------------

func TestP7_StaticPW_PreviewImport_FileNotFound(t *testing.T) {
	svc := NewStaticPasswordService(&p7MockStaticPWStore{})
	_, err := svc.PreviewImport(ImportParams{
		FilePath: "/nonexistent/file.csv",
		Format:   "csv",
	})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// StaticPasswordService - ImportPasswords file not found (line 989-994 loop)
// ---------------------------------------------------------------------------

func TestP7_StaticPW_ImportPasswords_FileNotFound(t *testing.T) {
	svc := NewStaticPasswordService(&p7MockStaticPWStore{})
	_, err := svc.ImportPasswords(ImportParams{
		FilePath: "/nonexistent/file.csv",
		Format:   "csv",
	})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Connection Service - Connect with SPKI pin path (lines 138-148)
// ---------------------------------------------------------------------------

func TestP7_ConnectionService_Connect_SPKIPinWithCAFile(t *testing.T) {
	cap := &p7EventCapture{}
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetEventEmitter(cap.emit)

	_, err := svc.Connect("grpc", "localhost:1", true, "/tmp/nonexistent-ca.pem", "sha256/abc123")
	assert.Error(t, err, "should fail when server is not reachable")
}

// ---------------------------------------------------------------------------
// Connection Service - Connect without SPKI pin (lines 150-157)
// ---------------------------------------------------------------------------

func TestP7_ConnectionService_Connect_NoSPKIPin(t *testing.T) {
	cap := &p7EventCapture{}
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetEventEmitter(cap.emit)

	_, err := svc.Connect("rest", "localhost:1", false, "", "")
	assert.Error(t, err, "should fail when server is not reachable")
}

// ---------------------------------------------------------------------------
// PINService - ChangeSOPIN / ChangeUserPIN error paths (lines 171-174, 199-202)
// ---------------------------------------------------------------------------

func TestP7_PINService_ChangeSOPIN_NoPINService(t *testing.T) {
	svc := NewPINService()
	err := svc.ChangeSOPIN("old", "new")
	assert.Error(t, err)
}

func TestP7_PINService_ChangeUserPIN_NoPINService(t *testing.T) {
	svc := NewPINService()
	err := svc.ChangeUserPIN("old", "new")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Certificate Service - ListCertificates no client (line 83-87)
// ---------------------------------------------------------------------------

func TestP7_CertificateService_ListCertificates_NoClient(t *testing.T) {
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	result, err := svc.ListCertificates("software")
	assert.ErrorIs(t, err, ErrCertServiceNoClient)
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// OATH Service - GenerateHOTP type mismatch (line 236-238)
// ---------------------------------------------------------------------------

func TestP7_OATHService_GenerateHOTP_WrongType(t *testing.T) {
	oathStore := oath.NewMemoryStore()
	svc := NewOATHService(oathStore)

	// Add a TOTP credential.
	_, err := svc.AddAccountManual("test-account", "test-issuer", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)

	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)

	// Try to generate HOTP for a TOTP account.
	_, err = svc.GenerateHOTP(accounts[0].ID)
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

func TestP7_OATHService_GenerateHOTP_NilStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.GenerateHOTP("some-id")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

func TestP7_OATHService_GenerateHOTP_EmptyID(t *testing.T) {
	oathStore := oath.NewMemoryStore()
	svc := NewOATHService(oathStore)
	_, err := svc.GenerateHOTP("")
	assert.ErrorIs(t, err, ErrOATHInvalidID)
}

// ---------------------------------------------------------------------------
// OATH Service - GenerateTOTP type mismatch (line 197-199)
// ---------------------------------------------------------------------------

func TestP7_OATHService_GenerateTOTP_WrongType_HOTP(t *testing.T) {
	oathStore := oath.NewMemoryStore()
	svc := NewOATHService(oathStore)

	// Add an HOTP credential via URI.
	_, err := svc.AddAccountFromURI("otpauth://hotp/testissuer:testuser?secret=JBSWY3DPEHPK3PXP&counter=0&issuer=testissuer")
	require.NoError(t, err)

	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)

	_, err = svc.GenerateTOTP(accounts[0].ID)
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

// ---------------------------------------------------------------------------
// Clipboard Service - CopyToClipboard tool unavailable (line 96-98)
// ---------------------------------------------------------------------------

func TestP7_ClipboardService_CopyToClipboard_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	err := svc.CopyWithClear("test")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}
