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

package truststore

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// newTestStore creates a FileStore in a temporary directory for testing.
func newTestStore(t *testing.T) *FileStore {
	t.Helper()

	dir := t.TempDir()
	store, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	return store
}

func TestNewFileStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d, want 0 for new store", count)
	}

	// Verify directories were created.
	certsDir := filepath.Join(dir, certsDirName)
	info, err := os.Stat(certsDir)
	if err != nil {
		t.Fatalf("certificates directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("certificates path is not a directory")
	}
}

func TestNewFileStore_NilConfig(t *testing.T) {
	_, err := NewFileStore(nil)
	if err == nil {
		t.Fatal("NewFileStore(nil) expected error, got nil")
	}
}

func TestNewFileStore_EmptyBaseDir(t *testing.T) {
	_, err := NewFileStore(&FileStoreConfig{BaseDir: ""})
	if err == nil {
		t.Fatal("NewFileStore(empty BaseDir) expected error, got nil")
	}
}

func TestNewFileStore_ReadOnlyParent(t *testing.T) {
	dir := t.TempDir()
	// Create a read-only directory so MkdirAll fails for subdirectory creation.
	readOnlyDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readOnlyDir, 0o500); err != nil {
		t.Fatalf("failed to create read-only directory: %v", err)
	}
	t.Cleanup(func() { os.Chmod(readOnlyDir, 0o700) })

	_, err := NewFileStore(&FileStoreConfig{BaseDir: filepath.Join(readOnlyDir, "subdir")})
	if err == nil {
		t.Fatal("NewFileStore() with read-only parent expected error, got nil")
	}
	if !errors.Is(err, ErrStorageWrite) {
		t.Errorf("NewFileStore() error = %v, want ErrStorageWrite", err)
	}
}

func TestAddCertificate(t *testing.T) {
	store := newTestStore(t)
	cert := generateTestCert(t, "Test Root CA")

	err := store.AddCertificate(cert)
	if err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d, want 1", count)
	}

	// Verify PEM file exists on disk.
	fp := Fingerprint(cert)
	pemPath := filepath.Join(store.config.BaseDir, certsDirName, fp+pemFileExt)
	if _, err := os.Stat(pemPath); err != nil {
		t.Errorf("PEM file not created at %s: %v", pemPath, err)
	}

	// Verify metadata.json exists and contains the certificate.
	metaPath := filepath.Join(store.config.BaseDir, metadataFile)
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("metadata.json not found: %v", err)
	}

	var entries []*CertMetadata
	if err := json.Unmarshal(metaData, &entries); err != nil {
		t.Fatalf("failed to parse metadata.json: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("metadata.json has %d entries, want 1", len(entries))
	}
	if entries[0].Fingerprint != fp {
		t.Errorf("metadata fingerprint = %q, want %q", entries[0].Fingerprint, fp)
	}
}

func TestAddCertificate_NilCert(t *testing.T) {
	store := newTestStore(t)

	err := store.AddCertificate(nil)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("AddCertificate(nil) error = %v, want ErrInvalidCertificate", err)
	}
}

func TestAddCertificate_Duplicate(t *testing.T) {
	store := newTestStore(t)
	cert := generateTestCert(t, "Test Root CA")

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("first AddCertificate() returned unexpected error: %v", err)
	}

	err := store.AddCertificate(cert)
	if !errors.Is(err, ErrCertificateExists) {
		t.Errorf("duplicate AddCertificate() error = %v, want ErrCertificateExists", err)
	}
}

func TestAddCertificate_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	cert := generateTestCert(t, "Test CA")
	err := store.AddCertificate(cert)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("AddCertificate() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestAddCertificate_WritePEMFailure(t *testing.T) {
	store := newTestStore(t)

	// Make the certificates directory read-only to cause PEM write failure.
	certsDir := filepath.Join(store.config.BaseDir, certsDirName)
	os.Chmod(certsDir, 0o500)
	t.Cleanup(func() { os.Chmod(certsDir, 0o700) })

	cert := generateTestCert(t, "Write Fail CA")
	err := store.AddCertificate(cert)
	if err == nil {
		t.Fatal("AddCertificate() expected error when cert dir is read-only, got nil")
	}
	if !errors.Is(err, ErrStorageWrite) {
		t.Errorf("AddCertificate() error = %v, want ErrStorageWrite", err)
	}

	// Store should remain empty (rolled back).
	count, _ := store.Count()
	if count != 0 {
		t.Errorf("Count() = %d after failed add, want 0", count)
	}
}

func TestAddCertificate_MetadataWriteFailure(t *testing.T) {
	store := newTestStore(t)

	// Add a certificate successfully first.
	cert1 := generateTestCert(t, "First CA")
	if err := store.AddCertificate(cert1); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	// Make the base directory read-only to cause metadata write failure
	// (temp file creation will fail).
	os.Chmod(store.config.BaseDir, 0o500)
	t.Cleanup(func() { os.Chmod(store.config.BaseDir, 0o700) })

	cert2 := generateTestCert(t, "Second CA")
	err := store.AddCertificate(cert2)
	if err == nil {
		t.Fatal("AddCertificate() expected error when base dir is read-only, got nil")
	}
	if !errors.Is(err, ErrStorageWrite) {
		t.Errorf("AddCertificate() error = %v, want ErrStorageWrite", err)
	}

	// Restore permissions to check count.
	os.Chmod(store.config.BaseDir, 0o700)

	// Should still only have the first cert (rollback on metadata failure).
	count, _ := store.Count()
	if count != 1 {
		t.Errorf("Count() = %d after metadata write failure, want 1", count)
	}
}

func TestAddPEM(t *testing.T) {
	store := newTestStore(t)

	pem1 := generateTestCertPEM(t, "CA One")
	pem2 := generateTestCertPEM(t, "CA Two")
	combined := append(pem1, pem2...)

	added, err := store.AddPEM(combined)
	if err != nil {
		t.Fatalf("AddPEM() returned unexpected error: %v", err)
	}
	if added != 2 {
		t.Errorf("AddPEM() added = %d, want 2", added)
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("Count() = %d, want 2", count)
	}
}

func TestAddPEM_EmptyData(t *testing.T) {
	store := newTestStore(t)

	_, err := store.AddPEM([]byte{})
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("AddPEM(empty) error = %v, want ErrInvalidCertificate", err)
	}
}

func TestAddPEM_InvalidPEM(t *testing.T) {
	store := newTestStore(t)

	_, err := store.AddPEM([]byte("not valid PEM data"))
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("AddPEM(invalid) error = %v, want ErrInvalidCertificate", err)
	}
}

func TestAddPEM_SkipsDuplicates(t *testing.T) {
	store := newTestStore(t)
	certPEM := generateTestCertPEM(t, "Duplicate CA")

	// Add once.
	added, err := store.AddPEM(certPEM)
	if err != nil {
		t.Fatalf("first AddPEM() returned unexpected error: %v", err)
	}
	if added != 1 {
		t.Errorf("first AddPEM() added = %d, want 1", added)
	}

	// Add same cert again via PEM.
	added, err = store.AddPEM(certPEM)
	if err != nil {
		t.Fatalf("second AddPEM() returned unexpected error: %v", err)
	}
	if added != 0 {
		t.Errorf("second AddPEM() added = %d, want 0 (duplicate should be skipped)", added)
	}
}

func TestAddPEM_CorruptDER(t *testing.T) {
	store := newTestStore(t)

	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("corrupt DER data"),
	})

	_, err := store.AddPEM(badPEM)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("AddPEM(corrupt DER) error = %v, want ErrInvalidCertificate", err)
	}
}

func TestRemoveCertificate(t *testing.T) {
	store := newTestStore(t)
	cert := generateTestCert(t, "Removable CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	err := store.RemoveCertificate(fp)
	if err != nil {
		t.Fatalf("RemoveCertificate() returned unexpected error: %v", err)
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d, want 0 after removal", count)
	}

	// Verify PEM file is deleted.
	pemPath := filepath.Join(store.config.BaseDir, certsDirName, fp+pemFileExt)
	if _, err := os.Stat(pemPath); !os.IsNotExist(err) {
		t.Error("PEM file still exists after RemoveCertificate()")
	}

	// Verify Contains returns false.
	contains, err := store.Contains(fp)
	if err != nil {
		t.Fatalf("Contains() returned unexpected error: %v", err)
	}
	if contains {
		t.Error("Contains() = true after RemoveCertificate(), want false")
	}
}

func TestRemoveCertificate_NotFound(t *testing.T) {
	store := newTestStore(t)

	// Valid fingerprint format, but no such cert.
	fp := "a" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
	err := store.RemoveCertificate(fp)
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Errorf("RemoveCertificate(nonexistent) error = %v, want ErrCertificateNotFound", err)
	}
}

func TestRemoveCertificate_InvalidFingerprint(t *testing.T) {
	store := newTestStore(t)

	tests := []struct {
		name string
		fp   string
	}{
		{"empty", ""},
		{"too short", "abcdef"},
		{"uppercase", "A0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE"},
		{"invalid chars", "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.RemoveCertificate(tt.fp)
			if !errors.Is(err, ErrInvalidFingerprint) {
				t.Errorf("RemoveCertificate(%q) error = %v, want ErrInvalidFingerprint", tt.fp, err)
			}
		})
	}
}

func TestRemoveCertificate_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	cert := generateTestCert(t, "Test CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	store.Close()

	err := store.RemoveCertificate(fp)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("RemoveCertificate() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestRemoveCertificate_PEMAlreadyDeleted(t *testing.T) {
	store := newTestStore(t)
	cert := generateTestCert(t, "Already Deleted CA")
	fp := Fingerprint(cert)

	store.AddCertificate(cert)

	// Manually delete the PEM file before calling RemoveCertificate.
	pemPath := filepath.Join(store.config.BaseDir, certsDirName, fp+pemFileExt)
	os.Remove(pemPath)

	// RemoveCertificate should still succeed (PEM already gone is not an error).
	err := store.RemoveCertificate(fp)
	if err != nil {
		t.Fatalf("RemoveCertificate() with already-deleted PEM returned unexpected error: %v", err)
	}

	count, _ := store.Count()
	if count != 0 {
		t.Errorf("Count() = %d after removal, want 0", count)
	}
}

func TestCertificates(t *testing.T) {
	store := newTestStore(t)

	cert1 := generateTestCert(t, "CA One")
	cert2 := generateTestCert(t, "CA Two")

	store.AddCertificate(cert1)
	store.AddCertificate(cert2)

	certs, err := store.Certificates()
	if err != nil {
		t.Fatalf("Certificates() returned unexpected error: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Certificates() returned %d certs, want 2", len(certs))
	}
}

func TestCertificates_Empty(t *testing.T) {
	store := newTestStore(t)

	certs, err := store.Certificates()
	if err != nil {
		t.Fatalf("Certificates() returned unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("Certificates() returned %d certs, want 0", len(certs))
	}
}

func TestCertificates_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	_, err := store.Certificates()
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Certificates() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestCertPool(t *testing.T) {
	store := newTestStore(t)

	cert := generateTestCert(t, "Pool Test CA")
	store.AddCertificate(cert)

	pool, err := store.CertPool()
	if err != nil {
		t.Fatalf("CertPool() returned unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("CertPool() returned nil")
	}

	// Verify the pool is usable in x509 verification.
	opts := x509.VerifyOptions{Roots: pool}
	if opts.Roots == nil {
		t.Error("pool is nil in VerifyOptions")
	}
}

func TestCertPool_Caching(t *testing.T) {
	store := newTestStore(t)
	cert := generateTestCert(t, "Cache Test CA")
	store.AddCertificate(cert)

	// First call builds the pool.
	pool1, err := store.CertPool()
	if err != nil {
		t.Fatalf("first CertPool() returned unexpected error: %v", err)
	}

	// Second call should return the cached pool.
	pool2, err := store.CertPool()
	if err != nil {
		t.Fatalf("second CertPool() returned unexpected error: %v", err)
	}

	if pool1 != pool2 {
		t.Error("CertPool() should return cached pool on second call")
	}

	// Mutation should invalidate the cache.
	cert2 := generateTestCert(t, "Another CA")
	store.AddCertificate(cert2)

	pool3, err := store.CertPool()
	if err != nil {
		t.Fatalf("third CertPool() returned unexpected error: %v", err)
	}

	if pool3 == pool1 {
		t.Error("CertPool() should return new pool after mutation")
	}
}

func TestCertPool_Empty(t *testing.T) {
	store := newTestStore(t)

	pool, err := store.CertPool()
	if err != nil {
		t.Fatalf("CertPool() returned unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("CertPool() returned nil for empty store")
	}
}

func TestCertPool_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	_, err := store.CertPool()
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("CertPool() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestContains(t *testing.T) {
	store := newTestStore(t)
	cert := generateTestCert(t, "Contains Test CA")
	fp := Fingerprint(cert)

	store.AddCertificate(cert)

	contains, err := store.Contains(fp)
	if err != nil {
		t.Fatalf("Contains() returned unexpected error: %v", err)
	}
	if !contains {
		t.Error("Contains() = false, want true for added certificate")
	}
}

func TestContains_NotFound(t *testing.T) {
	store := newTestStore(t)

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	contains, err := store.Contains(fp)
	if err != nil {
		t.Fatalf("Contains() returned unexpected error: %v", err)
	}
	if contains {
		t.Error("Contains() = true, want false for absent certificate")
	}
}

func TestContains_InvalidFingerprint(t *testing.T) {
	store := newTestStore(t)

	_, err := store.Contains("invalid")
	if !errors.Is(err, ErrInvalidFingerprint) {
		t.Errorf("Contains(invalid) error = %v, want ErrInvalidFingerprint", err)
	}
}

func TestContains_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_, err := store.Contains(fp)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Contains() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestCount(t *testing.T) {
	store := newTestStore(t)

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d, want 0", count)
	}

	store.AddCertificate(generateTestCert(t, "CA One"))
	store.AddCertificate(generateTestCert(t, "CA Two"))
	store.AddCertificate(generateTestCert(t, "CA Three"))

	count, err = store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("Count() = %d, want 3", count)
	}
}

func TestCount_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	_, err := store.Count()
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Count() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestClose(t *testing.T) {
	store := newTestStore(t)

	err := store.Close()
	if err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	// Double close should return ErrStoreClosed.
	err = store.Close()
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("double Close() error = %v, want ErrStoreClosed", err)
	}
}

func TestPersistence_ReloadFromMetadata(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create store and add certificates.
	store1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	cert1 := generateTestCert(t, "Persistent CA One")
	cert2 := generateTestCert(t, "Persistent CA Two")
	fp1 := Fingerprint(cert1)
	fp2 := Fingerprint(cert2)

	store1.AddCertificate(cert1)
	store1.AddCertificate(cert2)
	store1.Close()

	// Reopen store from the same directory.
	store2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() (reopen) returned unexpected error: %v", err)
	}
	defer store2.Close()

	count, err := store2.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("Count() = %d after reopen, want 2", count)
	}

	contains1, err := store2.Contains(fp1)
	if err != nil {
		t.Fatalf("Contains(fp1) returned unexpected error: %v", err)
	}
	if !contains1 {
		t.Error("Contains(fp1) = false after reopen, want true")
	}

	contains2, err := store2.Contains(fp2)
	if err != nil {
		t.Fatalf("Contains(fp2) returned unexpected error: %v", err)
	}
	if !contains2 {
		t.Error("Contains(fp2) = false after reopen, want true")
	}
}

func TestPersistence_ReloadFromPEMFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create store and add a certificate.
	store1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	cert := generateTestCert(t, "PEM Reload CA")
	store1.AddCertificate(cert)
	store1.Close()

	// Delete metadata.json to force rebuild from PEM files.
	metaPath := filepath.Join(dir, metadataFile)
	os.Remove(metaPath)

	// Reopen store; should rebuild from PEM files.
	store2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() (reopen without metadata) returned unexpected error: %v", err)
	}
	defer store2.Close()

	count, err := store2.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d after PEM rebuild, want 1", count)
	}

	fp := Fingerprint(cert)
	contains, err := store2.Contains(fp)
	if err != nil {
		t.Fatalf("Contains() returned unexpected error: %v", err)
	}
	if !contains {
		t.Error("Contains() = false after PEM rebuild, want true")
	}
}

func TestPersistence_CorruptMetadata(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create store and add a certificate.
	store1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	cert := generateTestCert(t, "Corrupt Meta CA")
	store1.AddCertificate(cert)
	store1.Close()

	// Corrupt metadata.json.
	metaPath := filepath.Join(dir, metadataFile)
	os.WriteFile(metaPath, []byte("{invalid json"), 0o600)

	// Reopen store; should fall back to PEM file rebuild.
	store2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() (corrupt metadata) returned unexpected error: %v", err)
	}
	defer store2.Close()

	count, err := store2.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d after corrupt metadata rebuild, want 1", count)
	}
}

func TestPersistence_MissingPEMFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create store and add two certificates.
	store1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	cert1 := generateTestCert(t, "Keep CA")
	cert2 := generateTestCert(t, "Remove CA")
	fp2 := Fingerprint(cert2)

	store1.AddCertificate(cert1)
	store1.AddCertificate(cert2)
	store1.Close()

	// Delete one PEM file without updating metadata.
	pemPath := filepath.Join(dir, certsDirName, fp2+pemFileExt)
	os.Remove(pemPath)

	// Reopen store; the missing PEM should be skipped.
	store2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() (missing PEM) returned unexpected error: %v", err)
	}
	defer store2.Close()

	count, err := store2.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d after missing PEM reopen, want 1", count)
	}
}

func TestPersistence_FingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create store and add a certificate.
	store1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	cert1 := generateTestCert(t, "Original CA")
	fp1 := Fingerprint(cert1)
	store1.AddCertificate(cert1)
	store1.Close()

	// Replace the PEM file content with a different certificate but keep
	// the original filename, creating a fingerprint mismatch.
	cert2 := generateTestCert(t, "Replacement CA")
	pemPath := filepath.Join(dir, certsDirName, fp1+pemFileExt)
	newPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert2.Raw,
	})
	os.WriteFile(pemPath, newPEM, pemFileMode)

	// Reopen store; the mismatched cert should be skipped during metadata load.
	store2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() (fingerprint mismatch) returned unexpected error: %v", err)
	}
	defer store2.Close()

	// The cert with mismatched fingerprint should be rejected.
	contains, _ := store2.Contains(fp1)
	if contains {
		t.Error("Contains(fp1) = true for fingerprint-mismatched cert, want false")
	}
}

func TestConcurrency(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	const numGoroutines = 20
	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines*3)

	// Concurrent adds.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cert := generateTestCert(t, "Concurrent CA")
			err := store.AddCertificate(cert)
			if err != nil && !errors.Is(err, ErrCertificateExists) {
				errCh <- err
			}
		}(i)
	}

	// Concurrent reads.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Certificates()
			if err != nil {
				errCh <- err
			}
			_, err = store.CertPool()
			if err != nil {
				errCh <- err
			}
			_, err = store.Count()
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent operation error: %v", err)
	}
}

func TestCertPool_InvalidatedAfterRemove(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "Remove Pool CA")
	fp := Fingerprint(cert)

	store.AddCertificate(cert)

	pool1, err := store.CertPool()
	if err != nil {
		t.Fatalf("CertPool() returned unexpected error: %v", err)
	}

	store.RemoveCertificate(fp)

	pool2, err := store.CertPool()
	if err != nil {
		t.Fatalf("CertPool() returned unexpected error: %v", err)
	}

	if pool1 == pool2 {
		t.Error("CertPool() should return new pool after RemoveCertificate()")
	}
}

func TestValidateFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		fp      string
		wantErr bool
	}{
		{"valid", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"empty", "", true},
		{"too short", "abcdef", true},
		{"too long", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00", true},
		{"uppercase", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", true},
		{"invalid chars", "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", true},
		{"spaces", "0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFingerprint(tt.fp)
			if tt.wantErr && err == nil {
				t.Errorf("validateFingerprint(%q) expected error, got nil", tt.fp)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateFingerprint(%q) unexpected error: %v", tt.fp, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidFingerprint) {
				t.Errorf("validateFingerprint(%q) error = %v, want ErrInvalidFingerprint", tt.fp, err)
			}
		})
	}
}

func TestMetadataContent(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "Metadata Test CA")
	fp := Fingerprint(cert)
	store.AddCertificate(cert)

	// Read metadata from the store's in-memory state.
	store.mu.RLock()
	meta, ok := store.metadata[fp]
	store.mu.RUnlock()

	if !ok {
		t.Fatal("metadata entry not found for added certificate")
	}

	if meta.Fingerprint != fp {
		t.Errorf("metadata.Fingerprint = %q, want %q", meta.Fingerprint, fp)
	}
	if meta.Subject == "" {
		t.Error("metadata.Subject is empty")
	}
	if meta.Issuer == "" {
		t.Error("metadata.Issuer is empty")
	}
	if meta.Algorithm != "ECDSA" {
		t.Errorf("metadata.Algorithm = %q, want %q", meta.Algorithm, "ECDSA")
	}
	if meta.AddedAt.IsZero() {
		t.Error("metadata.AddedAt is zero")
	}
	if meta.NotBefore.IsZero() {
		t.Error("metadata.NotBefore is zero")
	}
	if meta.NotAfter.IsZero() {
		t.Error("metadata.NotAfter is zero")
	}
}

func TestAddPEM_NonCertBlockSkipped(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// Create PEM with a non-certificate block followed by a valid cert.
	certPEM := generateTestCertPEM(t, "Valid CA")
	keyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake key data"),
	})

	combined := append(keyBlock, certPEM...)

	added, err := store.AddPEM(combined)
	if err != nil {
		t.Fatalf("AddPEM() returned unexpected error: %v", err)
	}
	if added != 1 {
		t.Errorf("AddPEM() added = %d, want 1 (non-cert blocks should be skipped)", added)
	}
}

func TestInterfaceCompliance(t *testing.T) {
	// Verify FileStore implements TrustStore interface at compile time.
	var _ TrustStore = (*FileStore)(nil)
}

func TestPersistence_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create an empty certificates directory manually.
	os.MkdirAll(filepath.Join(dir, certsDirName), dirMode)

	store, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() on empty dir returned unexpected error: %v", err)
	}
	defer store.Close()

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d for empty directory, want 0", count)
	}
}

func TestPersistence_NonPEMFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create certificates directory with a non-PEM file.
	certsDir := filepath.Join(dir, certsDirName)
	os.MkdirAll(certsDir, dirMode)
	os.WriteFile(filepath.Join(certsDir, "readme.txt"), []byte("not a cert"), 0o600)

	store, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}
	defer store.Close()

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d, want 0 (non-PEM files should be ignored)", count)
	}
}

func TestPersistence_CorruptPEMFileSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create a corrupt PEM file in the certificates directory.
	certsDir := filepath.Join(dir, certsDirName)
	os.MkdirAll(certsDir, dirMode)
	os.WriteFile(filepath.Join(certsDir, "badcert.pem"), []byte("corrupt pem"), 0o600)

	// Also add a valid cert.
	store1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	cert := generateTestCert(t, "Valid CA")
	store1.AddCertificate(cert)
	store1.Close()

	// Delete metadata to force PEM reload.
	os.Remove(filepath.Join(dir, metadataFile))

	// Reopen; corrupt PEM should be skipped, valid one loaded.
	store2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}
	defer store2.Close()

	count, err := store2.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d after corrupt PEM skip, want 1", count)
	}
}

func TestAddPEM_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	pemData := generateTestCertPEM(t, "Closed Store CA")
	_, err := store.AddPEM(pemData)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("AddPEM() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestPersistence_SubdirectoryInCertsDir(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	// Create a subdirectory inside certificates/ that should be ignored.
	certsDir := filepath.Join(dir, certsDirName)
	os.MkdirAll(filepath.Join(certsDir, "subdir"), dirMode)

	store, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}
	defer store.Close()

	count, _ := store.Count()
	if count != 0 {
		t.Errorf("Count() = %d, want 0 (subdirectories should be ignored)", count)
	}
}

func TestReadCertPEM_InvalidBlockType(t *testing.T) {
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "wrong-type.pem")

	// Write a PEM block that is not of type CERTIFICATE.
	badBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("key data"),
	})
	os.WriteFile(pemPath, badBlock, 0o600)

	_, err := readCertPEM(pemPath)
	if err == nil {
		t.Fatal("readCertPEM() expected error for wrong PEM block type, got nil")
	}
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("readCertPEM() error = %v, want ErrInvalidCertificate", err)
	}
}

func TestReadCertPEM_CorruptDER(t *testing.T) {
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "corrupt.pem")

	// Write a CERTIFICATE PEM block with garbage DER.
	badBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not valid DER"),
	})
	os.WriteFile(pemPath, badBlock, 0o600)

	_, err := readCertPEM(pemPath)
	if err == nil {
		t.Fatal("readCertPEM() expected error for corrupt DER, got nil")
	}
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("readCertPEM() error = %v, want ErrInvalidCertificate", err)
	}
}

func TestReadCertPEM_FileNotFound(t *testing.T) {
	_, err := readCertPEM("/nonexistent/path/cert.pem")
	if err == nil {
		t.Fatal("readCertPEM() expected error for missing file, got nil")
	}
	if !errors.Is(err, ErrStorageRead) {
		t.Errorf("readCertPEM() error = %v, want ErrStorageRead", err)
	}
}

// ---------------------------------------------------------------------------
// Tests for AddCertificateWithOptions
// ---------------------------------------------------------------------------

func TestAddCertificateWithOptions(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "Options CA")
	fp := Fingerprint(cert)

	opts := &AddCertificateOptions{
		Purpose: PurposeTPMManufacturer,
		Source:  "manual-import",
		Tags:    []string{"production", "hardware"},
	}

	err := store.AddCertificateWithOptions(cert, opts)
	if err != nil {
		t.Fatalf("AddCertificateWithOptions() returned unexpected error: %v", err)
	}

	// Verify the certificate was added.
	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d, want 1", count)
	}

	// Verify metadata has the explicit values from options.
	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Purpose != PurposeTPMManufacturer {
		t.Errorf("metadata.Purpose = %q, want %q", meta.Purpose, PurposeTPMManufacturer)
	}
	if meta.Source != "manual-import" {
		t.Errorf("metadata.Source = %q, want %q", meta.Source, "manual-import")
	}
	if len(meta.Tags) != 2 {
		t.Fatalf("metadata.Tags length = %d, want 2", len(meta.Tags))
	}
	if meta.Tags[0] != "production" || meta.Tags[1] != "hardware" {
		t.Errorf("metadata.Tags = %v, want [production hardware]", meta.Tags)
	}
}

func TestAddCertificateWithOptions_NilOpts(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "NilOpts CA")
	fp := Fingerprint(cert)

	// Nil opts should behave like AddCertificate (auto-classify).
	err := store.AddCertificateWithOptions(cert, nil)
	if err != nil {
		t.Fatalf("AddCertificateWithOptions(nil opts) returned unexpected error: %v", err)
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d, want 1", count)
	}

	// Verify auto-classification occurred (self-signed CA -> PurposeUserCA).
	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Purpose != PurposeUserCA {
		t.Errorf("metadata.Purpose = %q, want %q (auto-classified)", meta.Purpose, PurposeUserCA)
	}
}

func TestAddCertificateWithOptions_NilCert(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	opts := &AddCertificateOptions{
		Purpose: PurposeGeneral,
	}

	err := store.AddCertificateWithOptions(nil, opts)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("AddCertificateWithOptions(nil cert) error = %v, want ErrInvalidCertificate", err)
	}
}

func TestAddCertificateWithOptions_Duplicate(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "Duplicate Opts CA")

	opts := &AddCertificateOptions{
		Purpose: PurposeBootstrapCA,
		Source:  "bootstrap",
	}

	if err := store.AddCertificateWithOptions(cert, opts); err != nil {
		t.Fatalf("first AddCertificateWithOptions() returned unexpected error: %v", err)
	}

	err := store.AddCertificateWithOptions(cert, opts)
	if !errors.Is(err, ErrCertificateExists) {
		t.Errorf("duplicate AddCertificateWithOptions() error = %v, want ErrCertificateExists", err)
	}
}

func TestAddCertificateWithOptions_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	cert := generateTestCert(t, "Closed Opts CA")
	opts := &AddCertificateOptions{
		Purpose: PurposeGeneral,
	}

	err := store.AddCertificateWithOptions(cert, opts)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("AddCertificateWithOptions() on closed store error = %v, want ErrStoreClosed", err)
	}
}

// ---------------------------------------------------------------------------
// Tests for CertificatesByPurpose
// ---------------------------------------------------------------------------

func TestCertificatesByPurpose(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// Add certs with different purposes.
	cert1 := generateTestCert(t, "TPM Cert One")
	cert2 := generateTestCert(t, "TPM Cert Two")
	cert3 := generateTestCert(t, "Bootstrap Cert")

	store.AddCertificateWithOptions(cert1, &AddCertificateOptions{
		Purpose: PurposeTPMManufacturer,
	})
	store.AddCertificateWithOptions(cert2, &AddCertificateOptions{
		Purpose: PurposeTPMManufacturer,
	})
	store.AddCertificateWithOptions(cert3, &AddCertificateOptions{
		Purpose: PurposeBootstrapCA,
	})

	// Query for TPM manufacturer certs only.
	tpmCerts, err := store.CertificatesByPurpose(PurposeTPMManufacturer)
	if err != nil {
		t.Fatalf("CertificatesByPurpose() returned unexpected error: %v", err)
	}
	if len(tpmCerts) != 2 {
		t.Errorf("CertificatesByPurpose(TPMManufacturer) returned %d certs, want 2", len(tpmCerts))
	}

	// Query for bootstrap certs.
	bootstrapCerts, err := store.CertificatesByPurpose(PurposeBootstrapCA)
	if err != nil {
		t.Fatalf("CertificatesByPurpose() returned unexpected error: %v", err)
	}
	if len(bootstrapCerts) != 1 {
		t.Errorf("CertificatesByPurpose(BootstrapCA) returned %d certs, want 1", len(bootstrapCerts))
	}
}

func TestCertificatesByPurpose_Empty(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// Add a cert with a different purpose than what we query for.
	cert := generateTestCert(t, "Other Purpose CA")
	store.AddCertificateWithOptions(cert, &AddCertificateOptions{
		Purpose: PurposeTPMManufacturer,
	})

	// Query for a purpose that has no matching certs.
	certs, err := store.CertificatesByPurpose(PurposeAndroidHardware)
	if err != nil {
		t.Fatalf("CertificatesByPurpose() returned unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("CertificatesByPurpose(AndroidHardware) returned %d certs, want 0", len(certs))
	}
}

func TestCertificatesByPurpose_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	_, err := store.CertificatesByPurpose(PurposeGeneral)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("CertificatesByPurpose() on closed store error = %v, want ErrStoreClosed", err)
	}
}

// ---------------------------------------------------------------------------
// Tests for Metadata
// ---------------------------------------------------------------------------

func TestMetadata(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "Metadata Query CA")
	fp := Fingerprint(cert)

	opts := &AddCertificateOptions{
		Purpose: PurposeIDevIDIssuer,
		Source:  "idevid-enrollment",
		Tags:    []string{"device-identity"},
	}
	if err := store.AddCertificateWithOptions(cert, opts); err != nil {
		t.Fatalf("AddCertificateWithOptions() returned unexpected error: %v", err)
	}

	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}

	if meta.Fingerprint != fp {
		t.Errorf("metadata.Fingerprint = %q, want %q", meta.Fingerprint, fp)
	}
	if meta.Subject == "" {
		t.Error("metadata.Subject is empty")
	}
	if meta.Issuer == "" {
		t.Error("metadata.Issuer is empty")
	}
	if meta.Algorithm != "ECDSA" {
		t.Errorf("metadata.Algorithm = %q, want %q", meta.Algorithm, "ECDSA")
	}
	if meta.AddedAt.IsZero() {
		t.Error("metadata.AddedAt is zero")
	}
	if meta.NotBefore.IsZero() {
		t.Error("metadata.NotBefore is zero")
	}
	if meta.NotAfter.IsZero() {
		t.Error("metadata.NotAfter is zero")
	}
	if meta.Purpose != PurposeIDevIDIssuer {
		t.Errorf("metadata.Purpose = %q, want %q", meta.Purpose, PurposeIDevIDIssuer)
	}
	if meta.Source != "idevid-enrollment" {
		t.Errorf("metadata.Source = %q, want %q", meta.Source, "idevid-enrollment")
	}
	if len(meta.Tags) != 1 || meta.Tags[0] != "device-identity" {
		t.Errorf("metadata.Tags = %v, want [device-identity]", meta.Tags)
	}
}

func TestMetadata_NotFound(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// Valid fingerprint format, but no certificate stored.
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_, err := store.Metadata(fp)
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Errorf("Metadata(nonexistent) error = %v, want ErrCertificateNotFound", err)
	}
}

func TestMetadata_InvalidFingerprint(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	_, err := store.Metadata("not-a-valid-fingerprint")
	if !errors.Is(err, ErrInvalidFingerprint) {
		t.Errorf("Metadata(invalid) error = %v, want ErrInvalidFingerprint", err)
	}
}

func TestMetadata_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_, err := store.Metadata(fp)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Metadata() on closed store error = %v, want ErrStoreClosed", err)
	}
}

// ---------------------------------------------------------------------------
// Tests for SetPurpose
// ---------------------------------------------------------------------------

func TestSetPurpose(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "SetPurpose CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	// Verify initial auto-classified purpose.
	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Purpose != PurposeUserCA {
		t.Errorf("initial metadata.Purpose = %q, want %q", meta.Purpose, PurposeUserCA)
	}

	// Update purpose.
	if err := store.SetPurpose(fp, PurposeBootstrapCA); err != nil {
		t.Fatalf("SetPurpose() returned unexpected error: %v", err)
	}

	// Verify updated purpose.
	meta, err = store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Purpose != PurposeBootstrapCA {
		t.Errorf("updated metadata.Purpose = %q, want %q", meta.Purpose, PurposeBootstrapCA)
	}
}

func TestSetPurpose_NotFound(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := store.SetPurpose(fp, PurposeGeneral)
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Errorf("SetPurpose(nonexistent) error = %v, want ErrCertificateNotFound", err)
	}
}

func TestSetPurpose_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	store.Close()

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := store.SetPurpose(fp, PurposeGeneral)
	if !errors.Is(err, ErrStoreClosed) {
		t.Errorf("SetPurpose() on closed store error = %v, want ErrStoreClosed", err)
	}
}

func TestSetPurpose_PersistsAfterReopen(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileStoreConfig{BaseDir: dir}

	store1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() returned unexpected error: %v", err)
	}

	cert := generateTestCert(t, "Persist Purpose CA")
	fp := Fingerprint(cert)

	if err := store1.AddCertificate(cert); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	// Set purpose and close.
	if err := store1.SetPurpose(fp, PurposeTPMManufacturer); err != nil {
		t.Fatalf("SetPurpose() returned unexpected error: %v", err)
	}
	store1.Close()

	// Reopen and verify persistence.
	store2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("NewFileStore() (reopen) returned unexpected error: %v", err)
	}
	defer store2.Close()

	meta, err := store2.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Purpose != PurposeTPMManufacturer {
		t.Errorf("metadata.Purpose after reopen = %q, want %q", meta.Purpose, PurposeTPMManufacturer)
	}
}

// ---------------------------------------------------------------------------
// Tests for SetSource
// ---------------------------------------------------------------------------

func TestSetSource(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "SetSource CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	// Verify initial source is empty.
	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Source != "" {
		t.Errorf("initial metadata.Source = %q, want empty", meta.Source)
	}

	// Set source.
	if err := store.SetSource(fp, "tpm-vendor-download"); err != nil {
		t.Fatalf("SetSource() returned unexpected error: %v", err)
	}

	// Verify updated source.
	meta, err = store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Source != "tpm-vendor-download" {
		t.Errorf("updated metadata.Source = %q, want %q", meta.Source, "tpm-vendor-download")
	}
}

func TestSetSource_NotFound(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := store.SetSource(fp, "some-source")
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Errorf("SetSource(nonexistent) error = %v, want ErrCertificateNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Tests for SetSystemInstalled
// ---------------------------------------------------------------------------

func TestSetSystemInstalled(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "SystemInstalled CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	// Verify initial system_installed is false.
	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.SystemInstalled {
		t.Error("initial metadata.SystemInstalled = true, want false")
	}

	// Set to true.
	if err := store.SetSystemInstalled(fp, true); err != nil {
		t.Fatalf("SetSystemInstalled(true) returned unexpected error: %v", err)
	}

	meta, err = store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if !meta.SystemInstalled {
		t.Error("metadata.SystemInstalled = false after set to true, want true")
	}

	// Set back to false.
	if err := store.SetSystemInstalled(fp, false); err != nil {
		t.Fatalf("SetSystemInstalled(false) returned unexpected error: %v", err)
	}

	meta, err = store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.SystemInstalled {
		t.Error("metadata.SystemInstalled = true after set to false, want false")
	}
}

func TestSetSystemInstalled_NotFound(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := store.SetSystemInstalled(fp, true)
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Errorf("SetSystemInstalled(nonexistent) error = %v, want ErrCertificateNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Tests for SetTags
// ---------------------------------------------------------------------------

func TestSetTags(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "SetTags CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("AddCertificate() returned unexpected error: %v", err)
	}

	// Verify initial tags are nil/empty.
	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if len(meta.Tags) != 0 {
		t.Errorf("initial metadata.Tags = %v, want empty", meta.Tags)
	}

	// Set tags.
	tags := []string{"critical", "root-ca", "internal"}
	if err := store.SetTags(fp, tags); err != nil {
		t.Fatalf("SetTags() returned unexpected error: %v", err)
	}

	// Verify updated tags.
	meta, err = store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if len(meta.Tags) != 3 {
		t.Fatalf("metadata.Tags length = %d, want 3", len(meta.Tags))
	}
	if meta.Tags[0] != "critical" || meta.Tags[1] != "root-ca" || meta.Tags[2] != "internal" {
		t.Errorf("metadata.Tags = %v, want [critical root-ca internal]", meta.Tags)
	}

	// Verify defensive copy: modifying the original slice does not affect stored tags.
	tags[0] = "modified"
	meta, err = store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Tags[0] != "critical" {
		t.Errorf("metadata.Tags[0] = %q after modifying source slice, want %q (defensive copy)", meta.Tags[0], "critical")
	}
}

func TestSetTags_EmptySlice(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	cert := generateTestCert(t, "EmptyTags CA")
	fp := Fingerprint(cert)

	opts := &AddCertificateOptions{
		Purpose: PurposeGeneral,
		Tags:    []string{"initial-tag"},
	}
	if err := store.AddCertificateWithOptions(cert, opts); err != nil {
		t.Fatalf("AddCertificateWithOptions() returned unexpected error: %v", err)
	}

	// Set empty tags -- should clear tags to nil.
	if err := store.SetTags(fp, []string{}); err != nil {
		t.Fatalf("SetTags(empty) returned unexpected error: %v", err)
	}

	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() returned unexpected error: %v", err)
	}
	if meta.Tags != nil {
		t.Errorf("metadata.Tags = %v after SetTags(empty), want nil", meta.Tags)
	}
}

func TestSetTags_NotFound(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := store.SetTags(fp, []string{"tag"})
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Errorf("SetTags(nonexistent) error = %v, want ErrCertificateNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Tests for auto-classification
// ---------------------------------------------------------------------------

func TestNewCertMetadata_AutoClassifiesPurpose(t *testing.T) {
	// generateTestCert creates a self-signed CA cert (IsCA=true,
	// Subject.Organization == Issuer.Organization, Subject.CN == Issuer.CN).
	// ClassifyCertificate should classify this as PurposeUserCA.
	cert := generateTestCert(t, "Auto Classify CA")
	fp := Fingerprint(cert)

	meta := newCertMetadata(cert, fp)
	if meta.Purpose != PurposeUserCA {
		t.Errorf("newCertMetadata() auto-classified Purpose = %q, want %q", meta.Purpose, PurposeUserCA)
	}
}
