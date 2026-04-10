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
	"context"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newTestBackendStore creates a BackendStore backed by in-memory storage.
func newTestBackendStore(t *testing.T) *BackendStore {
	t.Helper()
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "trust/")
	if err != nil {
		t.Fatalf("failed to create backend store: %v", err)
	}
	return store
}

// --- NewBackendStore tests ---

func TestBackendStore_NewBackendStore_Success(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "trust/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.prefix != "trust/" {
		t.Errorf("expected prefix %q, got %q", "trust/", store.prefix)
	}
}

func TestBackendStore_NewBackendStore_NilBackend(t *testing.T) {
	_, err := NewBackendStore(nil, "trust/")
	if err == nil {
		t.Fatal("expected error for nil backend")
	}
}

func TestBackendStore_NewBackendStore_EmptyPrefix(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.prefix != "" {
		t.Errorf("expected empty prefix, got %q", store.prefix)
	}
}

func TestBackendStore_NewBackendStore_LoadsExisting(t *testing.T) {
	backend := storage.NewMemory()
	cert := generateTestCert(t, "Preloaded CA")
	fp := Fingerprint(cert)

	// Pre-populate the backend with a certificate and metadata.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := backend.Put(context.Background(), "trust/certificates/"+fp+".pem", pemBytes); err != nil {
		t.Fatalf("failed to put cert: %v", err)
	}
	meta := newCertMetadata(cert, fp)
	metaBytes, _ := json.Marshal(meta)
	if err := backend.Put(context.Background(), "trust/metadata/"+fp+".json", metaBytes); err != nil {
		t.Fatalf("failed to put metadata: %v", err)
	}

	// Create store - should load existing data.
	store, err := NewBackendStore(backend, "trust/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 loaded certificate, got %d", count)
	}

	contains, err := store.Contains(fp)
	if err != nil {
		t.Fatalf("Contains() error: %v", err)
	}
	if !contains {
		t.Error("expected store to contain preloaded certificate")
	}
}

// --- AddCertificate tests ---

func TestBackendStore_AddCertificate_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Test CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the certificate is in the store.
	contains, err := store.Contains(fp)
	if err != nil {
		t.Fatalf("Contains() error: %v", err)
	}
	if !contains {
		t.Error("expected store to contain added certificate")
	}

	// Verify the certificate was persisted to the backend.
	certData, err := store.backend.Get(context.Background(), store.certKey(fp))
	if err != nil {
		t.Fatalf("cert not found in backend: %v", err)
	}
	if len(certData) == 0 {
		t.Error("expected non-empty cert data in backend")
	}

	// Verify metadata was persisted.
	metaData, err := store.backend.Get(context.Background(), store.metaKey(fp))
	if err != nil {
		t.Fatalf("metadata not found in backend: %v", err)
	}
	if len(metaData) == 0 {
		t.Error("expected non-empty metadata in backend")
	}
}

func TestBackendStore_AddCertificate_NilCert(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.AddCertificate(nil)
	if err != ErrInvalidCertificate {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestBackendStore_AddCertificate_Duplicate(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Dup CA")

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	err := store.AddCertificate(cert)
	if err != ErrCertificateExists {
		t.Fatalf("expected ErrCertificateExists, got %v", err)
	}
}

func TestBackendStore_AddCertificate_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.Close()

	err := store.AddCertificate(generateTestCert(t, "Closed CA"))
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- AddCertificateWithOptions tests ---

func TestBackendStore_AddCertificateWithOptions_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Options CA")
	fp := Fingerprint(cert)

	opts := &AddCertificateOptions{
		Purpose: PurposeTPMManufacturer,
		Source:  "manual-import",
		Tags:    []string{"tpm", "test"},
	}

	if err := store.AddCertificateWithOptions(cert, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() error: %v", err)
	}
	if meta.Purpose != PurposeTPMManufacturer {
		t.Errorf("expected purpose %q, got %q", PurposeTPMManufacturer, meta.Purpose)
	}
	if meta.Source != "manual-import" {
		t.Errorf("expected source %q, got %q", "manual-import", meta.Source)
	}
	if len(meta.Tags) != 2 || meta.Tags[0] != "tpm" || meta.Tags[1] != "test" {
		t.Errorf("unexpected tags: %v", meta.Tags)
	}
}

func TestBackendStore_AddCertificateWithOptions_NilCert(t *testing.T) {
	store := newTestBackendStore(t)
	opts := &AddCertificateOptions{Purpose: PurposeGeneral}

	err := store.AddCertificateWithOptions(nil, opts)
	if err != ErrInvalidCertificate {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestBackendStore_AddCertificateWithOptions_NilOpts(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "NilOpts CA")

	if err := store.AddCertificateWithOptions(cert, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count, _ := store.Count()
	if count != 1 {
		t.Errorf("expected 1 certificate, got %d", count)
	}
}

func TestBackendStore_AddCertificateWithOptions_Duplicate(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "DupOpts CA")
	opts := &AddCertificateOptions{Purpose: PurposeGeneral}

	if err := store.AddCertificateWithOptions(cert, opts); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	err := store.AddCertificateWithOptions(cert, opts)
	if err != ErrCertificateExists {
		t.Fatalf("expected ErrCertificateExists, got %v", err)
	}
}

func TestBackendStore_AddCertificateWithOptions_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.Close()

	err := store.AddCertificateWithOptions(generateTestCert(t, "Closed CA"), &AddCertificateOptions{})
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- AddPEM tests ---

func TestBackendStore_AddPEM_Success(t *testing.T) {
	store := newTestBackendStore(t)
	pemData := generateTestCertPEM(t, "PEM CA Add")

	count, err := store.AddPEM(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 added, got %d", count)
	}

	total, _ := store.Count()
	if total != 1 {
		t.Errorf("expected 1 total, got %d", total)
	}
}

func TestBackendStore_AddPEM_MultipleCerts(t *testing.T) {
	store := newTestBackendStore(t)
	pem1 := generateTestCertPEM(t, "PEM CA 1")
	pem2 := generateTestCertPEM(t, "PEM CA 2")

	pemData := append(pem1, pem2...)

	count, err := store.AddPEM(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 added, got %d", count)
	}
}

func TestBackendStore_AddPEM_SkipsDuplicates(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Dup PEM CA")

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	count, err := store.AddPEM(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 added (duplicate), got %d", count)
	}
}

func TestBackendStore_AddPEM_EmptyData(t *testing.T) {
	store := newTestBackendStore(t)

	_, err := store.AddPEM(nil)
	if err != ErrInvalidCertificate {
		t.Fatalf("expected ErrInvalidCertificate for nil data, got %v", err)
	}

	_, err = store.AddPEM([]byte{})
	if err != ErrInvalidCertificate {
		t.Fatalf("expected ErrInvalidCertificate for empty data, got %v", err)
	}
}

func TestBackendStore_AddPEM_InvalidPEM(t *testing.T) {
	store := newTestBackendStore(t)

	_, err := store.AddPEM([]byte("not valid pem data"))
	if err == nil {
		t.Fatal("expected error for invalid PEM data")
	}
}

// --- RemoveCertificate tests ---

func TestBackendStore_RemoveCertificate_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Remove CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	if err := store.RemoveCertificate(fp); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	contains, _ := store.Contains(fp)
	if contains {
		t.Error("certificate should have been removed")
	}

	count, _ := store.Count()
	if count != 0 {
		t.Errorf("expected 0 certificates, got %d", count)
	}

	// Verify backend entries are deleted.
	_, certErr := store.backend.Get(context.Background(), store.certKey(fp))
	if certErr == nil {
		t.Error("expected cert key to be deleted from backend")
	}
	_, metaErr := store.backend.Get(context.Background(), store.metaKey(fp))
	if metaErr == nil {
		t.Error("expected meta key to be deleted from backend")
	}
}

func TestBackendStore_RemoveCertificate_NotFound(t *testing.T) {
	store := newTestBackendStore(t)

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	err := store.RemoveCertificate(fp)
	if err != ErrCertificateNotFound {
		t.Fatalf("expected ErrCertificateNotFound, got %v", err)
	}
}

func TestBackendStore_RemoveCertificate_InvalidFingerprint(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.RemoveCertificate("invalid")
	if err != ErrInvalidFingerprint {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}
}

func TestBackendStore_RemoveCertificate_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Remove Closed CA")
	fp := Fingerprint(cert)

	if err := store.AddCertificate(cert); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	_ = store.Close()

	err := store.RemoveCertificate(fp)
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- Certificates tests ---

func TestBackendStore_Certificates_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert1 := generateTestCert(t, "Cert 1")
	cert2 := generateTestCert(t, "Cert 2")

	_ = store.AddCertificate(cert1)
	_ = store.AddCertificate(cert2)

	certs, err := store.Certificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
	}
}

func TestBackendStore_Certificates_Empty(t *testing.T) {
	store := newTestBackendStore(t)

	certs, err := store.Certificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(certs))
	}
}

func TestBackendStore_Certificates_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.Close()

	_, err := store.Certificates()
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- CertificatesByPurpose tests ---

func TestBackendStore_CertificatesByPurpose_Success(t *testing.T) {
	store := newTestBackendStore(t)

	cert1 := generateTestCert(t, "TPM Mfr CA")
	cert2 := generateTestCert(t, "User CA")

	_ = store.AddCertificateWithOptions(cert1, &AddCertificateOptions{Purpose: PurposeTPMManufacturer})
	_ = store.AddCertificateWithOptions(cert2, &AddCertificateOptions{Purpose: PurposeUserCA})

	tpmCerts, err := store.CertificatesByPurpose(PurposeTPMManufacturer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tpmCerts) != 1 {
		t.Errorf("expected 1 TPM manufacturer cert, got %d", len(tpmCerts))
	}

	userCerts, err := store.CertificatesByPurpose(PurposeUserCA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(userCerts) != 1 {
		t.Errorf("expected 1 user CA cert, got %d", len(userCerts))
	}
}

func TestBackendStore_CertificatesByPurpose_NoneMatch(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.AddCertificate(generateTestCert(t, "General CA"))

	certs, err := store.CertificatesByPurpose(PurposeAndroidHardware)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(certs))
	}
}

func TestBackendStore_CertificatesByPurpose_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.Close()

	_, err := store.CertificatesByPurpose(PurposeGeneral)
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- Metadata tests ---

func TestBackendStore_Metadata_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Meta CA")
	fp := Fingerprint(cert)

	_ = store.AddCertificate(cert)

	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Fingerprint != fp {
		t.Errorf("expected fingerprint %q, got %q", fp, meta.Fingerprint)
	}
	if meta.Subject == "" {
		t.Error("expected non-empty subject")
	}
	if meta.Issuer == "" {
		t.Error("expected non-empty issuer")
	}
	if meta.Algorithm == "" {
		t.Error("expected non-empty algorithm")
	}
	if meta.AddedAt.IsZero() {
		t.Error("expected non-zero AddedAt")
	}
}

func TestBackendStore_Metadata_NotFound(t *testing.T) {
	store := newTestBackendStore(t)

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	_, err := store.Metadata(fp)
	if err != ErrCertificateNotFound {
		t.Fatalf("expected ErrCertificateNotFound, got %v", err)
	}
}

func TestBackendStore_Metadata_InvalidFingerprint(t *testing.T) {
	store := newTestBackendStore(t)

	_, err := store.Metadata("bad")
	if err != ErrInvalidFingerprint {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}
}

func TestBackendStore_Metadata_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Closed Meta CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)
	_ = store.Close()

	_, err := store.Metadata(fp)
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- SetPurpose tests ---

func TestBackendStore_SetPurpose_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Purpose CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)

	if err := store.SetPurpose(fp, PurposeIDevIDIssuer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, _ := store.Metadata(fp)
	if meta.Purpose != PurposeIDevIDIssuer {
		t.Errorf("expected purpose %q, got %q", PurposeIDevIDIssuer, meta.Purpose)
	}

	// Verify persisted in backend.
	metaData, err := store.backend.Get(context.Background(), store.metaKey(fp))
	if err != nil {
		t.Fatalf("metadata not persisted: %v", err)
	}
	var persisted CertMetadata
	_ = json.Unmarshal(metaData, &persisted)
	if persisted.Purpose != PurposeIDevIDIssuer {
		t.Errorf("expected persisted purpose %q, got %q", PurposeIDevIDIssuer, persisted.Purpose)
	}
}

func TestBackendStore_SetPurpose_NotFound(t *testing.T) {
	store := newTestBackendStore(t)

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	err := store.SetPurpose(fp, PurposeGeneral)
	if err != ErrCertificateNotFound {
		t.Fatalf("expected ErrCertificateNotFound, got %v", err)
	}
}

func TestBackendStore_SetPurpose_InvalidFingerprint(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.SetPurpose("bad", PurposeGeneral)
	if err != ErrInvalidFingerprint {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}
}

func TestBackendStore_SetPurpose_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Closed Purpose CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)
	_ = store.Close()

	err := store.SetPurpose(fp, PurposeGeneral)
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- SetSource tests ---

func TestBackendStore_SetSource_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Source CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)

	if err := store.SetSource(fp, "api-upload"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, _ := store.Metadata(fp)
	if meta.Source != "api-upload" {
		t.Errorf("expected source %q, got %q", "api-upload", meta.Source)
	}
}

func TestBackendStore_SetSource_NotFound(t *testing.T) {
	store := newTestBackendStore(t)

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	err := store.SetSource(fp, "test")
	if err != ErrCertificateNotFound {
		t.Fatalf("expected ErrCertificateNotFound, got %v", err)
	}
}

func TestBackendStore_SetSource_InvalidFingerprint(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.SetSource("bad", "test")
	if err != ErrInvalidFingerprint {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}
}

func TestBackendStore_SetSource_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Closed Source CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)
	_ = store.Close()

	err := store.SetSource(fp, "test")
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- SetSystemInstalled tests ---

func TestBackendStore_SetSystemInstalled_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "SysInstall CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)

	if err := store.SetSystemInstalled(fp, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, _ := store.Metadata(fp)
	if !meta.SystemInstalled {
		t.Error("expected SystemInstalled to be true")
	}

	// Set back to false.
	if err := store.SetSystemInstalled(fp, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, _ = store.Metadata(fp)
	if meta.SystemInstalled {
		t.Error("expected SystemInstalled to be false")
	}
}

func TestBackendStore_SetSystemInstalled_NotFound(t *testing.T) {
	store := newTestBackendStore(t)

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	err := store.SetSystemInstalled(fp, true)
	if err != ErrCertificateNotFound {
		t.Fatalf("expected ErrCertificateNotFound, got %v", err)
	}
}

func TestBackendStore_SetSystemInstalled_InvalidFingerprint(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.SetSystemInstalled("bad", true)
	if err != ErrInvalidFingerprint {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}
}

func TestBackendStore_SetSystemInstalled_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Closed SysInstall CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)
	_ = store.Close()

	err := store.SetSystemInstalled(fp, true)
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- SetTags tests ---

func TestBackendStore_SetTags_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Tags CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)

	tags := []string{"production", "primary"}
	if err := store.SetTags(fp, tags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, _ := store.Metadata(fp)
	if len(meta.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(meta.Tags))
	}
	if meta.Tags[0] != "production" || meta.Tags[1] != "primary" {
		t.Errorf("unexpected tags: %v", meta.Tags)
	}

	// Verify tags are a copy (modifying original should not affect stored).
	tags[0] = "modified"
	meta, _ = store.Metadata(fp)
	if meta.Tags[0] != "production" {
		t.Error("tags should be a copy, not a reference")
	}
}

func TestBackendStore_SetTags_ClearTags(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "ClearTags CA")
	fp := Fingerprint(cert)

	_ = store.AddCertificateWithOptions(cert, &AddCertificateOptions{Tags: []string{"old"}})

	if err := store.SetTags(fp, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, _ := store.Metadata(fp)
	if meta.Tags != nil {
		t.Errorf("expected nil tags, got %v", meta.Tags)
	}
}

func TestBackendStore_SetTags_EmptySlice(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "EmptyTags CA")
	fp := Fingerprint(cert)

	_ = store.AddCertificateWithOptions(cert, &AddCertificateOptions{Tags: []string{"old"}})

	if err := store.SetTags(fp, []string{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, _ := store.Metadata(fp)
	if meta.Tags != nil {
		t.Errorf("expected nil tags, got %v", meta.Tags)
	}
}

func TestBackendStore_SetTags_NotFound(t *testing.T) {
	store := newTestBackendStore(t)

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	err := store.SetTags(fp, []string{"test"})
	if err != ErrCertificateNotFound {
		t.Fatalf("expected ErrCertificateNotFound, got %v", err)
	}
}

func TestBackendStore_SetTags_InvalidFingerprint(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.SetTags("bad", []string{"test"})
	if err != ErrInvalidFingerprint {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}
}

func TestBackendStore_SetTags_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Closed Tags CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)
	_ = store.Close()

	err := store.SetTags(fp, []string{"test"})
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- CertPool tests ---

func TestBackendStore_CertPool_Success(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Pool CA")
	_ = store.AddCertificate(cert)

	pool, err := store.CertPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	// Second call should return cached pool.
	pool2, err := store.CertPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool != pool2 {
		t.Error("expected cached pool on second call")
	}
}

func TestBackendStore_CertPool_EmptyStore(t *testing.T) {
	store := newTestBackendStore(t)

	pool, err := store.CertPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool even for empty store")
	}
}

func TestBackendStore_CertPool_InvalidatedOnMutation(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Pool Mutation CA")

	pool1, _ := store.CertPool()

	_ = store.AddCertificate(cert)

	pool2, _ := store.CertPool()
	if pool1 == pool2 {
		t.Error("expected pool to be rebuilt after mutation")
	}
}

func TestBackendStore_CertPool_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.Close()

	_, err := store.CertPool()
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- Contains tests ---

func TestBackendStore_Contains_True(t *testing.T) {
	store := newTestBackendStore(t)
	cert := generateTestCert(t, "Contains CA")
	fp := Fingerprint(cert)
	_ = store.AddCertificate(cert)

	contains, err := store.Contains(fp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contains {
		t.Error("expected Contains to return true")
	}
}

func TestBackendStore_Contains_False(t *testing.T) {
	store := newTestBackendStore(t)

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	contains, err := store.Contains(fp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contains {
		t.Error("expected Contains to return false")
	}
}

func TestBackendStore_Contains_InvalidFingerprint(t *testing.T) {
	store := newTestBackendStore(t)

	_, err := store.Contains("bad")
	if err != ErrInvalidFingerprint {
		t.Fatalf("expected ErrInvalidFingerprint, got %v", err)
	}
}

func TestBackendStore_Contains_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.Close()

	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	_, err := store.Contains(fp)
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- Count tests ---

func TestBackendStore_Count_Success(t *testing.T) {
	store := newTestBackendStore(t)

	count, err := store.Count()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	_ = store.AddCertificate(generateTestCert(t, "Count CA 1"))
	_ = store.AddCertificate(generateTestCert(t, "Count CA 2"))

	count, err = store.Count()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestBackendStore_Count_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.Close()

	_, err := store.Count()
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

// --- Close tests ---

func TestBackendStore_Close_Success(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second close should return ErrStoreClosed.
	err = store.Close()
	if err != ErrStoreClosed {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}

func TestBackendStore_Close_ClearsPool(t *testing.T) {
	store := newTestBackendStore(t)
	_ = store.AddCertificate(generateTestCert(t, "Close Pool CA"))

	// Populate the pool cache.
	_, _ = store.CertPool()

	_ = store.Close()

	if store.pool != nil {
		t.Error("expected pool to be nil after close")
	}
}

// --- Persistence round-trip test ---

func TestBackendStore_PersistenceRoundTrip(t *testing.T) {
	backend := storage.NewMemory()
	cert := generateTestCert(t, "Roundtrip CA")
	fp := Fingerprint(cert)

	// First store instance: add a certificate.
	store1, err := NewBackendStore(backend, "trust/")
	if err != nil {
		t.Fatalf("store1 creation failed: %v", err)
	}

	opts := &AddCertificateOptions{
		Purpose: PurposeBootstrapCA,
		Source:  "enrollment",
		Tags:    []string{"bootstrap", "primary"},
	}
	if err := store1.AddCertificateWithOptions(cert, opts); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	if err := store1.SetSystemInstalled(fp, true); err != nil {
		t.Fatalf("SetSystemInstalled failed: %v", err)
	}

	_ = store1.Close()

	// Second store instance: verify data was loaded from backend.
	store2, err := NewBackendStore(backend, "trust/")
	if err != nil {
		t.Fatalf("store2 creation failed: %v", err)
	}
	defer store2.Close()

	count, _ := store2.Count()
	if count != 1 {
		t.Fatalf("expected 1 certificate after reload, got %d", count)
	}

	contains, _ := store2.Contains(fp)
	if !contains {
		t.Fatal("expected certificate to survive reload")
	}

	meta, err := store2.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() error after reload: %v", err)
	}
	if meta.Purpose != PurposeBootstrapCA {
		t.Errorf("expected purpose %q, got %q", PurposeBootstrapCA, meta.Purpose)
	}
	if meta.Source != "enrollment" {
		t.Errorf("expected source %q, got %q", "enrollment", meta.Source)
	}
	if len(meta.Tags) != 2 || meta.Tags[0] != "bootstrap" || meta.Tags[1] != "primary" {
		t.Errorf("unexpected tags after reload: %v", meta.Tags)
	}
	if !meta.SystemInstalled {
		t.Error("expected SystemInstalled to be true after reload")
	}
}

// --- Rebuild from certs test (metadata-less recovery) ---

func TestBackendStore_RebuildFromCertsOnly(t *testing.T) {
	backend := storage.NewMemory()
	cert := generateTestCert(t, "Orphan CA")
	fp := Fingerprint(cert)

	// Store only PEM, no metadata.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := backend.Put(context.Background(), "trust/certificates/"+fp+".pem", pemBytes); err != nil {
		t.Fatalf("failed to put cert: %v", err)
	}

	store, err := NewBackendStore(backend, "trust/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store.Close()

	count, _ := store.Count()
	if count != 1 {
		t.Errorf("expected 1 rebuilt certificate, got %d", count)
	}

	contains, _ := store.Contains(fp)
	if !contains {
		t.Error("expected store to contain rebuilt certificate")
	}

	// Verify metadata was rebuilt and persisted.
	meta, err := store.Metadata(fp)
	if err != nil {
		t.Fatalf("Metadata() error: %v", err)
	}
	if meta.Fingerprint != fp {
		t.Errorf("expected fingerprint %q, got %q", fp, meta.Fingerprint)
	}
}

// --- extractFingerprint helper tests ---

func TestBackendStore_extractFingerprint_Valid(t *testing.T) {
	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	key := "trust/certificates/" + fp + ".pem"
	got := extractFingerprint(key, "trust/certificates/", ".pem")
	if got != fp {
		t.Errorf("expected %q, got %q", fp, got)
	}
}

func TestBackendStore_extractFingerprint_InvalidPrefix(t *testing.T) {
	got := extractFingerprint("wrong/prefix/abc.pem", "trust/certificates/", ".pem")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestBackendStore_extractFingerprint_InvalidSuffix(t *testing.T) {
	fp := "a000000000000000000000000000000000000000000000000000000000000001"
	got := extractFingerprint("trust/certificates/"+fp+".json", "trust/certificates/", ".pem")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestBackendStore_extractFingerprint_InvalidFingerprint(t *testing.T) {
	got := extractFingerprint("trust/certificates/not-hex.pem", "trust/certificates/", ".pem")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// --- parsePEMBytes tests ---

func TestBackendStore_parsePEMBytes_Valid(t *testing.T) {
	cert := generateTestCert(t, "Parse PEM CA")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	parsed, err := parsePEMBytes(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if Fingerprint(parsed) != Fingerprint(cert) {
		t.Error("parsed certificate fingerprint does not match original")
	}
}

func TestBackendStore_parsePEMBytes_InvalidPEM(t *testing.T) {
	_, err := parsePEMBytes([]byte("not pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestBackendStore_parsePEMBytes_WrongBlockType(t *testing.T) {
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	_, err := parsePEMBytes(data)
	if err == nil {
		t.Fatal("expected error for wrong block type")
	}
}

// --- Interface compliance ---

func TestBackendStore_ImplementsTrustStore(t *testing.T) {
	var _ TrustStore = (*BackendStore)(nil)
}
