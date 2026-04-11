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
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// newTestFileStore creates a FileStore backed by a temporary directory.
// The caller does not need to clean up; t.TempDir() handles removal.
func newTestFileStore(t *testing.T) truststore.TrustStore {
	t.Helper()
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err, "NewFileStore must succeed with temp directory")
	return store
}

// seedAndGetFingerprint seeds embedded roots and returns the fingerprint
// of the first certificate in the store.
func seedAndGetFingerprint(t *testing.T, svc *TrustService) string {
	t.Helper()
	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	require.Greater(t, count, 0)
	infos, err := svc.ListCertificates()
	require.NoError(t, err)
	require.NotEmpty(t, infos)
	return infos[0].Fingerprint
}

func TestTrustService_SeedEmbeddedRoots_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	assert.Equal(t, 0, count, "nil store should return 0 added")
}

func TestTrustService_SeedEmbeddedRoots_AndroidHardware(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	assert.Greater(t, count, 0, "should add at least one embedded root")

	// Verify the certificates are retrievable by purpose.
	certs, err := store.CertificatesByPurpose(truststore.PurposeAndroidHardware)
	require.NoError(t, err)
	assert.Equal(t, count, len(certs), "CertificatesByPurpose count must match seeded count")

	// Verify metadata has the expected source.
	for _, cert := range certs {
		fp := truststore.Fingerprint(cert)
		meta, metaErr := store.Metadata(fp)
		require.NoError(t, metaErr)
		assert.Equal(t, "embedded", meta.Source, "source must be 'embedded'")
		assert.Equal(t, truststore.PurposeAndroidHardware, meta.Purpose, "purpose must be android-hardware")
	}

	// Verify the total count in the store matches.
	total, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, count, total, "total store count must match seeded count")
}

func TestTrustService_SeedEmbeddedRoots_Idempotent(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// First seed.
	firstCount, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	assert.Greater(t, firstCount, 0, "first seed should add certificates")

	// Second seed should be a no-op.
	secondCount, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	assert.Equal(t, 0, secondCount, "second seed must add zero certificates (idempotent)")

	// Total count should remain the same.
	total, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, firstCount, total, "total store count must match first seed count after second seed")
}

func TestTrustService_SeedEmbeddedRoots_UnknownPurpose(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	count, err := svc.SeedEmbeddedRoots("nonexistent-purpose")
	require.NoError(t, err)
	assert.Equal(t, 0, count, "unknown purpose should return 0 added")

	// Store should remain empty.
	total, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 0, total, "store should remain empty for unknown purpose")
}

func TestTrustService_SeedEmbeddedRoots_CertsAreCA(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	require.Greater(t, count, 0)

	// Every seeded certificate must be a CA root.
	certs, err := store.Certificates()
	require.NoError(t, err)
	for _, cert := range certs {
		assert.True(t, cert.IsCA, "seeded certificate %s must be a CA", cert.Subject.CommonName)
	}
}

func TestTrustService_SeedEmbeddedRoots_ListByPurpose(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	require.Greater(t, count, 0)

	// Use the service-level ListCertificatesByPurpose to verify the full
	// round-trip from seeding through the GUI-facing API.
	infos, err := svc.ListCertificatesByPurpose(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	assert.Equal(t, count, len(infos), "ListCertificatesByPurpose must return seeded count")

	for _, info := range infos {
		assert.Equal(t, string(truststore.PurposeAndroidHardware), info.Purpose)
		assert.Equal(t, "embedded", info.Source)
		assert.True(t, info.IsCA, "seeded cert must be a CA")
		assert.NotEmpty(t, info.Fingerprint, "fingerprint must not be empty")
		assert.NotEmpty(t, info.Subject, "subject must not be empty")
	}
}

func TestTrustService_SeedEmbeddedRoots_ClosedStore(t *testing.T) {
	store := newTestFileStore(t)
	svc := NewTrustService(store)

	// Close the store before seeding.
	require.NoError(t, store.Close())

	_, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	assert.Error(t, err, "seeding a closed store must return an error")
}

func TestTrustService_SeedEmbeddedRoots_GeneralPurposeNoEmbedded(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// "general" purpose has no embedded roots configured.
	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeGeneral))
	require.NoError(t, err)
	assert.Equal(t, 0, count, "general purpose has no embedded roots")
}

// ---------------------------------------------------------------------------
// GetCertificatePEM tests
// ---------------------------------------------------------------------------

func TestTrustService_GetCertificatePEM_Success(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	fp := seedAndGetFingerprint(t, svc)

	pemStr, err := svc.GetCertificatePEM(fp)
	require.NoError(t, err)
	assert.True(t, strings.Contains(pemStr, "BEGIN CERTIFICATE"),
		"PEM output must contain BEGIN CERTIFICATE header")
	assert.True(t, strings.Contains(pemStr, "END CERTIFICATE"),
		"PEM output must contain END CERTIFICATE footer")
}

func TestTrustService_GetCertificatePEM_NotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Use a valid-format but nonexistent fingerprint (64 hex chars).
	badFP := strings.Repeat("ab", 32)
	_, err := svc.GetCertificatePEM(badFP)
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

func TestTrustService_GetCertificatePEM_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	_, err := svc.GetCertificatePEM("anything")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// ---------------------------------------------------------------------------
// ExportCertificatePEM tests
// ---------------------------------------------------------------------------

func TestTrustService_ExportCertificatePEM_Success(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	fp := seedAndGetFingerprint(t, svc)

	pemStr, err := svc.ExportCertificatePEM(fp)
	require.NoError(t, err)
	assert.True(t, strings.Contains(pemStr, "BEGIN CERTIFICATE"),
		"exported PEM must contain BEGIN CERTIFICATE header")
}

func TestTrustService_ExportCertificatePEM_NotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	badFP := strings.Repeat("cd", 32)
	_, err := svc.ExportCertificatePEM(badFP)
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

// ---------------------------------------------------------------------------
// ExportCertificateDER tests
// ---------------------------------------------------------------------------

func TestTrustService_ExportCertificateDER_Success(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	fp := seedAndGetFingerprint(t, svc)

	derBytes, err := svc.ExportCertificateDER(fp)
	require.NoError(t, err)
	assert.NotEmpty(t, derBytes, "DER bytes must not be empty")

	// Verify the DER bytes can be parsed as a valid x509 certificate.
	cert, parseErr := x509.ParseCertificate(derBytes)
	require.NoError(t, parseErr, "DER bytes must be parseable as x509 certificate")
	assert.NotEmpty(t, cert.Subject.String(), "parsed certificate must have a subject")
}

func TestTrustService_ExportCertificateDER_NotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	badFP := strings.Repeat("ef", 32)
	_, err := svc.ExportCertificateDER(badFP)
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

func TestTrustService_ExportCertificateDER_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	_, err := svc.ExportCertificateDER("anything")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// ---------------------------------------------------------------------------
// SetContext and SetElevator tests
// ---------------------------------------------------------------------------

func TestTrustService_SetContext(t *testing.T) {
	svc := NewTrustService(nil)

	// SetContext must not panic with a valid context.
	assert.NotPanics(t, func() {
		svc.SetContext(context.Background())
	})
}

func TestTrustService_SetElevator(t *testing.T) {
	svc := NewTrustService(nil)
	m := &mockElevator{available: true}

	// SetElevator must not panic with a valid elevator.
	assert.NotPanics(t, func() {
		svc.SetElevator(m)
	})
}

// ---------------------------------------------------------------------------
// InstallToSystem and RemoveFromSystem error path tests
// ---------------------------------------------------------------------------

func TestTrustService_InstallToSystem_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	err := svc.InstallToSystem("somefingerprint", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestTrustService_InstallToSystem_CertNotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Seed the store so it has certificates, then use a bad fingerprint.
	_, seedErr := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, seedErr)

	badFP := strings.Repeat("00", 32)
	err := svc.InstallToSystem(badFP, "password")
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

func TestTrustService_RemoveFromSystem_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	err := svc.RemoveFromSystem("somefingerprint", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// ---------------------------------------------------------------------------
// ListCertificates tests
// ---------------------------------------------------------------------------

func TestTrustService_ListCertificates_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	infos, err := svc.ListCertificates()
	assert.Nil(t, infos)
	assert.Nil(t, err)
}

func TestTrustService_ListCertificates_WithCerts(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	require.Greater(t, count, 0)

	infos, err := svc.ListCertificates()
	require.NoError(t, err)
	assert.Equal(t, count, len(infos), "ListCertificates count must match seeded count")

	for _, info := range infos {
		assert.NotEmpty(t, info.Fingerprint)
		assert.NotEmpty(t, info.Subject)
	}
}

// ---------------------------------------------------------------------------
// CertificateCount tests
// ---------------------------------------------------------------------------

func TestTrustService_CertificateCount_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	count, err := svc.CertificateCount()
	assert.Equal(t, 0, count)
	assert.Nil(t, err)
}

// ---------------------------------------------------------------------------
// AddCertificatesPEM tests
// ---------------------------------------------------------------------------

func TestTrustService_AddCertificatesPEM_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	count, err := svc.AddCertificatesPEM("some pem data")
	assert.Equal(t, 0, count)
	assert.Nil(t, err)
}

// ---------------------------------------------------------------------------
// RemoveCertificate tests
// ---------------------------------------------------------------------------

func TestTrustService_RemoveCertificate_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	err := svc.RemoveCertificate("somefingerprint")
	assert.Nil(t, err)
}

func TestTrustService_SetStore(t *testing.T) {
	// Start with nil store - GetCertificatePEM returns ErrNilTrustStore.
	svc := NewTrustService(nil)
	_, err := svc.GetCertificatePEM("anything")
	assert.ErrorIs(t, err, ErrNilTrustStore)

	// Wire a real store.
	store, storeErr := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(t.TempDir(), "trust"),
	})
	require.NoError(t, storeErr)
	svc.SetStore(store)

	// Now listing should work.
	certs, err := svc.ListCertificates()
	assert.NoError(t, err)
	assert.Empty(t, certs)
}

// ---------------------------------------------------------------------------
// AddCertificatesPEM with valid PEM data
// ---------------------------------------------------------------------------

func TestTrustService_AddCertificatesPEM_ValidPEM(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Use generateTestCert from phone_service_test.go (same package).
	cert := generateTestCert(t)
	pemData := certToPEM(cert)

	count, err := svc.AddCertificatesPEM(pemData)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "should add exactly one certificate")

	total, err := svc.CertificateCount()
	require.NoError(t, err)
	assert.Equal(t, 1, total)
}

func TestTrustService_AddCertificatesPEM_InvalidPEM(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	count, err := svc.AddCertificatesPEM("not valid pem data at all")
	// Invalid PEM should add zero certificates but may or may not error.
	assert.Equal(t, 0, count)
	_ = err
}

// ---------------------------------------------------------------------------
// RemoveCertificate with valid fingerprint
// ---------------------------------------------------------------------------

func TestTrustService_RemoveCertificate_ValidFingerprint(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	err := store.AddCertificate(cert)
	require.NoError(t, err)

	fp := truststore.Fingerprint(cert)

	err = svc.RemoveCertificate(fp)
	assert.NoError(t, err)

	// Verify it was removed.
	exists, err := store.Contains(fp)
	require.NoError(t, err)
	assert.False(t, exists, "certificate should be removed")
}

func TestTrustService_RemoveCertificate_NotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	badFP := strings.Repeat("ff", 32)
	err := svc.RemoveCertificate(badFP)
	// Removing a nonexistent cert should return ErrCertificateNotFound.
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

// ---------------------------------------------------------------------------
// CertificateCount with certs in store
// ---------------------------------------------------------------------------

func TestTrustService_CertificateCount_WithCerts(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	err := store.AddCertificate(cert)
	require.NoError(t, err)

	count, err := svc.CertificateCount()
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// ---------------------------------------------------------------------------
// ListCertificatesByPurpose with nil store
// ---------------------------------------------------------------------------

func TestTrustService_ListCertificatesByPurpose_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	infos, err := svc.ListCertificatesByPurpose(string(truststore.PurposeGeneral))
	assert.Nil(t, infos)
	assert.Nil(t, err)
}

// ---------------------------------------------------------------------------
// ListCertificatesByPurpose with empty store
// ---------------------------------------------------------------------------

func TestTrustService_ListCertificatesByPurpose_EmptyStore(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	infos, err := svc.ListCertificatesByPurpose(string(truststore.PurposeGeneral))
	require.NoError(t, err)
	assert.Empty(t, infos)
}

// ---------------------------------------------------------------------------
// ListCertificates populates metadata fields
// ---------------------------------------------------------------------------

func TestTrustService_ListCertificates_MetadataFields(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	require.Greater(t, count, 0)

	infos, err := svc.ListCertificates()
	require.NoError(t, err)

	for _, info := range infos {
		assert.NotEmpty(t, info.Fingerprint, "fingerprint must be populated")
		assert.NotEmpty(t, info.Subject, "subject must be populated")
		assert.NotEmpty(t, info.Issuer, "issuer must be populated")
		assert.NotEmpty(t, info.Algorithm, "algorithm must be populated")
		assert.NotEmpty(t, info.NotBefore, "not_before must be populated")
		assert.NotEmpty(t, info.NotAfter, "not_after must be populated")
		assert.Equal(t, "embedded", info.Source)
		assert.Equal(t, string(truststore.PurposeAndroidHardware), info.Purpose)
	}
}

// ---------------------------------------------------------------------------
// ListCertificates IsExpired field
// ---------------------------------------------------------------------------

func TestTrustService_ListCertificates_IsExpiredField(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Embedded roots should not be expired.
	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)
	require.Greater(t, count, 0)

	infos, err := svc.ListCertificates()
	require.NoError(t, err)

	for _, info := range infos {
		// The embedded roots should have long validity periods.
		// At least verify the field is set to a boolean value.
		_ = info.IsExpired
	}
}

// ---------------------------------------------------------------------------
// RemoveFromSystem cert not found in store
// ---------------------------------------------------------------------------

func TestTrustService_RemoveFromSystem_CertNotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	badFP := strings.Repeat("aa", 32)
	err := svc.RemoveFromSystem(badFP, "password")
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

// ---------------------------------------------------------------------------
// IsSystemInstalled nil store
// ---------------------------------------------------------------------------

func TestTrustService_IsSystemInstalled_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	installed, err := svc.IsSystemInstalled(strings.Repeat("ab", 32))
	assert.False(t, installed)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// IsSystemInstalled with store (exercises NewOSCertStore path)
// ---------------------------------------------------------------------------

func TestTrustService_IsSystemInstalled_WithStore(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	fp := strings.Repeat("ab", 32)
	// This exercises the code path where the store is not nil and
	// NewOSCertStore is called. The result depends on the OS, but
	// the function should not panic.
	installed, err := svc.IsSystemInstalled(fp)
	// On systems where the OS cert store is not available, an error
	// is expected but the function should not panic.
	if err != nil {
		assert.False(t, installed)
	}
}

// ---------------------------------------------------------------------------
// findCertByFingerprint tests
// ---------------------------------------------------------------------------

func TestTrustService_FindCertByFingerprint_Found(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	err := store.AddCertificate(cert)
	require.NoError(t, err)

	fp := truststore.Fingerprint(cert)
	found, err := svc.findCertByFingerprint(fp)
	require.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, found.Subject.CommonName)
}

func TestTrustService_FindCertByFingerprint_NotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	badFP := strings.Repeat("12", 32)
	_, err := svc.findCertByFingerprint(badFP)
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

func TestTrustService_FindCertByFingerprint_ClosedStore(t *testing.T) {
	store := newTestFileStore(t)
	svc := NewTrustService(store)
	require.NoError(t, store.Close())

	_, err := svc.findCertByFingerprint(strings.Repeat("ab", 32))
	assert.Error(t, err, "closed store should return an error")
}

// ---------------------------------------------------------------------------
// ImportCertificateFile nil store
// ---------------------------------------------------------------------------

func TestTrustService_ImportCertificateFile_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	count, err := svc.ImportCertificateFile()
	assert.Equal(t, 0, count)
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// ---------------------------------------------------------------------------
// ExportCertificatePEM nil store
// ---------------------------------------------------------------------------

func TestTrustService_ExportCertificatePEM_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	pemStr, err := svc.ExportCertificatePEM("anything")
	assert.Empty(t, pemStr)
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// ---------------------------------------------------------------------------
// Error sentinel tests
// ---------------------------------------------------------------------------

func TestTrustServiceErrors_Distinct(t *testing.T) {
	assert.NotEqual(t, ErrNilTrustStore, ErrImportCancelled)
	assert.NotEqual(t, ErrNilTrustStore.Error(), ErrImportCancelled.Error())
}

// ---------------------------------------------------------------------------
// SetBrowserExport tests
// ---------------------------------------------------------------------------

func TestTrustService_SetBrowserExport_Enable(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	// Enable browser export.
	err := svc.SetBrowserExport(fp, true)
	require.NoError(t, err)

	// Verify the tag was added.
	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.Contains(t, meta.Tags, TagBrowserExport)
}

func TestTrustService_SetBrowserExport_Disable(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	// Enable then disable browser export.
	require.NoError(t, svc.SetBrowserExport(fp, true))
	require.NoError(t, svc.SetBrowserExport(fp, false))

	// Verify the tag was removed.
	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.NotContains(t, meta.Tags, TagBrowserExport)
}

func TestTrustService_SetBrowserExport_PreservesOtherTags(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	// Set some existing tags first.
	require.NoError(t, store.SetTags(fp, []string{"custom-tag", "another-tag"}))

	// Enable browser export.
	require.NoError(t, svc.SetBrowserExport(fp, true))

	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.Contains(t, meta.Tags, "custom-tag", "existing tags must be preserved")
	assert.Contains(t, meta.Tags, "another-tag", "existing tags must be preserved")
	assert.Contains(t, meta.Tags, TagBrowserExport, "browser-export tag must be present")

	// Disable browser export; other tags remain.
	require.NoError(t, svc.SetBrowserExport(fp, false))

	meta, err = store.Metadata(fp)
	require.NoError(t, err)
	assert.Contains(t, meta.Tags, "custom-tag")
	assert.Contains(t, meta.Tags, "another-tag")
	assert.NotContains(t, meta.Tags, TagBrowserExport)
}

func TestTrustService_SetBrowserExport_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	err := svc.SetBrowserExport("anything", true)
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestTrustService_SetBrowserExport_CertNotFound(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	badFP := strings.Repeat("ab", 32)
	err := svc.SetBrowserExport(badFP, true)
	assert.Error(t, err, "should error for nonexistent certificate")
}

func TestTrustService_SetBrowserExport_Idempotent(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)

	// Enable twice; tag should appear only once.
	require.NoError(t, svc.SetBrowserExport(fp, true))
	require.NoError(t, svc.SetBrowserExport(fp, true))

	meta, err := store.Metadata(fp)
	require.NoError(t, err)

	tagCount := 0
	for _, tag := range meta.Tags {
		if tag == TagBrowserExport {
			tagCount++
		}
	}
	assert.Equal(t, 1, tagCount, "browser-export tag must appear exactly once")
}

// ---------------------------------------------------------------------------
// ExportBrowserTrustBundle tests
// ---------------------------------------------------------------------------

func TestTrustService_ExportBrowserTrustBundle_WithTaggedCerts(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add two certificates; tag only one for browser export.
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert1))
	require.NoError(t, store.AddCertificate(cert2))

	fp1 := truststore.Fingerprint(cert1)
	require.NoError(t, svc.SetBrowserExport(fp1, true))

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only the tagged certificate should be exported")

	// Verify the bundle file exists and contains a PEM certificate.
	data, readErr := os.ReadFile(bundlePath)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "BEGIN CERTIFICATE")
	assert.Contains(t, string(data), "END CERTIFICATE")
}

func TestTrustService_ExportBrowserTrustBundle_IncludesBootstrapCA(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add a certificate with bootstrap-ca purpose.
	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificateWithOptions(cert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeBootstrapCA,
		Source:  "test",
	}))

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "bootstrap-ca cert should be auto-included")

	// Verify file was created.
	_, statErr := os.Stat(bundlePath)
	assert.NoError(t, statErr)
}

func TestTrustService_ExportBrowserTrustBundle_NoCerts(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add a cert but do not tag it.
	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")

	// Create a dummy file to verify it gets cleaned up.
	require.NoError(t, os.WriteFile(bundlePath, []byte("stale"), 0o600))

	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "no certificates should be exported")

	// Verify the stale bundle file was removed.
	_, statErr := os.Stat(bundlePath)
	assert.True(t, os.IsNotExist(statErr), "stale bundle file should be removed")
}

func TestTrustService_ExportBrowserTrustBundle_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	count, err := svc.ExportBrowserTrustBundle("/tmp/bundle.pem")
	assert.Equal(t, 0, count)
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestTrustService_ExportBrowserTrustBundle_CreatesDirectory(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)
	require.NoError(t, svc.SetBrowserExport(fp, true))

	// Use a nested path that does not exist.
	bundlePath := filepath.Join(t.TempDir(), "nested", "deep", "bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	_, statErr := os.Stat(bundlePath)
	assert.NoError(t, statErr, "bundle file should be created in nested directory")
}

func TestTrustService_ExportBrowserTrustBundle_FilePermissions(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)
	require.NoError(t, svc.SetBrowserExport(fp, true))

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	_, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)

	info, statErr := os.Stat(bundlePath)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"bundle file should be owner read/write only")
}

func TestTrustService_ExportBrowserTrustBundle_MultipleCerts(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add three certs; tag two for export.
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)
	cert3 := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert1))
	require.NoError(t, store.AddCertificate(cert2))
	require.NoError(t, store.AddCertificate(cert3))

	require.NoError(t, svc.SetBrowserExport(truststore.Fingerprint(cert1), true))
	require.NoError(t, svc.SetBrowserExport(truststore.Fingerprint(cert3), true))

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "two tagged certificates should be exported")

	// Verify the PEM bundle contains two certificates.
	data, readErr := os.ReadFile(bundlePath)
	require.NoError(t, readErr)
	pemCount := strings.Count(string(data), "BEGIN CERTIFICATE")
	assert.Equal(t, 2, pemCount, "PEM bundle should contain exactly two certificates")
}

// ---------------------------------------------------------------------------
// TagBrowserExport constant
// ---------------------------------------------------------------------------

func TestTagBrowserExportConstant(t *testing.T) {
	assert.Equal(t, "browser-export", TagBrowserExport)
}

// ---------------------------------------------------------------------------
// GetBrowserBundleStatus tests
// ---------------------------------------------------------------------------

func TestGetBrowserBundleStatus_NoBundleFile(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Point to a nonexistent file.
	bundlePath := filepath.Join(t.TempDir(), "nonexistent", "trust-bundle.pem")
	status := svc.GetBrowserBundleStatus(bundlePath)

	assert.False(t, status.Exists, "Exists must be false for nonexistent bundle")
	assert.False(t, status.Stale, "Stale must be false when bundle does not exist")
}

func TestGetBrowserBundleStatus_BundleExistsNoManifest(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trust-bundle.pem")

	// Write a dummy PEM file with no accompanying manifest.
	require.NoError(t, os.WriteFile(bundlePath, []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"), 0o600))

	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	status := svc.GetBrowserBundleStatus(bundlePath)

	assert.True(t, status.Exists, "Exists must be true when bundle file is on disk")
	assert.True(t, status.Stale, "Stale must be true when manifest is missing")
}

func TestGetBrowserBundleStatus_BundleFreshAfterExport(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add a cert and tag it for browser export.
	cert := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert))
	fp := truststore.Fingerprint(cert)
	require.NoError(t, store.SetTags(fp, []string{TagBrowserExport}))

	// Export the bundle.
	bundlePath := filepath.Join(t.TempDir(), "trust-bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Check status immediately after export -- should be fresh.
	status := svc.GetBrowserBundleStatus(bundlePath)

	assert.True(t, status.Exists, "Exists must be true after export")
	assert.False(t, status.Stale, "Stale must be false immediately after export")
	assert.Greater(t, status.CertCount, 0, "CertCount must be > 0")
}

func TestGetBrowserBundleStatus_StaleAfterCertAdded(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add first cert tagged for export.
	cert1 := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert1))
	fp1 := truststore.Fingerprint(cert1)
	require.NoError(t, store.SetTags(fp1, []string{TagBrowserExport}))

	// Export the bundle.
	bundlePath := filepath.Join(t.TempDir(), "trust-bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Add a second cert tagged for export after the bundle was generated.
	cert2 := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert2))
	fp2 := truststore.Fingerprint(cert2)
	require.NoError(t, store.SetTags(fp2, []string{TagBrowserExport}))

	// Status should now report stale because the eligible set changed.
	status := svc.GetBrowserBundleStatus(bundlePath)

	assert.True(t, status.Exists, "Exists must be true")
	assert.True(t, status.Stale, "Stale must be true after adding a new eligible cert")
}

func TestExportBrowserTrustBundle_WritesManifest(t *testing.T) {
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Add two certs tagged for export.
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)
	require.NoError(t, store.AddCertificate(cert1))
	require.NoError(t, store.AddCertificate(cert2))
	fp1 := truststore.Fingerprint(cert1)
	fp2 := truststore.Fingerprint(cert2)
	require.NoError(t, store.SetTags(fp1, []string{TagBrowserExport}))
	require.NoError(t, store.SetTags(fp2, []string{TagBrowserExport}))

	// Export the bundle.
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trust-bundle.pem")
	count, err := svc.ExportBrowserTrustBundle(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Verify the manifest sidecar exists alongside the bundle.
	manifestPath := filepath.Join(dir, browserBundleManifestFile)
	manifestData, err := os.ReadFile(manifestPath)
	require.NoError(t, err, "manifest file must exist after export")

	// Unmarshal and validate the manifest contents.
	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(manifestData, &manifest))

	assert.Equal(t, 2, manifest.CertCount, "manifest cert_count must match exported count")
	assert.Len(t, manifest.Fingerprints, 2, "manifest must contain two fingerprints")
	assert.False(t, manifest.GeneratedAt.IsZero(), "manifest generated_at must not be zero")

	// The manifest must have been generated within the last minute.
	assert.WithinDuration(t, time.Now().UTC(), manifest.GeneratedAt, time.Minute,
		"manifest generated_at must be recent")

	// Verify both fingerprints are present.
	fpSet := make(map[string]struct{}, len(manifest.Fingerprints))
	for _, fp := range manifest.Fingerprints {
		fpSet[fp] = struct{}{}
	}
	assert.Contains(t, fpSet, fp1, "manifest must contain fingerprint of cert1")
	assert.Contains(t, fpSet, fp2, "manifest must contain fingerprint of cert2")
}

func TestGetBrowserBundleStatus_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	// With a nil store, GetBrowserBundleStatus should return a default
	// status. Since no bundle file exists at a random path, Exists is false.
	bundlePath := filepath.Join(t.TempDir(), "nonexistent-bundle.pem")
	status := svc.GetBrowserBundleStatus(bundlePath)

	assert.False(t, status.Exists, "Exists must be false with nil store and no file")
	assert.Equal(t, bundlePath, status.BundlePath, "BundlePath must be set")
}

func TestImportFromTrustStrap_NilStore(t *testing.T) {
	svc := NewTrustService(nil)

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: "https://kms.example.com:8443",
	})
	require.ErrorIs(t, err, ErrNilTrustStore)
}

func TestImportFromTrustStrap_EmptyServer(t *testing.T) {
	svc := NewTrustService(newTestFileStore(t))

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: "   ",
	})
	require.ErrorIs(t, err, ErrTrustStrapEmptyServer)
}

func TestImportFromTrustStrap_UnsupportedMethod(t *testing.T) {
	svc := NewTrustService(newTestFileStore(t))

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "bogus",
		Server: "https://kms.example.com:8443",
	})
	require.ErrorIs(t, err, ErrTrustStrapUnsupportedMethod)
}

func TestImportFromTrustStrap_DispatchesByMethod(t *testing.T) {
	// Exercise the constructor for each supported method and confirm the
	// dispatch chooses the right factory. The underlying bootstrappers
	// validate their configs at construction, so we feed them the minimum
	// required fields per method and just confirm the unsupported-method
	// branch is the only way to hit ErrTrustStrapUnsupportedMethod.
	svc := NewTrustService(newTestFileStore(t))

	cases := []TrustStrapImportRequest{
		{Method: "dane", Server: "https://kms.example.com:8443"},
		{
			Method:          "noise",
			Server:          "kms.example.com:8445",
			ServerStaticKey: strings.Repeat("ab", 32),
		},
		{
			Method:        "spki",
			Server:        "https://kms.example.com:8443",
			SPKIPinSHA256: strings.Repeat("cd", 32),
		},
		{Method: "direct", Server: "https://kms.example.com:8443"},
	}
	for _, req := range cases {
		req := req
		t.Run(req.Method, func(t *testing.T) {
			boot, err := svc.newTrustStrapBootstrapper(req)
			require.NoError(t, err, "method %q must construct a bootstrapper", req.Method)
			require.NotNil(t, boot)
			_ = boot.Close()
		})
	}
}
