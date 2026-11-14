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
	"encoding/pem"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAOTrustStore creates a DAOStore backed by in-memory storage for testing.
func newTestDAOTrustStore(t *testing.T) *DAOStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOStore(dao.NewStoreFactory(kvStore))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

// purposeOpts returns the options that classify a certificate as purpose.
func purposeOpts(purpose CertPurpose) *AddCertificateOptions {
	return &AddCertificateOptions{Purpose: purpose}
}

func TestDAOStore_NewDAOStore_NilFactory(t *testing.T) {
	store, err := NewDAOStore(nil)
	var creation ErrDAOCreation
	require.ErrorAs(t, err, &creation)
	require.ErrorIs(t, err, dao.ErrNilFactory)
	assert.Nil(t, store)
}

func TestDAOStore_AddAndGet(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert := generateTestCert(t, "Test CA")
	fp := Fingerprint(cert)

	require.NoError(t, store.Add(ctx, cert, purposeOpts(PurposeUserCA)))

	gotCert, gotMeta, err := store.Get(ctx, fp)
	require.NoError(t, err)
	require.NotNil(t, gotCert)
	require.NotNil(t, gotMeta)

	assert.Equal(t, cert.Subject.String(), gotCert.Subject.String())
	assert.Equal(t, fp, gotMeta.Fingerprint)
	assert.Equal(t, PurposeUserCA, gotMeta.Purpose)
	assert.Equal(t, "ECDSA", gotMeta.Algorithm)
	assert.Equal(t, cert.Subject.String(), gotMeta.Subject)
	assert.Equal(t, cert.Issuer.String(), gotMeta.Issuer)
}

func TestDAOStore_Add_NilCert(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	err := store.Add(ctx, nil, purposeOpts(PurposeGeneral))
	require.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestDAOStore_Add_Closed(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.Close())

	cert := generateTestCert(t, "Test CA")
	err := store.Add(ctx, cert, purposeOpts(PurposeGeneral))
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_Add_Exists(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert := generateTestCert(t, "Test CA")
	fp := Fingerprint(cert)

	require.NoError(t, store.Add(ctx, cert, purposeOpts(PurposeGeneral)))

	// A second Add is refused and leaves the stored purpose alone.
	err := store.Add(ctx, cert, purposeOpts(PurposeUserCA))
	require.ErrorIs(t, err, ErrCertificateExists)

	_, meta, err := store.Get(ctx, fp)
	require.NoError(t, err)
	assert.Equal(t, PurposeGeneral, meta.Purpose)
}

func TestDAOStore_Add_ClassifiesAndRecordsSource(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert := generateTestCert(t, "Test CA")
	require.NoError(t, store.Add(ctx, cert, &AddCertificateOptions{Source: "aia"}))

	_, meta, err := store.Get(ctx, Fingerprint(cert))
	require.NoError(t, err)
	assert.Equal(t, ClassifyCertificate(cert), meta.Purpose)
	assert.Equal(t, "aia", meta.Source)
}

func TestDAOStore_Add_InvalidPurpose(t *testing.T) {
	store := newTestDAOTrustStore(t)

	cert := generateTestCert(t, "Test CA")
	err := store.Add(context.Background(), cert, purposeOpts("bogus"))
	require.ErrorIs(t, err, ErrInvalidPurpose)
}

func TestDAOStore_ImportPEM(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	first := generateTestCert(t, "First CA")
	second := generateTestCert(t, "Second CA")
	require.NoError(t, store.Add(ctx, first, purposeOpts(PurposeGeneral)))

	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Raw})...)
	result, err := store.ImportPEM(ctx, bundle, &AddCertificateOptions{Purpose: PurposeImageSigner, Source: "bundle"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Added)
	assert.Equal(t, 1, result.Skipped)

	_, meta, err := store.Get(ctx, Fingerprint(second))
	require.NoError(t, err)
	assert.Equal(t, PurposeImageSigner, meta.Purpose)
	assert.Equal(t, "bundle", meta.Source)
}

func TestDAOStore_SetPurpose_Quarantine(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert := generateTestCert(t, "Test CA")
	require.NoError(t, store.Add(ctx, cert, purposeOpts(PurposeIDevIDIssuer)))

	anchors, err := store.Anchors(ctx, PurposeIDevIDIssuer)
	require.NoError(t, err)
	require.Len(t, anchors, 1)

	meta, err := store.SetPurpose(ctx, Fingerprint(cert), PurposeSynced)
	require.NoError(t, err)
	assert.Equal(t, PurposeSynced, meta.Purpose)

	// The quarantined root no longer anchors its former purpose...
	anchors, err = store.Anchors(ctx, PurposeIDevIDIssuer)
	require.NoError(t, err)
	assert.Empty(t, anchors)

	// ...and the quarantine itself is refused as an anchor set.
	_, err = store.Anchors(ctx, PurposeSynced)
	require.ErrorIs(t, err, ErrNotAnchorPurpose)

	// It stays listed.
	_, meta, err = store.Get(ctx, Fingerprint(cert))
	require.NoError(t, err)
	assert.Equal(t, PurposeSynced, meta.Purpose)
}

func TestDAOStore_SetPurpose_Errors(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert := generateTestCert(t, "Test CA")
	fp := Fingerprint(cert)

	_, err := store.SetPurpose(ctx, fp, PurposeSynced)
	require.ErrorIs(t, err, ErrCertificateNotFound)

	require.NoError(t, store.Add(ctx, cert, purposeOpts(PurposeGeneral)))
	_, err = store.SetPurpose(ctx, fp, "bogus")
	require.ErrorIs(t, err, ErrInvalidPurpose)

	_, err = store.SetPurpose(ctx, "not-hex", PurposeSynced)
	require.Error(t, err)

	require.NoError(t, store.Close())
	_, err = store.SetPurpose(ctx, fp, PurposeSynced)
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_Get_InvalidFingerprint(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert, meta, err := store.Get(ctx, "invalid")
	require.ErrorIs(t, err, ErrInvalidFingerprint)
	assert.Nil(t, cert)
	assert.Nil(t, meta)
}

func TestDAOStore_Get_Closed(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.Close())

	fp := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cert, meta, err := store.Get(ctx, fp)
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, cert)
	assert.Nil(t, meta)
}

func TestDAOStore_GetByPurpose(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	certCA := generateTestCert(t, "CA Cert")
	certTPM := generateTestCert(t, "TPM Manufacturer Cert")
	certGeneral := generateTestCert(t, "General Cert")

	require.NoError(t, store.Add(ctx, certCA, purposeOpts(PurposeUserCA)))
	require.NoError(t, store.Add(ctx, certTPM, purposeOpts(PurposeTPMManufacturer)))
	require.NoError(t, store.Add(ctx, certGeneral, purposeOpts(PurposeGeneral)))

	// Query by PurposeUserCA.
	caCerts, err := store.GetByPurpose(ctx, PurposeUserCA)
	require.NoError(t, err)
	assert.Len(t, caCerts, 1)
	assert.Equal(t, certCA.Subject.String(), caCerts[0].Subject.String())

	// Query by PurposeTPMManufacturer.
	tpmCerts, err := store.GetByPurpose(ctx, PurposeTPMManufacturer)
	require.NoError(t, err)
	assert.Len(t, tpmCerts, 1)
	assert.Equal(t, certTPM.Subject.String(), tpmCerts[0].Subject.String())

	// Query by non-existent purpose returns empty.
	androidCerts, err := store.GetByPurpose(ctx, PurposeAndroidHardware)
	require.NoError(t, err)
	assert.Empty(t, androidCerts)
}

func TestDAOStore_GetByPurpose_Closed(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.Close())

	certs, err := store.GetByPurpose(ctx, PurposeGeneral)
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, certs)
}

func TestDAOStore_List(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert1 := generateTestCert(t, "Alpha CA")
	cert2 := generateTestCert(t, "Beta CA")
	cert3 := generateTestCert(t, "Gamma CA")

	require.NoError(t, store.Add(ctx, cert1, purposeOpts(PurposeGeneral)))
	require.NoError(t, store.Add(ctx, cert2, purposeOpts(PurposeUserCA)))
	require.NoError(t, store.Add(ctx, cert3, purposeOpts(PurposeTPMManufacturer)))

	certs, metas, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, certs, 3)
	assert.Len(t, metas, 3)

	// Verify sorted by subject.
	for i := 1; i < len(metas); i++ {
		assert.True(t, metas[i-1].Subject <= metas[i].Subject,
			"expected sorted order: %q <= %q", metas[i-1].Subject, metas[i].Subject)
	}
}

func TestDAOStore_List_Closed(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.Close())

	certs, metas, err := store.List(ctx)
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, certs)
	assert.Nil(t, metas)
}

func TestDAOStore_Delete(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	cert := generateTestCert(t, "Delete Me CA")
	fp := Fingerprint(cert)

	require.NoError(t, store.Add(ctx, cert, purposeOpts(PurposeGeneral)))

	// Confirm it exists.
	_, _, err := store.Get(ctx, fp)
	require.NoError(t, err)

	// Delete it.
	require.NoError(t, store.Delete(ctx, fp))

	// Confirm it is gone.
	_, _, err = store.Get(ctx, fp)
	require.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	fp := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	err := store.Delete(ctx, fp)
	require.ErrorIs(t, err, ErrCertificateNotFound)
}

func TestDAOStore_Delete_InvalidFingerprint(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "bad")
	require.ErrorIs(t, err, ErrInvalidFingerprint)
}

func TestDAOStore_Delete_Closed(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.Close())

	fp := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	err := store.Delete(ctx, fp)
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_Page(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	// Add 5 certificates.
	for i := 0; i < 5; i++ {
		cert := generateTestCert(t, "Page Cert "+string(rune('A'+i)))
		require.NoError(t, store.Add(ctx, cert, purposeOpts(PurposeGeneral)))
	}

	// Page 1 with page size 2.
	result, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)

	// Page 2 with page size 2.
	result2, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 2, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result2.Entities, 2)

	// Page 3 with page size 2 should have 1 remaining.
	result3, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
}

func TestDAOStore_Page_Closed(t *testing.T) {
	store := newTestDAOTrustStore(t)
	ctx := context.Background()

	require.NoError(t, store.Close())

	_, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_Close_Idempotent(t *testing.T) {
	store := newTestDAOTrustStore(t)

	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestDAOStore_EntityToMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	entity := &TrustCertEntity{
		ID:          42,
		Fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Purpose:     string(PurposeBootstrapCA),
		Subject:     "CN=Bootstrap CA",
		Issuer:      "CN=Root CA",
		Algorithm:   "ECDSA",
		NotBefore:   now.Add(-365 * 24 * time.Hour),
		NotAfter:    now.Add(365 * 24 * time.Hour),
		PEM:         "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		Source:      "bootstrap",
		AddedAt:     now,
	}

	meta := entityToMetadata(entity)

	assert.Equal(t, entity.Fingerprint, meta.Fingerprint)
	assert.Equal(t, PurposeBootstrapCA, meta.Purpose)
	assert.Equal(t, entity.Subject, meta.Subject)
	assert.Equal(t, entity.Issuer, meta.Issuer)
	assert.Equal(t, entity.Algorithm, meta.Algorithm)
	assert.Equal(t, entity.Source, meta.Source)
	assert.True(t, meta.NotBefore.Equal(entity.NotBefore))
	assert.True(t, meta.NotAfter.Equal(entity.NotAfter))
	assert.True(t, meta.AddedAt.Equal(entity.AddedAt))
}

func TestDAOStore_ErrDAOCreation(t *testing.T) {
	err := ErrDAOCreation{Cause: ErrStoreClosed}
	assert.Contains(t, err.Error(), "failed to create DAO")
	assert.ErrorIs(t, err, ErrStoreClosed)
}
