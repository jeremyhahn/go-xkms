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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingImporter records what importPEM asked it to write and can fail on
// demand, so the loop's behaviour is observable without a real store.
type countingImporter struct {
	calls    int
	err      error
	existing bool
}

func (c *countingImporter) AddCertificateWithOptions(_ *x509.Certificate, _ *AddCertificateOptions) error {
	c.calls++
	if c.existing {
		return ErrCertificateExists
	}
	return c.err
}

// A bundle whose certificates are all present is a successful import that
// added nothing and skipped everything. Both numbers matter: "0 added" alone
// cannot be told from a parse failure.
func TestImportPEM_CountsSkips(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	certPEM := generateTestCertPEM(t, "import test ca")

	first, err := store.ImportPEM(certPEM, nil)
	require.NoError(t, err)
	assert.Equal(t, ImportResult{Added: 1}, first)

	second, err := store.ImportPEM(certPEM, nil)
	require.NoError(t, err)
	assert.Equal(t, ImportResult{Skipped: 1}, second)
}

// An empty bundle carries nothing to import and must say so.
func TestImportPEM_EmptyDataIsAnError(t *testing.T) {
	importer := &countingImporter{}

	result, err := importPEM(importer, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidCertificate))
	assert.Equal(t, ImportResult{}, result)
	assert.Equal(t, 0, importer.calls)
}

// A write failure stops the import and is reported with the partial count,
// rather than being counted as a skip.
func TestImportPEM_WriteFailureStopsTheImport(t *testing.T) {
	importer := &countingImporter{err: errors.New("disk full")}

	result, err := importPEM(importer, generateTestCertPEM(t, "import test ca"), nil)
	require.Error(t, err)
	assert.Equal(t, ImportResult{}, result)
	assert.Equal(t, 1, importer.calls)
}

// TLSRoots reports the operator-added CAs and withholds the attestation
// purposes: a TPM vendor root anchors attestation chains, not TLS sessions.
func TestFileStore_TLSRoots_ExcludesAttestationPurposes(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	userCA := generateTestCert(t, "user ca")
	tpmCA := generateTestCert(t, "tpm vendor ca")

	require.NoError(t, store.AddCertificateWithOptions(userCA, &AddCertificateOptions{Purpose: PurposeUserCA}))
	require.NoError(t, store.AddCertificateWithOptions(tpmCA, &AddCertificateOptions{Purpose: PurposeTPMManufacturer}))

	roots, err := store.TLSRoots()
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Equal(t, "user ca", roots[0].Subject.CommonName)
}

// A self-signed CA imported under PurposeSynced keeps the caller's purpose
// instead of being auto-classified as a user CA, and is withheld from the TLS
// anchors (#1304): a certificate a paired device pushed is never a root.
func TestFileStore_ImportPEM_SyncedSelfSignedCAIsNotATLSAnchor(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	certPEM := generateTestCertPEM(t, "phone planted ca")
	result, err := store.ImportPEM(certPEM, &AddCertificateOptions{Purpose: PurposeSynced})
	require.NoError(t, err)
	require.Equal(t, ImportResult{Added: 1}, result)

	certs, err := store.CertificatesByPurpose(PurposeSynced)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.Equal(t, PurposeUserCA, ClassifyCertificate(certs[0]),
		"precondition: auto-classification would have made this a TLS anchor")

	roots, err := store.TLSRoots()
	require.NoError(t, err)
	assert.Empty(t, roots)
}

// An empty store yields no anchors and no error: verification then rests on
// the platform roots alone.
func TestFileStore_TLSRoots_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	roots, err := store.TLSRoots()
	require.NoError(t, err)
	assert.Empty(t, roots)
}

// A closed store cannot answer, and says so rather than reporting an empty
// set of anchors — an empty set would silently narrow verification.
func TestFileStore_TLSRoots_ClosedStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(&FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	_, err = store.TLSRoots()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStoreClosed))
}

// The backend-backed store selects the same TLS anchors as the file store:
// one policy, two persistence layers.
func TestBackendStore_TLSRoots_ExcludesAttestationPurposes(t *testing.T) {
	store := newTestBackendStore(t)
	defer func() { require.NoError(t, store.Close()) }()

	userCA := generateTestCert(t, "user ca")
	androidCA := generateTestCert(t, "android attestation ca")

	require.NoError(t, store.AddCertificateWithOptions(userCA, &AddCertificateOptions{Purpose: PurposeUserCA}))
	require.NoError(t, store.AddCertificateWithOptions(androidCA, &AddCertificateOptions{Purpose: PurposeAndroidHardware}))

	roots, err := store.TLSRoots()
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Equal(t, "user ca", roots[0].Subject.CommonName)
}

// A closed backend store reports the failure rather than an empty anchor set.
func TestBackendStore_TLSRoots_ClosedStore(t *testing.T) {
	store := newTestBackendStore(t)
	require.NoError(t, store.Close())

	_, err := store.TLSRoots()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStoreClosed))
}

// ImportPEM on the backend store counts skips the same way.
func TestBackendStore_ImportPEM_CountsSkips(t *testing.T) {
	store := newTestBackendStore(t)
	defer func() { require.NoError(t, store.Close()) }()

	certPEM := generateTestCertPEM(t, "backend import ca")

	first, err := store.ImportPEM(certPEM, nil)
	require.NoError(t, err)
	assert.Equal(t, ImportResult{Added: 1}, first)

	second, err := store.ImportPEM(certPEM, nil)
	require.NoError(t, err)
	assert.Equal(t, ImportResult{Skipped: 1}, second)
}
