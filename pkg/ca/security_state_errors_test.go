// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package ca failure-injection tests for issue #687: operations that persist
// or change security state (certificate import, revocation-driven key and
// certificate deletion) must propagate storage failures instead of
// discarding them with `_ =`.
package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// failingKeyStore wraps an xkms.Backend and injects a failure into SaveCert,
// the method ImportCertificate calls, so tests can prove the error now
// propagates instead of being discarded. Every other method delegates to
// the embedded Backend unchanged.
type failingKeyStore struct {
	xkms.Backend
	failSaveCert error
}

func (f *failingKeyStore) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	if f.failSaveCert != nil {
		return f.failSaveCert
	}
	return f.Backend.SaveCert(ctx, keyID, cert)
}

// failingCertStore wraps a certstore.CertStore and injects failures into
// StoreCertificate and DeleteCertificate. Every other method delegates to
// the embedded CertStore unchanged.
type failingCertStore struct {
	certstore.CertStore
	failStore  error
	failDelete error
}

func (f *failingCertStore) StoreCertificate(cert *x509.Certificate) error {
	if f.failStore != nil {
		return f.failStore
	}
	return f.CertStore.StoreCertificate(cert)
}

func (f *failingCertStore) DeleteCertificate(cn string) error {
	if f.failDelete != nil {
		return f.failDelete
	}
	return f.CertStore.DeleteCertificate(cn)
}

// TestImportCertificate_KeyStoreSaveCertFailurePropagates proves a keystore
// SaveCert failure is now returned to the caller instead of being
// discarded, while the certStore write — the authoritative copy — still
// happens.
func TestImportCertificate_KeyStoreSaveCertFailurePropagates(t *testing.T) {
	ca := setupTestCA(t)
	injected := errors.New("injected keystore SaveCert failure")
	ca.keyStore = &failingKeyStore{Backend: ca.keyStore, failSaveCert: injected}

	cert := issueTestLeafCert(t, ca, "importcert-keystore-fail.example.com")

	err := ca.ImportCertificate(context.Background(), cert)
	require.Error(t, err, "a discarded keystore SaveCert failure must now surface")
	assert.ErrorIs(t, err, injected)

	// The certStore write is authoritative and must still have happened.
	got, getErr := ca.certStore.GetCertificate(cert.Subject.CommonName)
	require.NoError(t, getErr)
	assert.Equal(t, cert.Raw, got.Raw)
}

// TestImportCertificate_Success proves the happy path returns no error and
// persists the certificate to both stores.
func TestImportCertificate_Success(t *testing.T) {
	ca := setupTestCA(t)
	cert := issueTestLeafCert(t, ca, "importcert-success.example.com")

	err := ca.ImportCertificate(context.Background(), cert)
	require.NoError(t, err)

	got, err := ca.certStore.GetCertificate(cert.Subject.CommonName)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got.Raw)
}

// TestRevokeCert_DeleteKeysCertStoreFailurePropagates proves that when
// RevokeCert(opts.DeleteKeys: true) hits a failure deleting the
// certificate's authoritative certStore copy, that failure surfaces
// instead of being discarded, while the revocation record itself (already
// persisted before deletion is attempted) is unaffected.
//
// keyStore.DeleteKey/DeleteCert are deliberately not exercised here: see
// the comment at their call site in RevokeCert (ca_extensions.go) for why
// their errors are not joined into the return.
func TestRevokeCert_DeleteKeysCertStoreFailurePropagates(t *testing.T) {
	ca := setupTestCA(t)
	cert := issueTestLeafCert(t, ca, "revoke-delkeys-fail.example.com")

	storeErr := errors.New("injected certstore DeleteCertificate failure")
	ca.certStore = &failingCertStore{CertStore: ca.certStore, failDelete: storeErr}

	err := ca.RevokeCert(context.Background(), cert, RevokeOptions{DeleteKeys: true})
	require.Error(t, err, "a discarded certstore DeleteCertificate failure during revocation must now surface")
	assert.ErrorIs(t, err, storeErr)

	// The revocation itself must have taken regardless of the cleanup
	// failure: it is recorded before deletion is attempted.
	revoked, revokedErr := ca.IsRevoked(cert.SerialNumber)
	require.NoError(t, revokedErr)
	assert.True(t, revoked, "the certificate must be revoked even though certStore cleanup failed")
}

// TestRevokeCert_DeleteKeysSuccess proves the happy path (no injected
// failures) still revokes and cleans up without error.
func TestRevokeCert_DeleteKeysSuccess(t *testing.T) {
	ca := setupTestCA(t)
	cert := issueTestLeafCert(t, ca, "revoke-delkeys-success.example.com")

	err := ca.RevokeCert(context.Background(), cert, RevokeOptions{DeleteKeys: true})
	require.NoError(t, err)

	revoked, revokedErr := ca.IsRevoked(cert.SerialNumber)
	require.NoError(t, revokedErr)
	assert.True(t, revoked)
}

// issueTestLeafCert issues a leaf certificate signed by ca for use as
// ImportCertificate/RevokeCert test fixtures.
func issueTestLeafCert(t *testing.T, ca *CA, cn string) *x509.Certificate {
	t.Helper()
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: cn},
		Valid:   365,
	})
	require.NoError(t, err)
	return issued.Certificate
}
