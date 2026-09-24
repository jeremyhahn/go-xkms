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

// Package ca tests for issue #751: RevokeCert's DeleteKeys option must
// resolve the exact KeyAttributes a server-generated key was stored under
// (rather than reconstructing an incomplete value from the certificate
// alone), must treat a CSR-signed certificate -- one whose key the CA never
// held -- as a no-op instead of a failure, and must propagate a genuine
// keystore deletion failure instead of discarding it.
package ca

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// revokeFailingKeyStore wraps an xkms.Backend and injects a failure into
// DeleteKey, so tests can prove a real keystore deletion failure propagates
// out of RevokeCert instead of being discarded. Every other method
// delegates to the embedded Backend unchanged. Named distinctly from any
// similarly-purposed double introduced by go-xkms#687 to avoid a merge
// collision between the two issues' branches.
type revokeFailingKeyStore struct {
	xkms.Backend
	failDeleteKey error
}

func (f *revokeFailingKeyStore) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if f.failDeleteKey != nil {
		return f.failDeleteKey
	}
	return f.Backend.DeleteKey(ctx, attrs)
}

// issueServerKeyedCert issues a leaf certificate whose private key the CA
// generated itself through ca.keyStore under attrs, using IssueCertificate
// (server-side keygen). Returns the certificate and the exact KeyAttributes
// the key was generated under, so tests can look the key up directly.
func issueServerKeyedCert(t *testing.T, ca *CA, cn string) (*x509.Certificate, *types.KeyAttributes) {
	t.Helper()
	attrs := &types.KeyAttributes{
		CN:           cn,
		StoreType:    types.StoreSoftware,
		KeyType:      types.KeyTypeTLS,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject:       Subject{CommonName: cn},
		Valid:         365,
		KeyAttributes: attrs,
	})
	require.NoError(t, err)
	return issued.Certificate, attrs
}

// TestRevokeCert_DeleteKeys_ServerGeneratedKey_DeletesKeyAndCert proves that
// for a certificate whose key the CA generated at issuance, DeleteKeys
// deletes both the key (looked up under the exact attributes issuance
// recorded) and the certificate, and that both are subsequently reported as
// not found.
func TestRevokeCert_DeleteKeys_ServerGeneratedKey_DeletesKeyAndCert(t *testing.T) {
	ca := setupTestCA(t)
	cert, attrs := issueServerKeyedCert(t, ca, "revoke-serverkey.example.com")

	// Sanity: the key exists before revocation.
	_, err := ca.keyStore.Signer(context.Background(), attrs)
	require.NoError(t, err, "key must exist before revocation")

	err = ca.RevokeCert(context.Background(), cert, RevokeOptions{DeleteKeys: true})
	require.NoError(t, err)

	_, err = ca.keyStore.Signer(context.Background(), attrs)
	assert.Error(t, err, "key must be gone from the keystore after DeleteKeys")

	_, err = ca.certStore.GetCertificate(cert.Subject.CommonName)
	require.Error(t, err, "certificate must be gone from the certstore after DeleteKeys")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// The bookkeeping record itself must also be gone, so a second
	// resolution reports the CSR-signed no-op shape rather than stale data.
	resolved, err := ca.resolveIssuedKeyAttributes(context.Background(), cert.SerialNumber)
	require.NoError(t, err)
	assert.Nil(t, resolved)
}

// TestRevokeCert_DeleteKeys_CSRSigned_NoOp proves that revoking a
// CSR-signed certificate -- one whose private key the CA never held -- with
// DeleteKeys succeeds without attempting (or failing) a key deletion.
func TestRevokeCert_DeleteKeys_CSRSigned_NoOp(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := makeLeafCSR(t, "revoke-csrsigned.example.com")

	cert, err := ca.SignCSR(context.Background(), csrPEM, nil)
	require.NoError(t, err)

	// Precondition: issuance never wrote an issued-key record for this
	// certificate, because SignCSR never generates or resolves a key
	// through ca.keyStore.
	resolved, err := ca.resolveIssuedKeyAttributes(context.Background(), cert.SerialNumber)
	require.NoError(t, err)
	require.Nil(t, resolved)

	err = ca.RevokeCert(context.Background(), cert, RevokeOptions{DeleteKeys: true})
	require.NoError(t, err, "DeleteKeys on a CSR-signed certificate must be a no-op, not a failure")

	_, err = ca.certStore.GetCertificate(cert.Subject.CommonName)
	assert.ErrorIs(t, err, storage.ErrNotFound, "the certificate itself is still removed")

	revoked, err := ca.IsRevoked(cert.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// TestRevokeCert_DeleteKeys_KeyStoreDeleteFailurePropagates proves that a
// genuine keystore.DeleteKey failure now surfaces from RevokeCert instead
// of being discarded, while the revocation itself (already durable before
// cleanup is attempted) is unaffected.
func TestRevokeCert_DeleteKeys_KeyStoreDeleteFailurePropagates(t *testing.T) {
	ca := setupTestCA(t)
	cert, _ := issueServerKeyedCert(t, ca, "revoke-delkey-fail.example.com")

	injected := errors.New("injected keystore DeleteKey failure")
	ca.keyStore = &revokeFailingKeyStore{Backend: ca.keyStore, failDeleteKey: injected}

	err := ca.RevokeCert(context.Background(), cert, RevokeOptions{DeleteKeys: true})
	require.Error(t, err, "a discarded keystore DeleteKey failure during revocation must now surface")
	assert.ErrorIs(t, err, injected)

	revoked, revokedErr := ca.IsRevoked(cert.SerialNumber)
	require.NoError(t, revokedErr)
	assert.True(t, revoked, "the certificate must be revoked even though key cleanup failed")
}

// TestRecordIssuedKey_NilAttrs proves recordIssuedKey rejects a nil attrs
// argument with a typed error instead of silently doing nothing or
// panicking.
func TestRecordIssuedKey_NilAttrs(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.recordIssuedKey(context.Background(), cert751TestSerial(), nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestResolveIssuedKeyAttributes_RoundTrip proves resolveIssuedKeyAttributes
// reconstructs the same StoreType/KeyType/algorithm/curve recordIssuedKey
// persisted, including for an RSA key (exercising the RSAAttributes branch
// that the ECDSA-only issuance tests above never touch).
func TestResolveIssuedKeyAttributes_RoundTrip(t *testing.T) {
	ca := setupTestCA(t)
	serial := cert751TestSerial()
	attrs := &types.KeyAttributes{
		CN:           "resolve-roundtrip.example.com",
		StoreType:    types.StoreSoftware,
		KeyType:      types.KeyTypeTLS,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	require.NoError(t, ca.recordIssuedKey(context.Background(), serial, attrs))

	resolved, err := ca.resolveIssuedKeyAttributes(context.Background(), serial)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, attrs.CN, resolved.CN)
	assert.Equal(t, attrs.StoreType, resolved.StoreType)
	assert.Equal(t, attrs.KeyType, resolved.KeyType)
	assert.Equal(t, attrs.KeyAlgorithm, resolved.KeyAlgorithm)
	require.NotNil(t, resolved.RSAAttributes)
	assert.Equal(t, 2048, resolved.RSAAttributes.KeySize)

	// Validate must accept the reconstructed attributes -- the entire point
	// of recording them at issuance (go-xkms#751).
	assert.NoError(t, resolved.Validate())
}

// TestResolveIssuedKeyAttributes_NotFoundIsNilNil proves that resolving a
// serial with no recorded key returns (nil, nil), the no-op signal RevokeCert
// relies on, rather than an error.
func TestResolveIssuedKeyAttributes_NotFoundIsNilNil(t *testing.T) {
	ca := setupTestCA(t)
	resolved, err := ca.resolveIssuedKeyAttributes(context.Background(), cert751TestSerial())
	require.NoError(t, err)
	assert.Nil(t, resolved)
}

// TestDeleteIssuedKeyRecord_NotFoundIsNoError proves that deleting a record
// that was never written (or was already deleted) is not an error.
func TestDeleteIssuedKeyRecord_NotFoundIsNoError(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.deleteIssuedKeyRecord(context.Background(), cert751TestSerial())
	assert.NoError(t, err)
}

// revokeFailingRevocationStore wraps a storage.Backend and injects a
// failure into Put, so tests can prove that a failure persisting the
// issued-key record at issuance time surfaces from IssueCertificateWithProfile
// instead of leaving a certificate on record with no recoverable key
// attributes. Every other method delegates to the embedded Backend
// unchanged.
type revokeFailingRevocationStore struct {
	storage.Backend
	failPut error
}

func (f *revokeFailingRevocationStore) Put(ctx context.Context, key string, value []byte) error {
	if f.failPut != nil {
		return f.failPut
	}
	return f.Backend.Put(ctx, key, value)
}

// TestIssueCertificateWithProfile_RecordIssuedKeyFailurePropagates proves
// that a failure persisting the issuance-time key-attribute record surfaces
// from IssueCertificateWithProfile as a real error instead of issuing a
// certificate whose key can never be resolved for a later DeleteKeys
// revocation.
func TestIssueCertificateWithProfile_RecordIssuedKeyFailurePropagates(t *testing.T) {
	ca := setupTestCA(t)
	injected := errors.New("injected revocation store Put failure")
	ca.revocationStore = &revokeFailingRevocationStore{Backend: ca.revocationStore, failPut: injected}

	_, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "issue-recordkey-fail.example.com"},
		Valid:   365,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, injected)
}

// cert751TestSerial returns a fixed serial number for tests that exercise
// the issued-key record helpers directly without issuing a real
// certificate.
func cert751TestSerial() *big.Int {
	return big.NewInt(90751)
}
