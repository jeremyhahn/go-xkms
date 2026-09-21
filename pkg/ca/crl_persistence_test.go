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

package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestCAWithRevocationStore builds on the shared setupTestCA helper by
// attaching an in-memory datastore-backed revocation store, the same
// backend CRL artifacts and revocation state replicate through (go-xkms#275).
func setupTestCAWithRevocationStore(t *testing.T) *CA {
	t.Helper()
	ca := setupTestCA(t)
	ca.revocationStore = storage.NewMemory()
	return ca
}

// =============================================================================
// putCRLBlob / getCRLBlob — storage-layer round trip
// =============================================================================

// TestCRLBlob_PersistReadRoundTrip is the replication guard: a CRL artifact
// written by one CA instance is visible to a second CA instance over the
// same backend, modeling any node in a qrdb/Raft cluster reading what
// another node signed.
func TestCRLBlob_PersistReadRoundTrip(t *testing.T) {
	backend := storage.NewMemory()
	ski := []byte{0x01, 0x02, 0x03, 0x04}
	rec := &persistedCRL{
		DER:        []byte("fake-crl-der"),
		Number:     "5",
		ThisUpdate: time.Now().UTC().Truncate(time.Second),
		NextUpdate: time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Second),
	}

	writer := &CA{revocationStore: backend}
	persisted, err := writer.putCRLBlob(context.Background(), ski, rec)
	require.NoError(t, err)
	assert.True(t, persisted)

	reader := &CA{revocationStore: backend}
	got, err := reader.getCRLBlob(context.Background(), ski)
	require.NoError(t, err)
	assert.Equal(t, rec.DER, got.DER)
	assert.Equal(t, rec.Number, got.Number)
	assert.True(t, rec.ThisUpdate.Equal(got.ThisUpdate))
	assert.True(t, rec.NextUpdate.Equal(got.NextUpdate))
}

// TestGetCRLBlob_NotFound covers the unknown-issuer case: no artifact has
// ever been published under this SKI.
func TestGetCRLBlob_NotFound(t *testing.T) {
	ca := &CA{revocationStore: storage.NewMemory()}
	_, err := ca.getCRLBlob(context.Background(), []byte{0xAA, 0xBB})
	assert.ErrorIs(t, err, ErrCRLNotFound)
}

// TestGetCRLBlob_NoStoreConfigured covers the case where neither
// revocationStore nor objectStore is configured: reads report "not found"
// rather than panicking.
func TestGetCRLBlob_NoStoreConfigured(t *testing.T) {
	ca := &CA{}
	_, err := ca.getCRLBlob(context.Background(), []byte{0x01})
	assert.ErrorIs(t, err, ErrCRLNotFound)
}

// TestPutCRLBlob_NoStoreConfigured covers the case where neither store is
// configured: the write is reported as not persisted but is not an error
// (matches putRevocationBlob's contract for the same condition).
func TestPutCRLBlob_NoStoreConfigured(t *testing.T) {
	ca := &CA{}
	persisted, err := ca.putCRLBlob(context.Background(), []byte{0x01}, &persistedCRL{Number: "1"})
	require.NoError(t, err)
	assert.False(t, persisted)
}

// errCRLStoreFault is a non-sentinel storage fault used to exercise
// putCRLBlob/getCRLBlob's error-wrapping branches.
var errCRLStoreFault = errors.New("crl_persistence_test: store unavailable")

// faultyCRLBackend wraps a real storage.Backend and forces every Put and Get
// call to fail, letting tests drive the storage-fault branches without a
// live storage fault.
type faultyCRLBackend struct {
	storage.Backend
}

func (f *faultyCRLBackend) Put(ctx context.Context, key string, value []byte) error {
	return errCRLStoreFault
}

func (f *faultyCRLBackend) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, errCRLStoreFault
}

// TestPutCRLBlob_StoreError covers putCRLBlob's revocationStore.Put error
// branch: the fault must surface wrapped in ErrStorageError, not be
// silently swallowed.
func TestPutCRLBlob_StoreError(t *testing.T) {
	ca := &CA{revocationStore: &faultyCRLBackend{Backend: storage.NewMemory()}}
	_, err := ca.putCRLBlob(context.Background(), []byte{0x01}, &persistedCRL{Number: "1"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.Contains(t, err.Error(), errCRLStoreFault.Error())
}

// TestGetCRLBlob_StoreError covers getCRLBlob's revocationStore.Get error
// branch for a fault distinct from "not found".
func TestGetCRLBlob_StoreError(t *testing.T) {
	ca := &CA{revocationStore: &faultyCRLBackend{Backend: storage.NewMemory()}}
	_, err := ca.getCRLBlob(context.Background(), []byte{0x01})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.Contains(t, err.Error(), errCRLStoreFault.Error())
}

// =============================================================================
// CA.CRL — regenerate-on-read semantics
// =============================================================================

// TestCRL_NotInitialized covers the guard before any signing/storage I/O.
func TestCRL_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.CRL(context.Background())
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// TestCRL_NoIssuingCertificate covers a CA that is initialized but has no
// issuing certificate available -- generation cannot proceed.
func TestCRL_NoIssuingCertificate(t *testing.T) {
	ca := &CA{}
	ca.initialized.Store(true)
	_, err := ca.CRL(context.Background())
	assert.ErrorIs(t, err, ErrCRLGenerationFailed)
}

// TestCRL_GeneratesAndPersistsWhenMissing covers the first read of a CA that
// has never published a CRL: CRL must regenerate and persist rather than
// erroring.
func TestCRL_GeneratesAndPersistsWhenMissing(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)
	ctx := context.Background()

	der, err := ca.CRL(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, der)

	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()
	require.NotNil(t, issuingCert)

	rec, err := ca.getCRLBlob(ctx, issuingCert.SubjectKeyId)
	require.NoError(t, err)
	assert.Equal(t, der, rec.DER)
}

// TestCRL_NoRegenerateWhenFresh covers the common read path: a second call
// before NextUpdate returns byte-identical DER instead of paying for a new
// signing operation.
func TestCRL_NoRegenerateWhenFresh(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)
	ctx := context.Background()

	der1, err := ca.CRL(ctx)
	require.NoError(t, err)

	der2, err := ca.CRL(ctx)
	require.NoError(t, err)

	assert.Equal(t, der1, der2)
}

// TestCRL_RegenerateOnRead_PastNextUpdate covers the staleness-repair path:
// a read after the injected clock passes the persisted artifact's
// NextUpdate must regenerate, producing a new (incremented) CRL Number.
func TestCRL_RegenerateOnRead_PastNextUpdate(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)
	ctx := context.Background()

	base := time.Now().UTC()
	ca.clock = func() time.Time { return base }

	der1, err := ca.CRL(ctx)
	require.NoError(t, err)
	crl1, err := x509.ParseRevocationList(der1)
	require.NoError(t, err)

	// A read still within validity does not regenerate.
	der2, err := ca.CRL(ctx)
	require.NoError(t, err)
	assert.Equal(t, der1, der2)

	// Advance the clock past NextUpdate.
	past := crl1.NextUpdate.Add(time.Second)
	ca.clock = func() time.Time { return past }

	der3, err := ca.CRL(ctx)
	require.NoError(t, err)
	crl3, err := x509.ParseRevocationList(der3)
	require.NoError(t, err)

	assert.NotEqual(t, der1, der3)
	assert.Equal(t, crl1.Number.Int64()+1, crl3.Number.Int64())
	assert.True(t, crl3.NextUpdate.After(past))
}

// TestCRL_NoRegenerateBeforeNextUpdate is the negative counterpart to
// TestCRL_RegenerateOnRead_PastNextUpdate: advancing the clock but staying
// before NextUpdate must not regenerate.
func TestCRL_NoRegenerateBeforeNextUpdate(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)
	ctx := context.Background()

	base := time.Now().UTC()
	ca.clock = func() time.Time { return base }

	der1, err := ca.CRL(ctx)
	require.NoError(t, err)
	crl1, err := x509.ParseRevocationList(der1)
	require.NoError(t, err)

	// Advance, but stay strictly before NextUpdate.
	stillFresh := crl1.NextUpdate.Add(-time.Second)
	ca.clock = func() time.Time { return stillFresh }

	der2, err := ca.CRL(ctx)
	require.NoError(t, err)
	assert.Equal(t, der1, der2)
}

// =============================================================================
// Refresh-on-revoke and force-regenerate
// =============================================================================

// TestCRL_RefreshOnRevoke_NumberIncrements covers the refresh-on-revoke
// hook in recordRevocation: a successful revocation must regenerate and
// persist a new CRL that both increments the Number extension and includes
// the newly revoked serial.
func TestCRL_RefreshOnRevoke_NumberIncrements(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)
	ctx := context.Background()

	der0, err := ca.GenerateCRL(ctx)
	require.NoError(t, err)
	crl0, err := x509.ParseRevocationList(der0)
	require.NoError(t, err)
	assert.Empty(t, crl0.RevokedCertificateEntries)

	serial := big.NewInt(9001)
	require.NoError(t, ca.Revoke(ctx, serial, ReasonKeyCompromise))

	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()

	rec, err := ca.getCRLBlob(ctx, issuingCert.SubjectKeyId)
	require.NoError(t, err)

	crl1, err := x509.ParseRevocationList(rec.DER)
	require.NoError(t, err)

	assert.Equal(t, crl0.Number.Int64()+1, crl1.Number.Int64())
	require.Len(t, crl1.RevokedCertificateEntries, 1)
	assert.Equal(t, 0, crl1.RevokedCertificateEntries[0].SerialNumber.Cmp(serial))
}

// TestGenerateCRL_ForcesRegenerationEvenWhenFresh covers the explicit
// force-refresh contract: GenerateCRL must produce a new CRL (incremented
// Number) even when a just-published artifact is still fully valid, unlike
// CRL which would return the cached DER unchanged.
func TestGenerateCRL_ForcesRegenerationEvenWhenFresh(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)
	ctx := context.Background()

	der1, err := ca.CRL(ctx)
	require.NoError(t, err)
	crl1, err := x509.ParseRevocationList(der1)
	require.NoError(t, err)

	// Confirm the artifact is indeed still fresh (a plain read would not
	// regenerate it).
	der2, err := ca.CRL(ctx)
	require.NoError(t, err)
	assert.Equal(t, der1, der2)

	der3, err := ca.GenerateCRL(ctx)
	require.NoError(t, err)
	crl3, err := x509.ParseRevocationList(der3)
	require.NoError(t, err)

	assert.Equal(t, crl1.Number.Int64()+1, crl3.Number.Int64())
}
