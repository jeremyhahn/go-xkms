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

package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCertificateTestDAO returns a CertificateDAO backed by a fresh in-memory
// store. pkg/storage.NewMemory satisfies qrdbsdk.AtomicKVStore (see
// pkg/storage/kvadapter/atomic_test.go), so SaveCertificateNoCollision
// exercises its atomic SaveIfAbsent path here, not the non-atomic fallback.
func newCertificateTestDAO(t *testing.T) storage.Factory {
	t.Helper()

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	return factory
}

// collidingCertificate builds an ACMECertificate whose DAO row key
// (EntityID) is forced to rowID regardless of its Serial, by setting
// NumericID directly rather than letting it derive from Serial. Two
// certificates built with the same rowID and different serials simulate an
// FNV-1a hash collision (entities.StringToEntityID's hash space is 64
// bits, so a real collision is possible in principle) without needing to
// find one.
func collidingCertificate(serial string, rowID uint64) *entities.ACMECertificate {
	cert := &entities.ACMECertificate{Serial: serial, PEM: "pem-for-" + serial}
	cert.SetEntityID(rowID)
	return cert
}

func TestSaveCertificateNoCollision_CreatesNewCertificate(t *testing.T) {
	factory := newCertificateTestDAO(t)
	dao, err := factory.CertificateDAO()
	require.NoError(t, err)

	ctx := context.Background()
	cert := collidingCertificate("aaaa", 42)

	err = storage.SaveCertificateNoCollision(ctx, dao, cert)
	require.NoError(t, err)

	stored, err := dao.Get(ctx, 42)
	require.NoError(t, err)
	assert.Equal(t, "aaaa", stored.Serial)
}

func TestSaveCertificateNoCollision_RefusesDifferentSerialAtSameRow(t *testing.T) {
	factory := newCertificateTestDAO(t)
	dao, err := factory.CertificateDAO()
	require.NoError(t, err)

	ctx := context.Background()

	certA := collidingCertificate("aaaa", 42)
	require.NoError(t, storage.SaveCertificateNoCollision(ctx, dao, certA))

	certB := collidingCertificate("bbbb", 42)
	err = storage.SaveCertificateNoCollision(ctx, dao, certB)
	require.Error(t, err)

	var collisionErr *storage.CertificateSerialCollisionError
	require.ErrorAs(t, err, &collisionErr)
	assert.Equal(t, "bbbb", collisionErr.Wanted)
	assert.Equal(t, "aaaa", collisionErr.Existing)

	// certA's row must be untouched - certB was never written.
	stored, err := dao.Get(ctx, 42)
	require.NoError(t, err)
	assert.Equal(t, "aaaa", stored.Serial)
	assert.Equal(t, "pem-for-aaaa", stored.PEM)
}

func TestSaveCertificateNoCollision_IdempotentResaveIsNotACollision(t *testing.T) {
	factory := newCertificateTestDAO(t)
	dao, err := factory.CertificateDAO()
	require.NoError(t, err)

	ctx := context.Background()

	first := collidingCertificate("aaaa", 42)
	require.NoError(t, storage.SaveCertificateNoCollision(ctx, dao, first))

	// A second, distinct *entities.ACMECertificate value with the SAME
	// Serial (and therefore the same row) must be treated as an idempotent
	// re-save, not a collision.
	second := collidingCertificate("aaaa", 42)
	err = storage.SaveCertificateNoCollision(ctx, dao, second)
	require.NoError(t, err)

	var collisionErr *storage.CertificateSerialCollisionError
	assert.False(t, errors.As(err, &collisionErr))
}

func TestCertificateSerialCollisionError_Error(t *testing.T) {
	err := &storage.CertificateSerialCollisionError{Wanted: "bbbb", Existing: "aaaa"}
	assert.Contains(t, err.Error(), "bbbb")
	assert.Contains(t, err.Error(), "aaaa")
}
