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

package hardware

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This adapter deliberately does NOT implement storage.CompareAndDeleter, and
// that absence is the contract being pinned here. It is not a gap left for
// later: DeleteCert addresses a certificate ID rather than a record, so a
// guarded release of certs/{id}.pem or certs/{id}-chain.pem cannot be scoped to
// the key it names. Implementing the capability would mean destroying the
// sibling record — whose bytes were never compared — and reporting success.
//
// Expressing that by NOT having the method, rather than by having one that
// always errors, is what makes it visible to a caller at the type assertion
// instead of on the first call in production. Tracked by #143.
func TestHardwareBackendAdapter_DoesNotClaimCompareAndDeleter(t *testing.T) {
	adapter := NewHardwareBackendAdapter(newMockHardwareCertStorage(10))

	_, ok := adapter.(storage.CompareAndDeleter)
	assert.False(t, ok,
		"the hardware adapter must not claim a guarded delete it cannot scope to one record (#143)")

	// It is still a Backend in every other respect: the missing capability
	// costs nothing else.
	assert.Implements(t, (*storage.Backend)(nil), adapter)
}

// CHARACTERIZATION of the behaviour that makes the capability unimplementable.
// Unguarded Delete removes the certificate AND its chain, because it addresses
// the id. This is long-standing and deliberately unchanged.
//
// It is pinned so the two facts cannot drift apart silently: if a future change
// scopes Delete to a single record — which is what #143 would need — this test
// fails, and the decision not to implement CompareAndDeleter has to be
// re-derived rather than quietly left in place.
func TestHardwareBackendAdapter_DeleteStillRemovesThePairedRecord(t *testing.T) {
	ctx := context.Background()

	const id = "paired-delete"
	leaf := generateTestCertForAdapter(t, "paired-delete-leaf")
	primary := generateTestCertForAdapter(t, "paired-delete-primary")

	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)
	require.NoError(t, hw.SaveCert(id, primary))
	require.NoError(t, hw.SaveCertChain(id, []*x509.Certificate{leaf}))

	require.NoError(t, adapter.Delete(ctx, "certs/"+id+".pem"))

	_, err := hw.GetCert(id)
	assert.ErrorIs(t, err, storage.ErrNotFound, "the certificate is removed, as always")
	_, err = hw.GetCertChain(id)
	assert.ErrorIs(t, err, storage.ErrNotFound,
		"and so is the chain -- this is why a guarded delete cannot be scoped here (#143)")
}
