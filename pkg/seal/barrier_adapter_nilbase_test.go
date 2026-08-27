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

package seal

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A NIL BASE IS A SENTINEL UPSTREAM, and wrapping destroys it. This is the
// classic typed-nil-in-interface trap: guardedStorageBackend{nil} is a non-nil
// interface value holding a nil Backend, so every `base == nil` test on the
// go-qrdb side stops firing.
//
// Two upstream behaviours depend on that test:
//
//   - BarrierRegistry.RegisterTenant treats nil as "allocate this tenant's
//     storage from the volume pool" (barrier_registry.go:273). Wrapped, the
//     pooled allocation is skipped silently and a tenant barrier is built over
//     a wrapper whose embedded Backend is nil -- which fails or panics on the
//     first storage access instead of allocating, or instead of returning
//     ErrPoolNotConfigured when no pool is attached.
//   - NewTenantBarrier rejects a nil base with ErrNilStorageBackend
//     (tenant_barrier.go:40). Wrapped, that guard is bypassed and the same
//     deferred nil-dereference is created.
//
// Both are silent at the call site, which is what makes them worth a test: the
// wrapper compiles, satisfies the interface, and only misbehaves later.
func TestGuardStorage_PreservesANilBase(t *testing.T) {
	// The helper itself: nil in, nil OUT, as an interface value.
	var none storage.Backend
	wrapped := guardStorage(none)
	assert.Nil(t, wrapped,
		"a nil base must stay nil through the wrapper, or upstream's base==nil sentinel stops firing")

	// And a real backend is still wrapped.
	mem := storage.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	assert.NotNil(t, guardStorage(mem))
}

// NewTenantBarrier's nil guard must still fire through the adapter.
func TestNewTenantBarrier_NilBaseStillRejected(t *testing.T) {
	tb, err := NewTenantBarrier("tenant-a", testLogger(), nil, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())

	require.Error(t, err, "a nil base must be refused, not wrapped into a deferred nil-dereference")
	assert.ErrorIs(t, err, qrdbsdk.ErrNilStorageBackend)
	assert.Nil(t, tb)
}

// CHARACTERIZATION of the asymmetry, measured rather than assumed: the SYSTEM
// barrier constructor has no nil-base guard at all. NewStorageBarrier
// (barrier.go:187) validates only that a strategy was supplied, so a nil base
// is accepted and fails later on first use.
//
// That is upstream's behaviour, unchanged by the wrapper in either direction --
// before it existed the nil passed straight through, and guardStorage restores
// exactly that. It is pinned because the asymmetry is surprising: the TENANT
// constructor rejects nil and this one does not, so a reader who assumed the
// guard were symmetric would mis-place the sentinel handling.
func TestNewBarrier_NilBaseIsAcceptedUpstream(t *testing.T) {
	b, err := NewBarrier(testLogger(), nil, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())

	require.NoError(t, err,
		"NewStorageBarrier has no nil-base guard; if it grows one, this test should say so")
	assert.NotNil(t, b)
}

// RegisterTenantWithConfig must reach the POOLED path for a nil backend. With
// no pool attached that surfaces as a configuration error -- the honest answer
// -- rather than a tenant built over a nil backend that breaks later.
func TestRegisterTenantWithConfig_NilBaseReachesThePooledPath(t *testing.T) {
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })

	system, err := NewBarrier(testLogger(), base, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	initAndUnsealBarrier(t, system, Credentials{Secret: []byte("test-password")})

	registry, err := NewBarrierRegistry(system)
	require.NoError(t, err)
	t.Cleanup(func() { _ = registry.Close() })

	tb, err := registry.RegisterTenantWithConfig("tenant-pooled", nil, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())

	require.Error(t, err,
		"a nil backend means 'allocate from the pool'; with no pool configured that is an error, "+
			"not a tenant over a nil backend")
	assert.Nil(t, tb)
}
