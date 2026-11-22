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
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSwapTestBarrierBackend returns an unsealed BarrierBackend over a fresh
// memory base, and the base so a test can break it.
func newSwapTestBarrierBackend(t *testing.T) (*BarrierBackend, storage.Backend) {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := NewBarrier(testLogger(), base, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := CredentialsFor(t.Context(), []byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)
	return NewBarrierBackend(barrier), base
}

// A matching expectation swaps; a stale one is refused and reports the
// decrypted value that is present, so the caller can recompute and retry.
func TestBarrierBackend_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	bb, base := newSwapTestBarrierBackend(t)
	t.Cleanup(func() { _ = base.Close() })
	require.True(t, storage.GuardedWritesUsable(bb),
		"the barrier backend must offer the guarded writes a DAO needs")

	require.NoError(t, bb.Put(ctx, "k", []byte("v1")))

	swapped, current, err := bb.CompareAndSwap(ctx, "k", []byte("stale"), []byte("v2"))
	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Equal(t, []byte("v1"), current, "a refusal reports the plaintext present")

	swapped, current, err = bb.CompareAndSwap(ctx, "k", []byte("v1"), []byte("v2"))
	require.NoError(t, err)
	assert.True(t, swapped)
	assert.Nil(t, current)

	got, err := bb.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got)
}

// A swap does not create: an absent key is an ordinary refusal with no current
// value, not an error.
func TestBarrierBackend_CompareAndSwapAbsentKeyIsARefusal(t *testing.T) {
	ctx := context.Background()
	bb, base := newSwapTestBarrierBackend(t)
	t.Cleanup(func() { _ = base.Close() })

	swapped, current, err := bb.CompareAndSwap(ctx, "missing", nil, []byte("v"))
	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Nil(t, current)

	ok, err := bb.Exists(ctx, "missing")
	require.NoError(t, err)
	assert.False(t, ok, "a refused swap must not create the key")
}

// A failure that is not "absent" stays an error, because swapped=false is the
// claim that the guard was evaluated.
func TestBarrierBackend_CompareAndSwapSurfacesRealFailures(t *testing.T) {
	ctx := context.Background()
	bb, base := newSwapTestBarrierBackend(t)
	require.NoError(t, base.Close())

	swapped, current, err := bb.CompareAndSwap(ctx, "k", []byte("v1"), []byte("v2"))
	require.Error(t, err)
	assert.NotErrorIs(t, err, storage.ErrNotFound)
	assert.False(t, swapped)
	assert.Nil(t, current)
}

// A nil barrier yields no backend, so a caller cannot hold a BarrierBackend
// whose every call would dereference nil.
func TestNewBarrierBackend_NilBarrier(t *testing.T) {
	assert.Nil(t, NewBarrierBackend(nil))
}
