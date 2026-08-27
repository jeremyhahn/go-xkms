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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This is where two different shapes of the same idea meet. go-qrdb's
// StorageBackend (go-quicraft's interface) requires CompareAndDelete as a
// MANDATORY method; xkms models it as the OPTIONAL storage.CompareAndDeleter so
// a backend that cannot provide it can say so by not having it. The adapter is
// the only place that difference is resolved, so it is the only place that needs
// to be right about it.
func TestGuardedStorageBackend_SatisfiesQRDBStorageBackend(t *testing.T) {
	// The compile-time claim the three barrier constructors depend on.
	var _ qrdbsdk.StorageBackend = guardedStorageBackend{storage.NewMemory()}
	assert.Implements(t, (*qrdbsdk.StorageBackend)(nil), guardedStorageBackend{storage.NewMemory()})
}

// A backend that claims the capability is forwarded to, unchanged.
func TestGuardedStorageBackend_ForwardsToACapableBackend(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	require.Implements(t, (*storage.CompareAndDeleter)(nil), mem)

	g := guardedStorageBackend{mem}
	const key = "keys/boundary"
	require.NoError(t, g.Put(ctx, key, []byte("A")))

	// A mismatched guard is a refusal, not an error -- the contract survives the
	// hop through the adapter.
	deleted, err := g.CompareAndDelete(ctx, key, []byte("B"))
	require.NoError(t, err)
	assert.False(t, deleted)

	deleted, err = g.CompareAndDelete(ctx, key, []byte("A"))
	require.NoError(t, err)
	assert.True(t, deleted)

	ok, err := g.Exists(ctx, key)
	require.NoError(t, err)
	assert.False(t, ok)
}

// A backend WITHOUT the capability produces the typed error here, and only here.
// That is the design: the backend itself has no method to be wrong about, and
// the one place quicraft's contract demands a method is the one place that has
// to answer for its absence. quicraft's own contract allows exactly this -- a
// backend that cannot perform the operation reports an error rather than
// approximating it.
func TestGuardedStorageBackend_ReportsAnIncapableBackendAtTheBoundary(t *testing.T) {
	ctx := context.Background()
	base := incapableBackend{storage.NewMemory()}
	t.Cleanup(func() { _ = base.Close() })
	require.NotImplements(t, (*storage.CompareAndDeleter)(nil), base,
		"the fixture must not claim the capability, or this test proves nothing")

	g := guardedStorageBackend{base}
	const key = "keys/boundary"
	require.NoError(t, g.Put(ctx, key, []byte("A")))

	deleted, err := g.CompareAndDelete(ctx, key, []byte("A"))

	require.Error(t, err, "an absent capability is an error, never a refusal")
	assert.ErrorIs(t, err, storage.ErrCompareAndDeleteUnsupported)
	assert.False(t, deleted)

	// It must not have degraded to a read followed by an unguarded delete.
	ok, existsErr := g.Exists(ctx, key)
	require.NoError(t, existsErr)
	assert.True(t, ok, "nothing may be removed when the guard cannot be evaluated")
}

// incapableBackend is a storage.Backend that deliberately hides the wrapped
// backend's CompareAndDeleter, standing in for the hardware adapter and the
// remote PKCS#11 state backend without importing either.
type incapableBackend struct {
	storage.Backend
}

// qrdbShapedSwap mirrors go-qrdb's unexported guardedSwapBackend, which is what
// StorageBarrier.CompareAndSwap type-asserts its base against.
type qrdbShapedSwap interface {
	CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error)
}

// A wrapper must not silently DROP a capability. Embedding storage.Backend
// narrows the value to that interface's method set, so without explicit
// forwarding a wrapped backend stops satisfying storage.CompareAndSwapper even
// though the backend underneath implements it.
//
// In a design where capabilities are discovered by type assertion, a wrapper
// that quietly removes one is the characteristic failure: nothing breaks at
// compile time, and the capability just stops being found.
func TestGuardedStorageBackend_PreservesTheSwapCapability(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	require.Implements(t, (*storage.CompareAndSwapper)(nil), mem,
		"the fixture must have the capability, or this test proves nothing")

	var wrapped any = guardedStorageBackend{mem}
	cas, ok := wrapped.(storage.CompareAndSwapper)
	require.True(t, ok, "wrapping must not hide storage.CompareAndSwapper")

	// Forwarded, not merely declared: it has to reach the real backend, and the
	// third return value -- the current value on a failed swap -- has to survive.
	const key = "keys/swap"
	require.NoError(t, mem.Put(ctx, key, []byte("A")))

	swapped, current, err := cas.CompareAndSwap(ctx, key, []byte("WRONG"), []byte("B"))
	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Equal(t, []byte("A"), current,
		"xkms's three-value shape is preserved, so a read-modify-write caller can retry")

	swapped, _, err = cas.CompareAndSwap(ctx, key, []byte("A"), []byte("B"))
	require.NoError(t, err)
	assert.True(t, swapped)

	got, err := mem.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("B"), got)
}

// CHARACTERIZATION, and the reason the forwarding above keeps xkms's signature
// rather than adapting to go-qrdb's.
//
// go-qrdb's guardedSwapBackend wants CompareAndSwap(...) (bool, error); xkms's
// CompareAndSwapper returns (swapped, current, err). Those shapes have never
// matched, so a barrier's own CompareAndSwap has always reported
// ErrGuardedSwapUnsupported over an xkms backend — before this wrapper existed
// and after. Adapting between them would newly enable a path that has never
// worked, which is a behaviour change and not this change's business.
//
// Pinned on the BARE backend as well as the wrapped one, because that is what
// makes it a pre-existing property rather than something the wrapper caused.
func TestGuardedStorageBackend_QRDBShapedSwapWasNeverSatisfied(t *testing.T) {
	mem := storage.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })

	var bare any = mem
	_, bareOK := bare.(qrdbShapedSwap)
	assert.False(t, bareOK,
		"an xkms backend has never matched go-qrdb's two-value swap shape")

	var wrapped any = guardedStorageBackend{mem}
	_, wrappedOK := wrapped.(qrdbShapedSwap)
	assert.False(t, wrappedOK, "and wrapping does not change that either way")
}

// BarrierBackend claims the capability, so it is held to the same conformance
// body as every other claiming backend rather than exempted for inheriting its
// implementation from upstream.
//
// It only conforms because CompareAndDelete is OVERRIDDEN to translate
// storage.ErrNotFound into the refusal the contract requires; the promoted
// barrier method recognises only go-qrdb's ErrSecretNotFound and let the absent
// case escape as an error. Two subtests fail without that override -- the absent
// key, and every loser in the concurrent release, which reaches the same path
// once the winner has removed the key.
//
// The base is a real storage.NewMemory rather than a package test double
// deliberately: the barrier DELEGATES its guard to the base, so a base whose own
// compare-then-delete is not serialized would make the one-winner subtest
// meaningless, and the engine backend's is.
//
// This is also the encrypting case end to end. The barrier guards on the
// CIPHERTEXT it read and its sealing is randomised, so the stale-releaser
// subtest passes because the envelope changed, not because the plaintext did.
func TestBarrierBackend_CompareAndDeleteContract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			base := storage.NewMemory()
			t.Cleanup(func() { _ = base.Close() })

			barrier, err := NewBarrier(testLogger(), base, BarrierConfig{
				RootKeyPath: "test/root-key",
			}, NewSoftwareStrategy())
			require.NoError(t, err)
			initAndUnsealBarrier(t, barrier, Credentials{Secret: []byte("test-password")})

			return NewBarrierBackend(barrier)
		},
		AllowsEmptyValue: true,
	})
}

// The override must translate the absent sentinel and NOTHING else: a real
// failure still has to surface as an error, because deleted=false is the claim
// that the guard was evaluated.
func TestBarrierBackend_CompareAndDeleteTranslatesOnlyTheAbsentSentinel(t *testing.T) {
	ctx := context.Background()
	base := storage.NewMemory()
	barrier, err := NewBarrier(testLogger(), base, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())
	require.NoError(t, err)
	initAndUnsealBarrier(t, barrier, Credentials{Secret: []byte("test-password")})
	bb := NewBarrierBackend(barrier)

	// A closed base fails for a reason that is NOT "absent", so it must remain
	// an error rather than being flattened into a refusal.
	require.NoError(t, base.Close())

	deleted, err := bb.CompareAndDelete(ctx, "keys/anything", []byte("value-A"))
	assert.False(t, deleted)
	require.Error(t, err, "a real failure must not be translated into a refusal")
	assert.NotErrorIs(t, err, storage.ErrNotFound,
		"and it is a different fault than the absent case the override handles")
}
