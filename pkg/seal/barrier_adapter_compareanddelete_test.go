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

// The wrapper gives go-qrdb's barrier the guarded swap of an xkms backend in
// the barrier's own two-value shape, forwarded to the real backend.
func TestGuardedStorageBackend_ForwardsTheSwapInQRDBShape(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	require.Implements(t, (*storage.CompareAndSwapper)(nil), mem,
		"the fixture must have the capability, or this test proves nothing")

	var wrapped any = guardedStorageBackend{mem}
	cas, ok := wrapped.(qrdbShapedSwap)
	require.True(t, ok, "the barrier type-asserts its base against go-qrdb's swap shape")

	const key = "keys/swap"
	require.NoError(t, mem.Put(ctx, key, []byte("A")))

	swapped, err := cas.CompareAndSwap(ctx, key, []byte("WRONG"), []byte("B"))
	require.NoError(t, err)
	assert.False(t, swapped)

	swapped, err = cas.CompareAndSwap(ctx, key, []byte("A"), []byte("B"))
	require.NoError(t, err)
	assert.True(t, swapped)

	got, err := mem.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("B"), got)
}

// A base without the capability is refused, never approximated by a read and
// an unguarded write.
func TestGuardedStorageBackend_SwapUnsupportedIsRefused(t *testing.T) {
	var wrapped any = guardedStorageBackend{noSwapBackend{storage.NewMemory()}}
	cas, ok := wrapped.(qrdbShapedSwap)
	require.True(t, ok)
	_, err := cas.CompareAndSwap(context.Background(), "k", []byte("a"), []byte("b"))
	assert.ErrorIs(t, err, storage.ErrCompareAndSwapUnsupported)
}

// noSwapBackend hides its base's optional capabilities.
type noSwapBackend struct{ storage.Backend }

// A barrier over an xkms backend swaps end to end: it compares the decrypted
// value and lands the new one, and refuses a stale expectation.
func TestBarrierOverXKMSBackend_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	barrier, err := NewBarrier(testLogger(), base, BarrierConfig{RootKeyPath: "test/root-key"}, NewSoftwareStrategy())
	require.NoError(t, err)
	creds := MustCredentials(t.Context(), []byte("swap-test-passphrase"))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(ctx, creds))

	require.NoError(t, barrier.Put(ctx, "k", []byte("v1")))
	swapped, err := barrier.CompareAndSwap(ctx, "k", []byte("stale"), []byte("v2"))
	require.NoError(t, err)
	assert.False(t, swapped)
	swapped, err = barrier.CompareAndSwap(ctx, "k", []byte("v1"), []byte("v2"))
	require.NoError(t, err)
	assert.True(t, swapped)
	got, err := barrier.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got)
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
			creds, err := CredentialsFor(t.Context(), []byte("test-password"))
			require.NoError(t, err)
			defer creds.Secret.Destroy()
			initAndUnsealBarrier(t, barrier, creds)

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
	creds, err := CredentialsFor(t.Context(), []byte("test-password"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	initAndUnsealBarrier(t, barrier, creds)
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
