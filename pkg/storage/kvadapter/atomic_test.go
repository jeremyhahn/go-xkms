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

package kvadapter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// guardedErrorBackend is errorBackend plus CompareAndSwap, so it satisfies all
// three guarded operations and New gives it the atomic adapter. It exists to
// reach the adapter's error paths, which the honest negative fixture
// (errorBackend, which has no CompareAndSwap) cannot reach by construction.
type guardedErrorBackend struct {
	errorBackend
	swapErr error
}

func (g *guardedErrorBackend) CompareAndSwap(_ context.Context, _ string, _, _ []byte) (bool, []byte, error) {
	if g.swapErr != nil {
		return false, nil, g.swapErr
	}
	return true, nil, nil
}

// atomicStore is the assertion go-qrdb's DAO layer makes. Every test that
// needs the guarded surface goes through it rather than through a concrete
// type, because the assertion IS the contract this change is about.
func atomicStore(t *testing.T, backend storage.Backend) qrdbsdk.AtomicKVStore {
	t.Helper()
	store, err := New(backend)
	require.NoError(t, err)
	atomic, ok := store.(qrdbsdk.AtomicKVStore)
	require.True(t, ok, "a backend with all three guarded operations must produce an AtomicKVStore")
	return atomic
}

func TestNew_BackendWithoutCompareAndSwapDoesNotClaimAtomicKVStore(t *testing.T) {
	// errorBackend carries PutIfAbsent and CompareAndDelete but no
	// CompareAndSwap, so it can serve two of the three. Claiming the
	// interface would pass go-qrdb's assertion and then fail at call time,
	// after the caller has committed to the guarded path.
	store, err := New(&errorBackend{})
	require.NoError(t, err)

	_, ok := store.(qrdbsdk.AtomicKVStore)
	assert.False(t, ok, "a backend missing one of the three must not claim the interface")
}

func TestAtomicAdapter_PutIfAbsentCreatesOnceAndThenRefuses(t *testing.T) {
	ctx := context.Background()
	backend := storage.NewMemory()
	store := atomicStore(t, backend)

	stored, err := store.PutIfAbsent(ctx, "lock", []byte("first"))
	require.NoError(t, err)
	assert.True(t, stored)

	stored, err = store.PutIfAbsent(ctx, "lock", []byte("second"))
	require.NoError(t, err)
	assert.False(t, stored, "the key was present, so this call stores nothing")

	value, err := backend.Get(ctx, "lock")
	require.NoError(t, err)
	assert.Equal(t, []byte("first"), value, "the refused call must leave the holder's value in place")
}

func TestAtomicAdapter_CompareAndDeleteReleasesOnlyTheExpectedValue(t *testing.T) {
	ctx := context.Background()
	backend := storage.NewMemory()
	store := atomicStore(t, backend)
	require.NoError(t, backend.Put(ctx, "lock", []byte("held-by-a")))

	deleted, err := store.CompareAndDelete(ctx, "lock", []byte("held-by-b"))
	require.NoError(t, err)
	assert.False(t, deleted, "a different value is a refusal, not an error")

	value, err := backend.Get(ctx, "lock")
	require.NoError(t, err)
	assert.Equal(t, []byte("held-by-a"), value)

	deleted, err = store.CompareAndDelete(ctx, "lock", []byte("held-by-a"))
	require.NoError(t, err)
	assert.True(t, deleted)

	_, err = backend.Get(ctx, "lock")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestAtomicAdapter_CompareAndDeleteOnAbsentKeyIsARefusal(t *testing.T) {
	store := atomicStore(t, storage.NewMemory())

	deleted, err := store.CompareAndDelete(context.Background(), "never-written", []byte("anything"))
	require.NoError(t, err, "an absent key leaves the store as the caller wanted it")
	assert.False(t, deleted)
}

func TestAtomicAdapter_CompareAndSwapReplacesOnlyTheExpectedValue(t *testing.T) {
	ctx := context.Background()
	backend := storage.NewMemory()
	store := atomicStore(t, backend)
	require.NoError(t, backend.Put(ctx, "counter", []byte("1")))

	swapped, err := store.CompareAndSwap(ctx, "counter", []byte("9"), []byte("2"))
	require.NoError(t, err)
	assert.False(t, swapped)

	value, err := backend.Get(ctx, "counter")
	require.NoError(t, err)
	assert.Equal(t, []byte("1"), value)

	swapped, err = store.CompareAndSwap(ctx, "counter", []byte("1"), []byte("2"))
	require.NoError(t, err)
	assert.True(t, swapped)

	value, err = backend.Get(ctx, "counter")
	require.NoError(t, err)
	assert.Equal(t, []byte("2"), value)
}

// TestAtomicAdapter_CompareAndSwapWithNilExpectedNeverCreates pins the
// property that makes CompareAndSwap a safe straight delegation (#186):
// go-xkms's CompareAndSwapper and go-qrdb's CompareAndSwap now agree that a
// nil expected is never "require the key to be absent" -- an absent key
// refuses on both sides, so forwarding the nil cannot create a key the
// qrdb-side caller was told could not be created.
func TestAtomicAdapter_CompareAndSwapWithNilExpectedNeverCreates(t *testing.T) {
	ctx := context.Background()
	backend := storage.NewMemory()
	store := atomicStore(t, backend)

	swapped, err := store.CompareAndSwap(ctx, "absent", nil, []byte("created"))
	require.NoError(t, err)
	assert.False(t, swapped)

	_, err = backend.Get(ctx, "absent")
	assert.ErrorIs(t, err, storage.ErrNotFound, "a swap is not a create")
}

func TestAtomicAdapter_CompareAndSwapWithNilExpectedLeavesAPresentKeyAlone(t *testing.T) {
	ctx := context.Background()
	backend := storage.NewMemory()
	store := atomicStore(t, backend)
	require.NoError(t, backend.Put(ctx, "held", []byte("original")))

	swapped, err := store.CompareAndSwap(ctx, "held", nil, []byte("overwritten"))
	require.NoError(t, err)
	assert.False(t, swapped)

	value, err := backend.Get(ctx, "held")
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), value)
}

// TestAtomicAdapter_CompareAndSwapWithEmptyExpectedIsForwarded pins the other
// half of that rule: an expected that is non-nil but empty is a real stored
// value, not a nil, so it must reach the backend.
func TestAtomicAdapter_CompareAndSwapWithEmptyExpectedIsForwarded(t *testing.T) {
	ctx := context.Background()
	backend := storage.NewMemory()
	store := atomicStore(t, backend)
	require.NoError(t, backend.Put(ctx, "empty", []byte{}))

	swapped, err := store.CompareAndSwap(ctx, "empty", []byte{}, []byte("filled"))
	require.NoError(t, err)
	assert.True(t, swapped, "the stored value is the empty slice, which equals the expectation")

	value, err := backend.Get(ctx, "empty")
	require.NoError(t, err)
	assert.Equal(t, []byte("filled"), value)
}

func TestAtomicAdapter_SurfacesBackendErrors(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("backend is unavailable")

	store := atomicStore(t, &guardedErrorBackend{
		errorBackend: errorBackend{putErr: sentinel, deleteErr: sentinel},
		swapErr:      sentinel,
	})

	stored, err := store.PutIfAbsent(ctx, "k", []byte("v"))
	assert.False(t, stored)
	assert.ErrorIs(t, err, sentinel, "an unknown outcome must not read as stored=false")

	deleted, err := store.CompareAndDelete(ctx, "k", []byte("v"))
	assert.False(t, deleted)
	assert.ErrorIs(t, err, sentinel)

	swapped, err := store.CompareAndSwap(ctx, "k", []byte("old"), []byte("new"))
	assert.False(t, swapped)
	assert.ErrorIs(t, err, sentinel)
}

// unavailableGuardedBackend declares all three guarded operations and reports
// that none of them can execute — the shape of the QRDB backend built through
// the embedded constructors, which fails every guarded write for want of a
// transaction service (#125).
type unavailableGuardedBackend struct {
	guardedErrorBackend
}

func (u *unavailableGuardedBackend) GuardedWritesAvailable() bool { return false }

func TestNew_BackendThatReportsGuardedWritesUnavailableIsNotClaimedAtomic(t *testing.T) {
	store, err := New(&unavailableGuardedBackend{})
	require.NoError(t, err)

	_, ok := store.(qrdbsdk.AtomicKVStore)
	assert.False(t, ok,
		"declaring the methods is not performing them: a backend that reports the operations "+
			"unavailable must fail the assertion rather than fail the first guarded write")
}

// TestNew_EmbeddedQRDBBackendsAreClaimedAtomic is the regression the
// capability report exists for, against the real constructors rather than a
// fake: pkg/storage/qrdb's embedded memory, file and pebble backends declare
// CompareAndSwapper and CompareAndDeleter and, since #125, can execute all
// three guarded verbs through the transport's own guarded-write capability, so
// New must claim them as an AtomicKVStore.
func TestNew_EmbeddedQRDBBackendsAreClaimedAtomic(t *testing.T) {
	dir := t.TempDir()

	memory, err := qrdbstorage.NewMemory()
	require.NoError(t, err)
	t.Cleanup(func() { _ = memory.Close() })

	file, err := qrdbstorage.NewFile(filepath.Join(dir, "file"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	pebble, err := qrdbstorage.NewPebble(filepath.Join(dir, "pebble"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = pebble.Close() })

	for name, backend := range map[string]storage.Backend{
		"memory": memory,
		"file":   file,
		"pebble": pebble,
	} {
		t.Run(name, func(t *testing.T) {
			// The premise: these backends DO declare the guarded verbs, so a
			// method-set test would claim them.
			_, canSwap := backend.(storage.CompareAndSwapper)
			_, canDelete := backend.(storage.CompareAndDeleter)
			require.True(t, canSwap && canDelete, "the premise of this test is that the methods are declared")

			store, err := New(backend)
			require.NoError(t, err)

			_, ok := store.(qrdbsdk.AtomicKVStore)
			assert.True(t, ok, "the embedded transport's GuardedKVClient capability serves all three guarded writes (#125)")
		})
	}
}

// TestNew_PrefixedBackendOverANonGuardedBackendIsNotClaimedAtomic is the
// decorator half of the same rule, at the level that matters: a PrefixBackend
// satisfies CompareAndSwapper and CompareAndDeleter whatever it wraps, so
// without asking it what the inner backend can do, this adapter would advertise
// AtomicKVStore for a store whose first guarded write returns
// ErrCompareAndSwapUnsupported.
func TestNew_PrefixedBackendOverANonGuardedBackendIsNotClaimedAtomic(t *testing.T) {
	// errorBackend declares PutIfAbsent and CompareAndDelete and no
	// CompareAndSwap, so the prefixed view of it cannot serve all three.
	prefixed, err := storage.NewPrefixBackend(&errorBackend{}, "tenant")
	require.NoError(t, err)

	_, canSwap := storage.Backend(prefixed).(storage.CompareAndSwapper)
	_, canDelete := storage.Backend(prefixed).(storage.CompareAndDeleter)
	require.True(t, canSwap && canDelete, "the premise: the decorator declares both whatever it wraps")

	store, err := New(prefixed)
	require.NoError(t, err)

	_, ok := store.(qrdbsdk.AtomicKVStore)
	assert.False(t, ok, "the wrapped backend cannot swap, so the prefixed view cannot either")
}

func TestNew_PrefixedBackendOverAGuardedBackendKeepsTheCapability(t *testing.T) {
	prefixed, err := storage.NewPrefixBackend(storage.NewMemory(), "tenant")
	require.NoError(t, err)

	store, err := New(prefixed)
	require.NoError(t, err)

	_, ok := store.(qrdbsdk.AtomicKVStore)
	assert.True(t, ok, "prefixing an able backend must not take the capability away")
}
