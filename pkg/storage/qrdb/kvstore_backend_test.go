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

package qrdb

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plainKVStore hides every capability of the store it wraps, leaving only
// the KVStore method set: a store with no guarded writes.
type plainKVStore struct {
	qrdbsdk.KVStore
}

// failingKVStore fails every base operation with err.
type failingKVStore struct {
	qrdbsdk.KVStore
	err error
}

func (f failingKVStore) Get(context.Context, string) ([]byte, error)  { return nil, f.err }
func (f failingKVStore) Put(context.Context, string, []byte) error    { return f.err }
func (f failingKVStore) Delete(context.Context, string) error         { return f.err }
func (f failingKVStore) Exists(context.Context, string) (bool, error) { return false, f.err }
func (f failingKVStore) List(context.Context, string) ([]string, error) {
	return nil, f.err
}
func (f failingKVStore) Scan(context.Context, string, func(string, []byte) error) error {
	return f.err
}

func newMemoryKVStoreBackend(t *testing.T) *KVStoreBackend {
	t.Helper()
	b, err := NewKVStoreBackend(qrdbsdk.NewMemoryKVStore())
	require.NoError(t, err)
	return b
}

func TestNewKVStoreBackend_RejectsNilStore(t *testing.T) {
	b, err := NewKVStoreBackend(nil)
	assert.Nil(t, b)
	assert.ErrorIs(t, err, ErrNilKVStore)
}

// TestKVStoreBackend_Lifecycle drives the base Backend contract over a real
// in-memory KVStore: absent reads are ErrNotFound, an empty value is not
// absence, deletes are idempotent, and List/Scan see what Put wrote.
func TestKVStoreBackend_Lifecycle(t *testing.T) {
	ctx := t.Context()
	b := newMemoryKVStoreBackend(t)

	_, err := b.Get(ctx, "missing")
	assert.ErrorIs(t, err, ErrNotFound)

	require.NoError(t, b.Put(ctx, "app/a", []byte("1")))
	require.NoError(t, b.Put(ctx, "app/empty", []byte{}))
	require.NoError(t, b.Put(ctx, "other/b", []byte("2")))

	got, err := b.Get(ctx, "app/a")
	require.NoError(t, err)
	assert.Equal(t, []byte("1"), got)

	empty, err := b.Get(ctx, "app/empty")
	require.NoError(t, err, "a stored empty value is present, not absent")
	assert.Empty(t, empty)

	keys, err := b.List(ctx, "app/")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"app/a", "app/empty"}, keys)

	seen := map[string]string{}
	require.NoError(t, b.Scan(ctx, "app/", func(k string, v []byte) error {
		seen[k] = string(v)
		return nil
	}))
	assert.Equal(t, map[string]string{"app/a": "1", "app/empty": ""}, seen)

	exists, err := b.Exists(ctx, "other/b")
	require.NoError(t, err)
	assert.True(t, exists)

	require.NoError(t, b.Delete(ctx, "other/b"))
	require.NoError(t, b.Delete(ctx, "other/b"), "deleting an absent key is not an error")
	_, err = b.Get(ctx, "other/b")
	assert.ErrorIs(t, err, ErrNotFound)

	assert.NoError(t, b.Close())
}

// TestKVStoreBackend_ScanStopsAtCallbackError proves fn's error ends the
// scan and reaches the caller unwrapped.
func TestKVStoreBackend_ScanStopsAtCallbackError(t *testing.T) {
	ctx := t.Context()
	b := newMemoryKVStoreBackend(t)
	require.NoError(t, b.Put(ctx, "k1", []byte("v")))
	require.NoError(t, b.Put(ctx, "k2", []byte("v")))

	stop := errors.New("stop")
	calls := 0
	err := b.Scan(ctx, "", func(string, []byte) error {
		calls++
		return stop
	})
	assert.Same(t, stop, err)
	assert.Equal(t, 1, calls)
}

// TestKVStoreBackend_GuardedWrites proves the three guarded verbs keep the
// storage contract on an atomic store: a create refuses an existing key, a
// swap edits but never creates and reports the current value on a refusal,
// and a delete honours its guard.
func TestKVStoreBackend_GuardedWrites(t *testing.T) {
	ctx := t.Context()
	b := newMemoryKVStoreBackend(t)
	require.True(t, b.GuardedWritesAvailable())

	stored, err := b.PutIfAbsent(ctx, "k", []byte("v1"))
	require.NoError(t, err)
	assert.True(t, stored)
	stored, err = b.PutIfAbsent(ctx, "k", []byte("v2"))
	require.NoError(t, err)
	assert.False(t, stored)

	swapped, current, err := b.CompareAndSwap(ctx, "k", []byte("wrong"), []byte("v2"))
	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Equal(t, []byte("v1"), current)

	swapped, current, err = b.CompareAndSwap(ctx, "k", []byte("v1"), []byte("v2"))
	require.NoError(t, err)
	assert.True(t, swapped)
	assert.Nil(t, current)

	swapped, current, err = b.CompareAndSwap(ctx, "absent", nil, []byte("x"))
	require.NoError(t, err)
	assert.False(t, swapped, "a swap never creates")
	assert.Nil(t, current)

	deleted, err := b.CompareAndDelete(ctx, "k", []byte("v1"))
	require.NoError(t, err)
	assert.False(t, deleted)
	deleted, err = b.CompareAndDelete(ctx, "k", []byte("v2"))
	require.NoError(t, err)
	assert.True(t, deleted)
}

// TestKVStoreBackend_GuardedWritesUnsupported proves a store without the
// atomic capability says so up front and refuses each guarded verb with the
// SDK's marker rather than degrading to a racy read-then-write.
func TestKVStoreBackend_GuardedWritesUnsupported(t *testing.T) {
	ctx := t.Context()
	b, err := NewKVStoreBackend(plainKVStore{qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	assert.False(t, b.GuardedWritesAvailable())

	_, err = b.PutIfAbsent(ctx, "k", []byte("v"))
	assert.ErrorIs(t, err, qrdbsdk.ErrKVAtomicWriteUnsupported)
	_, _, err = b.CompareAndSwap(ctx, "k", []byte("a"), []byte("b"))
	assert.ErrorIs(t, err, qrdbsdk.ErrKVAtomicWriteUnsupported)
	_, err = b.CompareAndDelete(ctx, "k", []byte("a"))
	assert.ErrorIs(t, err, qrdbsdk.ErrKVAtomicWriteUnsupported)
}

// TestKVStoreBackend_WrapsStoreErrors proves every store failure surfaces as
// a *BackendError naming the operation, with the cause reachable.
func TestKVStoreBackend_WrapsStoreErrors(t *testing.T) {
	ctx := t.Context()
	cause := errors.New("store down")
	b, err := NewKVStoreBackend(failingKVStore{err: cause})
	require.NoError(t, err)

	ops := map[string]func() error{
		"get":    func() error { _, err := b.Get(ctx, "k"); return err },
		"put":    func() error { return b.Put(ctx, "k", []byte("v")) },
		"delete": func() error { return b.Delete(ctx, "k") },
		"exists": func() error { _, err := b.Exists(ctx, "k"); return err },
		"list":   func() error { _, err := b.List(ctx, "p"); return err },
		"scan": func() error {
			return b.Scan(ctx, "p", func(string, []byte) error { return nil })
		},
	}
	for op, call := range ops {
		t.Run(op, func(t *testing.T) {
			err := call()
			var backendErr *BackendError
			require.ErrorAs(t, err, &backendErr)
			assert.Equal(t, op, backendErr.Op)
			assert.ErrorIs(t, err, cause)
		})
	}
}
