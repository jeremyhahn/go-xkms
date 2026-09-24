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

package pkcs11state

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(storage.NewMemory())
	require.NoError(t, err)
	return s
}

func TestNewStore_RejectsNilBackend(t *testing.T) {
	_, err := NewStore(nil)
	require.ErrorIs(t, err, ErrNilBackend)
}

func TestStore_PutGetDelete_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	value := []byte("token-state-blob")
	require.NoError(t, s.Put(ctx, "tenant-a", "tok0", "pkcs11/tokens/0", value))

	got, found, err := s.Get(ctx, "tenant-a", "tok0", "pkcs11/tokens/0")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, value, got)

	require.NoError(t, s.Delete(ctx, "tenant-a", "tok0", "pkcs11/tokens/0"))
	_, found, err = s.Get(ctx, "tenant-a", "tok0", "pkcs11/tokens/0")
	require.NoError(t, err)
	assert.False(t, found, "a deleted record must read back as absent")
}

func TestStore_Get_AbsentIsNotAnError(t *testing.T) {
	s := newTestStore(t)
	_, found, err := s.Get(context.Background(), "t", "tok0", "missing")
	require.NoError(t, err, "an absent key is (nil, false, nil), not an error")
	assert.False(t, found)
}

func TestStore_Get_DistinguishesEmptyValueFromAbsent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "t", "tok0", "empty", []byte{}))

	_, found, err := s.Get(ctx, "t", "tok0", "empty")
	require.NoError(t, err)
	assert.True(t, found, "a present empty value must report found=true, not be mistaken for absent")
}

func TestStore_PutIfAbsent_IsAtomicFirstWriterWins(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.PutIfAbsent(ctx, "t", "tok0", "marker", []byte("first"))
	require.NoError(t, err)
	assert.True(t, stored, "the first write must be stored")

	stored, err = s.PutIfAbsent(ctx, "t", "tok0", "marker", []byte("second"))
	require.NoError(t, err)
	assert.False(t, stored, "a second write to an existing key must be refused")

	got, _, err := s.Get(ctx, "t", "tok0", "marker")
	require.NoError(t, err)
	assert.Equal(t, []byte("first"), got, "the original value must be preserved")
}

func TestStore_Delete_MissingKeyIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Delete(context.Background(), "t", "tok0", "never-existed"))
}

func TestStore_List_ReturnsNamespaceRelativeKeys(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "t", "tok0", "pkcs11/objects/1", []byte("a")))
	require.NoError(t, s.Put(ctx, "t", "tok0", "pkcs11/objects/2", []byte("b")))
	require.NoError(t, s.Put(ctx, "t", "tok0", "pkcs11/tokens/0", []byte("c")))
	// A different token must not leak into this token's listing.
	require.NoError(t, s.Put(ctx, "t", "tok1", "pkcs11/objects/9", []byte("d")))

	keys, err := s.List(ctx, "t", "tok0", "pkcs11/objects/")
	require.NoError(t, err)
	sort.Strings(keys)
	assert.Equal(t, []string{"pkcs11/objects/1", "pkcs11/objects/2"}, keys,
		"List must return keys relative to the token namespace and exclude other tokens")
}

func TestStore_Isolation_TenantAndTokenNamespacesDoNotAlias(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "tenant-a", "tok0", "k", []byte("a")))
	require.NoError(t, s.Put(ctx, "tenant-b", "tok0", "k", []byte("b")))
	require.NoError(t, s.Put(ctx, "", "tok0", "k", []byte("system")))

	for _, tc := range []struct {
		tenant string
		want   string
	}{{"tenant-a", "a"}, {"tenant-b", "b"}, {"", "system"}} {
		got, found, err := s.Get(ctx, tc.tenant, "tok0", "k")
		require.NoError(t, err)
		require.True(t, found)
		assert.Equalf(t, []byte(tc.want), got, "tenant %q must see its own value", tc.tenant)
	}
}

// noGuardedDeleteBackend hides every optional capability of the backend it
// wraps: its method set is exactly storage.Backend's.
type noGuardedDeleteBackend struct {
	storage.Backend
}

// erroringBackend wraps a real backend but forces Get and List to fail with
// errBackendUnavailable, so tests can exercise the error path Store must
// propagate rather than swallow.
type erroringBackend struct {
	storage.Backend
}

var errBackendUnavailable = errors.New("pkcs11state test: backend unavailable")

func (erroringBackend) Get(context.Context, string) ([]byte, error) {
	return nil, errBackendUnavailable
}

func (erroringBackend) List(context.Context, string) ([]string, error) {
	return nil, errBackendUnavailable
}

func TestStore_Get_PropagatesNonNotFoundErrors(t *testing.T) {
	s, err := NewStore(erroringBackend{Backend: storage.NewMemory()})
	require.NoError(t, err)

	_, found, err := s.Get(context.Background(), "t", "tok0", "k")
	require.ErrorIs(t, err, errBackendUnavailable,
		"an error other than ErrNotFound must be returned to the caller, not swallowed")
	assert.False(t, found)
}

func TestStore_List_PropagatesBackendErrors(t *testing.T) {
	s, err := NewStore(erroringBackend{Backend: storage.NewMemory()})
	require.NoError(t, err)

	keys, err := s.List(context.Background(), "t", "tok0", "")
	require.ErrorIs(t, err, errBackendUnavailable)
	assert.Nil(t, keys)
}

func TestStore_CompareAndSwap_SwapsOnlyWhenExpectedMatches(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.Put(ctx, "t", "tok0", "counter", []byte("1")))

	swapped, current, err := s.CompareAndSwap(ctx, "t", "tok0", "counter", []byte("wrong"), []byte("2"))
	require.NoError(t, err)
	assert.False(t, swapped, "a mismatched expected value must refuse without an error")
	assert.Equal(t, []byte("1"), current, "the refusal must report the current value")

	swapped, _, err = s.CompareAndSwap(ctx, "t", "tok0", "counter", []byte("1"), []byte("2"))
	require.NoError(t, err)
	assert.True(t, swapped)

	got, found, err := s.Get(ctx, "t", "tok0", "counter")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("2"), got, "a successful swap must persist the new value")
}

func TestStore_CompareAndSwap_UnsupportedBackendIsAnError(t *testing.T) {
	s, err := NewStore(noGuardedDeleteBackend{Backend: storage.NewMemory()})
	require.NoError(t, err)

	swapped, current, err := s.CompareAndSwap(context.Background(), "t", "tok0", "counter", nil, []byte("1"))
	require.ErrorIs(t, err, ErrCompareAndSwapUnsupported,
		"a backend without the capability must refuse with an error, never emulate the guard")
	assert.False(t, swapped)
	assert.Nil(t, current)
}

func TestStore_CompareAndDelete_ReleasesOnlyTheObservedValue(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.Put(ctx, "t", "tok0", "marker", []byte("holder-A")))

	deleted, err := s.CompareAndDelete(ctx, "t", "tok0", "marker", []byte("holder-B"))
	require.NoError(t, err)
	assert.False(t, deleted, "a different value must refuse without an error")

	deleted, err = s.CompareAndDelete(ctx, "t", "tok0", "never-existed", []byte("holder-A"))
	require.NoError(t, err)
	assert.False(t, deleted, "an absent key must refuse without an error")

	deleted, err = s.CompareAndDelete(ctx, "t", "tok0", "marker", []byte("holder-A"))
	require.NoError(t, err)
	assert.True(t, deleted)

	_, found, err := s.Get(ctx, "t", "tok0", "marker")
	require.NoError(t, err)
	assert.False(t, found, "the record is gone once the guard matched")
}

func TestStore_CompareAndDelete_UnsupportedBackendIsAnError(t *testing.T) {
	s, err := NewStore(noGuardedDeleteBackend{Backend: storage.NewMemory()})
	require.NoError(t, err)

	deleted, err := s.CompareAndDelete(context.Background(), "t", "tok0", "marker", []byte("holder-A"))
	require.ErrorIs(t, err, ErrCompareAndDeleteUnsupported,
		"a backend without the capability must refuse with an error, never emulate the guard")
	assert.False(t, deleted)
}
