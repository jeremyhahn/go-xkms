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
	"fmt"
	"sort"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	return s
}

// newStoreOver returns a store over kv as its database.
func newStoreOver(t *testing.T, kv qrdbsdk.KVStore) *Store {
	t.Helper()
	s, err := NewStore(dao.NewStoreFactory(kv))
	require.NoError(t, err)
	return s
}

func TestNewStore_RequiresAFactoryServingItsDatabase(t *testing.T) {
	_, err := NewStore(nil)
	require.ErrorIs(t, err, ErrNilDAOFactory)

	_, err = NewStore(dao.NewStoreFactory(nil))
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "open", storeErr.Op)
	var unavailable *dao.DatabaseUnavailableError
	assert.ErrorAs(t, err, &unavailable)
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

	require.NoError(t, s.Put(ctx, "tenant-a", "tok0", "pkcs11/tokens/0", []byte("rewritten")))
	got, _, err = s.Get(ctx, "tenant-a", "tok0", "pkcs11/tokens/0")
	require.NoError(t, err)
	assert.Equal(t, []byte("rewritten"), got, "Put overwrites an existing record")

	require.NoError(t, s.Delete(ctx, "tenant-a", "tok0", "pkcs11/tokens/0"))
	_, found, err = s.Get(ctx, "tenant-a", "tok0", "pkcs11/tokens/0")
	require.NoError(t, err)
	assert.False(t, found, "a deleted record must read back as absent")
}

// TestStore_RecordsSurviveAFreshStoreOverTheSameDatabase reproduces a restart:
// a second store over the same database reads what the first one wrote.
func TestStore_RecordsSurviveAFreshStoreOverTheSameDatabase(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	ctx := context.Background()

	before, err := NewStore(daos)
	require.NoError(t, err)
	require.NoError(t, before.Put(ctx, "t", "tok0", "pkcs11/objects/1", []byte("a")))

	after, err := NewStore(daos)
	require.NoError(t, err)
	got, found, err := after.Get(ctx, "t", "tok0", "pkcs11/objects/1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("a"), got)
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

func TestStore_PutIfAbsent_OneOfManyConcurrentWritersWins(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const workers = 32
	stored := make([]bool, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			stored[idx], errs[idx] = s.PutIfAbsent(ctx, "t", "tok0", "marker", []byte(fmt.Sprint(idx)))
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i, err := range errs {
		require.NoError(t, err, "worker %d", i)
		if stored[i] {
			winners++
		}
	}
	assert.Equal(t, 1, winners, "exactly one concurrent create of one key may succeed")
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
	// A different token or tenant must not leak into this token's listing.
	require.NoError(t, s.Put(ctx, "t", "tok1", "pkcs11/objects/9", []byte("d")))
	require.NoError(t, s.Put(ctx, "u", "tok0", "pkcs11/objects/8", []byte("e")))

	keys, err := s.List(ctx, "t", "tok0", "pkcs11/objects/")
	require.NoError(t, err)
	sort.Strings(keys)
	assert.Equal(t, []string{"pkcs11/objects/1", "pkcs11/objects/2"}, keys,
		"List must return keys relative to the token namespace and exclude other tokens")

	keys, err = s.List(ctx, "t", "tok0", "")
	require.NoError(t, err)
	assert.Len(t, keys, 3, "an empty prefix lists every key of the token")

	keys, err = s.List(ctx, "t", "empty-token", "")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestStore_List_ReadsEveryPage proves List does not stop at one page.
func TestStore_List_ReadsEveryPage(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const records = listPageSize + 3
	for i := 0; i < records; i++ {
		require.NoError(t, s.Put(ctx, "t", "tok0", fmt.Sprintf("pkcs11/objects/%d", i), []byte("v")))
	}

	keys, err := s.List(ctx, "t", "tok0", "pkcs11/objects/")
	require.NoError(t, err)
	assert.Len(t, keys, records)
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
	}{{"tenant-a", "a"}, {"tenant-b", "b"}, {"", "system"}, {qrdbsdk.SystemTenantID, "system"}} {
		got, found, err := s.Get(ctx, tc.tenant, "tok0", "k")
		require.NoError(t, err)
		require.True(t, found)
		assert.Equalf(t, []byte(tc.want), got, "tenant %q must see its own value", tc.tenant)
	}
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

func TestStore_CompareAndSwap_AbsentKeyRefuses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	swapped, current, err := s.CompareAndSwap(ctx, "t", "tok0", "counter", nil, []byte("1"))
	require.NoError(t, err)
	assert.False(t, swapped, "a swap cannot create: an absent key refuses whatever expected is")
	assert.Nil(t, current)

	_, found, err := s.Get(ctx, "t", "tok0", "counter")
	require.NoError(t, err)
	assert.False(t, found)
}

// TestStore_CompareAndSwap_ConcurrentIncrementsLoseNoUpdate is the lockout
// counter the operation exists for: every client retries its increment
// against the current value until it swaps, and the final count is exact.
func TestStore_CompareAndSwap_ConcurrentIncrementsLoseNoUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "t", "tok0", "counter", []byte("0")))

	const workers = 16
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			current, _, err := s.Get(ctx, "t", "tok0", "counter")
			for err == nil {
				var n int
				if _, err = fmt.Sscan(string(current), &n); err != nil {
					break
				}
				var swapped bool
				swapped, current, err = s.CompareAndSwap(ctx, "t", "tok0", "counter", current, []byte(fmt.Sprint(n+1)))
				if swapped {
					break
				}
			}
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "worker %d", i)
	}
	got, _, err := s.Get(ctx, "t", "tok0", "counter")
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprint(workers), string(got), "no increment may be lost")
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

// failingKV is an atomic KVStore whose every read and conditional write
// fails, so each method's error reporting can be exercised.
type failingKV struct {
	*qrdbsdk.MemoryKVStore
	err error
}

func (f failingKV) Get(context.Context, string) ([]byte, error) { return nil, f.err }

func (f failingKV) PutIfAbsent(context.Context, string, []byte) (bool, error) {
	return false, f.err
}

func (f failingKV) Scan(context.Context, string, func(string, []byte) error) error { return f.err }

// TestStore_ReportsAStoreFailure proves a datastore failure is a *StoreError
// carrying the cause, never folded into "absent" or a refusal.
func TestStore_ReportsAStoreFailure(t *testing.T) {
	cause := errors.New("datastore unavailable")
	s := newStoreOver(t, failingKV{MemoryKVStore: qrdbsdk.NewMemoryKVStore(), err: cause})
	ctx := context.Background()

	checks := map[string]func() error{
		"get": func() error {
			_, found, err := s.Get(ctx, "t", "tok0", "k")
			assert.False(t, found)
			return err
		},
		"put-if-absent": func() error {
			stored, err := s.PutIfAbsent(ctx, "t", "tok0", "k", []byte("v"))
			assert.False(t, stored)
			return err
		},
		"compare-and-swap": func() error {
			swapped, _, err := s.CompareAndSwap(ctx, "t", "tok0", "k", []byte("a"), []byte("b"))
			assert.False(t, swapped)
			return err
		},
		"compare-and-delete": func() error {
			deleted, err := s.CompareAndDelete(ctx, "t", "tok0", "k", []byte("a"))
			assert.False(t, deleted)
			return err
		},
		"delete": func() error { return s.Delete(ctx, "t", "tok0", "k") },
		"list": func() error {
			keys, err := s.List(ctx, "t", "tok0", "")
			assert.Nil(t, keys)
			return err
		},
	}
	for op, call := range checks {
		t.Run(op, func(t *testing.T) {
			err := call()
			var storeErr *StoreError
			require.ErrorAs(t, err, &storeErr)
			assert.Equal(t, op, storeErr.Op)
			assert.ErrorIs(t, err, cause)
		})
	}
}
