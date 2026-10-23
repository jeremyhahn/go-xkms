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

package keypolicy

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// failingKV is a KVStore whose reads and writes fail, so the store's error
// wrapping can be observed.
type failingKV struct {
	qrdbsdk.KVStore
	err error
}

func (f failingKV) Get(context.Context, string) ([]byte, error)  { return nil, f.err }
func (f failingKV) Put(context.Context, string, []byte) error    { return f.err }
func (f failingKV) Delete(context.Context, string) error         { return f.err }
func (f failingKV) Exists(context.Context, string) (bool, error) { return false, f.err }

// newTestStore returns a Store over a real in-process DAO and that DAO, so
// a test can see what the store persisted.
func newTestStore(t *testing.T) (*Store, qrdbsdk.GenericDAO[*Entity]) {
	t.Helper()
	daos := testutil.NewMemoryDAOFactory()
	s, err := NewStore(daos)
	require.NoError(t, err)
	raw, err := newRecordDAO(daos)
	require.NoError(t, err)
	return s, raw
}

// TestNewStore proves a store needs a factory serving its database.
func TestNewStore(t *testing.T) {
	_, err := NewStore(nil)
	assert.ErrorIs(t, err, ErrNilDAOFactory)

	_, err = NewStore(dao.NewStoreFactory(nil))
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "open", storeErr.Op)
}

// TestStoreRoundTrip proves a record is stored as one entity named by its
// tenant, backend and key, read back intact, and deleted.
func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, raw := newTestStore(t)

	rec, found, err := s.Load(ctx, "acme", "software", "k")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, Implicit("k", "software"), rec)

	rec.Status = StatusDisabled
	rec.Tags = map[string]string{"team": "payments"}
	rec.Policy = &Policy{Version: 1, AllowedOperations: []Operation{OpSign}}
	rec.Safety = &Safety{MaxOperations: 10, WarningPercent: 70}
	require.NoError(t, s.Put(ctx, "acme", rec))

	stored, err := raw.GetByNaturalKey(ctx, "acme/software/k")
	require.NoError(t, err)
	assert.Equal(t, StatusDisabled, stored.Status)

	got, found, err := s.Load(ctx, "acme", "software", "k")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, rec, got)

	got.Usage.Uses = 4
	require.NoError(t, s.Put(ctx, "acme", got), "a second Put updates the record")
	count, err := raw.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	require.NoError(t, s.Delete(ctx, "acme", "software", "k"))
	require.NoError(t, s.Delete(ctx, "acme", "software", "k"), "deleting an absent record is not an error")
	_, found, err = s.Load(ctx, "acme", "software", "k")
	require.NoError(t, err)
	assert.False(t, found)
}

// TestStoreListScopesTenant proves List returns one tenant's records only,
// ordered, with the empty tenant and "system" one scope.
func TestStoreListScopesTenant(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	for _, r := range []struct{ tenant, backend, key string }{
		{"acme", "software", "b"}, {"acme", "software", "a"}, {"acme", "pkcs11", "z"},
		{"acmecorp", "software", "x"}, {"", "software", "s"},
	} {
		require.NoError(t, s.Put(ctx, r.tenant, Implicit(r.key, r.backend)))
	}

	got, err := s.List(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, got, 3, "a tenant whose name extends another's is not listed with it")
	assert.Equal(t, []string{"pkcs11/z", "software/a", "software/b"},
		[]string{got[0].Backend + "/" + got[0].KeyID, got[1].Backend + "/" + got[1].KeyID, got[2].Backend + "/" + got[2].KeyID})

	system, err := s.List(ctx, SystemTenant)
	require.NoError(t, err)
	require.Len(t, system, 1)
	assert.Equal(t, "s", system[0].KeyID)

	none, err := s.List(ctx, "globex")
	require.NoError(t, err)
	assert.Empty(t, none)

	var invalid *InvalidRecordKeyError
	_, err = s.List(ctx, "a/b")
	assert.ErrorAs(t, err, &invalid)
}

// TestStoreRefusesInvalidKeys proves segments that would escape the naming
// are refused on every operation.
func TestStoreRefusesInvalidKeys(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	var invalid *InvalidRecordKeyError

	_, _, err := s.Load(ctx, "a/b", "software", "k")
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "tenant", invalid.Field)
	assert.Contains(t, invalid.Error(), "tenant")

	_, _, err = s.Load(ctx, "acme", "", "k")
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "backend", invalid.Field)

	err = s.Put(ctx, "acme", &Record{KeyID: "..", Backend: "software"})
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "key ID", invalid.Field)

	assert.ErrorAs(t, s.Delete(ctx, "acme", "soft/ware", "k"), &invalid)
	assert.ErrorIs(t, s.Put(ctx, "acme", nil), ErrNilRecord)
}

// TestStoreWrapsStoreFailures proves a datastore failure is reported as a
// *StoreError naming the operation, never as an absent record.
func TestStoreWrapsStoreFailures(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("unavailable")
	broken := failingKV{KVStore: qrdbsdk.NewMemoryKVStore(), err: cause}
	s, err := NewStore(dao.NewStoreFactory(broken))
	require.NoError(t, err)

	var storeErr *StoreError
	_, _, err = s.Load(ctx, "acme", "software", "k")
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "get", storeErr.Op)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, storeErr.Error(), "get")

	err = s.Put(ctx, "acme", Implicit("k", "software"))
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "put", storeErr.Op)

	err = s.Delete(ctx, "acme", "software", "k")
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "delete", storeErr.Op)
}

// TestStoreLockSerializes proves Lock admits one holder per key at a time
// and does not block other keys.
func TestStoreLockSerializes(t *testing.T) {
	s, _ := newTestStore(t)
	unlock := s.Lock("acme", "software", "k")

	otherDone := make(chan struct{})
	go func() {
		s.Lock("acme", "software", "other")()
		close(otherDone)
	}()
	<-otherDone

	acquired := make(chan struct{})
	go func() {
		s.Lock("", "software", "k")()
		close(acquired)
	}()
	sameDone := make(chan struct{})
	go func() {
		s.Lock("acme", "software", "k")()
		close(sameDone)
	}()
	<-acquired
	select {
	case <-sameDone:
		t.Fatal("a second holder acquired a held lock")
	default:
	}
	unlock()
	<-sameDone
}
