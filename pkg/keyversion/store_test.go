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

package keyversion

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// failingStorage is a storage.Backend whose every operation fails, so the
// store's error wrapping can be observed.
type failingStorage struct {
	storage.Backend
	err error
}

func (f failingStorage) Get(context.Context, string) ([]byte, error) { return nil, f.err }
func (f failingStorage) Put(context.Context, string, []byte) error   { return f.err }
func (f failingStorage) Delete(context.Context, string) error        { return f.err }

func newTestStore(t *testing.T) (*Store, storage.Backend) {
	t.Helper()
	backend := storage.New()
	s, err := NewStore(backend)
	require.NoError(t, err)
	return s, backend
}

// TestNewStore proves a store needs a backend.
func TestNewStore(t *testing.T) {
	_, err := NewStore(nil)
	assert.ErrorIs(t, err, ErrNilStore)
}

// TestStoreRoundTrip proves a record is stored under the documented layout,
// read back intact, and deleted.
func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, backend := newTestStore(t)

	rec, found, err := s.Load(ctx, "acme", "software", "k")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, Implicit("k", "software"), rec)

	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	rec.AddCurrent(2, created, "alice")
	require.NoError(t, s.Put(ctx, "acme", rec))

	raw, err := backend.Get(ctx, "acme/key-versions/software/k")
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"current":2`)

	got, found, err := s.Load(ctx, "acme", "software", "k")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, uint32(2), got.Current)
	assert.Equal(t, "alice", got.Versions[1].CreatedBy)
	assert.True(t, created.Equal(got.Versions[1].CreatedAt))

	require.NoError(t, s.Delete(ctx, "acme", "software", "k"))
	require.NoError(t, s.Delete(ctx, "acme", "software", "k"), "deleting an absent record is not an error")
	_, found, err = s.Load(ctx, "acme", "software", "k")
	require.NoError(t, err)
	assert.False(t, found)
}

// TestStoreSystemTenant proves the empty tenant is stored under "system".
func TestStoreSystemTenant(t *testing.T) {
	ctx := context.Background()
	s, backend := newTestStore(t)
	rec := Implicit("k", "software")
	rec.AddCurrent(2, time.Now(), "")
	require.NoError(t, s.Put(ctx, "", rec))

	_, err := backend.Get(ctx, "system/key-versions/software/k")
	require.NoError(t, err)
	_, found, err := s.Load(ctx, SystemTenant, "software", "k")
	require.NoError(t, err)
	assert.True(t, found, "the empty tenant and \"system\" are one scope")
}

// TestStoreTenantIsolation proves one tenant's record is not another's.
func TestStoreTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	rec := Implicit("k", "software")
	rec.AddCurrent(2, time.Now(), "")
	require.NoError(t, s.Put(ctx, "acme", rec))

	got, found, err := s.Load(ctx, "globex", "software", "k")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, uint32(1), got.Current)
}

// TestStoreRefusesInvalidKeys proves segments that would escape the layout
// are refused on every operation.
func TestStoreRefusesInvalidKeys(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	var invalid *InvalidRecordKeyError

	_, _, err := s.Load(ctx, "a/b", "software", "k")
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "tenant", invalid.Field)

	_, _, err = s.Load(ctx, "acme", "", "k")
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "backend", invalid.Field)

	err = s.Put(ctx, "acme", &Record{KeyID: "..", Backend: "software"})
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "key ID", invalid.Field)

	assert.ErrorAs(t, s.Delete(ctx, "acme", "soft/ware", "k"), &invalid)
	assert.ErrorIs(t, s.Put(ctx, "acme", nil), ErrNilRecord)
}

// TestStoreWrapsBackendFailures proves a storage failure is reported as a
// *StoreError naming the operation, and a corrupt record as a decode error.
func TestStoreWrapsBackendFailures(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("unavailable")
	s, err := NewStore(failingStorage{err: cause})
	require.NoError(t, err)

	var storeErr *StoreError
	_, _, err = s.Load(ctx, "acme", "software", "k")
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "get", storeErr.Op)
	assert.ErrorIs(t, err, cause)

	err = s.Put(ctx, "acme", Implicit("k", "software"))
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "put", storeErr.Op)

	err = s.Delete(ctx, "acme", "software", "k")
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "delete", storeErr.Op)

	good, backend := newTestStore(t)
	require.NoError(t, backend.Put(ctx, "acme/key-versions/software/k", []byte("{not json")))
	_, _, err = good.Load(ctx, "acme", "software", "k")
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "decode", storeErr.Op)
}

// TestStoreLockSerializes proves Lock admits one holder per key at a time
// and does not block other keys.
func TestStoreLockSerializes(t *testing.T) {
	s, _ := newTestStore(t)
	unlock := s.Lock("acme", "software", "k")

	otherDone := make(chan struct{})
	go func() {
		defer close(otherDone)
		s.Lock("acme", "software", "other")()
	}()
	<-otherDone

	acquired := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		release := s.Lock("acme", "software", "k")
		close(acquired)
		release()
	}()
	select {
	case <-acquired:
		t.Fatal("a second holder acquired a held lock")
	default:
	}
	unlock()
	wg.Wait()
	<-acquired
}
