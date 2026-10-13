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

//go:build frost

package frost

import (
	"context"
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// errInjected is the failure failingKV returns for an operation it has been
// told to fail.
var errInjected = errors.New("injected store failure")

// Operation classes failingKV can be told to fail.
const (
	failPut    = "put"
	failGet    = "get"
	failDelete = "delete"
	failScan   = "scan"
)

// failingKV is a real in-memory go-qrdb store that fails one class of
// operation on keys containing target, typically an entity type. Embedding
// *qrdbsdk.MemoryKVStore keeps every other method, including the atomic ones
// SaveIfAbsent needs, so the store still behaves as the production engine does.
type failingKV struct {
	*qrdbsdk.MemoryKVStore
	op     string
	target string
}

// newFailingDAOs returns a store that fails nothing until failOn is called,
// and a DAO factory over it.
func newFailingDAOs() (*failingKV, *qrdbsdk.DAOFactory) {
	kv := &failingKV{MemoryKVStore: qrdbsdk.NewMemoryKVStore()}
	return kv, dao.NewStoreFactory(kv)
}

// failOn makes every op-class operation on a key containing target fail.
func (f *failingKV) failOn(op, target string) {
	f.op = op
	f.target = target
}

func (f *failingKV) fails(op, key string) bool {
	return f.op == op && strings.Contains(key, f.target)
}

func (f *failingKV) Put(ctx context.Context, key string, value []byte) error {
	if f.fails(failPut, key) {
		return errInjected
	}
	return f.MemoryKVStore.Put(ctx, key, value)
}

func (f *failingKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.fails(failPut, key) {
		return false, errInjected
	}
	return f.MemoryKVStore.PutIfAbsent(ctx, key, value)
}

func (f *failingKV) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	if f.fails(failPut, key) {
		return false, errInjected
	}
	return f.MemoryKVStore.PutIfAllAbsent(ctx, key, value, fences...)
}

func (f *failingKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if f.fails(failPut, key) {
		return false, errInjected
	}
	return f.MemoryKVStore.CompareAndSwap(ctx, key, expected, next)
}

func (f *failingKV) Get(ctx context.Context, key string) ([]byte, error) {
	if f.fails(failGet, key) {
		return nil, errInjected
	}
	return f.MemoryKVStore.Get(ctx, key)
}

func (f *failingKV) Exists(ctx context.Context, key string) (bool, error) {
	if f.fails(failGet, key) {
		return false, errInjected
	}
	return f.MemoryKVStore.Exists(ctx, key)
}

func (f *failingKV) Delete(ctx context.Context, key string) error {
	if f.fails(failDelete, key) {
		return errInjected
	}
	return f.MemoryKVStore.Delete(ctx, key)
}

func (f *failingKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if f.fails(failDelete, key) {
		return false, errInjected
	}
	return f.MemoryKVStore.CompareAndDelete(ctx, key, expected)
}

func (f *failingKV) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.fails(failScan, prefix) {
		return errInjected
	}
	return f.MemoryKVStore.Scan(ctx, prefix, fn)
}

func (f *failingKV) List(ctx context.Context, prefix string) ([]string, error) {
	if f.fails(failScan, prefix) {
		return nil, errInjected
	}
	return f.MemoryKVStore.List(ctx, prefix)
}

func TestShareName(t *testing.T) {
	assert.Equal(t, "key-a/1", shareName("key-a", 1))
	assert.Equal(t, "key-a/12", shareName("key-a", 12))
	assert.NotEqual(t, shareName("key-a", 1), shareName("key-a1", 1),
		"different keys must never produce the same share name")
}

func TestNewDAO(t *testing.T) {
	d, err := newDAO(testutil.NewMemoryDAOFactory(), keyEntityType, newFrostKey)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, d.Save(ctx, &FrostKey{Name: "key-a", GroupPublicKey: []byte{1}}))
	loaded, err := d.GetByNaturalKey(ctx, "key-a")
	require.NoError(t, err)
	assert.Equal(t, []byte{1}, loaded.GroupPublicKey)
	assert.NotZero(t, loaded.ID, "the ID generator must derive an ID from the name")
}

func TestNewDAO_NilFactory(t *testing.T) {
	d, err := newDAO(nil, keyEntityType, newFrostKey)
	assert.Nil(t, d)
	assert.ErrorIs(t, err, ErrNilDAOFactory)
}

func TestNewDAO_NoFrostDatabase(t *testing.T) {
	// A factory with no partitioned provider cannot open the frost database.
	kv := qrdbsdk.NewMemoryKVStore()
	daos := qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
		KVStoreProvider: func(uint64) qrdbsdk.KVStore { return kv },
	})

	d, err := newDAO(daos, keyEntityType, newFrostKey)
	assert.Nil(t, d)
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "open", storeErr.Op)
	assert.Equal(t, keyEntityType, storeErr.Key)
	var unavailable *dao.DatabaseUnavailableError
	assert.ErrorAs(t, err, &unavailable)
}
