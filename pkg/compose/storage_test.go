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

package compose

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// TestFactoryStorage_PrefixedViewsOverTheFactory proves each feature's
// storage is a prefix+name+"/" view over the factory's default store: the
// write lands under the prefixed key, and features cannot see each other.
func TestFactoryStorage_PrefixedViewsOverTheFactory(t *testing.T) {
	ctx := t.Context()
	store := qrdbsdk.NewMemoryKVStore()
	open, err := FactoryStorage(qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return store }), "xkms/")
	require.NoError(t, err)

	serials, err := open(StorageCASerials)
	require.NoError(t, err)
	require.NoError(t, serials.Put(ctx, "k", []byte("v")))

	raw, err := store.Get(ctx, "xkms/ca-serials/k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), raw)

	platform, err := open(StoragePlatformStore)
	require.NoError(t, err)
	exists, err := platform.Exists(ctx, "k")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestFactoryStorage_Refusals proves a missing factory, or a factory that
// serves no default store, is refused with a typed error.
func TestFactoryStorage_Refusals(t *testing.T) {
	open, err := FactoryStorage(nil, "xkms/")
	assert.Nil(t, open)
	assert.ErrorIs(t, err, ErrNilDAOFactory)

	backend, err := FactoryBackend(qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{}))
	assert.True(t, backend == nil, "a refusal must return a nil interface, not a typed nil")
	assert.ErrorIs(t, err, qrdbstorage.ErrNilKVStore)
}
