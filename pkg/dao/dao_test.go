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

package dao

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type note struct {
	ID   uint64 `json:"id"`
	Text string `json:"text"`
}

func (n *note) EntityID() uint64      { return n.ID }
func (n *note) SetEntityID(id uint64) { n.ID = id }

func newNote() *note { return &note{} }

// newFactory returns a factory whose default store is def and which serves
// the named databases in named.
func newFactory(def qrdbsdk.KVStore, named map[string]qrdbsdk.KVStore) *qrdbsdk.DAOFactory {
	return qrdbsdk.NewDAOFactoryWithConfig(&qrdbsdk.DAOFactoryConfig{
		KVStoreProvider: func(uint64) qrdbsdk.KVStore { return def },
		PartitionedProvider: func(name string, _ uint64) qrdbsdk.KVStore {
			return named[name]
		},
	})
}

// TestNew_DefaultDatabase proves an empty database name builds a DAO over
// the factory's default store that round-trips an entity.
func TestNew_DefaultDatabase(t *testing.T) {
	ctx := t.Context()
	factory := newFactory(qrdbsdk.NewMemoryKVStore(), nil)

	notes, err := New(factory, "", "notes", newNote)
	require.NoError(t, err)

	saved := &note{Text: "hello"}
	require.NoError(t, notes.Save(ctx, saved))
	got, err := notes.Get(ctx, saved.ID)
	require.NoError(t, err)
	assert.Equal(t, "hello", got.Text)
}

// TestNew_NamedDatabase proves a named database's DAO writes only to that
// database's store, never the default one.
func TestNew_NamedDatabase(t *testing.T) {
	ctx := t.Context()
	def := qrdbsdk.NewMemoryKVStore()
	factory := newFactory(def, map[string]qrdbsdk.KVStore{"oidc": qrdbsdk.NewMemoryKVStore()})

	scoped, err := New(factory, "oidc", "notes", newNote)
	require.NoError(t, err)
	require.NoError(t, scoped.Save(ctx, &note{Text: "scoped"}))

	count, err := scoped.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	unscoped, err := New(factory, "", "notes", newNote)
	require.NoError(t, err)
	count, err = unscoped.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count, "the default database must not see the named database's entities")
}

func TestNew_RejectsNilFactory(t *testing.T) {
	d, err := New[*note](nil, "", "notes", newNote)
	assert.Nil(t, d)
	assert.ErrorIs(t, err, ErrNilFactory)
}

// TestNew_DatabaseUnavailable proves a named database the factory does not
// serve is refused -- whether the partitioned provider has no store for it,
// or there is no partitioned provider to fall back from.
func TestNew_DatabaseUnavailable(t *testing.T) {
	factories := map[string]*qrdbsdk.DAOFactory{
		"database not open": newFactory(qrdbsdk.NewMemoryKVStore(), nil),
		"no partitioned provider": qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore {
			return qrdbsdk.NewMemoryKVStore()
		}),
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			d, err := New(factory, "oidc", "notes", newNote)
			assert.Nil(t, d)
			var unavailable *DatabaseUnavailableError
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, "oidc", unavailable.Database)
		})
	}
}

// TestNew_WrapsNewDAOError proves go-qrdb's refusal (here, an empty entity
// type) surfaces as a typed NewDAOError with the cause reachable.
func TestNew_WrapsNewDAOError(t *testing.T) {
	factory := newFactory(qrdbsdk.NewMemoryKVStore(), nil)

	d, err := New(factory, "", "", newNote)
	assert.Nil(t, d)
	var daoErr *NewDAOError
	require.ErrorAs(t, err, &daoErr)
	assert.NotNil(t, daoErr.Unwrap())
	assert.Contains(t, err.Error(), "dao:")
}

// TestNewStoreFactory_ServesEveryDatabaseFromTheStore proves the default
// database and a named one are both served by the one store, so a feature's
// named database works on a host with no go-qrdb node.
func TestNewStoreFactory_ServesEveryDatabaseFromTheStore(t *testing.T) {
	ctx := t.Context()
	store := qrdbsdk.NewMemoryKVStore()
	factory := NewStoreFactory(store)

	named, err := New(factory, "oidc", "notes", newNote)
	require.NoError(t, err)
	saved := &note{Text: "named"}
	require.NoError(t, named.Save(ctx, saved))

	direct, err := qrdbsdk.NewDAO(store, "notes", newNote)
	require.NoError(t, err)
	got, err := direct.Get(ctx, saved.ID)
	require.NoError(t, err)
	assert.Equal(t, "named", got.Text)

	def, err := New(factory, "", "notes", newNote)
	require.NoError(t, err)
	count, err := def.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestNewStoreFactory_NilStoreServesNoDatabase proves a factory over no
// store builds no DAO, for the default database or a named one.
func TestNewStoreFactory_NilStoreServesNoDatabase(t *testing.T) {
	factory := NewStoreFactory(nil)
	for _, database := range []string{"", "oidc"} {
		d, err := New(factory, database, "notes", newNote)
		assert.Nil(t, d)
		var unavailable *DatabaseUnavailableError
		require.ErrorAs(t, err, &unavailable)
	}
}
