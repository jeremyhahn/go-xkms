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

package datastore

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// TestDatabaseKVStore_CreatesAndScopesDatabase proves the named database
// does not exist at Open, DatabaseKVStore creates it, and the returned
// KVStore's writes are confined to it -- invisible to the default database.
func TestDatabaseKVStore_CreatesAndScopesDatabase(t *testing.T) {
	ctx := t.Context()
	ds := openTestDatastore(t, memoryConfig(t))

	kv, err := ds.DatabaseKVStore(ctx, "oidc")
	require.NoError(t, err)
	require.NoError(t, kv.Put(ctx, "k", []byte("v")))
	got, err := kv.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)

	exists, err := ds.Client().KVStore().Exists(ctx, "k")
	require.NoError(t, err)
	assert.False(t, exists, "the default database must not see the named database's key")
}

// TestDatabaseKVStore_TransportWithoutDatabasePlane proves a client whose
// transport cannot scope to a database -- one serving KV alone -- is refused
// with *ErrDatabaseScope rather than reaching for the database plane it lacks.
func TestDatabaseKVStore_TransportWithoutDatabasePlane(t *testing.T) {
	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)
	ds, err := New(client, config.DatastoreConfig{})
	require.NoError(t, err)

	kv, err := ds.DatabaseKVStore(t.Context(), "oidc")
	assert.Nil(t, kv)
	var scopeErr *ErrDatabaseScope
	require.ErrorAs(t, err, &scopeErr)
	assert.Equal(t, "oidc", scopeErr.Name)
	var unsupported *qrdbtransport.DatabaseScopeUnsupportedError
	assert.ErrorAs(t, err, &unsupported)
}

// TestDatabaseKVStore_Idempotent proves a second call for the same name
// returns the same store rather than failing on "already exists".
func TestDatabaseKVStore_Idempotent(t *testing.T) {
	ctx := t.Context()
	ds := openTestDatastore(t, memoryConfig(t))

	first, err := ds.DatabaseKVStore(ctx, "oidc")
	require.NoError(t, err)
	second, err := ds.DatabaseKVStore(ctx, "oidc")
	require.NoError(t, err)
	assert.Same(t, first, second)
}

// TestDatabaseKVStore_DAOFactoryServesOpenedDatabase proves the factory
// serves a named database only once it is opened, and that a DAO built for
// it writes there and not to the default database.
func TestDatabaseKVStore_DAOFactoryServesOpenedDatabase(t *testing.T) {
	ctx := t.Context()
	ds := openTestDatastore(t, memoryConfig(t))

	_, err := dao.New(ds.DAOFactory(), "oidc", "notes", newNote)
	var unavailable *dao.DatabaseUnavailableError
	require.ErrorAs(t, err, &unavailable, "an unopened database must not fall back to the default one")

	_, err = ds.DatabaseKVStore(ctx, "oidc")
	require.NoError(t, err)
	id := saveNote(t, ds, "oidc", "notes", "scoped")
	assert.Equal(t, "scoped", loadNote(t, ds, "oidc", "notes", id))

	unscoped, err := dao.New(ds.DAOFactory(), "", "notes", newNote)
	require.NoError(t, err)
	count, err := unscoped.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count)
}

// TestDatabaseKVStore_BackendOverrideHonoured proves a Datastore.Databases
// entry's Backend is the one go-qrdb creates the database with, and that a
// database with no entry falls back to Datastore.Engine.
func TestDatabaseKVStore_BackendOverrideHonoured(t *testing.T) {
	ctx := t.Context()
	cfg := memoryConfig(t)
	cfg.Datastore.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "oidc", Backend: "file"}}
	ds := openTestDatastore(t, cfg)

	for name, want := range map[string]string{"oidc": "file", "audit": "memory"} {
		_, err := ds.DatabaseKVStore(ctx, name)
		require.NoError(t, err)
		info, err := ds.Client().Database().GetDatabase(ctx, name)
		require.NoError(t, err)
		assert.Equal(t, want, info.Backend, name)
	}
}

// TestDatabaseKVStore_Refusals proves an empty name and a database go-qrdb
// cannot create both fail with typed errors, and neither is served after.
func TestDatabaseKVStore_Refusals(t *testing.T) {
	ctx := t.Context()
	cfg := memoryConfig(t)
	cfg.Datastore.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "bad", Backend: "carrier-pigeon"}}
	ds := openTestDatastore(t, cfg)

	kv, err := ds.DatabaseKVStore(ctx, "")
	assert.Nil(t, kv)
	assert.ErrorIs(t, err, ErrDatabaseNameRequired)

	kv, err = ds.DatabaseKVStore(ctx, "bad")
	assert.Nil(t, kv)
	var ensureErr *ErrEnsureDatabase
	require.ErrorAs(t, err, &ensureErr)
	assert.Equal(t, "bad", ensureErr.Name)
	assert.Nil(t, ds.databaseStore("bad", 0))
}

// TestResolveDatabaseBackend pins the override/default resolution table.
func TestResolveDatabaseBackend(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.DatastoreConfig
		want string
	}{
		{
			name: "override honoured",
			cfg: config.DatastoreConfig{
				Engine:    "pebble",
				Databases: []qrdbsdk.DaemonDatabaseConfig{{Name: "oidc", Backend: "File"}},
			},
			want: "file",
		},
		{
			name: "no matching override falls back to engine",
			cfg: config.DatastoreConfig{
				Engine:    "memory",
				Databases: []qrdbsdk.DaemonDatabaseConfig{{Name: "other", Backend: "file"}},
			},
			want: "memory",
		},
		{
			name: "empty override falls back to engine",
			cfg: config.DatastoreConfig{
				Engine:    "pebble",
				Databases: []qrdbsdk.DaemonDatabaseConfig{{Name: "oidc"}},
			},
			want: "pebble",
		},
		{
			name: "empty engine defaults to pebble",
			want: "pebble",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveDatabaseBackend(tc.cfg, "oidc"))
		})
	}
}
