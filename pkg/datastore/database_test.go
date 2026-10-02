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
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// openTestBackend opens a standalone, memory-engine datastore for a test and
// registers its Close with t.Cleanup.
func openTestBackend(t *testing.T, cfg *config.Config) storage.Backend {
	t.Helper()
	backend, err := Open(context.Background(), cfg, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })
	return backend
}

// TestDatabaseKVStore_CreatesAndScopesDatabase proves the composition-root
// path a feature's DAO reaches its own go-qrdb database through: the named
// database does not exist at Open, DatabaseKVStore creates it, and the
// returned KVStore's writes are confined to it -- invisible to the
// datastore's own "default" database.
func TestDatabaseKVStore_CreatesAndScopesDatabase(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}
	backend := openTestBackend(t, cfg)

	kv, err := DatabaseKVStore(context.Background(), backend, cfg, "oidc")
	require.NoError(t, err)
	require.NotNil(t, kv)

	require.NoError(t, kv.Put(context.Background(), "k", []byte("v")))
	got, err := kv.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)

	// The default database's own view (the storage.Backend DatabaseKVStore
	// was given) never sees the scoped database's key.
	_, err = backend.Get(context.Background(), "k")
	assert.Error(t, err)
}

// TestDatabaseKVStore_Idempotent proves a second call for the same database
// name reuses it rather than failing on "already exists" -- the ensure
// semantics DatabaseKVStore promises every composition root.
func TestDatabaseKVStore_Idempotent(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}
	backend := openTestBackend(t, cfg)
	ctx := context.Background()

	first, err := DatabaseKVStore(ctx, backend, cfg, "oidc")
	require.NoError(t, err)
	require.NoError(t, first.Put(ctx, "k", []byte("v1")))

	second, err := DatabaseKVStore(ctx, backend, cfg, "oidc")
	require.NoError(t, err)

	got, err := second.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v1"), got, "the second call must see the first call's data: same database")
}

// TestDatabaseKVStore_BackendOverrideHonoured proves a
// Datastore.Databases entry's Backend is the one go-qrdb creates the named
// database with, not Datastore.Engine.
func TestDatabaseKVStore_BackendOverrideHonoured(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{
			Engine: "memory",
			Path:   t.TempDir(),
			Databases: []qrdbsdk.DaemonDatabaseConfig{
				{Name: "oidc", Backend: "file"},
			},
		},
	}
	backend := openTestBackend(t, cfg)
	cb, ok := backend.(ClientBackend)
	require.True(t, ok)

	kv, err := DatabaseKVStore(context.Background(), backend, cfg, "oidc")
	require.NoError(t, err)
	require.NotNil(t, kv)

	info, err := cb.Client().Database().GetDatabase(context.Background(), "oidc")
	require.NoError(t, err)
	assert.Equal(t, "file", info.Backend)
}

// TestDatabaseKVStore_DefaultEngineWhenNoOverride proves a database with no
// Datastore.Databases entry falls back to Datastore.Engine.
func TestDatabaseKVStore_DefaultEngineWhenNoOverride(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}
	backend := openTestBackend(t, cfg)
	cb, ok := backend.(ClientBackend)
	require.True(t, ok)

	_, err := DatabaseKVStore(context.Background(), backend, cfg, "oidc")
	require.NoError(t, err)

	info, err := cb.Client().Database().GetDatabase(context.Background(), "oidc")
	require.NoError(t, err)
	assert.Equal(t, "memory", info.Backend)
}

// TestDatabaseKVStore_ClientUnavailable proves a storage.Backend that does
// not implement ClientBackend (one built directly, bypassing Open) fails
// closed with a typed error rather than a nil-pointer panic.
func TestDatabaseKVStore_ClientUnavailable(t *testing.T) {
	cfg := &config.Config{Datastore: config.DatastoreConfig{Engine: "memory"}}
	backend := storage.NewMemory()
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	kv, err := DatabaseKVStore(context.Background(), backend, cfg, "oidc")
	require.Error(t, err)
	assert.Nil(t, kv)

	var clientErr *ErrClientUnavailable
	require.ErrorAs(t, err, &clientErr)
}

// TestResolveDatabaseBackend pins the override/default resolution table
// DatabaseKVStore relies on.
func TestResolveDatabaseBackend(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		db   string
		want string
	}{
		{
			name: "override honoured",
			cfg: &config.Config{Datastore: config.DatastoreConfig{
				Engine:    "pebble",
				Databases: []qrdbsdk.DaemonDatabaseConfig{{Name: "oidc", Backend: "file"}},
			}},
			db:   "oidc",
			want: "file",
		},
		{
			name: "no matching override falls back to engine",
			cfg: &config.Config{Datastore: config.DatastoreConfig{
				Engine:    "pebble",
				Databases: []qrdbsdk.DaemonDatabaseConfig{{Name: "other", Backend: "file"}},
			}},
			db:   "oidc",
			want: "pebble",
		},
		{
			name: "empty override falls back to engine",
			cfg: &config.Config{Datastore: config.DatastoreConfig{
				Engine:    "pebble",
				Databases: []qrdbsdk.DaemonDatabaseConfig{{Name: "oidc"}},
			}},
			db:   "oidc",
			want: "pebble",
		},
		{
			name: "empty engine defaults to pebble",
			cfg:  &config.Config{Datastore: config.DatastoreConfig{}},
			db:   "oidc",
			want: "pebble",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveDatabaseBackend(tc.cfg, tc.db))
		})
	}
}
