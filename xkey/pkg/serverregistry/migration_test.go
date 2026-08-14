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

package serverregistry

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errBackend is the failure injected into the legacy backend stub.
var errBackend = errors.New("legacy backend unavailable")

// seedLegacyServer writes a legacy prefix-keyed server blob.
func seedLegacyServer(t *testing.T, ctx context.Context, backend xkms.StorageBackend, key string, entry *ServerEntry) {
	t.Helper()

	data, err := json.Marshal(entry)
	require.NoError(t, err)
	require.NoError(t, backend.Put(ctx, key, data))
}

// TestMigrateToDAO_MovesEntriesAndClearsLegacyKeys verifies legacy registry
// entries land in the DAO store and the old keys are cleaned up.
func TestMigrateToDAO_MovesEntriesAndClearsLegacyKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { _ = backend.Close() })

	seedLegacyServer(t, ctx, backend, "servers/a.json",
		newTestServerEntry("https://a.example.com", "A", "grpc"))
	seedLegacyServer(t, ctx, backend, "servers/b.json",
		newTestServerEntry("https://b.example.com", "B", "grpc"))

	store := newTestDAOStore(t)

	migrated, err := MigrateToDAO(ctx, backend, "servers/", store)
	require.NoError(t, err)
	assert.Equal(t, 2, migrated)

	for _, url := range []string{"https://a.example.com", "https://b.example.com"} {
		entry, lookupErr := store.Lookup(ctx, url)
		require.NoError(t, lookupErr, url)
		assert.Equal(t, url, entry.URL)
	}

	remaining, err := backend.List(ctx, "servers/")
	require.NoError(t, err)
	assert.Empty(t, remaining, "legacy keys must be removed after migration")
}

// TestMigrateToDAO_IsIdempotent verifies re-running the migration over an
// entry that already exists in the DAO store does not fail and still clears
// the legacy key.
func TestMigrateToDAO_IsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { _ = backend.Close() })

	entry := newTestServerEntry("https://a.example.com", "A", "grpc")
	seedLegacyServer(t, ctx, backend, "servers/a.json", entry)

	store := newTestDAOStore(t)
	require.NoError(t, store.Register(ctx, newTestServerEntry("https://a.example.com", "A", "grpc")))

	migrated, err := MigrateToDAO(ctx, backend, "servers/", store)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated, "an already-registered server is not counted again")

	remaining, err := backend.List(ctx, "servers/")
	require.NoError(t, err)
	assert.Empty(t, remaining, "the legacy key must still be cleaned up")
}

// TestMigrateToDAO_SkipsUnusableEntries verifies malformed and invalid blobs
// are skipped without aborting the migration of healthy neighbours.
func TestMigrateToDAO_SkipsUnusableEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { _ = backend.Close() })

	require.NoError(t, backend.Put(ctx, "servers/corrupt.json", []byte("{not json")))
	// A structurally valid blob that fails entry validation (no URL).
	seedLegacyServer(t, ctx, backend, "servers/invalid.json", &ServerEntry{Name: "no url"})
	seedLegacyServer(t, ctx, backend, "servers/good.json",
		newTestServerEntry("https://good.example.com", "Good", "grpc"))

	store := newTestDAOStore(t)

	migrated, err := MigrateToDAO(ctx, backend, "servers/", store)
	require.NoError(t, err)
	assert.Equal(t, 1, migrated)

	_, lookupErr := store.Lookup(ctx, "https://good.example.com")
	assert.NoError(t, lookupErr)

	remaining, err := backend.List(ctx, "servers/")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"servers/corrupt.json", "servers/invalid.json"}, remaining,
		"unusable legacy keys must be left for inspection")
}

func TestMigrateToDAO_NilArguments(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	migrated, err := MigrateToDAO(ctx, nil, "servers/", newTestDAOStore(t))
	assert.Zero(t, migrated)
	assert.ErrorIs(t, err, ErrNilBackend)

	migrated, err = MigrateToDAO(ctx, xkms.NewStorageMemory(), "servers/", nil)
	assert.Zero(t, migrated)
	assert.ErrorIs(t, err, ErrNilKVStore)
}

func TestMigrateToDAO_BackendFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("list failure aborts", func(t *testing.T) {
		migrated, err := MigrateToDAO(ctx, &stubBackend{listErr: errBackend}, "servers/", newTestDAOStore(t))
		assert.Zero(t, migrated)
		assert.ErrorIs(t, err, errBackend)
	})

	t.Run("get failure aborts", func(t *testing.T) {
		backend := &stubBackend{keys: []string{"servers/a.json"}, getErr: errBackend}
		migrated, err := MigrateToDAO(ctx, backend, "servers/", newTestDAOStore(t))
		assert.Zero(t, migrated)
		assert.ErrorIs(t, err, errBackend)
	})

	t.Run("vanished key is skipped", func(t *testing.T) {
		backend := &stubBackend{keys: []string{"servers/a.json"}, getErr: xkms.ErrStorageNotFound}
		migrated, err := MigrateToDAO(ctx, backend, "servers/", newTestDAOStore(t))
		assert.Zero(t, migrated)
		assert.NoError(t, err, "an entry deleted between List and Get must not fail the migration")
	})

	t.Run("delete failure still counts the migration", func(t *testing.T) {
		data, err := json.Marshal(newTestServerEntry("https://a.example.com", "A", "grpc"))
		require.NoError(t, err)

		backend := &stubBackend{
			keys:      []string{"servers/a.json"},
			values:    map[string][]byte{"servers/a.json": data},
			deleteErr: errBackend,
		}

		store := newTestDAOStore(t)
		migrated, err := MigrateToDAO(ctx, backend, "servers/", store)
		require.NoError(t, err)
		assert.Equal(t, 1, migrated, "the entry is durable even though cleanup failed")

		_, lookupErr := store.Lookup(ctx, "https://a.example.com")
		assert.NoError(t, lookupErr)
	})
}

func TestServerRegistryTypedErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("kvstore unavailable")

	daoErr := ErrDAOCreation{Cause: cause}
	assert.Equal(t, "serverregistry: failed to create DAO: kvstore unavailable", daoErr.Error())
	assert.ErrorIs(t, daoErr, cause)

	migErr := ErrMigration{Cause: cause}
	assert.Equal(t, "serverregistry: migration failed: kvstore unavailable", migErr.Error())
	assert.ErrorIs(t, migErr, cause)
	assert.NotErrorIs(t, migErr, ErrServerNotFound)
}

// stubBackend is a StorageBackend whose List/Get/Delete behaviour is scripted.
type stubBackend struct {
	xkms.StorageBackend

	keys      []string
	values    map[string][]byte
	listErr   error
	getErr    error
	deleteErr error
}

func (b *stubBackend) List(_ context.Context, _ string) ([]string, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	return b.keys, nil
}

func (b *stubBackend) Get(_ context.Context, key string) ([]byte, error) {
	if b.getErr != nil {
		return nil, b.getErr
	}
	return b.values[key], nil
}

func (b *stubBackend) Delete(_ context.Context, _ string) error {
	return b.deleteErr
}
