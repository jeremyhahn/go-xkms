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

package tokenstore

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

// seedLegacyToken writes a legacy prefix-keyed token blob.
func seedLegacyToken(t *testing.T, ctx context.Context, backend xkms.StorageBackend, key string, entry *TokenEntry) {
	t.Helper()

	data, err := json.Marshal(entry)
	require.NoError(t, err)
	require.NoError(t, backend.Put(ctx, key, data))
}

// TestMigrateFromBackend_MovesEntriesAndClearsLegacyKeys verifies the legacy
// prefix-keyed tokens land in the DAO store and the plaintext legacy keys are
// removed, which is the whole point of the migration.
func TestMigrateFromBackend_MovesEntriesAndClearsLegacyKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { _ = backend.Close() })

	seedLegacyToken(t, ctx, backend, "tokens/a", testEntry("https://a.example.com"))
	seedLegacyToken(t, ctx, backend, "tokens/b", testEntry("https://b.example.com"))

	daoStore := newTestDAOStore(t)

	errs := MigrateFromBackend(ctx, backend, daoStore, "tokens/")
	assert.Empty(t, errs)

	for _, server := range []string{"https://a.example.com", "https://b.example.com"} {
		entry, err := daoStore.Load(ctx, server)
		require.NoError(t, err, server)
		assert.Equal(t, server, entry.ServerURL)
		assert.Equal(t, TypeBearer, entry.TokenType)
	}

	remaining, err := backend.List(ctx, "tokens/")
	require.NoError(t, err)
	assert.Empty(t, remaining, "legacy keys must be deleted after migration")

	// Running again is a no-op rather than an error.
	assert.Empty(t, MigrateFromBackend(ctx, backend, daoStore, "tokens/"))
}

func TestMigrateFromBackend_NilArguments(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	assert.Nil(t, MigrateFromBackend(ctx, nil, newTestDAOStore(t), "tokens/"))
	assert.Nil(t, MigrateFromBackend(ctx, xkms.NewStorageMemory(), nil, "tokens/"))
}

// TestMigrateFromBackend_SkipsMalformedEntries verifies a corrupt legacy blob
// is reported but does not stop the remaining entries from migrating.
func TestMigrateFromBackend_SkipsMalformedEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { _ = backend.Close() })

	require.NoError(t, backend.Put(ctx, "tokens/corrupt", []byte("{not json")))
	seedLegacyToken(t, ctx, backend, "tokens/good", testEntry("https://good.example.com"))

	daoStore := newTestDAOStore(t)

	errs := MigrateFromBackend(ctx, backend, daoStore, "tokens/")
	require.Len(t, errs, 1)

	var migErr ErrMigration
	require.ErrorAs(t, errs[0], &migErr)
	assert.Equal(t, "tokens/corrupt", migErr.Key)

	_, err := daoStore.Load(ctx, "https://good.example.com")
	assert.NoError(t, err, "a corrupt neighbour must not block a valid entry")

	remaining, err := backend.List(ctx, "tokens/")
	require.NoError(t, err)
	assert.Equal(t, []string{"tokens/corrupt"}, remaining,
		"the corrupt key must be left in place for inspection")
}

func TestMigrateFromBackend_ListFailure(t *testing.T) {
	t.Parallel()

	backend := &stubBackend{listErr: errBackend}

	errs := MigrateFromBackend(context.Background(), backend, newTestDAOStore(t), "tokens/")
	require.Len(t, errs, 1)
	assert.ErrorIs(t, errs[0], errBackend)
}

func TestMigrateFromBackend_GetAndDeleteFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("get failure is reported per key", func(t *testing.T) {
		backend := &stubBackend{keys: []string{"tokens/a"}, getErr: errBackend}

		errs := MigrateFromBackend(ctx, backend, newTestDAOStore(t), "tokens/")
		require.Len(t, errs, 1)
		assert.ErrorIs(t, errs[0], errBackend)
	})

	t.Run("delete failure is reported after a successful save", func(t *testing.T) {
		data, err := json.Marshal(testEntry("https://a.example.com"))
		require.NoError(t, err)

		backend := &stubBackend{
			keys:      []string{"tokens/a"},
			values:    map[string][]byte{"tokens/a": data},
			deleteErr: errBackend,
		}

		daoStore := newTestDAOStore(t)
		errs := MigrateFromBackend(ctx, backend, daoStore, "tokens/")
		require.Len(t, errs, 1)
		assert.ErrorIs(t, errs[0], errBackend)

		// The entry must still have been persisted despite the cleanup failure.
		_, loadErr := daoStore.Load(ctx, "https://a.example.com")
		assert.NoError(t, loadErr)
	})
}

func TestTokenStoreTypedErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("kvstore unavailable")

	daoErr := ErrDAOCreation{Cause: cause}
	assert.Equal(t, "tokenstore: failed to create DAO: kvstore unavailable", daoErr.Error())
	assert.ErrorIs(t, daoErr, cause)

	migErr := ErrMigration{Key: "tokens/a", Cause: cause}
	assert.Equal(t, `tokenstore: migration failed for key "tokens/a": kvstore unavailable`, migErr.Error())
	assert.ErrorIs(t, migErr, cause)
	assert.NotErrorIs(t, migErr, ErrTokenNotFound)
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
