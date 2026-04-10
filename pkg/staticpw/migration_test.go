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

package staticpw

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- MigrateEntry ---

func TestMigrateEntry_PopulatesTitle(t *testing.T) {
	pw := &StaticPassword{Name: "gmail", Password: "pass"}
	assert.True(t, MigrateEntry(pw))
	assert.Equal(t, "gmail", pw.Title)
}

func TestMigrateEntry_NoOpIfTitleSet(t *testing.T) {
	pw := &StaticPassword{Name: "gmail", Title: "My Gmail", Password: "pass"}
	assert.False(t, MigrateEntry(pw))
	assert.Equal(t, "My Gmail", pw.Title)
}

// --- MigrateStore ---

func TestMigrateStore_MigratesEntries(t *testing.T) {
	store := newTestStore()
	defer func() { _ = store.Close() }()

	require.NoError(t, store.Add(&StaticPassword{Name: "a", Password: "p"}))
	require.NoError(t, store.Add(&StaticPassword{Name: "b", Password: "p", Title: "Already Set"}))

	count, err := MigrateStore(store)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	pw, err := store.Get("a")
	require.NoError(t, err)
	assert.Equal(t, "a", pw.Title)
}

func TestMigrateStore_EmptyStore(t *testing.T) {
	store := newTestStore()
	defer func() { _ = store.Close() }()

	count, err := MigrateStore(store)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// --- MigrateToScopedLayout ---

func TestMigrateToScopedLayout_MigratesLegacyEntries(t *testing.T) {
	backend := storage.New()

	// Simulate legacy entries at {tenantID}/staticpw/{id}.json.
	legacyStore, err := NewTenantStore(backend, "acme")
	require.NoError(t, err)

	require.NoError(t, legacyStore.Add(&StaticPassword{Name: "pw1", Password: "p1"}))
	require.NoError(t, legacyStore.Add(&StaticPassword{Name: "pw2", Password: "p2"}))

	// Run migration (do not close the store — it shares the backend).
	count, err := MigrateToScopedLayout(backend, "acme")
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Verify entries are now under the shared prefix.
	sharedStore, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)

	pws, err := sharedStore.List()
	require.NoError(t, err)
	assert.Len(t, pws, 2)

	// Verify entries have Shared=true.
	for _, pw := range pws {
		assert.True(t, pw.Shared)
	}

	// Verify legacy entries are gone.
	legacyKeys, err := backend.List(context.Background(), "acme/staticpw/")
	require.NoError(t, err)
	for _, key := range legacyKeys {
		assert.Contains(t, key, "/shared/", "all keys should be under shared/")
	}
}

func TestMigrateToScopedLayout_SkipsAlreadyMigrated(t *testing.T) {
	backend := storage.New()

	// Create an entry already in the shared prefix.
	sharedStore, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	require.NoError(t, sharedStore.Add(&StaticPassword{Name: "already-shared", Password: "p", Shared: true}))

	// Create an entry in the personal prefix.
	personalStore, err := NewPersonalTenantStore(backend, "acme", "alice")
	require.NoError(t, err)
	require.NoError(t, personalStore.Add(&StaticPassword{Name: "already-personal", Password: "p"}))

	// Run migration — should skip both.
	count, err := MigrateToScopedLayout(backend, "acme")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestMigrateToScopedLayout_MixedEntries(t *testing.T) {
	backend := storage.New()

	// Legacy entry.
	legacyStore, err := NewTenantStore(backend, "acme")
	require.NoError(t, err)
	require.NoError(t, legacyStore.Add(&StaticPassword{Name: "legacy-pw", Password: "p"}))

	// Already-shared entry.
	sharedStore, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	require.NoError(t, sharedStore.Add(&StaticPassword{Name: "new-pw", Password: "p", Shared: true}))

	// Run migration — only the legacy entry should be migrated.
	count, err := MigrateToScopedLayout(backend, "acme")
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify both entries are now accessible from the shared store.
	sharedStore2, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)

	pws, err := sharedStore2.List()
	require.NoError(t, err)
	assert.Len(t, pws, 2)
}

func TestMigrateToScopedLayout_InvalidTenantID(t *testing.T) {
	backend := storage.New()

	_, err := MigrateToScopedLayout(backend, "")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestMigrateToScopedLayout_NoEntries(t *testing.T) {
	backend := storage.New()

	count, err := MigrateToScopedLayout(backend, "empty-tenant")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestMigrateToScopedLayout_Idempotent(t *testing.T) {
	backend := storage.New()

	legacyStore, err := NewTenantStore(backend, "acme")
	require.NoError(t, err)
	require.NoError(t, legacyStore.Add(&StaticPassword{Name: "pw1", Password: "p"}))

	// First migration.
	count1, err := MigrateToScopedLayout(backend, "acme")
	require.NoError(t, err)
	assert.Equal(t, 1, count1)

	// Second migration — should be a no-op.
	count2, err := MigrateToScopedLayout(backend, "acme")
	require.NoError(t, err)
	assert.Equal(t, 0, count2)
}

// --- Targeted coverage tests ---

func TestMigrateToScopedLayout_SkipsCorruptedEntries(t *testing.T) {
	backend := storage.New()

	// Add a valid legacy entry.
	legacyStore, err := NewTenantStore(backend, "acme")
	require.NoError(t, err)
	require.NoError(t, legacyStore.Add(&StaticPassword{Name: "valid", Password: "p"}))

	// Inject a corrupted entry at the legacy prefix.
	require.NoError(t, backend.Put(context.Background(), "acme/staticpw/corrupt.json", []byte("not-json")))

	// Migration should skip the corrupted entry and migrate the valid one.
	count, err := MigrateToScopedLayout(backend, "acme")
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify the valid entry was migrated to the shared prefix.
	sharedStore, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	pws, err := sharedStore.List()
	require.NoError(t, err)
	assert.Len(t, pws, 1)
	assert.Equal(t, "valid", pws[0].Name)
	assert.True(t, pws[0].Shared)
}
