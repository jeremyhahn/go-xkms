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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAOStore creates a DAOStore backed by in-memory storage for testing.
func newTestDAOStore(t *testing.T) *DAOStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

func TestDAOStore_NewDAOStore_NilKVStore(t *testing.T) {
	store, err := NewDAOStore(nil)
	require.ErrorIs(t, err, ErrNilBackend)
	assert.Nil(t, store)
}

func TestDAOStore_SaveLoad(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := testEntry("https://api.example.com")
	require.NoError(t, store.Save(ctx, entry))

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "https://api.example.com", loaded.ServerURL)
	assert.Equal(t, TypeBearer, loaded.TokenType)
	assert.Equal(t, SourceOIDC, loaded.Source)
	assert.Equal(t, entry.Token, loaded.Token)
	assert.Equal(t, "https://auth.example.com", loaded.Issuer)
	assert.Equal(t, "user-123", loaded.Subject)
}

func TestDAOStore_Save_NilEntry(t *testing.T) {
	store := newTestDAOStore(t)
	err := store.Save(context.Background(), nil)
	require.ErrorIs(t, err, ErrNilEntry)
}

func TestDAOStore_Save_EmptyServer(t *testing.T) {
	store := newTestDAOStore(t)
	entry := testEntry("")
	entry.ServerURL = ""
	err := store.Save(context.Background(), entry)
	require.ErrorIs(t, err, ErrInvalidServer)
}

func TestDAOStore_Save_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Save(context.Background(), testEntry("https://api.example.com"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_Delete(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	require.NoError(t, store.Save(ctx, testEntry("https://api.example.com")))

	err := store.Delete(ctx, "https://api.example.com")
	require.NoError(t, err)

	// Verify the token is gone.
	loaded, err := store.Load(ctx, "https://api.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestDAOStore(t)
	err := store.Delete(context.Background(), "https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestDAOStore_Delete_EmptyServer(t *testing.T) {
	store := newTestDAOStore(t)
	err := store.Delete(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidServer)
}

func TestDAOStore_Delete_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Delete(context.Background(), "https://api.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_List(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry1 := testEntry("https://z-server.example.com")
	entry1.Source = SourceFIDO2
	require.NoError(t, store.Save(ctx, entry1))

	entry2 := testEntry("https://a-server.example.com")
	entry2.Source = SourceBootstrap
	require.NoError(t, store.Save(ctx, entry2))

	entry3 := testEntry("https://m-server.example.com")
	entry3.Source = SourceOIDC
	require.NoError(t, store.Save(ctx, entry3))

	entries, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Entries should be sorted by ServerURL.
	assert.Equal(t, "https://a-server.example.com", entries[0].ServerURL)
	assert.Equal(t, "https://m-server.example.com", entries[1].ServerURL)
	assert.Equal(t, "https://z-server.example.com", entries[2].ServerURL)
}

func TestDAOStore_List_Empty(t *testing.T) {
	store := newTestDAOStore(t)

	entries, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestDAOStore_List_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	entries, err := store.List(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, entries)
}

func TestDAOStore_Page(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	// Save 5 entries.
	for i := 0; i < 5; i++ {
		entry := testEntry(fmt.Sprintf("https://server-%02d.example.com", i))
		entry.Token = fmt.Sprintf("token-%d", i)
		require.NoError(t, store.Save(ctx, entry))
	}

	// Page with size 2.
	result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 2, result.PageSize)

	// Page 2.
	result2, err := store.Page(ctx, dao.PageQuery{Page: 2, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result2.Entities, 2)
	assert.True(t, result2.HasMore)

	// Page 3 (last page with 1 entry).
	result3, err := store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestDAOStore_Page_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_DuplicateURL(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	// Save initial entry.
	entry1 := testEntry("https://api.example.com")
	entry1.Token = "first-token"
	require.NoError(t, store.Save(ctx, entry1))

	// Save again with the same URL (should overwrite).
	entry2 := testEntry("https://api.example.com")
	entry2.Token = "second-token"
	require.NoError(t, store.Save(ctx, entry2))

	// Load should return the latest.
	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.Equal(t, "second-token", loaded.Token)

	// List should show only one entry.
	entries, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestDAOStore_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	loaded, err := store.Load(context.Background(), "https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestDAOStore_Load_EmptyServer(t *testing.T) {
	store := newTestDAOStore(t)

	loaded, err := store.Load(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidServer)
	assert.Nil(t, loaded)
}

func TestDAOStore_Load_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	loaded, err := store.Load(context.Background(), "https://api.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, loaded)
}

func TestDAOStore_ServerNormalization(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	entry := testEntry("https://auth.example.com/")
	require.NoError(t, store.Save(ctx, entry))

	// Load without trailing slash.
	loaded, err := store.Load(ctx, "https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, entry.Token, loaded.Token)

	// Load with uppercase.
	loaded, err = store.Load(ctx, "HTTPS://AUTH.EXAMPLE.COM/")
	require.NoError(t, err)
	assert.Equal(t, entry.Token, loaded.Token)

	// Delete with mixed case and trailing slash.
	err = store.Delete(ctx, "Https://Auth.Example.Com/")
	require.NoError(t, err)

	// Verify it is gone.
	_, err = store.Load(ctx, "https://auth.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestDAOStore_Close_Idempotent(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestDAOStore_Concurrency(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent saves.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = store.Save(ctx, testEntry("https://api.example.com"))
		}()
	}

	// Concurrent loads.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.Load(ctx, "https://api.example.com")
		}()
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List(ctx)
		}()
	}

	wg.Wait()

	// After all goroutines complete, the store should be consistent.
	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, loaded.Token)
}

func TestDAOStore_ImplementsInterface(t *testing.T) {
	store := newTestDAOStore(t)
	var _ TokenStore = store
}

func TestDAOStore_TimestampPreservation(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	entry := &TokenEntry{
		ServerURL: "https://api.example.com",
		TokenType: TypeBearer,
		Source:    SourceOIDC,
		Token:     "test-token",
		ExpiresAt: now.Add(1 * time.Hour),
		IssuedAt:  now,
		Issuer:    "https://auth.example.com",
		Subject:   "user-456",
	}
	require.NoError(t, store.Save(ctx, entry))

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)

	// Timestamps should be preserved through serialization.
	assert.WithinDuration(t, entry.ExpiresAt, loaded.ExpiresAt, time.Second)
	assert.WithinDuration(t, entry.IssuedAt, loaded.IssuedAt, time.Second)
}
