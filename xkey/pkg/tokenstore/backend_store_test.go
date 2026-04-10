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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEntry returns a fresh TokenEntry for use in tests.
func testEntry(serverURL string) *TokenEntry {
	return &TokenEntry{
		ServerURL: serverURL,
		TokenType: TypeBearer,
		Source:    SourceOIDC,
		Token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-payload.signature",
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		IssuedAt:  time.Now().UTC(),
		Issuer:    "https://auth.example.com",
		Subject:   "user-123",
	}
}

func TestBackendTokenStore_NewBackendTokenStore_NilBackend(t *testing.T) {
	store, err := NewBackendTokenStore(nil, "tokens/")
	require.ErrorIs(t, err, ErrNilBackend)
	assert.Nil(t, store)
}

func TestBackendTokenStore_NewBackendTokenStore_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	assert.Equal(t, "tokens/", store.prefix)
}

func TestBackendTokenStore_Save_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	entry := testEntry("https://api.example.com")
	err = store.Save(ctx, entry)
	require.NoError(t, err)

	// Verify the token was persisted by loading it back.
	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", loaded.ServerURL)
	assert.Equal(t, TypeBearer, loaded.TokenType)
	assert.Equal(t, SourceOIDC, loaded.Source)
	assert.Equal(t, entry.Token, loaded.Token)
	assert.Equal(t, "https://auth.example.com", loaded.Issuer)
	assert.Equal(t, "user-123", loaded.Subject)
}

func TestBackendTokenStore_Save_NilEntry(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	err = store.Save(context.Background(), nil)
	require.ErrorIs(t, err, ErrNilEntry)
}

func TestBackendTokenStore_Save_EmptyServer(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	entry := testEntry("")
	entry.ServerURL = ""
	err = store.Save(context.Background(), entry)
	require.ErrorIs(t, err, ErrInvalidServer)
}

func TestBackendTokenStore_Save_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	err = store.Save(context.Background(), testEntry("https://api.example.com"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestBackendTokenStore_Save_Overwrite(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Save initial entry.
	entry1 := testEntry("https://api.example.com")
	entry1.Token = "first-token"
	require.NoError(t, store.Save(ctx, entry1))

	// Overwrite with new token.
	entry2 := testEntry("https://api.example.com")
	entry2.Token = "second-token"
	require.NoError(t, store.Save(ctx, entry2))

	// Load should return the latest.
	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.Equal(t, "second-token", loaded.Token)
}

func TestBackendTokenStore_Load_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	entry := testEntry("https://api.example.com")
	require.NoError(t, store.Save(ctx, entry))

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, entry.Token, loaded.Token)
	assert.Equal(t, TypeBearer, loaded.TokenType)
	assert.Equal(t, SourceOIDC, loaded.Source)
}

func TestBackendTokenStore_Load_NotFound(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	loaded, err := store.Load(context.Background(), "https://unknown.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Load_EmptyServer(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	loaded, err := store.Load(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidServer)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Load_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	loaded, err := store.Load(context.Background(), "https://api.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Delete_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	require.NoError(t, store.Save(ctx, testEntry("https://api.example.com")))

	err = store.Delete(ctx, "https://api.example.com")
	require.NoError(t, err)

	// Verify the token is no longer loadable.
	loaded, err := store.Load(ctx, "https://api.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Delete_NotFound(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	err = store.Delete(context.Background(), "https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestBackendTokenStore_Delete_EmptyServer(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	err = store.Delete(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidServer)
}

func TestBackendTokenStore_Delete_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	err = store.Delete(context.Background(), "https://api.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestBackendTokenStore_List_Empty(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	entries, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBackendTokenStore_List_MultipleSorted(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

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

func TestBackendTokenStore_List_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	entries, err := store.List(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, entries)
}

func TestBackendTokenStore_Close_Idempotent(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestBackendTokenStore_Close_DoesNotCloseBackend(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	// The backend should remain usable after the store is closed, because
	// Close only marks the store as closed without closing the shared backend.
	err = backend.Put(context.Background(), "test-key", []byte("test-value"))
	require.NoError(t, err)

	val, err := backend.Get(context.Background(), "test-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("test-value"), val)
}

func TestBackendTokenStore_ServerNormalization(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	entry := testEntry("https://auth.example.com/")
	require.NoError(t, store.Save(ctx, entry))

	// Load without trailing slash should find the same token because
	// normalizeServer strips trailing slashes.
	loaded, err := store.Load(ctx, "https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, entry.Token, loaded.Token)

	// Load with uppercase should also work because normalizeServer
	// lowercases the server URL.
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

func TestBackendTokenStore_Concurrency(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	ctx := context.Background()

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

	// After all goroutines complete, the store should be in a consistent state.
	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, loaded.Token)
}

func TestBackendTokenStore_ImplementsInterface(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "tokens/")
	require.NoError(t, err)
	defer store.Close()

	var _ TokenStore = store
}
