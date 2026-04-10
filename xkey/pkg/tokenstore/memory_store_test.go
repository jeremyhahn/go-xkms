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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryTokenStore_Save_Success(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()
	entry := testEntry("https://api.example.com")
	err := store.Save(ctx, entry)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", loaded.ServerURL)
	assert.Equal(t, TypeBearer, loaded.TokenType)
	assert.Equal(t, SourceOIDC, loaded.Source)
	assert.Equal(t, entry.Token, loaded.Token)
}

func TestMemoryTokenStore_Save_NilEntry(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	err := store.Save(context.Background(), nil)
	require.ErrorIs(t, err, ErrNilEntry)
}

func TestMemoryTokenStore_Save_EmptyServer(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	entry := &TokenEntry{
		Token: "test-jwt",
	}
	err := store.Save(context.Background(), entry)
	require.ErrorIs(t, err, ErrInvalidServer)
}

func TestMemoryTokenStore_Save_Closed(t *testing.T) {
	store := NewMemoryTokenStore()
	require.NoError(t, store.Close())

	err := store.Save(context.Background(), testEntry("https://api.example.com"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestMemoryTokenStore_Save_Overwrite(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()

	entry1 := testEntry("https://api.example.com")
	entry1.Token = "first-token"
	require.NoError(t, store.Save(ctx, entry1))

	entry2 := testEntry("https://api.example.com")
	entry2.Token = "second-token"
	require.NoError(t, store.Save(ctx, entry2))

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.Equal(t, "second-token", loaded.Token)
}

func TestMemoryTokenStore_Save_DeepCopy(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()
	entry := testEntry("https://api.example.com")
	require.NoError(t, store.Save(ctx, entry))

	// Mutating the original entry should not affect the stored one.
	entry.Token = "mutated-token"

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.NotEqual(t, "mutated-token", loaded.Token)
}

func TestMemoryTokenStore_Load_Success(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()
	entry := testEntry("https://api.example.com")
	require.NoError(t, store.Save(ctx, entry))

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, entry.Token, loaded.Token)
}

func TestMemoryTokenStore_Load_NotFound(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	loaded, err := store.Load(context.Background(), "https://unknown.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestMemoryTokenStore_Load_EmptyServer(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	loaded, err := store.Load(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidServer)
	assert.Nil(t, loaded)
}

func TestMemoryTokenStore_Load_Closed(t *testing.T) {
	store := NewMemoryTokenStore()
	require.NoError(t, store.Close())

	loaded, err := store.Load(context.Background(), "https://api.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, loaded)
}

func TestMemoryTokenStore_Load_DeepCopy(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()
	require.NoError(t, store.Save(ctx, testEntry("https://api.example.com")))

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)

	// Mutating the loaded entry should not affect the stored one.
	loaded.Token = "mutated-token"

	reloaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.NotEqual(t, "mutated-token", reloaded.Token)
}

func TestMemoryTokenStore_Delete_Success(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()
	require.NoError(t, store.Save(ctx, testEntry("https://api.example.com")))

	err := store.Delete(ctx, "https://api.example.com")
	require.NoError(t, err)

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestMemoryTokenStore_Delete_NotFound(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	err := store.Delete(context.Background(), "https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestMemoryTokenStore_Delete_EmptyServer(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	err := store.Delete(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidServer)
}

func TestMemoryTokenStore_Delete_Closed(t *testing.T) {
	store := NewMemoryTokenStore()
	require.NoError(t, store.Close())

	err := store.Delete(context.Background(), "https://api.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestMemoryTokenStore_List_Empty(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	entries, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestMemoryTokenStore_List_MultipleSorted(t *testing.T) {
	store := NewMemoryTokenStore()
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

	assert.Equal(t, "https://a-server.example.com", entries[0].ServerURL)
	assert.Equal(t, "https://m-server.example.com", entries[1].ServerURL)
	assert.Equal(t, "https://z-server.example.com", entries[2].ServerURL)
}

func TestMemoryTokenStore_List_Closed(t *testing.T) {
	store := NewMemoryTokenStore()
	require.NoError(t, store.Close())

	entries, err := store.List(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, entries)
}

func TestMemoryTokenStore_Close_Idempotent(t *testing.T) {
	store := NewMemoryTokenStore()

	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestMemoryTokenStore_ServerNormalization(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

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

	// Delete with mixed case.
	err = store.Delete(ctx, "Https://Auth.Example.Com/")
	require.NoError(t, err)

	_, err = store.Load(ctx, "https://auth.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestMemoryTokenStore_Concurrency(t *testing.T) {
	store := NewMemoryTokenStore()
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

	loaded, err := store.Load(ctx, "https://api.example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, loaded.Token)
}

func TestMemoryTokenStore_ImplementsInterface(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	var _ TokenStore = store
}

func TestMemoryTokenStore_AllSources(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	sources := []struct {
		server string
		source string
	}{
		{"https://oidc.example.com", SourceOIDC},
		{"https://fido2.example.com", SourceFIDO2},
		{"https://bootstrap.example.com", SourceBootstrap},
	}

	for _, s := range sources {
		entry := &TokenEntry{
			ServerURL: s.server,
			TokenType: TypeBearer,
			Source:    s.source,
			Token:     "jwt-" + s.source,
			ExpiresAt: now.Add(1 * time.Hour),
			IssuedAt:  now,
			Issuer:    s.server,
			Subject:   "user-" + s.source,
		}
		require.NoError(t, store.Save(ctx, entry))
	}

	entries, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Verify each source was stored correctly.
	for _, s := range sources {
		loaded, err := store.Load(ctx, s.server)
		require.NoError(t, err)
		assert.Equal(t, s.source, loaded.Source)
		assert.Equal(t, "jwt-"+s.source, loaded.Token)
	}
}
