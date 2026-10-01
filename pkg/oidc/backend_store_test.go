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

package oidc

import (
	"context"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testToken returns a fresh TokenResponse for use in tests.
func testToken() *TokenResponse {
	return &TokenResponse{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		ExpiresIn:    3600,
		IDToken:      "test-id-token",
	}
}

func TestBackendTokenStore_NewBackendTokenStore_NilBackend(t *testing.T) {
	store, err := NewBackendTokenStore(nil, "oidc/tokens/")
	require.ErrorIs(t, err, ErrNilBackend)
	assert.Nil(t, store)
}

func TestBackendTokenStore_NewBackendTokenStore_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	assert.Equal(t, "oidc/tokens/", store.prefix)
	assert.False(t, store.closed)
}

func TestBackendTokenStore_Save_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	token := testToken()
	err = store.Save("https://auth.example.com", token)
	require.NoError(t, err)

	// Verify the token was persisted by loading it back.
	loaded, err := store.Load("https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, token.AccessToken, loaded.AccessToken)
	assert.Equal(t, token.TokenType, loaded.TokenType)
	assert.Equal(t, token.RefreshToken, loaded.RefreshToken)
	assert.Equal(t, token.ExpiresIn, loaded.ExpiresIn)
	assert.Equal(t, token.IDToken, loaded.IDToken)
}

func TestBackendTokenStore_Save_EmptyIssuer(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	err = store.Save("", testToken())
	require.ErrorIs(t, err, ErrInvalidIssuer)
}

func TestBackendTokenStore_Save_NilToken(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	err = store.Save("https://auth.example.com", nil)
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestBackendTokenStore_Save_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	err = store.Save("https://auth.example.com", testToken())
	require.ErrorIs(t, err, ErrBackendStoreClosed)
}

func TestBackendTokenStore_Load_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	token := testToken()
	require.NoError(t, store.Save("https://auth.example.com", token))

	loaded, err := store.Load("https://auth.example.com")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "test-access-token", loaded.AccessToken)
	assert.Equal(t, "Bearer", loaded.TokenType)
	assert.Equal(t, "test-refresh-token", loaded.RefreshToken)
	assert.Equal(t, 3600, loaded.ExpiresIn)
	assert.Equal(t, "test-id-token", loaded.IDToken)
}

func TestBackendTokenStore_Load_NotFound(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	loaded, err := store.Load("https://unknown.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Load_EmptyIssuer(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	loaded, err := store.Load("")
	require.ErrorIs(t, err, ErrInvalidIssuer)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Load_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	loaded, err := store.Load("https://auth.example.com")
	require.ErrorIs(t, err, ErrBackendStoreClosed)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Delete_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	require.NoError(t, store.Save("https://auth.example.com", testToken()))

	err = store.Delete("https://auth.example.com")
	require.NoError(t, err)

	// Verify the token is no longer loadable.
	loaded, err := store.Load("https://auth.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestBackendTokenStore_Delete_NotFound(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	err = store.Delete("https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestBackendTokenStore_Delete_EmptyIssuer(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	err = store.Delete("")
	require.ErrorIs(t, err, ErrInvalidIssuer)
}

func TestBackendTokenStore_Delete_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	err = store.Delete("https://auth.example.com")
	require.ErrorIs(t, err, ErrBackendStoreClosed)
}

func TestBackendTokenStore_List_Empty(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	issuers, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, issuers)
}

func TestBackendTokenStore_List_Success(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	require.NoError(t, store.Save("https://auth.example.com", testToken()))
	require.NoError(t, store.Save("https://accounts.google.com", testToken()))

	issuers, err := store.List()
	require.NoError(t, err)
	assert.Len(t, issuers, 2)

	// List returns sorted results.
	assert.Contains(t, issuers, store.tokenKey("https://auth.example.com")[len(store.prefix):len(store.tokenKey("https://auth.example.com"))-5])
	assert.Contains(t, issuers, store.tokenKey("https://accounts.google.com")[len(store.prefix):len(store.tokenKey("https://accounts.google.com"))-5])
}

func TestBackendTokenStore_List_Closed(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())

	issuers, err := store.List()
	require.ErrorIs(t, err, ErrBackendStoreClosed)
	assert.Nil(t, issuers)
}

func TestBackendTokenStore_Close_Idempotent(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)

	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestBackendTokenStore_Close_DoesNotCloseBackend(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
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

func TestBackendTokenStore_Concurrency(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent saves.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			issuer := "https://auth.example.com"
			token := &TokenResponse{
				AccessToken:  "access-token",
				TokenType:    "Bearer",
				RefreshToken: "refresh-token",
				ExpiresIn:    3600,
				IDToken:      "id-token",
			}
			_ = store.Save(issuer, token)
		}(i)
	}

	// Concurrent loads.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _ = store.Load("https://auth.example.com")
		}(i)
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _ = store.List()
		}(i)
	}

	wg.Wait()

	// After all goroutines complete, the store should be in a consistent state.
	loaded, err := store.Load("https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, "access-token", loaded.AccessToken)
}

func TestBackendTokenStore_ImplementsInterface(t *testing.T) {
	// Compile-time interface check is already in backend_store.go,
	// but verify it at runtime as well.
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	var _ TokenStore = store
}

func TestBackendTokenStore_IssuerNormalization(t *testing.T) {
	backend := storage.NewMemory()
	defer backend.Close()

	store, err := NewBackendTokenStore(backend, "oidc/tokens/")
	require.NoError(t, err)
	defer store.Close()

	token := testToken()

	// Save with trailing slash.
	require.NoError(t, store.Save("https://auth.example.com/", token))

	// Load without trailing slash should find the same token because
	// normalizeIssuer strips trailing slashes.
	loaded, err := store.Load("https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, token.AccessToken, loaded.AccessToken)

	// Load with uppercase should also work because normalizeIssuer
	// lowercases the issuer.
	loaded, err = store.Load("HTTPS://AUTH.EXAMPLE.COM/")
	require.NoError(t, err)
	assert.Equal(t, token.AccessToken, loaded.AccessToken)

	// Delete with mixed case and trailing slash.
	err = store.Delete("Https://Auth.Example.Com/")
	require.NoError(t, err)

	// Verify it is gone.
	_, err = store.Load("https://auth.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}
