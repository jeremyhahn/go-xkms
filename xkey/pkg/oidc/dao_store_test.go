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
	"fmt"
	"sync"
	"testing"

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

// testTokenResponse creates a test TokenResponse for the given issuer.
func testTokenResponse(issuer string) *TokenResponse {
	return &TokenResponse{
		AccessToken:  "access-token-for-" + issuer,
		TokenType:    "Bearer",
		RefreshToken: "refresh-token-for-" + issuer,
		ExpiresIn:    3600,
		IDToken:      "id-token-for-" + issuer,
		Scope:        "openid profile email",
	}
}

func TestDAOStore_NewDAOStore_NilKVStore(t *testing.T) {
	store, err := NewDAOStore(nil)
	require.ErrorIs(t, err, ErrNilBackend)
	assert.Nil(t, store)
}

func TestDAOStore_SaveLoad(t *testing.T) {
	store := newTestDAOStore(t)

	issuer := "https://auth.example.com"
	tokens := testTokenResponse(issuer)
	require.NoError(t, store.Save(issuer, tokens))

	loaded, err := store.Load(issuer)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, tokens.AccessToken, loaded.AccessToken)
	assert.Equal(t, tokens.TokenType, loaded.TokenType)
	assert.Equal(t, tokens.RefreshToken, loaded.RefreshToken)
	assert.Equal(t, tokens.ExpiresIn, loaded.ExpiresIn)
	assert.Equal(t, tokens.IDToken, loaded.IDToken)
	assert.Equal(t, tokens.Scope, loaded.Scope)
}

func TestDAOStore_Save_EmptyIssuer(t *testing.T) {
	store := newTestDAOStore(t)
	err := store.Save("", testTokenResponse("test"))
	require.ErrorIs(t, err, ErrInvalidIssuer)
}

func TestDAOStore_Save_NilTokens(t *testing.T) {
	store := newTestDAOStore(t)
	err := store.Save("https://auth.example.com", nil)
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestDAOStore_Save_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Save("https://auth.example.com", testTokenResponse("test"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_Delete(t *testing.T) {
	store := newTestDAOStore(t)

	issuer := "https://auth.example.com"
	require.NoError(t, store.Save(issuer, testTokenResponse(issuer)))

	err := store.Delete(issuer)
	require.NoError(t, err)

	// Verify the token is gone.
	loaded, err := store.Load(issuer)
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestDAOStore(t)
	err := store.Delete("https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestDAOStore_Delete_EmptyIssuer(t *testing.T) {
	store := newTestDAOStore(t)
	err := store.Delete("")
	require.ErrorIs(t, err, ErrInvalidIssuer)
}

func TestDAOStore_Delete_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Delete("https://auth.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestDAOStore_List(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Save("https://z-auth.example.com", testTokenResponse("z")))
	require.NoError(t, store.Save("https://a-auth.example.com", testTokenResponse("a")))
	require.NoError(t, store.Save("https://m-auth.example.com", testTokenResponse("m")))

	issuers, err := store.List()
	require.NoError(t, err)
	require.Len(t, issuers, 3)

	// Issuers should be sorted alphabetically.
	assert.Equal(t, "https://a-auth.example.com", issuers[0])
	assert.Equal(t, "https://m-auth.example.com", issuers[1])
	assert.Equal(t, "https://z-auth.example.com", issuers[2])
}

func TestDAOStore_List_Empty(t *testing.T) {
	store := newTestDAOStore(t)

	issuers, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, issuers)
}

func TestDAOStore_List_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	issuers, err := store.List()
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, issuers)
}

func TestDAOStore_Page(t *testing.T) {
	store := newTestDAOStore(t)

	// Save 5 entries.
	for i := 0; i < 5; i++ {
		issuer := fmt.Sprintf("https://auth-%02d.example.com", i)
		require.NoError(t, store.Save(issuer, testTokenResponse(issuer)))
	}

	// Page with size 2.
	result, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 2, result.PageSize)

	// Page 2.
	result2, err := store.Page(context.Background(), dao.PageQuery{Page: 2, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result2.Entities, 2)
	assert.True(t, result2.HasMore)

	// Page 3 (last page with 1 entry).
	result3, err := store.Page(context.Background(), dao.PageQuery{Page: 3, PageSize: 2})
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

func TestDAOStore_DuplicateIssuer(t *testing.T) {
	store := newTestDAOStore(t)

	issuer := "https://auth.example.com"

	// Save initial tokens.
	tokens1 := testTokenResponse(issuer)
	tokens1.AccessToken = "first-token"
	require.NoError(t, store.Save(issuer, tokens1))

	// Save again with the same issuer (should overwrite).
	tokens2 := testTokenResponse(issuer)
	tokens2.AccessToken = "second-token"
	require.NoError(t, store.Save(issuer, tokens2))

	// Load should return the latest.
	loaded, err := store.Load(issuer)
	require.NoError(t, err)
	assert.Equal(t, "second-token", loaded.AccessToken)

	// List should show only one issuer.
	issuers, err := store.List()
	require.NoError(t, err)
	assert.Len(t, issuers, 1)
}

func TestDAOStore_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	loaded, err := store.Load("https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Nil(t, loaded)
}

func TestDAOStore_Load_EmptyIssuer(t *testing.T) {
	store := newTestDAOStore(t)

	loaded, err := store.Load("")
	require.ErrorIs(t, err, ErrInvalidIssuer)
	assert.Nil(t, loaded)
}

func TestDAOStore_Load_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	loaded, err := store.Load("https://auth.example.com")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, loaded)
}

func TestDAOStore_IssuerNormalization(t *testing.T) {
	store := newTestDAOStore(t)

	tokens := testTokenResponse("test")
	require.NoError(t, store.Save("https://auth.example.com/", tokens))

	// Load without trailing slash.
	loaded, err := store.Load("https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, tokens.AccessToken, loaded.AccessToken)

	// Load with uppercase.
	loaded, err = store.Load("HTTPS://AUTH.EXAMPLE.COM/")
	require.NoError(t, err)
	assert.Equal(t, tokens.AccessToken, loaded.AccessToken)

	// Delete with mixed case and trailing slash.
	err = store.Delete("Https://Auth.Example.Com/")
	require.NoError(t, err)

	// Verify it is gone.
	_, err = store.Load("https://auth.example.com")
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

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	issuer := "https://auth.example.com"
	tokens := testTokenResponse(issuer)

	// Concurrent saves.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = store.Save(issuer, tokens)
		}()
	}

	// Concurrent loads.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.Load(issuer)
		}()
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List()
		}()
	}

	wg.Wait()

	// After all goroutines complete, the store should be consistent.
	loaded, err := store.Load(issuer)
	require.NoError(t, err)
	assert.NotEmpty(t, loaded.AccessToken)
}

func TestDAOStore_ImplementsInterface(t *testing.T) {
	store := newTestDAOStore(t)
	var _ TokenStore = store
}

func TestDAOStore_DPoPKeyPreservation(t *testing.T) {
	store := newTestDAOStore(t)

	issuer := "https://auth.example.com"
	tokens := &TokenResponse{
		AccessToken:  "access-token",
		TokenType:    "DPoP",
		RefreshToken: "refresh-token",
		ExpiresIn:    3600,
		IDToken:      "id-token",
		Scope:        "openid",
		DPoPKeyPEM:   "-----BEGIN EC PRIVATE KEY-----\nfake-key-data\n-----END EC PRIVATE KEY-----",
	}
	require.NoError(t, store.Save(issuer, tokens))

	loaded, err := store.Load(issuer)
	require.NoError(t, err)
	assert.Equal(t, tokens.DPoPKeyPEM, loaded.DPoPKeyPEM)
}
