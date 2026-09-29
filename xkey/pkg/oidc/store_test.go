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
	"testing"

	"github.com/stretchr/testify/assert"
)

// MemoryTokenStore tests

func TestMemoryTokenStore_NewMemoryTokenStore(t *testing.T) {
	store := NewMemoryTokenStore()
	assert.NotNil(t, store)
	defer store.Close()
}

func TestMemoryTokenStore_Save(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	t.Run("saves token successfully", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken:  "access-123",
			RefreshToken: "refresh-456",
		}

		err := store.Save("https://auth.example.com", token)
		assert.NoError(t, err)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		token := &TokenResponse{AccessToken: "test"}
		err := store.Save("", token)
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails with nil token", func(t *testing.T) {
		err := store.Save("https://example.com", nil)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		token := &TokenResponse{AccessToken: "test"}
		err := closedStore.Save("https://example.com", token)
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_Load(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	// Save a token first
	token := &TokenResponse{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
	}
	store.Save("https://auth.example.com", token)

	t.Run("loads token successfully", func(t *testing.T) {
		loaded, err := store.Load("https://auth.example.com")
		assert.NoError(t, err)
		assert.Equal(t, "access-123", loaded.AccessToken)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		_, err := store.Load("")
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails when token not found", func(t *testing.T) {
		_, err := store.Load("https://nonexistent.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		_, err := closedStore.Load("https://example.com")
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_Delete(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	// Save a token first
	store.Save("https://auth.example.com", &TokenResponse{AccessToken: "test"})

	t.Run("deletes token successfully", func(t *testing.T) {
		err := store.Delete("https://auth.example.com")
		assert.NoError(t, err)

		_, err = store.Load("https://auth.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		err := store.Delete("")
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails when token not found", func(t *testing.T) {
		err := store.Delete("https://nonexistent.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		err := closedStore.Delete("https://example.com")
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_List(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	t.Run("returns empty list when no tokens", func(t *testing.T) {
		issuers, err := store.List()
		assert.NoError(t, err)
		assert.Empty(t, issuers)
	})

	t.Run("lists all issuers", func(t *testing.T) {
		store.Save("https://auth1.example.com", &TokenResponse{AccessToken: "1"})
		store.Save("https://auth2.example.com", &TokenResponse{AccessToken: "2"})

		issuers, err := store.List()
		assert.NoError(t, err)
		assert.Len(t, issuers, 2)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		_, err := closedStore.List()
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_Close(t *testing.T) {
	store := NewMemoryTokenStore()

	t.Run("closes successfully", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err)
	})

	t.Run("idempotent close", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err)
	})
}

func TestNormalizeIssuer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://auth.example.com", "https://auth.example.com"},
		{"https://auth.example.com/", "https://auth.example.com"},
		{"HTTPS://AUTH.EXAMPLE.COM", "https://auth.example.com"},
		{"HTTPS://AUTH.EXAMPLE.COM/", "https://auth.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeIssuer(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTokenStoreInterface(t *testing.T) {
	// Verify the in-memory implementation satisfies the interface.
	// BackendTokenStore's own compile-time assertion lives in
	// backend_store.go alongside its implementation.
	var _ TokenStore = (*MemoryTokenStore)(nil)
}
