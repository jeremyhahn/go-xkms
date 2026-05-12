// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClaims() *TokenClaims {
	now := time.Now()
	return &TokenClaims{
		UserID:      "user-001",
		Username:    "alice",
		Email:       "alice@example.com",
		TenantID:    "tenant-001",
		Roles:       []string{"admin"},
		Groups:      []string{"engineering"},
		Permissions: []string{"read", "write"},
		SessionID:   "session-001",
		IssuedAt:    now,
		ExpiresAt:   now.Add(1 * time.Hour),
		Valid:       true,
	}
}

func TestMemoryClientValidateToken(t *testing.T) {
	client := NewMemoryClient()
	claims := newTestClaims()
	client.AddToken("valid-token", claims)

	ctx := context.Background()
	result, err := client.ValidateToken(ctx, "valid-token")
	require.NoError(t, err)
	assert.Equal(t, claims.UserID, result.UserID)
	assert.Equal(t, claims.Username, result.Username)
	assert.Equal(t, claims.Email, result.Email)
	assert.Equal(t, claims.TenantID, result.TenantID)
	assert.Equal(t, claims.Roles, result.Roles)
	assert.Equal(t, claims.SessionID, result.SessionID)
}

func TestMemoryClientValidateTokenNotFound(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	result, err := client.ValidateToken(ctx, "nonexistent-token")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
	assert.Contains(t, err.Error(), "not found")
}

func TestMemoryClientValidateTokenEmpty(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	result, err := client.ValidateToken(ctx, "")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
	assert.Contains(t, err.Error(), "empty token")
}

func TestMemoryClientValidateTokenExpired(t *testing.T) {
	client := NewMemoryClient()
	claims := newTestClaims()
	claims.ExpiresAt = time.Now().Add(-1 * time.Hour) // expired 1 hour ago
	client.AddToken("expired-token", claims)

	ctx := context.Background()
	result, err := client.ValidateToken(ctx, "expired-token")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsTokenExpired(err))
}

func TestMemoryClientValidateTokenZeroExpiry(t *testing.T) {
	client := NewMemoryClient()
	claims := newTestClaims()
	claims.ExpiresAt = time.Time{} // zero value means no expiry
	client.AddToken("no-expiry-token", claims)

	ctx := context.Background()
	result, err := client.ValidateToken(ctx, "no-expiry-token")
	require.NoError(t, err)
	assert.Equal(t, claims.UserID, result.UserID)
}

func TestMemoryClientRefreshToken(t *testing.T) {
	client := NewMemoryClient()
	claims := newTestClaims()
	client.AddToken("old-token", claims)

	ctx := context.Background()
	newToken, err := client.RefreshToken(ctx, "old-token")
	require.NoError(t, err)
	assert.NotEmpty(t, newToken)
	assert.NotEqual(t, "old-token", newToken)

	// Old token should no longer be valid
	_, err = client.ValidateToken(ctx, "old-token")
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))

	// New token should be valid with same user data
	result, err := client.ValidateToken(ctx, newToken)
	require.NoError(t, err)
	assert.Equal(t, claims.UserID, result.UserID)
	assert.Equal(t, claims.Username, result.Username)
	assert.Equal(t, claims.Email, result.Email)
	assert.True(t, result.Valid)
	assert.True(t, result.ExpiresAt.After(time.Now()))
}

func TestMemoryClientRefreshTokenNotFound(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	newToken, err := client.RefreshToken(ctx, "nonexistent")
	assert.Empty(t, newToken)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
}

func TestMemoryClientRefreshTokenEmpty(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	newToken, err := client.RefreshToken(ctx, "")
	assert.Empty(t, newToken)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
}

func TestMemoryClientRevokeToken(t *testing.T) {
	client := NewMemoryClient()
	claims := newTestClaims()
	client.AddToken("revoke-me", claims)

	ctx := context.Background()

	// Verify token exists
	_, err := client.ValidateToken(ctx, "revoke-me")
	require.NoError(t, err)

	// Revoke
	err = client.RevokeToken(ctx, "revoke-me")
	require.NoError(t, err)

	// Verify token no longer valid
	_, err = client.ValidateToken(ctx, "revoke-me")
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
}

func TestMemoryClientRevokeTokenNotFound(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	err := client.RevokeToken(ctx, "nonexistent")
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
}

func TestMemoryClientRevokeTokenEmpty(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	err := client.RevokeToken(ctx, "")
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
}

func TestMemoryClientRemoveToken(t *testing.T) {
	client := NewMemoryClient()
	claims := newTestClaims()
	client.AddToken("remove-me", claims)

	ctx := context.Background()
	_, err := client.ValidateToken(ctx, "remove-me")
	require.NoError(t, err)

	client.RemoveToken("remove-me")

	_, err = client.ValidateToken(ctx, "remove-me")
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
}

func TestMemoryClientConcurrentAccess(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()
	const goroutines = 100

	// Pre-populate tokens
	for i := range goroutines {
		claims := newTestClaims()
		claims.UserID = string(rune('A' + i%26))
		token := "token-" + string(rune('A'+i%26)) + "-" + time.Now().Format("150405.000000000")
		client.AddToken(token, claims)
	}

	var wg sync.WaitGroup

	// Concurrent writes
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			claims := newTestClaims()
			claims.UserID = "concurrent-user-" + string(rune('A'+idx%26))
			client.AddToken("concurrent-"+string(rune('A'+idx%26)), claims)
		}(i)
	}

	// Concurrent reads
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This may return an error (not found) which is fine
			_, _ = client.ValidateToken(ctx, "concurrent-A")
		}()
	}

	// Concurrent revocations
	for i := range goroutines / 2 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = client.RevokeToken(ctx, "concurrent-"+string(rune('A'+idx%26)))
		}(i)
	}

	wg.Wait()
}

func TestMemoryClientInterfaceCompliance(t *testing.T) {
	var client Client = NewMemoryClient()
	assert.NotNil(t, client)
}
