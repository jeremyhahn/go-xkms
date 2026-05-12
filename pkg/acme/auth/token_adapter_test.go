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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenAdapterValidateToken(t *testing.T) {
	expectedClaims := &TokenClaims{
		UserID:   "user-test",
		Username: "testuser",
		Email:    "testuser@example.com",
		Valid:    true,
	}

	adapter := NewTokenAdapter(
		WithValidateFunc(func(_ context.Context, token string) (*TokenClaims, error) {
			if token == "good-token" {
				return expectedClaims, nil
			}
			return nil, &InvalidTokenError{Reason: "unknown token"}
		}),
	)

	ctx := context.Background()
	result, err := adapter.ValidateToken(ctx, "good-token")
	require.NoError(t, err)
	assert.Equal(t, expectedClaims.UserID, result.UserID)
	assert.Equal(t, expectedClaims.Username, result.Username)
}

func TestTokenAdapterValidateTokenError(t *testing.T) {
	adapter := NewTokenAdapter(
		WithValidateFunc(func(_ context.Context, _ string) (*TokenClaims, error) {
			return nil, &AuthServiceError{
				Message: "upstream failure",
				Cause:   errors.New("connection timeout"),
			}
		}),
	)

	ctx := context.Background()
	result, err := adapter.ValidateToken(ctx, "any-token")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upstream failure")
}

func TestTokenAdapterValidateTokenNoFunc(t *testing.T) {
	adapter := NewTokenAdapter()

	ctx := context.Background()
	result, err := adapter.ValidateToken(ctx, "any-token")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate function not configured")
}

func TestTokenAdapterRefreshToken(t *testing.T) {
	adapter := NewTokenAdapter(
		WithRefreshFunc(func(_ context.Context, token string) (string, error) {
			if token == "old-token" {
				return "new-token-from-provider", nil
			}
			return "", &InvalidTokenError{Reason: "unknown token"}
		}),
	)

	ctx := context.Background()
	newToken, err := adapter.RefreshToken(ctx, "old-token")
	require.NoError(t, err)
	assert.Equal(t, "new-token-from-provider", newToken)
}

func TestTokenAdapterRefreshTokenError(t *testing.T) {
	adapter := NewTokenAdapter(
		WithRefreshFunc(func(_ context.Context, _ string) (string, error) {
			return "", &TokenExpiredError{ExpiredAt: time.Now().Add(-1 * time.Hour)}
		}),
	)

	ctx := context.Background()
	newToken, err := adapter.RefreshToken(ctx, "expired-token")
	assert.Empty(t, newToken)
	require.Error(t, err)
	assert.True(t, IsTokenExpired(err))
}

func TestTokenAdapterRefreshTokenNoFunc(t *testing.T) {
	adapter := NewTokenAdapter()

	ctx := context.Background()
	newToken, err := adapter.RefreshToken(ctx, "any-token")
	assert.Empty(t, newToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh function not configured")
}

func TestTokenAdapterRevokeToken(t *testing.T) {
	adapter := NewTokenAdapter(
		WithRevokeFunc(func(_ context.Context, token string) error {
			if token == "revoke-this" {
				return nil
			}
			return &InvalidTokenError{Reason: "unknown token"}
		}),
	)

	ctx := context.Background()
	err := adapter.RevokeToken(ctx, "revoke-this")
	require.NoError(t, err)
}

func TestTokenAdapterRevokeTokenError(t *testing.T) {
	adapter := NewTokenAdapter(
		WithRevokeFunc(func(_ context.Context, _ string) error {
			return &AuthServiceError{
				Message: "revocation failed",
				Cause:   errors.New("service down"),
			}
		}),
	)

	ctx := context.Background()
	err := adapter.RevokeToken(ctx, "any-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation failed")
}

func TestTokenAdapterRevokeTokenNoFunc(t *testing.T) {
	adapter := NewTokenAdapter()

	ctx := context.Background()
	err := adapter.RevokeToken(ctx, "any-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoke function not configured")
}

func TestTokenAdapterInterfaceCompliance(t *testing.T) {
	var client Client = NewTokenAdapter()
	assert.NotNil(t, client)
}

func TestTokenAdapterAllOptions(t *testing.T) {
	adapter := NewTokenAdapter(
		WithValidateFunc(func(_ context.Context, _ string) (*TokenClaims, error) {
			return &TokenClaims{UserID: "all-opts"}, nil
		}),
		WithRefreshFunc(func(_ context.Context, _ string) (string, error) {
			return "refreshed", nil
		}),
		WithRevokeFunc(func(_ context.Context, _ string) error {
			return nil
		}),
	)

	ctx := context.Background()

	claims, err := adapter.ValidateToken(ctx, "t")
	require.NoError(t, err)
	assert.Equal(t, "all-opts", claims.UserID)

	newToken, err := adapter.RefreshToken(ctx, "t")
	require.NoError(t, err)
	assert.Equal(t, "refreshed", newToken)

	err = adapter.RevokeToken(ctx, "t")
	require.NoError(t, err)
}
