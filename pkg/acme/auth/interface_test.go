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

package auth

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenClaimsFields(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	expires := now.Add(1 * time.Hour)

	claims := &TokenClaims{
		UserID:      "user-123",
		Username:    "testuser",
		Email:       "test@example.com",
		TenantID:    "tenant-456",
		Roles:       []string{"admin", "user"},
		Groups:      []string{"engineering"},
		Permissions: []string{"read", "write"},
		SessionID:   "session-789",
		IssuedAt:    now,
		ExpiresAt:   expires,
		Valid:       true,
	}

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "testuser", claims.Username)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "tenant-456", claims.TenantID)
	assert.Equal(t, []string{"admin", "user"}, claims.Roles)
	assert.Equal(t, []string{"engineering"}, claims.Groups)
	assert.Equal(t, []string{"read", "write"}, claims.Permissions)
	assert.Equal(t, "session-789", claims.SessionID)
	assert.Equal(t, now, claims.IssuedAt)
	assert.Equal(t, expires, claims.ExpiresAt)
	assert.True(t, claims.Valid)
}

func TestTokenClaimsJSONSerialization(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	expires := now.Add(1 * time.Hour)

	original := &TokenClaims{
		UserID:      "user-123",
		Username:    "testuser",
		Email:       "test@example.com",
		TenantID:    "tenant-456",
		Roles:       []string{"admin"},
		Groups:      []string{"ops"},
		Permissions: []string{"deploy"},
		SessionID:   "session-abc",
		IssuedAt:    now,
		ExpiresAt:   expires,
		Valid:       true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded TokenClaims
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.UserID, decoded.UserID)
	assert.Equal(t, original.Username, decoded.Username)
	assert.Equal(t, original.Email, decoded.Email)
	assert.Equal(t, original.TenantID, decoded.TenantID)
	assert.Equal(t, original.Roles, decoded.Roles)
	assert.Equal(t, original.Groups, decoded.Groups)
	assert.Equal(t, original.Permissions, decoded.Permissions)
	assert.Equal(t, original.SessionID, decoded.SessionID)
	assert.True(t, original.IssuedAt.Equal(decoded.IssuedAt))
	assert.True(t, original.ExpiresAt.Equal(decoded.ExpiresAt))
	assert.Equal(t, original.Valid, decoded.Valid)
}

func TestTokenClaimsJSONFieldNames(t *testing.T) {
	claims := &TokenClaims{
		UserID:   "uid",
		Username: "uname",
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, "uid", raw["user_id"])
	assert.Equal(t, "uname", raw["username"])
	_, hasUserID := raw["user_id"]
	assert.True(t, hasUserID, "JSON should use snake_case field name user_id")
}

// TestTokenClaimsCarryNoPermissions checks that the claims carry no
// permissions list: authorization comes from the qrdb authorizer, so a
// "permissions" key in a token is dropped on decode and never re-encoded,
// and a refreshed claim set carries none.
func TestTokenClaimsCarryNoPermissions(t *testing.T) {
	in := []byte(`{"user_id":"uid","username":"uname","roles":["admin"],"permissions":["read","write"],"valid":true}`)

	var claims TokenClaims
	require.NoError(t, json.Unmarshal(in, &claims))
	assert.Equal(t, "uid", claims.UserID)
	assert.Equal(t, []string{"admin"}, claims.Roles)

	out, err := json.Marshal(&claims)
	require.NoError(t, err)
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &raw))
	assert.NotContains(t, raw, "permissions", "re-encoded claims must not carry permissions")

	client := NewMemoryClient()
	client.AddToken("perm-token", &claims)
	ctx := context.Background()
	newToken, err := client.RefreshToken(ctx, "perm-token")
	require.NoError(t, err)
	refreshed, err := client.ValidateToken(ctx, newToken)
	require.NoError(t, err)
	assert.Equal(t, "uid", refreshed.UserID)

	out, err = json.Marshal(refreshed)
	require.NoError(t, err)
	raw = nil
	require.NoError(t, json.Unmarshal(out, &raw))
	assert.NotContains(t, raw, "permissions", "refreshed claims must not carry permissions")
}

func TestTokenClaimsZeroValue(t *testing.T) {
	claims := &TokenClaims{}

	assert.Empty(t, claims.UserID)
	assert.Empty(t, claims.Username)
	assert.Empty(t, claims.Email)
	assert.Empty(t, claims.TenantID)
	assert.Nil(t, claims.Roles)
	assert.Nil(t, claims.Groups)
	assert.Nil(t, claims.Permissions)
	assert.Empty(t, claims.SessionID)
	assert.True(t, claims.IssuedAt.IsZero())
	assert.True(t, claims.ExpiresAt.IsZero())
	assert.False(t, claims.Valid)
}
