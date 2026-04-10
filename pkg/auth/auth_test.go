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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentity_HasRole(t *testing.T) {
	tests := []struct {
		name     string
		identity *Identity
		role     string
		want     bool
	}{
		{
			name: "has role - string slice",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"roles": []string{"admin", "user"},
				},
			},
			role: "admin",
			want: true,
		},
		{
			name: "has role - interface slice",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"roles": []interface{}{"admin", "user"},
				},
			},
			role: "user",
			want: true,
		},
		{
			name: "has role - single string",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"roles": "admin",
				},
			},
			role: "admin",
			want: true,
		},
		{
			name: "does not have role",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"roles": []string{"user", "guest"},
				},
			},
			role: "admin",
			want: false,
		},
		{
			name:     "nil identity",
			identity: nil,
			role:     "admin",
			want:     false,
		},
		{
			name: "nil claims",
			identity: &Identity{
				Subject: "user1",
				Claims:  nil,
			},
			role: "admin",
			want: false,
		},
		{
			name: "empty roles",
			identity: &Identity{
				Subject: "user1",
				Claims:  map[string]interface{}{},
			},
			role: "admin",
			want: false,
		},
		{
			name: "roles claim missing",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"other": "value",
				},
			},
			role: "admin",
			want: false,
		},
		{
			name: "interface slice with non-string",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"roles": []interface{}{"admin", 123, "user"},
				},
			},
			role: "admin",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.identity.HasRole(tt.role)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIdentity_HasPermission(t *testing.T) {
	tests := []struct {
		name       string
		identity   *Identity
		permission string
		want       bool
	}{
		{
			name: "has permission - string slice",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"permissions": []string{"read", "write"},
				},
			},
			permission: "read",
			want:       true,
		},
		{
			name: "has permission - interface slice",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"permissions": []interface{}{"read", "write"},
				},
			},
			permission: "write",
			want:       true,
		},
		{
			name: "has permission - single string",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"permissions": "read",
				},
			},
			permission: "read",
			want:       true,
		},
		{
			name: "does not have permission",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"permissions": []string{"read"},
				},
			},
			permission: "write",
			want:       false,
		},
		{
			name:       "nil identity",
			identity:   nil,
			permission: "read",
			want:       false,
		},
		{
			name: "nil claims",
			identity: &Identity{
				Subject: "user1",
				Claims:  nil,
			},
			permission: "read",
			want:       false,
		},
		{
			name: "empty permissions",
			identity: &Identity{
				Subject: "user1",
				Claims:  map[string]interface{}{},
			},
			permission: "read",
			want:       false,
		},
		{
			name: "permissions claim missing",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"other": "value",
				},
			},
			permission: "read",
			want:       false,
		},
		{
			name: "interface slice with non-string",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"permissions": []interface{}{"read", 456, "write"},
				},
			},
			permission: "read",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.identity.HasPermission(tt.permission)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithIdentity_GetIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity *Identity
	}{
		{
			name: "valid identity",
			identity: &Identity{
				Subject: "user1",
				Claims: map[string]interface{}{
					"roles": []string{"admin"},
				},
				Attributes: map[string]string{
					"auth_method": "apikey",
				},
			},
		},
		{
			name: "minimal identity",
			identity: &Identity{
				Subject: "user2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Add identity to context
			ctxWithIdentity := WithIdentity(ctx, tt.identity)

			// Retrieve identity from context
			retrieved := GetIdentity(ctxWithIdentity)

			require.NotNil(t, retrieved)
			assert.Equal(t, tt.identity.Subject, retrieved.Subject)
		})
	}
}

func TestGetIdentity_NoIdentity(t *testing.T) {
	ctx := context.Background()

	identity := GetIdentity(ctx)

	assert.Nil(t, identity)
}

func TestGetIdentity_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), IdentityContextKey, "not an identity")

	identity := GetIdentity(ctx)

	assert.Nil(t, identity)
}

func TestNoOpAuthenticator_AuthenticateHTTP(t *testing.T) {
	auth := NewNoOpAuthenticator()

	identity, err := auth.AuthenticateHTTP(nil)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "anonymous", identity.Subject)
	assert.NotNil(t, identity.Claims)
	assert.NotNil(t, identity.Attributes)
	assert.Equal(t, "none", identity.Attributes["auth_method"])
}

func TestNoOpAuthenticator_AuthenticateGRPC(t *testing.T) {
	auth := NewNoOpAuthenticator()

	identity, err := auth.AuthenticateGRPC(context.Background(), nil)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "anonymous", identity.Subject)
	assert.NotNil(t, identity.Claims)
	assert.NotNil(t, identity.Attributes)
	assert.Equal(t, "none", identity.Attributes["auth_method"])
}

func TestNoOpAuthenticator_Name(t *testing.T) {
	auth := NewNoOpAuthenticator()

	name := auth.Name()

	assert.Equal(t, "noop", name)
}

func TestIdentity_TenantID_Empty(t *testing.T) {
	identity := &Identity{
		Subject: "user1",
	}
	assert.True(t, identity.IsCrossTenant(), "IsCrossTenant should return true for empty TenantID")
}

func TestIdentity_TenantID_Set(t *testing.T) {
	identity := &Identity{
		Subject:  "user1",
		TenantID: "tenant-abc",
	}
	assert.False(t, identity.IsCrossTenant(), "IsCrossTenant should return false for populated TenantID")
	assert.Equal(t, "tenant-abc", identity.TenantID)
}

func TestIdentity_TenantID_Nil(t *testing.T) {
	var identity *Identity
	assert.True(t, identity.IsCrossTenant(), "IsCrossTenant should return true for nil identity")
}

func TestWithTenantBarrier_GetTenantBarrier(t *testing.T) {
	ctx := context.Background()

	type mockBarrier struct {
		name string
	}
	barrier := &mockBarrier{name: "test-barrier"}

	ctx = WithTenantBarrier(ctx, barrier)
	retrieved := GetTenantBarrier(ctx)

	require.NotNil(t, retrieved)
	got, ok := retrieved.(*mockBarrier)
	require.True(t, ok, "expected *mockBarrier type")
	assert.Equal(t, "test-barrier", got.name)
}

func TestGetTenantBarrier_NotPresent(t *testing.T) {
	ctx := context.Background()

	barrier := GetTenantBarrier(ctx)

	assert.Nil(t, barrier)
}
