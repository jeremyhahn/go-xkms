// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
			if got != tt.want {
				t.Errorf("HasRole() = %v, want %v", got, tt.want)
			}
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
			if got != tt.want {
				t.Errorf("HasPermission() = %v, want %v", got, tt.want)
			}
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

			if retrieved == nil {
				t.Fatal("GetIdentity() returned nil")
				return
			}

			if retrieved.Subject != tt.identity.Subject {
				t.Errorf("Subject = %v, want %v", retrieved.Subject, tt.identity.Subject)
			}
		})
	}
}

func TestGetIdentity_NoIdentity(t *testing.T) {
	ctx := context.Background()

	identity := GetIdentity(ctx)

	if identity != nil {
		t.Errorf("GetIdentity() = %v, want nil", identity)
	}
}

func TestGetIdentity_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), IdentityContextKey, "not an identity")

	identity := GetIdentity(ctx)

	if identity != nil {
		t.Errorf("GetIdentity() = %v, want nil for wrong type", identity)
	}
}

func TestNoOpAuthenticator_AuthenticateHTTP(t *testing.T) {
	auth := NewNoOpAuthenticator()

	identity, err := auth.AuthenticateHTTP(nil)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil", err)
	}

	if identity == nil {
		t.Fatal("AuthenticateHTTP() returned nil identity")
		return
	}

	if identity.Subject != "anonymous" {
		t.Errorf("Subject = %v, want anonymous", identity.Subject)
	}

	if identity.Claims == nil {
		t.Error("Claims should not be nil")
	}

	if identity.Attributes == nil {
		t.Error("Attributes should not be nil")
	}

	if identity.Attributes["auth_method"] != "none" {
		t.Errorf("auth_method = %v, want none", identity.Attributes["auth_method"])
	}
}

func TestNoOpAuthenticator_AuthenticateGRPC(t *testing.T) {
	auth := NewNoOpAuthenticator()

	identity, err := auth.AuthenticateGRPC(context.Background(), nil)

	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v, want nil", err)
	}

	if identity == nil {
		t.Fatal("AuthenticateGRPC() returned nil identity")
		return
	}

	if identity.Subject != "anonymous" {
		t.Errorf("Subject = %v, want anonymous", identity.Subject)
	}

	if identity.Claims == nil {
		t.Error("Claims should not be nil")
	}

	if identity.Attributes == nil {
		t.Error("Attributes should not be nil")
	}

	if identity.Attributes["auth_method"] != "none" {
		t.Errorf("auth_method = %v, want none", identity.Attributes["auth_method"])
	}
}

func TestNoOpAuthenticator_Name(t *testing.T) {
	auth := NewNoOpAuthenticator()

	name := auth.Name()

	if name != "noop" {
		t.Errorf("Name() = %v, want noop", name)
	}
}
