//go:build codec_json

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

package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/auth"
)

func TestAuthMiddleware_ValidToken(t *testing.T) {
	client := auth.NewMemoryClient()

	// Add a valid token
	client.AddToken("valid-token", &auth.TokenClaims{
		Valid:     true,
		UserID:    "user-123",
		Username:  "testuser",
		TenantID:  "tenant-abc",
		Roles:     []string{"admin"},
		ExpiresAt: time.Now().Add(time.Hour),
	})

	middleware := NewAuthMiddleware(client)

	var capturedUser *AuthenticatedUser
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, "user-123", capturedUser.UserID)
	assert.Equal(t, "tenant-abc", capturedUser.TenantID)
	assert.Equal(t, RoleAdmin, capturedUser.Role)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	client := auth.NewMemoryClient()

	// Add an invalid token
	client.AddToken("invalid-token", &auth.TokenClaims{
		Valid: false,
	})

	middleware := NewAuthMiddleware(client)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_MissingAuthHeader(t *testing.T) {
	client := auth.NewMemoryClient()
	middleware := NewAuthMiddleware(client)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidAuthFormat(t *testing.T) {
	client := auth.NewMemoryClient()
	middleware := NewAuthMiddleware(client)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	client := auth.NewMemoryClient()

	// Add an expired token
	client.AddToken("expired-token", &auth.TokenClaims{
		Valid:     true,
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(-time.Hour), // Expired
	})

	middleware := NewAuthMiddleware(client)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called for expired token")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer expired-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRole_AdminHasAllPermissions(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyRole, RoleAdmin)

	handler := RequireRole(RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_OperatorHasOperatorAndViewerPermissions(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyRole, RoleOperator)

	// Operator accessing viewer endpoint - should succeed
	handler := RequireRole(RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Operator accessing admin endpoint - should fail
	handler = RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req = httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_NoRoleInContext(t *testing.T) {
	ctx := context.Background()

	handler := RequireRole(RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called without role in context")
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireTenant_SameTenant(t *testing.T) {
	user := &AuthenticatedUser{
		UserID:   "user-123",
		TenantID: "tenant-abc",
		Role:     RoleAdmin,
	}
	ctx := context.WithValue(context.Background(), ContextKeyUser, user)

	getTenantID := func(r *http.Request) string { return "tenant-abc" }

	handler := RequireTenant(getTenantID)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireTenant_DifferentTenant(t *testing.T) {
	user := &AuthenticatedUser{
		UserID:   "user-123",
		TenantID: "tenant-abc",
		Role:     RoleAdmin,
	}
	ctx := context.WithValue(context.Background(), ContextKeyUser, user)

	getTenantID := func(r *http.Request) string { return "tenant-xyz" }

	handler := RequireTenant(getTenantID)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireTenant_SuperAdminCanAccessAnyTenant(t *testing.T) {
	user := &AuthenticatedUser{
		UserID:   "user-123",
		TenantID: "tenant-abc",
		Role:     RoleSuperAdmin,
	}
	ctx := context.WithValue(context.Background(), ContextKeyUser, user)

	getTenantID := func(r *http.Request) string { return "tenant-xyz" }

	handler := RequireTenant(getTenantID)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireTenant_EmptyTenantID(t *testing.T) {
	user := &AuthenticatedUser{
		UserID:   "user-123",
		TenantID: "tenant-abc",
		Role:     RoleAdmin,
	}
	ctx := context.WithValue(context.Background(), ContextKeyUser, user)

	getTenantID := func(r *http.Request) string { return "" }

	handler := RequireTenant(getTenantID)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetHighestRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		expected Role
	}{
		{"single super-admin", []string{"super-admin"}, RoleSuperAdmin},
		{"single admin", []string{"admin"}, RoleAdmin},
		{"single endorser", []string{"endorser"}, RoleEndorser},
		{"single operator", []string{"operator"}, RoleOperator},
		{"single viewer", []string{"viewer"}, RoleViewer},
		{"multiple roles picks highest", []string{"viewer", "admin", "operator"}, RoleAdmin},
		{"super-admin with others", []string{"viewer", "super-admin", "admin"}, RoleSuperAdmin},
		{"empty roles", []string{}, ""},
		{"nil roles", nil, ""},
		{"unknown roles only", []string{"unknown", "invalid"}, ""},
		{"mixed known and unknown", []string{"unknown", "operator"}, RoleOperator},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getHighestRole(tt.roles)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetUserFromContext(t *testing.T) {
	user := &AuthenticatedUser{
		UserID:   "user-123",
		TenantID: "tenant-abc",
	}
	ctx := context.WithValue(context.Background(), ContextKeyUser, user)

	result := GetUserFromContext(ctx)
	require.NotNil(t, result)
	assert.Equal(t, "user-123", result.UserID)

	// Test with missing user
	emptyCtx := context.Background()
	nilResult := GetUserFromContext(emptyCtx)
	assert.Nil(t, nilResult)
}

func TestGetRoleFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyRole, RoleAdmin)

	role, ok := GetRoleFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, RoleAdmin, role)

	// Test with missing role
	emptyCtx := context.Background()
	_, ok = GetRoleFromContext(emptyCtx)
	assert.False(t, ok)
}

func TestGetTenantIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyTenantID, "tenant-abc")

	tenantID := GetTenantIDFromContext(ctx)
	assert.Equal(t, "tenant-abc", tenantID)

	// Test with missing tenant
	emptyCtx := context.Background()
	emptyResult := GetTenantIDFromContext(emptyCtx)
	assert.Empty(t, emptyResult)
}

func TestHasPermissionForOperation(t *testing.T) {
	tests := []struct {
		name      string
		role      Role
		operation string
		expected  bool
	}{
		// super-admin operations
		{"super-admin can manage_tenants", RoleSuperAdmin, "manage_tenants", true},
		{"super-admin can manage_root_ca", RoleSuperAdmin, "manage_root_ca", true},
		{"super-admin can system_config", RoleSuperAdmin, "system_config", true},
		{"super-admin can manage_tenant_ca", RoleSuperAdmin, "manage_tenant_ca", true},
		{"super-admin can create_eab", RoleSuperAdmin, "create_eab", true},
		{"super-admin can revoke_certificate", RoleSuperAdmin, "revoke_certificate", true},
		{"super-admin can read", RoleSuperAdmin, "read", true},
		{"super-admin can write", RoleSuperAdmin, "write", true},

		// admin operations
		{"admin cannot manage_tenants", RoleAdmin, "manage_tenants", false},
		{"admin cannot manage_root_ca", RoleAdmin, "manage_root_ca", false},
		{"admin can manage_tenant_ca", RoleAdmin, "manage_tenant_ca", true},
		{"admin can create_eab", RoleAdmin, "create_eab", true},
		{"admin can revoke_certificate", RoleAdmin, "revoke_certificate", true},
		{"admin can read", RoleAdmin, "read", true},
		{"admin can write", RoleAdmin, "write", true},

		// endorser operations
		{"endorser cannot manage_tenants", RoleEndorser, "manage_tenants", false},
		{"endorser cannot manage_tenant_ca", RoleEndorser, "manage_tenant_ca", false},
		{"endorser can create_eab", RoleEndorser, "create_eab", true},
		{"endorser can endorse_01", RoleEndorser, "endorse_01", true},
		{"endorser cannot revoke_certificate", RoleEndorser, "revoke_certificate", false},
		{"endorser can read", RoleEndorser, "read", true},
		{"endorser can write", RoleEndorser, "write", true},

		// operator operations
		{"operator cannot manage_tenants", RoleOperator, "manage_tenants", false},
		{"operator cannot create_eab", RoleOperator, "create_eab", false},
		{"operator cannot revoke_certificate", RoleOperator, "revoke_certificate", false},
		{"operator can read", RoleOperator, "read", true},
		{"operator can write", RoleOperator, "write", true},

		// viewer operations
		{"viewer cannot manage_tenants", RoleViewer, "manage_tenants", false},
		{"viewer cannot create_eab", RoleViewer, "create_eab", false},
		{"viewer can read", RoleViewer, "read", true},
		{"viewer can list", RoleViewer, "list", true},
		{"viewer cannot write", RoleViewer, "write", false},

		// unknown operations
		{"super-admin cannot unknown_operation", RoleSuperAdmin, "unknown_operation", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasPermissionForOperation(tt.role, tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequireOperation_Success(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyRole, RoleAdmin)

	handler := RequireOperation("manage_tenant_ca")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireOperation_Forbidden(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyRole, RoleViewer)

	handler := RequireOperation("manage_tenant_ca")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireOperation_NoRoleInContext(t *testing.T) {
	ctx := context.Background()

	handler := RequireOperation("read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called without role in context")
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"valid bearer token", "Bearer mytoken123", "mytoken123"},
		{"bearer lowercase", "bearer mytoken123", "mytoken123"},
		{"BEARER uppercase", "BEARER mytoken123", "mytoken123"},
		{"empty header", "", ""},
		{"basic auth", "Basic dXNlcjpwYXNz", ""},
		{"no space", "Bearertoken", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			result := extractBearerToken(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthMiddleware_NilClaims(t *testing.T) {
	client := auth.NewMemoryClient()
	// Don't add any token - ValidateToken will return error for unknown token

	middleware := NewAuthMiddleware(client)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called for nil claims")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer unknown-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireTenant_NoUserInContext(t *testing.T) {
	ctx := context.Background() // No user in context

	getTenantID := func(r *http.Request) string { return "tenant-123" }

	handler := RequireTenant(getTenantID)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called without user in context")
	}))

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHasPermissionForOperation_AdditionalOps(t *testing.T) {
	tests := []struct {
		name      string
		role      Role
		operation string
		expected  bool
	}{
		{"admin can create_intermediate_ca", RoleAdmin, "create_intermediate_ca", true},
		{"admin can create_root_ca", RoleAdmin, "create_root_ca", true},
		{"viewer can get", RoleViewer, "get", true},
		{"operator can create", RoleOperator, "create", true},
		{"operator can update", RoleOperator, "update", true},
		{"admin can disable_account", RoleAdmin, "disable_account", true},
		{"operator cannot disable_account", RoleOperator, "disable_account", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasPermissionForOperation(tt.role, tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}
