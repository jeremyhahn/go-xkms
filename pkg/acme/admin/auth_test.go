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
	xkmsauth "github.com/jeremyhahn/go-xkms/pkg/auth"
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
	var capturedCtx context.Context
	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserFromContext(r.Context())
		capturedCtx = r.Context()
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
	assert.Equal(t, []string{"admin"}, capturedUser.Roles)

	// The middleware must publish the canonical identity the qrdb-backed
	// PermissionGate reads.
	identity := xkmsauth.GetIdentity(capturedCtx)
	require.NotNil(t, identity)
	assert.Equal(t, "user-123", identity.Subject)
	assert.Equal(t, "tenant-abc", identity.TenantID)
	assert.Equal(t, []string{"admin"}, identity.Roles)
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

// tenantScopedRequest builds a request whose context carries a canonical
// identity, exactly as the auth middleware publishes it.
func tenantScopedRequest(tenantID string, roles ...string) *http.Request {
	user := &AuthenticatedUser{UserID: "user-123", TenantID: tenantID, Roles: roles}
	req := httptest.NewRequest("GET", "/test", nil)
	return req.WithContext(withUser(req.Context(), user))
}

// TestRequireTenant_SameTenant verifies a tenant-scoped identity reaches its own
// tenant.
func TestRequireTenant_SameTenant(t *testing.T) {
	handler := RequireTenant(func(r *http.Request) string { return "tenant-abc" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, tenantScopedRequest("tenant-abc", "admin"))
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequireTenant_DifferentTenant verifies a tenant-scoped identity is
// confined to its own tenant, whatever role it holds, and that the refusal
// reads exactly like a missing tenant.
func TestRequireTenant_DifferentTenant(t *testing.T) {
	handler := RequireTenant(func(r *http.Request) string { return "tenant-xyz" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("Handler should not be called")
		}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, tenantScopedRequest("tenant-abc", "admin"))
	missing := httptest.NewRecorder()
	writeTenantNotFound(missing)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, missing.Body.String(), w.Body.String())
}

// TestRequireTenant_SystemTenantReachesAnyTenant verifies qrdb's system-tenant
// rule replaces the deleted "super-admin can access any tenant" check.
func TestRequireTenant_SystemTenantReachesAnyTenant(t *testing.T) {
	handler := RequireTenant(func(r *http.Request) string { return "tenant-xyz" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, tenantScopedRequest("", "admin"))
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequireTenant_EmptyTenantID verifies a request that names no target
// tenant is rejected as a bad request rather than defaulting to allow.
func TestRequireTenant_EmptyTenantID(t *testing.T) {
	handler := RequireTenant(func(r *http.Request) string { return "" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("Handler should not be called")
		}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, tenantScopedRequest("tenant-abc", "admin"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
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

func TestGetTenantIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyTenantID, "tenant-abc")

	tenantID := GetTenantIDFromContext(ctx)
	assert.Equal(t, "tenant-abc", tenantID)

	// Test with missing tenant
	emptyCtx := context.Background()
	emptyResult := GetTenantIDFromContext(emptyCtx)
	assert.Empty(t, emptyResult)
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
