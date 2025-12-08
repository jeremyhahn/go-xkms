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

package rest

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRBACMiddleware(t *testing.T) (*RBACMiddleware, *rbac.MemoryRBACAdapter) {
	t.Helper()
	adapter := rbac.NewMemoryRBACAdapter(true)
	// Create a discard logger for tests
	discardLogger := logger.NewSlogAdapter(&logger.SlogConfig{
		Handler: slog.NewTextHandler(io.Discard, nil),
	})

	middleware := NewRBACMiddleware(&RBACConfig{
		Adapter:   adapter,
		Logger:    discardLogger,
		SkipPaths: map[string]bool{"/health": true},
	})

	return middleware, adapter
}

func TestNewRBACMiddleware(t *testing.T) {
	adapter := rbac.NewMemoryRBACAdapter(true)
	discardLogger := logger.NewSlogAdapter(&logger.SlogConfig{
		Handler: slog.NewTextHandler(io.Discard, nil),
	})

	t.Run("creates middleware with config", func(t *testing.T) {
		middleware := NewRBACMiddleware(&RBACConfig{
			Adapter:   adapter,
			Logger:    discardLogger,
			SkipPaths: map[string]bool{"/health": true},
		})
		assert.NotNil(t, middleware)
	})

	t.Run("initializes empty SkipPaths if nil", func(t *testing.T) {
		middleware := NewRBACMiddleware(&RBACConfig{
			Adapter:   adapter,
			Logger:    discardLogger,
			SkipPaths: nil,
		})
		assert.NotNil(t, middleware.skipPaths)
	})
}

func TestRBACMiddleware_RequirePermission(t *testing.T) {
	middleware, adapter := newTestRBACMiddleware(t)
	ctx := context.Background()

	// Create test users
	_ = adapter.AssignRole(ctx, "admin@example.com", rbac.RoleAdmin)
	_ = adapter.AssignRole(ctx, "user@example.com", rbac.RoleUser)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	t.Run("grants access with valid permission", func(t *testing.T) {
		handler := middleware.RequirePermission(rbac.ResourceKeys, rbac.ActionCreate)(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", nil)
		// Add identity to context
		identity := &auth.Identity{Subject: "admin@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})

	t.Run("denies access without permission", func(t *testing.T) {
		handler := middleware.RequirePermission(rbac.ResourceKeys, rbac.ActionDelete)(nextHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/123", nil)
		// User role cannot delete keys
		identity := &auth.Identity{Subject: "user@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("returns 401 without identity", func(t *testing.T) {
		handler := middleware.RequirePermission(rbac.ResourceKeys, rbac.ActionRead)(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		// No identity in context

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 403 for nonexistent user", func(t *testing.T) {
		handler := middleware.RequirePermission(rbac.ResourceKeys, rbac.ActionRead)(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		identity := &auth.Identity{Subject: "nonexistent@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestRBACMiddleware_RequireRole(t *testing.T) {
	middleware, adapter := newTestRBACMiddleware(t)
	ctx := context.Background()

	// Create test users
	_ = adapter.AssignRole(ctx, "admin@example.com", rbac.RoleAdmin)
	_ = adapter.AssignRole(ctx, "operator@example.com", rbac.RoleOperator)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	t.Run("grants access with correct role", func(t *testing.T) {
		handler := middleware.RequireRole(rbac.RoleAdmin)(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		identity := &auth.Identity{Subject: "admin@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("denies access with wrong role", func(t *testing.T) {
		handler := middleware.RequireRole(rbac.RoleAdmin)(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		identity := &auth.Identity{Subject: "operator@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("returns 401 without identity", func(t *testing.T) {
		handler := middleware.RequireRole(rbac.RoleAdmin)(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestRBACMiddleware_RequireAnyRole(t *testing.T) {
	middleware, adapter := newTestRBACMiddleware(t)
	ctx := context.Background()

	// Create test users
	_ = adapter.AssignRole(ctx, "admin@example.com", rbac.RoleAdmin)
	_ = adapter.AssignRole(ctx, "operator@example.com", rbac.RoleOperator)
	_ = adapter.AssignRole(ctx, "user@example.com", rbac.RoleUser)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	t.Run("grants access with any matching role", func(t *testing.T) {
		handler := middleware.RequireAnyRole(rbac.RoleAdmin, rbac.RoleOperator)(nextHandler)

		// Admin has access
		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		identity := &auth.Identity{Subject: "admin@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Operator also has access
		req = httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		identity = &auth.Identity{Subject: "operator@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("denies access without matching role", func(t *testing.T) {
		handler := middleware.RequireAnyRole(rbac.RoleAdmin, rbac.RoleOperator)(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		identity := &auth.Identity{Subject: "user@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("returns 401 without identity", func(t *testing.T) {
		handler := middleware.RequireAnyRole(rbac.RoleAdmin, rbac.RoleOperator)(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestUserRoleContext(t *testing.T) {
	t.Run("stores and retrieves role", func(t *testing.T) {
		ctx := context.Background()
		ctx = WithUserRole(ctx, "admin")

		role := GetUserRole(ctx)
		assert.Equal(t, "admin", role)
	})

	t.Run("returns empty string for missing role", func(t *testing.T) {
		ctx := context.Background()
		role := GetUserRole(ctx)
		assert.Equal(t, "", role)
	})
}

func TestPermissionConstants(t *testing.T) {
	// Verify permission constants are correctly defined
	tests := []struct {
		name       string
		permission rbac.Permission
		resource   string
		action     string
	}{
		{"PermissionKeysCreate", PermissionKeysCreate, rbac.ResourceKeys, rbac.ActionCreate},
		{"PermissionKeysRead", PermissionKeysRead, rbac.ResourceKeys, rbac.ActionRead},
		{"PermissionKeysList", PermissionKeysList, rbac.ResourceKeys, rbac.ActionList},
		{"PermissionKeysDelete", PermissionKeysDelete, rbac.ResourceKeys, rbac.ActionDelete},
		{"PermissionKeysSign", PermissionKeysSign, rbac.ResourceKeys, rbac.ActionSign},
		{"PermissionKeysVerify", PermissionKeysVerify, rbac.ResourceKeys, rbac.ActionVerify},
		{"PermissionKeysEncrypt", PermissionKeysEncrypt, rbac.ResourceKeys, rbac.ActionEncrypt},
		{"PermissionKeysDecrypt", PermissionKeysDecrypt, rbac.ResourceKeys, rbac.ActionDecrypt},
		{"PermissionKeysRotate", PermissionKeysRotate, rbac.ResourceKeys, rbac.ActionRotate},
		{"PermissionKeysImport", PermissionKeysImport, rbac.ResourceKeys, rbac.ActionImport},
		{"PermissionKeysExport", PermissionKeysExport, rbac.ResourceKeys, rbac.ActionExport},
		{"PermissionCertsCreate", PermissionCertsCreate, rbac.ResourceCertificates, rbac.ActionCreate},
		{"PermissionCertsRead", PermissionCertsRead, rbac.ResourceCertificates, rbac.ActionRead},
		{"PermissionCertsList", PermissionCertsList, rbac.ResourceCertificates, rbac.ActionList},
		{"PermissionCertsDelete", PermissionCertsDelete, rbac.ResourceCertificates, rbac.ActionDelete},
		{"PermissionUsersCreate", PermissionUsersCreate, rbac.ResourceUsers, rbac.ActionCreate},
		{"PermissionUsersRead", PermissionUsersRead, rbac.ResourceUsers, rbac.ActionRead},
		{"PermissionUsersList", PermissionUsersList, rbac.ResourceUsers, rbac.ActionList},
		{"PermissionUsersUpdate", PermissionUsersUpdate, rbac.ResourceUsers, rbac.ActionUpdate},
		{"PermissionUsersDelete", PermissionUsersDelete, rbac.ResourceUsers, rbac.ActionDelete},
		{"PermissionBackendsList", PermissionBackendsList, rbac.ResourceBackends, rbac.ActionList},
		{"PermissionBackendsRead", PermissionBackendsRead, rbac.ResourceBackends, rbac.ActionRead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.resource, tt.permission.Resource)
			require.Equal(t, tt.action, tt.permission.Action)
		})
	}
}
