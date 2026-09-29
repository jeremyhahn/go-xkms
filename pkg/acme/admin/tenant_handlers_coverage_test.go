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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestCheckTenantAccess_SuperAdmin(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())
	user := createPlatformAdminUser()

	req := httptest.NewRequest("GET", "/api/v1/tenants/any-tenant", nil)
	req = req.WithContext(withUser(context.Background(), user))
	w := httptest.NewRecorder()

	assert.True(t, handlers.checkTenantAccess(w, req, "get tenant", "any-tenant"))
	assert.Equal(t, 0, w.Body.Len(), "an admitted request must not be answered")
}

func TestCheckTenantAccess_SameTenant(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())
	user := createAdminUser("tenant-1")

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1", nil)
	req = req.WithContext(withUser(context.Background(), user))
	w := httptest.NewRecorder()

	assert.True(t, handlers.checkTenantAccess(w, req, "get tenant", "tenant-1"))
	assert.Equal(t, 0, w.Body.Len(), "an admitted request must not be answered")
}

// TestCheckTenantAccess_CrossTenantDenied proves a foreign tenant is answered
// exactly as a missing one (go-xkms#1112, #1225).
func TestCheckTenantAccess_CrossTenantDenied(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())
	user := createAdminUser("tenant-1")

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-2", nil)
	req = req.WithContext(withUser(context.Background(), user))
	w := httptest.NewRecorder()

	assert.False(t, handlers.checkTenantAccess(w, req, "get tenant", "tenant-2"))
	missing := httptest.NewRecorder()
	writeTenantNotFound(missing)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, missing.Body.String(), w.Body.String())
}

// TestCheckTenantAccess_Unauthenticated proves a request with no caller is
// answered 401 and not admitted.
func TestCheckTenantAccess_Unauthenticated(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1", nil)
	w := httptest.NewRecorder()

	assert.False(t, handlers.checkTenantAccess(w, req, "get tenant", "tenant-1"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTenant_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.GetTenant(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTenant_ForeignTenantNotFound(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/other-tenant", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.GetTenant(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTenantHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		getTenantFunc: func(ctx context.Context, tenantID string) (*TenantInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createPlatformAdminUser())
	w := httptest.NewRecorder()

	handlers.GetTenant(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateTenant_Unauthorized(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"name": "Updated Tenant"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/tenant-1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	// No user in context
	w := httptest.NewRecorder()

	handlers.UpdateTenant(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateTenant_ForeignTenantNotFound(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"name": "Updated Tenant"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/other-tenant", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.UpdateTenant(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateTenant_InternalError(t *testing.T) {
	service := &mockTenantService{
		createTenantFunc: func(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error) {
			return nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	body := `{"id": "new-tenant", "name": "New Tenant"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handlers.CreateTenant(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteTenantHandler_Success(t *testing.T) {
	service := &mockTenantService{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createPlatformAdminUser())
	w := httptest.NewRecorder()

	handlers.DeleteTenant(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteTenantHandler_NotFound(t *testing.T) {
	service := &mockTenantService{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return ErrTenantNotFound
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	req = addUserToRequest(req, createPlatformAdminUser())
	w := httptest.NewRecorder()

	handlers.DeleteTenant(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteTenantHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/tenant-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tenant-1"})
	req = addUserToRequest(req, createPlatformAdminUser())
	w := httptest.NewRecorder()

	handlers.DeleteTenant(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListTenantsHandler_Success(t *testing.T) {
	now := time.Now()
	service := &mockTenantService{
		listTenantsFunc: func(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
			return []*TenantInfo{
				{ID: "tenant-1", Name: "Tenant 1", Status: "active", CreatedAt: now},
				{ID: "tenant-2", Name: "Tenant 2", Status: "active", CreatedAt: now},
			}, &Pagination{Page: 1, PerPage: 20, Total: 2}, nil
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	req = addUserToRequest(req, createPlatformAdminUser())
	w := httptest.NewRecorder()

	handlers.ListTenants(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListTenantsHandler_InternalError(t *testing.T) {
	service := &mockTenantService{
		listTenantsFunc: func(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
			return nil, nil, errors.New("database error")
		},
	}
	handlers := NewTenantHandlers(service, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	req = addUserToRequest(req, createPlatformAdminUser())
	w := httptest.NewRecorder()

	handlers.ListTenants(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
