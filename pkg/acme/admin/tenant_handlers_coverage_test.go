//go:build codec_json

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

// createViewerUser creates an AuthenticatedUser with viewer role for testing
func createViewerUser(tenantID string) *AuthenticatedUser {
	return &AuthenticatedUser{
		UserID:   "viewer-user-1",
		Username: "viewer",
		Email:    "viewer@example.com",
		Role:     RoleViewer,
		TenantID: tenantID,
		Roles:    []string{string(RoleViewer)},
		Groups:   []string{"viewers"},
	}
}

// createEndorserUser creates an AuthenticatedUser with endorser role for testing
func createEndorserUser(tenantID string) *AuthenticatedUser {
	return &AuthenticatedUser{
		UserID:   "endorser-user-1",
		Username: "endorser",
		Email:    "endorser@example.com",
		Role:     RoleEndorser,
		TenantID: tenantID,
		Roles:    []string{string(RoleEndorser)},
		Groups:   []string{"endorsers"},
	}
}

func TestCheckTenantAccess_SuperAdmin(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())
	user := createSuperAdminUser()

	req := httptest.NewRequest("GET", "/api/v1/tenants/any-tenant", nil)
	err := handlers.checkTenantAccess(context.Background(), req, user, "any-tenant", ActionRead)

	assert.NoError(t, err)
}

func TestCheckTenantAccess_SameTenant(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())
	user := createAdminUser("tenant-1")

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-1", nil)
	err := handlers.checkTenantAccess(context.Background(), req, user, "tenant-1", ActionRead)

	assert.NoError(t, err)
}

func TestCheckTenantAccess_CrossTenantDenied(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())
	user := createAdminUser("tenant-1")

	req := httptest.NewRequest("GET", "/api/v1/tenants/tenant-2", nil)
	err := handlers.checkTenantAccess(context.Background(), req, user, "tenant-2", ActionRead)

	assert.Equal(t, ErrForbidden, err)
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

func TestGetTenant_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	req := httptest.NewRequest("GET", "/api/v1/tenants/other-tenant", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.GetTenant(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
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
	req = addUserToRequest(req, createSuperAdminUser())
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

func TestUpdateTenant_Forbidden(t *testing.T) {
	handlers := NewTenantHandlers(&mockTenantService{}, slog.Default())

	body := `{"name": "Updated Tenant"}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/other-tenant", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "other-tenant"})
	req = addUserToRequest(req, createAdminUser("my-tenant"))
	w := httptest.NewRecorder()

	handlers.UpdateTenant(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
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
	req = addUserToRequest(req, createSuperAdminUser())
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
	req = addUserToRequest(req, createSuperAdminUser())
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
	req = addUserToRequest(req, createSuperAdminUser())
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
	req = addUserToRequest(req, createSuperAdminUser())
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
	req = addUserToRequest(req, createSuperAdminUser())
	w := httptest.NewRecorder()

	handlers.ListTenants(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
