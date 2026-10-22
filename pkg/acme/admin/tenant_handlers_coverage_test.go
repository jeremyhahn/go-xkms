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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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
