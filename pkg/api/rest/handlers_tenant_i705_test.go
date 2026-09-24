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

package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers UpdateTenantEntitlementsHandler and
// UpdateTenantQuotasHandler (go-xkms #705, batch A), neither of which had a
// test. It reuses handlers_tenant_test.go's setupTenantTestHandlers,
// registering the two routes that helper's router does not mount.

func setupTenantEntitlementsRouter(t *testing.T) (*TenantHandlers, *chi.Mux) {
	t.Helper()
	handlers, router := setupTenantTestHandlers(t)
	router.Put("/tenants/{tenantID}/entitlements", handlers.UpdateTenantEntitlementsHandler)
	router.Put("/tenants/{tenantID}/quotas", handlers.UpdateTenantQuotasHandler)
	return handlers, router
}

func TestUpdateTenantEntitlementsHandler_Success(t *testing.T) {
	_, router := setupTenantEntitlementsRouter(t)
	createTenantViaAPI(t, router, "acme", "Acme")

	body, err := json.Marshal(transport.UpdateTenantEntitlementsRequest{
		Entitlements: transport.TenantEntitlements{AllowedIsolationModes: []string{"prefix"}, AllowVolumeStorage: true},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/tenants/acme/entitlements", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp transport.UpdateTenantEntitlementsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "acme", resp.Tenant.ID)
	require.NotNil(t, resp.Tenant.Entitlements)
	assert.True(t, resp.Tenant.Entitlements.AllowVolumeStorage)
}

func TestUpdateTenantEntitlementsHandler_MissingTenantID(t *testing.T) {
	_, router := setupTenantEntitlementsRouter(t)
	req := httptest.NewRequest(http.MethodPut, "/tenants//entitlements", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an empty tenantID segment is a bad request, never an empty-ID update")
}

func TestUpdateTenantEntitlementsHandler_InvalidBody(t *testing.T) {
	_, router := setupTenantEntitlementsRouter(t)
	createTenantViaAPI(t, router, "acme", "Acme")

	req := httptest.NewRequest(http.MethodPut, "/tenants/acme/entitlements", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUpdateTenantEntitlementsHandler_NotFound(t *testing.T) {
	_, router := setupTenantEntitlementsRouter(t)
	req := httptest.NewRequest(http.MethodPut, "/tenants/ghost/entitlements", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusOK, rec.Code)
}

func TestUpdateTenantEntitlementsHandler_ServiceNotConfigured(t *testing.T) {
	// The zero-value TenantHandlers models a server whose composition root
	// never wired a servicer at all -- NewTenantHandlers itself refuses that
	// combination, so this exercises the handler's own defensive nil check
	// directly rather than going unreachable.
	handlers := &TenantHandlers{}
	router := chi.NewRouter()
	router.Put("/tenants/{tenantID}/entitlements", handlers.UpdateTenantEntitlementsHandler)

	req := httptest.NewRequest(http.MethodPut, "/tenants/acme/entitlements", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestUpdateTenantQuotasHandler_Success(t *testing.T) {
	_, router := setupTenantEntitlementsRouter(t)
	createTenantViaAPI(t, router, "acme", "Acme")

	body, err := json.Marshal(transport.UpdateTenantQuotasRequest{
		Quotas: transport.TenantQuotas{MaxKeys: 100},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/tenants/acme/quotas", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp transport.UpdateTenantQuotasResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "acme", resp.Tenant.ID)
	require.NotNil(t, resp.Tenant.Quotas)
	assert.Equal(t, int64(100), resp.Tenant.Quotas.MaxKeys)
}

func TestUpdateTenantQuotasHandler_InvalidBody(t *testing.T) {
	_, router := setupTenantEntitlementsRouter(t)
	createTenantViaAPI(t, router, "acme", "Acme")

	req := httptest.NewRequest(http.MethodPut, "/tenants/acme/quotas", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUpdateTenantQuotasHandler_ServiceNotConfigured(t *testing.T) {
	handlers := &TenantHandlers{}
	router := chi.NewRouter()
	router.Put("/tenants/{tenantID}/quotas", handlers.UpdateTenantQuotasHandler)

	req := httptest.NewRequest(http.MethodPut, "/tenants/acme/quotas", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
