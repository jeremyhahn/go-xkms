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
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTenantLogger returns a quiet logger for tenant handler tests.
func testTenantLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testTenantRegistry creates an initialized BarrierRegistry backed by
// an in-memory storage backend and the SoftwareStrategy. The barrier
// is initialized and unsealed so tenant registration works immediately.
func testTenantRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		testTenantLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: "test-password"}
	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// setupTenantTestHandlers creates TenantHandlers backed by a real
// BarrierRegistry and mounts them on a chi router with the expected
// route patterns.
func setupTenantTestHandlers(t *testing.T) (*TenantHandlers, *chi.Mux) {
	t.Helper()
	registry := testTenantRegistry(t)
	handlers := NewTenantHandlers(registry)
	r := chi.NewRouter()
	r.Route("/tenants", func(r chi.Router) {
		r.Post("/", handlers.CreateTenantHandler)
		r.Get("/", handlers.ListTenantsHandler)
		r.Get("/{tenantID}", handlers.GetTenantHandler)
		r.Delete("/{tenantID}", handlers.DeleteTenantHandler)
		r.Get("/{tenantID}/barrier/status", handlers.TenantBarrierStatusHandler)
		r.Post("/{tenantID}/barrier/init", handlers.TenantBarrierInitHandler)
		r.Post("/{tenantID}/barrier/unseal", handlers.TenantBarrierUnsealHandler)
	})
	return handlers, r
}

// setupNilRegistryHandlers creates TenantHandlers with a nil registry
// and mounts them on a chi router.
func setupNilRegistryHandlers(t *testing.T) *chi.Mux {
	t.Helper()
	handlers := NewTenantHandlers(nil)
	r := chi.NewRouter()
	r.Route("/tenants", func(r chi.Router) {
		r.Post("/", handlers.CreateTenantHandler)
		r.Get("/", handlers.ListTenantsHandler)
		r.Get("/{tenantID}", handlers.GetTenantHandler)
		r.Delete("/{tenantID}", handlers.DeleteTenantHandler)
		r.Get("/{tenantID}/barrier/status", handlers.TenantBarrierStatusHandler)
		r.Post("/{tenantID}/barrier/init", handlers.TenantBarrierInitHandler)
		r.Post("/{tenantID}/barrier/unseal", handlers.TenantBarrierUnsealHandler)
	})
	return r
}

// createTenantViaAPI is a helper that POSTs a tenant creation request and
// returns the HTTP response recorder.
func createTenantViaAPI(t *testing.T, router *chi.Mux, id, name string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(createTenantRequest{ID: id, Name: name})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tenants/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// --- CreateTenantHandler tests ---

func TestCreateTenantHandler_Success(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "acme-corp", "Acme Corporation")
	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp wrappedTenantResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", resp.Tenant.ID)
	assert.Equal(t, "Acme Corporation", resp.Tenant.Name)
}

func TestCreateTenantHandler_InvalidRequest(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/tenants/", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "invalid request")
}

func TestCreateTenantHandler_MissingID(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	body, err := json.Marshal(createTenantRequest{Name: "No ID Tenant"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tenants/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp ErrorResponse
	err = json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "missing tenant_id")
}

func TestCreateTenantHandler_MissingName(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	body, err := json.Marshal(createTenantRequest{ID: "no-name-tenant"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tenants/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp ErrorResponse
	err = json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "missing tenant name")
}

func TestCreateTenantHandler_Duplicate(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "dup-tenant", "Dup Tenant")
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = createTenantViaAPI(t, router, "dup-tenant", "Dup Tenant Again")
	assert.Equal(t, http.StatusConflict, rec.Code)

	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "tenant already exists")
}

// --- ListTenantsHandler tests ---

func TestListTenantsHandler_Empty(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/tenants/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp listTenantsResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Empty(t, resp.Tenants)
}

func TestListTenantsHandler_WithTenants(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "alpha-org", "Alpha Organization")
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = createTenantViaAPI(t, router, "beta-org", "Beta Organization")
	require.Equal(t, http.StatusCreated, rec.Code)

	req := httptest.NewRequest(http.MethodGet, "/tenants/", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp listTenantsResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	require.Len(t, resp.Tenants, 2)

	// ListTenants returns sorted IDs, so the response order is deterministic.
	assert.Equal(t, "alpha-org", resp.Tenants[0].ID)
	assert.Equal(t, "beta-org", resp.Tenants[1].ID)
}

// --- GetTenantHandler tests ---

func TestGetTenantHandler_Success(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "get-tenant", "Get Tenant")
	require.Equal(t, http.StatusCreated, rec.Code)

	req := httptest.NewRequest(http.MethodGet, "/tenants/get-tenant", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp wrappedTenantResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "get-tenant", resp.Tenant.ID)
}

func TestGetTenantHandler_NotFound(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/tenants/nonexistent", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "tenant not found")
}

// --- DeleteTenantHandler tests ---

func TestDeleteTenantHandler_Success(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "del-tenant", "Delete Tenant")
	require.Equal(t, http.StatusCreated, rec.Code)

	req := httptest.NewRequest(http.MethodDelete, "/tenants/del-tenant", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Verify the tenant is removed by attempting GET.
	req = httptest.NewRequest(http.MethodGet, "/tenants/del-tenant", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDeleteTenantHandler_NotFound(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/tenants/nonexistent", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "tenant not found")
}

// --- TenantBarrierStatusHandler tests ---

func TestTenantBarrierStatusHandler_Success(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "status-tenant", "Status Tenant")
	require.Equal(t, http.StatusCreated, rec.Code)

	req := httptest.NewRequest(http.MethodGet, "/tenants/status-tenant/barrier/status", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tenantBarrierStatusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "status-tenant", resp.TenantID)
	// Newly registered tenant barrier starts sealed (independent DEK,
	// not yet initialized).
	assert.True(t, resp.Sealed)
}

func TestTenantBarrierStatusHandler_NotFound(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/tenants/nonexistent/barrier/status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "tenant not found")
}

// --- TenantBarrierInitHandler tests ---

func TestTenantBarrierInitHandler_Success(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "init-tenant", "Init Tenant")
	require.Equal(t, http.StatusCreated, rec.Code)

	// Initialize the tenant barrier (generates independent DEK).
	body, err := json.Marshal(tenantBarrierInitRequest{Threshold: 2, Shares: 3})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tenants/init-tenant/barrier/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tenantBarrierStatusResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "init-tenant", resp.TenantID)
	// After initialization, tenant barrier is unsealed.
	assert.False(t, resp.Sealed)
	assert.Equal(t, seal.StrategySoftware, resp.Strategy)
}

func TestTenantBarrierInitHandler_NotFound(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	body, err := json.Marshal(tenantBarrierInitRequest{Threshold: 2, Shares: 3})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tenants/nonexistent/barrier/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestTenantBarrierInitHandler_InvalidBody(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "init-bad-body", "Init Bad Body")
	require.Equal(t, http.StatusCreated, rec.Code)

	req := httptest.NewRequest(http.MethodPost, "/tenants/init-bad-body/barrier/init", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- TenantBarrierUnsealHandler tests ---

func TestTenantBarrierUnsealHandler_Success(t *testing.T) {
	registry := testTenantRegistry(t)
	handlers := NewTenantHandlers(registry)
	r := chi.NewRouter()
	r.Route("/tenants", func(r chi.Router) {
		r.Post("/", handlers.CreateTenantHandler)
		r.Post("/{tenantID}/barrier/init", handlers.TenantBarrierInitHandler)
		r.Post("/{tenantID}/barrier/unseal", handlers.TenantBarrierUnsealHandler)
	})

	// Create tenant.
	rec := createTenantViaAPI(t, r, "unseal-tenant", "Unseal Tenant")
	require.Equal(t, http.StatusCreated, rec.Code)

	// Initialize the tenant barrier first.
	initBody, err := json.Marshal(tenantBarrierInitRequest{Threshold: 2, Shares: 3})
	require.NoError(t, err)
	initReq := httptest.NewRequest(http.MethodPost, "/tenants/unseal-tenant/barrier/init", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", "application/json")
	initRec := httptest.NewRecorder()
	r.ServeHTTP(initRec, initReq)
	require.Equal(t, http.StatusOK, initRec.Code)

	// Seal the tenant barrier so we can test unseal.
	err = registry.SealTenant("unseal-tenant")
	require.NoError(t, err)

	// Unseal the tenant barrier with the init credentials.
	body, err := json.Marshal(tenantBarrierUnsealRequest{Key: []byte("tenant-init")})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tenants/unseal-tenant/barrier/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp tenantBarrierStatusResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "unseal-tenant", resp.TenantID)
	assert.False(t, resp.Sealed)
}

func TestTenantBarrierUnsealHandler_NotFound(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	body, err := json.Marshal(tenantBarrierUnsealRequest{Key: []byte("test-key")})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tenants/nonexistent/barrier/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestTenantBarrierUnsealHandler_InvalidBody(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "unseal-bad-body", "Unseal Bad Body")
	require.Equal(t, http.StatusCreated, rec.Code)

	req := httptest.NewRequest(http.MethodPost, "/tenants/unseal-bad-body/barrier/unseal", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Nil registry tests ---

func TestTenantHandlers_NilRegistry(t *testing.T) {
	router := setupNilRegistryHandlers(t)

	tests := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{
			name:   "CreateTenant",
			method: http.MethodPost,
			path:   "/tenants/",
			body:   []byte(`{"id":"test","name":"test"}`),
		},
		{
			name:   "ListTenants",
			method: http.MethodGet,
			path:   "/tenants/",
		},
		{
			name:   "GetTenant",
			method: http.MethodGet,
			path:   "/tenants/some-id",
		},
		{
			name:   "DeleteTenant",
			method: http.MethodDelete,
			path:   "/tenants/some-id",
		},
		{
			name:   "BarrierStatus",
			method: http.MethodGet,
			path:   "/tenants/some-id/barrier/status",
		},
		{
			name:   "BarrierInit",
			method: http.MethodPost,
			path:   "/tenants/some-id/barrier/init",
			body:   []byte(`{"threshold":2,"shares":3}`),
		},
		{
			name:   "BarrierUnseal",
			method: http.MethodPost,
			path:   "/tenants/some-id/barrier/unseal",
			body:   []byte(`{"key":"dGVzdA=="}`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader *bytes.Reader
			if tc.body != nil {
				bodyReader = bytes.NewReader(tc.body)
			} else {
				bodyReader = bytes.NewReader(nil)
			}

			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			if tc.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
				"expected 503 for %s with nil registry", tc.name)

			var errResp ErrorResponse
			err := json.NewDecoder(rec.Body).Decode(&errResp)
			require.NoError(t, err)
			assert.Contains(t, errResp.Error, "tenant service not configured")
		})
	}
}

// --- handleTenantError tests ---

func TestHandleTenantError_MappedErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "TenantNotFound",
			err:        seal.ErrTenantNotFound,
			wantStatus: http.StatusNotFound,
			wantMsg:    "tenant not found",
		},
		{
			name:       "TenantAlreadyExists",
			err:        seal.ErrTenantAlreadyExists,
			wantStatus: http.StatusConflict,
			wantMsg:    "tenant already exists",
		},
		{
			name:       "EmptyTenantID",
			err:        seal.ErrEmptyTenantID,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "tenant ID must not be empty",
		},
		{
			name:       "Sealed",
			err:        seal.ErrSealed,
			wantStatus: http.StatusServiceUnavailable,
			wantMsg:    "barrier is sealed",
		},
		{
			name:       "NotInitialized",
			err:        seal.ErrNotInitialized,
			wantStatus: http.StatusPreconditionFailed,
			wantMsg:    "barrier not initialized",
		},
		{
			name:       "AlreadyInitialized",
			err:        seal.ErrAlreadyInitialized,
			wantStatus: http.StatusConflict,
			wantMsg:    "barrier already initialized",
		},
		{
			name:       "AlreadyUnsealed",
			err:        seal.ErrAlreadyUnsealed,
			wantStatus: http.StatusConflict,
			wantMsg:    "barrier is already unsealed",
		},
		{
			name:       "NilSystemBarrier",
			err:        seal.ErrNilSystemBarrier,
			wantStatus: http.StatusServiceUnavailable,
			wantMsg:    "system barrier must not be nil",
		},
		{
			name:       "UnknownError",
			err:        assert.AnError,
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handleTenantError(rec, tc.err)

			assert.Equal(t, tc.wantStatus, rec.Code)

			var errResp ErrorResponse
			err := json.NewDecoder(rec.Body).Decode(&errResp)
			require.NoError(t, err)
			assert.Contains(t, errResp.Error, tc.wantMsg)
		})
	}
}

// --- Edge case: CreateTenantHandler with empty JSON body ---

func TestCreateTenantHandler_EmptyBody(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/tenants/", bytes.NewReader([]byte("")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- CreateTenantHandler sealed field reflects tenant barrier state ---

func TestCreateTenantHandler_SealedField(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	rec := createTenantViaAPI(t, router, "sealed-check", "Sealed Check")
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp wrappedTenantResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	// Newly created tenant barrier starts sealed (independent DEK,
	// not yet initialized).
	assert.True(t, resp.Tenant.Sealed)
}

// --- Tenant filtering tests ---

// TestListTenantsHandler_TenantFiltering tests tenant-scoped filtering for ListTenantsHandler.
func TestListTenantsHandler_TenantFiltering(t *testing.T) {
	t.Run("SO sees all tenants", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-a", "Tenant A")
		require.Equal(t, http.StatusCreated, rec.Code)

		rec = createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/", nil)
		identity := &auth.Identity{Subject: "so-admin", TenantID: ""}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp listTenantsResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Tenants, 2)
	})

	t.Run("tenant user sees only own tenant", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-a", "Tenant A")
		require.Equal(t, http.StatusCreated, rec.Code)

		rec = createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/", nil)
		identity := &auth.Identity{Subject: "user-a", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp listTenantsResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		require.Len(t, resp.Tenants, 1)
		assert.Equal(t, "tenant-a", resp.Tenants[0].ID)
	})

	t.Run("no identity returns all tenants", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-a", "Tenant A")
		require.Equal(t, http.StatusCreated, rec.Code)

		rec = createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/", nil)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp listTenantsResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Tenants, 2)
	})
}

// TestGetTenantHandler_TenantFiltering tests tenant-scoped filtering for GetTenantHandler.
func TestGetTenantHandler_TenantFiltering(t *testing.T) {
	t.Run("SO can access any tenant", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/tenant-b", nil)
		identity := &auth.Identity{Subject: "so-admin", TenantID: ""}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp wrappedTenantResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "tenant-b", resp.Tenant.ID)
	})

	t.Run("tenant user gets 404 for other tenant", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/tenant-b", nil)
		identity := &auth.Identity{Subject: "user-a", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)

		var errResp ErrorResponse
		err := json.NewDecoder(rec.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp.Error, "tenant not found")
	})

	t.Run("tenant user can access own tenant", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-a", "Tenant A")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/tenant-a", nil)
		identity := &auth.Identity{Subject: "user-a", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp wrappedTenantResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", resp.Tenant.ID)
	})
}

// TestDeleteTenantHandler_TenantFiltering tests tenant-scoped filtering for DeleteTenantHandler.
func TestDeleteTenantHandler_TenantFiltering(t *testing.T) {
	t.Run("tenant user gets 404 for cross-tenant delete", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodDelete, "/tenants/tenant-b", nil)
		identity := &auth.Identity{Subject: "user-a", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)

		var errResp ErrorResponse
		err := json.NewDecoder(rec.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp.Error, "tenant not found")
	})

	t.Run("SO can delete any tenant", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodDelete, "/tenants/tenant-b", nil)
		identity := &auth.Identity{Subject: "so-admin", TenantID: ""}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}

// TestTenantBarrierStatusHandler_TenantFiltering tests tenant-scoped access for barrier status.
func TestTenantBarrierStatusHandler_TenantFiltering(t *testing.T) {
	t.Run("tenant user gets 404 for other tenant barrier status", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/tenant-b/barrier/status", nil)
		identity := &auth.Identity{Subject: "user-a", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("SO can view any tenant barrier status", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/tenant-b/barrier/status", nil)
		identity := &auth.Identity{Subject: "so-admin", TenantID: ""}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestTenantBarrierInitHandler_TenantFiltering tests tenant-scoped access for barrier init.
func TestTenantBarrierInitHandler_TenantFiltering(t *testing.T) {
	t.Run("tenant user gets 404 for other tenant barrier init", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		body, err := json.Marshal(tenantBarrierInitRequest{Threshold: 2, Shares: 3})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/tenants/tenant-b/barrier/init", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		identity := &auth.Identity{Subject: "user-a", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// TestTenantBarrierUnsealHandler_TenantFiltering tests tenant-scoped access for barrier unseal.
func TestTenantBarrierUnsealHandler_TenantFiltering(t *testing.T) {
	t.Run("tenant user gets 404 for other tenant barrier unseal", func(t *testing.T) {
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		body, err := json.Marshal(tenantBarrierUnsealRequest{Key: []byte("test-key")})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/tenants/tenant-b/barrier/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		identity := &auth.Identity{Subject: "user-a", TenantID: "tenant-a"}
		ctx := auth.WithIdentity(req.Context(), identity)
		req = req.WithContext(ctx)

		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
