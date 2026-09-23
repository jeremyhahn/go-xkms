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
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
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
// It also returns the configured XKMSService for injection into TenantHandlers.
func testTenantRegistry(t *testing.T) (*seal.BarrierRegistry, *xkms.XKMSService) {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		testTenantLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.MustCredentials([]byte("test-password"))
	defer creds.Secret.Destroy()
	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	// The tenant CRUD and barrier init/unseal/status handlers all route
	// through the XKMSService servicer, which requires a composed
	// TenantService (there is no barrier-registry-only fallback). Build a
	// real go-qrdb TenantService over the same barrier registry the
	// handlers' tenantSealed() helper reads, so both paths agree.
	tenantSvc, err := seal.NewHardwareTenantService(barrier, registry, testTenantLogger(), nil)
	require.NoError(t, err)

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetTenantService(tenantSvc)
	t.Cleanup(func() { xkms.Reset() })

	return registry, svc
}

// setupTenantTestHandlers creates TenantHandlers backed by a real
// BarrierRegistry and mounts them on a chi router with the expected
// route patterns.
func setupTenantTestHandlers(t *testing.T) (*TenantHandlers, *chi.Mux) {
	t.Helper()
	registry, svc := testTenantRegistry(t)
	handlers, err := NewTenantHandlers(registry, svc)
	require.NoError(t, err)
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
	assert.Contains(t, errResp.Error, "tenant: already exists")
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
	assert.Contains(t, errResp.Error, "tenant: not found")
}

// --- DeleteTenantHandler tests ---
//
// TestDeleteTenantHandler_Success is intentionally absent here: a tenant's
// teardown (go-qrdb's DeleteTenant) needs a DatabaseLister / KeyspaceReclaimer
// / DEKShredder wired via tenant.TenantServiceOption to fully reclaim its
// keyspace, which needs a real embedded qrdb node. This in-memory unit test
// fixture (a bare TenantService over a memory-backed store, no node)
// deliberately does not stand that up. The success path is covered against a
// fake TenantServicer in pkg/xkms/servicer_tenant_delegation_test.go
// (TestDeleteTenant_Delegates); this file covers the not-found guard below.

func TestDeleteTenantHandler_NotFound(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/tenants/nonexistent", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var errResp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp.Error, "tenant: not found")
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

	var resp transport.TenantBarrierStatusResponse
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
	assert.Contains(t, errResp.Error, "tenant: not found")
}

// --- TenantBarrierInitHandler tests ---
//
// TestTenantBarrierInitHandler_Success is intentionally absent here:
// initializing a tenant's barrier provisions go-qrdb's pooled per-tenant
// storage (WithVolumePool / WithPerTenantRegistry), which needs real
// Pebble-backed pool infrastructure this in-memory unit test fixture
// deliberately does not stand up. The success path is covered against a
// fake TenantServicer in pkg/xkms/servicer_tenant_delegation_test.go
// (TestTenantBarrierInit_DelegatesWithStrategy); this file covers the
// not-found and invalid-body guards below.

func TestTenantBarrierInitHandler_NotFound(t *testing.T) {
	_, router := setupTenantTestHandlers(t)

	body, err := json.Marshal(tenantBarrierInitRequest{Passphrase: "tenant-admin-pw"})
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
//
// TestTenantBarrierUnsealHandler_Success is intentionally absent here for the
// same reason as TenantBarrierInit's: it depends on a prior successful
// barrier init, which needs go-qrdb's pooled per-tenant storage. That success
// path is covered against a fake TenantServicer in
// pkg/xkms/servicer_tenant_delegation_test.go
// (TestTenantBarrierUnseal_DelegatesKeyAndShare); this file covers the
// not-found guard below.

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

// --- Construction-time typed error tests ---
//
// NewTenantHandlers requires both registry and svc (with a TenantService
// composed on svc): there is no runtime fallback for an unconfigured tenant
// subsystem, only a construction-time error. These replace the deleted
// TestTenantHandlers_NilRegistry, which exercised per-request 503s from
// handlers built with nil dependencies — a construction path that no longer
// exists.

func TestNewTenantHandlers_NilRegistryAndService(t *testing.T) {
	handlers, err := NewTenantHandlers(nil, nil)
	assert.Nil(t, handlers)
	assert.ErrorIs(t, err, ErrTenantNotConfigured)
}

func TestNewTenantHandlers_ServiceWithoutTenantService(t *testing.T) {
	registry, svc := testTenantRegistry(t)
	// svc was configured with SetTenantService by testTenantRegistry via the
	// delegation fake in production wiring terms this models a server that
	// wired the barrier registry but never composed go-qrdb's TenantService.
	svc.SetTenantService(nil)

	handlers, err := NewTenantHandlers(registry, svc)
	assert.Nil(t, handlers)
	assert.ErrorIs(t, err, ErrTenantNotConfigured)
}

func TestNewTenantHandlers_Success(t *testing.T) {
	registry, svc := testTenantRegistry(t)
	handlers, err := NewTenantHandlers(registry, svc)
	require.NoError(t, err)
	require.NotNil(t, handlers)
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
	// createTenantRequest carries no IsolationType, so CreateTenant defaults
	// to prefix isolation: the tenant shares the system barrier rather than
	// registering its own dedicated (and therefore initially sealed) one, so
	// tenantSealed() reports it as unsealed.
	assert.False(t, resp.Tenant.Sealed)
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
		assert.Contains(t, errResp.Error, "qrdb/seal: tenant not found")
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

	t.Run("system-tenant identity can access any tenant (regression)", func(t *testing.T) {
		// Regression test: a caller minted with the reserved "system" TenantID
		// (e.g. a WebAuthn-registered identity, see pkg/server.webAuthnSystemTenant)
		// must be treated as cross-tenant scoped exactly like an empty TenantID.
		// Before isCrossTenantAccess delegated to auth.IsCrossTenant, "system" was
		// compared literally against the target tenant and this test failed with
		// 404.
		_, router := setupTenantTestHandlers(t)

		rec := createTenantViaAPI(t, router, "tenant-b", "Tenant B")
		require.Equal(t, http.StatusCreated, rec.Code)

		req := httptest.NewRequest(http.MethodGet, "/tenants/tenant-b", nil)
		identity := &auth.Identity{Subject: "system-user", TenantID: "system"}
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
		assert.Contains(t, errResp.Error, "qrdb/seal: tenant not found")
	})

	// "SO can delete any tenant" (asserting a real 204) is intentionally
	// absent here for the same reason as TestDeleteTenantHandler_Success: full
	// teardown needs a real embedded qrdb node. The cross-tenant-filtering
	// behavior this test exists to cover is exercised above regardless of
	// caller role, since the 404 fires on the identity check before deletion
	// is attempted.
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
