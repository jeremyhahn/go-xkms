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
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTenantMiddlewareLogger returns a quiet logger for tenant middleware tests.
func testTenantMiddlewareLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testTenantMiddlewareRegistry creates an initialized and unsealed BarrierRegistry
// backed by in-memory storage for use in middleware tests.
func testTenantMiddlewareRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		testTenantMiddlewareLogger(),
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

// testTenantMiddlewareRegisteredTenant registers and initializes a tenant in the
// given registry, returning the unsealed TenantBarrier. Each tenant barrier has
// its own independent barrier that must be initialized separately from the system
// barrier.
func testTenantMiddlewareRegisteredTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) *seal.TenantBarrier {
	t.Helper()
	tb, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: "tenant-password"}
	err = registry.InitializeTenant(ctx, tenantID, creds)
	require.NoError(t, err)
	require.False(t, tb.IsSealed(), "tenant barrier should be unsealed after initialization")

	return tb
}

// newTenantMiddlewareServer creates a minimal Server with the given registry
// and logger for middleware testing. No HTTP server or router is needed.
func newTenantMiddlewareServer(registry *seal.BarrierRegistry) *Server {
	return &Server{
		logger:          testTenantMiddlewareLogger(),
		barrierRegistry: registry,
	}
}

// tenantTestOKHandler is a simple HTTP handler that writes a 200 OK response.
var tenantTestOKHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestTenantMiddleware_NoIdentity(t *testing.T) {
	t.Run("passes through when no identity in context", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)
		s := newTenantMiddlewareServer(registry)

		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestTenantMiddleware_SystemLevel(t *testing.T) {
	t.Run("passes through when identity has empty TenantID", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)
		s := newTenantMiddlewareServer(registry)

		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		identity := &auth.Identity{
			Subject:  "system-admin",
			TenantID: "",
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestTenantMiddleware_SORole(t *testing.T) {
	t.Run("SO role gets cross-tenant access", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)
		s := newTenantMiddlewareServer(registry)

		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		// SO identity with a tenant ID should still pass through
		identity := &auth.Identity{
			Subject:  "security-officer",
			TenantID: "nonexistent-tenant",
			Claims: map[string]interface{}{
				"roles": []string{"so"},
			},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("SO role with interface slice claims passes through", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)
		s := newTenantMiddlewareServer(registry)

		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		identity := &auth.Identity{
			Subject:  "security-officer",
			TenantID: "any-tenant",
			Claims: map[string]interface{}{
				"roles": []interface{}{"so", "admin"},
			},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestTenantMiddleware_TenantNotFound(t *testing.T) {
	t.Run("returns 403 when tenant is not registered", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)
		s := newTenantMiddlewareServer(registry)

		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		identity := &auth.Identity{
			Subject:  "tenant-user",
			TenantID: "nonexistent-tenant",
			Claims: map[string]interface{}{
				"roles": []string{"user"},
			},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		var errResp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "tenant not found", errResp.Message)
		assert.Equal(t, http.StatusForbidden, errResp.Code)
	})
}

func TestTenantMiddleware_TenantSealed(t *testing.T) {
	t.Run("returns 503 when tenant barrier is sealed", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)

		// Register a tenant but do NOT initialize it.
		// The tenant barrier starts in sealed state by default.
		_, err := registry.RegisterTenant("sealed-tenant")
		require.NoError(t, err)

		s := newTenantMiddlewareServer(registry)
		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		identity := &auth.Identity{
			Subject:  "tenant-user",
			TenantID: "sealed-tenant",
			Claims: map[string]interface{}{
				"roles": []string{"operator"},
			},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)

		var errResp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "tenant barrier is sealed", errResp.Message)
		assert.Equal(t, http.StatusServiceUnavailable, errResp.Code)
	})
}

func TestTenantMiddleware_TenantBarrierInjected(t *testing.T) {
	t.Run("injects TenantBarrier into context for downstream handlers", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)

		// Register and initialize the tenant so its barrier is unsealed.
		testTenantMiddlewareRegisteredTenant(t, registry, "active-tenant")

		s := newTenantMiddlewareServer(registry)

		// Handler that verifies the tenant barrier is in context.
		var capturedBarrier interface{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedBarrier = auth.GetTenantBarrier(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		middleware := s.TenantMiddleware()(handler)

		identity := &auth.Identity{
			Subject:  "tenant-user",
			TenantID: "active-tenant",
			Claims: map[string]interface{}{
				"roles": []string{"operator"},
			},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedBarrier)

		// Verify it is a *seal.TenantBarrier with the correct tenant ID.
		tb, ok := capturedBarrier.(*seal.TenantBarrier)
		require.True(t, ok, "expected *seal.TenantBarrier")
		assert.Equal(t, "active-tenant", tb.TenantID())
	})
}

func TestTenantMiddleware_NoRegistry(t *testing.T) {
	t.Run("passes through when barrier registry is nil", func(t *testing.T) {
		s := newTenantMiddlewareServer(nil) // No registry

		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		identity := &auth.Identity{
			Subject:  "tenant-user",
			TenantID: "some-tenant",
			Claims: map[string]interface{}{
				"roles": []string{"user"},
			},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestTenantMiddleware_NonSORoleNotCrossTenant(t *testing.T) {
	t.Run("non-SO role with TenantID requires valid tenant", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)
		s := newTenantMiddlewareServer(registry)

		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		// Admin role (not SO) with a non-existent tenant.
		identity := &auth.Identity{
			Subject:  "tenant-admin",
			TenantID: "missing-tenant",
			Claims: map[string]interface{}{
				"roles": []string{"admin"},
			},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestTenantMiddleware_IdentityWithNoClaims(t *testing.T) {
	t.Run("identity with nil claims and valid tenant passes through", func(t *testing.T) {
		registry := testTenantMiddlewareRegistry(t)

		// Register and initialize the tenant so its barrier is unsealed.
		testTenantMiddlewareRegisteredTenant(t, registry, "valid-tenant")

		s := newTenantMiddlewareServer(registry)
		middleware := s.TenantMiddleware()(tenantTestOKHandler)

		// Identity with no claims (nil) -- HasRole returns false,
		// but tenant exists and is unsealed so it passes.
		identity := &auth.Identity{
			Subject:  "basic-user",
			TenantID: "valid-tenant",
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
