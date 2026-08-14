// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package quic

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tenantMiddlewareTestLogger returns a discard logger for tenant middleware tests.
func tenantMiddlewareTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tenantMiddlewareTestRegistry creates an initialized and unsealed
// BarrierRegistry backed by in-memory storage for tenant middleware tests.
func tenantMiddlewareTestRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		tenantMiddlewareTestLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: []byte("test-password")}
	require.NoError(t, barrier.Initialize(ctx, creds))

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// tenantMiddlewareTestRegisteredTenant registers and initializes a tenant,
// returning its unsealed TenantBarrier.
func tenantMiddlewareTestRegisteredTenant(t *testing.T, registry *seal.BarrierRegistry, tenantID string) *seal.TenantBarrier {
	t.Helper()
	tb, err := registry.RegisterTenant(tenantID)
	require.NoError(t, err)

	ctx := context.Background()
	creds := seal.Credentials{Secret: []byte("tenant-password")}
	require.NoError(t, registry.InitializeTenant(ctx, tenantID, creds))
	require.False(t, tb.IsSealed(), "tenant barrier should be unsealed after initialization")

	return tb
}

// tenantMiddlewareOKHandler writes a 200 OK response.
var tenantMiddlewareOKHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestQUICTenantMiddleware_NoIdentity(t *testing.T) {
	registry := tenantMiddlewareTestRegistry(t)
	s := &Server{logger: tenantMiddlewareTestLogger(), barrierRegistry: registry}
	mw := s.tenantMiddleware(tenantMiddlewareOKHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestQUICTenantMiddleware_EmptyTenantID(t *testing.T) {
	registry := tenantMiddlewareTestRegistry(t)
	s := &Server{logger: tenantMiddlewareTestLogger(), barrierRegistry: registry}
	mw := s.tenantMiddleware(tenantMiddlewareOKHandler)

	identity := &auth.Identity{Subject: "system-admin", TenantID: ""}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestQUICTenantMiddleware_SystemTenantID is the QUIC regression test for the
// reported bug: a "system"-tenant identity (e.g. a WebAuthn-registered user,
// see pkg/server.webAuthnSystemTenant) must pass the tenant gate exactly like
// an empty-TenantID identity. QUIC carried NO tenant enforcement at all
// before this change, so this test also proves the gate now exists on this
// transport.
func TestQUICTenantMiddleware_SystemTenantID(t *testing.T) {
	registry := tenantMiddlewareTestRegistry(t)
	s := &Server{logger: tenantMiddlewareTestLogger(), barrierRegistry: registry}
	mw := s.tenantMiddleware(tenantMiddlewareOKHandler)

	identity := &auth.Identity{Subject: "webauthn-user", TenantID: "system"}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestQUICTenantMiddleware_SORole(t *testing.T) {
	registry := tenantMiddlewareTestRegistry(t)
	s := &Server{logger: tenantMiddlewareTestLogger(), barrierRegistry: registry}
	mw := s.tenantMiddleware(tenantMiddlewareOKHandler)

	identity := &auth.Identity{Subject: "so-admin", TenantID: "nonexistent-tenant", Roles: []string{"so"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestQUICTenantMiddleware_NoRegistry(t *testing.T) {
	s := &Server{logger: tenantMiddlewareTestLogger()} // no registry
	mw := s.tenantMiddleware(tenantMiddlewareOKHandler)

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "some-tenant"}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestQUICTenantMiddleware_TenantNotFound(t *testing.T) {
	registry := tenantMiddlewareTestRegistry(t)
	s := &Server{logger: tenantMiddlewareTestLogger(), barrierRegistry: registry}
	mw := s.tenantMiddleware(tenantMiddlewareOKHandler)

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "nonexistent-tenant", Roles: []string{"user"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "tenant not found", resp.Error)
}

func TestQUICTenantMiddleware_TenantSealed(t *testing.T) {
	registry := tenantMiddlewareTestRegistry(t)
	_, err := registry.RegisterTenant("sealed-tenant")
	require.NoError(t, err)

	s := &Server{logger: tenantMiddlewareTestLogger(), barrierRegistry: registry}
	mw := s.tenantMiddleware(tenantMiddlewareOKHandler)

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "sealed-tenant", Roles: []string{"operator"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "tenant barrier is sealed", resp.Error)
}

func TestQUICTenantMiddleware_TenantBarrierInjected(t *testing.T) {
	registry := tenantMiddlewareTestRegistry(t)
	tenantMiddlewareTestRegisteredTenant(t, registry, "active-tenant")

	s := &Server{logger: tenantMiddlewareTestLogger(), barrierRegistry: registry}

	var captured interface{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = auth.GetTenantBarrier(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw := s.tenantMiddleware(handler)

	identity := &auth.Identity{Subject: "tenant-user", TenantID: "active-tenant", Roles: []string{"operator"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, captured)

	tb, ok := captured.(*seal.TenantBarrier)
	require.True(t, ok, "expected *seal.TenantBarrier")
	assert.Equal(t, "active-tenant", tb.TenantID())
}
