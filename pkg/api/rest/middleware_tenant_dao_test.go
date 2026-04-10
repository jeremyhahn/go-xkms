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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// testBarrierRegistry is a test double that maps tenant IDs to in-memory
// storage backends.
type testBarrierRegistry struct {
	tenants map[string]storage.Backend
}

// Compile-time interface check.
var _ staticpw.BarrierRegistryAccessor = (*testBarrierRegistry)(nil)

// GetTenantBarrier returns the in-memory backend for the tenant.
func (r *testBarrierRegistry) GetTenantBarrier(tenantID string) (storage.Backend, error) {
	backend, ok := r.tenants[tenantID]
	if !ok {
		return nil, errors.New("tenant not found")
	}
	return backend, nil
}

// newTestDAOFactory creates a TenantDAOFactory for testing.
func newTestDAOFactory(t *testing.T, tenants map[string]storage.Backend) *staticpw.TenantDAOFactory {
	t.Helper()

	systemBackend := storage.New()
	systemKV, err := kvadapter.New(systemBackend)
	if err != nil {
		t.Fatalf("failed to create system kvstore: %v", err)
	}

	registry := &testBarrierRegistry{tenants: tenants}
	factory, err := staticpw.NewTenantDAOFactory(systemKV, registry)
	if err != nil {
		t.Fatalf("failed to create factory: %v", err)
	}
	return factory
}

// TestTenantDAOMiddleware_InjectsFactory verifies the middleware puts
// the factory in context.
func TestTenantDAOMiddleware_InjectsFactory(t *testing.T) {
	factory := newTestDAOFactory(t, map[string]storage.Backend{})

	var captured *staticpw.TenantDAOFactory
	handler := TenantDAOMiddleware(factory)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = GetTenantDAOFactory(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("expected factory in context, got nil")
	}
	if captured != factory {
		t.Error("expected same factory instance in context")
	}
}

// TestTenantDAOMiddleware_NilFactory verifies the middleware passes
// through when factory is nil.
func TestTenantDAOMiddleware_NilFactory(t *testing.T) {
	called := false
	handler := TenantDAOMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		factory := GetTenantDAOFactory(r.Context())
		if factory != nil {
			t.Error("expected nil factory in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("handler was not called")
	}
}

// TestGetTenantDAOFactory_NotPresent verifies GetTenantDAOFactory returns
// nil when no factory is in context.
func TestGetTenantDAOFactory_NotPresent(t *testing.T) {
	ctx := context.Background()
	factory := GetTenantDAOFactory(ctx)
	if factory != nil {
		t.Errorf("expected nil, got %v", factory)
	}
}

// TestResolvePasswordDAOStore_SystemStore verifies system store is returned
// when no tenant identity is present.
func TestResolvePasswordDAOStore_SystemStore(t *testing.T) {
	factory := newTestDAOFactory(t, map[string]storage.Backend{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := WithTenantDAOFactory(req.Context(), factory)
	req = req.WithContext(ctx)

	store, err := ResolvePasswordDAOStore(req)
	if err != nil {
		t.Fatalf("ResolvePasswordDAOStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

// TestResolvePasswordDAOStore_TenantStore verifies tenant store is returned
// when the request has a tenant identity.
func TestResolvePasswordDAOStore_TenantStore(t *testing.T) {
	factory := newTestDAOFactory(t, map[string]storage.Backend{
		"acme": storage.New(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	identity := &auth.Identity{
		Subject:  "user1",
		TenantID: "acme",
	}
	ctx := auth.WithIdentity(req.Context(), identity)
	ctx = WithTenantDAOFactory(ctx, factory)
	req = req.WithContext(ctx)

	store, err := ResolvePasswordDAOStore(req)
	if err != nil {
		t.Fatalf("ResolvePasswordDAOStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil tenant store")
	}
}

// TestResolvePasswordDAOStore_NoFactory verifies error when no factory
// is in context.
func TestResolvePasswordDAOStore_NoFactory(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := ResolvePasswordDAOStore(req)
	if err == nil {
		t.Fatal("expected error when no factory present")
	}
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got %v", err)
	}
}

// TestResolveTeamDAOStore_SystemStore verifies system team store is returned
// when no tenant identity is present.
func TestResolveTeamDAOStore_SystemStore(t *testing.T) {
	factory := newTestDAOFactory(t, map[string]storage.Backend{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := WithTenantDAOFactory(req.Context(), factory)
	req = req.WithContext(ctx)

	store, err := ResolveTeamDAOStore(req)
	if err != nil {
		t.Fatalf("ResolveTeamDAOStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

// TestResolveTeamDAOStore_TenantStore verifies tenant team store is returned
// when the request has a tenant identity.
func TestResolveTeamDAOStore_TenantStore(t *testing.T) {
	factory := newTestDAOFactory(t, map[string]storage.Backend{
		"acme": storage.New(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	identity := &auth.Identity{
		Subject:  "user1",
		TenantID: "acme",
	}
	ctx := auth.WithIdentity(req.Context(), identity)
	ctx = WithTenantDAOFactory(ctx, factory)
	req = req.WithContext(ctx)

	store, err := ResolveTeamDAOStore(req)
	if err != nil {
		t.Fatalf("ResolveTeamDAOStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil tenant team store")
	}
}

// TestResolveTeamDAOStore_NoFactory verifies error when no factory
// is in context.
func TestResolveTeamDAOStore_NoFactory(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := ResolveTeamDAOStore(req)
	if err == nil {
		t.Fatal("expected error when no factory present")
	}
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got %v", err)
	}
}

// TestWithTenantDAOFactory_RoundTrip verifies context injection and retrieval.
func TestWithTenantDAOFactory_RoundTrip(t *testing.T) {
	factory := newTestDAOFactory(t, map[string]storage.Backend{})

	ctx := context.Background()
	ctx = WithTenantDAOFactory(ctx, factory)

	retrieved := GetTenantDAOFactory(ctx)
	if retrieved != factory {
		t.Error("expected same factory instance from context")
	}
}
