//go:build local

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

package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
)

// mockTenantDAO implements GenericDAO[*entities.Tenant] for testing
type mockTenantDAO struct {
	qrdbsdk.GenericDAO[*entities.Tenant]
	tenants map[string]*entities.Tenant
}

func newMockTenantDAO() *mockTenantDAO {
	return &mockTenantDAO{
		tenants: make(map[string]*entities.Tenant),
	}
}

func (m *mockTenantDAO) Save(ctx context.Context, tenant *entities.Tenant) error {
	m.tenants[tenant.ID] = tenant
	return nil
}

func (m *mockTenantDAO) Get(ctx context.Context, id uint64) (*entities.Tenant, error) {
	for _, t := range m.tenants {
		if t.EntityID() == id {
			return t, nil
		}
	}
	return nil, ErrTenantNotFound
}

func (m *mockTenantDAO) QueryOneByIndex(ctx context.Context, fieldName string, value interface{}) (*entities.Tenant, error) {
	if fieldName == "ID" {
		if id, ok := value.(string); ok {
			if tenant, found := m.tenants[id]; found {
				return tenant, nil
			}
		}
	}
	return nil, ErrTenantNotFound
}

func (m *mockTenantDAO) Delete(ctx context.Context, entity *entities.Tenant) error {
	delete(m.tenants, entity.ID)
	return nil
}

// mockTenantAwareFactory implements TenantAwareFactory for testing
type mockTenantAwareFactory struct {
	storage.Factory
	tenantDAO *mockTenantDAO
	tenantID  string
}

func newMockTenantAwareFactory() *mockTenantAwareFactory {
	return &mockTenantAwareFactory{
		tenantDAO: newMockTenantDAO(),
	}
}

func (f *mockTenantAwareFactory) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	return f.tenantDAO, nil
}

func (f *mockTenantAwareFactory) ForTenant(tenantID string) (storage.Factory, error) {
	return &mockTenantAwareFactory{
		tenantDAO: f.tenantDAO,
		tenantID:  tenantID,
	}, nil
}

func (f *mockTenantAwareFactory) GetTenantID() string {
	return f.tenantID
}

func TestDefaultTenantExtractor(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "extracts tenant from header",
			header:   "tenant1",
			expected: "tenant1",
		},
		{
			name:     "returns empty when no header",
			header:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
			if tt.header != "" {
				req.Header.Set(TenantHeader, tt.header)
			}

			result := DefaultTenantExtractor(req)
			if result != tt.expected {
				t.Errorf("DefaultTenantExtractor() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSubdomainTenantExtractor(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "extracts tenant from subdomain",
			host:     "tenant1.acme.example.com",
			expected: "tenant1",
		},
		{
			name:     "extracts tenant with port",
			host:     "tenant1.acme.example.com:8443",
			expected: "tenant1",
		},
		{
			name:     "returns empty for two-part domain",
			host:     "acme.com",
			expected: "",
		},
		{
			name:     "returns empty for single part",
			host:     "localhost",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
			req.Host = tt.host

			result := SubdomainTenantExtractor(req)
			if result != tt.expected {
				t.Errorf("SubdomainTenantExtractor() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPathTenantExtractor(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "extracts tenant from path",
			path:     "/tenant1/acme/directory",
			expected: "tenant1",
		},
		{
			name:     "returns empty for acme path",
			path:     "/acme/directory",
			expected: "",
		},
		{
			name:     "returns empty for root",
			path:     "/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)

			result := PathTenantExtractor(req)
			if result != tt.expected {
				t.Errorf("PathTenantExtractor() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTenantMiddleware_Basic(t *testing.T) {
	logger := slog.Default()
	factory := newMockTenantAwareFactory()

	middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
		StorageFactory: factory,
		Logger:         logger,
	})

	// Handler that checks tenant context
	var capturedTenant string
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("sets tenant from header", func(t *testing.T) {
		capturedTenant = ""
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "tenant1")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if capturedTenant != "tenant1" {
			t.Errorf("expected tenant 'tenant1', got '%s'", capturedTenant)
		}
		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("proceeds without tenant when not required", func(t *testing.T) {
		capturedTenant = ""
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if capturedTenant != "" {
			t.Errorf("expected empty tenant, got '%s'", capturedTenant)
		}
		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

func TestTenantMiddleware_RequireTenant(t *testing.T) {
	logger := slog.Default()
	factory := newMockTenantAwareFactory()

	middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
		StorageFactory: factory,
		Logger:         logger,
		RequireTenant:  true,
	})

	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("rejects request without tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
	})

	t.Run("accepts request with tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "tenant1")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

func TestTenantMiddleware_DefaultTenant(t *testing.T) {
	logger := slog.Default()
	factory := newMockTenantAwareFactory()

	middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
		StorageFactory: factory,
		Logger:         logger,
		DefaultTenant:  "default",
		RequireTenant:  true,
	})

	var capturedTenant string
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("uses default tenant when not specified", func(t *testing.T) {
		capturedTenant = ""
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if capturedTenant != "default" {
			t.Errorf("expected tenant 'default', got '%s'", capturedTenant)
		}
		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("uses specified tenant over default", func(t *testing.T) {
		capturedTenant = ""
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "tenant1")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if capturedTenant != "tenant1" {
			t.Errorf("expected tenant 'tenant1', got '%s'", capturedTenant)
		}
	})
}

func TestTenantMiddleware_ValidateTenant(t *testing.T) {
	logger := slog.Default()
	factory := newMockTenantAwareFactory()

	// Add an active tenant
	factory.tenantDAO.tenants["active-tenant"] = &entities.Tenant{
		ID:     "active-tenant",
		Name:   "Active Tenant",
		Status: "active",
	}

	// Add an inactive tenant
	factory.tenantDAO.tenants["inactive-tenant"] = &entities.Tenant{
		ID:     "inactive-tenant",
		Name:   "Inactive Tenant",
		Status: "suspended",
	}

	middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
		StorageFactory: factory,
		Logger:         logger,
		ValidateTenant: true,
	})

	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("accepts active tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "active-tenant")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("rejects inactive tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "inactive-tenant")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
	})

	t.Run("rejects unknown tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "unknown-tenant")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
	})
}

func TestTenantFromContext(t *testing.T) {
	t.Run("returns empty for context without tenant", func(t *testing.T) {
		ctx := context.Background()
		result := TenantFromContext(ctx)
		if result != "" {
			t.Errorf("expected empty string, got '%s'", result)
		}
	})

	t.Run("returns tenant ID from context", func(t *testing.T) {
		ctx := WithTenant(context.Background(), "tenant1")
		result := TenantFromContext(ctx)
		if result != "tenant1" {
			t.Errorf("expected 'tenant1', got '%s'", result)
		}
	})
}

func TestGetTenantScopedFactory(t *testing.T) {
	factory := newMockTenantAwareFactory()

	t.Run("returns original factory when no tenant in context", func(t *testing.T) {
		ctx := context.Background()
		result, err := GetTenantScopedFactory(ctx, factory)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != factory {
			t.Error("expected original factory")
		}
	})

	t.Run("returns tenant-scoped factory when tenant in context", func(t *testing.T) {
		ctx := WithTenant(context.Background(), "tenant1")
		result, err := GetTenantScopedFactory(ctx, factory)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Check that the result is a tenant-scoped factory
		tenantFactory, ok := result.(*mockTenantAwareFactory)
		if !ok {
			t.Error("expected mockTenantAwareFactory")
		}
		if tenantFactory.tenantID != "tenant1" {
			t.Errorf("expected tenant ID 'tenant1', got '%s'", tenantFactory.tenantID)
		}
	})
}
