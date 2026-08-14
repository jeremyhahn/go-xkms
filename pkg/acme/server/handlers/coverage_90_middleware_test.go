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

package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTenantDAO implements GenericDAO[*entities.Tenant] for testing
type testTenantDAO struct {
	tenants  map[uint64]*entities.Tenant
	getError error
}

func newTestTenantDAO() *testTenantDAO {
	return &testTenantDAO{
		tenants: make(map[uint64]*entities.Tenant),
	}
}

func (m *testTenantDAO) Save(_ context.Context, tenant *entities.Tenant) error {
	m.tenants[tenant.EntityID()] = tenant
	return nil
}

func (m *testTenantDAO) SaveWithCondition(_ context.Context, _ *entities.Tenant, _ qrdbsdk.Condition) error {
	panic("not implemented")
}

func (m *testTenantDAO) SaveIfAbsent(_ context.Context, _ *entities.Tenant) (bool, error) {
	panic("not implemented")
}

func (m *testTenantDAO) Get(_ context.Context, id uint64) (*entities.Tenant, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	if tenant, ok := m.tenants[id]; ok {
		return tenant, nil
	}
	return nil, ErrTenantNotFound
}

func (m *testTenantDAO) Delete(_ context.Context, tenant *entities.Tenant) error {
	delete(m.tenants, tenant.EntityID())
	return nil
}

func (m *testTenantDAO) Count(_ context.Context) (int, error) {
	return len(m.tenants), nil
}

func (m *testTenantDAO) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.Tenant], error) {
	panic("not implemented")
}

func (m *testTenantDAO) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbsdk.PagerFunc[*entities.Tenant]) error {
	panic("not implemented")
}

func (m *testTenantDAO) EntityType() string {
	return "tenants"
}

func (m *testTenantDAO) QueryByIndex(_ context.Context, _ string, _ interface{}) ([]*entities.Tenant, error) {
	panic("not implemented")
}

func (m *testTenantDAO) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.Tenant, error) {
	panic("not implemented")
}

func (m *testTenantDAO) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.Tenant, error) {
	panic("not implemented")
}

func (m *testTenantDAO) QueryOneByIndex(_ context.Context, fieldName string, value interface{}) (*entities.Tenant, error) {
	if fieldName == "ID" {
		id, ok := value.(string)
		if !ok {
			return nil, ErrTenantNotFound
		}
		for _, t := range m.tenants {
			if t.ID == id {
				return t, nil
			}
		}
		return nil, ErrTenantNotFound
	}
	return nil, ErrTenantNotFound
}

func (m *testTenantDAO) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.Tenant, error) {
	panic("not implemented")
}

func (m *testTenantDAO) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.Tenant], error) {
	panic("not implemented")
}

func (m *testTenantDAO) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *testTenantDAO) Find(_ context.Context) *qrdbsdk.QueryBuilder[*entities.Tenant] {
	panic("not implemented")
}

// testTenantAwareFactory implements TenantAwareFactory for testing
type testTenantAwareFactory struct {
	storage.Factory
	tenantDAO    *testTenantDAO
	tenantID     string
	tenantDAOErr error
}

func newTestTenantAwareFactory() *testTenantAwareFactory {
	return &testTenantAwareFactory{
		tenantDAO: newTestTenantDAO(),
	}
}

func (f *testTenantAwareFactory) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error) {
	if f.tenantDAOErr != nil {
		return nil, f.tenantDAOErr
	}
	return f.tenantDAO, nil
}

func (f *testTenantAwareFactory) ForTenant(tenantID string) (storage.Factory, error) {
	return &testTenantAwareFactory{
		tenantDAO: f.tenantDAO,
		tenantID:  tenantID,
	}, nil
}

func (f *testTenantAwareFactory) GetTenantID() string {
	return f.tenantID
}

func (f *testTenantAwareFactory) TenantAccountDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return nil, nil
}

func (f *testTenantAwareFactory) TenantOrderDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return nil, nil
}

func (f *testTenantAwareFactory) TenantAuthorizationDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return nil, nil
}

func (f *testTenantAwareFactory) TenantChallengeDAO(tenantID string, accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return nil, nil
}

func (f *testTenantAwareFactory) TenantCertificateDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return nil, nil
}

func (f *testTenantAwareFactory) TenantExternalAccountBindingDAO(tenantID string) (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return nil, nil
}

// nonTenantAwareFactory is a factory that does not support tenant awareness
type nonTenantAwareFactory struct{}

func (f *nonTenantAwareFactory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error) {
	return nil, nil
}
func (f *nonTenantAwareFactory) OrderDAO(id uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error) {
	return nil, nil
}
func (f *nonTenantAwareFactory) AuthorizationDAO(id uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error) {
	return nil, nil
}
func (f *nonTenantAwareFactory) ChallengeDAO(id uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error) {
	return nil, nil
}
func (f *nonTenantAwareFactory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	return nil, nil
}
func (f *nonTenantAwareFactory) NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error) {
	return nil, nil
}
func (f *nonTenantAwareFactory) ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error) {
	return nil, nil
}

func TestDefaultTenantExtractorCoverage(t *testing.T) {
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
		{
			name:     "extracts complex tenant ID",
			header:   "org-12345-tenant",
			expected: "org-12345-tenant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
			if tt.header != "" {
				req.Header.Set(TenantHeader, tt.header)
			}

			result := DefaultTenantExtractor(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSubdomainTenantExtractorCoverage(t *testing.T) {
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
		{
			name:     "extracts from deep subdomain",
			host:     "tenant.sub.acme.example.com",
			expected: "tenant",
		},
		{
			name:     "handles port with two-part domain",
			host:     "acme.com:443",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
			req.Host = tt.host

			result := SubdomainTenantExtractor(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPathTenantExtractorCoverage(t *testing.T) {
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
		{
			name:     "extracts from longer path",
			path:     "/org123/v1/acme/directory",
			expected: "org123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)

			result := PathTenantExtractor(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPathTenantExtractorEmptyPath(t *testing.T) {
	// Test with manually constructed request with empty path
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: ""},
	}

	result := PathTenantExtractor(req)
	assert.Equal(t, "", result)
}

func TestTenantMiddlewareCoverage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("sets tenant from header", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
		})

		var capturedTenant string
		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedTenant = TenantFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "tenant1")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "tenant1", capturedTenant)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("proceeds without tenant when not required", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
		})

		var capturedTenant string
		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedTenant = TenantFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "", capturedTenant)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("rejects request without tenant when required", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
			RequireTenant:  true,
		})

		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("uses default tenant when not specified", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
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

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "default", capturedTenant)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("validates active tenant", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		at := &entities.Tenant{
			ID:     "active-tenant",
			Name:   "Active Tenant",
			Status: "active",
		}
		factory.tenantDAO.tenants[at.EntityID()] = at

		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
			ValidateTenant: true,
		})

		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "active-tenant")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("rejects inactive tenant", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		it := &entities.Tenant{
			ID:     "inactive-tenant",
			Name:   "Inactive Tenant",
			Status: "suspended",
		}
		factory.tenantDAO.tenants[it.EntityID()] = it

		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
			ValidateTenant: true,
		})

		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "inactive-tenant")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("rejects unknown tenant", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
			ValidateTenant: true,
		})

		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "unknown-tenant")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("handles tenant DAO creation error", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		factory.tenantDAOErr = errors.New("DAO creation failed")

		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
			ValidateTenant: true,
		})

		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		req.Header.Set(TenantHeader, "any-tenant")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("uses custom tenant extractor", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
			StorageFactory: factory,
			Logger:         logger,
			TenantExtractor: func(r *http.Request) string {
				return "custom-tenant"
			},
		})

		var capturedTenant string
		handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedTenant = TenantFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "custom-tenant", capturedTenant)
	})
}

func TestTenantFromContextCoverage(t *testing.T) {
	t.Run("returns empty for context without tenant", func(t *testing.T) {
		ctx := context.Background()
		result := TenantFromContext(ctx)
		assert.Equal(t, "", result)
	})

	t.Run("returns tenant ID from context", func(t *testing.T) {
		ctx := WithTenant(context.Background(), "tenant1")
		result := TenantFromContext(ctx)
		assert.Equal(t, "tenant1", result)
	})

	t.Run("handles empty tenant ID", func(t *testing.T) {
		ctx := WithTenant(context.Background(), "")
		result := TenantFromContext(ctx)
		assert.Equal(t, "", result)
	})
}

func TestWithTenantCoverage(t *testing.T) {
	t.Run("adds tenant to context", func(t *testing.T) {
		ctx := context.Background()
		ctx = WithTenant(ctx, "tenant123")

		result := TenantFromContext(ctx)
		assert.Equal(t, "tenant123", result)
	})

	t.Run("overwrites existing tenant", func(t *testing.T) {
		ctx := WithTenant(context.Background(), "tenant1")
		ctx = WithTenant(ctx, "tenant2")

		result := TenantFromContext(ctx)
		assert.Equal(t, "tenant2", result)
	})
}

func TestGetTenantScopedFactoryCoverage(t *testing.T) {
	t.Run("returns original factory when no tenant in context", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		ctx := context.Background()

		result, err := GetTenantScopedFactory(ctx, factory)
		require.NoError(t, err)
		assert.Equal(t, factory, result)
	})

	t.Run("returns tenant-scoped factory when tenant in context", func(t *testing.T) {
		factory := newTestTenantAwareFactory()
		ctx := WithTenant(context.Background(), "tenant1")

		result, err := GetTenantScopedFactory(ctx, factory)
		require.NoError(t, err)

		tenantFactory, ok := result.(*testTenantAwareFactory)
		require.True(t, ok)
		assert.Equal(t, "tenant1", tenantFactory.tenantID)
	})

	t.Run("returns original factory when factory is not tenant aware", func(t *testing.T) {
		factory := &nonTenantAwareFactory{}
		ctx := WithTenant(context.Background(), "tenant1")

		result, err := GetTenantScopedFactory(ctx, factory)
		require.NoError(t, err)
		assert.Equal(t, factory, result)
	})
}

func TestNewTenantMiddlewareDefaultExtractor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	factory := newTestTenantAwareFactory()

	// Test that nil TenantExtractor gets replaced with default
	middleware := NewTenantMiddleware(&TenantMiddlewareConfig{
		StorageFactory:  factory,
		Logger:          logger,
		TenantExtractor: nil,
	})

	require.NotNil(t, middleware.config.TenantExtractor)

	// Verify the default extractor works
	req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
	req.Header.Set(TenantHeader, "test-tenant")

	result := middleware.config.TenantExtractor(req)
	assert.Equal(t, "test-tenant", result)
}
