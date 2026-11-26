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

func (m *testTenantDAO) GetByNaturalKey(_ context.Context, _ string) (*entities.Tenant, error) {
	panic("not implemented")
}

func (m *testTenantDAO) CompareAndSwap(_ context.Context, _, _ *entities.Tenant) (bool, error) {
	panic("not implemented")
}

func (m *testTenantDAO) DeleteIfMatch(_ context.Context, _ *entities.Tenant) (bool, error) {
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
