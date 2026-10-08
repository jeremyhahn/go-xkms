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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoverageBoost_UpdateTenantIntermediateCAStatus_Suspend(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)
	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	// Create tenant first so tenantDAO can find it
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-suspend",
		Name: "Suspend Test",
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	service.mu.Lock()
	service.tenantCAs["tenant-suspend"] = &tenantCAEntry{
		intermediateCAs: map[string]*tenantIntermediateCAEntry{
			"int-1": {cert: makeTestCert(t, "Int CA"), signer: key},
		},
		defaultIntCA: "int-1",
	}
	service.mu.Unlock()

	// Suspend the CA - should clear signer and default
	err = service.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-suspend", "int-1", "suspended")
	require.NoError(t, err)

	service.mu.RLock()
	entry := service.tenantCAs["tenant-suspend"]
	assert.Nil(t, entry.intermediateCAs["int-1"].signer)
	assert.Empty(t, entry.defaultIntCA)
	service.mu.RUnlock()
}
func TestHandlers_GetAlgorithms(t *testing.T) {
	testCA, storageFactory, cleanup := createTestInfrastructure(t)
	defer cleanup()

	svc := NewAdminService(testCA, storageFactory, slog.Default(), "1.0.0")
	h := NewHandlers(svc, slog.Default())

	router := mux.NewRouter()
	h.RegisterRoutes(router, nil, newPermissiveGate())

	req := authenticated(httptest.NewRequest(http.MethodGet, "/admin/algorithms", nil))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp AlgorithmsResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Signing)
	assert.NotNil(t, resp.KeyEncapsulation)

	// createTestInfrastructure configures exactly one backend, so the default
	// discoverer must report that backend and no other.
	for _, info := range resp.Signing {
		assert.Equal(t, []string{"software"}, info.Backends,
			"algorithm %s must be reported against the configured backend only", info.Algorithm)
	}
}

// TestTenantAwareAdminService_CreateTenant_DelegatesToQRDB proves that once
// a qrdb TenantServicer is wired (SetTenantService), CreateTenant delegates
// tenant identity registration to it rather than the local entities.Tenant
// DAO — the owner decision this change implements.
func TestTenantAwareAdminService_CreateTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	info, err := svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "acme-corp", Name: "ACME Corp"})
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", info.ID)
	assert.Equal(t, "ACME Corp", info.Name)

	// Verify it actually landed in qrdb, not just a local copy.
	qt, err := fake.GetTenant(context.Background(), "acme-corp")
	require.NoError(t, err)
	assert.Equal(t, "ACME Corp", qt.Name)
}

// TestTenantAwareAdminService_CreateTenant_QRDBAlreadyExists proves a
// duplicate create against qrdb maps to the same ErrTenantAlreadyExists
// sentinel the local-only path returns, so handlers.go's error mapping does
// not need to know which backing store served the request.
func TestTenantAwareAdminService_CreateTenant_QRDBAlreadyExists(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "dup", Name: "Dup"})
	require.NoError(t, err)

	_, err = svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "dup", Name: "Dup Again"})
	assert.ErrorIs(t, err, ErrTenantAlreadyExists)
}
func TestTenantAwareAdminService_CreateTenant_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)

	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	req := CreateTenantRequest{
		ID:   "tenant-success",
		Name: "Test Tenant",
	}

	tenant, err := service.CreateTenant(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, tenant)

	// Verify tenant info
	assert.Equal(t, "tenant-success", tenant.ID)
	assert.Equal(t, "Test Tenant", tenant.Name)
	assert.Equal(t, "active", tenant.Status)
	assert.False(t, tenant.CreatedAt.IsZero())
	assert.False(t, tenant.UpdatedAt.IsZero())
}

// TestTenantAwareAdminService_DeleteTenant_DelegatesToQRDB proves deletion
// removes the tenant from qrdb (the canonical store) and that a repeat
// delete answers ErrTenantNotFound.
func TestTenantAwareAdminService_DeleteTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := fake.CreateTenant(context.Background(), "gone-soon", "Gone Soon", "")
	require.NoError(t, err)

	require.NoError(t, svc.DeleteTenant(context.Background(), "gone-soon"))
	_, err = fake.GetTenant(context.Background(), "gone-soon")
	assert.True(t, errors.Is(err, qrdbsdk.ErrTenantMissing))

	err = svc.DeleteTenant(context.Background(), "gone-soon")
	assert.ErrorIs(t, err, ErrTenantNotFound)
}
func TestTenantAwareAdminService_DeleteTenant_Success(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)

	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	// Create tenant first
	_, err := service.CreateTenant(context.Background(), CreateTenantRequest{
		ID:   "tenant-delete-test",
		Name: "Delete Test",
	})
	require.NoError(t, err)

	// Delete tenant
	err = service.DeleteTenant(context.Background(), "tenant-delete-test")
	require.NoError(t, err)

	// Verify tenant is gone
	_, err = service.GetTenant(context.Background(), "tenant-delete-test")
	assert.Equal(t, ErrTenantNotFound, err)
}

// TestTenantAwareAdminService_GetTenant_DelegatesToQRDB proves GetTenant
// answers ErrTenantNotFound (the admin package's sentinel) for a tenant
// qrdb does not know about, and returns qrdb's copy for one it does.
func TestTenantAwareAdminService_GetTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := svc.GetTenant(context.Background(), "missing")
	assert.ErrorIs(t, err, ErrTenantNotFound)

	_, err = fake.CreateTenant(context.Background(), "known", "Known Tenant", "")
	require.NoError(t, err)

	info, err := svc.GetTenant(context.Background(), "known")
	require.NoError(t, err)
	assert.Equal(t, "Known Tenant", info.Name)
}
func TestTenantAwareAdminService_GetTenant_FallbackNotFound(t *testing.T) {
	// This test verifies that ErrTenantNotFound is returned for nonexistent
	// tenants once a qrdb TenantServicer is wired (qrdb is the single tenant
	// authority; there is no local-only fallback to test here anymore).
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)

	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	_, err := service.GetTenant(context.Background(), "tenant-123")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}
func TestTenantAwareAdminService_GetTenant_NotFound(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)

	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	_, err := service.GetTenant(context.Background(), "nonexistent-tenant")
	require.Error(t, err)
	assert.Equal(t, ErrTenantNotFound, err)
}
func TestTenantAwareAdminService_ListTenants_Defaults(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)

	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	// Test with defaults (page 0, perPage 0)
	tenants, pagination, err := service.ListTenants(context.Background(), ListTenantsRequest{})

	assert.NoError(t, err)
	assert.NotNil(t, tenants)
	assert.NotNil(t, pagination)
	assert.Equal(t, 1, pagination.Page)
	assert.Equal(t, 20, pagination.PerPage)
}

// TestTenantAwareAdminService_ListTenants_DelegatesToQRDB proves the listed
// set comes from qrdb rather than an empty/local-only result.
func TestTenantAwareAdminService_ListTenants_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := fake.CreateTenant(context.Background(), "a", "A", "")
	require.NoError(t, err)
	_, err = fake.CreateTenant(context.Background(), "b", "B", "")
	require.NoError(t, err)

	list, pagination, err := svc.ListTenants(context.Background(), ListTenantsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 2, pagination.Total)
	assert.Len(t, list, 2)
}
func TestTenantAwareAdminService_ListTenants_MaxPerPage(t *testing.T) {
	logger := slog.Default()
	qrdbSvc := newTestQRDB(t)

	service := mustTenantAwareAdminService(t, nil, nil, qrdbSvc, logger, "1.0.0")
	service.SetTenantService(newFakeTenantServicer())

	// Test with too high perPage
	_, pagination, err := service.ListTenants(context.Background(), ListTenantsRequest{
		Page:    1,
		PerPage: 200, // Should be capped at 100
	})

	assert.NoError(t, err)
	assert.Equal(t, 100, pagination.PerPage)
}

// TestTenantAwareAdminService_UpdateTenant_DelegatesToQRDB proves the name
// patch reaches qrdb.
func TestTenantAwareAdminService_UpdateTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := fake.CreateTenant(context.Background(), "t1", "Old Name", "")
	require.NoError(t, err)

	info, err := svc.UpdateTenant(context.Background(), "t1", UpdateTenantRequest{Name: "New Name"})
	require.NoError(t, err)
	assert.Equal(t, "New Name", info.Name)

	qt, err := fake.GetTenant(context.Background(), "t1")
	require.NoError(t, err)
	assert.Equal(t, "New Name", qt.Name)
}
