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

// handlers_tenant_admin_test.go covers the MCP tenant administration
// methods: dispatch registration, the not-configured path taken when no
// go-qrdb TenantService is composed, the success path against a fake
// ServiceTenantServicer, and the cross-tenant anti-enumeration refusal that
// mirrors REST's isCrossTenantAccess.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// fakeTenantServicer is a partial qrdbsdk.ServiceTenantServicer. Embedding
// the interface satisfies its (large) method set; only the methods the MCP
// tenant admin handlers delegate to are overridden.
type fakeTenantServicer struct {
	qrdbsdk.ServiceTenantServicer

	tenants map[string]*qrdbsdk.ServiceTenantInfo
	err     error

	initTenantID   string
	unsealTenantID string
}

func newFakeTenantServicer() *fakeTenantServicer {
	return &fakeTenantServicer{tenants: make(map[string]*qrdbsdk.ServiceTenantInfo)}
}

func (f *fakeTenantServicer) CreateTenant(_ context.Context, id, name string, iso qrdbsdk.TenantIsolationType, _ ...qrdbsdk.CreateTenantOption) (*qrdbsdk.ServiceTenantInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	info := &qrdbsdk.ServiceTenantInfo{ID: id, Name: name, IsolationType: iso}
	f.tenants[id] = info
	return info, nil
}

func (f *fakeTenantServicer) GetTenant(_ context.Context, id string) (*qrdbsdk.ServiceTenantInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	info, ok := f.tenants[id]
	if !ok {
		return nil, seal.ErrTenantNotFound
	}
	return info, nil
}

func (f *fakeTenantServicer) ListTenants(_ context.Context) ([]qrdbsdk.ServiceTenantInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]qrdbsdk.ServiceTenantInfo, 0, len(f.tenants))
	for _, t := range f.tenants {
		out = append(out, *t)
	}
	return out, nil
}

func (f *fakeTenantServicer) DeleteTenant(_ context.Context, id string) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.tenants[id]; !ok {
		return seal.ErrTenantNotFound
	}
	delete(f.tenants, id)
	return nil
}

func (f *fakeTenantServicer) TenantBarrierInitWithStrategy(_ context.Context, id string, _ []byte, _, _ int, strategy qrdbsdk.StrategyID) (*qrdbsdk.ServiceTenantBarrierInitResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.initTenantID = id
	return &qrdbsdk.ServiceTenantBarrierInitResult{TenantID: id, Strategy: string(strategy)}, nil
}

func (f *fakeTenantServicer) TenantBarrierUnseal(_ context.Context, id string, _ []byte) error {
	if f.err != nil {
		return f.err
	}
	f.unsealTenantID = id
	return nil
}

func (f *fakeTenantServicer) TenantBarrierStatus(_ context.Context, id string) (*qrdbsdk.ServiceTenantBarrierStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &qrdbsdk.ServiceTenantBarrierStatus{TenantID: id, Sealed: false, Initialized: true, Strategy: "passphrase"}, nil
}

func (f *fakeTenantServicer) UpdateEntitlements(_ context.Context, id string, ents *qrdbsdk.Entitlements) (*qrdbsdk.ServiceTenantInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &qrdbsdk.ServiceTenantInfo{ID: id, Entitlements: ents}, nil
}

func (f *fakeTenantServicer) UpdateQuotas(_ context.Context, id string, q *qrdbsdk.Quotas) (*qrdbsdk.ServiceTenantInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &qrdbsdk.ServiceTenantInfo{ID: id, Quotas: q}, nil
}

// newTenantAdminServer returns an MCP server backed by the standard test
// XKMS service, optionally composed with a tenant servicer.
func newTenantAdminServer(t *testing.T, tenantSvc qrdbsdk.ServiceTenantServicer) *Server {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)
	if tenantSvc != nil {
		svc.SetTenantService(tenantSvc)
	}

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return server
}

func tenantAdminRequest(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()

	raw, err := json.Marshal(params)
	require.NoError(t, err)

	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// systemCtx returns a context carrying a system-scoped (cross-tenant)
// identity, matching the reserved system tenant REST treats as platform-scoped.
func systemCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "so@example.com", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"so"},
	})
}

// scopedCtx returns a context carrying an identity bound to tenantID.
func scopedCtx(tid string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "admin@example.com", TenantID: tid, Roles: []string{"tenant-admin"},
	})
}

// TestTenantAdminMethods_Dispatchable proves every tenant admin method is
// reachable through the dispatch table and carries a permission mapping.
func TestTenantAdminMethods_Dispatchable(t *testing.T) {
	for _, method := range []string{
		"xkms.createTenant", "xkms.getTenant", "xkms.listTenants", "xkms.deleteTenant",
		"xkms.tenantBarrierInit", "xkms.tenantBarrierUnseal", "xkms.tenantBarrierStatus",
		"xkms.updateTenantEntitlements", "xkms.updateTenantQuotas",
	} {
		_, ok := rpcMethodHandlers[method]
		assert.True(t, ok, "method %q must be dispatchable", method)
		_, mapped := methodPermissions[method]
		assert.True(t, mapped, "method %q must carry a permission mapping", method)
	}
}

func TestHandleCreateTenant_Success(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	result, err := server.handleCreateTenant(systemCtx(),
		tenantAdminRequest(t, "xkms.createTenant", transport.CreateTenantRequest{ID: "t1", Name: "Acme"}))

	require.NoError(t, err)
	resp, ok := result.(*transport.CreateTenantResponse)
	require.True(t, ok, "result must be *transport.CreateTenantResponse, got %T", result)
	assert.Equal(t, "t1", resp.Tenant.ID)
}

func TestHandleCreateTenant_NotConfigured(t *testing.T) {
	server := newTenantAdminServer(t, nil)

	_, err := server.handleCreateTenant(systemCtx(),
		tenantAdminRequest(t, "xkms.createTenant", transport.CreateTenantRequest{ID: "t1", Name: "Acme"}))

	require.Error(t, err, "a service with no tenant servicer must report failure, not panic")
}

func TestHandleCreateTenant_InvalidParams(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.createTenant", Params: json.RawMessage(`{`), ID: 1}
	_, err := server.handleCreateTenant(systemCtx(), req)

	require.Error(t, err)
	var keyOpErr *KeyOpError
	require.True(t, errors.As(err, &keyOpErr), "decode failure must be a *KeyOpError")
	assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
}

func TestHandleGetTenant_Success(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["t1"] = &qrdbsdk.ServiceTenantInfo{ID: "t1", Name: "Acme"}
	server := newTenantAdminServer(t, fake)

	result, err := server.handleGetTenant(systemCtx(),
		tenantAdminRequest(t, "xkms.getTenant", TenantIDParams{TenantID: "t1"}))

	require.NoError(t, err)
	resp, ok := result.(*transport.GetTenantResponse)
	require.True(t, ok, "result must be *transport.GetTenantResponse, got %T", result)
	assert.Equal(t, "Acme", resp.Tenant.Name)
}

func TestHandleGetTenant_NotFound(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	_, err := server.handleGetTenant(systemCtx(),
		tenantAdminRequest(t, "xkms.getTenant", TenantIDParams{TenantID: "missing"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, seal.ErrTenantNotFound))
}

// TestHandleGetTenant_CrossTenantDenied proves a tenant-scoped caller naming
// a different tenant is refused with the identical error a nonexistent
// tenant produces, matching REST's GetTenantHandler anti-enumeration
// behavior (pkg/api/rest/handlers_tenant.go).
func TestHandleGetTenant_CrossTenantDenied(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["other-tenant"] = &qrdbsdk.ServiceTenantInfo{ID: "other-tenant", Name: "Other"}
	server := newTenantAdminServer(t, fake)

	_, err := server.handleGetTenant(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.getTenant", TenantIDParams{TenantID: "other-tenant"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, seal.ErrTenantNotFound),
		"cross-tenant access must report the same refusal a genuine miss would")
}

// TestHandleGetTenant_SameTenantAllowed proves a tenant-scoped caller may
// still read its own tenant.
func TestHandleGetTenant_SameTenantAllowed(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["tenant-a"] = &qrdbsdk.ServiceTenantInfo{ID: "tenant-a", Name: "Mine"}
	server := newTenantAdminServer(t, fake)

	result, err := server.handleGetTenant(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.getTenant", TenantIDParams{TenantID: "tenant-a"}))

	require.NoError(t, err)
	resp, ok := result.(*transport.GetTenantResponse)
	require.True(t, ok, "result must be *transport.GetTenantResponse, got %T", result)
	assert.Equal(t, "Mine", resp.Tenant.Name)
}

func TestHandleListTenants_FiltersToOwnTenantWhenScoped(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["tenant-a"] = &qrdbsdk.ServiceTenantInfo{ID: "tenant-a"}
	fake.tenants["tenant-b"] = &qrdbsdk.ServiceTenantInfo{ID: "tenant-b"}
	server := newTenantAdminServer(t, fake)

	result, err := server.handleListTenants(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.listTenants", struct{}{}))

	require.NoError(t, err)
	resp, ok := result.(*transport.ListTenantsResponse)
	require.True(t, ok, "result must be *transport.ListTenantsResponse, got %T", result)
	require.Len(t, resp.Tenants, 1)
	assert.Equal(t, "tenant-a", resp.Tenants[0].ID)
}

func TestHandleListTenants_SystemSeesAll(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["tenant-a"] = &qrdbsdk.ServiceTenantInfo{ID: "tenant-a"}
	fake.tenants["tenant-b"] = &qrdbsdk.ServiceTenantInfo{ID: "tenant-b"}
	server := newTenantAdminServer(t, fake)

	result, err := server.handleListTenants(systemCtx(),
		tenantAdminRequest(t, "xkms.listTenants", struct{}{}))

	require.NoError(t, err)
	resp, ok := result.(*transport.ListTenantsResponse)
	require.True(t, ok, "result must be *transport.ListTenantsResponse, got %T", result)
	assert.Len(t, resp.Tenants, 2)
}

func TestHandleListTenants_NotConfigured(t *testing.T) {
	server := newTenantAdminServer(t, nil)

	_, err := server.handleListTenants(systemCtx(), tenantAdminRequest(t, "xkms.listTenants", struct{}{}))

	require.Error(t, err)
}

func TestHandleDeleteTenant_Success(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["t1"] = &qrdbsdk.ServiceTenantInfo{ID: "t1"}
	server := newTenantAdminServer(t, fake)

	result, err := server.handleDeleteTenant(systemCtx(),
		tenantAdminRequest(t, "xkms.deleteTenant", TenantIDParams{TenantID: "t1"}))

	require.NoError(t, err)
	assert.Equal(t, tenantAdminSuccess, result)
}

// TestHandleDeleteTenant_CrossTenantDenied mirrors REST's
// DeleteTenantHandler anti-enumeration behavior.
func TestHandleDeleteTenant_CrossTenantDenied(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["other-tenant"] = &qrdbsdk.ServiceTenantInfo{ID: "other-tenant"}
	server := newTenantAdminServer(t, fake)

	_, err := server.handleDeleteTenant(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.deleteTenant", TenantIDParams{TenantID: "other-tenant"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, seal.ErrTenantNotFound))
	_, stillThere := fake.tenants["other-tenant"]
	assert.True(t, stillThere, "a denied cross-tenant delete must never reach the service layer")
}

func TestHandleTenantBarrierInit_Success(t *testing.T) {
	fake := newFakeTenantServicer()
	server := newTenantAdminServer(t, fake)

	result, err := server.handleTenantBarrierInit(systemCtx(),
		tenantAdminRequest(t, "xkms.tenantBarrierInit", transport.TenantBarrierInitRequest{
			TenantID: "t1", Passphrase: []byte("s3cret!"),
		}))

	require.NoError(t, err)
	_, ok := result.(*transport.TenantBarrierStatusResponse)
	require.True(t, ok, "result must be *transport.TenantBarrierStatusResponse, got %T", result)
	assert.Equal(t, "t1", fake.initTenantID)
}

// TestHandleTenantBarrierInit_CrossTenantDenied mirrors REST's
// TenantBarrierInitHandler anti-enumeration behavior.
func TestHandleTenantBarrierInit_CrossTenantDenied(t *testing.T) {
	fake := newFakeTenantServicer()
	server := newTenantAdminServer(t, fake)

	_, err := server.handleTenantBarrierInit(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.tenantBarrierInit", transport.TenantBarrierInitRequest{
			TenantID: "other-tenant", Passphrase: []byte("s3cret!"),
		}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, seal.ErrTenantNotFound))
	assert.Empty(t, fake.initTenantID, "a denied cross-tenant init must never reach the service layer")
}

func TestHandleTenantBarrierInit_RequiresTenantID(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	_, err := server.handleTenantBarrierInit(systemCtx(),
		tenantAdminRequest(t, "xkms.tenantBarrierInit", transport.TenantBarrierInitRequest{}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

func TestHandleTenantBarrierUnseal_Success(t *testing.T) {
	fake := newFakeTenantServicer()
	server := newTenantAdminServer(t, fake)

	result, err := server.handleTenantBarrierUnseal(systemCtx(),
		tenantAdminRequest(t, "xkms.tenantBarrierUnseal", transport.TenantBarrierUnsealRequest{
			TenantID: "t1", Key: []byte("s3cret!"),
		}))

	require.NoError(t, err)
	_, ok := result.(*transport.TenantBarrierStatusResponse)
	require.True(t, ok, "result must be *transport.TenantBarrierStatusResponse, got %T", result)
	assert.Equal(t, "t1", fake.unsealTenantID)
}

// TestHandleTenantBarrierUnseal_CrossTenantDenied mirrors REST's
// TenantBarrierUnsealHandler anti-enumeration behavior.
func TestHandleTenantBarrierUnseal_CrossTenantDenied(t *testing.T) {
	fake := newFakeTenantServicer()
	server := newTenantAdminServer(t, fake)

	_, err := server.handleTenantBarrierUnseal(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.tenantBarrierUnseal", transport.TenantBarrierUnsealRequest{
			TenantID: "other-tenant", Key: []byte("s3cret!"),
		}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, seal.ErrTenantNotFound))
	assert.Empty(t, fake.unsealTenantID, "a denied cross-tenant unseal must never reach the service layer")
}

func TestHandleTenantBarrierStatus_Success(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	result, err := server.handleTenantBarrierStatus(systemCtx(),
		tenantAdminRequest(t, "xkms.tenantBarrierStatus", TenantIDParams{TenantID: "t1"}))

	require.NoError(t, err)
	resp, ok := result.(*transport.TenantBarrierStatusResponse)
	require.True(t, ok, "result must be *transport.TenantBarrierStatusResponse, got %T", result)
	assert.Equal(t, "t1", resp.TenantID)
}

// TestHandleTenantBarrierStatus_CrossTenantDenied mirrors REST's
// TenantBarrierStatusHandler anti-enumeration behavior.
func TestHandleTenantBarrierStatus_CrossTenantDenied(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	_, err := server.handleTenantBarrierStatus(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.tenantBarrierStatus", TenantIDParams{TenantID: "other-tenant"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, seal.ErrTenantNotFound))
}

func TestHandleUpdateTenantEntitlements_Success(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	result, err := server.handleUpdateTenantEntitlements(systemCtx(),
		tenantAdminRequest(t, "xkms.updateTenantEntitlements", transport.UpdateTenantEntitlementsRequest{
			TenantID: "t1", Entitlements: transport.TenantEntitlements{AllowDedicatedRaft: true},
		}))

	require.NoError(t, err)
	resp, ok := result.(*transport.UpdateTenantEntitlementsResponse)
	require.True(t, ok, "result must be *transport.UpdateTenantEntitlementsResponse, got %T", result)
	assert.Equal(t, "t1", resp.Tenant.ID)
}

func TestHandleUpdateTenantEntitlements_RequiresTenantID(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	_, err := server.handleUpdateTenantEntitlements(systemCtx(),
		tenantAdminRequest(t, "xkms.updateTenantEntitlements", transport.UpdateTenantEntitlementsRequest{}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

func TestHandleUpdateTenantQuotas_Success(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	result, err := server.handleUpdateTenantQuotas(systemCtx(),
		tenantAdminRequest(t, "xkms.updateTenantQuotas", transport.UpdateTenantQuotasRequest{
			TenantID: "t1", Quotas: transport.TenantQuotas{MaxKeys: 100},
		}))

	require.NoError(t, err)
	resp, ok := result.(*transport.UpdateTenantQuotasResponse)
	require.True(t, ok, "result must be *transport.UpdateTenantQuotasResponse, got %T", result)
	assert.Equal(t, "t1", resp.Tenant.ID)
}

func TestHandleUpdateTenantQuotas_RequiresTenantID(t *testing.T) {
	server := newTenantAdminServer(t, newFakeTenantServicer())

	_, err := server.handleUpdateTenantQuotas(systemCtx(),
		tenantAdminRequest(t, "xkms.updateTenantQuotas", transport.UpdateTenantQuotasRequest{}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

// TestTenantAdminAccessDenied covers tenantAdminAccessDenied's own decision
// table directly, independent of any handler.
func TestTenantAdminAccessDenied(t *testing.T) {
	tests := []struct {
		name     string
		identity *auth.Identity
		tenantID string
		want     bool
	}{
		{"nil identity may address any tenant", nil, "tenant-a", false},
		{"system tenant identity may address any tenant", &auth.Identity{TenantID: qrdbsdk.SystemTenantID}, "tenant-a", false},
		{"same tenant is allowed", &auth.Identity{TenantID: "tenant-a"}, "tenant-a", false},
		{"different tenant is denied", &auth.Identity{TenantID: "tenant-a"}, "tenant-b", true},
		{"empty target tenant is never cross-tenant", &auth.Identity{TenantID: "tenant-a"}, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tenantAdminAccessDenied(tc.identity, tc.tenantID))
		})
	}
}
