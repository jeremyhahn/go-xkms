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
// ServiceTenantServicer, and the mapping of XKMSService's cross-tenant
// refusal (xkms.TenantBindingError) onto the same not-found a genuine miss
// produces.
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
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// fakeTenantServicer is a partial qrdbsdk.ServiceTenantServicer. Embedding
// the interface satisfies its (large) method set; only the methods the MCP
// tenant admin handlers delegate to are overridden.
type fakeTenantServicer struct {
	qrdbsdk.ServiceTenantServicer

	tenants map[string]*qrdbsdk.ServiceTenantInfo
	err     error

	unsealTenantID string
	planTenantID   string
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
		// go-qrdb's TenantService reports an unknown tenant with this
		// sentinel, unwrapped.
		return nil, qrdbsdk.ErrTenantMissing
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
		return qrdbsdk.ErrTenantMissing
	}
	delete(f.tenants, id)
	return nil
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
	f.planTenantID = id
	return &qrdbsdk.ServiceTenantInfo{ID: id, Entitlements: ents}, nil
}

func (f *fakeTenantServicer) UpdateQuotas(_ context.Context, id string, q *qrdbsdk.Quotas) (*qrdbsdk.ServiceTenantInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.planTenantID = id
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
	assert.True(t, errors.Is(err, qrdbsdk.ErrTenantMissing))
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
	assert.True(t, errors.Is(err, qrdbsdk.ErrTenantMissing),
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
	assert.True(t, errors.Is(err, qrdbsdk.ErrTenantMissing))
	_, stillThere := fake.tenants["other-tenant"]
	assert.True(t, stillThere, "a denied cross-tenant delete must never reach the service layer")
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

// TestHandleGetTenant_CrossTenantRefusalMatchesGenuineMiss proves the MCP
// rendering of XKMSService's tenant binding refusal is byte-for-byte the
// answer a nonexistent tenant gets: same JSON-RPC code, same message. A
// tenant-scoped probe therefore cannot tell another tenant's ID from an
// unused one.
func TestHandleGetTenant_CrossTenantRefusalMatchesGenuineMiss(t *testing.T) {
	fake := newFakeTenantServicer()
	fake.tenants["other-tenant"] = &qrdbsdk.ServiceTenantInfo{ID: "other-tenant", Name: "Other"}
	server := newTenantAdminServer(t, fake)

	_, refused := server.handleGetTenant(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.getTenant", TenantIDParams{TenantID: "other-tenant"}))
	_, missing := server.handleGetTenant(systemCtx(),
		tenantAdminRequest(t, "xkms.getTenant", TenantIDParams{TenantID: "no-such-tenant"}))

	var refusedErr, missingErr *KeyOpError
	require.ErrorAs(t, refused, &refusedErr)
	require.ErrorAs(t, missing, &missingErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, refusedErr.Code)
	assert.Equal(t, missingErr.Code, refusedErr.Code)
	assert.Equal(t, missingErr.Error(), refusedErr.Error())
}

// TestHandleUpdateTenantPlan_TenantScopedRefused proves a tenant-scoped
// caller cannot change even its OWN tenant's entitlements or quotas: plan
// management is platform-only, and the refusal is the not-found answer, never
// reaching the tenant service.
func TestHandleUpdateTenantPlan_TenantScopedRefused(t *testing.T) {
	fake := newFakeTenantServicer()
	server := newTenantAdminServer(t, fake)

	_, err := server.handleUpdateTenantEntitlements(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.updateTenantEntitlements", transport.UpdateTenantEntitlementsRequest{
			TenantID: "tenant-a", Entitlements: transport.TenantEntitlements{AllowDedicatedRaft: true},
		}))
	var keyOpErr *KeyOpError
	require.ErrorAs(t, err, &keyOpErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyOpErr.Code)

	_, err = server.handleUpdateTenantQuotas(scopedCtx("tenant-a"),
		tenantAdminRequest(t, "xkms.updateTenantQuotas", transport.UpdateTenantQuotasRequest{
			TenantID: "tenant-a", Quotas: transport.TenantQuotas{MaxKeys: 1_000_000},
		}))
	require.ErrorAs(t, err, &keyOpErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyOpErr.Code)

	assert.Empty(t, fake.planTenantID, "a refused plan change must never reach the tenant service")
}
