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
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-qrdb/pkg/ceremony"
	"github.com/jeremyhahn/go-qrdb/pkg/quota"
	"github.com/jeremyhahn/go-qrdb/pkg/seal"
	tenantpkg "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// fakeTenantServicer is a minimal in-memory qrdbsdk.ServiceTenantServicer
// double. Only the tenant-lifecycle methods (Create/Get/List/Update/Delete)
// that pkg/acme/admin's thin pass-through actually calls are exercised by
// these tests; every other method of the (large) TenantServicer interface
// panics if called, so an accidental new dependency on one fails loudly
// instead of silently returning a zero value.
type fakeTenantServicer struct {
	tenants map[string]*qrdbsdk.ServiceTenantInfo
}

func newFakeTenantServicer() *fakeTenantServicer {
	return &fakeTenantServicer{tenants: map[string]*qrdbsdk.ServiceTenantInfo{}}
}

func (f *fakeTenantServicer) CreateTenant(ctx context.Context, id, name string, isolationType qrdbsdk.TenantIsolationType, opts ...qrdbsdk.CreateTenantOption) (*qrdbsdk.ServiceTenantInfo, error) {
	if _, exists := f.tenants[id]; exists {
		return nil, qrdbsdk.ErrTenantExists
	}
	now := time.Now()
	t := &qrdbsdk.ServiceTenantInfo{ID: id, Name: name, CreatedAt: now, UpdatedAt: now}
	f.tenants[id] = t
	cp := *t
	return &cp, nil
}

func (f *fakeTenantServicer) GetTenant(ctx context.Context, tenantID string) (*qrdbsdk.ServiceTenantInfo, error) {
	t, ok := f.tenants[tenantID]
	if !ok {
		return nil, qrdbsdk.ErrTenantMissing
	}
	cp := *t
	return &cp, nil
}

func (f *fakeTenantServicer) ListTenants(ctx context.Context) ([]qrdbsdk.ServiceTenantInfo, error) {
	out := make([]qrdbsdk.ServiceTenantInfo, 0, len(f.tenants))
	for _, t := range f.tenants {
		out = append(out, *t)
	}
	return out, nil
}

func (f *fakeTenantServicer) DeleteTenant(ctx context.Context, tenantID string) error {
	if _, ok := f.tenants[tenantID]; !ok {
		return qrdbsdk.ErrTenantMissing
	}
	delete(f.tenants, tenantID)
	return nil
}

func (f *fakeTenantServicer) UpdateTenant(ctx context.Context, tenantID string, patch qrdbsdk.TenantPatch) (*qrdbsdk.ServiceTenantInfo, error) {
	t, ok := f.tenants[tenantID]
	if !ok {
		return nil, qrdbsdk.ErrTenantMissing
	}
	if patch.Name != "" {
		t.Name = patch.Name
	}
	t.UpdatedAt = time.Now()
	cp := *t
	return &cp, nil
}

func (f *fakeTenantServicer) notImplemented() {
	panic("fakeTenantServicer: method not exercised by these tests")
}

func (f *fakeTenantServicer) UpdateQuotas(context.Context, string, *quota.Quotas) (*tenantpkg.TenantInfo, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) UpdateEntitlements(context.Context, string, *quota.Entitlements) (*tenantpkg.TenantInfo, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) CheckBarrierMode(context.Context, string, seal.StrategyID) error {
	f.notImplemented()
	return nil
}
func (f *fakeTenantServicer) IncrementQuotaUsage(context.Context, string, quota.Resource, int64) (*tenantpkg.TenantInfo, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) DecrementQuotaUsage(context.Context, string, quota.Resource, int64) (*tenantpkg.TenantInfo, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) GetQuotaUsage(context.Context, string, quota.Resource) (int64, error) {
	f.notImplemented()
	return 0, nil
}
func (f *fakeTenantServicer) TenantBarrierInit(context.Context, string, string, int, int) (*tenantpkg.TenantBarrierInitResult, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierInitWithStrategy(context.Context, string, string, int, int, seal.StrategyID) (*tenantpkg.TenantBarrierInitResult, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierUnseal(context.Context, string, []byte) error {
	f.notImplemented()
	return nil
}
func (f *fakeTenantServicer) TenantBarrierUnsealShare(context.Context, string, string) (*tenantpkg.TenantBarrierUnsealProgress, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierSeal(context.Context, string) error {
	f.notImplemented()
	return nil
}
func (f *fakeTenantServicer) TenantBarrierStatus(context.Context, string) (*tenantpkg.TenantBarrierStatus, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierOfficerRegister(context.Context, string, *ceremony.RegisterOfficerRequest) (*ceremony.RegisterOfficerResult, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierOfficerList(context.Context, string) ([]*ceremony.OfficerStatus, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierShareClaimBegin(context.Context, string, string, string) (*ceremony.ChallengeResponse, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierShareClaimComplete(context.Context, string, string, string, []byte, string) (*ceremony.ShareClaimResult, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierOfficerClaimStatus(context.Context, string) ([]*ceremony.OfficerStatus, error) {
	f.notImplemented()
	return nil, nil
}
func (f *fakeTenantServicer) TenantBarrierShamirSealVote(context.Context, string, string) (*tenantpkg.TenantBarrierUnsealProgress, error) {
	f.notImplemented()
	return nil, nil
}

var _ qrdbsdk.ServiceTenantServicer = (*fakeTenantServicer)(nil)

// TestTenantAwareAdminService_CreateTenant_DelegatesToQRDB proves that once
// a qrdb TenantServicer is wired (SetTenantService), CreateTenant delegates
// tenant identity registration to it rather than the local entities.Tenant
// DAO — the owner decision this change implements.
func TestTenantAwareAdminService_CreateTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := NewTenantAwareAdminService(nil, nil, nil, slog.Default(), "1.0.0")
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
	svc := NewTenantAwareAdminService(nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "dup", Name: "Dup"})
	require.NoError(t, err)

	_, err = svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "dup", Name: "Dup Again"})
	assert.ErrorIs(t, err, ErrTenantAlreadyExists)
}

// TestTenantAwareAdminService_GetTenant_DelegatesToQRDB proves GetTenant
// answers ErrTenantNotFound (the admin package's sentinel) for a tenant
// qrdb does not know about, and returns qrdb's copy for one it does.
func TestTenantAwareAdminService_GetTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := NewTenantAwareAdminService(nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := svc.GetTenant(context.Background(), "missing")
	assert.ErrorIs(t, err, ErrTenantNotFound)

	_, err = fake.CreateTenant(context.Background(), "known", "Known Tenant", "")
	require.NoError(t, err)

	info, err := svc.GetTenant(context.Background(), "known")
	require.NoError(t, err)
	assert.Equal(t, "Known Tenant", info.Name)
}

// TestTenantAwareAdminService_UpdateTenant_DelegatesToQRDB proves the name
// patch reaches qrdb.
func TestTenantAwareAdminService_UpdateTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := NewTenantAwareAdminService(nil, nil, nil, slog.Default(), "1.0.0")
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

// TestTenantAwareAdminService_DeleteTenant_DelegatesToQRDB proves deletion
// removes the tenant from qrdb (the canonical store) and that a repeat
// delete answers ErrTenantNotFound.
func TestTenantAwareAdminService_DeleteTenant_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := NewTenantAwareAdminService(nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	_, err := fake.CreateTenant(context.Background(), "gone-soon", "Gone Soon", "")
	require.NoError(t, err)

	require.NoError(t, svc.DeleteTenant(context.Background(), "gone-soon"))
	_, err = fake.GetTenant(context.Background(), "gone-soon")
	assert.True(t, errors.Is(err, qrdbsdk.ErrTenantMissing))

	err = svc.DeleteTenant(context.Background(), "gone-soon")
	assert.ErrorIs(t, err, ErrTenantNotFound)
}

// TestTenantAwareAdminService_ListTenants_DelegatesToQRDB proves the listed
// set comes from qrdb rather than an empty/local-only result.
func TestTenantAwareAdminService_ListTenants_DelegatesToQRDB(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := NewTenantAwareAdminService(nil, nil, nil, slog.Default(), "1.0.0")
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

// TestTenantAwareAdminService_TenantLifecycle_NoQRDBFailsClosed proves that
// without SetTenantService, every tenant identity lifecycle method fails
// with ErrTenantServiceUnavailable rather than silently falling back to a
// local-only entities.Tenant model — qrdb is the single tenant authority,
// per the owner decision this change implements.
func TestTenantAwareAdminService_TenantLifecycle_NoQRDBFailsClosed(t *testing.T) {
	svc := NewTenantAwareAdminService(nil, nil, nil, slog.Default(), "1.0.0")
	// No SetTenantService call.
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, CreateTenantRequest{ID: "local-only", Name: "Local Only"})
	assert.ErrorIs(t, err, ErrTenantServiceUnavailable)

	_, err = svc.GetTenant(ctx, "local-only")
	assert.ErrorIs(t, err, ErrTenantServiceUnavailable)

	_, err = svc.UpdateTenant(ctx, "local-only", UpdateTenantRequest{Name: "New Name"})
	assert.ErrorIs(t, err, ErrTenantServiceUnavailable)

	err = svc.DeleteTenant(ctx, "local-only")
	assert.ErrorIs(t, err, ErrTenantServiceUnavailable)

	_, _, err = svc.ListTenants(ctx, ListTenantsRequest{})
	assert.ErrorIs(t, err, ErrTenantServiceUnavailable)
}
