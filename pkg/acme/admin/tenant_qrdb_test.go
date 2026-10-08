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
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	tenantpkg "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// fakeTenantServicer is a minimal in-memory qrdbsdk.ServiceTenantServicer
// double. Only the tenant-lifecycle methods (Create/Get/List/Update/Delete)
// that pkg/acme/admin's thin pass-through actually calls are exercised by
// these tests; every other method of the (large) TenantServicer interface is
// promoted from the nil embedded interface and panics if called, so an
// accidental new dependency on one fails loudly instead of silently
// returning a zero value.
type fakeTenantServicer struct {
	qrdbsdk.ServiceTenantServicer
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

// ReconcileDeletedTenants has no residue to remove: the fake hard-deletes.
func (f *fakeTenantServicer) ReconcileDeletedTenants(context.Context) (*tenantpkg.ReconcileReport, error) {
	return &tenantpkg.ReconcileReport{}, nil
}

// ListDeletedTenants reports no deleted tenants: the fake hard-deletes.
func (f *fakeTenantServicer) ListDeletedTenants(context.Context, string, int) (*tenantpkg.DeletedTenantsPage, error) {
	return &tenantpkg.DeletedTenantsPage{}, nil
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

var _ qrdbsdk.ServiceTenantServicer = (*fakeTenantServicer)(nil)

// TestTenantAwareAdminService_TenantLifecycle_NoQRDBFailsClosed proves that
// without SetTenantService, every tenant identity lifecycle method fails
// with ErrTenantServiceUnavailable rather than silently falling back to a
// local-only entities.Tenant model — qrdb is the single tenant authority,
// per the owner decision this change implements.
func TestTenantAwareAdminService_TenantLifecycle_NoQRDBFailsClosed(t *testing.T) {
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
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
