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

package xkms

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// fakeTenantServicer is a partial ServiceTenantServicer. Embedding the
// interface satisfies the (large) method set; only the methods the xkms tenant
// servicer delegates to are overridden, each capturing its call for assertions.
type fakeTenantServicer struct {
	qrdbsdk.ServiceTenantServicer

	createID, createName string
	createIsolation      qrdbsdk.TenantIsolationType
	createOptCount       int
	createReturn         *qrdbsdk.ServiceTenantInfo

	getReturn  *qrdbsdk.ServiceTenantInfo
	listReturn []qrdbsdk.ServiceTenantInfo

	deletedID string

	checkedTenantID     string
	checkedMode         qrdbsdk.StrategyID
	checkBarrierModeErr error
}

// CheckBarrierMode overrides the embedded interface's nil method (which would
// panic if invoked) with a deterministic allow-by-default result, recording the
// call for assertions. xkms does not currently delegate to it, but the override
// future-proofs the fake against the go-qrdb TenantServicer interface addition.
func (f *fakeTenantServicer) CheckBarrierMode(_ context.Context, tenantID string, mode qrdbsdk.StrategyID) error {
	f.checkedTenantID, f.checkedMode = tenantID, mode
	return f.checkBarrierModeErr
}

func (f *fakeTenantServicer) CreateTenant(_ context.Context, id, name string, iso qrdbsdk.TenantIsolationType, opts ...qrdbsdk.CreateTenantOption) (*qrdbsdk.ServiceTenantInfo, error) {
	f.createID, f.createName, f.createIsolation, f.createOptCount = id, name, iso, len(opts)
	if f.createReturn != nil {
		return f.createReturn, nil
	}
	return &qrdbsdk.ServiceTenantInfo{ID: id, Name: name, IsolationType: iso}, nil
}

func (f *fakeTenantServicer) GetTenant(_ context.Context, _ string) (*qrdbsdk.ServiceTenantInfo, error) {
	return f.getReturn, nil
}

func (f *fakeTenantServicer) ListTenants(_ context.Context) ([]qrdbsdk.ServiceTenantInfo, error) {
	return f.listReturn, nil
}

func (f *fakeTenantServicer) DeleteTenant(_ context.Context, id string) error {
	f.deletedID = id
	return nil
}

func (f *fakeTenantServicer) UpdateEntitlements(_ context.Context, tenantID string, ents *qrdbsdk.Entitlements) (*qrdbsdk.ServiceTenantInfo, error) {
	return &qrdbsdk.ServiceTenantInfo{ID: tenantID, Name: tenantID, Entitlements: ents}, nil
}

func (f *fakeTenantServicer) UpdateQuotas(_ context.Context, tenantID string, q *qrdbsdk.Quotas) (*qrdbsdk.ServiceTenantInfo, error) {
	return &qrdbsdk.ServiceTenantInfo{ID: tenantID, Name: tenantID, Quotas: q}, nil
}

func TestCreateTenant_DelegatesToTenantService(t *testing.T) {
	fake := &fakeTenantServicer{}
	svc := &XKMSService{}
	svc.SetTenantService(fake)

	resp, err := svc.CreateTenant(context.Background(), &transport.CreateTenantRequest{
		ID:                "acme",
		Name:              "Acme Corp",
		IsolationType:     transport.TenantIsolationType(qrdbsdk.TenantIsolationBarrier),
		BarrierAutoUnseal: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", fake.createID)
	assert.Equal(t, "Acme Corp", fake.createName)
	assert.Equal(t, qrdbsdk.TenantIsolationBarrier, fake.createIsolation)
	assert.Equal(t, 1, fake.createOptCount, "WithBarrierAutoUnseal option must be forwarded")
	assert.Equal(t, "acme", resp.Tenant.ID)
	assert.Equal(t, transport.TenantIsolationType(qrdbsdk.TenantIsolationBarrier), resp.Tenant.IsolationType)
}

func TestGetTenant_DelegatesAndMapsQuotasEntitlements(t *testing.T) {
	fake := &fakeTenantServicer{
		getReturn: &qrdbsdk.ServiceTenantInfo{
			ID:            "acme",
			Name:          "Acme",
			IsolationType: qrdbsdk.TenantIsolationVolume,
			Quotas:        &qrdbsdk.Quotas{MaxDatabases: 5, MaxKeys: 100},
			Entitlements:  &qrdbsdk.Entitlements{AllowVolumeStorage: true, AllowedIsolationModes: []string{"volume"}},
		},
	}
	svc := &XKMSService{}
	svc.SetTenantService(fake)

	resp, err := svc.GetTenant(context.Background(), "acme")
	require.NoError(t, err)
	require.NotNil(t, resp.Tenant.Quotas)
	assert.Equal(t, int64(5), resp.Tenant.Quotas.MaxDatabases)
	require.NotNil(t, resp.Tenant.Entitlements)
	assert.True(t, resp.Tenant.Entitlements.AllowVolumeStorage)
	assert.Equal(t, transport.TenantIsolationType(qrdbsdk.TenantIsolationVolume), resp.Tenant.IsolationType)
}

func TestListTenants_DelegatesAndMaps(t *testing.T) {
	fake := &fakeTenantServicer{
		listReturn: []qrdbsdk.ServiceTenantInfo{
			{ID: "a", Name: "A"},
			{ID: "b", Name: "B"},
		},
	}
	svc := &XKMSService{}
	svc.SetTenantService(fake)

	resp, err := svc.ListTenants(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Tenants, 2)
	assert.Equal(t, "a", resp.Tenants[0].ID)
	assert.Equal(t, "b", resp.Tenants[1].ID)
}

func TestDeleteTenant_Delegates(t *testing.T) {
	fake := &fakeTenantServicer{}
	svc := &XKMSService{}
	svc.SetTenantService(fake)

	require.NoError(t, svc.DeleteTenant(context.Background(), "acme"))
	assert.Equal(t, "acme", fake.deletedID)
}

func TestUpdateTenantEntitlements_Delegates(t *testing.T) {
	svc := &XKMSService{}
	svc.SetTenantService(&fakeTenantServicer{})

	resp, err := svc.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{
		TenantID: "acme",
		Entitlements: transport.TenantEntitlements{
			AllowedIsolationModes: []string{"prefix", "volume"},
			AllowVolumeStorage:    true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Tenant.Entitlements)
	assert.True(t, resp.Tenant.Entitlements.AllowVolumeStorage)
	assert.Equal(t, []string{"prefix", "volume"}, resp.Tenant.Entitlements.AllowedIsolationModes)
}

func TestUpdateTenantQuotas_Delegates(t *testing.T) {
	svc := &XKMSService{}
	svc.SetTenantService(&fakeTenantServicer{})

	resp, err := svc.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{
		TenantID: "acme",
		Quotas:   transport.TenantQuotas{MaxDatabases: 7, MaxKeys: 500},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Tenant.Quotas)
	assert.Equal(t, int64(7), resp.Tenant.Quotas.MaxDatabases)
	assert.Equal(t, int64(500), resp.Tenant.Quotas.MaxKeys)
}

func TestUpdateTenantEntitlements_RequiresTenantService(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{TenantID: "acme"})
	assert.ErrorIs(t, err, ErrTenantServiceNotConfigured)
}
