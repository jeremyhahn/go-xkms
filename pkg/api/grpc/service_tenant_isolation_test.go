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

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newTenantServiceWiredXKMS builds an XKMSService backed by go-qrdb's
// TenantService composed over an unsealed in-memory barrier, so the gRPC tenant
// handlers exercise the servicer-routed (isolation-aware) path rather than the
// legacy barrier-registry fallback.
func newTenantServiceWiredXKMS(t *testing.T) *xkms.XKMSService {
	t.Helper()
	ctx := context.Background()

	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(discardLogger(), base, seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)

	creds := seal.Credentials{Secret: []byte("test-password")}
	require.NoError(t, barrier.Initialize(ctx, creds))
	if barrier.IsSealed() {
		require.NoError(t, barrier.Unseal(ctx, creds))
	}

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	tenantSvc, err := seal.NewHardwareTenantService(barrier, registry, discardLogger(), nil)
	require.NoError(t, err)

	setupXKMSForTest(t)
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetBarrierRegistry(registry)
	svc.SetTenantService(tenantSvc)
	t.Cleanup(func() { xkms.Reset() })
	return svc
}

// TestCreateTenant_ServicerRoutedIsolation verifies that a CreateTenant gRPC
// call routes through the XKMSService servicer (go-qrdb TenantService) and that
// the requested isolation mode round-trips on the response.
func TestCreateTenant_ServicerRoutedIsolation(t *testing.T) {
	svc := newTenantServiceWiredXKMS(t)
	grpcSvc := NewService(nil, nil, svc)

	resp, err := grpcSvc.CreateTenant(context.Background(), &pb.CreateTenantRequest{
		Id:            "acme",
		Name:          "Acme Corp",
		IsolationType: "prefix",
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.Tenant.Id)
	assert.Equal(t, "Acme Corp", resp.Tenant.Name)
	assert.Equal(t, "prefix", resp.Tenant.IsolationType)

	// And it is retrievable with the isolation metadata preserved.
	getResp, err := grpcSvc.GetTenant(context.Background(), &pb.GetTenantRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "acme", getResp.Tenant.Id)
	assert.Equal(t, "prefix", getResp.Tenant.IsolationType)
}

// TestUpdateTenantEntitlementsAndQuotas_ServicerRouted verifies the operator
// management RPCs round-trip through the gRPC handlers, the XKMSService
// servicer, and go-qrdb's TenantService (including the proto<->wire mapping of
// quotas and entitlements).
func TestUpdateTenantEntitlementsAndQuotas_ServicerRouted(t *testing.T) {
	svc := newTenantServiceWiredXKMS(t)
	grpcSvc := NewService(nil, nil, svc)
	ctx := context.Background()

	_, err := grpcSvc.CreateTenant(ctx, &pb.CreateTenantRequest{Id: "acme", Name: "Acme", IsolationType: "prefix"})
	require.NoError(t, err)

	entResp, err := grpcSvc.UpdateTenantEntitlements(ctx, &pb.UpdateTenantEntitlementsRequest{
		TenantId: "acme",
		Entitlements: &pb.TenantEntitlements{
			AllowedIsolationModes: []string{"prefix", "volume"},
			AllowVolumeStorage:    true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, entResp.Tenant.Entitlements)
	assert.True(t, entResp.Tenant.Entitlements.AllowVolumeStorage)
	assert.Equal(t, []string{"prefix", "volume"}, entResp.Tenant.Entitlements.AllowedIsolationModes)

	quotaResp, err := grpcSvc.UpdateTenantQuotas(ctx, &pb.UpdateTenantQuotasRequest{
		TenantId: "acme",
		Quotas:   &pb.TenantQuotas{MaxDatabases: 9, MaxKeys: 250},
	})
	require.NoError(t, err)
	require.NotNil(t, quotaResp.Tenant.Quotas)
	assert.Equal(t, int64(9), quotaResp.Tenant.Quotas.MaxDatabases)
	assert.Equal(t, int64(250), quotaResp.Tenant.Quotas.MaxKeys)
}
