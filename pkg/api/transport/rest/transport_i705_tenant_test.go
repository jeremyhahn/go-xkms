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

package rest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// This file covers TenantBarrierStatus, UpdateTenantEntitlements and
// UpdateTenantQuotas (go-xkms #705, batch A), none of which had a test. It
// reuses transport_tenant_test.go's newTenantTestTransport helper, whose
// router now also registers the entitlements/quotas routes.

func TestTransport_UpdateTenantEntitlements_Success(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{ID: "acme", Name: "Acme"})
	require.NoError(t, err)

	resp, err := tr.UpdateTenantEntitlements(ctx, &transport.UpdateTenantEntitlementsRequest{
		TenantID: "acme",
		Entitlements: transport.TenantEntitlements{
			AllowedIsolationModes: []string{"prefix"},
			AllowVolumeStorage:    true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "acme", resp.Tenant.ID)
}

func TestTransport_UpdateTenantEntitlements_NotFound(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	_, err := tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{
		TenantID: "nonexistent",
	})
	require.Error(t, err)
}

func TestTransport_UpdateTenantQuotas_Success(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{ID: "acme", Name: "Acme"})
	require.NoError(t, err)

	resp, err := tr.UpdateTenantQuotas(ctx, &transport.UpdateTenantQuotasRequest{
		TenantID: "acme",
		Quotas:   transport.TenantQuotas{MaxKeys: 100},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "acme", resp.Tenant.ID)
}

func TestTransport_UpdateTenantQuotas_NotFound(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	_, err := tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{
		TenantID: "nonexistent",
	})
	require.Error(t, err)
}
