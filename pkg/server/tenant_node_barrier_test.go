// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	"github.com/stretchr/testify/require"
)

// TestNodeBarrier_TenantCreateGetList is a regression test (bootstrap suite): a
// just-created default (prefix) isolation tenant should be readable immediately
// via GetTenant on a node-barrier (passphrase-sealed qrdb) deployment.
func TestNodeBarrier_TenantCreateGetList(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{
		Enabled:    true,
		Strategy:   "passphrase",
		Passphrase: "test-node-seal-boot-secret",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	require.True(t, server.nodeSealEnabled, "node-seal flip must engage")
	require.NotNil(t, server.xkmsService)

	ctx := context.Background()
	const tenantID = "repro-tenant-1"

	createResp, err := server.xkmsService.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   tenantID,
		Name: "Repro Tenant",
	})
	require.NoError(t, err, "CreateTenant should succeed")
	t.Logf("CreateTenant OK: id=%s name=%s", createResp.Tenant.ID, createResp.Tenant.Name)

	// The smoking gun: read it back immediately.
	getResp, getErr := server.xkmsService.GetTenant(ctx, tenantID)
	if getErr != nil {
		t.Fatalf("GetTenant right after CreateTenant FAILED: %v", getErr)
	}
	t.Logf("GetTenant OK: id=%s name=%s", getResp.Tenant.ID, getResp.Tenant.Name)

	// Also exercise List for good measure.
	listResp, listErr := server.xkmsService.ListTenants(ctx)
	require.NoError(t, listErr, "ListTenants should succeed")
	t.Logf("ListTenants returned %d tenant(s)", len(listResp.Tenants))
}
