// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package multiprotocol

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantLifecycleMultiProtocol tests the complete tenant lifecycle across all protocols.
// This test follows the multi-protocol adapter pattern required by CLAUDE.md.
func TestTenantLifecycleMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	// Run the test against each protocol
	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testTenantLifecycle(t, ctx, adapter)
	})
}

// testTenantLifecycle performs the tenant lifecycle test using the provided adapter.
func testTenantLifecycle(t *testing.T, ctx context.Context, adapter api.AdminAdapter) {
	t.Helper()

	protocol := adapter.Protocol()
	tenantID := "test-tenant-" + string(protocol)

	// Create tenant
	tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "Test Tenant (" + string(protocol) + ")",
	})
	require.NoError(t, err, "CreateTenant should succeed via %s", protocol)
	assert.Equal(t, tenantID, tenant.ID)
	assert.Equal(t, "Test Tenant ("+string(protocol)+")", tenant.Name)
	assert.Equal(t, "active", tenant.Status)

	// Get tenant
	retrieved, err := adapter.GetTenant(ctx, tenantID)
	require.NoError(t, err, "GetTenant should succeed via %s", protocol)
	assert.Equal(t, tenant.ID, retrieved.ID)
	assert.Equal(t, tenant.Name, retrieved.Name)

	// Update tenant
	updated, err := adapter.UpdateTenant(ctx, tenantID, &admin.UpdateTenantRequest{
		Name: "Updated Tenant (" + string(protocol) + ")",
	})
	require.NoError(t, err, "UpdateTenant should succeed via %s", protocol)
	assert.Equal(t, "Updated Tenant ("+string(protocol)+")", updated.Name)

	// List tenants
	tenants, pagination, err := adapter.ListTenants(ctx, &admin.ListTenantsRequest{
		Page:    1,
		PerPage: 10,
	})
	require.NoError(t, err, "ListTenants should succeed via %s", protocol)
	assert.NotEmpty(t, tenants)
	assert.NotNil(t, pagination)

	// Delete tenant
	err = adapter.DeleteTenant(ctx, tenantID)
	require.NoError(t, err, "DeleteTenant should succeed via %s", protocol)

	// Verify deletion
	_, err = adapter.GetTenant(ctx, tenantID)
	assert.Error(t, err, "GetTenant should fail after deletion via %s", protocol)
}

// TestEABLifecycleMultiProtocol tests EAB operations across all protocols.
func TestEABLifecycleMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testEABLifecycle(t, ctx, adapter)
	})
}

func testEABLifecycle(t *testing.T, ctx context.Context, adapter api.AdminAdapter) {
	t.Helper()

	protocol := adapter.Protocol()
	tenantID := "eab-test-tenant-" + string(protocol)

	// Create tenant first
	_, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "EAB Test Tenant (" + string(protocol) + ")",
	})
	require.NoError(t, err)
	defer func() { _ = adapter.DeleteTenant(ctx, tenantID) }()

	// Create EAB
	eab, err := adapter.CreateEAB(ctx, tenantID, &admin.CreateEABRequest{
		Purpose:       "account-binding",
		ExpiresInDays: 30,
		Contact:       []string{"admin@example.com"},
	})
	require.NoError(t, err, "CreateEAB should succeed via %s", protocol)
	assert.NotEmpty(t, eab.ID)
	assert.NotEmpty(t, eab.MACKey)

	// Get EAB
	retrieved, err := adapter.GetEAB(ctx, tenantID, eab.ID)
	require.NoError(t, err, "GetEAB should succeed via %s", protocol)
	assert.Equal(t, eab.ID, retrieved.ID)

	// List EABs
	eabs, pagination, err := adapter.ListEABs(ctx, tenantID, &admin.ListEABRequest{
		Page:    1,
		PerPage: 10,
	})
	require.NoError(t, err, "ListEABs should succeed via %s", protocol)
	assert.NotEmpty(t, eabs)
	assert.NotNil(t, pagination)

	// Delete EAB
	err = adapter.DeleteEAB(ctx, tenantID, eab.ID)
	require.NoError(t, err, "DeleteEAB should succeed via %s", protocol)

	// Verify deletion
	_, err = adapter.GetEAB(ctx, tenantID, eab.ID)
	assert.Error(t, err, "GetEAB should fail after deletion via %s", protocol)
}

// TestCertificateOperationsMultiProtocol tests certificate operations across all protocols.
func TestCertificateOperationsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testCertificateOperations(t, ctx, adapter)
	})
}

func testCertificateOperations(t *testing.T, ctx context.Context, adapter api.AdminAdapter) {
	t.Helper()

	protocol := adapter.Protocol()

	// List certificates
	certs, pagination, err := adapter.ListCertificates(ctx, &admin.ListCertificatesRequest{
		Page:    1,
		PerPage: 10,
	})
	require.NoError(t, err, "ListCertificates should succeed via %s", protocol)
	// May be empty if no certificates exist
	assert.NotNil(t, pagination)
	_ = certs // Use variable
}

// TestStatusOperationsMultiProtocol tests status operations across all protocols.
func TestStatusOperationsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testStatusOperations(t, ctx, adapter)
	})
}

func testStatusOperations(t *testing.T, ctx context.Context, adapter api.AdminAdapter) {
	t.Helper()

	protocol := adapter.Protocol()

	// Get status
	status, err := adapter.GetStatus(ctx)
	require.NoError(t, err, "GetStatus should succeed via %s", protocol)
	assert.NotNil(t, status)

	// Get stats
	stats, err := adapter.GetStats(ctx)
	require.NoError(t, err, "GetStats should succeed via %s", protocol)
	assert.NotNil(t, stats)
}

// BenchmarkTenantCreateMultiProtocol benchmarks tenant creation across all protocols.
func BenchmarkTenantCreateMultiProtocol(b *testing.B) {
	tc := NewTestContext(&testing.T{})
	defer tc.Cleanup()

	ctx := context.Background()

	protocols := []struct {
		name    string
		adapter api.AdminAdapter
	}{
		{"REST", tc.RESTAdapter},
		{"gRPC", tc.GRPCAdapter},
		{"QUIC", tc.QUICAdapter},
		{"MCP", tc.MCPAdapter},
		{"gRPC-UDS", tc.GRPCUnixAdapter},
	}

	for _, p := range protocols {
		if p.adapter == nil {
			continue
		}

		// Skip stub adapters
		if _, ok := p.adapter.(*stubAdapter); ok {
			continue
		}

		b.Run(p.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tenantID := "bench-tenant-" + string(rune('a'+i%26))
				_, _ = p.adapter.CreateTenant(ctx, &admin.CreateTenantRequest{
					ID:   tenantID,
					Name: "Benchmark Tenant",
				})
				_ = p.adapter.DeleteTenant(ctx, tenantID)
			}
		})
	}
}
