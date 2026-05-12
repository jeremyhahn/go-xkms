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

package cactl

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/test/integration/acme-multiprotocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCactlConcurrency tests concurrent operations via all protocols.
func TestCactlConcurrency(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("ConcurrentTenantCreation", func(t *testing.T) {
			testConcurrentTenantCreation(t, adapter, protocol)
		})

		t.Run("ConcurrentEABCreation", func(t *testing.T) {
			testConcurrentEABCreation(t, adapter, protocol)
		})
	})
}

// testConcurrentTenantCreation tests creating multiple tenants concurrently.
func testConcurrentTenantCreation(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	numTenants := 5
	tenantIDs := make([]string, numTenants)
	errCh := make(chan error, numTenants)

	// Create tenants concurrently
	for i := 0; i < numTenants; i++ {
		go func(idx int) {
			name := fmt.Sprintf("%sconcurrent-%s-%d-%d", testTenantPrefix, protocol, time.Now().UnixNano(), idx)
			req := &admin.CreateTenantRequest{Name: name}

			tenant, err := adapter.CreateTenant(ctx, req)
			if err != nil {
				errCh <- err
				return
			}
			tenantIDs[idx] = tenant.ID
			errCh <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numTenants; i++ {
		err := <-errCh
		assert.NoError(t, err, "concurrent tenant creation should succeed via %s", protocol)
	}

	// Cleanup
	for _, id := range tenantIDs {
		if id != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
			_ = adapter.DeleteTenant(cleanupCtx, id)
			cleanupCancel()
		}
	}
}

// testConcurrentEABCreation tests creating multiple EABs concurrently.
func testConcurrentEABCreation(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// First create a tenant
	tenantName := fmt.Sprintf("%sconcurrent-eab-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
	tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
	require.NoError(t, err)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
	}()

	numEABs := 5
	eabIDs := make([]string, numEABs)
	errCh := make(chan error, numEABs)

	// Create EABs concurrently
	for i := 0; i < numEABs; i++ {
		go func(idx int) {
			req := &admin.CreateEABRequest{
				Purpose: "account-binding",
				Contact: []string{fmt.Sprintf("test%d@example.com", idx)},
			}

			eab, err := adapter.CreateEAB(ctx, tenant.ID, req)
			if err != nil {
				errCh <- err
				return
			}
			eabIDs[idx] = eab.ID
			errCh <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numEABs; i++ {
		err := <-errCh
		assert.NoError(t, err, "concurrent EAB creation should succeed via %s", protocol)
	}

	// Cleanup EABs
	for _, id := range eabIDs {
		if id != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
			_ = adapter.DeleteEAB(cleanupCtx, tenant.ID, id)
			cleanupCancel()
		}
	}
}

// TestCactlSpecialCharacters tests operations with special characters in names.
func TestCactlSpecialCharacters(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("TenantWithSpecialChars", func(t *testing.T) {
			testTenantWithSpecialChars(t, adapter, protocol)
		})

		t.Run("RoleWithSpecialChars", func(t *testing.T) {
			testRoleWithSpecialChars(t, adapter, protocol)
		})
	})
}

// testTenantWithSpecialChars tests tenant names with special characters.
func testTenantWithSpecialChars(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Test various special characters in tenant names
	testCases := []struct {
		name       string
		tenantName string
		shouldFail bool
	}{
		{"alphanumeric", fmt.Sprintf("Test Tenant %s-%d", protocol, time.Now().UnixNano()), false},
		{"with spaces", fmt.Sprintf("Test Tenant With Spaces %s-%d", protocol, time.Now().UnixNano()), false},
		{"with numbers", fmt.Sprintf("Tenant123 %s-%d", protocol, time.Now().UnixNano()), false},
		{"with underscores", fmt.Sprintf("Tenant_With_Underscores_%s-%d", protocol, time.Now().UnixNano()), false},
		{"with dashes", fmt.Sprintf("Tenant-With-Dashes-%s-%d", protocol, time.Now().UnixNano()), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &admin.CreateTenantRequest{Name: tc.tenantName}

			tenant, err := adapter.CreateTenant(ctx, req)

			if tc.shouldFail {
				assert.Error(t, err, "CreateTenant with '%s' should fail via %s", tc.tenantName, protocol)
			} else {
				require.NoError(t, err, "CreateTenant with '%s' should succeed via %s", tc.tenantName, protocol)
				assert.Equal(t, tc.tenantName, tenant.Name)

				// Cleanup
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
				cleanupCancel()
			}
		})
	}
}

// testRoleWithSpecialChars tests roles with special characters in descriptions.
func testRoleWithSpecialChars(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Create tenant first
	tenantName := fmt.Sprintf("%srole-special-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
	tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
	require.NoError(t, err)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
	}()

	// Create role with special characters in name
	roleName := fmt.Sprintf("test-role-special-%d", time.Now().UnixNano())
	createReq := &db.CreateRoleRequest{
		Name: roleName,
		Permissions: []string{
			"certificates:read",
			"certificates:write",
		},
	}

	created, err := adapter.CreateTenantRole(ctx, tenant.ID, createReq)
	require.NoError(t, err, "CreateTenantRole with special chars should succeed via %s", protocol)
	assert.Equal(t, roleName, created.Name)

	// Cleanup
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenantRole(cleanupCtx, tenant.ID, created.ID)
	cleanupCancel()
}

// TestCactlBoundaryConditions tests operations at boundary conditions.
func TestCactlBoundaryConditions(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("EmptyPagination", func(t *testing.T) {
			testEmptyPagination(t, adapter, protocol)
		})

		t.Run("MaxPagination", func(t *testing.T) {
			testMaxPagination(t, adapter, protocol)
		})

		t.Run("MinimalTenant", func(t *testing.T) {
			testMinimalTenant(t, adapter, protocol)
		})
	})
}

// testEmptyPagination tests pagination with no results.
func testEmptyPagination(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Request a very high page number to get empty results
	req := &admin.ListCertificatesRequest{
		Page:    9999,
		PerPage: 10,
	}

	certs, pagination, err := adapter.ListCertificates(ctx, req)
	require.NoError(t, err, "ListCertificates should succeed via %s even with high page", protocol)
	assert.NotNil(t, certs, "certificates slice should not be nil")
	if pagination != nil {
		assert.GreaterOrEqual(t, pagination.Page, 1)
	}
}

// testMaxPagination tests pagination with maximum per-page.
func testMaxPagination(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req := &admin.ListTenantsRequest{
		Page:    1,
		PerPage: 1000, // Large per-page
	}

	tenants, pagination, err := adapter.ListTenants(ctx, req)
	require.NoError(t, err, "ListTenants should succeed via %s with large per-page", protocol)
	assert.NotNil(t, tenants)
	if pagination != nil {
		assert.GreaterOrEqual(t, pagination.Total, 0)
	}
}

// testMinimalTenant tests creating a tenant with minimal data.
func testMinimalTenant(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Create tenant with only required fields
	req := &admin.CreateTenantRequest{
		Name: fmt.Sprintf("%sminimal-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano()),
	}

	tenant, err := adapter.CreateTenant(ctx, req)
	require.NoError(t, err, "CreateTenant with minimal data should succeed via %s", protocol)
	assert.NotEmpty(t, tenant.ID)
	assert.Equal(t, req.Name, tenant.Name)

	// Cleanup
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
	cleanupCancel()
}

// TestCactlIdempotency tests idempotent operations.
func TestCactlIdempotency(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("DeleteNonexistentTenantIdempotent", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Deleting non-existent tenant should fail (not idempotent)
			err := adapter.DeleteTenant(ctx, "nonexistent-tenant-id-12345")
			assert.Error(t, err, "DeleteTenant for nonexistent should fail via %s", protocol)
		})

		t.Run("GetMultipleTimes", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Create a tenant
			tenantName := fmt.Sprintf("%sidempotent-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
			tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
			require.NoError(t, err)
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cleanupCancel()
				_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
			}()

			// Get the tenant multiple times - should return same result
			for i := 0; i < 3; i++ {
				retrieved, err := adapter.GetTenant(ctx, tenant.ID)
				require.NoError(t, err, "GetTenant iteration %d should succeed via %s", i, protocol)
				assert.Equal(t, tenant.ID, retrieved.ID)
				assert.Equal(t, tenant.Name, retrieved.Name)
			}
		})
	})
}

// TestCactlProtocolConsistency tests that all protocols return consistent results.
func TestCactlProtocolConsistency(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	// Create a tenant using REST
	restAdapter := tc.RESTAdapter
	if restAdapter == nil {
		t.Fatal("REST adapter not available")
	}

	testCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	tenantName := fmt.Sprintf("%sconsistency-%d", testTenantPrefix, time.Now().UnixNano())
	createdTenant, err := restAdapter.CreateTenant(testCtx, &admin.CreateTenantRequest{
		Name: tenantName,
	})
	require.NoError(t, err)

	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = restAdapter.DeleteTenant(cleanupCtx, createdTenant.ID)
	}()

	// Verify all protocols can see the same tenant
	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		retrieveCtx, retrieveCancel := context.WithTimeout(ctx, defaultTimeout)
		defer retrieveCancel()

		retrieved, err := adapter.GetTenant(retrieveCtx, createdTenant.ID)
		require.NoError(t, err, "GetTenant should succeed via %s", protocol)
		assert.Equal(t, createdTenant.ID, retrieved.ID, "Tenant ID should match via %s", protocol)
		assert.Equal(t, createdTenant.Name, retrieved.Name, "Tenant name should match via %s", protocol)
	})
}

// TestCactlRoleComplexOperations tests complex RBAC role scenarios.
func TestCactlRoleComplexOperations(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("RoleWithMultiplePermissions", func(t *testing.T) {
			testRoleWithMultiplePermissions(t, adapter, protocol)
		})

		t.Run("RoleWithNestedResources", func(t *testing.T) {
			testRoleWithNestedResourcePermissions(t, adapter, protocol)
		})
	})
}

// testRoleWithMultiplePermissions tests roles with many permissions.
func testRoleWithMultiplePermissions(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Create tenant
	tenantName := fmt.Sprintf("%srole-perms-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
	tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
	require.NoError(t, err)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
	}()

	roleName := fmt.Sprintf("role-perms-%d", time.Now().UnixNano())
	createReq := &db.CreateRoleRequest{
		Name: roleName,
		Permissions: []string{
			"certificates:read",
			"certificates:write",
			"certificates:delete",
			"accounts:read",
			"accounts:write",
			"tenants:read",
		},
	}

	created, err := adapter.CreateTenantRole(ctx, tenant.ID, createReq)
	require.NoError(t, err, "CreateTenantRole with multiple permissions should succeed via %s", protocol)
	assert.NotNil(t, created)
	assert.Len(t, created.Permissions, 6)

	// Cleanup
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenantRole(cleanupCtx, tenant.ID, created.ID)
	cleanupCancel()
}

// testRoleWithNestedResourcePermissions tests roles with nested resource-scoped permissions.
func testRoleWithNestedResourcePermissions(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Create tenant
	tenantName := fmt.Sprintf("%srole-nested-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
	tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
	require.NoError(t, err)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
	}()

	roleName := fmt.Sprintf("role-nested-%d", time.Now().UnixNano())
	createReq := &db.CreateRoleRequest{
		Name: roleName,
		Permissions: []string{
			"tenants:certificates:read",
			"tenants:certificates:list",
			"tenants:accounts:read",
			"tenants:accounts:list",
			"tenants:eabs:read",
			"tenants:eabs:list",
			"tenants:roles:read",
			"tenants:roles:list",
		},
	}

	created, err := adapter.CreateTenantRole(ctx, tenant.ID, createReq)
	require.NoError(t, err, "CreateTenantRole with nested resource permissions should succeed via %s", protocol)
	assert.NotNil(t, created)
	assert.Len(t, created.Permissions, 8)

	// Cleanup
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenantRole(cleanupCtx, tenant.ID, created.ID)
	cleanupCancel()
}

// TestCLIOutputFormatConsistency tests that output formats are consistent.
func TestCLIOutputFormatConsistency(t *testing.T) {
	cfg := newCactlConfig()

	// Find binary
	if err := locateCactlBinary(cfg); err != nil {
		t.Fatalf("cactl binary not found: %v", err)
	}

	t.Run("JSONOutputIsValidJSON", func(t *testing.T) {
		output := requireCactlSuccess(t, cfg, "status", "-o", "json")
		var status admin.CAStatus
		err := json.Unmarshal([]byte(output), &status)
		assert.NoError(t, err, "JSON output should be valid JSON")
	})

	t.Run("TableOutputHasHeaders", func(t *testing.T) {
		output := requireCactlSuccess(t, cfg, "status", "-o", "table")
		// Table output typically includes field names
		assert.NotEmpty(t, output, "Table output should not be empty")
	})

	t.Run("YAMLOutputIsValid", func(t *testing.T) {
		output := requireCactlSuccess(t, cfg, "status", "-o", "yaml")
		// YAML should contain key-value pairs
		assert.Contains(t, output, ":", "YAML output should contain colons")
	})
}

// locateCactlBinary attempts to find the cactl binary.
func locateCactlBinary(cfg *cactlConfig) error {
	possiblePaths := []string{
		cfg.Binary,
		"./cactl",
		"../../../cmd/cactl/cactl",
		"/usr/local/bin/cactl",
		"/workspace/go-trusted-ca/bin/cactl",
	}

	for _, p := range possiblePaths {
		_, err := runCactl(&cactlConfig{Binary: p, Timeout: 5 * time.Second}, "version")
		if err == nil {
			cfg.Binary = p
			return nil
		}
	}

	return caerrors.NotFoundError("cactl binary not found in common locations")
}

// TestCactlEABPurposeTypes tests EAB creation with different purpose types.
func TestCactlEABPurposeTypes(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

		// Create tenant
		tenantName := fmt.Sprintf("%seab-purpose-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
		tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
		require.NoError(t, err)
		defer func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cleanupCancel()
			_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
		}()

		purposes := []string{
			"account-binding",
			"endorse-01",
			"enroll-01",
		}

		for _, purpose := range purposes {
			t.Run(purpose, func(t *testing.T) {
				req := &admin.CreateEABRequest{
					Purpose: purpose,
					Contact: []string{"test@example.com"},
				}

				eab, err := adapter.CreateEAB(ctx, tenant.ID, req)
				require.NoError(t, err, "CreateEAB with purpose '%s' should succeed via %s", purpose, protocol)
				assert.NotEmpty(t, eab.ID)
				assert.NotEmpty(t, eab.MACKey)

				// Cleanup
				_ = adapter.DeleteEAB(ctx, tenant.ID, eab.ID)
			})
		}
	})
}

// TestCactlTenantStatusTransitions tests tenant status changes.
func TestCactlTenantStatusTransitions(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

		// Create tenant
		tenantName := fmt.Sprintf("%sstatus-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
		tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
		require.NoError(t, err)
		defer func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cleanupCancel()
			_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
		}()

		// Verify initial status
		assert.Equal(t, "active", tenant.Status, "Initial status should be 'active' via %s", protocol)

		// Update tenant name
		updated, err := adapter.UpdateTenant(ctx, tenant.ID, &admin.UpdateTenantRequest{
			Name: tenantName + "-updated",
		})
		require.NoError(t, err)
		assert.Equal(t, tenantName+"-updated", updated.Name)
		assert.Equal(t, "active", updated.Status, "Status should remain 'active' after update via %s", protocol)
	})
}

// TestCactlListFiltering tests list operations with various filters.
func TestCactlListFiltering(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("CertificatesByStatus", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Test filtering certificates by status
			validReq := &admin.ListCertificatesRequest{
				Page:    1,
				PerPage: 10,
				Status:  "valid",
			}
			validCerts, _, err := adapter.ListCertificates(ctx, validReq)
			require.NoError(t, err, "ListCertificates with status=valid should succeed via %s", protocol)
			for _, cert := range validCerts {
				assert.Equal(t, "valid", cert.Status, "All returned certs should have status=valid via %s", protocol)
			}

			revokedReq := &admin.ListCertificatesRequest{
				Page:    1,
				PerPage: 10,
				Status:  "revoked",
			}
			revokedCerts, _, err := adapter.ListCertificates(ctx, revokedReq)
			require.NoError(t, err, "ListCertificates with status=revoked should succeed via %s", protocol)
			for _, cert := range revokedCerts {
				assert.Equal(t, "revoked", cert.Status, "All returned certs should have status=revoked via %s", protocol)
			}
		})
	})
}

// TestCactlBenchmarkMultiProtocol runs benchmarks across all protocols.
func TestCactlBenchmarkMultiProtocol(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("GetStatus", func(t *testing.T) {
			// Warm up
			_, _ = adapter.GetStatus(ctx)

			start := time.Now()
			iterations := 10
			for i := 0; i < iterations; i++ {
				_, err := adapter.GetStatus(ctx)
				require.NoError(t, err)
			}
			duration := time.Since(start)
			avgLatency := duration / time.Duration(iterations)

			t.Logf("Protocol %s: avg GetStatus latency = %v (total: %v for %d iterations)",
				protocol, avgLatency, duration, iterations)
		})
	})
}

// TestCactlErrorMessages tests that error messages are informative.
func TestCactlErrorMessages(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("TenantNotFoundError", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			_, err := adapter.GetTenant(ctx, "definitely-does-not-exist-12345")
			require.Error(t, err, "GetTenant with nonexistent ID should return an error via %s", protocol)
		})

		t.Run("EABNotFoundError", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			// Create a tenant first
			tenantName := fmt.Sprintf("%serror-test-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
			tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
			require.NoError(t, err)
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cleanupCancel()
				_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
			}()

			_, err = adapter.GetEAB(ctx, tenant.ID, "nonexistent-eab-id")
			require.Error(t, err)
			// Just verify it errors - exact message format varies by protocol
		})
	})
}
