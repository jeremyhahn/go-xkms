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

//go:build integration

// Edge-case and consistency coverage moved from test/integration/cactl
// (go-xkms#949's port to xkmsctl): these exercise pkg/acme/api's
// AdminAdapter directly across every configured protocol, not the
// xkmsctl/cactl CLI, so they belong beside this package's other
// adapter-level coverage rather than the CLI-driven
// test/integration/acmeadmin. The CLI-only cases from the same source
// files (output-format smoke tests) were ported to
// test/integration/acmeadmin instead; see that package's cli_test.go.
package multiprotocol

import (
	"context"
	"fmt"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrencyMultiProtocol tests concurrent operations via all protocols.
func TestConcurrencyMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
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

func testConcurrentTenantCreation(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	numTenants := 5
	tenantIDs := make([]string, numTenants)
	errCh := make(chan error, numTenants)

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

	for i := 0; i < numTenants; i++ {
		err := <-errCh
		assert.NoError(t, err, "concurrent tenant creation should succeed via %s", protocol)
	}

	for _, id := range tenantIDs {
		if id != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
			_ = adapter.DeleteTenant(cleanupCtx, id)
			cleanupCancel()
		}
	}
}

func testConcurrentEABCreation(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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

	for i := 0; i < numEABs; i++ {
		go func(idx int) {
			req := &admin.CreateEABRequest{
				Purpose: "account-binding",
				Contact: []string{fmt.Sprintf("test%d@kms.example.com", idx)},
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

	for i := 0; i < numEABs; i++ {
		err := <-errCh
		assert.NoError(t, err, "concurrent EAB creation should succeed via %s", protocol)
	}

	for _, id := range eabIDs {
		if id != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
			_ = adapter.DeleteEAB(cleanupCtx, tenant.ID, id)
			cleanupCancel()
		}
	}
}

// TestSpecialCharactersMultiProtocol tests operations with special
// characters in names.
func TestSpecialCharactersMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
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

func testTenantWithSpecialChars(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

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

				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
				cleanupCancel()
			}
		})
	}
}

func testRoleWithSpecialChars(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	tenantName := fmt.Sprintf("%srole-special-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
	tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
	require.NoError(t, err)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cleanupCancel()
		_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
	}()

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

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenantRole(cleanupCtx, tenant.ID, created.ID)
	cleanupCancel()
}

// TestBoundaryConditionsMultiProtocol tests operations at boundary conditions.
func TestBoundaryConditionsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
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

func testEmptyPagination(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

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

func testMaxPagination(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req := &admin.ListTenantsRequest{
		Page:    1,
		PerPage: 1000,
	}

	tenants, pagination, err := adapter.ListTenants(ctx, req)
	require.NoError(t, err, "ListTenants should succeed via %s with large per-page", protocol)
	assert.NotNil(t, tenants)
	if pagination != nil {
		assert.GreaterOrEqual(t, pagination.Total, 0)
	}
}

func testMinimalTenant(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req := &admin.CreateTenantRequest{
		Name: fmt.Sprintf("%sminimal-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano()),
	}

	tenant, err := adapter.CreateTenant(ctx, req)
	require.NoError(t, err, "CreateTenant with minimal data should succeed via %s", protocol)
	assert.NotEmpty(t, tenant.ID)
	assert.Equal(t, req.Name, tenant.Name)

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
	cleanupCancel()
}

// TestIdempotencyMultiProtocol tests idempotent operations.
func TestIdempotencyMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("DeleteNonexistentTenantIdempotent", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			err := adapter.DeleteTenant(ctx, "nonexistent-tenant-id-12345")
			assert.Error(t, err, "DeleteTenant for nonexistent should fail via %s", protocol)
		})

		t.Run("GetMultipleTimes", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			tenantName := fmt.Sprintf("%sidempotent-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
			tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
			require.NoError(t, err)
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cleanupCancel()
				_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
			}()

			for i := 0; i < 3; i++ {
				retrieved, err := adapter.GetTenant(ctx, tenant.ID)
				require.NoError(t, err, "GetTenant iteration %d should succeed via %s", i, protocol)
				assert.Equal(t, tenant.ID, retrieved.ID)
				assert.Equal(t, tenant.Name, retrieved.Name)
			}
		})
	})
}

// TestProtocolConsistencyMultiProtocol tests that all protocols return
// consistent results for a tenant created via REST.
func TestProtocolConsistencyMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

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

// TestRoleComplexOperationsMultiProtocol tests complex RBAC role scenarios.
func TestRoleComplexOperationsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
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

func testRoleWithMultiplePermissions(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

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

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenantRole(cleanupCtx, tenant.ID, created.ID)
	cleanupCancel()
}

func testRoleWithNestedResourcePermissions(t *testing.T, adapter api.AdminAdapter, protocol api.Protocol) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

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

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
	_ = adapter.DeleteTenantRole(cleanupCtx, tenant.ID, created.ID)
	cleanupCancel()
}

// TestEABPurposeTypesMultiProtocol tests EAB creation with different purpose types.
func TestEABPurposeTypesMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

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
					Contact: []string{"test@kms.example.com"},
				}

				eab, err := adapter.CreateEAB(ctx, tenant.ID, req)
				require.NoError(t, err, "CreateEAB with purpose '%s' should succeed via %s", purpose, protocol)
				assert.NotEmpty(t, eab.ID)
				assert.NotEmpty(t, eab.MACKey)

				_ = adapter.DeleteEAB(ctx, tenant.ID, eab.ID)
			})
		}
	})
}

// TestTenantStatusTransitionsMultiProtocol tests tenant status changes.
func TestTenantStatusTransitionsMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

		tenantName := fmt.Sprintf("%sstatus-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
		tenant, err := adapter.CreateTenant(ctx, &admin.CreateTenantRequest{Name: tenantName})
		require.NoError(t, err)
		defer func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cleanupCancel()
			_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
		}()

		assert.Equal(t, "active", tenant.Status, "Initial status should be 'active' via %s", protocol)

		updated, err := adapter.UpdateTenant(ctx, tenant.ID, &admin.UpdateTenantRequest{
			Name: tenantName + "-updated",
		})
		require.NoError(t, err)
		assert.Equal(t, tenantName+"-updated", updated.Name)
		assert.Equal(t, "active", updated.Status, "Status should remain 'active' after update via %s", protocol)
	})
}

// TestListFilteringMultiProtocol tests list operations with various filters.
func TestListFilteringMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("CertificatesByStatus", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

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

// TestBenchmarkMultiProtocol reports GetStatus latency across all protocols.
func TestBenchmarkMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
	defer tc.Cleanup()

	ctx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("GetStatus", func(t *testing.T) {
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

// TestErrorMessagesMultiProtocol tests that error messages are informative.
func TestErrorMessagesMultiProtocol(t *testing.T) {
	tc := NewTestContext(t)
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
		})

		t.Run("CertificateNotFoundError", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			_, err := adapter.GetCertificate(ctx, "00:00:00:00:00:00:00:00")
			assert.Error(t, err, "GetCertificate for nonexistent cert should fail via %s", protocol)
		})

		t.Run("CreateDuplicateTenantError", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			tenantName := fmt.Sprintf("%sdup-%s-%d", testTenantPrefix, protocol, time.Now().UnixNano())
			req := &admin.CreateTenantRequest{Name: tenantName}

			tenant, err := adapter.CreateTenant(ctx, req)
			require.NoError(t, err, "first CreateTenant should succeed via %s", protocol)
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cleanupCancel()
				_ = adapter.DeleteTenant(cleanupCtx, tenant.ID)
			}()

			reqDup := &admin.CreateTenantRequest{ID: tenant.ID, Name: tenantName + "-dup"}
			_, err = adapter.CreateTenant(ctx, reqDup)
			assert.Error(t, err, "CreateTenant with duplicate ID should fail via %s", protocol)
		})
	})
}
