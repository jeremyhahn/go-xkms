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

package admin_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContext provides common test setup for integration tests
type TestContext struct {
	logger         *slog.Logger
	qrdbSvc        qrdb.Service
	adminService   *admin.TenantAwareAdminService
	storageFactory storage.Factory
	tmpDir         string
	cleanup        func()
}

// setupTestContext creates a new test context with QRDB.
// Note: For full integration tests, this would connect to a real QRDB.
// For now, we use in-memory components with RBAC via QRDB.
func setupTestContext(t *testing.T) *TestContext {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create temporary directory for storage
	tmpDir, err := os.MkdirTemp("", "admin-integration-test-*")
	require.NoError(t, err)

	// Create local file storage backend
	store := local.New()
	err = store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	// Create tenant-aware storage factory for ACME storage (including EAB and tenants)
	storageFactory, err := objstore.NewTenantAwareFactory(store)
	require.NoError(t, err)

	// Create QRDB service with in-memory components
	qrdbSvc := qrdb.NewTestService()

	// Create admin service with storage factory
	adminSvc := admin.NewTenantAwareAdminService(nil, storageFactory, qrdbSvc, logger, "1.0.0-test")

	return &TestContext{
		logger:         logger,
		qrdbSvc:        qrdbSvc,
		adminService:   adminSvc,
		storageFactory: storageFactory,
		tmpDir:         tmpDir,
		cleanup: func() {
			qrdbSvc.Close()
			_ = os.RemoveAll(tmpDir)
		},
	}
}

// TestAdminService_TenantLifecycle tests the complete tenant lifecycle
func TestAdminService_TenantLifecycle(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	testCtx := context.Background()

	// Create tenant
	tenant, err := ctx.adminService.CreateTenant(testCtx, admin.CreateTenantRequest{
		ID:   "test-tenant-1",
		Name: "Test Tenant 1",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-tenant-1", tenant.ID)
	assert.Equal(t, "Test Tenant 1", tenant.Name)
	assert.Equal(t, "active", tenant.Status)

	// Get tenant
	retrieved, err := ctx.adminService.GetTenant(testCtx, "test-tenant-1")
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, retrieved.ID)

	// Update tenant
	updated, err := ctx.adminService.UpdateTenant(testCtx, "test-tenant-1", admin.UpdateTenantRequest{
		Name: "Updated Tenant Name",
	})
	require.NoError(t, err)
	assert.Equal(t, "Updated Tenant Name", updated.Name)

	// List tenants
	tenants, pagination, err := ctx.adminService.ListTenants(testCtx, admin.ListTenantsRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, tenants)
	assert.GreaterOrEqual(t, pagination.Total, 1)

	// Update status
	err = ctx.adminService.UpdateTenantStatus(testCtx, "test-tenant-1", "suspended")
	require.NoError(t, err)

	// Verify status change
	suspended, err := ctx.adminService.GetTenant(testCtx, "test-tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "suspended", suspended.Status)

	// Delete tenant
	err = ctx.adminService.DeleteTenant(testCtx, "test-tenant-1")
	require.NoError(t, err)
}

// TestAdminService_TenantCA tests tenant CA creation and management
func TestAdminService_TenantCA(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	testCtx := context.Background()
	tenantID := "ca-test-tenant"

	// Create tenant first
	_, err := ctx.adminService.CreateTenant(testCtx, admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "CA Test Tenant",
	})
	require.NoError(t, err)

	// Create root CA
	rootCA, err := ctx.adminService.CreateTenantRootCA(testCtx, tenantID, admin.CreateTenantRootCARequest{
		CommonName:    "Test Root CA",
		KeyAlgorithm:  "RSA",
		ValidityYears: 10,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, rootCA.SerialNumber)
	assert.Equal(t, "Test Root CA", rootCA.CommonName)
	assert.Equal(t, "active", rootCA.Status)

	// Create intermediate CA
	intCA, err := ctx.adminService.CreateTenantIntermediateCA(testCtx, tenantID, admin.CreateTenantIntermediateCARequest{
		CommonName:    "Test Intermediate CA",
		ParentType:    "tenant",
		KeyAlgorithm:  "ECDSA",
		ValidityYears: 5,
		SetAsDefault:  true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, intCA.ID)
	assert.Equal(t, "Test Intermediate CA", intCA.CommonName)

	// Get CA status
	status, err := ctx.adminService.GetTenantCAStatus(testCtx, tenantID)
	require.NoError(t, err)
	assert.True(t, status.CanIssueCerts)
	assert.Equal(t, intCA.ID, status.DefaultIntermediateCAID)

	// Get signing CA
	signer, cert, err := ctx.adminService.GetTenantSigningCA(testCtx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, cert)
	assert.Equal(t, "Test Intermediate CA", cert.Subject.CommonName)
}

// TestAdminService_TenantEAB tests EAB creation and management
func TestAdminService_TenantEAB(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	testCtx := context.Background()
	tenantID := "eab-test-tenant"

	// Create tenant first
	_, err := ctx.adminService.CreateTenant(testCtx, admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "EAB Test Tenant",
	})
	require.NoError(t, err)

	// Create EAB
	eab, err := ctx.adminService.CreateTenantEAB(testCtx, tenantID, admin.CreateEABRequest{
		Purpose:       "account-binding",
		ExpiresInDays: 30,
		Contact:       []string{"admin@example.com"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eab.ID)
	assert.NotEmpty(t, eab.MACKey)
	assert.Equal(t, "HS256", eab.Algorithm)

	// Get EAB
	retrieved, err := ctx.adminService.GetTenantEAB(testCtx, tenantID, eab.ID)
	require.NoError(t, err)
	assert.Equal(t, eab.ID, retrieved.ID)
	assert.Equal(t, tenantID, retrieved.TenantID)

	// List EABs
	list, pagination, err := ctx.adminService.ListTenantEABs(testCtx, tenantID, admin.ListEABRequest{})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, 1, pagination.Total)

	// Delete EAB
	err = ctx.adminService.DeleteTenantEAB(testCtx, tenantID, eab.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = ctx.adminService.GetTenantEAB(testCtx, tenantID, eab.ID)
	assert.Error(t, err)
}

// TestAdminService_TenantRole tests RBAC role management
func TestAdminService_TenantRole(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	testCtx := context.Background()
	tenantID := "role-test-tenant"

	// Create tenant first
	_, err := ctx.adminService.CreateTenant(testCtx, admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "Role Test Tenant",
	})
	require.NoError(t, err)

	// Create role
	role, err := ctx.adminService.CreateTenantRole(testCtx, tenantID, &db.CreateRoleRequest{
		Name: "test-role",
		Permissions: []string{
			"certificates:read",
			"accounts:read",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "test-role", role.Name)
	assert.Equal(t, tenantID, role.TenantID)
	assert.NotEmpty(t, role.ID)

	// Get role
	retrieved, err := ctx.adminService.GetTenantRole(testCtx, tenantID, role.ID)
	require.NoError(t, err)
	assert.Equal(t, "test-role", retrieved.Name)

	// Update role
	updated, err := ctx.adminService.UpdateTenantRole(testCtx, tenantID, &db.UpdateRoleRequest{
		ID:   role.ID,
		Name: "updated-role",
		Permissions: []string{
			"certificates:read",
			"certificates:write",
			"accounts:read",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "updated-role", updated.Name)

	// List roles
	listResp, err := ctx.adminService.ListTenantRoles(testCtx, tenantID, &db.ListRolesRequest{
		TenantID: tenantID,
	})
	require.NoError(t, err)
	require.NotNil(t, listResp)
	foundOurRole := false
	for _, r := range listResp.Roles {
		if r.ID == role.ID {
			foundOurRole = true
			break
		}
	}
	assert.True(t, foundOurRole, "Our role should be in the list")

	// Delete role
	err = ctx.adminService.DeleteTenantRole(testCtx, tenantID, role.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = ctx.adminService.GetTenantRole(testCtx, tenantID, role.ID)
	assert.Error(t, err)
}

// TestAdminService_TenantUser tests RBAC user management
func TestAdminService_TenantUser(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	testCtx := context.Background()
	tenantID := "user-test-tenant"

	// Create tenant first
	_, err := ctx.adminService.CreateTenant(testCtx, admin.CreateTenantRequest{
		ID:   tenantID,
		Name: "User Test Tenant",
	})
	require.NoError(t, err)

	// Create a role to assign to the user
	role, err := ctx.adminService.CreateTenantRole(testCtx, tenantID, &db.CreateRoleRequest{
		Name:        "user-test-role",
		Permissions: []string{"certificates:read"},
	})
	require.NoError(t, err)

	// Create user with role assignment
	user, err := ctx.adminService.CreateTenantUser(testCtx, tenantID, &db.CreateUserRequest{
		Username: "test-user",
		RoleIDs:  []string{role.ID},
	})
	require.NoError(t, err)
	assert.Equal(t, "test-user", user.Username)
	assert.Equal(t, tenantID, user.TenantID)
	assert.NotEmpty(t, user.ID)

	// Get user
	retrieved, err := ctx.adminService.GetTenantUser(testCtx, tenantID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "test-user", retrieved.Username)

	// Update user
	updated, err := ctx.adminService.UpdateTenantUser(testCtx, tenantID, &db.UpdateUserRequest{
		ID:       user.ID,
		Username: "updated-user",
	})
	require.NoError(t, err)
	assert.Equal(t, "updated-user", updated.Username)

	// List users
	listResp, err := ctx.adminService.ListTenantUsers(testCtx, tenantID, &db.ListUsersRequest{
		TenantID: tenantID,
	})
	require.NoError(t, err)
	require.NotNil(t, listResp)
	foundOurUser := false
	for _, u := range listResp.Users {
		if u.ID == user.ID {
			foundOurUser = true
			break
		}
	}
	assert.True(t, foundOurUser, "Our user should be in the list")

	// Delete user
	err = ctx.adminService.DeleteTenantUser(testCtx, tenantID, user.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = ctx.adminService.GetTenantUser(testCtx, tenantID, user.ID)
	assert.Error(t, err)

	// Clean up role
	_ = ctx.adminService.DeleteTenantRole(testCtx, tenantID, role.ID)
}

// TestConcurrentTenantOperations tests concurrent access to tenant operations
func TestConcurrentTenantOperations(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	testCtx := context.Background()
	numTenants := 10

	// Create tenants concurrently
	done := make(chan bool, numTenants)
	for i := 0; i < numTenants; i++ {
		go func(idx int) {
			tenantID := "concurrent-tenant-" + string(rune('a'+idx))
			_, err := ctx.adminService.CreateTenant(testCtx, admin.CreateTenantRequest{
				ID:   tenantID,
				Name: "Concurrent Tenant " + string(rune('A'+idx)),
			})
			if err != nil {
				t.Logf("Error creating tenant %s: %v", tenantID, err)
			}
			done <- err == nil
		}(i)
	}

	// Wait for all goroutines
	successes := 0
	for i := 0; i < numTenants; i++ {
		if <-done {
			successes++
		}
	}

	assert.Equal(t, numTenants, successes)

	// Verify all tenants exist
	tenants, _, err := ctx.adminService.ListTenants(testCtx, admin.ListTenantsRequest{PerPage: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(tenants), numTenants)
}

// BenchmarkTenantCreation benchmarks tenant creation performance
func BenchmarkTenantCreation(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create in-memory components
	qrdbSvc := qrdb.NewTestService()
	defer qrdbSvc.Close()

	adminSvc := admin.NewTenantAwareAdminService(nil, nil, qrdbSvc, logger, "bench")
	testCtx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tenantID := "bench-tenant-" + time.Now().Format("20060102150405.000000000") + "-" + string(rune('a'+i%26))
		_, _ = adminSvc.CreateTenant(testCtx, admin.CreateTenantRequest{
			ID:   tenantID,
			Name: "Benchmark Tenant",
		})
	}
}

// Suppress unused import warnings for time package (used in benchmark)
var _ = time.Now
