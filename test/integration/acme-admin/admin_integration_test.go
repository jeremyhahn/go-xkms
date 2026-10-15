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

package admin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContext provides common test setup for integration tests
type TestContext struct {
	logger         *slog.Logger
	adminService   *admin.TenantAwareAdminService
	storageFactory storage.Factory
	cleanup        func()
}

// setupTestContext composes the admin service the way xkmsd's
// finalizeAdminModule does: over a real in-process go-qrdb node with the node
// barrier engaged. ACME storage comes from the node's datastore DAO factory,
// tenant identity from the node's TenantService, and roles and users from the
// node's client.
// jwtAuthConfig returns a JWT auth configuration whose verification key is a
// freshly generated P-256 public key written under dir. The server has no
// unauthenticated mode, so the composed node needs a real authenticator.
func jwtAuthConfig(tb testing.TB, dir string) config.AuthConfig {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(tb, err)
	keyFile := filepath.Join(dir, "jwt-public.pem")
	require.NoError(tb, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600))
	return config.AuthConfig{
		Enabled: true,
		Type:    "jwt",
		JWT: &config.JWTConfig{
			PublicKeyFile: keyFile,
			Issuer:        "acme-admin-integration",
			Audience:      []string{"acme-admin-integration"},
		},
	}
}

func setupTestContext(tb testing.TB) *TestContext {
	tb.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	dir := tb.TempDir()
	srv, err := server.New(&config.Config{
		Server:    config.ServerConfig{Host: "127.0.0.1", RESTPort: 0},
		Protocols: config.ProtocolsConfig{Unix: true},
		Unix: config.UnixConfig{
			SocketPath: filepath.Join(dir, "xkms.sock"),
		},
		Logging:   config.LoggingConfig{Level: "error", Format: "json"},
		TLS:       config.TLSConfig{Enabled: true},
		Auth:      jwtAuthConfig(tb, dir),
		Datastore: config.DatastoreConfig{Engine: "memory", Path: dir},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "none"},
		Default:   config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{Enabled: true, Path: filepath.Join(dir, "software")},
		},
	})
	require.NoError(tb, err)
	require.NotNil(tb, srv.Datastore(), "the embedded node must publish its datastore")
	require.NotNil(tb, srv.QRDBClient(), "the embedded node must publish its client")
	require.NotNil(tb, srv.TenantService(), "the node barrier must compose qrdb's TenantService")

	// Create tenant-aware storage factory for ACME storage (including EAB and tenants)
	storageFactory, err := objstore.NewTenantAwareFactory(srv.Datastore().DAOFactory())
	require.NoError(tb, err)

	adminSvc, err := admin.NewTenantAwareAdminService(nil, storageFactory, srv.QRDBClient(), logger, "1.0.0-test")
	require.NoError(tb, err)
	adminSvc.SetTenantService(srv.TenantService())

	return &TestContext{
		logger:         logger,
		adminService:   adminSvc,
		storageFactory: storageFactory,
		cleanup: func() {
			if err := srv.Shutdown(); err != nil {
				tb.Errorf("server.Shutdown: %v", err)
			}
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
			"certs:read",
			"users:read",
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
			"certs:read",
			"certs:issue",
			"users:read",
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
		Permissions: []string{"certs:read"},
	})
	require.NoError(t, err)

	// Create user with role assignment
	user, err := ctx.adminService.CreateTenantUser(testCtx, tenantID, &db.CreateUserRequest{
		Username: "test-user",
		Email:    "test-user@example.com",
		RoleIDs:  []string{role.ID},
	})
	require.NoError(t, err)
	assert.Equal(t, "test-user", user.Username)
	assert.Equal(t, tenantID, user.TenantID)
	assert.NotZero(t, user.ID)
	userID := strconv.FormatUint(user.ID, 10)

	// Get user
	retrieved, err := ctx.adminService.GetTenantUser(testCtx, tenantID, userID)
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
	err = ctx.adminService.DeleteTenantUser(testCtx, tenantID, userID)
	require.NoError(t, err)

	// Verify deleted
	_, err = ctx.adminService.GetTenantUser(testCtx, tenantID, userID)
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
	ctx := setupTestContext(b)
	defer ctx.cleanup()
	testCtx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ctx.adminService.CreateTenant(testCtx, admin.CreateTenantRequest{
			ID:   "bench-tenant-" + strconv.Itoa(i),
			Name: "Benchmark Tenant",
		})
		if err != nil {
			b.Fatalf("CreateTenant: %v", err)
		}
	}
}
