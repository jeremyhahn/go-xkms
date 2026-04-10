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

//go:build integration && linux

package xkey

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// TestTenantIsolatedPasswordStores verifies that tenant-scoped password stores
// backed by a shared file storage backend maintain strict data isolation.
// Passwords added to one tenant must not be visible to another tenant.
func TestTenantIsolatedPasswordStores(t *testing.T) {
	dir := tempDir(t)

	backend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	storeA, err := staticpw.NewTenantStore(backend, "tenant-A")
	require.NoError(t, err)

	storeB, err := staticpw.NewTenantStore(backend, "tenant-B")
	require.NoError(t, err)

	// Add a password to tenant-A.
	err = storeA.Add(&staticpw.StaticPassword{
		Name:     "db-cred",
		Password: "s3cret-A",
		Username: "admin-a",
	})
	require.NoError(t, err)

	// Add a password to tenant-B.
	err = storeB.Add(&staticpw.StaticPassword{
		Name:     "api-key",
		Password: "s3cret-B",
		Username: "admin-b",
	})
	require.NoError(t, err)

	// Tenant-A should only see its own password.
	listA, err := storeA.List()
	require.NoError(t, err)
	require.Len(t, listA, 1)
	assert.Equal(t, "db-cred", listA[0].Name)
	assert.Equal(t, "s3cret-A", listA[0].Password)

	// Tenant-B should only see its own password.
	listB, err := storeB.List()
	require.NoError(t, err)
	require.Len(t, listB, 1)
	assert.Equal(t, "api-key", listB[0].Name)
	assert.Equal(t, "s3cret-B", listB[0].Password)

	// Cross-tenant isolation: tenant-A cannot retrieve tenant-B's password.
	_, err = storeA.Get("api-key")
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)

	// Cross-tenant isolation: tenant-B cannot retrieve tenant-A's password.
	_, err = storeB.Get("db-cred")
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
}

// TestTenantIsolatedPasswordStores_SameNameDifferentTenants verifies that two
// tenants can each store a password with the same name without collision.
func TestTenantIsolatedPasswordStores_SameNameDifferentTenants(t *testing.T) {
	dir := tempDir(t)

	backend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	storeA, err := staticpw.NewTenantStore(backend, "tenant-A")
	require.NoError(t, err)

	storeB, err := staticpw.NewTenantStore(backend, "tenant-B")
	require.NoError(t, err)

	// Both tenants add a password with the same name.
	err = storeA.Add(&staticpw.StaticPassword{
		Name:     "shared-name",
		Password: "value-from-A",
	})
	require.NoError(t, err)

	err = storeB.Add(&staticpw.StaticPassword{
		Name:     "shared-name",
		Password: "value-from-B",
	})
	require.NoError(t, err)

	// Each tenant retrieves its own value.
	pwA, err := storeA.Get("shared-name")
	require.NoError(t, err)
	assert.Equal(t, "value-from-A", pwA.Password)

	pwB, err := storeB.Get("shared-name")
	require.NoError(t, err)
	assert.Equal(t, "value-from-B", pwB.Password)
}

// TestTenantIsolatedTeamStores verifies that tenant-scoped team stores using
// separate KVStore adapters with tenant-namespaced backends maintain strict
// data isolation. Teams created in one tenant must not be visible in another.
func TestTenantIsolatedTeamStores(t *testing.T) {
	dir := tempDir(t)

	// Create separate file backends for each tenant, using subdirectories
	// to simulate tenant-namespaced storage.
	backendA, err := filestorage.New(filepath.Join(dir, "tenant-A"))
	require.NoError(t, err)
	t.Cleanup(func() { backendA.Close() })

	backendB, err := filestorage.New(filepath.Join(dir, "tenant-B"))
	require.NoError(t, err)
	t.Cleanup(func() { backendB.Close() })

	kvStoreA, err := kvadapter.New(backendA)
	require.NoError(t, err)

	kvStoreB, err := kvadapter.New(backendB)
	require.NoError(t, err)

	teamStoreA, err := staticpw.NewDAOTeamStore(kvStoreA)
	require.NoError(t, err)
	t.Cleanup(func() { teamStoreA.Close() })

	teamStoreB, err := staticpw.NewDAOTeamStore(kvStoreB)
	require.NoError(t, err)
	t.Cleanup(func() { teamStoreB.Close() })

	ctx := context.Background()

	// Create a team with the same name in both tenants.
	err = teamStoreA.Create(ctx, &staticpw.TeamEntity{
		Name:     "ops",
		TenantID: "tenant-A",
		OwnerID:  "alice",
		Members:  []string{"alice"},
	})
	require.NoError(t, err)

	err = teamStoreB.Create(ctx, &staticpw.TeamEntity{
		Name:     "ops",
		TenantID: "tenant-B",
		OwnerID:  "bob",
		Members:  []string{"bob"},
	})
	require.NoError(t, err)

	// Tenant-A team store should only see its own "ops" team.
	teamsA, err := teamStoreA.List(ctx)
	require.NoError(t, err)
	require.Len(t, teamsA, 1)
	assert.Equal(t, "ops", teamsA[0].Name)
	assert.Equal(t, "tenant-A", teamsA[0].TenantID)
	assert.Equal(t, "alice", teamsA[0].OwnerID)

	// Tenant-B team store should only see its own "ops" team.
	teamsB, err := teamStoreB.List(ctx)
	require.NoError(t, err)
	require.Len(t, teamsB, 1)
	assert.Equal(t, "ops", teamsB[0].Name)
	assert.Equal(t, "tenant-B", teamsB[0].TenantID)
	assert.Equal(t, "bob", teamsB[0].OwnerID)
}

// TestTenantIsolatedTeamStores_ListByTenant verifies that ListByTenant
// correctly filters teams by their TenantID field even when multiple
// tenants share the same backing store.
func TestTenantIsolatedTeamStores_ListByTenant(t *testing.T) {
	dir := tempDir(t)

	// Use a single shared backend to verify ListByTenant filtering.
	sharedBackend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { sharedBackend.Close() })

	kvStore, err := kvadapter.New(sharedBackend)
	require.NoError(t, err)

	teamStore, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { teamStore.Close() })

	ctx := context.Background()

	// Create teams belonging to different tenants in the same store.
	err = teamStore.Create(ctx, &staticpw.TeamEntity{
		Name:     "ops-alpha",
		TenantID: "tenant-alpha",
		OwnerID:  "alice",
	})
	require.NoError(t, err)

	err = teamStore.Create(ctx, &staticpw.TeamEntity{
		Name:     "ops-beta",
		TenantID: "tenant-beta",
		OwnerID:  "bob",
	})
	require.NoError(t, err)

	err = teamStore.Create(ctx, &staticpw.TeamEntity{
		Name:     "dev-alpha",
		TenantID: "tenant-alpha",
		OwnerID:  "carol",
	})
	require.NoError(t, err)

	// ListByTenant for tenant-alpha should return only its two teams.
	alphaTeams, err := teamStore.ListByTenant(ctx, "tenant-alpha")
	require.NoError(t, err)
	require.Len(t, alphaTeams, 2)

	alphaNames := []string{alphaTeams[0].Name, alphaTeams[1].Name}
	assert.Contains(t, alphaNames, "dev-alpha")
	assert.Contains(t, alphaNames, "ops-alpha")

	// ListByTenant for tenant-beta should return only its one team.
	betaTeams, err := teamStore.ListByTenant(ctx, "tenant-beta")
	require.NoError(t, err)
	require.Len(t, betaTeams, 1)
	assert.Equal(t, "ops-beta", betaTeams[0].Name)

	// ListByTenant for a non-existent tenant returns empty.
	emptyTeams, err := teamStore.ListByTenant(ctx, "tenant-ghost")
	require.NoError(t, err)
	assert.Empty(t, emptyTeams)
}

// mockBarrierRegistry implements staticpw.BarrierRegistryAccessor for testing
// the TenantDAOFactory. Each tenant maps to a separate storage.Backend,
// providing data isolation without requiring a real barrier/encryption layer.
type mockBarrierRegistry struct {
	tenants map[string]storage.Backend
}

func (m *mockBarrierRegistry) GetTenantBarrier(tenantID string) (storage.Backend, error) {
	b, ok := m.tenants[tenantID]
	if !ok {
		return nil, staticpw.ErrInvalidTenant{TenantID: tenantID}
	}
	return b, nil
}

// TestTenantDAOFactory_IsolatedPasswordStores verifies that the
// TenantDAOFactory creates isolated DAOStore instances per tenant, and that
// data written through one tenant's store is not visible through another's.
func TestTenantDAOFactory_IsolatedPasswordStores(t *testing.T) {
	dir := tempDir(t)

	// Create separate file backends per tenant.
	backendA, err := filestorage.New(filepath.Join(dir, "tenant-A"))
	require.NoError(t, err)
	t.Cleanup(func() { backendA.Close() })

	backendB, err := filestorage.New(filepath.Join(dir, "tenant-B"))
	require.NoError(t, err)
	t.Cleanup(func() { backendB.Close() })

	systemBackend, err := filestorage.New(filepath.Join(dir, "system"))
	require.NoError(t, err)
	t.Cleanup(func() { systemBackend.Close() })

	systemKV, err := kvadapter.New(systemBackend)
	require.NoError(t, err)

	registry := &mockBarrierRegistry{
		tenants: map[string]storage.Backend{
			"tenant-A": backendA,
			"tenant-B": backendB,
		},
	}

	factory, err := staticpw.NewTenantDAOFactory(systemKV, registry)
	require.NoError(t, err)

	// Get tenant-scoped password stores via the factory.
	// DAOStore implements Store, so we use Add/Get/List (not Create).
	pwStoreA, err := factory.PasswordStoreForTenant("tenant-A")
	require.NoError(t, err)

	pwStoreB, err := factory.PasswordStoreForTenant("tenant-B")
	require.NoError(t, err)

	// Add a password via tenant-A's store.
	err = pwStoreA.Add(&staticpw.StaticPassword{
		Name:     "db-cred",
		Password: "tenant-A-secret",
	})
	require.NoError(t, err)

	// Add a password via tenant-B's store.
	err = pwStoreB.Add(&staticpw.StaticPassword{
		Name:     "api-key",
		Password: "tenant-B-secret",
	})
	require.NoError(t, err)

	// Tenant-A should only see its own password.
	allA, err := pwStoreA.List()
	require.NoError(t, err)
	require.Len(t, allA, 1)
	assert.Equal(t, "db-cred", allA[0].Name)

	// Tenant-B should only see its own password.
	allB, err := pwStoreB.List()
	require.NoError(t, err)
	require.Len(t, allB, 1)
	assert.Equal(t, "api-key", allB[0].Name)

	// Cross-tenant: tenant-A cannot find tenant-B's password.
	_, err = pwStoreA.Get("api-key")
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)

	// Cross-tenant: tenant-B cannot find tenant-A's password.
	_, err = pwStoreB.Get("db-cred")
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
}

// TestTenantDAOFactory_IsolatedTeamStores verifies that the TenantDAOFactory
// creates isolated DAOTeamStore instances per tenant.
func TestTenantDAOFactory_IsolatedTeamStores(t *testing.T) {
	dir := tempDir(t)

	backendA, err := filestorage.New(filepath.Join(dir, "tenant-A"))
	require.NoError(t, err)
	t.Cleanup(func() { backendA.Close() })

	backendB, err := filestorage.New(filepath.Join(dir, "tenant-B"))
	require.NoError(t, err)
	t.Cleanup(func() { backendB.Close() })

	systemBackend, err := filestorage.New(filepath.Join(dir, "system"))
	require.NoError(t, err)
	t.Cleanup(func() { systemBackend.Close() })

	systemKV, err := kvadapter.New(systemBackend)
	require.NoError(t, err)

	registry := &mockBarrierRegistry{
		tenants: map[string]storage.Backend{
			"tenant-A": backendA,
			"tenant-B": backendB,
		},
	}

	factory, err := staticpw.NewTenantDAOFactory(systemKV, registry)
	require.NoError(t, err)

	teamStoreA, err := factory.TeamStoreForTenant("tenant-A")
	require.NoError(t, err)

	teamStoreB, err := factory.TeamStoreForTenant("tenant-B")
	require.NoError(t, err)

	ctx := context.Background()

	// Create "ops" team in both tenants (same name, different tenant).
	err = teamStoreA.Create(ctx, &staticpw.TeamEntity{
		Name:     "ops",
		TenantID: "tenant-A",
		OwnerID:  "alice",
	})
	require.NoError(t, err)

	err = teamStoreB.Create(ctx, &staticpw.TeamEntity{
		Name:     "ops",
		TenantID: "tenant-B",
		OwnerID:  "bob",
	})
	require.NoError(t, err)

	// Each tenant sees only its own team.
	teamsA, err := teamStoreA.List(ctx)
	require.NoError(t, err)
	require.Len(t, teamsA, 1)
	assert.Equal(t, "alice", teamsA[0].OwnerID)

	teamsB, err := teamStoreB.List(ctx)
	require.NoError(t, err)
	require.Len(t, teamsB, 1)
	assert.Equal(t, "bob", teamsB[0].OwnerID)
}

// TestTenantDAOFactory_InvalidTenant verifies that the TenantDAOFactory
// returns appropriate errors for invalid or unregistered tenant IDs.
func TestTenantDAOFactory_InvalidTenant(t *testing.T) {
	dir := tempDir(t)

	systemBackend, err := filestorage.New(filepath.Join(dir, "system"))
	require.NoError(t, err)
	t.Cleanup(func() { systemBackend.Close() })

	systemKV, err := kvadapter.New(systemBackend)
	require.NoError(t, err)

	registry := &mockBarrierRegistry{
		tenants: map[string]storage.Backend{},
	}

	factory, err := staticpw.NewTenantDAOFactory(systemKV, registry)
	require.NoError(t, err)

	// Empty tenant ID should fail validation.
	_, err = factory.PasswordStoreForTenant("")
	assert.Error(t, err)

	// Unregistered tenant should fail with barrier unavailable.
	_, err = factory.PasswordStoreForTenant("unknown-tenant")
	assert.Error(t, err)

	// Same for team stores.
	_, err = factory.TeamStoreForTenant("")
	assert.Error(t, err)

	_, err = factory.TeamStoreForTenant("unknown-tenant")
	assert.Error(t, err)
}

// TestTenantDAOFactory_NilInputs verifies that the TenantDAOFactory
// constructor rejects nil inputs with typed errors.
func TestTenantDAOFactory_NilInputs(t *testing.T) {
	dir := tempDir(t)

	backend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	// Nil system KVStore.
	_, err = staticpw.NewTenantDAOFactory(nil, &mockBarrierRegistry{})
	assert.ErrorAs(t, err, &staticpw.ErrNilSystemKVStore{})

	// Nil barrier registry.
	_, err = staticpw.NewTenantDAOFactory(kvStore, nil)
	assert.ErrorAs(t, err, &staticpw.ErrNilBarrierRegistryAccessor{})
}

// TestTenantCleanupIsolation verifies that deleting all data in one tenant
// does not affect data in another tenant.
func TestTenantCleanupIsolation(t *testing.T) {
	dir := tempDir(t)

	backend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	storeA, err := staticpw.NewTenantStore(backend, "tenant-A")
	require.NoError(t, err)

	storeB, err := staticpw.NewTenantStore(backend, "tenant-B")
	require.NoError(t, err)

	// Populate both tenants.
	for _, name := range []string{"cred-1", "cred-2", "cred-3"} {
		err = storeA.Add(&staticpw.StaticPassword{
			Name:     name,
			Password: "A-" + name,
		})
		require.NoError(t, err)
	}

	for _, name := range []string{"key-1", "key-2"} {
		err = storeB.Add(&staticpw.StaticPassword{
			Name:     name,
			Password: "B-" + name,
		})
		require.NoError(t, err)
	}

	// Verify initial counts.
	listA, err := storeA.List()
	require.NoError(t, err)
	require.Len(t, listA, 3)

	listB, err := storeB.List()
	require.NoError(t, err)
	require.Len(t, listB, 2)

	// Delete all data in tenant-A.
	for _, pw := range listA {
		err = storeA.Delete(pw.Name)
		require.NoError(t, err)
	}

	// Tenant-A should now be empty.
	listA, err = storeA.List()
	require.NoError(t, err)
	assert.Empty(t, listA)

	// Tenant-B data must be completely unaffected.
	listB, err = storeB.List()
	require.NoError(t, err)
	require.Len(t, listB, 2)

	bNames := []string{listB[0].Name, listB[1].Name}
	assert.Contains(t, bNames, "key-1")
	assert.Contains(t, bNames, "key-2")
}

// TestTenantStore_InvalidTenantID verifies that NewTenantStore rejects
// invalid tenant IDs.
func TestTenantStore_InvalidTenantID(t *testing.T) {
	dir := tempDir(t)

	backend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	tests := []struct {
		name     string
		tenantID string
	}{
		{"empty", ""},
		{"starts with hyphen", "-invalid"},
		{"starts with underscore", "_invalid"},
		{"contains spaces", "tenant A"},
		{"contains special chars", "tenant@A!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := staticpw.NewTenantStore(backend, tt.tenantID)
			assert.ErrorIs(t, err, staticpw.ErrInvalidTenantID)
		})
	}
}

// TestTenantIsolatedFolders verifies that folder operations in one tenant
// do not leak into another tenant's folder namespace.
func TestTenantIsolatedFolders(t *testing.T) {
	dir := tempDir(t)

	backend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	storeA, err := staticpw.NewTenantStore(backend, "tenant-A")
	require.NoError(t, err)

	storeB, err := staticpw.NewTenantStore(backend, "tenant-B")
	require.NoError(t, err)

	// Create a folder in each tenant.
	err = storeA.CreateFolder("Work")
	require.NoError(t, err)

	err = storeB.CreateFolder("Personal")
	require.NoError(t, err)

	// Add a password in tenant-A's Work folder.
	err = storeA.Add(&staticpw.StaticPassword{
		Name:       "work-cred",
		Password:   "secret",
		FolderPath: "Work",
	})
	require.NoError(t, err)

	// Tenant-A should see its folder.
	foldersA, err := storeA.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, foldersA, "Work")
	assert.NotContains(t, foldersA, "Personal")

	// Tenant-B should only see its folder, not tenant-A's.
	foldersB, err := storeB.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, foldersB, "Personal")
	assert.NotContains(t, foldersB, "Work")

	// Tenant-B cannot see tenant-A's folder contents.
	byFolder, err := storeB.ListByFolder("Work")
	require.NoError(t, err)
	assert.Empty(t, byFolder)
}
