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

package staticpw

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// mockBarrierRegistry is a test double that maps tenant IDs to in-memory
// storage backends, simulating per-tenant barrier isolation.
type mockBarrierRegistry struct {
	tenants map[string]storage.Backend
}

// Compile-time interface check.
var _ BarrierRegistryAccessor = (*mockBarrierRegistry)(nil)

// GetTenantBarrier returns the in-memory backend for the tenant, or an
// error if the tenant is not registered.
func (m *mockBarrierRegistry) GetTenantBarrier(tenantID string) (storage.Backend, error) {
	backend, ok := m.tenants[tenantID]
	if !ok {
		return nil, errors.New("tenant not found")
	}
	return backend, nil
}

// newTestFactory creates a TenantDAOFactory with the given tenant backends.
// The system KVStore uses a fresh in-memory backend.
func newTestFactory(t *testing.T, tenants map[string]storage.Backend) *TenantDAOFactory {
	t.Helper()

	systemBackend := storage.New()
	systemKV, err := kvadapter.New(systemBackend)
	if err != nil {
		t.Fatalf("failed to create system kvstore: %v", err)
	}

	registry := &mockBarrierRegistry{tenants: tenants}

	factory, err := NewTenantDAOFactory(systemKV, registry)
	if err != nil {
		t.Fatalf("failed to create factory: %v", err)
	}
	return factory
}

// TestTenantDAOFactory_PasswordIsolation verifies that passwords stored
// by tenant A are not visible to tenant B.
func TestTenantDAOFactory_PasswordIsolation(t *testing.T) {
	tenantA := storage.New()
	tenantB := storage.New()

	factory := newTestFactory(t, map[string]storage.Backend{
		"tenantA": tenantA,
		"tenantB": tenantB,
	})

	// Create store for tenant A and add a password.
	storeA, err := factory.PasswordStoreForTenant("tenantA")
	if err != nil {
		t.Fatalf("PasswordStoreForTenant(tenantA): %v", err)
	}

	pw := &StaticPassword{
		Name:     "secret-a",
		Password: "hunter2hunter2",
	}
	if err := storeA.Add(pw); err != nil {
		t.Fatalf("storeA.Add: %v", err)
	}

	// Verify tenant A can see its password.
	passwords, err := storeA.List()
	if err != nil {
		t.Fatalf("storeA.List: %v", err)
	}
	if len(passwords) != 1 {
		t.Fatalf("expected 1 password in tenant A, got %d", len(passwords))
	}
	if passwords[0].Name != "secret-a" {
		t.Errorf("expected name %q, got %q", "secret-a", passwords[0].Name)
	}

	// Verify tenant B's store is empty.
	storeB, err := factory.PasswordStoreForTenant("tenantB")
	if err != nil {
		t.Fatalf("PasswordStoreForTenant(tenantB): %v", err)
	}

	passwordsB, err := storeB.List()
	if err != nil {
		t.Fatalf("storeB.List: %v", err)
	}
	if len(passwordsB) != 0 {
		t.Errorf("expected 0 passwords in tenant B, got %d", len(passwordsB))
	}
}

// TestTenantDAOFactory_SystemStoreIsolation verifies the system store
// is separate from tenant stores.
func TestTenantDAOFactory_SystemStoreIsolation(t *testing.T) {
	tenantA := storage.New()

	factory := newTestFactory(t, map[string]storage.Backend{
		"tenantA": tenantA,
	})

	// Add password to system store.
	systemStore, err := factory.SystemPasswordStore()
	if err != nil {
		t.Fatalf("SystemPasswordStore: %v", err)
	}

	pw := &StaticPassword{
		Name:     "system-secret",
		Password: "sys-pass-1234",
	}
	if err := systemStore.Add(pw); err != nil {
		t.Fatalf("systemStore.Add: %v", err)
	}

	// Verify system store has the password.
	sysPws, err := systemStore.List()
	if err != nil {
		t.Fatalf("systemStore.List: %v", err)
	}
	if len(sysPws) != 1 {
		t.Fatalf("expected 1 system password, got %d", len(sysPws))
	}

	// Verify tenant A does not see the system password.
	storeA, err := factory.PasswordStoreForTenant("tenantA")
	if err != nil {
		t.Fatalf("PasswordStoreForTenant(tenantA): %v", err)
	}

	tenantPws, err := storeA.List()
	if err != nil {
		t.Fatalf("storeA.List: %v", err)
	}
	if len(tenantPws) != 0 {
		t.Errorf("expected 0 passwords in tenant A, got %d", len(tenantPws))
	}
}

// TestTenantDAOFactory_TeamIsolation verifies that teams stored by
// tenant A are not visible to tenant B.
func TestTenantDAOFactory_TeamIsolation(t *testing.T) {
	tenantA := storage.New()
	tenantB := storage.New()

	factory := newTestFactory(t, map[string]storage.Backend{
		"tenantA": tenantA,
		"tenantB": tenantB,
	})

	ctx := context.Background()

	// Create team store for tenant A and add a team.
	teamStoreA, err := factory.TeamStoreForTenant("tenantA")
	if err != nil {
		t.Fatalf("TeamStoreForTenant(tenantA): %v", err)
	}

	team := &TeamEntity{
		Name:     "engineering",
		TenantID: "tenantA",
		OwnerID:  "user1",
		Members:  []string{"user1"},
	}
	if err := teamStoreA.Create(ctx, team); err != nil {
		t.Fatalf("teamStoreA.Create: %v", err)
	}

	// Verify tenant A can see its team.
	teamsA, err := teamStoreA.List(ctx)
	if err != nil {
		t.Fatalf("teamStoreA.List: %v", err)
	}
	if len(teamsA) != 1 {
		t.Fatalf("expected 1 team in tenant A, got %d", len(teamsA))
	}

	// Verify tenant B's team store is empty.
	teamStoreB, err := factory.TeamStoreForTenant("tenantB")
	if err != nil {
		t.Fatalf("TeamStoreForTenant(tenantB): %v", err)
	}

	teamsB, err := teamStoreB.List(ctx)
	if err != nil {
		t.Fatalf("teamStoreB.List: %v", err)
	}
	if len(teamsB) != 0 {
		t.Errorf("expected 0 teams in tenant B, got %d", len(teamsB))
	}
}

// TestTenantDAOFactory_InvalidTenant verifies that an empty or invalid
// tenant ID returns an appropriate error.
func TestTenantDAOFactory_InvalidTenant(t *testing.T) {
	factory := newTestFactory(t, map[string]storage.Backend{})

	tests := []struct {
		name     string
		tenantID string
	}{
		{name: "empty tenant ID", tenantID: ""},
		{name: "whitespace tenant ID", tenantID: "   "},
		{name: "special chars", tenantID: "tenant/../../etc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := factory.PasswordStoreForTenant(tt.tenantID)
			if err == nil {
				t.Error("expected error for invalid tenant ID, got nil")
			}
			var invalidTenant ErrInvalidTenant
			if !errors.As(err, &invalidTenant) {
				t.Errorf("expected ErrInvalidTenant, got %T: %v", err, err)
			}
		})
	}

	for _, tt := range tests {
		t.Run("team_"+tt.name, func(t *testing.T) {
			_, err := factory.TeamStoreForTenant(tt.tenantID)
			if err == nil {
				t.Error("expected error for invalid tenant ID, got nil")
			}
			var invalidTenant ErrInvalidTenant
			if !errors.As(err, &invalidTenant) {
				t.Errorf("expected ErrInvalidTenant, got %T: %v", err, err)
			}
		})
	}
}

// TestTenantDAOFactory_UnregisteredTenant verifies that requesting a store
// for a tenant not in the registry returns ErrTenantBarrierUnavailable.
func TestTenantDAOFactory_UnregisteredTenant(t *testing.T) {
	factory := newTestFactory(t, map[string]storage.Backend{
		"tenantA": storage.New(),
	})

	_, err := factory.PasswordStoreForTenant("nonexistent")
	if err == nil {
		t.Fatal("expected error for unregistered tenant, got nil")
	}
	var unavailable ErrTenantBarrierUnavailable
	if !errors.As(err, &unavailable) {
		t.Errorf("expected ErrTenantBarrierUnavailable, got %T: %v", err, err)
	}
	if unavailable.TenantID != "nonexistent" {
		t.Errorf("expected tenant ID %q, got %q", "nonexistent", unavailable.TenantID)
	}
}

// TestTenantDAOFactory_NilConstructorArgs verifies constructor validation.
func TestTenantDAOFactory_NilConstructorArgs(t *testing.T) {
	systemBackend := storage.New()
	systemKV, err := kvadapter.New(systemBackend)
	if err != nil {
		t.Fatalf("failed to create system kvstore: %v", err)
	}

	registry := &mockBarrierRegistry{tenants: map[string]storage.Backend{}}

	t.Run("nil system kvstore", func(t *testing.T) {
		_, err := NewTenantDAOFactory(nil, registry)
		if err == nil {
			t.Fatal("expected error for nil system kvstore")
		}
		var nilKV ErrNilSystemKVStore
		if !errors.As(err, &nilKV) {
			t.Errorf("expected ErrNilSystemKVStore, got %T: %v", err, err)
		}
	})

	t.Run("nil registry", func(t *testing.T) {
		_, err := NewTenantDAOFactory(systemKV, nil)
		if err == nil {
			t.Fatal("expected error for nil registry")
		}
		var nilReg ErrNilBarrierRegistryAccessor
		if !errors.As(err, &nilReg) {
			t.Errorf("expected ErrNilBarrierRegistryAccessor, got %T: %v", err, err)
		}
	})
}

// TestTenantDAOFactory_SystemTeamStoreIsolation verifies that the system
// team store is separate from tenant team stores.
func TestTenantDAOFactory_SystemTeamStoreIsolation(t *testing.T) {
	factory := newTestFactory(t, map[string]storage.Backend{
		"tenantA": storage.New(),
	})

	ctx := context.Background()

	// Add team to system store.
	systemTeamStore, err := factory.SystemTeamStore()
	if err != nil {
		t.Fatalf("SystemTeamStore: %v", err)
	}

	team := &TeamEntity{
		Name:    "platform-team",
		OwnerID: "admin",
		Members: []string{"admin"},
	}
	if err := systemTeamStore.Create(ctx, team); err != nil {
		t.Fatalf("systemTeamStore.Create: %v", err)
	}

	// Verify system store has the team.
	sysTeams, err := systemTeamStore.List(ctx)
	if err != nil {
		t.Fatalf("systemTeamStore.List: %v", err)
	}
	if len(sysTeams) != 1 {
		t.Fatalf("expected 1 system team, got %d", len(sysTeams))
	}

	// Verify tenant A does not see the system team.
	tenantTeamStore, err := factory.TeamStoreForTenant("tenantA")
	if err != nil {
		t.Fatalf("TeamStoreForTenant(tenantA): %v", err)
	}

	tenantTeams, err := tenantTeamStore.List(ctx)
	if err != nil {
		t.Fatalf("tenantTeamStore.List: %v", err)
	}
	if len(tenantTeams) != 0 {
		t.Errorf("expected 0 teams in tenant A, got %d", len(tenantTeams))
	}
}

// TestTenantDAOFactory_InvalidateTenant verifies that invalidating a
// tenant's cached KVStore forces re-resolution on next access.
func TestTenantDAOFactory_InvalidateTenant(t *testing.T) {
	tenantA := storage.New()

	factory := newTestFactory(t, map[string]storage.Backend{
		"tenantA": tenantA,
	})

	// Access tenant A to cache the KVStore.
	storeA, err := factory.PasswordStoreForTenant("tenantA")
	if err != nil {
		t.Fatalf("PasswordStoreForTenant(tenantA): %v", err)
	}

	pw := &StaticPassword{
		Name:     "before-invalidate",
		Password: "pw-before-12345",
	}
	if err := storeA.Add(pw); err != nil {
		t.Fatalf("storeA.Add: %v", err)
	}

	// Invalidate and re-access. Since the underlying backend is the same,
	// the data should still be there (the KVStore adapter is recreated,
	// but the storage backend persists).
	factory.InvalidateTenant("tenantA")

	storeA2, err := factory.PasswordStoreForTenant("tenantA")
	if err != nil {
		t.Fatalf("PasswordStoreForTenant(tenantA) after invalidate: %v", err)
	}

	passwords, err := storeA2.List()
	if err != nil {
		t.Fatalf("storeA2.List: %v", err)
	}
	if len(passwords) != 1 {
		t.Fatalf("expected 1 password after invalidate, got %d", len(passwords))
	}
	if passwords[0].Name != "before-invalidate" {
		t.Errorf("expected name %q, got %q", "before-invalidate", passwords[0].Name)
	}
}

// TestTenantDAOFactory_ErrorTypes verifies error message formatting and
// unwrap behavior for tenant-specific error types.
func TestTenantDAOFactory_ErrorTypes(t *testing.T) {
	t.Run("ErrInvalidTenant empty", func(t *testing.T) {
		err := ErrInvalidTenant{}
		if err.Error() != "staticpw: tenant ID is empty" {
			t.Errorf("unexpected message: %s", err.Error())
		}
	})

	t.Run("ErrInvalidTenant with ID", func(t *testing.T) {
		err := ErrInvalidTenant{TenantID: "bad-id!"}
		expected := `staticpw: invalid tenant ID "bad-id!"`
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrTenantBarrierUnavailable unwrap", func(t *testing.T) {
		cause := errors.New("barrier sealed")
		err := ErrTenantBarrierUnavailable{TenantID: "t1", Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("expected Unwrap to return cause")
		}
		expected := `staticpw: tenant barrier unavailable for "t1": barrier sealed`
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrNilSystemKVStore message", func(t *testing.T) {
		err := ErrNilSystemKVStore{}
		if err.Error() != "staticpw: nil system kvstore" {
			t.Errorf("unexpected message: %s", err.Error())
		}
	})

	t.Run("ErrNilBarrierRegistryAccessor message", func(t *testing.T) {
		err := ErrNilBarrierRegistryAccessor{}
		if err.Error() != "staticpw: nil barrier registry accessor" {
			t.Errorf("unexpected message: %s", err.Error())
		}
	})
}

// TestTenantDAOFactory_ConcurrentAccess verifies that concurrent access
// to the same tenant produces consistent results without data races.
func TestTenantDAOFactory_ConcurrentAccess(t *testing.T) {
	factory := newTestFactory(t, map[string]storage.Backend{
		"tenantA": storage.New(),
	})

	const goroutines = 10
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := factory.PasswordStoreForTenant("tenantA")
			errCh <- err
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent PasswordStoreForTenant: %v", err)
		}
	}
}

// TestTenantDAOFactory_MultiTenantPasswordCRUD performs CRUD operations
// across multiple tenants to verify full data lifecycle isolation.
func TestTenantDAOFactory_MultiTenantPasswordCRUD(t *testing.T) {
	factory := newTestFactory(t, map[string]storage.Backend{
		"alpha": storage.New(),
		"beta":  storage.New(),
	})

	// Add passwords to both tenants.
	storeAlpha, err := factory.PasswordStoreForTenant("alpha")
	if err != nil {
		t.Fatalf("PasswordStoreForTenant(alpha): %v", err)
	}
	storeBeta, err := factory.PasswordStoreForTenant("beta")
	if err != nil {
		t.Fatalf("PasswordStoreForTenant(beta): %v", err)
	}

	pwAlpha := &StaticPassword{Name: "alpha-secret", Password: "alpha-pw-1234"}
	pwBeta := &StaticPassword{Name: "beta-secret", Password: "beta-pw-56789"}

	if err := storeAlpha.Add(pwAlpha); err != nil {
		t.Fatalf("storeAlpha.Add: %v", err)
	}
	if err := storeBeta.Add(pwBeta); err != nil {
		t.Fatalf("storeBeta.Add: %v", err)
	}

	// Verify each tenant sees only its own password.
	listAlpha, err := storeAlpha.List()
	if err != nil {
		t.Fatalf("storeAlpha.List: %v", err)
	}
	if len(listAlpha) != 1 || listAlpha[0].Name != "alpha-secret" {
		t.Errorf("alpha tenant: expected [alpha-secret], got %v", listAlpha)
	}

	listBeta, err := storeBeta.List()
	if err != nil {
		t.Fatalf("storeBeta.List: %v", err)
	}
	if len(listBeta) != 1 || listBeta[0].Name != "beta-secret" {
		t.Errorf("beta tenant: expected [beta-secret], got %v", listBeta)
	}

	// Delete alpha's password and verify beta is unaffected.
	if err := storeAlpha.Delete("alpha-secret"); err != nil {
		t.Fatalf("storeAlpha.Delete: %v", err)
	}

	listAlpha2, err := storeAlpha.List()
	if err != nil {
		t.Fatalf("storeAlpha.List after delete: %v", err)
	}
	if len(listAlpha2) != 0 {
		t.Errorf("expected 0 alpha passwords after delete, got %d", len(listAlpha2))
	}

	listBeta2, err := storeBeta.List()
	if err != nil {
		t.Fatalf("storeBeta.List after alpha delete: %v", err)
	}
	if len(listBeta2) != 1 {
		t.Errorf("expected 1 beta password after alpha delete, got %d", len(listBeta2))
	}
}
