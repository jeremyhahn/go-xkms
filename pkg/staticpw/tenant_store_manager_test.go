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
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBarrierConfig returns a BarrierConfig suitable for test barriers.
func testBarrierConfig() seal.BarrierConfig {
	return seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
	}
}

// testLogger returns a quiet logger for test output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// newTestBarrier creates an initialized (unsealed) system barrier for testing.
func newTestBarrier(t *testing.T) *seal.Barrier {
	t.Helper()
	backend := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		testLogger(),
		backend,
		testBarrierConfig(),
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)
	err = barrier.Initialize(context.Background(), seal.Credentials{Secret: "test-system-pw"})
	require.NoError(t, err)
	return barrier
}

// newTestRegistry creates a BarrierRegistry backed by an initialized system barrier.
func newTestRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	barrier := newTestBarrier(t)
	reg, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return reg
}

// registerAndInitTenant registers a tenant in the registry, initializes it,
// and returns the BarrierRegistry. The tenant barrier is unsealed.
func registerAndInitTenant(t *testing.T, reg *seal.BarrierRegistry, tenantID string) {
	t.Helper()
	_, err := reg.RegisterTenant(tenantID)
	require.NoError(t, err)
	err = reg.InitializeTenant(context.Background(), tenantID, seal.Credentials{Secret: "pw-" + tenantID})
	require.NoError(t, err)
}

// newTestManager creates a TenantPasswordStoreManager with a valid registry
// and system store for testing.
func newTestManager(t *testing.T) (*TenantPasswordStoreManager, *seal.BarrierRegistry) {
	t.Helper()
	reg := newTestRegistry(t)
	systemStore := NewStore(storage.New())
	mgr, err := NewTenantPasswordStoreManager(reg, systemStore)
	require.NoError(t, err)
	return mgr, reg
}

// --- NewTenantPasswordStoreManager ---

func TestNewTenantPasswordStoreManager_Success(t *testing.T) {
	reg := newTestRegistry(t)
	systemStore := NewStore(storage.New())

	mgr, err := NewTenantPasswordStoreManager(reg, systemStore)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Same(t, systemStore, mgr.SystemStore())
}

func TestNewTenantPasswordStoreManager_NilRegistry(t *testing.T) {
	systemStore := NewStore(storage.New())

	mgr, err := NewTenantPasswordStoreManager(nil, systemStore)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilBarrierRegistry)
}

func TestNewTenantPasswordStoreManager_NilStore(t *testing.T) {
	reg := newTestRegistry(t)

	mgr, err := NewTenantPasswordStoreManager(reg, nil)
	assert.Nil(t, mgr)
	assert.ErrorIs(t, err, ErrNilStore)
}

func TestNewTenantPasswordStoreManager_BothNil(t *testing.T) {
	mgr, err := NewTenantPasswordStoreManager(nil, nil)
	assert.Nil(t, mgr)
	// nil registry is checked first
	assert.ErrorIs(t, err, ErrNilBarrierRegistry)
}

// --- SystemStore ---

func TestSystemStore_ReturnsSystemStore(t *testing.T) {
	reg := newTestRegistry(t)
	systemStore := NewStore(storage.New())
	mgr, err := NewTenantPasswordStoreManager(reg, systemStore)
	require.NoError(t, err)

	result := mgr.SystemStore()
	assert.Same(t, systemStore, result)
}

// --- ResolveStore ---

func TestResolveStore_EmptyTenantID(t *testing.T) {
	mgr, _ := newTestManager(t)

	store, err := mgr.ResolveStore("")
	require.NoError(t, err)
	assert.Same(t, mgr.SystemStore(), store)
}

func TestResolveStore_TenantNotFound(t *testing.T) {
	mgr, _ := newTestManager(t)

	store, err := mgr.ResolveStore("nonexistent-tenant")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestResolveStore_LockedByDefault(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "locked-tenant")

	store, err := mgr.ResolveStore("locked-tenant")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStoreLocked)
}

func TestResolveStore_AfterUnlock(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "unlocked-tenant")

	err := mgr.UnlockTenant("unlocked-tenant")
	require.NoError(t, err)

	store, err := mgr.ResolveStore("unlocked-tenant")
	require.NoError(t, err)
	require.NotNil(t, store)
}

// --- StoreForTenant ---

func TestStoreForTenant_CreatesStore_LockedByDefault(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "new-tenant")

	// First access creates the store but returns ErrStoreLocked.
	store, err := mgr.StoreForTenant("new-tenant")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStoreLocked)
}

func TestStoreForTenant_ReturnsCachedStoreAfterUnlock(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "cached-tenant")

	// First access creates the store (returns locked).
	_, err := mgr.StoreForTenant("cached-tenant")
	assert.ErrorIs(t, err, ErrStoreLocked)

	// Unlock the tenant.
	err = mgr.UnlockTenant("cached-tenant")
	require.NoError(t, err)

	// Second access returns the cached store.
	store1, err := mgr.StoreForTenant("cached-tenant")
	require.NoError(t, err)
	require.NotNil(t, store1)

	// Third access returns the same instance.
	store2, err := mgr.StoreForTenant("cached-tenant")
	require.NoError(t, err)
	assert.Same(t, store1, store2)
}

func TestStoreForTenant_UnknownTenant(t *testing.T) {
	mgr, _ := newTestManager(t)

	store, err := mgr.StoreForTenant("does-not-exist")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestStoreForTenant_StoreIsUsable(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "usable-tenant")

	err := mgr.UnlockTenant("usable-tenant")
	require.NoError(t, err)

	store, err := mgr.StoreForTenant("usable-tenant")
	require.NoError(t, err)

	// Add and retrieve a password through the tenant store.
	pw := &StaticPassword{Name: "test-pw", Password: "secret123"}
	require.NoError(t, store.Add(pw))

	retrieved, err := store.Get("test-pw")
	require.NoError(t, err)
	assert.Equal(t, "test-pw", retrieved.Name)
	assert.Equal(t, "secret123", retrieved.Password)
}

// --- LockTenant ---

func TestLockTenant_Success(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "lock-me")

	// Unlock first so we can lock.
	err := mgr.UnlockTenant("lock-me")
	require.NoError(t, err)

	// Verify unlocked.
	locked, err := mgr.IsLocked("lock-me")
	require.NoError(t, err)
	assert.False(t, locked)

	// Lock the tenant.
	err = mgr.LockTenant("lock-me")
	require.NoError(t, err)

	// Verify locked.
	locked, err = mgr.IsLocked("lock-me")
	require.NoError(t, err)
	assert.True(t, locked)
}

func TestLockTenant_AlreadyLocked(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "already-locked")

	// Access the tenant to create state (starts locked).
	_, _ = mgr.StoreForTenant("already-locked")

	err := mgr.LockTenant("already-locked")
	assert.ErrorIs(t, err, ErrStoreAlreadyLocked)
}

func TestLockTenant_NoStateTenantExists(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "no-state-tenant")

	// Lock without any prior access (no cached state).
	// Tenant exists in registry but has no state -> defaults to locked.
	err := mgr.LockTenant("no-state-tenant")
	assert.ErrorIs(t, err, ErrStoreAlreadyLocked)
}

func TestLockTenant_UnknownTenant(t *testing.T) {
	mgr, _ := newTestManager(t)

	err := mgr.LockTenant("unknown-tenant")
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestLockTenant_PreventsStoreAccess(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "lock-access")

	// Unlock, verify access, then lock and verify denied.
	err := mgr.UnlockTenant("lock-access")
	require.NoError(t, err)

	store, err := mgr.StoreForTenant("lock-access")
	require.NoError(t, err)
	require.NotNil(t, store)

	err = mgr.LockTenant("lock-access")
	require.NoError(t, err)

	store, err = mgr.StoreForTenant("lock-access")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStoreLocked)
}

// --- UnlockTenant ---

func TestUnlockTenant_Success(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "unlock-me")

	err := mgr.UnlockTenant("unlock-me")
	require.NoError(t, err)

	locked, err := mgr.IsLocked("unlock-me")
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestUnlockTenant_BarrierSealed(t *testing.T) {
	mgr, reg := newTestManager(t)

	// Register a tenant but do NOT initialize its barrier (remains sealed).
	_, err := reg.RegisterTenant("sealed-barrier")
	require.NoError(t, err)

	err = mgr.UnlockTenant("sealed-barrier")
	assert.ErrorIs(t, err, seal.ErrTenantSealed)
}

func TestUnlockTenant_AlreadyUnlocked(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "already-unlocked")

	err := mgr.UnlockTenant("already-unlocked")
	require.NoError(t, err)

	err = mgr.UnlockTenant("already-unlocked")
	assert.ErrorIs(t, err, ErrStoreNotLocked)
}

func TestUnlockTenant_UnknownTenant(t *testing.T) {
	mgr, _ := newTestManager(t)

	err := mgr.UnlockTenant("nonexistent")
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestUnlockTenant_WithExistingLockedState(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "existing-state")

	// Create the store state (starts locked).
	_, err := mgr.StoreForTenant("existing-state")
	assert.ErrorIs(t, err, ErrStoreLocked)

	// Unlock with existing locked state.
	err = mgr.UnlockTenant("existing-state")
	require.NoError(t, err)

	store, err := mgr.StoreForTenant("existing-state")
	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestUnlockTenant_ThenLockThenUnlock(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "cycle-tenant")

	// Unlock.
	err := mgr.UnlockTenant("cycle-tenant")
	require.NoError(t, err)

	// Add a password while unlocked.
	store, err := mgr.StoreForTenant("cycle-tenant")
	require.NoError(t, err)
	require.NoError(t, store.Add(&StaticPassword{Name: "cycle-pw", Password: "pass"}))

	// Lock.
	err = mgr.LockTenant("cycle-tenant")
	require.NoError(t, err)

	// Verify locked.
	_, err = mgr.StoreForTenant("cycle-tenant")
	assert.ErrorIs(t, err, ErrStoreLocked)

	// Unlock again.
	err = mgr.UnlockTenant("cycle-tenant")
	require.NoError(t, err)

	// Verify data persists across lock/unlock cycle.
	store, err = mgr.StoreForTenant("cycle-tenant")
	require.NoError(t, err)
	retrieved, err := store.Get("cycle-pw")
	require.NoError(t, err)
	assert.Equal(t, "pass", retrieved.Password)
}

// --- IsLocked ---

func TestIsLocked_DefaultLocked(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "default-locked")

	locked, err := mgr.IsLocked("default-locked")
	require.NoError(t, err)
	assert.True(t, locked)
}

func TestIsLocked_AfterUnlock(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "after-unlock")

	err := mgr.UnlockTenant("after-unlock")
	require.NoError(t, err)

	locked, err := mgr.IsLocked("after-unlock")
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestIsLocked_UnknownTenant(t *testing.T) {
	mgr, _ := newTestManager(t)

	_, err := mgr.IsLocked("nonexistent")
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestIsLocked_AfterLockCycle(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "lock-cycle")

	// Default locked.
	locked, err := mgr.IsLocked("lock-cycle")
	require.NoError(t, err)
	assert.True(t, locked)

	// Unlock.
	err = mgr.UnlockTenant("lock-cycle")
	require.NoError(t, err)
	locked, err = mgr.IsLocked("lock-cycle")
	require.NoError(t, err)
	assert.False(t, locked)

	// Lock again.
	err = mgr.LockTenant("lock-cycle")
	require.NoError(t, err)
	locked, err = mgr.IsLocked("lock-cycle")
	require.NoError(t, err)
	assert.True(t, locked)
}

// --- TenantStoreStatus ---

func TestTenantStoreStatus_LockedWithSealedBarrier(t *testing.T) {
	mgr, reg := newTestManager(t)

	// Register but do not initialize -> barrier sealed, store locked.
	_, err := reg.RegisterTenant("sealed-status")
	require.NoError(t, err)

	status, err := mgr.TenantStoreStatus("sealed-status")
	require.NoError(t, err)
	assert.True(t, status.IsLocked)
	assert.True(t, status.BarrierSealed)
	assert.Equal(t, 0, status.PasswordCount)
}

func TestTenantStoreStatus_UnlockedWithPasswords(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "status-pws")

	err := mgr.UnlockTenant("status-pws")
	require.NoError(t, err)

	// Add passwords.
	store, err := mgr.StoreForTenant("status-pws")
	require.NoError(t, err)
	require.NoError(t, store.Add(&StaticPassword{Name: "pw1", Password: "secret1"}))
	require.NoError(t, store.Add(&StaticPassword{Name: "pw2", Password: "secret2"}))
	require.NoError(t, store.Add(&StaticPassword{Name: "pw3", Password: "secret3"}))

	status, err := mgr.TenantStoreStatus("status-pws")
	require.NoError(t, err)
	assert.False(t, status.IsLocked)
	assert.False(t, status.BarrierSealed)
	assert.Equal(t, 3, status.PasswordCount)
}

func TestTenantStoreStatus_UnknownTenant(t *testing.T) {
	mgr, _ := newTestManager(t)

	status, err := mgr.TenantStoreStatus("nonexistent")
	assert.Nil(t, status)
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestTenantStoreStatus_LockedWithUnsealedBarrier(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "locked-unsealed")

	// Create state by accessing (starts locked).
	_, _ = mgr.StoreForTenant("locked-unsealed")

	status, err := mgr.TenantStoreStatus("locked-unsealed")
	require.NoError(t, err)
	assert.True(t, status.IsLocked)
	assert.False(t, status.BarrierSealed)
	// Password count is 0 because store is locked.
	assert.Equal(t, 0, status.PasswordCount)
}

func TestTenantStoreStatus_NoStateYet(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "no-state-status")

	// Query status without ever accessing the store.
	status, err := mgr.TenantStoreStatus("no-state-status")
	require.NoError(t, err)
	assert.True(t, status.IsLocked)
	assert.False(t, status.BarrierSealed)
	assert.Equal(t, 0, status.PasswordCount)
}

// --- Close ---

func TestClose_ClosesAllStores(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "close-tenant-1")
	registerAndInitTenant(t, reg, "close-tenant-2")

	// Unlock and access stores to populate the cache.
	require.NoError(t, mgr.UnlockTenant("close-tenant-1"))
	require.NoError(t, mgr.UnlockTenant("close-tenant-2"))

	store1, err := mgr.StoreForTenant("close-tenant-1")
	require.NoError(t, err)
	require.NotNil(t, store1)

	store2, err := mgr.StoreForTenant("close-tenant-2")
	require.NoError(t, err)
	require.NotNil(t, store2)

	// Close the manager.
	err = mgr.Close()
	require.NoError(t, err)

	// After close, the internal map should be empty. Accessing the tenant
	// again will try to create a new store (which may return ErrStoreLocked
	// since it starts locked). The old store instances should be closed.
	// Verify the old stores are closed by checking that operations fail.
	assert.ErrorIs(t, store1.Add(&StaticPassword{Name: "fail", Password: "p"}), ErrStoreClosed)
	assert.ErrorIs(t, store2.Add(&StaticPassword{Name: "fail", Password: "p"}), ErrStoreClosed)
}

func TestClose_EmptyManager(t *testing.T) {
	mgr, _ := newTestManager(t)

	// Close with no tenants should succeed.
	err := mgr.Close()
	require.NoError(t, err)
}

// --- Multi-tenant isolation ---

func TestMultiTenant_DataIsolation(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "tenant-alpha")
	registerAndInitTenant(t, reg, "tenant-beta")

	require.NoError(t, mgr.UnlockTenant("tenant-alpha"))
	require.NoError(t, mgr.UnlockTenant("tenant-beta"))

	storeA, err := mgr.StoreForTenant("tenant-alpha")
	require.NoError(t, err)
	storeB, err := mgr.StoreForTenant("tenant-beta")
	require.NoError(t, err)

	// Both tenants add a password with the same name.
	require.NoError(t, storeA.Add(&StaticPassword{Name: "shared-name", Password: "alpha-secret"}))
	require.NoError(t, storeB.Add(&StaticPassword{Name: "shared-name", Password: "beta-secret"}))

	// Each tenant sees only its own data.
	pwA, err := storeA.Get("shared-name")
	require.NoError(t, err)
	assert.Equal(t, "alpha-secret", pwA.Password)

	pwB, err := storeB.Get("shared-name")
	require.NoError(t, err)
	assert.Equal(t, "beta-secret", pwB.Password)
}

func TestMultiTenant_IndependentLockState(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "indep-a")
	registerAndInitTenant(t, reg, "indep-b")

	// Unlock only tenant A.
	require.NoError(t, mgr.UnlockTenant("indep-a"))

	// Tenant A should be accessible.
	storeA, err := mgr.StoreForTenant("indep-a")
	require.NoError(t, err)
	assert.NotNil(t, storeA)

	// Tenant B should still be locked.
	_, err = mgr.StoreForTenant("indep-b")
	assert.ErrorIs(t, err, ErrStoreLocked)
}

// --- Edge cases ---

func TestResolveStore_SystemStoreNotAffectedByTenants(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "edge-tenant")

	// Add a password to the system store.
	sysStore := mgr.SystemStore()
	require.NoError(t, sysStore.Add(&StaticPassword{Name: "system-pw", Password: "syspass"}))

	// Resolve with empty tenantID returns system store with existing data.
	resolved, err := mgr.ResolveStore("")
	require.NoError(t, err)

	pw, err := resolved.Get("system-pw")
	require.NoError(t, err)
	assert.Equal(t, "syspass", pw.Password)
}

func TestUnlockTenant_CreatesStoreWhenNoExistingState(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "fresh-unlock")

	// Unlock without any prior StoreForTenant call.
	err := mgr.UnlockTenant("fresh-unlock")
	require.NoError(t, err)

	// Store should be accessible immediately.
	store, err := mgr.StoreForTenant("fresh-unlock")
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify the store is functional.
	require.NoError(t, store.Add(&StaticPassword{Name: "fresh-pw", Password: "pass123"}))
	retrieved, err := store.Get("fresh-pw")
	require.NoError(t, err)
	assert.Equal(t, "pass123", retrieved.Password)
}

func TestStoreForTenant_ReturnsLockedOnSubsequentCallsWithoutUnlock(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "repeat-locked")

	// Multiple calls should all return ErrStoreLocked.
	for i := 0; i < 3; i++ {
		store, err := mgr.StoreForTenant("repeat-locked")
		assert.Nil(t, store)
		assert.ErrorIs(t, err, ErrStoreLocked)
	}
}

// --- ResolveScopedStore ---

func TestResolveScopedStore_EmptyTenantID(t *testing.T) {
	mgr, _ := newTestManager(t)

	store, err := mgr.ResolveScopedStore("", "alice")
	require.NoError(t, err)
	assert.Same(t, mgr.SystemStore(), store)
}

func TestResolveScopedStore_TenantOnlyNoUser(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "scoped-t")

	require.NoError(t, mgr.UnlockTenant("scoped-t"))

	// Empty userID → shared store (backward compat).
	store, err := mgr.ResolveScopedStore("scoped-t", "")
	require.NoError(t, err)
	require.NotNil(t, store)

	// It should be a *BackendStore, not a ScopedStore.
	_, ok := store.(*BackendStore)
	assert.True(t, ok, "empty userID should return shared BackendStore")
}

func TestResolveScopedStore_TenantAndUser(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "scoped-tu")

	require.NoError(t, mgr.UnlockTenant("scoped-tu"))

	store, err := mgr.ResolveScopedStore("scoped-tu", "alice")
	require.NoError(t, err)
	require.NotNil(t, store)

	// Should be a *ScopedStore.
	_, ok := store.(*ScopedStore)
	assert.True(t, ok, "tenant+user should return ScopedStore")
}

func TestResolveScopedStore_LockedTenant(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "scoped-locked")

	store, err := mgr.ResolveScopedStore("scoped-locked", "alice")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrStoreLocked)
}

func TestResolveScopedStore_UnknownTenant(t *testing.T) {
	mgr, _ := newTestManager(t)

	store, err := mgr.ResolveScopedStore("nonexistent", "alice")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, seal.ErrTenantNotFound)
}

func TestResolveScopedStore_InvalidUserID(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "scoped-baduser")

	require.NoError(t, mgr.UnlockTenant("scoped-baduser"))

	store, err := mgr.ResolveScopedStore("scoped-baduser", "/bad")
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

func TestResolveScopedStore_PersonalIsolation(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "scoped-iso")

	require.NoError(t, mgr.UnlockTenant("scoped-iso"))

	aliceStore, err := mgr.ResolveScopedStore("scoped-iso", "alice")
	require.NoError(t, err)

	bobStore, err := mgr.ResolveScopedStore("scoped-iso", "bob")
	require.NoError(t, err)

	// Alice adds a personal password.
	require.NoError(t, aliceStore.Add(&StaticPassword{Name: "secret", Password: "alice-pass"}))

	// Bob adds a personal password with the same name.
	require.NoError(t, bobStore.Add(&StaticPassword{Name: "secret", Password: "bob-pass"}))

	// Alice adds a shared password.
	require.NoError(t, aliceStore.Add(&StaticPassword{Name: "team-key", Password: "shared", Shared: true}))

	// Each user sees their own personal + shared entries.
	aliceAll, err := aliceStore.List()
	require.NoError(t, err)
	assert.Len(t, aliceAll, 2) // personal "secret" + shared "team-key"

	bobAll, err := bobStore.List()
	require.NoError(t, err)
	assert.Len(t, bobAll, 2) // personal "secret" + shared "team-key"

	// Alice's personal password has her data.
	alicePW, err := aliceStore.Get("secret")
	require.NoError(t, err)
	assert.Equal(t, "alice-pass", alicePW.Password)

	// Bob's personal password has his data.
	bobPW, err := bobStore.Get("secret")
	require.NoError(t, err)
	assert.Equal(t, "bob-pass", bobPW.Password)
}

func TestResolveScopedStore_CachesPersonalStore(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "scoped-cache")

	require.NoError(t, mgr.UnlockTenant("scoped-cache"))

	// Resolve twice for the same user.
	store1, err := mgr.ResolveScopedStore("scoped-cache", "alice")
	require.NoError(t, err)

	// Add a password through the first store.
	require.NoError(t, store1.Add(&StaticPassword{Name: "cached", Password: "pass"}))

	// Second resolve should see the data (same underlying personal store).
	store2, err := mgr.ResolveScopedStore("scoped-cache", "alice")
	require.NoError(t, err)

	pw, err := store2.Get("cached")
	require.NoError(t, err)
	assert.Equal(t, "pass", pw.Password)
}

// --- Targeted coverage tests ---

func TestClose_WithPersonalStores(t *testing.T) {
	mgr, reg := newTestManager(t)
	registerAndInitTenant(t, reg, "close-personal")

	require.NoError(t, mgr.UnlockTenant("close-personal"))

	// Create scoped stores to trigger personal store creation in the state.
	aliceStore, err := mgr.ResolveScopedStore("close-personal", "alice@test.com")
	require.NoError(t, err)
	require.NoError(t, aliceStore.Add(&StaticPassword{Name: "alice-pw", Password: "p"}))

	bobStore, err := mgr.ResolveScopedStore("close-personal", "bob@test.com")
	require.NoError(t, err)
	require.NoError(t, bobStore.Add(&StaticPassword{Name: "bob-pw", Password: "p"}))

	// Close should close all stores including personal ones without error.
	err = mgr.Close()
	require.NoError(t, err)
}
