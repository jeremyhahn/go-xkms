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
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TenantStoreStatus contains the status of a tenant's password store
// including session lock state, barrier seal state, and password count.
type TenantStoreStatus struct {
	IsLocked      bool `json:"is_locked"`
	BarrierSealed bool `json:"barrier_sealed"`
	PasswordCount int  `json:"password_count"`
}

// tenantPasswordState holds the per-tenant shared store, per-user personal
// stores, the underlying backend, and session lock state.
type tenantPasswordState struct {
	shared   *BackendStore   // one shared store per tenant
	personal sync.Map        // userID -> *BackendStore
	locked   atomic.Bool     // starts locked (true)
	backend  storage.Backend // the TenantBarrier backend
	tenantID string

	// store is the legacy shared store for backward compatibility with
	// ResolveStore and StoreForTenant. It points to the same shared store.
	store *BackendStore
}

// TenantPasswordStoreManager manages per-tenant password stores and
// session lock state. Each tenant's store is backed by a TenantBarrier
// from the BarrierRegistry, providing cryptographic isolation between
// tenants. Stores are cached in a sync.Map for lock-free concurrent access.
type TenantPasswordStoreManager struct {
	registry    *seal.BarrierRegistry
	systemStore Store
	tenants     sync.Map // tenantID -> *tenantPasswordState
}

// NewTenantPasswordStoreManager creates a manager that routes password
// operations to per-tenant encrypted stores. The registry provides
// TenantBarrier instances for cryptographic isolation. The systemStore
// is used for non-tenant (system-level) operations.
func NewTenantPasswordStoreManager(registry *seal.BarrierRegistry, systemStore Store) (*TenantPasswordStoreManager, error) {
	if registry == nil {
		return nil, ErrNilBarrierRegistry
	}
	if systemStore == nil {
		return nil, ErrNilStore
	}
	return &TenantPasswordStoreManager{
		registry:    registry,
		systemStore: systemStore,
	}, nil
}

// SystemStore returns the system-level store for non-tenant operations.
func (m *TenantPasswordStoreManager) SystemStore() Store {
	return m.systemStore
}

// ResolveStore returns the appropriate store for the given tenant ID.
// If tenantID is empty, the system store is returned. Otherwise, the
// tenant store is returned (creating it if needed). Returns ErrStoreLocked
// if the tenant's session is locked.
func (m *TenantPasswordStoreManager) ResolveStore(tenantID string) (Store, error) {
	if tenantID == "" {
		return m.systemStore, nil
	}
	return m.StoreForTenant(tenantID)
}

// StoreForTenant returns the BackendStore for the given tenant, creating
// it on first access. Returns ErrStoreLocked if the tenant's session is
// locked. The store is backed by the tenant's TenantBarrier for per-tenant
// DEK encryption.
func (m *TenantPasswordStoreManager) StoreForTenant(tenantID string) (Store, error) {
	// Fast path: existing state.
	if val, ok := m.tenants.Load(tenantID); ok {
		state := val.(*tenantPasswordState)
		if state.locked.Load() {
			return nil, ErrStoreLocked
		}
		return state.store, nil
	}

	// Verify tenant exists in registry.
	tb, err := m.registry.Tenant(tenantID)
	if err != nil {
		return nil, err
	}

	// Create new shared tenant store backed by TenantBarrier.
	shared, err := NewSharedTenantStore(tb, tenantID)
	if err != nil {
		return nil, err
	}

	state := &tenantPasswordState{
		shared:   shared,
		store:    shared,
		backend:  tb,
		tenantID: tenantID,
	}
	state.locked.Store(true) // starts locked

	// Use LoadOrStore to handle concurrent creation.
	actual, loaded := m.tenants.LoadOrStore(tenantID, state)
	if loaded {
		// Another goroutine already created it. Close our duplicate.
		_ = shared.Close()
		existing := actual.(*tenantPasswordState)
		if existing.locked.Load() {
			return nil, ErrStoreLocked
		}
		return existing.store, nil
	}

	// We stored our state — it starts locked.
	return nil, ErrStoreLocked
}

// LockTenant sets the session lock for the given tenant. Returns
// ErrStoreAlreadyLocked if the tenant is already locked.
func (m *TenantPasswordStoreManager) LockTenant(tenantID string) error {
	val, ok := m.tenants.Load(tenantID)
	if !ok {
		// No state yet — verify tenant exists in registry.
		if _, err := m.registry.Tenant(tenantID); err != nil {
			return err
		}
		return ErrStoreAlreadyLocked // no state = default locked
	}
	state := val.(*tenantPasswordState)
	if !state.locked.CompareAndSwap(false, true) {
		return ErrStoreAlreadyLocked
	}
	return nil
}

// UnlockTenant clears the session lock for the given tenant. The tenant's
// barrier must be unsealed; returns seal.ErrTenantSealed if it is sealed.
// Returns ErrStoreNotLocked if the tenant is already unlocked.
func (m *TenantPasswordStoreManager) UnlockTenant(tenantID string) error {
	// Verify the tenant's barrier is unsealed.
	tb, err := m.registry.Tenant(tenantID)
	if err != nil {
		return err
	}
	if tb.IsSealed() {
		return seal.ErrTenantSealed
	}

	// Get or create the tenant state.
	val, ok := m.tenants.Load(tenantID)
	if !ok {
		// Create the shared store now that we know the barrier is unsealed.
		shared, storeErr := NewSharedTenantStore(tb, tenantID)
		if storeErr != nil {
			return storeErr
		}

		state := &tenantPasswordState{
			shared:   shared,
			store:    shared,
			backend:  tb,
			tenantID: tenantID,
		}
		state.locked.Store(false) // unlock immediately

		actual, loaded := m.tenants.LoadOrStore(tenantID, state)
		if loaded {
			_ = shared.Close()
			existing := actual.(*tenantPasswordState)
			if !existing.locked.CompareAndSwap(true, false) {
				return ErrStoreNotLocked
			}
		}
		return nil
	}

	state := val.(*tenantPasswordState)
	if !state.locked.CompareAndSwap(true, false) {
		return ErrStoreNotLocked
	}
	return nil
}

// IsLocked returns the session lock state for the given tenant. A tenant
// with no cached state defaults to locked.
func (m *TenantPasswordStoreManager) IsLocked(tenantID string) (bool, error) {
	val, ok := m.tenants.Load(tenantID)
	if !ok {
		// No state yet — verify tenant exists.
		if _, err := m.registry.Tenant(tenantID); err != nil {
			return false, err
		}
		return true, nil // default: locked
	}
	return val.(*tenantPasswordState).locked.Load(), nil
}

// TenantStoreStatus returns status information for the given tenant
// including session lock state, barrier seal state, and password count.
func (m *TenantPasswordStoreManager) TenantStoreStatus(tenantID string) (*TenantStoreStatus, error) {
	tb, err := m.registry.Tenant(tenantID)
	if err != nil {
		return nil, err
	}

	status := &TenantStoreStatus{
		BarrierSealed: tb.IsSealed(),
	}

	// Check lock state.
	val, ok := m.tenants.Load(tenantID)
	if !ok {
		status.IsLocked = true // default locked
		return status, nil
	}

	state := val.(*tenantPasswordState)
	status.IsLocked = state.locked.Load()

	// Count passwords if unlocked and barrier is unsealed.
	if !status.IsLocked && !status.BarrierSealed {
		passwords, listErr := state.shared.List()
		if listErr == nil {
			status.PasswordCount = len(passwords)
		}
	}

	return status, nil
}

// ResolveScopedStore returns a ScopedStore for the given tenant and user.
// If tenantID is empty, the system store is returned (backward compat).
// If userID is empty, the shared store is returned (backward compat for
// system-level operations). When both are present, a ScopedStore wrapping
// the shared and personal stores is returned.
func (m *TenantPasswordStoreManager) ResolveScopedStore(tenantID, userID string) (Store, error) {
	if tenantID == "" {
		return m.systemStore, nil
	}

	// Get or create the tenant state.
	val, ok := m.tenants.Load(tenantID)
	if !ok {
		// Force creation via StoreForTenant (which may return ErrStoreLocked).
		_, err := m.StoreForTenant(tenantID)
		if err != nil {
			return nil, err
		}
		val, ok = m.tenants.Load(tenantID)
		if !ok {
			return nil, ErrNotConfigured
		}
	}

	state := val.(*tenantPasswordState)
	if state.locked.Load() {
		return nil, ErrStoreLocked
	}

	// No userID → shared store only (backward compat).
	if userID == "" {
		return state.shared, nil
	}

	// Validate userID.
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}

	// Get or create the personal store for this user.
	personalStore, err := m.getOrCreatePersonalStore(state, userID)
	if err != nil {
		return nil, err
	}

	return NewScopedStore(state.shared, personalStore, userID)
}

// getOrCreatePersonalStore returns the cached personal store for a user,
// creating it on first access.
func (m *TenantPasswordStoreManager) getOrCreatePersonalStore(state *tenantPasswordState, userID string) (*BackendStore, error) {
	// Fast path: existing store.
	if val, ok := state.personal.Load(userID); ok {
		return val.(*BackendStore), nil
	}

	// Create new personal store.
	store, err := NewPersonalTenantStore(state.backend, state.tenantID, userID)
	if err != nil {
		return nil, err
	}

	// Use LoadOrStore to handle concurrent creation.
	actual, loaded := state.personal.LoadOrStore(userID, store)
	if loaded {
		_ = store.Close()
		return actual.(*BackendStore), nil
	}

	return store, nil
}

// Close closes all cached tenant stores and releases resources.
func (m *TenantPasswordStoreManager) Close() error {
	var lastErr error
	m.tenants.Range(func(key, value any) bool {
		state := value.(*tenantPasswordState)
		// Close personal stores.
		state.personal.Range(func(_, pVal any) bool {
			if err := pVal.(*BackendStore).Close(); err != nil {
				lastErr = err
			}
			return true
		})
		// Close shared store.
		if err := state.shared.Close(); err != nil {
			lastErr = err
		}
		m.tenants.Delete(key)
		return true
	})
	return lastErr
}
