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
	"errors"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ErrNoSystemBarrier is returned when the system tenant's password store is
// addressed and the barrier registry holds no system barrier.
var ErrNoSystemBarrier = errors.New("staticpw: the barrier registry has no system barrier")

// TenantStoreStatus is the password store status one user sees: whether the
// user's personal session is locked, whether the tenant barrier is sealed,
// and how many entries the user can currently read.
type TenantStoreStatus struct {
	IsLocked      bool `json:"is_locked"`
	BarrierSealed bool `json:"barrier_sealed"`
	PasswordCount int  `json:"password_count"`
}

// sealProbe reports whether a barrier is sealed. *seal.TenantBarrier and the
// system *seal.Barrier both satisfy it.
type sealProbe interface {
	IsSealed() bool
}

// tenantPasswordState holds one tenant's shared store, its users' personal
// stores, and the set of users whose personal session is open.
type tenantPasswordState struct {
	shared   *BackendStore   // the tenant-shared entries
	personal sync.Map        // subject -> *BackendStore
	unlocked sync.Map        // subject -> struct{}: open personal sessions
	backend  storage.Backend // the tenant barrier, as a storage backend
	barrier  sealProbe
	tenantID string
}

// sealed reports whether the tenant barrier is sealed. Sealing ends every
// personal session: a barrier unsealed again later does not resume them.
func (st *tenantPasswordState) sealed() bool {
	if !st.barrier.IsSealed() {
		return false
	}
	st.unlocked.Clear()
	return true
}

// TenantPasswordStoreManager routes password operations to per-tenant stores
// under the xkms scope model (pkg/scope):
//
//   - Shared entries ("{tenant}/staticpw/shared/") are readable and writable
//     by every authenticated user of the tenant whenever the tenant barrier
//     is unsealed. They have no session of their own.
//   - A user's personal entries ("{tenant}/staticpw/users/{subject}/") are
//     visible only to that user, and only while the user's personal session
//     is open (UnlockUser). Each user locks and unlocks independently: one
//     user locking never locks another.
//
// Each tenant's entries are encrypted by its TenantBarrier from the
// BarrierRegistry. The system tenant is an ordinary tenant whose entries are
// encrypted by the system barrier. The systemStore serves only requests that
// carry no identity (internal callers, authentication disabled).
type TenantPasswordStoreManager struct {
	registry    *seal.BarrierRegistry
	systemStore Store
	tenants     sync.Map // tenant scope name -> *tenantPasswordState
}

// NewTenantPasswordStoreManager creates a manager over registry. systemStore
// serves requests with no identity.
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

// SystemStore returns the store that serves requests with no identity.
func (m *TenantPasswordStoreManager) SystemStore() Store {
	return m.systemStore
}

// tenantState returns tenantID's state, creating it on first use. The empty
// tenant and the system tenant are both the system tenant.
func (m *TenantPasswordStoreManager) tenantState(tenantID string) (*tenantPasswordState, error) {
	name := scope.TenantName(tenantID)
	if val, ok := m.tenants.Load(name); ok {
		return val.(*tenantPasswordState), nil
	}

	backend, probe, err := m.barrierFor(name)
	if err != nil {
		return nil, err
	}
	shared, err := NewSharedTenantStore(backend, name)
	if err != nil {
		return nil, err
	}
	state := &tenantPasswordState{
		shared:   shared,
		backend:  backend,
		barrier:  probe,
		tenantID: name,
	}

	actual, loaded := m.tenants.LoadOrStore(name, state)
	if loaded {
		if cerr := shared.Close(); cerr != nil {
			slog.Debug("staticpw: failed to close a duplicate shared tenant store", "tenant_id", name, "error", cerr)
		}
		return actual.(*tenantPasswordState), nil
	}
	return state, nil
}

// barrierFor returns the barrier holding tenant name's entries, as a storage
// backend and as a seal probe.
func (m *TenantPasswordStoreManager) barrierFor(name string) (storage.Backend, sealProbe, error) {
	if name == scope.SystemTenant {
		system := m.registry.SystemBarrier()
		if system == nil {
			return nil, nil, ErrNoSystemBarrier
		}
		return seal.NewBarrierBackend(system), system, nil
	}
	tb, err := m.registry.Tenant(name)
	if err != nil {
		return nil, nil, err
	}
	return seal.NewBarrierBackend(tb.Barrier()), tb, nil
}

// ResolveScopedStore returns the store userID sees in tenantID: the tenant's
// shared entries, plus the user's personal entries while the user's personal
// session is open. With the session locked, personal operations report
// ErrStoreLocked and shared entries stay usable.
//
// An empty tenantID is a request without an identity and gets the
// systemStore. An empty userID gets the shared entries only. Returns
// seal.ErrTenantSealed while the tenant barrier is sealed.
func (m *TenantPasswordStoreManager) ResolveScopedStore(tenantID, userID string) (Store, error) {
	if tenantID == "" {
		return m.systemStore, nil
	}
	state, err := m.tenantState(tenantID)
	if err != nil {
		return nil, err
	}
	if state.sealed() {
		return nil, seal.ErrTenantSealed
	}
	if userID == "" {
		return state.shared, nil
	}
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	if _, open := state.unlocked.Load(userID); !open {
		return NewLockedScopedStore(state.shared, userID)
	}
	personal, err := m.getOrCreatePersonalStore(state, userID)
	if err != nil {
		return nil, err
	}
	return NewScopedStore(state.shared, personal, userID)
}

// UnlockUser opens userID's personal session in tenantID. The caller verifies
// the user's credential first; this only records the session. Returns
// seal.ErrTenantSealed while the tenant barrier is sealed and
// ErrStoreNotLocked when the session is already open.
func (m *TenantPasswordStoreManager) UnlockUser(tenantID, userID string) error {
	state, err := m.tenantState(tenantID)
	if err != nil {
		return err
	}
	if state.sealed() {
		return seal.ErrTenantSealed
	}
	if !isValidUserID(userID) {
		return ErrInvalidUserID
	}
	if _, open := state.unlocked.LoadOrStore(userID, struct{}{}); open {
		return ErrStoreNotLocked
	}
	return nil
}

// LockUser closes userID's personal session in tenantID. Other users'
// sessions are untouched. Returns ErrStoreAlreadyLocked when the session is
// not open.
func (m *TenantPasswordStoreManager) LockUser(tenantID, userID string) error {
	state, err := m.tenantState(tenantID)
	if err != nil {
		return err
	}
	if !isValidUserID(userID) {
		return ErrInvalidUserID
	}
	if _, open := state.unlocked.LoadAndDelete(userID); !open {
		return ErrStoreAlreadyLocked
	}
	return nil
}

// IsUserLocked reports whether userID's personal session in tenantID is
// locked. Sessions start locked.
func (m *TenantPasswordStoreManager) IsUserLocked(tenantID, userID string) (bool, error) {
	state, err := m.tenantState(tenantID)
	if err != nil {
		return false, err
	}
	if state.sealed() {
		return true, nil
	}
	_, open := state.unlocked.Load(userID)
	return !open, nil
}

// UserStoreStatus returns the status userID sees in tenantID. PasswordCount
// counts the entries the user can read now: the shared entries, and the
// personal ones while the session is open.
func (m *TenantPasswordStoreManager) UserStoreStatus(tenantID, userID string) (*TenantStoreStatus, error) {
	if userID != "" && !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	state, err := m.tenantState(tenantID)
	if err != nil {
		return nil, err
	}
	if state.sealed() {
		return &TenantStoreStatus{IsLocked: true, BarrierSealed: true}, nil
	}
	_, open := state.unlocked.Load(userID)
	status := &TenantStoreStatus{IsLocked: !open}

	store, err := m.ResolveScopedStore(state.tenantID, userID)
	if err != nil {
		return nil, err
	}
	entries, err := store.List()
	if err != nil {
		return nil, err
	}
	status.PasswordCount = len(entries)
	return status, nil
}

// getOrCreatePersonalStore returns the cached personal store for a user,
// creating it on first access.
func (m *TenantPasswordStoreManager) getOrCreatePersonalStore(state *tenantPasswordState, userID string) (*BackendStore, error) {
	if val, ok := state.personal.Load(userID); ok {
		return val.(*BackendStore), nil
	}

	store, err := NewPersonalTenantStore(state.backend, state.tenantID, userID)
	if err != nil {
		return nil, err
	}

	actual, loaded := state.personal.LoadOrStore(userID, store)
	if loaded {
		if cerr := store.Close(); cerr != nil {
			slog.Debug("staticpw: failed to close a duplicate personal store", "tenant_id", state.tenantID, "user_id", userID, "error", cerr)
		}
		return actual.(*BackendStore), nil
	}
	return store, nil
}

// Close closes all cached tenant stores and ends every session.
func (m *TenantPasswordStoreManager) Close() error {
	var lastErr error
	m.tenants.Range(func(key, value any) bool {
		state := value.(*tenantPasswordState)
		state.unlocked.Clear()
		state.personal.Range(func(_, pVal any) bool {
			if err := pVal.(*BackendStore).Close(); err != nil {
				lastErr = err
			}
			return true
		})
		if err := state.shared.Close(); err != nil {
			lastErr = err
		}
		m.tenants.Delete(key)
		return true
	})
	return lastErr
}
