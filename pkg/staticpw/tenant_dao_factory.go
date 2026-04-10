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
	"fmt"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// BarrierRegistryAccessor provides access to tenant barriers without
// importing the full seal package. This narrow interface enables the
// TenantDAOFactory to resolve per-tenant encrypted storage backends
// using only the barrier registry, keeping dependencies minimal.
type BarrierRegistryAccessor interface {
	// GetTenantBarrier returns the storage backend for the given tenant.
	// The returned backend encrypts/decrypts transparently with the
	// tenant's own DEK. Returns an error if the tenant is not registered
	// or the barrier is sealed.
	GetTenantBarrier(tenantID string) (storage.Backend, error)
}

// ErrNilSystemKVStore is returned when a nil system KVStore is provided
// to the TenantDAOFactory constructor.
type ErrNilSystemKVStore struct{}

// Error implements the error interface.
func (e ErrNilSystemKVStore) Error() string {
	return "staticpw: nil system kvstore"
}

// ErrNilBarrierRegistryAccessor is returned when a nil BarrierRegistryAccessor
// is provided to the TenantDAOFactory constructor.
type ErrNilBarrierRegistryAccessor struct{}

// Error implements the error interface.
func (e ErrNilBarrierRegistryAccessor) Error() string {
	return "staticpw: nil barrier registry accessor"
}

// ErrTenantBarrierUnavailable is returned when a tenant's barrier cannot
// be resolved or is in a sealed state.
type ErrTenantBarrierUnavailable struct {
	TenantID string
	Cause    error
}

// Error implements the error interface.
func (e ErrTenantBarrierUnavailable) Error() string {
	return fmt.Sprintf("staticpw: tenant barrier unavailable for %q: %v", e.TenantID, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrTenantBarrierUnavailable) Unwrap() error {
	return e.Cause
}

// ErrInvalidTenant is returned when a tenant ID is empty or fails validation.
type ErrInvalidTenant struct {
	TenantID string
}

// Error implements the error interface.
func (e ErrInvalidTenant) Error() string {
	if e.TenantID == "" {
		return "staticpw: tenant ID is empty"
	}
	return fmt.Sprintf("staticpw: invalid tenant ID %q", e.TenantID)
}

// TenantDAOFactory creates per-tenant DAO stores for password and team
// entities. Each tenant's stores are backed by their TenantBarrier, which
// provides transparent encryption with the tenant's own DEK. The factory
// caches KVStore adapters per tenant using a sync.Map for lock-free
// concurrent access.
//
// Architecture:
//
//	TenantBarrier (storage.Backend, encrypts with tenant DEK)
//	  -> kvadapter.KVStoreAdapter (bridges to kvstore.KVStore)
//	    -> DAOStore / DAOTeamStore (typed entity persistence)
type TenantDAOFactory struct {
	systemKVStore   qrdbsdk.KVStore
	barrierRegistry BarrierRegistryAccessor
	tenantKVStores  sync.Map // tenantID -> qrdbsdk.KVStore
}

// NewTenantDAOFactory creates a new TenantDAOFactory. The systemKVStore is
// used for system-level (non-tenant) stores. The registry provides access
// to per-tenant barrier-encrypted storage backends.
func NewTenantDAOFactory(systemKVStore qrdbsdk.KVStore, registry BarrierRegistryAccessor) (*TenantDAOFactory, error) {
	if systemKVStore == nil {
		return nil, ErrNilSystemKVStore{}
	}
	if registry == nil {
		return nil, ErrNilBarrierRegistryAccessor{}
	}
	return &TenantDAOFactory{
		systemKVStore:   systemKVStore,
		barrierRegistry: registry,
	}, nil
}

// PasswordStoreForTenant returns a tenant-scoped password DAOStore.
// The store is backed by the tenant's barrier, which transparently
// encrypts all data with the tenant's DEK. Returns ErrInvalidTenant if
// the tenant ID is empty or invalid, and ErrTenantBarrierUnavailable if
// the tenant's barrier cannot be resolved.
func (f *TenantDAOFactory) PasswordStoreForTenant(tenantID string) (*DAOStore, error) {
	kvStore, err := f.tenantKVStore(tenantID)
	if err != nil {
		return nil, err
	}
	return NewDAOStore(kvStore)
}

// TeamStoreForTenant returns a tenant-scoped team DAOTeamStore.
// The store is backed by the tenant's barrier, which transparently
// encrypts all data with the tenant's DEK.
func (f *TenantDAOFactory) TeamStoreForTenant(tenantID string) (*DAOTeamStore, error) {
	kvStore, err := f.tenantKVStore(tenantID)
	if err != nil {
		return nil, err
	}
	return NewDAOTeamStore(kvStore)
}

// SystemPasswordStore returns the system-level (non-tenant) password store.
func (f *TenantDAOFactory) SystemPasswordStore() (*DAOStore, error) {
	return NewDAOStore(f.systemKVStore)
}

// SystemTeamStore returns the system-level (non-tenant) team store.
func (f *TenantDAOFactory) SystemTeamStore() (*DAOTeamStore, error) {
	return NewDAOTeamStore(f.systemKVStore)
}

// tenantKVStore resolves and caches the KVStore adapter for a tenant.
// The adapter bridges the tenant's barrier (storage.Backend) to the
// kvstore.KVStore interface required by the DAO layer.
func (f *TenantDAOFactory) tenantKVStore(tenantID string) (qrdbsdk.KVStore, error) {
	if !isValidTenantID(tenantID) {
		return nil, ErrInvalidTenant{TenantID: tenantID}
	}

	// Fast path: cached KVStore.
	if val, ok := f.tenantKVStores.Load(tenantID); ok {
		return val.(qrdbsdk.KVStore), nil
	}

	// Resolve the tenant barrier from the registry.
	tenantBackend, err := f.barrierRegistry.GetTenantBarrier(tenantID)
	if err != nil {
		return nil, ErrTenantBarrierUnavailable{TenantID: tenantID, Cause: err}
	}

	// Create a KVStore adapter over the tenant's encrypted backend.
	kvStore, err := kvadapter.New(tenantBackend)
	if err != nil {
		return nil, ErrTenantBarrierUnavailable{TenantID: tenantID, Cause: err}
	}

	// Cache with LoadOrStore for concurrent safety.
	actual, _ := f.tenantKVStores.LoadOrStore(tenantID, kvStore)
	return actual.(qrdbsdk.KVStore), nil
}

// InvalidateTenant removes the cached KVStore for a tenant. This should
// be called when a tenant's barrier is re-sealed or the tenant is removed,
// so the next access creates a fresh adapter.
func (f *TenantDAOFactory) InvalidateTenant(tenantID string) {
	f.tenantKVStores.Delete(tenantID)
}
