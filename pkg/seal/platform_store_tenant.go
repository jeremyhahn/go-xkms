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

package seal

import (
	"log/slog"
	"sync"
)

// TenantPlatformStoreFactory creates and caches PlatformStore instances scoped
// to individual tenants. Each tenant's barrier provides namespace isolation so
// that secrets stored for one tenant are never visible to another.
type TenantPlatformStoreFactory struct {
	registry *BarrierRegistry
	logger   *slog.Logger
	stores   sync.Map // tenantID (string) -> *SealedPlatformStore
}

// NewTenantPlatformStoreFactory creates a new TenantPlatformStoreFactory.
// The registry must not be nil. If logger is nil, slog.Default() is used.
func NewTenantPlatformStoreFactory(registry *BarrierRegistry, logger *slog.Logger) *TenantPlatformStoreFactory {
	if logger == nil {
		logger = slog.Default()
	}
	return &TenantPlatformStoreFactory{
		registry: registry,
		logger:   logger,
	}
}

// ForTenant returns the cached PlatformStore for the given tenant, creating one
// on first access. Returns an error if the tenant is not registered in the
// registry or the store cannot be created.
func (f *TenantPlatformStoreFactory) ForTenant(tenantID string) (*SealedPlatformStore, error) {
	if v, ok := f.stores.Load(tenantID); ok {
		return v.(*SealedPlatformStore), nil
	}
	store, err := NewTenantPlatformStore(f.registry, tenantID, f.logger)
	if err != nil {
		return nil, err
	}
	// Use LoadOrStore so that a concurrent call wins gracefully.
	actual, _ := f.stores.LoadOrStore(tenantID, store)
	return actual.(*SealedPlatformStore), nil
}

// RemoveTenant evicts the cached PlatformStore for the given tenant. It is
// the caller's responsibility to remove the tenant from the registry afterward
// if desired. Calling RemoveTenant for an unknown tenant is a no-op.
func (f *TenantPlatformStoreFactory) RemoveTenant(tenantID string) {
	f.stores.Delete(tenantID)
}

// NewTenantPlatformStore creates a PlatformStore scoped to a specific tenant.
// The tenant's barrier provides automatic namespace isolation so that all
// secrets are stored under the tenant's encrypted key space.
func NewTenantPlatformStore(registry *BarrierRegistry, tenantID string, logger *slog.Logger) (*SealedPlatformStore, error) {
	tenantBarrier, err := registry.GetTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return NewPlatformStore(tenantBarrier.Barrier(), logger)
}
