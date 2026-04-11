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

package hardware

import (
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// TenantCertStorageFactory creates and caches HardwareCertStorage instances
// scoped to individual tenants. Each tenant's barrier provides namespace
// isolation so that certificates stored for one tenant are never visible to
// another.
type TenantCertStorageFactory struct {
	registry *seal.BarrierRegistry
	stores   sync.Map // tenantID (string) -> HardwareCertStorage
}

// NewTenantCertStorageFactory creates a new TenantCertStorageFactory backed
// by the given registry. The registry must not be nil.
func NewTenantCertStorageFactory(registry *seal.BarrierRegistry) *TenantCertStorageFactory {
	return &TenantCertStorageFactory{registry: registry}
}

// ForTenant returns the cached HardwareCertStorage for the given tenant,
// creating one on first access. Returns an error if the tenant is not
// registered in the registry.
func (f *TenantCertStorageFactory) ForTenant(tenantID string) (HardwareCertStorage, error) {
	if v, ok := f.stores.Load(tenantID); ok {
		return v.(HardwareCertStorage), nil
	}
	store, err := NewTenantCertStorage(f.registry, tenantID)
	if err != nil {
		return nil, err
	}
	// Use LoadOrStore so that a concurrent call wins gracefully.
	actual, _ := f.stores.LoadOrStore(tenantID, store)
	return actual.(HardwareCertStorage), nil
}

// RemoveTenant evicts the cached HardwareCertStorage for the given tenant.
// Calling RemoveTenant for an unknown tenant is a no-op.
func (f *TenantCertStorageFactory) RemoveTenant(tenantID string) {
	f.stores.Delete(tenantID)
}

// NewTenantCertStorage creates a HardwareCertStorage scoped to a specific
// tenant using the tenant's barrier for storage isolation.
func NewTenantCertStorage(registry *seal.BarrierRegistry, tenantID string) (HardwareCertStorage, error) {
	tenantBarrier, err := registry.GetTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return NewBackendCertStorageAdapter(tenantBarrier.Barrier()), nil
}
