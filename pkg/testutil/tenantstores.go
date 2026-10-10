// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package testutil

import (
	"context"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TenantStores is an in-memory qrdbsdk.TenantStoreResolver. Each tenant
// resolves to its own in-memory store, created on first use, as a
// barrier-isolated tenant resolves to the store of its own TenantBarrier on a
// node. A sealed tenant resolves to qrdbsdk.ErrTenantStoreSealed, the error
// go-qrdb's resolver fails closed with, and its data survives an unseal.
type TenantStores struct {
	mu     sync.Mutex
	stores map[string]*qrdbsdk.MemoryKVStore
	sealed map[string]bool
}

// NewTenantStores returns a resolver with no tenants and nothing sealed.
func NewTenantStores() *TenantStores {
	return &TenantStores{
		stores: map[string]*qrdbsdk.MemoryKVStore{},
		sealed: map[string]bool{},
	}
}

// Resolve implements qrdbsdk.TenantStoreResolver.
func (s *TenantStores) Resolve(_ context.Context, tenantID string) (qrdbsdk.KVStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed[tenantID] {
		return nil, qrdbsdk.ErrTenantStoreSealed
	}
	return s.storeLocked(tenantID), nil
}

// Store returns tenantID's store, sealed or not, to inspect what the tenant
// holds.
func (s *TenantStores) Store(tenantID string) *qrdbsdk.MemoryKVStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.storeLocked(tenantID)
}

// Seal makes tenantID resolve to qrdbsdk.ErrTenantStoreSealed.
func (s *TenantStores) Seal(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed[tenantID] = true
}

// Unseal makes tenantID resolve to its store again.
func (s *TenantStores) Unseal(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sealed, tenantID)
}

// storeLocked returns tenantID's store, creating it on first use. The
// caller holds s.mu.
func (s *TenantStores) storeLocked(tenantID string) *qrdbsdk.MemoryKVStore {
	store, ok := s.stores[tenantID]
	if !ok {
		store = qrdbsdk.NewMemoryKVStore()
		s.stores[tenantID] = store
	}
	return store
}
