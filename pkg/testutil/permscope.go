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

// ---------------------------------------------------------------------------
// Reading back a permission's declared tenancy scope
//
// A test that asserts what this repository contributed to go-qrdb's
// permission registry needs the READ side of RegisterPermissionScope, and the
// SDK re-exports the write side only.
//
// The seam that IS re-exported is the per-tenant scope store
// (qrdbsdk.NewTenantScopeStore). Its ResolveScope applies a documented
// precedence: the tenant's own stored definition first, then the
// process-global declaration layer. Backing it with an in-memory store
// nothing ever writes to leaves only the second step — exactly the
// declaration a module contributes — and a permission nobody declared
// surfaces as the same error the RBAC authorizer denies on, rather than as a
// scope. That is the property a scope gate must assert: not "what does the
// registry hold" but "what does the authorizer see".
// ---------------------------------------------------------------------------

// permScopeProbeTenant is the tenant PermissionScopeResolver asks about. Any
// non-system tenant does: the backing store is empty, so no per-tenant
// definition can shadow the process-global declaration under test.
const permScopeProbeTenant = "xkms-permscope-probe"

// PermissionScopeResolver answers the tenancy scope a permission was declared
// with, through the go-qrdb SDK alone.
type PermissionScopeResolver struct {
	store *qrdbsdk.TenantScopeStore
}

// NewPermissionScopeResolver returns a resolver over an empty in-memory
// store. It touches no process-global state, so separate tests may hold
// separate resolvers.
func NewPermissionScopeResolver() (*PermissionScopeResolver, error) {
	store, err := qrdbsdk.NewTenantScopeStore(newPermScopeStores())
	if err != nil {
		return nil, err
	}
	return &PermissionScopeResolver{store: store}, nil
}

// Scope returns the tenancy scope declared for p. A permission no layer has
// declared a scope for yields a *qrdbsdk.PermissionUndeclaredScopeError —
// never a scope — because that is what the authorizer sees and denies on.
func (r *PermissionScopeResolver) Scope(ctx context.Context, p qrdbsdk.Permission) (qrdbsdk.PermissionScope, error) {
	return r.store.ResolveScope(ctx, permScopeProbeTenant, p)
}

// permScopeStores hands every tenant its own in-memory store, which stays
// empty for the lifetime of a resolver.
type permScopeStores struct {
	mu     sync.Mutex
	stores map[string]qrdbsdk.KVStore
}

func newPermScopeStores() *permScopeStores {
	return &permScopeStores{stores: map[string]qrdbsdk.KVStore{}}
}

// Resolve implements qrdbsdk.TenantStoreResolver.
func (s *permScopeStores) Resolve(_ context.Context, tenantID string) (qrdbsdk.KVStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	store, ok := s.stores[tenantID]
	if !ok {
		store = qrdbsdk.NewMemoryKVStore()
		s.stores[tenantID] = store
	}
	return store, nil
}
