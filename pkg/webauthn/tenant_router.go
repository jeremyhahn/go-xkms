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

package webauthn

import (
	"context"
	"sync"
	"time"
)

// TenantRouterParams configures a TenantRouter.
type TenantRouterParams struct {
	// SystemTenant is the tenant System serves; an empty tenant selects it.
	SystemTenant string
	// System is the existing relying party of the system tenant.
	System *Service
	// TenantExists reports whether tenantID names a tenant. Only a
	// confirmed tenant is built and cached.
	TenantExists func(ctx context.Context, tenantID string) (bool, error)
	// Build builds the relying party of one confirmed tenant.
	Build func(tenantID string) (*Service, error)
}

// TenantRouter selects the relying party of the tenant a passkey ceremony
// names (go-xkms#2319, ruling 1234). Each known tenant has its own Service,
// scoped to that tenant's accounts and minting tokens that carry it; an
// unknown tenant is answered by a decoy-only Service that resolves no
// account, so its ceremonies look like real ones and every finish fails as
// a wrong assertion does. An unknown tenant is never cached.
type TenantRouter struct {
	systemTenant string
	system       *Service
	decoy        *Service
	exists       func(ctx context.Context, tenantID string) (bool, error)
	build        func(tenantID string) (*Service, error)

	mu      sync.Mutex
	tenants map[string]*Service
}

// ErrTenantRouterIncomplete is returned by NewTenantRouter when a required
// parameter is missing.
var ErrTenantRouterIncomplete = NewError("new tenant router", ErrInvalidRequest)

// NewTenantRouter builds a router over the system relying party.
func NewTenantRouter(p TenantRouterParams) (*TenantRouter, error) {
	if p.System == nil || p.TenantExists == nil || p.Build == nil {
		return nil, ErrTenantRouterIncomplete
	}
	cfg := *p.System.config
	decoy, err := NewService(ServiceParams{
		Config:          &cfg,
		UserStore:       emptyUserStore{},
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: emptyCredentialStore{},
		Logger:          p.System.logger,
	})
	if err != nil {
		return nil, err
	}
	return &TenantRouter{
		systemTenant: p.SystemTenant,
		system:       p.System,
		decoy:        decoy,
		exists:       p.TenantExists,
		build:        p.Build,
		tenants:      make(map[string]*Service),
	}, nil
}

// System returns the relying party of the system tenant.
func (r *TenantRouter) System() *Service { return r.system }

// For returns the relying party of tenantID: the system service for the
// system tenant or an empty tenant, the cached or newly built service of a
// known tenant, and the decoy service (scoped to tenantID) otherwise.
func (r *TenantRouter) For(ctx context.Context, tenantID string) (*Service, error) {
	if tenantID == "" || tenantID == r.systemTenant {
		return r.system, nil
	}
	r.mu.Lock()
	svc, ok := r.tenants[tenantID]
	r.mu.Unlock()
	if ok {
		return svc, nil
	}
	known, err := r.exists(ctx, tenantID)
	if err != nil {
		return nil, WrapError("look up tenant", err)
	}
	if !known {
		return r.decoy.forTenant(tenantID), nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if svc, ok := r.tenants[tenantID]; ok {
		return svc, nil
	}
	svc, err = r.build(tenantID)
	if err != nil {
		return nil, WrapError("build tenant relying party", err)
	}
	r.tenants[tenantID] = svc
	return svc, nil
}

// ForRequest applies the host rule: a host mapped in the system config's
// TenantHosts selects its tenant, and a request naming another tenant there
// is answered as an unknown tenant; otherwise the explicit tenant, then the
// system tenant, is used.
func (r *TenantRouter) ForRequest(ctx context.Context, host, tenantID string) (*Service, error) {
	if hostTenant, ok := r.system.config.TenantForHost(host); ok {
		if tenantID != "" && tenantID != hostTenant {
			return r.decoy.forTenant(tenantID), nil
		}
		return r.For(ctx, hostTenant)
	}
	return r.For(ctx, tenantID)
}

// CachedTenants returns how many non-system tenant services are cached.
func (r *TenantRouter) CachedTenants() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tenants)
}

// services returns the system, decoy and every cached tenant service.
func (r *TenantRouter) services() []*Service {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Service, 0, len(r.tenants)+2)
	out = append(out, r.system, r.decoy)
	for _, svc := range r.tenants {
		out = append(out, svc)
	}
	return out
}

// SweepSessions removes expired sessions from every routed service every
// interval until ctx is done, including tenants cached after it starts.
func (r *TenantRouter) SweepSessions(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultSessionSweepInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, svc := range r.services() {
				if c, ok := svc.sessions.(SessionCleaner); ok {
					c.Cleanup()
				}
			}
		}
	}
}

// errDecoyStore is returned by the decoy stores' writes: a decoy relying
// party holds no account and no credential.
var errDecoyStore = NewError("decoy relying party", ErrInvalidRequest)

// emptyUserStore resolves no account.
type emptyUserStore struct{}

func (emptyUserStore) GetByID(context.Context, []byte) (User, error)    { return nil, ErrUserNotFound }
func (emptyUserStore) GetByEmail(context.Context, string) (User, error) { return nil, ErrUserNotFound }
func (emptyUserStore) Create(context.Context, string, string) (User, error) {
	return nil, errDecoyStore
}
func (emptyUserStore) Save(context.Context, User) error     { return ErrUserNotFound }
func (emptyUserStore) Delete(context.Context, []byte) error { return ErrUserNotFound }

// emptyCredentialStore holds no credential.
type emptyCredentialStore struct{}

func (emptyCredentialStore) Save(context.Context, *Credential) error { return errDecoyStore }
func (emptyCredentialStore) GetByUserID(context.Context, []byte) ([]*Credential, error) {
	return nil, nil
}
func (emptyCredentialStore) GetByCredentialID(context.Context, []byte) (*Credential, error) {
	return nil, ErrCredentialNotFound
}
func (emptyCredentialStore) Update(context.Context, *Credential) error    { return ErrCredentialNotFound }
func (emptyCredentialStore) Delete(context.Context, []byte) error         { return ErrCredentialNotFound }
func (emptyCredentialStore) DeleteByUserID(context.Context, []byte) error { return nil }
