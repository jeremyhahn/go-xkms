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

package xkms

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TenantServicer defines operations for managing tenants and their barriers.
type TenantServicer interface {
	CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error)
	GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error)
	ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error)
	DeleteTenant(ctx context.Context, tenantID string) error
}

// CreateTenant provisions a SEALED tenant shell (Phase 1 of the two-phase
// tenant barrier model, §3.6). It registers the tenant barrier in the
// registry but deliberately does NOT initialize it and does NOT generate any
// secret: the server never holds a tenant's barrier key. After CreateTenant
// the tenant barrier is uninitialized and sealed, and remains unusable until
// the tenant admin calls TenantBarrierInit (Phase 2) with their own
// caller-supplied credentials.
//
// The seal strategy is fixed at registration time. CreateTenantRequest does
// not carry a strategy, so the tenant inherits the system barrier's
// strategies (typically the passphrase strategy); TenantBarrierInit then
// supplies the passphrase that seals the freshly generated tenant root key.
//
// Requires the composed TenantService (SetTenantService); returns
// ErrTenantServiceNotConfigured otherwise. There is no fallback to
// direct barrier-registry operations.
func (s *XKMSService) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.ID == "" {
		return nil, ErrTenantIDRequired
	}
	if req.Name == "" {
		return nil, ErrTenantNameRequired
	}
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}

	// Delegate to go-qrdb's TenantService, which owns the entitlement-gated
	// isolation modes (prefix/barrier/volume/raft) and the system-managed
	// auto-unseal key-management mode. For a self-managed dedicated-isolation
	// tenant it registers the barrier SEALED and uninitialized — preserving
	// xkms's two-phase model (§3.6): the tenant admin drives Phase 2 via
	// TenantBarrierInit.
	info, err := s.tenantService.CreateTenant(
		ctx, req.ID, req.Name,
		qrdbsdk.TenantIsolationType(req.IsolationType),
		qrdbsdk.WithBarrierAutoUnseal(req.BarrierAutoUnseal),
	)
	if err != nil {
		return nil, err
	}
	return &transport.CreateTenantResponse{Tenant: tenantInfoToTransport(info)}, nil
}

// GetTenant retrieves a tenant by its ID. The tenant registry is the system
// tenant's, so a system caller may read any tenant; any other caller only its
// own, and any other tenant ID is refused with a *TenantBindingError that
// reads as not-found (admitTenantRecord).
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}
	if err := admitTenantRecord(ctx, "get tenant", tenantID); err != nil {
		return nil, err
	}
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}

	info, err := s.tenantService.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return &transport.GetTenantResponse{Tenant: tenantInfoToTransport(info)}, nil
}

// ListTenants returns the registered tenants the caller may see: every tenant
// for a system-tenant caller, only its own tenant for any other.
// Filtering here rather than in each transport keeps tenant enumeration under
// the same single owner as the per-tenant binding.
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}

	infos, err := s.tenantService.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	tenants := make([]transport.TenantInfo, 0, len(infos))
	for i := range infos {
		if admitTenantRecord(ctx, "list tenants", infos[i].ID) == nil {
			tenants = append(tenants, tenantInfoToTransport(&infos[i]))
		}
	}
	return &transport.ListTenantsResponse{Tenants: tenants}, nil
}

// DeleteTenant deletes a tenant by its ID. A system caller may delete any
// tenant; any other caller only its own, and any other tenant ID is refused
// with a *TenantBindingError that reads as not-found (admitTenantRecord).
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantIDRequired
	}
	if err := admitTenantRecord(ctx, "delete tenant", tenantID); err != nil {
		return err
	}
	if s.tenantService == nil {
		return ErrTenantServiceNotConfigured
	}
	return s.tenantService.DeleteTenant(ctx, tenantID)
}

// UpdateTenantEntitlements updates a tenant's feature entitlements (which
// isolation tiers and dedicated-storage features its plan permits). Plan
// management is a platform operation: only a system-tenant caller may change
// any tenant's entitlements, and a tenant-scoped caller is refused with a
// *TenantBindingError that reads as not-found even for its own tenant
// (qrdbsdk.IdentityIsSystemTenant).
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) UpdateTenantEntitlements(ctx context.Context, req *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.TenantID == "" {
		return nil, ErrTenantIDRequired
	}
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(ctx)) {
		return nil, refuseTenant(ctx, "update tenant entitlements", req.TenantID)
	}
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}
	info, err := s.tenantService.UpdateEntitlements(ctx, req.TenantID, transportToEntitlements(req.Entitlements))
	if err != nil {
		return nil, err
	}
	return &transport.UpdateTenantEntitlementsResponse{Tenant: tenantInfoToTransport(info)}, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas. Like entitlements,
// quotas are plan management: only a system-tenant caller may change them,
// and a tenant-scoped caller is refused with a *TenantBindingError that reads
// as not-found even for its own tenant (qrdbsdk.IdentityIsSystemTenant).
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) UpdateTenantQuotas(ctx context.Context, req *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.TenantID == "" {
		return nil, ErrTenantIDRequired
	}
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(ctx)) {
		return nil, refuseTenant(ctx, "update tenant quotas", req.TenantID)
	}
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}
	info, err := s.tenantService.UpdateQuotas(ctx, req.TenantID, transportToQuotas(req.Quotas))
	if err != nil {
		return nil, err
	}
	return &transport.UpdateTenantQuotasResponse{Tenant: tenantInfoToTransport(info)}, nil
}
