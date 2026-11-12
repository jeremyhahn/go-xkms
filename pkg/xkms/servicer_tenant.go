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
	"errors"

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

// TenantRecords keeps the CA record each tenant carries beside its go-qrdb
// identity — lifecycle status, CA hierarchy and issuance settings — and the
// CA data hanging off it. The hosted ACME CA implements it; the tenant
// lifecycle composes it so /api/v1/tenants has one owner.
type TenantRecords interface {
	// CreateTenantRecord saves an active record for a tenant just created,
	// with the given issuance settings (nil for none).
	CreateTenantRecord(ctx context.Context, tenantID, name string, settings *transport.TenantSettingsInfo) error
	// TenantRecord returns the tenant's record, or nil when none is kept.
	TenantRecord(ctx context.Context, tenantID string) (*transport.TenantRecord, error)
	// ReleaseTenant removes the CA data kept for a tenant about to be
	// deleted (roles, CA material), best-effort.
	ReleaseTenant(ctx context.Context, tenantID string)
	// DeleteTenantRecord removes the record of a deleted tenant.
	DeleteTenantRecord(ctx context.Context, tenantID string) error
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
// Only a system-tenant caller may create a tenant, and the tenant gets a CA
// record when records are wired (CreateTenantDetail).
//
// Requires the composed TenantService (SetTenantService); returns
// ErrTenantServiceNotConfigured otherwise. There is no fallback to
// direct barrier-registry operations.
func (s *XKMSService) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	detail, err := s.CreateTenantDetail(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	return &transport.CreateTenantResponse{Tenant: detail.Tenant}, nil
}

// CreateTenantDetail creates a tenant as CreateTenant does and saves its CA
// record with the given issuance settings (nil for none), returning both.
// Creating a tenant is a platform operation: only a system-tenant caller may
// create one, and a tenant-scoped caller is refused with a
// *TenantBindingError that reads as not-found. An empty request ID is
// generated.
//
// The tenant and its record are created together: when the record cannot be
// saved the tenant is deleted again and a *TenantRecordError returned.
// Settings without a wired record keeper are refused with
// ErrTenantRecordsNotConfigured rather than dropped.
func (s *XKMSService) CreateTenantDetail(ctx context.Context, req *transport.CreateTenantRequest, settings *transport.TenantSettingsInfo) (*transport.TenantDetail, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.ID == "" {
		return nil, ErrTenantIDRequired
	}
	if req.Name == "" {
		return nil, ErrTenantNameRequired
	}
	tenantID := req.ID
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(ctx)) {
		return nil, refuseTenant(ctx, "create tenant", tenantID)
	}
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}
	records := s.tenantRecords.load()
	if records == nil && settings != nil {
		return nil, ErrTenantRecordsNotConfigured
	}

	// Delegate to go-qrdb's TenantService, which owns the entitlement-gated
	// isolation modes (prefix/barrier/volume/raft) and the system-managed
	// auto-unseal key-management mode. For a self-managed dedicated-isolation
	// tenant it registers the barrier SEALED and uninitialized — preserving
	// xkms's two-phase model (§3.6): the tenant admin drives Phase 2 via
	// TenantBarrierInit.
	info, err := s.tenantService.CreateTenant(
		ctx, tenantID, req.Name,
		qrdbsdk.TenantIsolationType(req.IsolationType),
		qrdbsdk.WithBarrierAutoUnseal(req.BarrierAutoUnseal),
	)
	if err != nil {
		return nil, err
	}
	detail := &transport.TenantDetail{Tenant: tenantInfoToTransport(info)}
	if records == nil {
		return detail, nil
	}
	if err := records.CreateTenantRecord(ctx, info.ID, info.Name, settings); err != nil {
		return nil, &TenantRecordError{
			Op:       "create tenant record",
			TenantID: info.ID,
			Err:      errors.Join(err, s.tenantService.DeleteTenant(ctx, info.ID)),
		}
	}
	detail.Record = &transport.TenantRecord{Status: transport.TenantStatusActive, Settings: settings}
	return detail, nil
}

// GetTenant retrieves a tenant by its ID, as GetTenantDetail does.
func (s *XKMSService) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	detail, err := s.GetTenantDetail(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return &transport.GetTenantResponse{Tenant: detail.Tenant}, nil
}

// GetTenantDetail retrieves a tenant and its CA record by the tenant's ID.
// The tenant registry is the system tenant's, so a system caller may read any
// tenant; any other caller only its own, and any other tenant ID is refused
// with a *TenantBindingError that reads as not-found (admitTenantRecord). A
// tenant whose record marks it deleted reads as not-found too
// (*TenantDeletedError).
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) GetTenantDetail(ctx context.Context, tenantID string) (*transport.TenantDetail, error) {
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
	return tenantDetail(ctx, s.tenantRecords.load(), tenantInfoToTransport(info))
}

// ListTenants returns the registered tenants the caller may see, as
// ListTenantDetails does with no status filter.
func (s *XKMSService) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	details, err := s.ListTenantDetails(ctx, "")
	if err != nil {
		return nil, err
	}
	tenants := make([]transport.TenantInfo, 0, len(details))
	for i := range details {
		tenants = append(tenants, details[i].Tenant)
	}
	return &transport.ListTenantsResponse{Tenants: tenants}, nil
}

// ListTenantDetails returns the registered tenants the caller may see, with
// their CA records: every tenant for a system-tenant caller, only its own
// tenant for any other. Filtering here rather than in each transport keeps
// tenant enumeration under the same single owner as the per-tenant binding.
// A non-empty status is refused with *TenantUnsupportedFieldError
// (ErrTenantStatusUnsupported) before any tenant is read, until go-qrdb
// carries a tenant status; tenants whose record marks them deleted are never
// listed.
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) ListTenantDetails(ctx context.Context, status string) ([]transport.TenantDetail, error) {
	if status != "" {
		return nil, &TenantUnsupportedFieldError{Field: "status"}
	}
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}

	infos, err := s.tenantService.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	records := s.tenantRecords.load()
	details := make([]transport.TenantDetail, 0, len(infos))
	for i := range infos {
		if admitTenantRecord(ctx, "list tenants", infos[i].ID) != nil {
			continue
		}
		detail, err := tenantDetail(ctx, records, tenantInfoToTransport(&infos[i]))
		if err != nil {
			var deleted *TenantDeletedError
			if errors.As(err, &deleted) {
				continue
			}
			return nil, err
		}
		details = append(details, *detail)
	}
	return details, nil
}

// tenantDetail pairs tenant with the CA record records keeps for it; with no
// records wired the tenant has none. A record marking the tenant deleted
// reads as an absent tenant (*TenantDeletedError).
func tenantDetail(ctx context.Context, records TenantRecords, tenant transport.TenantInfo) (*transport.TenantDetail, error) {
	detail := &transport.TenantDetail{Tenant: tenant}
	if records == nil {
		return detail, nil
	}
	record, err := records.TenantRecord(ctx, tenant.ID)
	if err != nil {
		return nil, &TenantRecordError{Op: "read tenant record", TenantID: tenant.ID, Err: err}
	}
	if record != nil && record.Status == transport.TenantStatusDeleted {
		return nil, &TenantDeletedError{TenantID: tenant.ID}
	}
	detail.Record = record
	return detail, nil
}

// DeleteTenant deletes a tenant by its ID. A system caller may delete any
// tenant; any other caller only its own, and any other tenant ID is refused
// with a *TenantBindingError that reads as not-found (admitTenantRecord).
//
// With tenant records wired, what the CA keeps for the tenant is released
// before the tenant is deleted and its record removed after; a record that
// cannot be removed is reported as a *TenantRecordError, the tenant itself
// being gone.
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

	records := s.tenantRecords.load()
	if records != nil {
		if _, err := s.tenantService.GetTenant(ctx, tenantID); err != nil {
			return err
		}
		records.ReleaseTenant(ctx, tenantID)
	}
	if err := s.tenantService.DeleteTenant(ctx, tenantID); err != nil {
		return err
	}
	if records != nil {
		if err := records.DeleteTenantRecord(ctx, tenantID); err != nil {
			return &TenantRecordError{Op: "delete tenant record", TenantID: tenantID, Err: err}
		}
	}
	return nil
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
