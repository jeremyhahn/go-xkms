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
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// TenantServicer defines operations for managing tenants and their barriers.
type TenantServicer interface {
	CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error)
	GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error)
	ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error)
	DeleteTenant(ctx context.Context, tenantID string) error
	TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error
	TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error
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

// GetTenant retrieves a tenant by its ID.
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	if tenantID == "" {
		return nil, ErrTenantIDRequired
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

// ListTenants returns all registered tenants.
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
	tenants := make([]transport.TenantInfo, len(infos))
	for i := range infos {
		tenants[i] = tenantInfoToTransport(&infos[i])
	}
	return &transport.ListTenantsResponse{Tenants: tenants}, nil
}

// DeleteTenant deletes a tenant by its ID.
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantIDRequired
	}
	if s.tenantService == nil {
		return ErrTenantServiceNotConfigured
	}
	return s.tenantService.DeleteTenant(ctx, tenantID)
}

// TenantBarrierInit initializes the encryption barrier for a specific tenant
// (Phase 2 of the two-phase tenant barrier model, §3.6). The tenant admin
// supplies their OWN credentials in the request; the server NEVER generates a
// tenant secret. The credentials are interpreted according to req.Strategy:
//
//   - "" / "passphrase" / "software": req.Passphrase is required and is used
//     as the Argon2id passphrase that seals the tenant root key. An empty
//     passphrase is a hard error (ErrTenantPassphraseRequired); there is no
//     server-generated fallback.
//   - "none": the barrier is initialized with empty credentials (no secret).
//   - "shamir": req.Passphrase is required (credential-mode Shamir splits the
//     caller's secret into shares). The recovery shares are produced by the
//     go-qrdb Shamir initialization path; this servicer surfaces no shares
//     because TenantBarrierInitResponse carries none — callers requiring share
//     distribution must use the dedicated custodian/share APIs.
//   - hardware strategies ("tpm2", "pkcs11", cloud KMS): no caller secret is
//     required; the strategy authenticates against its hardware/KMS backend.
//
// The seal strategy is fixed at tenant registration time. If req.Strategy
// names a strategy that conflicts with the one the tenant barrier was
// registered with, ErrTenantStrategyConflict is returned.
//
// This operation is idempotent: if the tenant barrier is already initialized,
// it returns nil without error.
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	if req.TenantID == "" {
		return ErrTenantIDRequired
	}
	if s.tenantService == nil {
		return ErrTenantServiceNotConfigured
	}

	// Delegate to go-qrdb's TenantService, which resolves the requested seal
	// strategy (passphrase/none/shamir or a hardware/cloud strategy —
	// tpm2/pkcs11/aws-kms/…) from the injected StrategyRegistry and
	// initializes the per-tenant barrier with the caller-supplied passphrase.
	// The server never generates a tenant secret.
	_, err := s.tenantService.TenantBarrierInitWithStrategy(
		ctx, req.TenantID, req.Passphrase, req.Threshold, req.Shares,
		seal.StrategyID(req.Strategy),
	)
	if err == seal.ErrAlreadyInitialized {
		return nil
	}
	return err
}

// isAlreadyUnsealed reports whether err indicates the tenant barrier was
// already unsealed — a no-op success for an idempotent unseal. Depending on the
// seal strategy the composed TenantService may surface either the tenant-scoped
// sentinel ("tenant barrier is already unsealed") or the generic barrier one
// ("barrier is already unsealed"), so both are treated as success.
func isAlreadyUnsealed(err error) bool {
	return err != nil &&
		(errors.Is(err, seal.ErrTenantAlreadyUnsealed) || errors.Is(err, seal.ErrAlreadyUnsealed))
}

// TenantBarrierUnseal unseals the encryption barrier for a specific tenant
// using the caller-supplied recovery material. The server holds no tenant
// secret, so it can only unseal with credentials taken from the request:
//
//   - req.Key carries the passphrase-derived key for software/passphrase and
//     hardware strategies (empty for "none").
//   - req.Share carries a single Shamir recovery share for the shamir strategy.
//
// If the tenant barrier is already unsealed, this is a no-op that returns nil.
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	if req.TenantID == "" {
		return ErrTenantIDRequired
	}
	if s.tenantService == nil {
		return ErrTenantServiceNotConfigured
	}

	// A Shamir share is submitted toward the quorum threshold; otherwise the
	// caller-supplied key material unseals the barrier directly.
	if len(req.Share) > 0 {
		_, err := s.tenantService.TenantBarrierUnsealShare(ctx, req.TenantID, string(req.Share))
		if isAlreadyUnsealed(err) {
			return nil
		}
		return err
	}
	if err := s.tenantService.TenantBarrierUnseal(ctx, req.TenantID, req.Key); err != nil {
		if isAlreadyUnsealed(err) {
			return nil
		}
		return err
	}
	return nil
}

// TenantBarrierStatus reports the current state of a per-tenant barrier
// (sealed/initialized flags, active seal strategy, hardware-backing, and Shamir
// quorum parameters).
//
// Requires the composed TenantService; returns ErrTenantServiceNotConfigured
// otherwise.
func (s *XKMSService) TenantBarrierStatus(ctx context.Context, tenantID string) (*transport.TenantBarrierStatusResponse, error) {
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}

	status, err := s.tenantService.TenantBarrierStatus(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return tenantBarrierStatusToTransport(status), nil
}

// UpdateTenantEntitlements updates a tenant's feature entitlements (which
// isolation tiers and dedicated-storage features its plan permits).
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
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}
	info, err := s.tenantService.UpdateEntitlements(ctx, req.TenantID, transportToEntitlements(req.Entitlements))
	if err != nil {
		return nil, err
	}
	return &transport.UpdateTenantEntitlementsResponse{Tenant: tenantInfoToTransport(info)}, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas.
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
	if s.tenantService == nil {
		return nil, ErrTenantServiceNotConfigured
	}
	info, err := s.tenantService.UpdateQuotas(ctx, req.TenantID, transportToQuotas(req.Quotas))
	if err != nil {
		return nil, err
	}
	return &transport.UpdateTenantQuotasResponse{Tenant: tenantInfoToTransport(info)}, nil
}
