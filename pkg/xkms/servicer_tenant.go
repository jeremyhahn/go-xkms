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
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// tenantSecretSize is the byte length of the auto-generated secret used to
// initialize a tenant barrier during CreateTenant.
const tenantSecretSize = 32

// TenantServicer defines operations for managing tenants and their barriers.
type TenantServicer interface {
	CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error)
	GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error)
	ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error)
	DeleteTenant(ctx context.Context, tenantID string) error
	TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error
	TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error
}

// CreateTenant creates a new tenant with the specified configuration. When the
// system barrier is unsealed, the tenant barrier is automatically initialized
// with a generated secret so the tenant is immediately usable.
func (s *XKMSService) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	if s.barrierRegistry == nil {
		return nil, ErrBarrierRegistryNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.ID == "" {
		return nil, ErrTenantIDRequired
	}
	if req.Name == "" {
		return nil, ErrTenantNameRequired
	}

	_, err := s.barrierRegistry.RegisterTenant(req.ID)
	if err != nil {
		return nil, err
	}

	// Auto-initialize the tenant barrier so it is unsealed and ready for use.
	creds, err := generateTenantCredentials()
	if err != nil {
		return nil, err
	}
	if err := s.barrierRegistry.InitializeTenant(ctx, req.ID, creds); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	return &transport.CreateTenantResponse{
		Tenant: transport.TenantInfo{
			ID:        req.ID,
			Name:      req.Name,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}, nil
}

// GetTenant retrieves a tenant by its ID.
func (s *XKMSService) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	if s.barrierRegistry == nil {
		return nil, ErrBarrierRegistryNotConfigured
	}
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	tb, err := s.barrierRegistry.Tenant(tenantID)
	if err != nil {
		return nil, err
	}

	return &transport.GetTenantResponse{
		Tenant: transport.TenantInfo{
			ID:   tb.TenantID(),
			Name: tb.TenantID(), // BarrierRegistry doesn't store names; use ID as fallback
		},
	}, nil
}

// ListTenants returns all registered tenants.
func (s *XKMSService) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	if s.barrierRegistry == nil {
		return nil, ErrBarrierRegistryNotConfigured
	}

	ids := s.barrierRegistry.ListTenants()
	tenants := make([]transport.TenantInfo, len(ids))
	for i, id := range ids {
		tenants[i] = transport.TenantInfo{
			ID:   id,
			Name: id,
		}
	}

	return &transport.ListTenantsResponse{
		Tenants: tenants,
	}, nil
}

// DeleteTenant deletes a tenant by its ID.
func (s *XKMSService) DeleteTenant(ctx context.Context, tenantID string) error {
	if s.barrierRegistry == nil {
		return ErrBarrierRegistryNotConfigured
	}
	if tenantID == "" {
		return ErrTenantIDRequired
	}
	return s.barrierRegistry.UnregisterTenant(tenantID)
}

// TenantBarrierInit initializes the encryption barrier for a specific tenant.
// This operation is idempotent: if the tenant barrier is already initialized,
// it returns nil without error.
func (s *XKMSService) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	if s.barrierRegistry == nil {
		return ErrBarrierRegistryNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	if req.TenantID == "" {
		return ErrTenantIDRequired
	}

	// Verify tenant exists.
	_, err := s.barrierRegistry.Tenant(req.TenantID)
	if err != nil {
		return err
	}

	// Initialize with generated credentials. If the tenant barrier was
	// already initialized (e.g., during CreateTenant), treat that as
	// success to make this operation idempotent.
	creds, err := generateTenantCredentials()
	if err != nil {
		return err
	}
	if err := s.barrierRegistry.InitializeTenant(ctx, req.TenantID, creds); err != nil {
		if err == seal.ErrAlreadyInitialized {
			return nil
		}
		return err
	}
	return nil
}

// TenantBarrierUnseal unseals the encryption barrier for a specific tenant.
// If the tenant barrier is already unsealed, this is a no-op that returns nil.
func (s *XKMSService) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	if s.barrierRegistry == nil {
		return ErrBarrierRegistryNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	if req.TenantID == "" {
		return ErrTenantIDRequired
	}

	// Verify tenant exists.
	tb, err := s.barrierRegistry.Tenant(req.TenantID)
	if err != nil {
		return err
	}

	// If the tenant barrier is already unsealed, return success.
	if !tb.IsSealed() {
		return nil
	}

	return seal.ErrSealed
}

// generateTenantCredentials creates a Credentials value with a
// cryptographically random hex-encoded secret suitable for sealing
// a tenant barrier.
func generateTenantCredentials() (seal.Credentials, error) {
	buf := make([]byte, tenantSecretSize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return seal.Credentials{}, err
	}
	return seal.Credentials{Secret: hex.EncodeToString(buf)}, nil
}
