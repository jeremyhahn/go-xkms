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
	"context"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Barrier is a type alias for qrdbsdk.StorageBarrier. Since go-xkms's
// storage.Backend and go-qrdb's StorageBackend interfaces are now identical
// (string keys, context-aware), no adapter layer is needed.
type Barrier = qrdbsdk.StorageBarrier

// TenantBarrier is a type alias for qrdbsdk.TenantBarrier.
type TenantBarrier = qrdbsdk.TenantBarrier

// BarrierRegistry manages the system barrier and per-tenant barriers.
// This is a thin wrapper around go-qrdb's BarrierRegistry that bridges
// the go-xkms BarrierConfig (with audit.Logger) to go-qrdb's config format.
type BarrierRegistry struct {
	inner  *qrdbsdk.BarrierRegistry
	system *Barrier
}

// NewBarrier creates a new sealed Barrier backed by the given storage.
// At least one SealingStrategy must be provided.
func NewBarrier(
	logger *slog.Logger,
	base storage.Backend,
	config BarrierConfig,
	strategies ...SealingStrategy,
) (*Barrier, error) {
	qrdbConfig := qrdbsdk.BarrierConfig{
		PreferenceOrder: config.PreferenceOrder,
		RootKeyPath:     config.RootKeyPath,
		AuditLogger:     AuditLoggerFromXKMS(config.AuditLogger),
		Shamir:          config.Shamir,
	}
	return qrdbsdk.NewStorageBarrier(logger, base, qrdbConfig, strategies...)
}

// NewTenantBarrier creates a new tenant-specific barrier with namespace
// isolation. The base storage backend is wrapped with a prefix of
// "{tenantID}/" so all keys are isolated per tenant.
func NewTenantBarrier(
	tenantID string,
	logger *slog.Logger,
	base storage.Backend,
	config BarrierConfig,
	strategies ...SealingStrategy,
) (*TenantBarrier, error) {
	qrdbConfig := qrdbsdk.BarrierConfig{
		PreferenceOrder: config.PreferenceOrder,
		RootKeyPath:     config.RootKeyPath,
		AuditLogger:     AuditLoggerFromXKMS(config.AuditLogger),
		Shamir:          config.Shamir,
	}
	return qrdbsdk.NewTenantBarrier(tenantID, logger, base, qrdbConfig, strategies...)
}

// NewBarrierRegistry creates a new BarrierRegistry with the given system
// barrier. The system barrier must not be nil.
func NewBarrierRegistry(system *Barrier) (*BarrierRegistry, error) {
	inner, err := qrdbsdk.NewBarrierRegistry(system.Logger(), system)
	if err != nil {
		return nil, err
	}
	return &BarrierRegistry{inner: inner, system: system}, nil
}

// SystemBarrier returns the system-level barrier.
func (r *BarrierRegistry) SystemBarrier() *Barrier { return r.system }

// RegisterTenant creates and registers a new tenant barrier with default
// in-memory storage. Returns ErrTenantAlreadyExists if the tenant ID is
// already registered. Delegates to go-qrdb's RegisterTenantDefault.
func (r *BarrierRegistry) RegisterTenant(tenantID string) (*TenantBarrier, error) {
	return r.inner.RegisterTenantDefault(tenantID)
}

// RegisterTenantWithConfig creates and registers a tenant barrier with
// custom storage, config, and strategies.
func (r *BarrierRegistry) RegisterTenantWithConfig(
	tenantID string,
	base storage.Backend,
	config BarrierConfig,
	strategies ...SealingStrategy,
) (*TenantBarrier, error) {
	qrdbConfig := qrdbsdk.BarrierConfig{
		PreferenceOrder: config.PreferenceOrder,
		RootKeyPath:     config.RootKeyPath,
		AuditLogger:     AuditLoggerFromXKMS(config.AuditLogger),
		Shamir:          config.Shamir,
	}
	return r.inner.RegisterTenant(tenantID, base, qrdbConfig, strategies...)
}

// GetTenant looks up a registered tenant barrier by ID.
func (r *BarrierRegistry) GetTenant(tenantID string) (*TenantBarrier, error) {
	return r.inner.GetTenant(tenantID)
}

// Tenant is an alias for GetTenant, delegating to go-qrdb's Tenant method.
func (r *BarrierRegistry) Tenant(tenantID string) (*TenantBarrier, error) {
	return r.inner.Tenant(tenantID)
}

// RemoveTenant seals and removes the tenant barrier for the given ID.
func (r *BarrierRegistry) RemoveTenant(tenantID string) error {
	return r.inner.RemoveTenant(tenantID)
}

// UnregisterTenant is an alias for RemoveTenant, delegating to go-qrdb's
// UnregisterTenant method.
func (r *BarrierRegistry) UnregisterTenant(tenantID string) error {
	return r.inner.UnregisterTenant(tenantID)
}

// InitializeTenant initializes the tenant barrier identified by tenantID.
func (r *BarrierRegistry) InitializeTenant(ctx context.Context, tenantID string, creds Credentials) error {
	return r.inner.InitializeTenant(ctx, tenantID, creds)
}

// UnsealTenant unseals the tenant barrier identified by tenantID.
func (r *BarrierRegistry) UnsealTenant(ctx context.Context, tenantID string, creds Credentials) error {
	return r.inner.UnsealTenant(ctx, tenantID, creds)
}

// SealTenant seals the tenant barrier identified by tenantID.
func (r *BarrierRegistry) SealTenant(tenantID string) error {
	return r.inner.SealTenant(tenantID)
}

// TenantStatus returns the current status of the tenant barrier.
func (r *BarrierRegistry) TenantStatus(tenantID string) (*BarrierStatus, error) {
	return r.inner.TenantStatus(tenantID)
}

// ListTenants returns all registered tenant IDs.
func (r *BarrierRegistry) ListTenants() []string {
	return r.inner.ListTenants()
}

// SealAll seals the system barrier and all tenant barriers.
func (r *BarrierRegistry) SealAll() error {
	return r.inner.SealAll()
}

// Close closes the system barrier and all tenant barriers.
func (r *BarrierRegistry) Close() error {
	return r.inner.Close()
}

// NewShamirStrategy creates a new Shamir secret sharing strategy with
// M-of-N threshold reconstruction. Since storage.Backend and StorageBackend
// are now interface-compatible, the store is passed directly.
func NewShamirStrategy(store storage.Backend, threshold, total int) (*qrdbsdk.ShamirStrategy, error) {
	return qrdbsdk.NewShamirStrategy(store, threshold, total)
}
