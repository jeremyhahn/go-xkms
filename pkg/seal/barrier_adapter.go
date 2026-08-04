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
	"errors"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// tenantMetadataStore adapts an xkms-backed StorageBackend to go-qrdb's
// not-found contract. go-qrdb's TenantService distinguishes "tenant does not
// exist yet" from a real storage failure via errors.Is(err, ErrSecretNotFound),
// but xkms storage backends (and the StorageBarrier wrapping them) report a
// missing key as storage.ErrNotFound. This adapter translates that sentinel on
// Get so tenant create/lookup behaves correctly; all other operations delegate
// unchanged.
type tenantMetadataStore struct {
	qrdbsdk.StorageBackend
}

// Get translates xkms's storage.ErrNotFound into go-qrdb's ErrSecretNotFound so
// the TenantService recognizes an absent tenant record.
func (s tenantMetadataStore) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := s.StorageBackend.Get(ctx, key)
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		return nil, qrdbsdk.ErrSecretNotFound
	}
	return v, err
}

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

// BarrierRegistryOption configures a BarrierRegistry at construction time
// (and via Attach). The canonical options are WithVolumePool and
// WithPerTenantRegistry, which wire the dedicated-isolation storage seam.
type BarrierRegistryOption = qrdbsdk.BarrierRegistryOption

// VolumePoolSubsystem bundles the pool Manager, StateStore, and
// PerTenantRegistry that back dedicated-isolation (barrier/volume/raft) tenant
// storage. Build it with BuildVolumePoolSubsystem and attach via WithVolumePool
// + WithPerTenantRegistry. Close must be called at shutdown.
type VolumePoolSubsystem = qrdbsdk.VolumePoolSubsystem

// WithVolumePool attaches the volume-pool Manager + round-robin StateStore so a
// dedicated-isolation tenant registered with a nil backend draws its per-tenant
// Pebble path from the pool. Without it, RegisterTenantPooled* fail with
// ErrPoolNotConfigured.
var WithVolumePool = qrdbsdk.WithVolumePool

// WithPerTenantRegistry attaches the per-tenant Pebble registry that opens and
// tracks each dedicated-isolation tenant's storage instance.
var WithPerTenantRegistry = qrdbsdk.WithPerTenantRegistry

// BuildVolumePoolSubsystem constructs the volume-pool subsystem from a data
// directory and the declared pool config. It returns (nil, nil) when no pools
// are configured.
var BuildVolumePoolSubsystem = qrdbsdk.BuildVolumePoolSubsystem

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
// barrier. The system barrier must not be nil. Optional options (notably
// WithVolumePool and WithPerTenantRegistry) wire the dedicated-isolation
// storage seam so barrier/volume/raft tenants can be registered with a
// pool-allocated per-tenant backend.
func NewBarrierRegistry(system *Barrier, opts ...BarrierRegistryOption) (*BarrierRegistry, error) {
	inner, err := qrdbsdk.NewBarrierRegistry(system.Logger(), system, opts...)
	if err != nil {
		return nil, err
	}
	return &BarrierRegistry{inner: inner, system: system}, nil
}

// WrapBarrierRegistry adapts an already-constructed go-qrdb BarrierRegistry
// (e.g. the one an embedded qrdb node builds and owns when its seal is enabled)
// into the go-xkms wrapper, so xkms can adopt the node's registry as its own
// without re-constructing the tenant/volume subsystem. The system barrier is
// the node's system StorageBarrier (registry.SystemBarrier()).
func WrapBarrierRegistry(inner *qrdbsdk.BarrierRegistry, system *Barrier) *BarrierRegistry {
	return &BarrierRegistry{inner: inner, system: system}
}

// SystemBarrier returns the system-level barrier.
func (r *BarrierRegistry) SystemBarrier() *Barrier { return r.system }

// Inner returns the underlying go-qrdb BarrierRegistry. It is the seam used to
// compose go-qrdb's TenantService (NewServiceTenantService) on top of the
// registry so xkms inherits the entitlement-gated isolation, system-managed
// auto-unseal, and volume/raft tenant lifecycle without re-implementing them.
func (r *BarrierRegistry) Inner() *qrdbsdk.BarrierRegistry { return r.inner }

// Attach wires additional options (e.g. WithVolumePool / WithPerTenantRegistry)
// onto an already-constructed registry. It is used when the volume-pool
// subsystem is built after the registry (the system barrier must exist first).
func (r *BarrierRegistry) Attach(opts ...BarrierRegistryOption) { r.inner.Attach(opts...) }

// RestoreVolumeTenants re-registers dedicated-isolation tenants from their
// persisted pool assignments at boot and, for system-managed (auto-unseal)
// tenants, re-attaches and unseals their barriers credential-free.
func (r *BarrierRegistry) RestoreVolumeTenants(ctx context.Context) error {
	return r.inner.RestoreVolumeTenants(ctx)
}

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
	return r.inner.RegisterTenant(context.Background(), tenantID, base, qrdbConfig, strategies...)
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
// M-of-N threshold reconstruction. Shares are never persisted.
func NewShamirStrategy(threshold, total int) (*qrdbsdk.ShamirStrategy, error) {
	return qrdbsdk.NewShamirStrategy(threshold, total)
}

// StrategyRegistry resolves seal strategies by name. go-qrdb's TenantService
// uses it to resolve a hardware/cloud strategy when a tenant barrier is
// initialized with an explicit strategy ID (TenantBarrierInitWithStrategy).
type StrategyRegistry = qrdbsdk.StrategyRegistry

// TenantService is go-qrdb's canonical tenant lifecycle servicer (entitlement-
// gated isolation, system-managed auto-unseal, quotas, and per-tenant barrier
// sealing). It is surfaced here so a composing service can hold the composed,
// hardware-enhanced instance returned by NewHardwareTenantService.
type TenantService = qrdbsdk.ServiceTenantServicer

// TenantServiceOption configures the composed TenantService.
type TenantServiceOption = qrdbsdk.TenantServiceOption

// NewHardwareTenantService composes go-qrdb's TenantService on top of a barrier
// registry with the given xkms hardware seal strategies injected as a
// StrategyRegistry. It is the one-call composition seam for hardware-backed
// per-tenant encryption: a tenant barrier initialized with an explicit hardware
// strategy ID (tpm2/pkcs11/awskms/…) is sealed by the matching xkms strategy,
// while the registry's volume pool (when attached) gives each dedicated-
// isolation tenant durable per-tenant storage. The store persists tenant
// metadata; pass the system barrier (or a replicated KV-backed store). Extra
// options (default entitlements/quotas, ceremony CA, distributor) are appended
// after the strategy registry.
func NewHardwareTenantService(
	store qrdbsdk.StorageBackend,
	registry *BarrierRegistry,
	logger *slog.Logger,
	strategies []SealingStrategy,
	opts ...TenantServiceOption,
) (TenantService, error) {
	hwRegistry, err := NewHardwareStrategyRegistry(strategies...)
	if err != nil {
		return nil, err
	}
	allOpts := append([]TenantServiceOption{qrdbsdk.WithTenantStrategyRegistry(hwRegistry)}, opts...)
	// Wrap the store so a missing tenant record surfaces go-qrdb's
	// ErrSecretNotFound rather than xkms's storage.ErrNotFound.
	return qrdbsdk.NewServiceTenantService(tenantMetadataStore{store}, registry.Inner(), logger, allOpts...)
}

// NewHardwareStrategyRegistry builds a StrategyRegistry seeded with go-qrdb's
// built-in software strategies (passphrase, none) and the hardware-backed
// strategies supplied by the caller. This is the composition seam that lets a
// per-tenant barrier be sealed by a TPM, PKCS#11 token, or cloud KMS: the
// returned registry is injected into go-qrdb's TenantService via
// WithTenantStrategyRegistry so TenantBarrierInitWithStrategy("tpm2"/"pkcs11"/
// "awskms"/…) resolves the matching xkms strategy by ID.
//
// Only hardware-backed strategies are registered; software/none strategies are
// already provided by the default registry, and registering a duplicate ID
// would error. Each strategy is stateless with respect to which root key it
// seals (the root key is passed per call), so a single instance is safely
// shared across every tenant barrier.
func NewHardwareStrategyRegistry(strategies ...SealingStrategy) (StrategyRegistry, error) {
	reg := qrdbsdk.NewDefaultStrategyRegistry()
	for _, st := range strategies {
		if st == nil || !st.HardwareBacked() {
			continue
		}
		strategy := st
		if err := reg.Register(strategy.ID(), func() (SealingStrategy, error) {
			return strategy, nil
		}); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
