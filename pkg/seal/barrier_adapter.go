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

// PutIfAllAbsent forwards the fenced create go-qrdb's TenantService commits
// a new tenant with: the record only while it and the tenant's tombstone are
// absent, in one atomic step. The metadata store is the system barrier,
// whose own PutIfAllAbsent encrypts and hands the decision to its base -- the
// xkms backend under guardedStorageBackend. A store without the capability
// reports storage.ErrFencedCreateUnsupported; there is no check-then-write.
func (s tenantMetadataStore) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	fc, ok := s.StorageBackend.(storage.FencedCreator)
	if !ok {
		return false, storage.ErrFencedCreateUnsupported
	}
	return fc.PutIfAllAbsent(ctx, key, value, fences...)
}

// CompareAndSwap completes go-qrdb's kvstore.AtomicKVStore, which its
// TenantService requires before it updates a tenant record. It delegates to
// the wrapped store's own atomic swap (the system barrier's, or an xkms
// storage.CompareAndSwapper's with the current value dropped); a store
// without one is refused, never emulated with a read-then-write.
func (s tenantMetadataStore) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	switch cas := s.StorageBackend.(type) {
	case interface {
		CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error)
	}:
		swapped, err := cas.CompareAndSwap(ctx, key, expected, next)
		if err != nil && errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return swapped, err
	case storage.CompareAndSwapper:
		swapped, _, err := cas.CompareAndSwap(ctx, key, expected, next)
		return swapped, err
	default:
		return false, storage.ErrCompareAndSwapUnsupported
	}
}

// guardedStorageBackend adapts an xkms storage.Backend to go-qrdb's
// StorageBackend, whose contract (go-quicraft's seal.StorageBackend) requires
// CompareAndDelete as a MANDATORY method.
//
// xkms models the guarded delete as an OPTIONAL capability instead —
// storage.CompareAndDeleter, alongside CompareAndSwapper — because several
// backends cannot provide it correctly and a mandatory method would force them
// to ship a stand-in. The two shapes meet here, and this is the right place for
// them to meet: quicraft's own contract says a backend that cannot perform the
// operation must report an error rather than approximate it, so the capability
// assertion is exactly what that error is for.
//
// The assertion happens per call rather than at construction on purpose.
// Refusing to build a barrier over a backend that cannot do ONE optional
// operation would take away everything else the barrier does with it, and every
// other method here is unaffected.
type guardedStorageBackend struct {
	storage.Backend
}

// guardStorage wraps base for go-qrdb while PRESERVING A NIL BASE.
//
// The nil is a sentinel upstream, not an absence of information, and wrapping
// destroys it: guardedStorageBackend{nil} is a NON-NIL interface value holding a
// nil Backend, so every `base == nil` test on the go-qrdb side silently stops
// firing. Two behaviours depend on those tests --
// BarrierRegistry.RegisterTenant reads nil as "allocate this tenant's storage
// from the volume pool" (barrier_registry.go:273), and NewTenantBarrier refuses
// a nil base with ErrNilStorageBackend (tenant_barrier.go:40).
//
// Wrapped unconditionally, the first skips the pooled allocation and the second
// skips its guard, and BOTH then build a barrier over a wrapper whose embedded
// Backend is nil -- a deferred nil dereference on the first storage access,
// with nothing wrong at the call site. Returning an untyped nil keeps the
// sentinel intact and lets upstream answer as it always did.
func guardStorage(base storage.Backend) qrdbsdk.StorageBackend {
	if base == nil {
		return nil
	}
	return guardedStorageBackend{base}
}

// MissingKeyError reports a key absent from the xkms storage backend under a
// barrier. xkms backends report that as storage.ErrNotFound while go-qrdb
// recognises it as ErrSecretNotFound -- the BarrierRegistry reads its
// tenant-root record through the system barrier and must tell "no record yet"
// from a failed read -- so the error matches both.
type MissingKeyError struct {
	// Key is the missing key.
	Key string

	// Err is the backend's own not-found error.
	Err error
}

// Error returns the backend's not-found message.
func (e *MissingKeyError) Error() string { return e.Err.Error() }

// Unwrap returns the backend's not-found error, so errors.Is(err,
// storage.ErrNotFound) still holds.
func (e *MissingKeyError) Unwrap() error { return e.Err }

// Is reports go-qrdb's not-found sentinel as a match.
func (e *MissingKeyError) Is(target error) bool { return target == qrdbsdk.ErrSecretNotFound }

// Get reads key from the wrapped backend, reporting an absent key as a
// *MissingKeyError.
func (g guardedStorageBackend) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := g.Backend.Get(ctx, key)
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		return nil, &MissingKeyError{Key: key, Err: err}
	}
	return v, err
}

// CompareAndDelete forwards to the wrapped backend's optional capability, and
// reports ErrCompareAndDeleteUnsupported when it has none. It never degrades to
// a read followed by an unguarded delete: that reintroduces precisely the race
// the operation exists to close.
func (g guardedStorageBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	cad, ok := g.Backend.(storage.CompareAndDeleter)
	if !ok {
		return false, storage.ErrCompareAndDeleteUnsupported
	}
	return cad.CompareAndDelete(ctx, key, expected)
}

// PutIfAllAbsent forwards to the wrapped backend's optional fenced create, and
// reports storage.ErrFencedCreateUnsupported when it has none. It never
// degrades to checking the fences and then writing.
func (g guardedStorageBackend) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	fc, ok := g.Backend.(storage.FencedCreator)
	if !ok {
		return false, storage.ErrFencedCreateUnsupported
	}
	return fc.PutIfAllAbsent(ctx, key, value, fences...)
}

// CompareAndSwap gives a barrier over an xkms backend its guarded swap.
//
// go-qrdb's StorageBarrier.CompareAndSwap compares the DECRYPTED value with the
// caller's expectation, then hands its base the ciphertext it read as the
// guard -- through go-qrdb's guardedSwapBackend, whose shape is
// CompareAndSwap(...) (bool, error). xkms's own optional capability,
// storage.CompareAndSwapper, returns (swapped, current, err). This method
// adapts the one to the other, dropping current: the barrier only needs to
// know whether the swap landed, and a caller that lost reads again.
//
// Before this adaptation the two shapes never met, and a barrier over an xkms
// backend -- xkmsd's system barrier among them -- answered every swap with
// ErrGuardedSwapUnsupported. A read-modify-write on the barrier (the OIDC
// credential service persists rotating refresh tokens this way) needs it.
// A backend without the capability still reports
// storage.ErrCompareAndSwapUnsupported: the guard never degrades to a read
// followed by an unguarded write.
func (g guardedStorageBackend) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	cas, ok := g.Backend.(storage.CompareAndSwapper)
	if !ok {
		return false, storage.ErrCompareAndSwapUnsupported
	}
	swapped, _, err := cas.CompareAndSwap(ctx, key, expected, next)
	return swapped, err
}

// Barrier is a type alias for qrdbsdk.StorageBarrier. An xkms storage.Backend
// reaches it through guardedStorageBackend, which supplies the one method
// go-qrdb's StorageBackend requires that xkms models as a capability.
type Barrier = qrdbsdk.StorageBarrier

// TenantBarrier is a type alias for qrdbsdk.TenantBarrier.
type TenantBarrier = qrdbsdk.TenantBarrier

// BarrierRegistry is a type alias for qrdbsdk.BarrierRegistry, which manages
// the system barrier and the per-tenant barriers. A running xkmsd has exactly
// one: the embedded qrdb node's own (node.BarrierRegistry()).
type BarrierRegistry = qrdbsdk.BarrierRegistry

// BarrierRegistryOption configures a BarrierRegistry at construction time
// (and via Attach).
type BarrierRegistryOption = qrdbsdk.BarrierRegistryOption

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
	return qrdbsdk.NewStorageBarrier(logger, guardStorage(base), qrdbConfig, strategies...)
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
	return qrdbsdk.NewTenantBarrier(tenantID, logger, guardStorage(base), qrdbConfig, strategies...)
}

// NewBarrierRegistry creates a go-qrdb BarrierRegistry over the given system
// barrier, logging through the system barrier's logger. A nil system barrier
// is refused with ErrNilSystemBarrier.
func NewBarrierRegistry(system *Barrier, opts ...BarrierRegistryOption) (*BarrierRegistry, error) {
	if system == nil {
		return nil, ErrNilSystemBarrier
	}
	return qrdbsdk.NewBarrierRegistry(system.Logger(), system, opts...)
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
	allOpts := append([]TenantServiceOption{qrdbsdk.WithTenantBarrierKeyProvider(qrdbsdk.NewBarrierKeyProvider(hwRegistry))}, opts...)
	// Wrap the store so a missing tenant record surfaces go-qrdb's
	// ErrSecretNotFound rather than xkms's storage.ErrNotFound.
	return qrdbsdk.NewServiceTenantService(tenantMetadataStore{store}, registry, logger, allOpts...)
}

// NewHardwareStrategyRegistry builds a StrategyRegistry seeded with go-qrdb's
// built-in software strategies (passphrase, none) and the hardware-backed
// strategies supplied by the caller. This is the composition seam that lets a
// per-tenant barrier be sealed by a TPM, PKCS#11 token, or cloud KMS: the
// returned registry is injected into go-qrdb's TenantService through its
// barrier key seam (WithTenantBarrierKeyProvider over NewBarrierKeyProvider)
// so TenantBarrierInitWithStrategy("tpm2"/"pkcs11"/"awskms"/…) resolves the
// matching xkms strategy by ID.
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
