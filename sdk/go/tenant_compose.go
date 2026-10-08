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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// Hardware-crypto-enhanced multi-tenant composition surface.
//
// go-qrdb owns the per-tenant barrier framework (isolation modes, entitlements,
// system-managed auto-unseal, quotas, volume pools); go-xkms owns the hardware
// and cloud seal strategies (TPM2/PKCS#11/AWS-KMS/GCP-KMS/Azure-KV/Vault). This
// file re-exports the composition seam so a downstream service (go-quicbaas)
// builds hardware-backed per-tenant encryption from the go-xkms SDK alone,
// rather than re-wiring the strategy-registry glue against two SDKs by hand.

// --- Strategy registry composition (the hardware glue) ---

// StrategyRegistry resolves seal strategies by name for per-tenant barrier
// initialization (TenantBarrierInitWithStrategy).
type StrategyRegistry = seal.StrategyRegistry

// NewHardwareStrategyRegistry builds a StrategyRegistry seeded with go-qrdb's
// built-in software strategies plus the hardware-backed strategies supplied by
// the caller. Inject it into go-qrdb's TenantService (WithTenantStrategyRegistry)
// or embedded node (WithStrategyRegistry) so a per-tenant barrier can be sealed
// by a TPM, PKCS#11 token, or cloud KMS.
var NewHardwareStrategyRegistry = seal.NewHardwareStrategyRegistry

// --- Barrier registry ---

// BarrierRegistry manages the system barrier and per-tenant barriers.
type BarrierRegistry = seal.BarrierRegistry

// BarrierRegistryOption configures a BarrierRegistry.
type BarrierRegistryOption = seal.BarrierRegistryOption

// NewBarrierRegistry creates a BarrierRegistry over the given system barrier.
var NewBarrierRegistry = seal.NewBarrierRegistry

// --- TenantService composition ---

// TenantService is go-qrdb's canonical tenant lifecycle servicer composed with
// xkms hardware seal strategies.
type TenantService = seal.TenantService

// TenantServiceOption configures the composed TenantService.
type TenantServiceOption = seal.TenantServiceOption

// NewHardwareTenantService composes go-qrdb's TenantService over a barrier
// registry with the given xkms hardware seal strategies injected. It is the
// one-call seam for hardware-backed per-tenant encryption.
var NewHardwareTenantService = seal.NewHardwareTenantService

// WithTenantDefaultEntitlements injects operator default entitlements applied to
// tenants whose own entitlements are nil.
var WithTenantDefaultEntitlements = qrdbsdk.WithTenantDefaultEntitlements

// WithTenantDefaultQuotas injects operator default quotas applied to tenants
// whose own quotas are nil.
var WithTenantDefaultQuotas = qrdbsdk.WithTenantDefaultQuotas

// WithTenantStrategyRegistry injects a StrategyRegistry directly (when not using
// NewHardwareTenantService, which wires one for you).
var WithTenantStrategyRegistry = qrdbsdk.WithTenantStrategyRegistry

// --- Tenant isolation + entitlement types ---

// TenantIsolationType identifies a tenant's isolation mode.
type TenantIsolationType = qrdbsdk.TenantIsolationType

const (
	// TenantIsolationPrefix isolates with logical key prefixing (no barrier).
	TenantIsolationPrefix = qrdbsdk.TenantIsolationPrefix
	// TenantIsolationBarrier routes a tenant through its own cryptographic barrier.
	TenantIsolationBarrier = qrdbsdk.TenantIsolationBarrier
	// TenantIsolationVolume gives a tenant a dedicated filesystem DataRoot.
	TenantIsolationVolume = qrdbsdk.TenantIsolationVolume
	// TenantIsolationRaft gives a tenant a dedicated Raft group per database.
	TenantIsolationRaft = qrdbsdk.TenantIsolationRaft
)

// WithBarrierAutoUnseal opts a dedicated-isolation tenant into system-managed
// auto-unseal (entitlement-gated).
var WithBarrierAutoUnseal = qrdbsdk.WithBarrierAutoUnseal

// Entitlements describes which isolation tiers and dedicated-storage features a
// tenant's plan permits.
type Entitlements = qrdbsdk.Entitlements

// DefaultEntitlements returns the conservative built-in default entitlements.
var DefaultEntitlements = qrdbsdk.DefaultEntitlements

// --- System-managed auto-unseal strategy ---

// SystemBarrierStrategy seals a tenant root key under the system barrier,
// enabling credential-free system-managed auto-unseal.
type SystemBarrierStrategy = qrdbsdk.SystemBarrierStrategy

// StrategySystemBarrier identifies the system-managed auto-unseal strategy.
const StrategySystemBarrier = qrdbsdk.StrategySystemBarrier

// NewSystemBarrierStrategy constructs a SystemBarrierStrategy over a system barrier.
var NewSystemBarrierStrategy = qrdbsdk.NewSystemBarrierStrategy
