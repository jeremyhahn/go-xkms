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
	"github.com/jeremyhahn/go-xkms/pkg/audit"
)

// BarrierConfig configures a Barrier instance.
type BarrierConfig struct {
	// PreferenceOrder specifies the order in which sealing strategies are
	// evaluated. The first available strategy is used to seal the root key.
	// If nil or empty, DefaultPreferenceOrder is used.
	PreferenceOrder []StrategyID

	// RootKeyPath is the storage key under which the sealed root key blob
	// is persisted. Must be non-empty.
	RootKeyPath string

	// AuditLogger receives audit events for seal/unseal operations.
	// If nil, audit logging is disabled.
	AuditLogger audit.Logger

	// Shamir configures optional Shamir secret sharing for barrier operations.
	// When set, InitializeShamir and UnsealWithShare/UnsealWithShares methods
	// become available.
	Shamir *ShamirConfig
}

// SealerConfig configures a PlatformSealer instance.
type SealerConfig struct {
	// PreferenceOrder specifies the order in which sealing strategies are
	// evaluated. The first available strategy is used for auto-selection.
	// If nil or empty, DefaultPreferenceOrder is used.
	PreferenceOrder []StrategyID

	// AuditLogger receives audit events for seal/unseal operations.
	// If nil, audit logging is disabled.
	AuditLogger audit.Logger
}

// TenantBarrierConfig configures per-tenant barrier behavior.
type TenantBarrierConfig struct {
	// Enabled enables per-tenant barriers. When false (default),
	// all operations use the system barrier for backward compatibility.
	Enabled bool `json:"enabled"`

	// TenantIDs lists the tenant IDs to pre-register on startup.
	TenantIDs []string `json:"tenant_ids,omitempty"`
}
