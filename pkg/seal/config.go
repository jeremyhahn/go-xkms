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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// BarrierConfig configures a Barrier instance.
type BarrierConfig struct {
	// PreferenceOrder is the explicit, ordered list of candidate sealing
	// strategies; the first available one seals the root key. Required — there
	// is no implicit default. An empty list is an error (ErrNoStrategySpecified).
	PreferenceOrder []StrategyID

	// RootKeyPath is the storage key under which the sealed root key blob
	// is persisted. Must be non-empty.
	RootKeyPath string

	// AuditLogger receives audit events for seal/unseal operations.
	// If nil, audit logging is disabled.
	AuditLogger qrdbsdk.NodeAuditLogger

	// Shamir configures optional Shamir secret sharing for barrier operations.
	// When set, InitializeShamir and UnsealWithShare/UnsealWithShares methods
	// become available.
	Shamir *ShamirConfig
}

// SealerConfig configures a PlatformSealer instance.
type SealerConfig struct {
	// PreferenceOrder is the explicit, ordered list of candidate sealing
	// strategies; the first available one is used. Required — there is no
	// implicit default. An empty list is an error (ErrNoStrategySpecified).
	PreferenceOrder []StrategyID

	// AuditLogger receives audit events for seal/unseal operations.
	// If nil, audit logging is disabled.
	AuditLogger qrdbsdk.NodeAuditLogger
}

// TenantBarrierConfig configures per-tenant barrier behavior.
type TenantBarrierConfig struct {
	// Enabled enables per-tenant barriers. When false (default),
	// all operations use the system barrier for backward compatibility.
	Enabled bool `json:"enabled"`

	// TenantIDs lists the tenant IDs to pre-register on startup.
	TenantIDs []string `json:"tenant_ids,omitempty"`
}
