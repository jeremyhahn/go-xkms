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

// Package auth_factors wraps xkms-specific authentication services
// (pkg/webauthn, pkg/pivcert) into qrdb's transport-level FactorVerifier
// interface so the qrdb embedded transport's FactorClient.Verify routes
// through xkms's hardware-aware verification logic.
//
// The adapters connect two layers:
//
//   - qrdb's pkg/auth.AuthFactor record model (User <-> Factor mapping)
//   - xkms's pkg/webauthn.Service and pkg/pivcert verification
//
// Phase 4 of the unified auth-stack refactor wires these adapters into
// xkms's SDK so callers like quicbaas can drive a single end-to-end flow:
// register a factor (qrdb persists), verify a challenge (xkms validates),
// resolve identity (qrdb LoginResolver yields a Principal).
package auth_factors
