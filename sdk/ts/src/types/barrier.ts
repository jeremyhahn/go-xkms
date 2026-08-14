// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * Barrier DTOs. Sources:
 *  - pkg/api/rest/handlers_barrier_pin.go (initialize / unseal / status)
 *  - pkg/api/rest/handlers_barrier_shamir.go (Shamir / rekey / recovery)
 *  - go-quicraft/pkg/seal (ShamirInitResult, QuorumProgress) and
 *    go-qrdb/pkg/seal (ShamirInitParams, RecoveryKeyResult, RootToken),
 *    which the handlers serialize verbatim.
 *  - pkg/api/transport/types.go BarrierEnableEncryption{Request,Response}.
 */

import type { Base64, RFC3339 } from './common.js';

/**
 * Mirrors pkg/api/rest/handlers_barrier_pin.go BarrierInitializeRequest.
 * `password_b64` is a base64-encoded passphrase consumed via a secure buffer
 * server-side; prefer it over `secret` for new integrations.
 */
export interface BarrierInitializeRequest {
  secret?: string;
  password_b64?: Base64;
}

/** Mirrors pkg/api/rest/handlers_barrier_pin.go BarrierUnsealRequest. */
export interface BarrierUnsealRequest {
  secret?: string;
  password_b64?: Base64;
}

/** Mirrors pkg/api/rest/handlers_barrier_pin.go BarrierStatusResponse. */
export interface BarrierStatusResponse {
  sealed: boolean;
  strategy: string;
  hardware_backed: boolean;
  initialized_at: RFC3339;
}

/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierInitializeShamirRequest. */
export interface BarrierInitializeShamirRequest {
  secret?: string;
}

/** Mirrors go-quicraft/pkg/seal ShamirInitResult (Shamir initialize response). */
export interface ShamirInitResult {
  shares: string[];
  threshold: number;
  total_shares: number;
}

/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierUnsealShareRequest. */
export interface BarrierUnsealShareRequest {
  share: string;
}

/** Mirrors go-quicraft/pkg/seal QuorumProgress (unseal-share response). */
export interface QuorumProgress {
  required: number;
  submitted: number;
  complete: boolean;
}

/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierUnsealSharesRequest. */
export interface BarrierUnsealSharesRequest {
  shares: string[];
}

/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierRekeyRequest. */
export interface BarrierRekeyRequest {
  threshold: number;
  total: number;
}

/** Mirrors go-qrdb/pkg/seal ShamirInitParams (rekey response). */
export interface ShamirInitParams {
  threshold: number;
  total_shares: number;
  share_count?: number;
}

/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierGenerateRecoveryKeysRequest. */
export interface BarrierGenerateRecoveryKeysRequest {
  threshold: number;
  total: number;
}

/** Mirrors go-qrdb/pkg/seal RecoveryKeyResult (recovery/generate response). */
export interface RecoveryKeyResult {
  share_count: number;
  threshold: number;
  total_shares: number;
}

/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierRecoverWithKeysRequest. */
export interface BarrierRecoverWithKeysRequest {
  keys: string[];
}

/** Mirrors pkg/api/rest/handlers_barrier_shamir.go BarrierGenerateRootTokenRequest. */
export interface BarrierGenerateRootTokenRequest {
  shares: string[];
}

/** Mirrors go-qrdb/pkg/seal RootToken (recovery/root-token response). */
export interface RootToken {
  token: string;
  created_at: RFC3339;
}

/** Mirrors pkg/api/transport/types.go BarrierEnableEncryptionRequest. */
export interface BarrierEnableEncryptionRequest {
  tenant_id?: string;
  strategy: string;
  mechanism?: string;
  availability?: string;
  passphrase?: string;
  shamir_threshold?: number;
  shamir_total?: number;
}

/** Mirrors pkg/api/transport/types.go BarrierEnableEncryptionResponse. */
export interface BarrierEnableEncryptionResponse {
  status: string;
  scope: string;
}
