/**
 * Copyright (C) 2024 Trusted CA Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0, or alternatively, under the terms of the
 * GNU Affero General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any
 * later version. A commercial license is available from the authors.
 *
 * TypeScript types for the barrier administration API, mirroring the Go
 * backend DTOs defined in pkg/admin/barrier_service.go.
 */

/** BarrierMode indicates whether the barrier is embedded or managed remotely. */
export type BarrierMode = 'embedded' | 'remote';

/** BarrierStatusResponse is the response body for GET /admin/barrier/status. */
export interface BarrierStatusResponse {
  mode: BarrierMode;
  sealed: boolean;
  strategy: string;
  hardware_backed: boolean;
  initialized_at: string;
  shares_provided: number;
  shares_required: number;
  shares_total: number;
}

/** BarrierInitializeRequest is the request body for POST /admin/barrier/initialize. */
export interface BarrierInitializeRequest {
  secret: string;
}

/** BarrierUnsealRequest is the request body for POST /admin/barrier/unseal. */
export interface BarrierUnsealRequest {
  secret: string;
}

/** BarrierInitializeShamirRequest is the request body for POST /admin/barrier/shamir/initialize. */
export interface BarrierInitializeShamirRequest {
  secret: string;
  threshold: number;
  total: number;
}

/**
 * BarrierInitializeShamirResponse is the response body for POST /admin/barrier/shamir/initialize.
 *
 * Share-free contract: the response carries Shamir metadata only. Shares are
 * sealed to enrolled Security Officers via the ceremony distributor and are
 * never returned over the wire.
 */
export interface BarrierInitializeShamirResponse {
  threshold: number;
  total_shares: number;
  share_count: number;
}

/** BarrierUnsealShareRequest is the request body for POST /admin/barrier/shamir/unseal-share. */
export interface BarrierUnsealShareRequest {
  share: string;
}

/** BarrierUnsealShareResponse is the response body for POST /admin/barrier/shamir/unseal-share. */
export interface BarrierUnsealShareResponse {
  required: number;
  submitted: number;
  complete: boolean;
}

/** BarrierRekeyRequest is the request body for POST /admin/barrier/rekey. */
export interface BarrierRekeyRequest {
  threshold: number;
  total: number;
}

/**
 * BarrierRekeyResponse is the response body for POST /admin/barrier/rekey.
 *
 * Share-free contract: the response carries Shamir metadata only. New shares
 * are sealed to enrolled Security Officers and are never returned over the wire.
 */
export interface BarrierRekeyResponse {
  threshold: number;
  total_shares: number;
  share_count: number;
}

/** BarrierGenerateRecoveryKeysRequest is the request body for POST /admin/barrier/recovery/generate. */
export interface BarrierGenerateRecoveryKeysRequest {
  threshold: number;
  total: number;
}

/**
 * BarrierRecoveryKeysResponse is the response body for POST /admin/barrier/recovery/generate.
 *
 * Share-free contract: the response carries recovery-key metadata only.
 * Recovery shares are sealed to enrolled recovery officers and are never
 * returned over the wire.
 */
export interface BarrierRecoveryKeysResponse {
  threshold: number;
  total: number;
  share_count: number;
}

/** BarrierRecoverWithKeysRequest is the request body for POST /admin/barrier/recovery/recover. */
export interface BarrierRecoverWithKeysRequest {
  keys: string[];
}

/** BarrierGenerateRootTokenRequest is the request body for POST /admin/barrier/root-token. */
export interface BarrierGenerateRootTokenRequest {
  shares: string[];
}

/** BarrierRootTokenResponse is the response body for POST /admin/barrier/root-token. */
export interface BarrierRootTokenResponse {
  token: string;
}
