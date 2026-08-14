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

/** FROST threshold-signature DTOs. Mirrors pkg/api/rest/handlers_frost.go. */

import type { PageResponse, RFC3339 } from './common.js';

export interface FrostGenerateKeyRequest {
  key_id?: string;
  algorithm?: string;
  threshold: number;
  total: number;
  participants?: string[];
  participant_id?: number;
  dealer_mode?: boolean;
}

export interface FrostKeyPackage {
  key_id: string;
  algorithm: string;
  threshold: number;
  total: number;
  participant_id: number;
  participant_name?: string;
  /** hex-encoded */
  secret_share: string;
  /** hex-encoded */
  group_public_key: string;
  /** participant id -> hex-encoded verification share */
  verification_shares: Record<string, string>;
}

export interface FrostGenerateKeyResponse {
  key_id: string;
  algorithm: string;
  threshold: number;
  total: number;
  /** hex-encoded */
  group_public_key: string;
  participant_id?: number;
  /** dealer mode only */
  packages?: FrostKeyPackage[];
  created_at: RFC3339;
}

export interface FrostKeyInfo {
  key_id: string;
  algorithm: string;
  threshold: number;
  total: number;
  participant_id: number;
  /** hex-encoded */
  group_public_key: string;
  participants?: string[];
  created_at: RFC3339;
}

export interface FrostImportKeyRequest {
  package: FrostKeyPackage;
}

export interface FrostImportKeyResponse {
  success: boolean;
  message: string;
  key_id: string;
  participant_id: number;
  /** hex-encoded */
  group_public_key: string;
}

export interface FrostListKeysResponse {
  keys: FrostKeyInfo[];
  total: number;
  pagination: PageResponse;
}

export interface FrostDeleteKeyResponse {
  success: boolean;
  message: string;
}

export interface FrostGenerateNoncesResponse {
  participant_id: number;
  session_id: string;
  /** hex-encoded (secret) */
  hiding_nonce: string;
  /** hex-encoded (secret) */
  binding_nonce: string;
  /** hex-encoded (public) */
  hiding_commitment: string;
  /** hex-encoded (public) */
  binding_commitment: string;
}

export interface FrostCommitment {
  participant_id: number;
  /** hex-encoded */
  hiding_commitment: string;
  /** hex-encoded */
  binding_commitment: string;
}

export interface FrostSignRoundRequest {
  key_id: string;
  /** hex-encoded */
  message: string;
  session_id: string;
  /** hex-encoded */
  hiding_nonce: string;
  /** hex-encoded */
  binding_nonce: string;
  /** hex-encoded */
  hiding_commitment: string;
  /** hex-encoded */
  binding_commitment: string;
  commitments: FrostCommitment[];
}

export interface FrostSignRoundResponse {
  participant_id: number;
  session_id: string;
  /** hex-encoded */
  signature_share: string;
}

export interface FrostSignatureShare {
  participant_id: number;
  session_id: string;
  /** hex-encoded */
  share: string;
}

export interface FrostAggregateRequest {
  key_id: string;
  /** hex-encoded */
  message: string;
  commitments: FrostCommitment[];
  shares: FrostSignatureShare[];
  verify: boolean;
}

export interface FrostAggregateResponse {
  /** hex-encoded */
  signature: string;
  verified: boolean;
}

export interface FrostVerifyRequest {
  key_id: string;
  /** hex-encoded */
  message: string;
  /** hex-encoded */
  signature: string;
}

export interface FrostVerifyResponse {
  valid: boolean;
  message: string;
}
