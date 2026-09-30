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

import type { Base64 } from './common.js';

/** Mirrors pkg/api/rest/types.go SealRequest. */
export interface SealRequest {
  backend: string;
  key_id?: string;
  data: Base64;
  aad?: Base64;
  /** The sealed object's authorization value (TPM2-specific). */
  password?: string;
  /** Names the TPM policy a TPM2 sealed object is bound to (TPM2 backends only). */
  tpm_policy?: string;
}

/** Mirrors pkg/api/rest/types.go SealResponse. */
export interface SealResponse {
  backend: string;
  ciphertext: Base64;
  nonce?: Base64;
  tag?: Base64;
  metadata?: Record<string, Base64>;
  key_id?: string;
  /** The sealing key version; absent for a TPM2 sealed object. Pass it back on unseal. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go UnsealRequest. */
export interface UnsealRequest {
  backend: string;
  key_id?: string;
  ciphertext: Base64;
  nonce?: Base64;
  tag?: Base64;
  aad?: Base64;
  metadata?: Record<string, Base64>;
  /** The sealing key version the seal reported; omitted tries every enabled version. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go UnsealResponse. */
export interface UnsealResponse {
  plaintext: Base64;
}

/** Mirrors pkg/api/rest/types.go CanSealResponse (GET /api/v1/seal/capability). */
export interface CanSealResponse {
  can_seal: boolean;
  backend?: string;
}
