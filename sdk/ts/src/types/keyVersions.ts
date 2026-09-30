// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
 * Key-version DTOs, served under /api/v1/keys/{id}/versions and
 * /api/v1/keys/rotate-all. Source: pkg/api/transport/types_keyversion.go
 * (the REST handlers encode the transport types directly).
 */

/** A key version's lifecycle state. */
export type KeyVersionState = 'enabled' | 'disabled' | 'retired';

/** Mirrors pkg/api/transport KeyVersionInfo. */
export interface KeyVersionInfo {
  version: number;
  state: KeyVersionState;
  /** Whether this is the version sign and encrypt use. */
  current?: boolean;
  /** RFC 3339 in UTC; absent for version 1 of a key rotated before it was recorded. */
  created_at?: string;
  created_by?: string;
  /** The version's public key, for an asymmetric version that is not retired. */
  public_key_pem?: string;
}

/** Mirrors pkg/api/transport ListKeyVersionsResponse. */
export interface ListKeyVersionsResponse {
  key_id: string;
  backend: string;
  current_version: number;
  versions: KeyVersionInfo[];
}

/** Mirrors pkg/api/transport KeyVersionStateResponse. */
export interface KeyVersionStateResponse {
  key_id: string;
  version: number;
  state: KeyVersionState;
  /** False when the version already had the state. */
  changed: boolean;
}

/** Mirrors pkg/api/transport AllKeyVersionsResponse. */
export interface AllKeyVersionsResponse {
  key_id: string;
  state: KeyVersionState;
  /** The versions whose state changed, ascending. */
  versions: number[];
  count: number;
}

/** Mirrors pkg/api/transport KeyRotationResult. */
export interface KeyRotationResult {
  backend: string;
  key_id: string;
  /** The new current version; absent when the rotation failed. */
  key_version?: number;
  /** Why the key was not rotated; absent on success. */
  error?: string;
}

/** Mirrors pkg/api/transport RotateScopeKeysResponse. */
export interface RotateScopeKeysResponse {
  tenant_id: string;
  results: KeyRotationResult[];
  rotated: number;
  failed: number;
}
