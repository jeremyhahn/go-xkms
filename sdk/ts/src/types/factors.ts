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
 * User N-factor DTOs. Mirrors pkg/api/rest/handlers_authfactor.go, which
 * proxies go-qrdb's transport.AuthFactor* types verbatim — the wire shape is
 * qrdb's, so field names must track go-qrdb/sdk/go/transport/auth_factor_types.go.
 *
 * Go `[]byte` fields marshal to base64 strings, so `credential`,
 * `spki_credential`, and `lookup_key` are base64 here, not hex.
 */

import type { RFC3339 } from './common.js';

/** The factor kinds qrdb recognises. */
export type AuthFactorType = 'mtls' | 'fido2' | 'piv';

export interface AuthFactorRecord {
  id: string;
  user_id: number;
  type: AuthFactorType | string;
  label?: string;
  /** base64 — canonical lookup-key bytes */
  credential: string;
  /** base64 — SHA-256 of the certificate SPKI (mtls/piv only) */
  spki_credential?: string;
  metadata?: Record<string, string>;
  registered_at: RFC3339;
  last_used_at?: RFC3339;
  revoked_at?: RFC3339;
  /** provenance: "self", "admin", "ceremony" */
  created_by?: string;
}

export interface AuthFactorAddRequest {
  user_id: number;
  type: AuthFactorType | string;
  label?: string;
  /** base64 */
  credential: string;
  /** base64 */
  spki_credential?: string;
  metadata?: Record<string, string>;
  created_by?: string;
}

export interface AuthFactorAddResponse {
  factor: AuthFactorRecord;
}

export interface AuthFactorListResponse {
  factors: AuthFactorRecord[];
  total: number;
}

export interface AuthFactorGetResponse {
  factor: AuthFactorRecord;
}

export interface AuthFactorRemoveResponse {
  /** "revoked" on success */
  status: string;
}

export interface AuthFactorRotateRequest {
  new_factor: AuthFactorAddRequest;
}

export interface AuthFactorRotateResponse {
  new_factor: AuthFactorRecord;
}

export interface AuthFactorRelabelRequest {
  label: string;
}

export interface AuthFactorRelabelResponse {
  factor: AuthFactorRecord;
}

export interface AuthFactorLoginRequest {
  type: AuthFactorType | string;
  /** base64 */
  lookup_key: string;
}

export interface AuthFactorLoginResponse {
  user_id: number;
  username: string;
  email?: string;
  tenant_id?: string;
  roles?: string[];
  active: boolean;
}
