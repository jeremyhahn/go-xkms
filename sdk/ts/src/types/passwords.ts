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

/** Password store DTOs. Mirrors pkg/api/rest/password_handlers.go. */

import type { Base64, RFC3339 } from './common.js';

export interface PasswordAddRequest {
  name: string;
  title?: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
  folder_path?: string;
  shared?: boolean;
}

export interface PasswordAddResponse {
  id: string;
  name: string;
  message: string;
}

export interface PasswordInfo {
  id: string;
  name: string;
  title?: string;
  username?: string;
  url?: string;
  folder_path?: string;
  owner_id?: string;
  shared?: boolean;
  created_at: string;
  updated_at: string;
}

export interface PasswordListResponse {
  passwords: PasswordInfo[];
  total: number;
}

export interface PasswordDetailResponse {
  id: string;
  name: string;
  title?: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
  folder_path?: string;
  owner_id?: string;
  shared?: boolean;
  read_only?: boolean;
  created_at: string;
  updated_at: string;
}

/** All members optional: only supplied fields are updated (Go *string semantics). */
export interface PasswordUpdateRequest {
  name?: string;
  title?: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  folder_path?: string;
}

export interface PasswordUpdateResponse {
  id: string;
  name: string;
  message: string;
}

export interface PasswordDeleteResponse {
  message: string;
}

/**
 * A factor of the caller's personal password vault. Mirrors
 * pkg/api/transport PasswordVaultCredential.
 *
 * - `passphrase`: set `passphrase`.
 * - `passkey`: a FIDO2 credential with the hmac-secret / WebAuthn PRF
 *   extension. Set `credential_id` and `secret` (the 32-byte PRF output the
 *   authenticator evaluated over the factor's 32-byte `prf_salt`); enrolling
 *   a passkey also sets `prf_salt` and `rp_id` (the server's
 *   `passkey_rp_id`). See `vaultPasskey.ts`.
 * - `piv` / `certificate` / `tpm` (key factors): enrolled by xkey or xkmsctl
 *   with the key's `public_key` or `certificate`; unlocked with
 *   `key_fingerprint` and the `secret` the private key recovered -- in a
 *   browser only through the xkey extension (`vaultBridge.ts`).
 */
export interface PasswordVaultCredential {
  factor: PasswordVaultFactorType;
  passphrase?: string;
  credential_id?: Base64;
  prf_salt?: Base64;
  secret?: Base64;
  label?: string;
  rp_id?: string;
  public_key?: Base64;
  certificate?: Base64;
  key_fingerprint?: string;
  key_ref?: PasswordVaultKeyRef;
}

/** The vault factor types a client can enroll or unlock with. */
export type PasswordVaultFactorType = 'passphrase' | 'passkey' | PasswordVaultKeyFactorType;

/** Key factors: a secret only the factor's private key recovers. */
export type PasswordVaultKeyFactorType = 'piv' | 'certificate' | 'tpm';

/** Where a key factor's private key lives on the client (a selection hint). */
export interface PasswordVaultKeyRef {
  backend?: string;
  key_id?: string;
  tpm_policy?: string;
}

/** POST /api/v1/password-vault/unlock opens the caller's session with one of their vault factors. */
export type PasswordStoreUnlockRequest = PasswordVaultCredential;

/**
 * The factor types a vault status lists: the enrollable ones plus the
 * recovery code every vault holds, which is never removed or unlocked with.
 */
export type PasswordVaultFactorInfoType = PasswordVaultFactorType | 'recovery';

/** One enrolled vault factor (never key material). */
export interface PasswordVaultFactor {
  id: string;
  factor: PasswordVaultFactorInfoType;
  label?: string;
  created_at: RFC3339;
  /** Passkey factors only: the credential to request from the authenticator. */
  credential_id?: Base64;
  /** Passkey factors only: the salt to evaluate the PRF over when unlocking. */
  prf_salt?: Base64;
  /** Passkey factors only: the relying party ID the passkey was created for. */
  rp_id?: string;
  /** Key factors only: what the private key's holder recovers the secret from. */
  key_fingerprint?: string;
  key_algorithm?: string;
  key_challenge?: Base64;
  key_check?: Base64;
  key_ref?: PasswordVaultKeyRef;
  certificate_subject?: string;
}

/** GET /api/v1/password-vault */
export interface PasswordVaultStatusResponse {
  initialized: boolean;
  unlocked: boolean;
  factors: PasswordVaultFactor[];
  /**
   * The relying party ID a new passkey must be created for -- the console's
   * domain. Absent when the deployment offers no passkeys.
   */
  passkey_rp_id?: string;
}

/** POST /api/v1/password-vault/factors */
export type PasswordVaultEnrollRequest = PasswordVaultCredential;

/**
 * The enrolled (or rotated, or recovered) factor. `recovery_code` is present
 * only on the first enrollment and on a recovery, and is shown exactly once.
 */
export interface PasswordVaultEnrollResponse {
  factor: PasswordVaultFactor;
  recovery_code?: string;
}

/** PUT /api/v1/password-vault/factors/{id}: a new secret of the same factor type. */
export type PasswordVaultRotateRequest = PasswordVaultCredential;

/** POST /api/v1/password-vault/recover */
export interface PasswordVaultRecoverRequest extends PasswordVaultCredential {
  recovery_code: string;
}

export interface PasswordStoreAccessModeRequest {
  mode: string;
}

export interface PasswordStoreAccessModeResponse {
  mode: string;
  message: string;
}

export interface PasswordStoreStatusResponse {
  available: boolean;
  is_locked: boolean;
  barrier_sealed: boolean;
  password_count: number;
  message: string;
}

export interface PasswordGenerateRequest {
  length?: number;
  charset?: string;
}

export interface PasswordGenerateResponse {
  password: string;
  length: number;
}
