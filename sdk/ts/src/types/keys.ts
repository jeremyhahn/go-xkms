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
 * Key and crypto-operation DTOs. Sources:
 *  - pkg/api/rest/types.go (the REST-local shapes the handlers decode/encode)
 *  - pkg/api/transport/types.go (the hardware-capability keyops handlers in
 *    pkg/api/rest/handlers_keyops.go decode transport.* directly)
 */

import type { Base64, PageResponse } from './common.js';

/** Mirrors pkg/api/rest/types.go GenerateKeyRequest. */
export interface GenerateKeyRequest {
  key_id: string;
  backend?: string;
  key_type: string;
  key_size?: number;
  curve?: string;
  hash?: string;
  algorithm?: string;
  exportable?: boolean;
  /** Names the TPM policy a TPM2 key is bound to; empty is the built-in "platform" policy. */
  tpm_policy?: string;
}

/** Mirrors pkg/api/rest/types.go GenerateKeyResponse. */
export interface GenerateKeyResponse {
  key_id: string;
  key_type: string;
  public_key_pem?: string;
  message?: string;
}

/** Mirrors pkg/api/rest/types.go KeyInfo. */
export interface KeyInfo {
  key_id: string;
  key_type: string;
  algorithm: string;
  backend: string;
  public_key_pem?: string;
  /** The key's current version, the one sign and encrypt use. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go ListKeysResponse. */
export interface ListKeysResponse {
  keys: KeyInfo[];
  pagination: PageResponse;
}

/** Mirrors pkg/api/rest/types.go GetKeyResponse (KeyInfo embedded flat). */
export type GetKeyResponse = KeyInfo;

/** Mirrors pkg/api/rest/types.go DeleteKeyResponse. */
export interface DeleteKeyResponse {
  success: boolean;
  message?: string;
}

/** Mirrors pkg/api/rest/types.go SignRequest. */
export interface SignRequest {
  backend?: string;
  data: Base64;
  hash?: string;
  padding?: string;
  salt_length?: number;
  data_is_digest?: boolean;
}

/** Mirrors pkg/api/rest/types.go SignResponse. */
export interface SignResponse {
  signature: Base64;
  algorithm?: string;
  /** The key version that produced the signature: always the current one. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go VerifyRequest. */
export interface VerifyRequest {
  backend?: string;
  data: Base64;
  signature: Base64;
  hash?: string;
  padding?: string;
  salt_length?: number;
  data_is_digest?: boolean;
  /** Verify with this enabled version; omitted tries every enabled version, newest first. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go VerifyResponse. */
export interface VerifyResponse {
  valid: boolean;
  message?: string;
  /** The key version the signature verified under; 0 or absent when it did not verify. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go RotateKeyResponse. */
export interface RotateKeyResponse {
  success: boolean;
  key_id: string;
  key_type: string;
  public_key_pem?: string;
  message?: string;
  /** The version the rotation created, now current. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go EncryptRequest. */
export interface EncryptRequest {
  backend?: string;
  plaintext: Base64;
  additional_data?: Base64;
  nonce?: Base64;
  mode?: string;
  iv?: Base64;
  tag_size?: number;
}

/** Mirrors pkg/api/rest/types.go EncryptResponse. */
export interface EncryptResponse {
  ciphertext: Base64;
  nonce: Base64;
  tag: Base64;
  iv?: Base64;
  gcm_nonce_mode?: string;
  /**
   * The key version that produced the ciphertext: always the current one.
   * Keep it: AES-CBC ciphertext needs it to decrypt once the key has more
   * than one enabled version.
   */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go DecryptRequest. */
export interface DecryptRequest {
  backend?: string;
  ciphertext: Base64;
  additional_data?: Base64;
  nonce?: Base64;
  tag?: Base64;
  mode?: string;
  iv?: Base64;
  tag_size?: number;
  gcm_nonce_mode?: string;
  /** RSA decryption padding: "" or "pkcs1v15" (default), or "oaep". */
  padding?: string;
  /** The OAEP digest. */
  hash?: string;
  /** The OAEP label. */
  label?: Base64;
  /**
   * Decrypt with this enabled version. Omitted tries every enabled version,
   * newest first, for AEAD and RSA-OAEP ciphertext, and requires exactly one
   * enabled version for AES-CBC and RSA PKCS#1 v1.5 ciphertext.
   */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go DecryptResponse. */
export interface DecryptResponse {
  plaintext: Base64;
  /** The key version that decrypted the ciphertext. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go EncryptAsymRequest. */
export interface EncryptAsymRequest {
  backend?: string;
  plaintext: Base64;
  hash?: string;
}

/** Mirrors pkg/api/rest/types.go EncryptAsymResponse. */
export interface EncryptAsymResponse {
  ciphertext: Base64;
  /** The key version whose public key encrypted: always the current one. */
  key_version?: number;
}

/** Mirrors pkg/api/rest/types.go GetImportParametersRequest. */
export interface GetImportParametersRequest {
  backend: string;
  key_id: string;
  key_type: string;
  algorithm: string;
  key_size?: number;
  curve?: string;
  hash?: string;
  aes_key_size?: number;
}

/** Mirrors pkg/api/rest/types.go GetImportParametersResponse. */
export interface GetImportParametersResponse {
  wrapping_public_key_pem: string;
  import_token?: Base64;
  algorithm: string;
  expires_at?: string;
}

/** Mirrors pkg/api/rest/types.go WrapKeyRequest. */
export interface WrapKeyRequest {
  backend: string;
  key_material: Base64;
  wrapping_public_key_pem: string;
  import_token?: Base64;
  algorithm: string;
}

/** Mirrors pkg/api/rest/types.go WrapKeyResponse. */
export interface WrapKeyResponse {
  wrapped_key: Base64;
  algorithm: string;
  import_token?: Base64;
}

/** Mirrors pkg/api/rest/types.go UnwrapKeyRequest. */
export interface UnwrapKeyRequest {
  backend: string;
  wrapped_key: Base64;
  wrapping_public_key_pem: string;
  import_token?: Base64;
  algorithm: string;
}

/** Mirrors pkg/api/rest/types.go UnwrapKeyResponse. */
export interface UnwrapKeyResponse {
  key_material: Base64;
}

/** Mirrors pkg/api/rest/types.go ImportKeyRequest. */
export interface ImportKeyRequest {
  backend: string;
  key_id: string;
  key_type: string;
  wrapped_key: Base64;
  import_token?: Base64;
  algorithm: string;
  key_size?: number;
  curve?: string;
  hash?: string;
  aes_key_size?: number;
}

/** Mirrors pkg/api/rest/types.go ImportKeyResponse. */
export interface ImportKeyResponse {
  success: boolean;
  key_id: string;
  message?: string;
  public_key_pem?: string;
}

/** Mirrors pkg/api/rest/types.go ExportKeyRequest. */
export interface ExportKeyRequest {
  backend?: string;
  algorithm: string;
}

/** Mirrors pkg/api/rest/types.go ExportKeyResponse. */
export interface ExportKeyResponse {
  key_id: string;
  wrapped_key: Base64;
  algorithm: string;
  import_token?: Base64;
}

/**
 * Mirrors pkg/api/rest/types.go CopyKeyRequest. It names the source key, the
 * destination, and the wrapping algorithm, and nothing about the key itself:
 * the copy takes its algorithm, size, curve, hash and partition from the
 * source key (XKMSService.CopyKey). key_type, key_size, curve, hash and
 * aes_key_size were removed rather than kept as fields the server has never
 * read (go-xkms#1223).
 */
export interface CopyKeyRequest {
  source_backend: string;
  source_key_id: string;
  dest_backend: string;
  dest_key_id: string;
  algorithm: string;
}

/** Mirrors pkg/api/rest/types.go CopyKeyResponse. */
export interface CopyKeyResponse {
  success: boolean;
  message: string;
}

/** Mirrors pkg/api/transport/types.go AttestKeyRequest (POST /api/v1/attest). */
export interface AttestKeyRequest {
  backend: string;
  key_id: string;
  nonce: Base64;
  tenant_id?: string;
}

/** Mirrors pkg/api/transport/types.go AttestKeyResponse. */
export interface AttestKeyResponse {
  format: string;
  certificate_chain: Base64[];
  attestation_data: Base64;
  signature: Base64;
  signature_algorithm?: string;
  nonce: Base64;
  backend: string;
}

/** Mirrors pkg/api/transport/types.go DeriveKeyECDHRequest. */
export interface DeriveKeyECDHRequest {
  key_id: string;
  backend: string;
  peer_public_key: Base64;
  kdf_algorithm?: string;
  kdf_hash?: string;
  kdf_salt?: Base64;
  kdf_info?: Base64;
  kdf_label?: Base64;
  key_length?: number;
  tenant_id?: string;
  /** Agree with this enabled version of the local key; omitted uses the current one. */
  key_version?: number;
}

/** Mirrors pkg/api/transport/types.go DeriveKeyECDHResponse. */
export interface DeriveKeyECDHResponse {
  derived_key: Base64;
  /** The version of the local key the agreement used. */
  key_version?: number;
}

/** Mirrors pkg/api/transport/types.go ExportKeyMaterialResponse. */
export interface ExportKeyMaterialResponse {
  key_material: Base64;
  key_type: string;
  key_size: number;
}

/** Mirrors pkg/api/transport/types.go WrapKeyByIDRequest. */
export interface WrapKeyByIDRequest {
  wrapping_key_id: string;
  wrapping_key_backend: string;
  target_key_id: string;
  target_key_backend: string;
  target_key_material?: Base64;
  algorithm: string;
  iv?: Base64;
  aad?: Base64;
  tag_bits?: number;
  oaep_label?: Base64;
  tenant_id?: string;
}

/** Mirrors pkg/api/transport/types.go WrapKeyByIDResponse. */
export interface WrapKeyByIDResponse {
  wrapped_key: Base64;
  algorithm: string;
  /** The wrapping key version that wrapped: always the current one. Pass it back on unwrap. */
  wrapping_key_version?: number;
}

/** Mirrors pkg/api/transport/types.go UnwrapKeyByIDRequest. */
export interface UnwrapKeyByIDRequest {
  wrapped_key: Base64;
  unwrapping_key_id: string;
  unwrapping_key_backend: string;
  algorithm: string;
  iv?: Base64;
  aad?: Base64;
  tag_bits?: number;
  oaep_label?: Base64;
  target_key_id: string;
  target_key_backend: string;
  target_key_type: string;
  target_key_size?: number;
  target_curve?: string;
  target_partition?: string;
  target_exportable?: boolean;
  tenant_id?: string;
  /**
   * Unwrap with this enabled version. Omitted tries every enabled version for
   * AES-KW, AES-KWP, AES-GCM and RSA-OAEP, and requires exactly one enabled
   * version for AES-CBC and RSA PKCS#1 v1.5.
   */
  unwrapping_key_version?: number;
}

/** Mirrors pkg/api/transport/types.go UnwrapKeyByIDResponse. */
export interface UnwrapKeyByIDResponse {
  key_id: string;
  backend: string;
  success: boolean;
  message?: string;
}
