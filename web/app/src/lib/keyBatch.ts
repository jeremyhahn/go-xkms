// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Batch encrypt/decrypt over the SDK HTTP core. sdk/ts has no method for
// these routes; the wire shapes mirror pkg/api/transport/types_cryptoutil.go.
// Byte fields are standard base64.

import { getSDKClient } from "$stores/sdkClient.ts";

/** Server-side cap on items per batch call (transport.MaxBatchItems). */
export const MAX_BATCH_ITEMS = 100;

export interface EncryptBatchItem {
  plaintext: string;
  additional_data?: string;
}

export interface EncryptResult {
  ciphertext: string;
  nonce?: string;
  tag?: string;
  iv?: string;
  gcm_nonce_mode?: string;
  key_version?: number;
}

export interface EncryptBatchResult {
  result?: EncryptResult;
  error?: string;
}

export interface EncryptBatchResponse {
  results: EncryptBatchResult[];
}

export interface DecryptBatchItem {
  ciphertext: string;
  additional_data?: string;
  nonce?: string;
  tag?: string;
  gcm_nonce_mode?: string;
  key_version?: number;
}

export interface DecryptBatchResult {
  plaintext?: string;
  key_version?: number;
  error?: string;
}

export interface DecryptBatchResponse {
  results: DecryptBatchResult[];
}

function batchPath(id: string, op: "encrypt-batch" | "decrypt-batch"): string {
  return `/api/v1/keys/${encodeURIComponent(id)}/${op}`;
}

/** Encrypts each item under key `id`; each result carries a value or an error. */
export function encryptBatch(id: string, backend: string, items: EncryptBatchItem[]): Promise<EncryptBatchResponse> {
  return getSDKClient().http.request<EncryptBatchResponse>("POST", batchPath(id, "encrypt-batch"), {
    body: { backend, items },
  });
}

/** Decrypts each item under key `id`; each result carries a plaintext or an error. */
export function decryptBatch(id: string, backend: string, items: DecryptBatchItem[]): Promise<DecryptBatchResponse> {
  return getSDKClient().http.request<DecryptBatchResponse>("POST", batchPath(id, "decrypt-batch"), {
    body: { backend, items },
  });
}
