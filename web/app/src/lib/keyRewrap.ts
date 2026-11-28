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

// Typed client for POST /api/v1/keys/rewrap (pkg/api/transport/types_cryptoutil.go).
// sdk/ts has no method for it, so the console calls the HTTP core directly.
// Every byte field is standard base64 on the wire.

import { getSDKClient } from "$stores/sdkClient.ts";
import { isB64 } from "$lib/b64.ts";

/** The DecryptRequest fields the rewrap source uses; the server fills the tenant. */
export interface RewrapSource {
  backend: string;
  key_id: string;
  ciphertext: string;
  nonce?: string;
  tag?: string;
  additional_data?: string;
  gcm_nonce_mode?: string;
  iv?: string;
  mode?: string;
}

/**
 * An empty target key rewraps under the source key's current version; an
 * empty target backend uses the source backend.
 */
export interface RewrapRequest {
  source: RewrapSource;
  target_key_id?: string;
  target_backend?: string;
}

export interface EncryptResponse {
  ciphertext: string;
  nonce?: string;
  tag?: string;
  iv?: string;
  gcm_nonce_mode?: string;
  key_version?: number;
}

export interface RewrapResponse {
  source_key_version?: number;
  wrapped: EncryptResponse;
}

/** The source byte fields a ciphertext box can carry. */
export type CiphertextFields = Pick<RewrapSource, "ciphertext" | "nonce" | "tag" | "iv" | "gcm_nonce_mode">;

export function rewrap(req: RewrapRequest): Promise<RewrapResponse> {
  return getSDKClient().http.request<RewrapResponse>("POST", "/api/v1/keys/rewrap", { body: req });
}

const CIPHERTEXT_ERROR = "Ciphertext must be base64 or an EncryptResponse JSON object.";

/**
 * Parses the ciphertext box: a bare base64 ciphertext, or a pasted
 * EncryptResponse JSON object (detected by a leading "{"). Returns the
 * source fields, or an error string.
 */
export function parseCiphertextInput(text: string): CiphertextFields | string {
  const t = text.trim();
  if (!t.startsWith("{")) {
    return isB64(t) ? { ciphertext: t } : CIPHERTEXT_ERROR;
  }
  let obj: unknown;
  try {
    obj = JSON.parse(t);
  } catch {
    return CIPHERTEXT_ERROR;
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return CIPHERTEXT_ERROR;
  const rec = obj as Record<string, unknown>;
  if (typeof rec.ciphertext !== "string" || !isB64(rec.ciphertext)) return CIPHERTEXT_ERROR;
  const out: CiphertextFields = { ciphertext: rec.ciphertext };
  for (const f of ["nonce", "tag", "iv"] as const) {
    const v = rec[f];
    if (v === undefined || v === null || v === "") continue;
    if (typeof v !== "string" || !isB64(v)) return `The pasted ${f} must be base64.`;
    out[f] = v;
  }
  if (typeof rec.gcm_nonce_mode === "string" && rec.gcm_nonce_mode !== "") {
    out.gcm_nonce_mode = rec.gcm_nonce_mode;
  }
  return out;
}
