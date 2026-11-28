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

import { getSDKClient } from "$stores/sdkClient.ts";

/** Wire shape of GET /api/v1/keys/{id}/public-key (pkg/api/transport/types_keymgmt.go). */
export interface GetPublicKeyResponse {
  key_id: string;
  /** Standard base64 of the DER-encoded SubjectPublicKeyInfo. */
  public_key: string;
  algorithm?: string;
  version: number;
  timestamp: string;
}

/** Armours a base64 DER public key as PEM, wrapping the body at 64 characters. */
export function toPem(b64: string): string {
  const lines = b64.match(/.{1,64}/g) ?? [];
  return ["-----BEGIN PUBLIC KEY-----", ...lines, "-----END PUBLIC KEY-----", ""].join("\n");
}

/** Fetches the public half of a key; version omitted means the latest. */
export function getPublicKey(id: string, backend: string, version?: number): Promise<GetPublicKeyResponse> {
  const query: Record<string, string> = { backend };
  if (version !== undefined) query.version = String(version);
  return getSDKClient().http.request<GetPublicKeyResponse>(
    "GET",
    `/api/v1/keys/${encodeURIComponent(id)}/public-key`,
    { query },
  );
}
