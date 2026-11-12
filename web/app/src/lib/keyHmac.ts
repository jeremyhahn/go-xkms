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

// HMAC with a stored key over the REST routes POST /api/v1/keys/{id}/hmac
// and /hmac/verify (pkg/api/rest/routes.go). sdk/ts has no method for them,
// so this calls the client's HTTP core directly. Wire types mirror
// pkg/api/transport/types_cryptoutil.go.

import { getSDKClient } from "$stores/sdkClient.ts";
import { b64ToBytes, bytesToB64, isB64 } from "./b64.ts";

export interface GenerateHMACRequest {
  backend: string;
  key_id: string;
  data: string;
  hash?: string;
}

export interface GenerateHMACResponse {
  mac: string;
  key_version?: number;
  hash: string;
}

export interface VerifyHMACRequest {
  backend: string;
  key_id: string;
  data: string;
  mac: string;
  hash?: string;
  key_version?: number;
}

export interface VerifyHMACResponse {
  valid: boolean;
  key_version?: number;
}

function hmacPath(id: string): string {
  return `/api/v1/keys/${encodeURIComponent(id)}/hmac`;
}

export function computeHmac(id: string, backend: string, dataB64: string, hash?: string): Promise<GenerateHMACResponse> {
  const body: GenerateHMACRequest = { backend, key_id: id, data: dataB64 };
  if (hash) body.hash = hash;
  return getSDKClient().http.request<GenerateHMACResponse>("POST", hmacPath(id), { body });
}

export function verifyHmac(id: string, backend: string, dataB64: string, macB64: string, hash?: string): Promise<VerifyHMACResponse> {
  const body: VerifyHMACRequest = { backend, key_id: id, data: dataB64, mac: macB64 };
  if (hash) body.hash = hash;
  return getSDKClient().http.request<VerifyHMACResponse>("POST", `${hmacPath(id)}/verify`, { body });
}

export function b64ToHex(b64: string): string {
  return Array.from(b64ToBytes(b64), (b) => b.toString(16).padStart(2, "0")).join("");
}

// macToB64 returns the MAC as standard base64, or null when it is neither
// hex (only [0-9a-f], even length) nor base64.
export function macToB64(mac: string): string | null {
  const t = mac.trim();
  if (t !== "" && t.length % 2 === 0 && /^[0-9a-f]+$/.test(t)) {
    const bytes = new Uint8Array(t.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(t.slice(2 * i, 2 * i + 2), 16);
    return bytesToB64(bytes);
  }
  return isB64(t) ? t : null;
}
