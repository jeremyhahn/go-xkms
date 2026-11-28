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

// Typed calls for the OTA image-signing key routes
// (POST /api/v1/ota-image-keys/{board}[/rotate|/sign]). sdk/ts has no method
// for them, so they go through the client's public HTTP core.

import { getSDKClient } from "$stores/sdkClient.ts";
import { bytesToB64 } from "./b64.ts";

/** Body of create and rotate; an empty algorithm selects ES256. */
export interface OtaKeyRequest {
  backend: string;
  algorithm?: "ES256";
}

/** Body of sign; data is standard base64 of the bytes. */
export interface OtaSignRequest {
  backend: string;
  data: string;
  data_is_digest?: boolean;
}

export interface OtaCreateResponse {
  key_id: string;
  key_type: string;
  public_key_pem?: string;
  message?: string;
}

export interface OtaRotateResponse {
  success: boolean;
  key_id: string;
  key_type?: string;
  message?: string;
  public_key_pem?: string;
  key_version?: number;
}

export interface OtaSignResponse {
  signature: string;
  algorithm?: string;
  key_version?: number;
}

function boardPath(board: string): string {
  return `/api/v1/ota-image-keys/${encodeURIComponent(board)}`;
}

export function createOtaKey(board: string, backend: string): Promise<OtaCreateResponse> {
  const body: OtaKeyRequest = { backend };
  return getSDKClient().http.request<OtaCreateResponse>("POST", boardPath(board), { body });
}

export function rotateOtaKey(board: string, backend: string): Promise<OtaRotateResponse> {
  const body: OtaKeyRequest = { backend };
  return getSDKClient().http.request<OtaRotateResponse>("POST", `${boardPath(board)}/rotate`, { body });
}

export function signOtaImage(board: string, req: OtaSignRequest): Promise<OtaSignResponse> {
  return getSDKClient().http.request<OtaSignResponse>("POST", `${boardPath(board)}/sign`, { body: req });
}

/** True for a SHA-256 digest written as 64 hex characters. */
export function isSha256Hex(s: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(s.trim());
}

/** Standard base64 of the bytes an even-length hex string encodes. */
export function hexToB64(hex: string): string {
  const t = hex.trim();
  const bytes = new Uint8Array(t.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(t.slice(i * 2, i * 2 + 2), 16);
  }
  return bytesToB64(bytes);
}
