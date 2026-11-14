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

// Typed calls for the key lifecycle endpoints that sdk/ts does not wrap:
// POST /api/v1/keys/{id}/status (keys:rotate) and POST /api/v1/keys/{id}/revoke
// (keys:delete). Wire types mirror pkg/api/transport/types_keymgmt.go.

import { getSDKClient } from "$stores/sdkClient.ts";

/** The statuses the console lets an operator set. */
export type SettableKeyStatus = "enabled" | "disabled";

export interface UpdateKeyStatusRequest {
  backend: string;
  /** Omitted or 0 targets the whole key. */
  version?: number;
  status: SettableKeyStatus;
}

export interface UpdateKeyStatusResponse {
  key_id: string;
  version?: number;
  status: string;
  timestamp: string;
}

export interface RevokeKeyRequest {
  backend: string;
  reason?: string;
}

export interface RevokeKeyResponse {
  key_id: string;
  status: string;
  timestamp: string;
}

function keyPath(id: string, action: "status" | "revoke"): string {
  return `/api/v1/keys/${encodeURIComponent(id)}/${action}`;
}

/** Enables or disables a key, or one of its versions when version is given. */
export function setKeyStatus(
  id: string,
  backend: string,
  status: SettableKeyStatus,
  version?: number,
): Promise<UpdateKeyStatusResponse> {
  const body: UpdateKeyStatusRequest =
    version === undefined ? { backend, status } : { backend, version, status };
  return getSDKClient().http.request<UpdateKeyStatusResponse>("POST", keyPath(id, "status"), { body });
}

/** Revokes a key. The server enforces keys:delete; revocation is final. */
export function revokeKey(id: string, backend: string, reason?: string): Promise<RevokeKeyResponse> {
  const body: RevokeKeyRequest = reason ? { backend, reason } : { backend };
  return getSDKClient().http.request<RevokeKeyResponse>("POST", keyPath(id, "revoke"), { body });
}
