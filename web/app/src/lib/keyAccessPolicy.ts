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

// Key access policy calls (GET/PUT/DELETE /api/v1/keys/{id}/policy). sdk/ts
// has no typed method for them, so they go through the client's HTTP core.
// Wire types mirror pkg/api/transport/types_keymgmt.go.

import { getSDKClient } from "$stores/sdkClient.ts";

export const KEY_USAGES = [
  "encrypt",
  "decrypt",
  "sign",
  "verify",
  "wrap_key",
  "derive_key",
  "generate_mac",
  "verify_mac",
] as const;

export type KeyUsage = (typeof KEY_USAGES)[number];

export interface KeyPolicy {
  key_id?: string;
  version?: number;
  allowed_operations?: KeyUsage[];
  allowed_principals?: string[];
  denied_principals?: string[];
  /** Unix seconds. */
  expires_at?: number;
  rotation_required?: boolean;
  max_usage_count?: number;
  require_mfa?: boolean;
  updated_at?: number;
}

export interface GetKeyPolicyResponse {
  policy?: KeyPolicy;
  timestamp: number;
}

export interface SetKeyPolicyResponse {
  key_id: string;
  policy_version: number;
  timestamp: number;
}

export interface KeyManagementResponse {
  key_id: string;
  timestamp: number;
}

function policyPath(id: string): string {
  return `/api/v1/keys/${encodeURIComponent(id)}/policy`;
}

export function getKeyPolicy(id: string, backend: string): Promise<GetKeyPolicyResponse> {
  return getSDKClient().http.request<GetKeyPolicyResponse>("GET", policyPath(id), { query: { backend } });
}

export function setKeyPolicy(id: string, backend: string, policy: KeyPolicy): Promise<SetKeyPolicyResponse> {
  return getSDKClient().http.request<SetKeyPolicyResponse>("PUT", policyPath(id), {
    body: { backend, key_id: id, policy },
  });
}

/** Removes the key's policy; the key falls back to the default policy. */
export function deleteKeyPolicy(id: string, backend: string): Promise<KeyManagementResponse> {
  return getSDKClient().http.request<KeyManagementResponse>("DELETE", policyPath(id), { query: { backend } });
}
