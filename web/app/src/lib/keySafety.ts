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

// Key usage-limit (safety) calls. sdk/ts has no client for these routes, so
// they go through the SDK's HTTP core (auth, base URL and error mapping
// included). Wire types mirror pkg/api/transport/types_keymgmt.go.

import { getSDKClient } from "$stores/sdkClient.ts";

/** Body of PUT /api/v1/keys/{id}/safety. An omitted field keeps its default. */
export interface SetKeySafetyRequest {
  backend: string;
  key_id: string;
  max_operations?: number;
  max_bytes?: number;
  /** 1-100; omitted means the server's default warning threshold. */
  warning_percent?: number;
}

export interface SafetyWarning {
  type: string;
  path: string;
  usage_percent: number;
  status: string;
  operations_used: number;
  bytes_used: number;
  max_operations?: number;
  max_bytes?: number;
}

export interface SafetyCheckResponse {
  warnings: SafetyWarning[];
  timestamp: number;
}

export interface SafetyReportResponse {
  all_items: SafetyWarning[];
  total_keys: number;
  total_deks: number;
  keys_at_warning: number;
  keys_at_critical: number;
  deks_at_warning: number;
  deks_at_critical: number;
  timestamp: number;
}

export interface KeyManagementResponse {
  success?: boolean;
  key_id: string;
  timestamp: number;
}

function keyPath(keyId: string): string {
  return `/api/v1/keys/${encodeURIComponent(keyId)}/safety`;
}

/** GET /api/v1/safety/check (keys:get): keys near or past their limits. */
export function safetyCheck(): Promise<SafetyCheckResponse> {
  return getSDKClient().http.request<SafetyCheckResponse>("GET", "/api/v1/safety/check");
}

/** GET /api/v1/safety/report (keys:get): the JSON usage report. */
export function safetyReport(): Promise<SafetyReportResponse> {
  return getSDKClient().http.request<SafetyReportResponse>("GET", "/api/v1/safety/report");
}

/** PUT /api/v1/keys/{id}/safety (keys:rotate): set a key's usage limits. */
export function setKeySafety(req: SetKeySafetyRequest): Promise<KeyManagementResponse> {
  return getSDKClient().http.request<KeyManagementResponse>("PUT", keyPath(req.key_id), { body: req });
}

/** DELETE /api/v1/keys/{id}/safety?backend= (keys:rotate): clear a key's limits. */
export function clearKeySafety(keyId: string, backend: string): Promise<KeyManagementResponse> {
  return getSDKClient().http.request<KeyManagementResponse>("DELETE", keyPath(keyId), { query: { backend } });
}
