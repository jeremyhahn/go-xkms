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

// Per-backend diagnostics routes (pkg/api/rest/routes.go), which sdk/ts does
// not wrap. Wire types mirror pkg/api/transport/types_keymgmt.go.

import { getSDKClient } from "$stores/sdkClient.ts";

export interface BackendStatusResponse {
  backend_type: string;
  status: string;
  device?: string;
  region?: string;
  key_id?: string;
  pcr_banks?: string[];
  pcr_registers?: number[];
  capabilities?: Record<string, boolean>;
  timestamp: string;
}

export interface BackendTestResponse {
  success: boolean;
  duration_ms: number;
  message?: string;
  timestamp: string;
}

export interface GetSupportedAlgorithmsResponse {
  algorithms: string[];
}

/** GET /api/v1/backend/status?backend= (backends:read). */
export function backendStatus(backend: string): Promise<BackendStatusResponse> {
  return getSDKClient().http.request<BackendStatusResponse>("GET", "/api/v1/backend/status", {
    query: { backend },
  });
}

/** POST /api/v1/backend/test (backends:read); exercises the device. */
export function backendTest(backend: string): Promise<BackendTestResponse> {
  return getSDKClient().http.request<BackendTestResponse>("POST", "/api/v1/backend/test", {
    body: { backend },
  });
}

/** GET /api/v1/backend/algorithms?backend= (keys:list). */
export function backendAlgorithms(backend: string): Promise<GetSupportedAlgorithmsResponse> {
  return getSDKClient().http.request<GetSupportedAlgorithmsResponse>("GET", "/api/v1/backend/algorithms", {
    query: { backend },
  });
}
