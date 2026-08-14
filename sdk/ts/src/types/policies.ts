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

/** TPM PCR-policy DTOs. Mirrors pkg/api/rest/policy_handlers.go. */

import type { Base64 } from './common.js';

export interface PolicyCreateRequest {
  name: string;
  bank: string;
  pcr_indices: number[];
}

export interface PolicyCreateResponse {
  name: string;
  bank: string;
  pcr_indices: number[];
  created_at: string;
  message: string;
}

export interface PolicyInfo {
  name: string;
  bank: string;
  pcr_indices: number[];
  created_at: string;
  updated_at: string;
}

export interface PolicyListResponse {
  policies: PolicyInfo[];
  total: number;
}

export interface PolicyGetResponse {
  name: string;
  bank: string;
  pcr_indices: number[];
  /** PCR index -> base64 PCR value */
  pcr_values: Record<string, Base64>;
  created_at: string;
  updated_at: string;
}

export interface PolicyDeleteResponse {
  message: string;
}

export interface PolicyRefreshResponse {
  name: string;
  bank: string;
  pcr_indices: number[];
  updated_at: string;
  message: string;
}

export interface PolicyVerifyResponse {
  name: string;
  valid: boolean;
  message: string;
}

export interface PolicyExportResponse {
  name: string;
  policy_json: string;
}
