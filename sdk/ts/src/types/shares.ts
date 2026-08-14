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

/** Custodian share DTOs. Mirrors pkg/api/rest/handlers_share.go. */

import type { Base64, PageResponse } from './common.js';

export interface SubmitShareRequest {
  server_url: string;
  group_id: string;
  group_name?: string;
  share_index: number;
  share_data: Base64;
  purpose?: string;
  tenant_id?: string;
}

/** The share status shape returned by submit / get / list (share data omitted). */
export interface ShareStatusResponse {
  server_url: string;
  group_id: string;
  group_name?: string;
  share_index: number;
  purpose?: string;
  received_at: string;
  tenant_id?: string;
}

export interface ListSharesResponse {
  shares: ShareStatusResponse[];
  pagination: PageResponse;
}

export interface ShareCollectionStatusResponse {
  group_id: string;
  collected: number;
}
