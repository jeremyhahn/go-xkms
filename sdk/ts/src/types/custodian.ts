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

/**
 * Custodian group DTOs. Requests mirror pkg/api/rest/handlers_custodian.go
 * local shapes; the group/member info mirrors go-qrdb/sdk/go/transport
 * custodian_types.go (aliased through pkg/api/transport/types_custodian.go).
 */

import type { PageResponse, RFC3339 } from './common.js';

export interface CustodianMemberInfo {
  share_index: number;
  user_id: string;
  username: string;
  assigned_at: RFC3339;
  received_at?: RFC3339;
  method: string;
}

export interface CustodianGroupInfo {
  id: string;
  tenant_id?: string;
  name: string;
  purpose: string;
  threshold: number;
  total: number;
  members: CustodianMemberInfo[];
  created_at: RFC3339;
  updated_at: RFC3339;
}

export interface CreateCustodianGroupRequest {
  id: string;
  tenant_id?: string;
  name: string;
  purpose: string;
  threshold: number;
  total: number;
}

export interface CreateCustodianGroupResponse {
  group: CustodianGroupInfo;
}

export interface GetCustodianGroupResponse {
  group: CustodianGroupInfo;
}

export interface ListCustodianGroupsResponse {
  groups: CustodianGroupInfo[];
  pagination: PageResponse;
}

export interface AddCustodianMemberRequest {
  user_id: string;
  username: string;
  method: string;
}

export interface AddCustodianMemberResponse {
  member: CustodianMemberInfo;
}

export interface DistributeSharesResponse {
  distributed: number;
}
