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

import type { HttpCore } from '../http.js';
import type { PageQuery } from '../types/common.js';
import type {
  AddCustodianMemberRequest,
  AddCustodianMemberResponse,
  CreateCustodianGroupRequest,
  CreateCustodianGroupResponse,
  DistributeSharesResponse,
  GetCustodianGroupResponse,
  ListCustodianGroupsResponse,
} from '../types/custodian.js';

const BASE = '/api/v1/custodian/groups';

/** Custodian (Shamir share officer) group management. */
export class CustodianClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/custodian/groups/ */
  createGroup(req: CreateCustodianGroupRequest): Promise<CreateCustodianGroupResponse> {
    return this.http.request('POST', `${BASE}/`, { body: req });
  }

  /** GET /api/v1/custodian/groups/ */
  listGroups(page?: PageQuery): Promise<ListCustodianGroupsResponse> {
    return this.http.request('GET', `${BASE}/`, { query: { ...page } });
  }

  /** GET /api/v1/custodian/groups/{id} */
  getGroup(id: string): Promise<GetCustodianGroupResponse> {
    return this.http.request('GET', `${BASE}/${encodeURIComponent(id)}`);
  }

  /** DELETE /api/v1/custodian/groups/{id} (204) */
  async deleteGroup(id: string): Promise<void> {
    await this.http.request<void>('DELETE', `${BASE}/${encodeURIComponent(id)}`, {
      parse: 'void',
    });
  }

  /** POST /api/v1/custodian/groups/{id}/members */
  addMember(id: string, req: AddCustodianMemberRequest): Promise<AddCustodianMemberResponse> {
    return this.http.request('POST', `${BASE}/${encodeURIComponent(id)}/members`, {
      body: req,
    });
  }

  /** DELETE /api/v1/custodian/groups/{id}/members/{userID} (204) */
  async removeMember(id: string, userId: string): Promise<void> {
    await this.http.request<void>(
      'DELETE',
      `${BASE}/${encodeURIComponent(id)}/members/${encodeURIComponent(userId)}`,
      { parse: 'void' },
    );
  }

  /** POST /api/v1/custodian/groups/{id}/distribute */
  distributeShares(id: string): Promise<DistributeSharesResponse> {
    return this.http.request('POST', `${BASE}/${encodeURIComponent(id)}/distribute`);
  }
}
