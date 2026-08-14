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

import { encodePathSegment, type HttpCore } from '../http.js';
import type { PageQuery } from '../types/common.js';
import type {
  ListSharesResponse,
  ShareCollectionStatusResponse,
  ShareStatusResponse,
  SubmitShareRequest,
} from '../types/shares.js';

const BASE = '/api/v1/shares';

/** Custodian share submission and inspection. */
export class SharesClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/shares/submit */
  submit(req: SubmitShareRequest): Promise<ShareStatusResponse> {
    return this.http.request('POST', `${BASE}/submit`, { body: req });
  }

  /** GET /api/v1/shares/ */
  list(page?: PageQuery): Promise<ListSharesResponse> {
    return this.http.request('GET', `${BASE}/`, { query: { ...page } });
  }

  /** GET /api/v1/shares/{serverURL}/{groupID}/{shareIndex} (serverURL is path-escaped). */
  get(serverURL: string, groupId: string, shareIndex: number): Promise<ShareStatusResponse> {
    return this.http.request(
      'GET',
      `${BASE}/${encodePathSegment(serverURL)}/${encodePathSegment(groupId)}/${shareIndex}`,
    );
  }

  /** DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex} (204). */
  async delete(serverURL: string, groupId: string, shareIndex: number): Promise<void> {
    await this.http.request<void>(
      'DELETE',
      `${BASE}/${encodePathSegment(serverURL)}/${encodePathSegment(groupId)}/${shareIndex}`,
      { parse: 'void' },
    );
  }

  /** GET /api/v1/shares/status/{groupID} */
  collectionStatus(groupId: string): Promise<ShareCollectionStatusResponse> {
    return this.http.request('GET', `${BASE}/status/${encodePathSegment(groupId)}`);
  }
}
