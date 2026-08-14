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
import type {
  PolicyCreateRequest,
  PolicyCreateResponse,
  PolicyDeleteResponse,
  PolicyExportResponse,
  PolicyGetResponse,
  PolicyListResponse,
  PolicyRefreshResponse,
  PolicyVerifyResponse,
} from '../types/policies.js';

const BASE = '/api/v1/policies';

/** TPM PCR policy management. */
export class PoliciesClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/policies/ */
  create(req: PolicyCreateRequest): Promise<PolicyCreateResponse> {
    return this.http.request('POST', `${BASE}/`, { body: req });
  }

  /** GET /api/v1/policies/ */
  list(): Promise<PolicyListResponse> {
    return this.http.request('GET', `${BASE}/`);
  }

  /** GET /api/v1/policies/{id} */
  get(id: string): Promise<PolicyGetResponse> {
    return this.http.request('GET', `${BASE}/${encodeURIComponent(id)}`);
  }

  /** DELETE /api/v1/policies/{id} */
  delete(id: string): Promise<PolicyDeleteResponse> {
    return this.http.request('DELETE', `${BASE}/${encodeURIComponent(id)}`);
  }

  /** POST /api/v1/policies/{id}/refresh */
  refresh(id: string): Promise<PolicyRefreshResponse> {
    return this.http.request('POST', `${BASE}/${encodeURIComponent(id)}/refresh`);
  }

  /** POST /api/v1/policies/{id}/verify */
  verify(id: string): Promise<PolicyVerifyResponse> {
    return this.http.request('POST', `${BASE}/${encodeURIComponent(id)}/verify`);
  }

  /** GET /api/v1/policies/{id}/export */
  export(id: string): Promise<PolicyExportResponse> {
    return this.http.request('GET', `${BASE}/${encodeURIComponent(id)}/export`);
  }
}
