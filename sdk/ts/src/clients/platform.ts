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
  SealStoreDeleteResponse,
  SealStoreGetResponse,
  SealStoreListResponse,
  SealStorePutRequest,
  SealStorePutResponse,
  SealStoreResealResponse,
  SealStoreStatusResponse,
} from '../types/platform.js';

const BASE = '/api/v1/platform';

/** Sealed platform credential store. */
export class PlatformClient {
  constructor(private readonly http: HttpCore) {}

  /** PUT /api/v1/platform/secrets/{key} */
  putSecret(key: string, req: SealStorePutRequest): Promise<SealStorePutResponse> {
    return this.http.request('PUT', `${BASE}/secrets/${encodeURIComponent(key)}`, {
      body: req,
    });
  }

  /** GET /api/v1/platform/secrets/{key} */
  getSecret(key: string): Promise<SealStoreGetResponse> {
    return this.http.request('GET', `${BASE}/secrets/${encodeURIComponent(key)}`);
  }

  /** DELETE /api/v1/platform/secrets/{key} */
  deleteSecret(key: string): Promise<SealStoreDeleteResponse> {
    return this.http.request('DELETE', `${BASE}/secrets/${encodeURIComponent(key)}`);
  }

  /** GET /api/v1/platform/secrets */
  listSecrets(): Promise<SealStoreListResponse> {
    return this.http.request('GET', `${BASE}/secrets`);
  }

  /** POST /api/v1/platform/secrets/{key}/reseal */
  resealSecret(key: string): Promise<SealStoreResealResponse> {
    return this.http.request('POST', `${BASE}/secrets/${encodeURIComponent(key)}/reseal`);
  }

  /** GET /api/v1/platform/status */
  status(): Promise<SealStoreStatusResponse> {
    return this.http.request('GET', `${BASE}/status`);
  }
}
