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
  FrostAggregateRequest,
  FrostAggregateResponse,
  FrostDeleteKeyResponse,
  FrostGenerateKeyRequest,
  FrostGenerateKeyResponse,
  FrostGenerateNoncesResponse,
  FrostImportKeyRequest,
  FrostImportKeyResponse,
  FrostKeyInfo,
  FrostListKeysResponse,
  FrostSignRoundRequest,
  FrostSignRoundResponse,
  FrostVerifyRequest,
  FrostVerifyResponse,
} from '../types/frost.js';

const BASE = '/api/v1/frost';

/** FROST threshold signatures. */
export class FrostClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/frost/keys */
  generateKey(req: FrostGenerateKeyRequest): Promise<FrostGenerateKeyResponse> {
    return this.http.request('POST', `${BASE}/keys`, { body: req });
  }

  /** POST /api/v1/frost/keys/import */
  importKey(req: FrostImportKeyRequest): Promise<FrostImportKeyResponse> {
    return this.http.request('POST', `${BASE}/keys/import`, { body: req });
  }

  /** GET /api/v1/frost/keys */
  listKeys(page?: PageQuery): Promise<FrostListKeysResponse> {
    return this.http.request('GET', `${BASE}/keys`, { query: { ...page } });
  }

  /** GET /api/v1/frost/keys/{id} */
  getKey(id: string): Promise<FrostKeyInfo> {
    return this.http.request('GET', `${BASE}/keys/${encodeURIComponent(id)}`);
  }

  /** DELETE /api/v1/frost/keys/{id} */
  deleteKey(id: string): Promise<FrostDeleteKeyResponse> {
    return this.http.request('DELETE', `${BASE}/keys/${encodeURIComponent(id)}`);
  }

  /** POST /api/v1/frost/keys/{id}/nonces */
  generateNonces(id: string): Promise<FrostGenerateNoncesResponse> {
    return this.http.request('POST', `${BASE}/keys/${encodeURIComponent(id)}/nonces`);
  }

  /** POST /api/v1/frost/keys/{id}/sign */
  signRound(id: string, req: FrostSignRoundRequest): Promise<FrostSignRoundResponse> {
    return this.http.request('POST', `${BASE}/keys/${encodeURIComponent(id)}/sign`, {
      body: req,
    });
  }

  /** POST /api/v1/frost/aggregate */
  aggregate(req: FrostAggregateRequest): Promise<FrostAggregateResponse> {
    return this.http.request('POST', `${BASE}/aggregate`, { body: req });
  }

  /** POST /api/v1/frost/verify */
  verify(req: FrostVerifyRequest): Promise<FrostVerifyResponse> {
    return this.http.request('POST', `${BASE}/verify`, { body: req });
  }
}
