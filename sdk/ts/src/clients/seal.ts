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
  CanSealResponse,
  SealRequest,
  SealResponse,
  UnsealRequest,
  UnsealResponse,
} from '../types/seal.js';

/** Hardware-backed data sealing. */
export class SealClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/seal */
  seal(req: SealRequest): Promise<SealResponse> {
    return this.http.request('POST', '/api/v1/seal', { body: req });
  }

  /** POST /api/v1/unseal */
  unseal(req: UnsealRequest): Promise<UnsealResponse> {
    return this.http.request('POST', '/api/v1/unseal', { body: req });
  }

  /** GET /api/v1/seal/capability?backend= */
  capability(backend?: string): Promise<CanSealResponse> {
    return this.http.request('GET', '/api/v1/seal/capability', { query: { backend } });
  }
}
