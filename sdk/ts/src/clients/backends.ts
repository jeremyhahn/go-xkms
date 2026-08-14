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
import type { BackendInfo, ListBackendsResponse } from '../types/backends.js';

/** Crypto backend discovery. */
export class BackendsClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /api/v1/backends */
  list(page?: PageQuery): Promise<ListBackendsResponse> {
    return this.http.request('GET', '/api/v1/backends', { query: { ...page } });
  }

  /** GET /api/v1/backends/{id} */
  get(id: string): Promise<BackendInfo> {
    return this.http.request('GET', `/api/v1/backends/${encodeURIComponent(id)}`);
  }
}
