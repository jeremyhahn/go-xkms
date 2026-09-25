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
import type { ClusterStatusResponse, ListClusterMembersResponse } from '../types/cluster.js';

const BASE = '/api/v1/cluster';

/**
 * Cluster status and membership — read-only. Membership mutation is never
 * exposed over REST, by design: it goes through go-qrdb's own control plane
 * exclusively, via `xkmsctl cluster add`/`remove`.
 */
export class ClusterClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /api/v1/cluster/status */
  status(): Promise<ClusterStatusResponse> {
    return this.http.request('GET', `${BASE}/status`);
  }

  /** GET /api/v1/cluster/members */
  members(): Promise<ListClusterMembersResponse> {
    return this.http.request('GET', `${BASE}/members`);
  }
}
