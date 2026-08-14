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
  AddClusterReplicaRequest,
  ClusterReplicaResponse,
  ClusterStatusResponse,
  ListClusterMembersResponse,
} from '../types/cluster.js';

const BASE = '/api/v1/cluster';

/**
 * Cluster status and membership. Membership mutation requires RBAC
 * (admin:add_member / admin:remove_member); without RBAC wired the server
 * fails closed with 403.
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

  /** POST /api/v1/cluster/members */
  addMember(req: AddClusterReplicaRequest): Promise<ClusterReplicaResponse> {
    return this.http.request('POST', `${BASE}/members`, { body: req });
  }

  /** DELETE /api/v1/cluster/members/{replicaID} */
  removeMember(replicaId: number): Promise<ClusterReplicaResponse> {
    return this.http.request('DELETE', `${BASE}/members/${encodeURIComponent(String(replicaId))}`);
  }
}
