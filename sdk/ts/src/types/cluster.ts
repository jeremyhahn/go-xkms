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
 * Cluster DTOs — read-only. Mirrors pkg/api/transport/types_cluster.go
 * exactly: the shard-scoped fields (shard_id, leader_id, has_leader,
 * replica_id, address, api_endpoints, is_leader) are go-qrdb's own
 * ClusterClient/Member vocabulary passed through unchanged; node_id and
 * clustered are the servicer's own facts about the responding node.
 *
 * There are deliberately no membership-mutation DTOs: REST never mutates
 * Raft membership, so there is no request/response shape to model — see
 * ClusterClient in clients/cluster.ts.
 */

export interface ClusterStatusInfo {
  shard_id: number;
  leader_id: number;
  has_leader: boolean;
  node_id: number;
  clustered: boolean;
}

export interface ClusterStatusResponse {
  status: ClusterStatusInfo;
}

export interface ClusterMemberInfo {
  replica_id: number;
  address: string;
  api_endpoints?: Record<string, string>;
  is_leader: boolean;
}

export interface ListClusterMembersResponse {
  members: ClusterMemberInfo[];
}
