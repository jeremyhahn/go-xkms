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

/** Cluster DTOs. Mirrors pkg/api/transport/types_cluster.go. */

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
  node_id: number;
  address: string;
  api_endpoints?: Record<string, string>;
  is_leader: boolean;
}

export interface ListClusterMembersResponse {
  members: ClusterMemberInfo[];
}

export interface AddClusterReplicaRequest {
  replica_id: number;
  raft_address: string;
}

export interface ClusterReplicaResponse {
  shard_id: number;
  replica_id: number;
}
