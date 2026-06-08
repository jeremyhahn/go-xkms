// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package transport

import "context"

// --- Cluster wire types ---
//
// These mirror the xkms-owned servicer DTOs (pkg/xkms.ClusterStatusInfo /
// ClusterMemberInfo). They are redeclared here rather than aliased because
// pkg/xkms imports pkg/api/transport; aliasing the other direction would form
// an import cycle. The JSON tags match the servicer DTOs exactly so the wire
// contract is identical regardless of which side serializes it.

// ClusterStatusInfo describes the Raft cluster status for the configured shard.
type ClusterStatusInfo struct {
	// ShardID is the Raft shard (group) the status pertains to.
	ShardID uint64 `json:"shard_id"`

	// LeaderID is the replica ID of the current shard leader. Zero when no
	// leader is known.
	LeaderID uint64 `json:"leader_id"`

	// HasLeader is true when the shard currently has an elected leader.
	HasLeader bool `json:"has_leader"`

	// NodeID is this node's Raft replica identifier. Zero when standalone.
	NodeID uint64 `json:"node_id"`

	// Clustered is true when the node participates in a Raft cluster.
	Clustered bool `json:"clustered"`
}

// ClusterMemberInfo describes a single Raft replica in the configured shard.
type ClusterMemberInfo struct {
	// NodeID is the replica's identifier within the shard.
	NodeID uint64 `json:"node_id"`

	// Address is the replica's Raft network address.
	Address string `json:"address"`

	// IsLeader is true when this replica is the shard's current leader.
	IsLeader bool `json:"is_leader"`
}

// ClusterStatusResponse wraps the cluster status for the SDK/REST contract.
type ClusterStatusResponse struct {
	Status ClusterStatusInfo `json:"status"`
}

// ListClusterMembersResponse wraps the cluster membership for the SDK/REST
// contract.
type ListClusterMembersResponse struct {
	Members []ClusterMemberInfo `json:"members"`
}

// ClusterReader is the read-only cluster surface exposed by the SDK. A client
// transport that can reach the cluster REST endpoints implements it; the SDK
// Cluster() accessor type-asserts to it. Membership mutation (add/remove
// replica) is intentionally absent: it requires a Raft replica-mutation API
// that is not yet surfaced through the xkms SDK.
type ClusterReader interface {
	// ClusterStatus returns the Raft leadership status for the configured shard.
	ClusterStatus(ctx context.Context) (*ClusterStatusResponse, error)

	// ClusterMembers returns the Raft replicas for the configured shard.
	ClusterMembers(ctx context.Context) (*ListClusterMembersResponse, error)
}
