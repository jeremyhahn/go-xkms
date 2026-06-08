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

package xkms

import "context"

// ClusterMember describes a single Raft replica as observed by the embedded
// go-qrdb node. It mirrors the fields the qrdb cluster client exposes for a
// shard peer and is the contract the servicer reads from.
type ClusterMember struct {
	// ReplicaID is the replica's identifier within the shard.
	ReplicaID uint64

	// Address is the replica's Raft network address.
	Address string

	// IsLeader is true when this replica is the shard's current leader.
	IsLeader bool
}

// ClusterReader is the minimal read-only view of the embedded go-qrdb node's
// cluster client that the servicer depends on. The qrdb sdk *ClusterClient
// satisfies this interface directly; tests provide a fake. Keeping the
// dependency narrow (two reads, no mutation) keeps membership mutation cleanly
// out of scope until a Raft replica-mutation API is exposed.
type ClusterReader interface {
	// Members returns the current membership of the given shard.
	Members(ctx context.Context, shardID uint64) ([]ClusterMember, error)

	// Leader returns the current leader replica ID for the given shard and
	// whether a leader is currently known.
	Leader(ctx context.Context, shardID uint64) (replicaID uint64, hasLeader bool, err error)
}

// ClusterStatusInfo is the xkms-owned DTO describing the Raft cluster status
// for the configured shard. When the node is not clustered (standalone),
// Clustered is false and LeaderID/HasLeader reflect the single-node node id.
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

	// Clustered is true when the node participates in a Raft cluster. When
	// false the remaining fields describe a single-node, non-clustered node.
	Clustered bool `json:"clustered"`
}

// ClusterMemberInfo is the xkms-owned DTO describing a single Raft replica in
// the configured shard.
type ClusterMemberInfo struct {
	// NodeID is the replica's identifier within the shard.
	NodeID uint64 `json:"node_id"`

	// Address is the replica's Raft network address.
	Address string `json:"address"`

	// IsLeader is true when this replica is the shard's current leader.
	IsLeader bool `json:"is_leader"`
}

// ClusterServicer defines the read-only cluster operations the servicer
// exposes. Membership mutation (add/remove replica) is intentionally excluded:
// it requires a Raft replica-mutation API that is not yet surfaced through the
// xkms SDK.
type ClusterServicer interface {
	ClusterStatus(ctx context.Context) (*ClusterStatusInfo, error)
	ClusterMembers(ctx context.Context) ([]ClusterMemberInfo, error)
}

// ClusterStatus returns the Raft leadership status for the configured shard.
//
// When the node runs standalone (no cluster client wired), it reports a
// single-node, non-clustered status rather than an error: the node is its own
// leader for its shard, which keeps callers (CLI, GUI, health probes) working
// uniformly whether or not clustering is enabled.
func (s *XKMSService) ClusterStatus(ctx context.Context) (*ClusterStatusInfo, error) {
	if s.cluster == nil {
		return &ClusterStatusInfo{
			ShardID:   s.clusterShardID,
			LeaderID:  s.clusterNodeID,
			HasLeader: true,
			NodeID:    s.clusterNodeID,
			Clustered: false,
		}, nil
	}

	leaderID, hasLeader, err := s.cluster.Leader(ctx, s.clusterShardID)
	if err != nil {
		return nil, &ClusterStatusError{ShardID: s.clusterShardID, Err: err}
	}

	return &ClusterStatusInfo{
		ShardID:   s.clusterShardID,
		LeaderID:  leaderID,
		HasLeader: hasLeader,
		NodeID:    s.clusterNodeID,
		Clustered: true,
	}, nil
}

// ClusterMembers returns the Raft replicas for the configured shard.
//
// When the node runs standalone (no cluster client wired), it returns an empty
// membership set: a non-clustered node has no Raft peers to enumerate.
func (s *XKMSService) ClusterMembers(ctx context.Context) ([]ClusterMemberInfo, error) {
	if s.cluster == nil {
		return []ClusterMemberInfo{}, nil
	}

	members, err := s.cluster.Members(ctx, s.clusterShardID)
	if err != nil {
		return nil, &ClusterMembersError{ShardID: s.clusterShardID, Err: err}
	}

	out := make([]ClusterMemberInfo, len(members))
	for i, m := range members {
		out[i] = ClusterMemberInfo{
			NodeID:   m.ReplicaID,
			Address:  m.Address,
			IsLeader: m.IsLeader,
		}
	}
	return out, nil
}
