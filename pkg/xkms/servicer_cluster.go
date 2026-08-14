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

import (
	"context"
	"net"
)

// ClusterMember describes a single Raft replica as observed by the embedded
// go-qrdb node. It mirrors the fields the qrdb cluster client exposes for a
// shard peer and is the contract the servicer reads from.
type ClusterMember struct {
	// ReplicaID is the replica's identifier within the shard.
	ReplicaID uint64

	// Address is the replica's Raft network address.
	Address string

	// APIEndpoints maps each client-facing API protocol the replica serves to
	// the address clients should dial for it. It is what turns a replica ID
	// into a reachable API address, which the Raft address alone cannot do.
	//
	// It is nil when the replica advertises nothing. Consumers must treat that
	// as "unknown" and degrade to the Raft-only view, never as an error.
	APIEndpoints map[string]string

	// IsLeader is true when this replica is the shard's current leader.
	IsLeader bool
}

// ClusterReader is the read-only view of the embedded go-qrdb node's cluster
// client. It answers "who is in the shard" and "who leads it".
type ClusterReader interface {
	// Members returns the current membership of the given shard.
	Members(ctx context.Context, shardID uint64) ([]ClusterMember, error)

	// Leader returns the current leader replica ID for the given shard and
	// whether a leader is currently known.
	Leader(ctx context.Context, shardID uint64) (replicaID uint64, hasLeader bool, err error)
}

// ClusterEndpointResolver resolves the leader's dialable API address for a
// protocol. It is the piece that makes a not-leader redirect actionable.
type ClusterEndpointResolver interface {
	// LeaderEndpoint returns the address to dial to reach the shard leader over
	// the named API protocol.
	LeaderEndpoint(ctx context.Context, shardID uint64, protocol string) (string, error)
}

// ClusterMutator applies Raft membership changes to a shard.
type ClusterMutator interface {
	// AddReplica adds a replica to the shard's Raft group.
	AddReplica(ctx context.Context, shardID, replicaID uint64, raftAddr string) error

	// RemoveReplica removes a replica from the shard's Raft group.
	RemoveReplica(ctx context.Context, shardID, replicaID uint64) error
}

// ClusterClient is the full cluster contract the servicer depends on. The qrdb
// sdk *ClusterClient satisfies every part of it, bridged by the server-side
// adapter; tests provide a fake. It is one interface rather than a set of
// optional ones so a deployment can never present a half-implemented cluster
// surface: either the node has a cluster client or it is standalone.
type ClusterClient interface {
	ClusterReader
	ClusterEndpointResolver
	ClusterMutator
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

	// APIEndpoints maps each client-facing API protocol this replica serves to
	// the address clients should dial for it. Omitted entirely when the replica
	// advertises nothing, so a pre-advertisement peer serializes exactly as it
	// did before this field existed.
	APIEndpoints map[string]string `json:"api_endpoints,omitempty"`

	// IsLeader is true when this replica is the shard's current leader.
	IsLeader bool `json:"is_leader"`
}

// ClusterServicer defines the cluster operations the servicer exposes: the
// read-only status/membership surface, leader endpoint resolution used to make
// a not-leader redirect actionable, and the privileged membership mutations.
type ClusterServicer interface {
	ClusterStatus(ctx context.Context) (*ClusterStatusInfo, error)
	ClusterMembers(ctx context.Context) ([]ClusterMemberInfo, error)
	ClusterLeaderEndpoint(ctx context.Context, protocol string) (string, error)
	AddClusterReplica(ctx context.Context, replicaID uint64, raftAddr string) error
	RemoveClusterReplica(ctx context.Context, replicaID uint64) error
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
			NodeID:       m.ReplicaID,
			Address:      m.Address,
			APIEndpoints: m.APIEndpoints,
			IsLeader:     m.IsLeader,
		}
	}
	return out, nil
}

// ClusterLeaderEndpoint returns the address a client should dial to reach the
// shard leader over the named API protocol, as published by the leader itself
// into the cluster registry.
//
// It returns an empty address and no error on a standalone node: there is no
// other replica to redirect to, which callers treat the same as "unknown".
// A resolution failure is returned as a *ClusterLeaderEndpointError so a caller
// can distinguish it from "no endpoint advertised", but no caller is required
// to fail because of it.
func (s *XKMSService) ClusterLeaderEndpoint(ctx context.Context, protocol string) (string, error) {
	if s.cluster == nil {
		return "", nil
	}

	addr, err := s.cluster.LeaderEndpoint(ctx, s.clusterShardID, protocol)
	if err != nil {
		return "", &ClusterLeaderEndpointError{
			ShardID:  s.clusterShardID,
			Protocol: protocol,
			Err:      err,
		}
	}
	return addr, nil
}

// AddClusterReplica adds a replica to the configured shard's Raft group.
//
// Membership mutation is privileged and is authorized by the transport before
// reaching the servicer. A standalone node has no Raft group to reconfigure and
// fails with a *ClusterNotClusteredError rather than silently succeeding.
//
// The underlying qrdb AddMember is idempotent: adding a replica already present
// in the group succeeds without changing the configuration.
func (s *XKMSService) AddClusterReplica(ctx context.Context, replicaID uint64, raftAddr string) error {
	if s.cluster == nil {
		return &ClusterNotClusteredError{Operation: "add_replica"}
	}
	if err := validateReplicaID(replicaID); err != nil {
		return err
	}
	if err := validateRaftAddress(replicaID, raftAddr); err != nil {
		return err
	}

	if err := s.cluster.AddReplica(ctx, s.clusterShardID, replicaID, raftAddr); err != nil {
		return &ClusterAddReplicaError{
			ShardID:   s.clusterShardID,
			ReplicaID: replicaID,
			Err:       err,
		}
	}
	return nil
}

// RemoveClusterReplica removes a replica from the configured shard's Raft
// group.
//
// Membership mutation is privileged and is authorized by the transport before
// reaching the servicer. A standalone node fails with a
// *ClusterNotClusteredError.
//
// The underlying qrdb RemoveMember is idempotent: removing a replica that is
// already absent succeeds.
func (s *XKMSService) RemoveClusterReplica(ctx context.Context, replicaID uint64) error {
	if s.cluster == nil {
		return &ClusterNotClusteredError{Operation: "remove_replica"}
	}
	if err := validateReplicaID(replicaID); err != nil {
		return err
	}

	if err := s.cluster.RemoveReplica(ctx, s.clusterShardID, replicaID); err != nil {
		return &ClusterRemoveReplicaError{
			ShardID:   s.clusterShardID,
			ReplicaID: replicaID,
			Err:       err,
		}
	}
	return nil
}

// validateReplicaID rejects the reserved zero replica identifier, which Raft
// uses to mean "no replica".
func validateReplicaID(replicaID uint64) error {
	if replicaID == 0 {
		return &ClusterReplicaInvalidError{
			ReplicaID: replicaID,
			Reason:    "replica id must be non-zero",
		}
	}
	return nil
}

// validateRaftAddress rejects an address that is not a dialable host:port, so a
// typo is caught here rather than becoming an unreachable Raft peer that the
// group then waits on.
func validateRaftAddress(replicaID uint64, raftAddr string) error {
	if raftAddr == "" {
		return &ClusterReplicaInvalidError{
			ReplicaID: replicaID,
			Reason:    "raft address must not be empty",
		}
	}
	host, port, err := net.SplitHostPort(raftAddr)
	if err != nil {
		return &ClusterReplicaInvalidError{
			ReplicaID: replicaID,
			Reason:    "raft address must be host:port",
		}
	}
	if host == "" || port == "" {
		return &ClusterReplicaInvalidError{
			ReplicaID: replicaID,
			Reason:    "raft address must be host:port",
		}
	}
	return nil
}
