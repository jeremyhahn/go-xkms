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

// ClusterStatus reports this node's Raft shard status: the shard ID, this
// node's own replica ID, and the shard's current leadership.
//
// It never fails on a standalone node: Clustered reports false and the
// leadership fields report the zero value, mirroring ClusterLeaderEndpoint's
// "standalone degrades, never errors" contract. A live cluster whose leader
// query itself fails returns a *ClusterStatusError.
type ClusterStatus struct {
	// ShardID is the Raft shard (group) identifier this status describes.
	ShardID uint64

	// NodeID is this node's own replica identifier. Zero when standalone.
	NodeID uint64

	// LeaderID is the shard's current leader replica ID, or 0 when unknown
	// or standalone.
	LeaderID uint64

	// HasLeader reports whether the shard currently has an elected leader.
	// Always false when standalone.
	HasLeader bool

	// Clustered reports whether this node runs as part of a Raft cluster.
	// Mirrors XKMSService.Clustered() at the instant the status was read.
	Clustered bool
}

// ClusterStatus returns the current shard status. See the ClusterStatus type
// for the standalone-degradation contract.
func (s *XKMSService) ClusterStatus(ctx context.Context) (*ClusterStatus, error) {
	if s.cluster == nil {
		return &ClusterStatus{ShardID: s.clusterShardID, NodeID: s.clusterNodeID}, nil
	}

	leaderID, hasLeader, err := s.cluster.Leader(ctx, s.clusterShardID)
	if err != nil {
		return nil, &ClusterStatusError{ShardID: s.clusterShardID, Err: err}
	}
	return &ClusterStatus{
		ShardID:   s.clusterShardID,
		NodeID:    s.clusterNodeID,
		LeaderID:  leaderID,
		HasLeader: hasLeader,
		Clustered: true,
	}, nil
}

// ClusterMembers returns the shard's current Raft membership, including each
// replica's advertised client-facing API endpoints.
//
// It never fails on a standalone node: it returns a nil (empty) slice instead
// of erroring, matching ClusterStatus's degradation contract.
func (s *XKMSService) ClusterMembers(ctx context.Context) ([]ClusterMember, error) {
	if s.cluster == nil {
		return nil, nil
	}

	members, err := s.cluster.Members(ctx, s.clusterShardID)
	if err != nil {
		return nil, &ClusterMembersError{ShardID: s.clusterShardID, Err: err}
	}
	return members, nil
}

// Deliberately no ClusterAddReplica/ClusterRemoveReplica servicer methods:
// Raft membership mutation is go-qrdb's own control plane, driven directly
// by xkmsctl over gRPC/the Unix socket (pkg/server/qrdb_control_plane.go,
// cmd/xkmsctl/cluster.go) and, over REST, deliberately refused by design
// (docs/clustering/api.md, docs/web/parity.md "Cluster mutations") rather than
// proxied. The ClusterMutator half of the ClusterClient contract exists so
// the adapter can satisfy the qrdb SDK's cluster client shape, but the
// servicer intentionally never calls AddReplica/RemoveReplica: doing so
// would reintroduce the xkms-authored cluster proxy plane that
// qrdb_control_plane.go's composition-root comment documents as already
// deleted once.
