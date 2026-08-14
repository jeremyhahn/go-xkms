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

package server

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// clusterClientAdapter bridges the embedded go-qrdb node's *ClusterClient to
// the xkms.ClusterClient contract the servicer depends on. It performs only
// shape translation between the qrdb Member and the xkms one; every decision
// (validation, authorization, standalone handling) stays in the layers that own
// it.
type clusterClientAdapter struct {
	cluster *qrdbsdk.ClusterClient
}

// clusterClientAdapter must satisfy the full servicer contract; a partial
// bridge would leave the cluster surface half-wired at runtime.
var _ xkms.ClusterClient = (*clusterClientAdapter)(nil)

// Members returns the shard membership translated into the xkms shape,
// including each replica's advertised client-facing API endpoints.
func (a *clusterClientAdapter) Members(ctx context.Context, shardID uint64) ([]xkms.ClusterMember, error) {
	members, err := a.cluster.Members(ctx, shardID)
	if err != nil {
		return nil, err
	}
	out := make([]xkms.ClusterMember, len(members))
	for i, m := range members {
		out[i] = xkms.ClusterMember{
			ReplicaID:    m.ReplicaID,
			Address:      m.Address,
			APIEndpoints: apiEndpointsToStrings(m.APIEndpoints),
			IsLeader:     m.IsLeader,
		}
	}
	return out, nil
}

// Leader reports the shard's current leader replica ID.
func (a *clusterClientAdapter) Leader(ctx context.Context, shardID uint64) (uint64, bool, error) {
	return a.cluster.Leader(ctx, shardID)
}

// LeaderEndpoint resolves the address to dial to reach the shard leader over
// the named API protocol. An unknown protocol name is rejected by the qrdb SDK
// with a typed error rather than silently returning no endpoint.
func (a *clusterClientAdapter) LeaderEndpoint(ctx context.Context, shardID uint64, protocol string) (string, error) {
	return a.cluster.LeaderEndpoint(ctx, shardID, qrdbsdk.APIProtocol(protocol))
}

// AddReplica adds a replica to the shard's Raft group.
func (a *clusterClientAdapter) AddReplica(ctx context.Context, shardID, replicaID uint64, raftAddr string) error {
	return a.cluster.AddReplica(ctx, shardID, replicaID, raftAddr)
}

// RemoveReplica removes a replica from the shard's Raft group.
func (a *clusterClientAdapter) RemoveReplica(ctx context.Context, shardID, replicaID uint64) error {
	return a.cluster.RemoveReplica(ctx, shardID, replicaID)
}

// apiEndpointsToStrings converts the qrdb protocol-keyed endpoint map into the
// plain string-keyed map the xkms DTOs carry across the wire. A replica that
// advertises nothing yields nil, preserving the "unknown, degrade" contract
// rather than an empty map that would read as "serves nothing".
func apiEndpointsToStrings(endpoints map[qrdbsdk.APIProtocol]string) map[string]string {
	if len(endpoints) == 0 {
		return nil
	}
	out := make(map[string]string, len(endpoints))
	for proto, addr := range endpoints {
		out[string(proto)] = addr
	}
	return out
}
