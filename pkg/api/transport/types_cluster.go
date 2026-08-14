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

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// API protocol names used to look up a replica's advertised endpoint. They are
// derived from go-qrdb's canonical protocol vocabulary rather than retyped, so
// the names a transport asks for can never drift from the names replicas
// publish. A transport passes its OWN protocol when resolving a leader endpoint
// because a redirected client must reach the leader over the same protocol it
// is already speaking.
//
// The unix socket is absent by design: a socket path is meaningful only on the
// node that owns it, so a unix client cannot be redirected to a peer.
var (
	// APIProtocolREST names the HTTP/REST API.
	APIProtocolREST = string(qrdbsdk.APIProtocolREST)

	// APIProtocolGRPC names the gRPC API.
	APIProtocolGRPC = string(qrdbsdk.APIProtocolGRPC)

	// APIProtocolQUIC names the native QUIC API.
	APIProtocolQUIC = string(qrdbsdk.APIProtocolQUIC)

	// APIProtocolMCP names the Model Context Protocol API.
	APIProtocolMCP = string(qrdbsdk.APIProtocolMCP)
)

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

	// APIEndpoints maps each client-facing API protocol this replica serves
	// ("rest", "grpc", "quic", "mcp") to the address a client should dial for
	// it. Each replica publishes its own from its configuration.
	//
	// It is omitted entirely when the replica advertises nothing, so a peer
	// that predates API advertisement serializes exactly as it did before this
	// field existed and consumers degrade to the Raft address alone.
	APIEndpoints map[string]string `json:"api_endpoints,omitempty"`

	// IsLeader is true when this replica is the shard's current leader.
	IsLeader bool `json:"is_leader"`
}

// AddClusterReplicaRequest asks the server to add a replica to the shard's Raft
// group.
type AddClusterReplicaRequest struct {
	// ReplicaID is the replica identifier to add. Must be non-zero.
	ReplicaID uint64 `json:"replica_id"`

	// RaftAddress is the new replica's Raft peer address ("host:port").
	RaftAddress string `json:"raft_address"`
}

// ClusterReplicaResponse acknowledges a membership mutation.
type ClusterReplicaResponse struct {
	// ShardID is the shard whose Raft group was reconfigured.
	ShardID uint64 `json:"shard_id"`

	// ReplicaID is the replica the mutation applied to.
	ReplicaID uint64 `json:"replica_id"`
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
// transport that can reach the cluster endpoints implements it; the SDK
// Cluster() accessor type-asserts to it.
type ClusterReader interface {
	// ClusterStatus returns the Raft leadership status for the configured shard.
	ClusterStatus(ctx context.Context) (*ClusterStatusResponse, error)

	// ClusterMembers returns the Raft replicas for the configured shard.
	ClusterMembers(ctx context.Context) (*ListClusterMembersResponse, error)
}

// ClusterMutator is the privileged membership-mutation surface. It is a
// separate interface from ClusterReader because the two carry different
// authorization weight: reads are gated like the rest of the read surface,
// while mutation reconfigures the Raft group and is gated on the canonical
// go-qrdb membership permissions.
type ClusterMutator interface {
	// AddClusterReplica adds a replica to the configured shard's Raft group.
	// The underlying operation is idempotent: adding a replica already present
	// succeeds without changing the configuration.
	AddClusterReplica(ctx context.Context, replicaID uint64, raftAddr string) (*ClusterReplicaResponse, error)

	// RemoveClusterReplica removes a replica from the configured shard's Raft
	// group. The underlying operation is idempotent: removing a replica that is
	// already absent succeeds.
	RemoveClusterReplica(ctx context.Context, replicaID uint64) (*ClusterReplicaResponse, error)
}

// ClusterClient is the full cluster surface a transport may expose.
type ClusterClient interface {
	ClusterReader
	ClusterMutator
}
