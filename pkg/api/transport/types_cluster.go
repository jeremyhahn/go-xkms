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

// Cluster status and membership DTOs, served read-only under
// /api/v1/cluster (go-xkms issue #847). They mirror pkg/xkms.ClusterStatus
// and pkg/xkms.ClusterMember exactly: the shard-scoped fields (ShardID,
// LeaderID, HasLeader, ReplicaID, Address, APIEndpoints, IsLeader) are
// go-qrdb's own ClusterClient/Member vocabulary passed through unchanged,
// and NodeID / Clustered are the servicer's own facts about this node
// (config's Cluster.NodeID and XKMSService.Clustered()), so no translation
// layer sits between the qrdb SDK and the wire.
//
// There are deliberately no request/response DTOs for membership mutation:
// REST never mutates Raft membership (docs/cluster/api.md, docs/web/parity.md
// "Cluster mutations") — that goes through go-qrdb's own control plane via
// `xkmsctl cluster add`/`remove` only.

// ClusterStatusInfo reports this node's Raft shard status.
type ClusterStatusInfo struct {
	// ShardID is the Raft shard (group) identifier this status describes.
	ShardID uint64 `json:"shard_id"`

	// LeaderID is the shard's current leader replica ID, or 0 when unknown
	// or standalone.
	LeaderID uint64 `json:"leader_id"`

	// HasLeader reports whether the shard currently has an elected leader.
	HasLeader bool `json:"has_leader"`

	// NodeID is this node's own replica identifier. Zero when standalone.
	NodeID uint64 `json:"node_id"`

	// Clustered reports whether this node runs as part of a Raft cluster.
	Clustered bool `json:"clustered"`
}

// ClusterStatusResponse is the GET /api/v1/cluster/status response.
type ClusterStatusResponse struct {
	Status ClusterStatusInfo `json:"status"`
}

// ClusterMemberInfo describes a single Raft replica, including its
// advertised client-facing API endpoints.
type ClusterMemberInfo struct {
	// ReplicaID is the replica's identifier within the shard.
	ReplicaID uint64 `json:"replica_id"`

	// Address is the replica's Raft network address.
	Address string `json:"address"`

	// APIEndpoints maps each client-facing API protocol the replica serves
	// to the address clients should dial for it. Omitted when the replica
	// advertises nothing.
	APIEndpoints map[string]string `json:"api_endpoints,omitempty"`

	// IsLeader is true when this replica is the shard's current leader.
	IsLeader bool `json:"is_leader"`
}

// ListClusterMembersResponse is the GET /api/v1/cluster/members response.
type ListClusterMembersResponse struct {
	Members []ClusterMemberInfo `json:"members"`
}
