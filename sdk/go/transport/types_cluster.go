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

import pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"

// Cluster types re-exported from the canonical transport package.
type (
	// ClusterStatusInfo describes the Raft cluster status for the shard.
	ClusterStatusInfo = pkgtransport.ClusterStatusInfo
	// ClusterMemberInfo describes a single Raft replica in the shard.
	ClusterMemberInfo = pkgtransport.ClusterMemberInfo
	// ClusterStatusResponse wraps the cluster status response.
	ClusterStatusResponse = pkgtransport.ClusterStatusResponse
	// ListClusterMembersResponse wraps the cluster membership response.
	ListClusterMembersResponse = pkgtransport.ListClusterMembersResponse
	// AddClusterReplicaRequest asks the server to add a replica to the shard.
	AddClusterReplicaRequest = pkgtransport.AddClusterReplicaRequest
	// ClusterReplicaResponse acknowledges a membership mutation.
	ClusterReplicaResponse = pkgtransport.ClusterReplicaResponse
	// ClusterReader is the read-only cluster surface.
	ClusterReader = pkgtransport.ClusterReader
	// ClusterMutator is the privileged membership-mutation surface.
	ClusterMutator = pkgtransport.ClusterMutator
	// ClusterClient is the full cluster surface a transport may expose.
	ClusterClient = pkgtransport.ClusterClient
)

// API protocol names used to look up a replica's advertised endpoint,
// re-exported from the canonical transport package.
var (
	// APIProtocolREST names the HTTP/REST API.
	APIProtocolREST = pkgtransport.APIProtocolREST
	// APIProtocolGRPC names the gRPC API.
	APIProtocolGRPC = pkgtransport.APIProtocolGRPC
	// APIProtocolQUIC names the native QUIC API.
	APIProtocolQUIC = pkgtransport.APIProtocolQUIC
	// APIProtocolMCP names the Model Context Protocol API.
	APIProtocolMCP = pkgtransport.APIProtocolMCP
)
