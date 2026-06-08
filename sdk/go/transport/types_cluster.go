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
	// ClusterReader is the read-only cluster surface.
	ClusterReader = pkgtransport.ClusterReader
)
