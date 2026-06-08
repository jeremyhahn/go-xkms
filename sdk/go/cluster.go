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
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Cluster DTO types re-exported for the SDK contract.
type (
	// ClusterStatusInfo describes the Raft cluster status for the shard.
	ClusterStatusInfo = transport.ClusterStatusInfo
	// ClusterMemberInfo describes a single Raft replica in the shard.
	ClusterMemberInfo = transport.ClusterMemberInfo
	// ClusterStatusResponse wraps the cluster status response.
	ClusterStatusResponse = transport.ClusterStatusResponse
	// ListClusterMembersResponse wraps the cluster membership response.
	ListClusterMembersResponse = transport.ListClusterMembersResponse
)

// ErrClusterUnsupported is returned by Cluster when the underlying client
// transport cannot reach the read-only cluster REST endpoints. The cluster
// surface is served over REST; clients connected via a transport that does not
// implement the cluster reader (e.g. an embedded service without the cluster
// endpoints) receive this error.
var ErrClusterUnsupported = errors.New("xkms: cluster surface not supported by this transport")

// ClusterClient is a thin read-only facade over the cluster REST endpoints. It
// is obtained from Cluster(client). Membership mutation (add/remove replica) is
// intentionally absent: it requires a Raft replica-mutation API that is not yet
// surfaced through the xkms SDK.
//
// TODO(cluster): add/remove require a Raft replica-mutation API (qrdb
// AddReplica/RemoveReplica) not yet exposed via the xkms SDK.
type ClusterClient struct {
	reader transport.ClusterReader
}

// Cluster returns a read-only ClusterClient for the given xkms client. It
// returns ErrClusterUnsupported when the client's transport does not expose the
// cluster reader surface.
func Cluster(c Client) (*ClusterClient, error) {
	reader, ok := c.(transport.ClusterReader)
	if !ok {
		return nil, ErrClusterUnsupported
	}
	return &ClusterClient{reader: reader}, nil
}

// Status returns the Raft leadership status for the configured shard. A
// standalone (non-clustered) node reports a single-node, non-clustered status.
func (cc *ClusterClient) Status(ctx context.Context) (*ClusterStatusResponse, error) {
	return cc.reader.ClusterStatus(ctx)
}

// Members returns the Raft replicas for the configured shard. A standalone node
// returns an empty membership set.
func (cc *ClusterClient) Members(ctx context.Context) (*ListClusterMembersResponse, error) {
	return cc.reader.ClusterMembers(ctx)
}
