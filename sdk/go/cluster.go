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
	// ClusterReplicaResponse acknowledges a membership mutation.
	ClusterReplicaResponse = transport.ClusterReplicaResponse
)

// ErrClusterUnsupported is returned by Cluster when the underlying client
// transport cannot reach the cluster endpoints. Clients connected via a
// transport that does not implement the cluster reader (e.g. an embedded
// service without the cluster endpoints) receive this error.
var ErrClusterUnsupported = errors.New("xkms: cluster surface not supported by this transport")

// ErrClusterMutationUnsupported is returned by AddReplica and RemoveReplica
// when the client's transport can read the cluster surface but cannot mutate
// membership. It is distinct from ErrClusterUnsupported so a caller can tell
// "this transport has no cluster surface at all" from "this transport can look
// but not touch".
var ErrClusterMutationUnsupported = errors.New("xkms: cluster membership mutation not supported by this transport")

// ClusterClient is a facade over the cluster endpoints, obtained from
// Cluster(client).
//
// Reads are available on every transport that exposes the cluster surface.
// Membership mutation additionally requires a transport that implements
// ClusterMutator, and is authorized server-side against go-qrdb's canonical
// membership permissions ("admin:add_member" / "admin:remove_member") — the
// same permissions qrdb enforces on its own control plane.
type ClusterClient struct {
	reader  transport.ClusterReader
	mutator transport.ClusterMutator
}

// Cluster returns a ClusterClient for the given xkms client. It returns
// ErrClusterUnsupported when the client's transport does not expose the cluster
// reader surface. A transport that reads but cannot mutate yields a client
// whose AddReplica/RemoveReplica return ErrClusterMutationUnsupported.
func Cluster(c Client) (*ClusterClient, error) {
	reader, ok := c.(transport.ClusterReader)
	if !ok {
		return nil, ErrClusterUnsupported
	}
	cc := &ClusterClient{reader: reader}
	if mutator, ok := c.(transport.ClusterMutator); ok {
		cc.mutator = mutator
	}
	return cc, nil
}

// Status returns the Raft leadership status for the configured shard. A
// standalone (non-clustered) node reports a single-node, non-clustered status.
func (cc *ClusterClient) Status(ctx context.Context) (*ClusterStatusResponse, error) {
	return cc.reader.ClusterStatus(ctx)
}

// Members returns the Raft replicas for the configured shard. A standalone node
// returns an empty membership set.
//
// Each member carries the API endpoints that replica advertised, which is what
// lets a caller turn a replica ID into an address it can dial. A replica that
// advertises nothing has no endpoints; callers must treat that as unknown and
// degrade, not as an error.
func (cc *ClusterClient) Members(ctx context.Context) (*ListClusterMembersResponse, error) {
	return cc.reader.ClusterMembers(ctx)
}

// AddReplica adds a replica to the configured shard's Raft group.
//
// The operation is idempotent: adding a replica that is already a member
// succeeds without changing the configuration.
//
// It returns ErrClusterMutationUnsupported when the client's transport cannot
// mutate membership. Authorization happens server-side; a caller without the
// membership permission is denied there rather than here.
func (cc *ClusterClient) AddReplica(ctx context.Context, replicaID uint64, raftAddr string) (*ClusterReplicaResponse, error) {
	if cc.mutator == nil {
		return nil, ErrClusterMutationUnsupported
	}
	return cc.mutator.AddClusterReplica(ctx, replicaID, raftAddr)
}

// RemoveReplica removes a replica from the configured shard's Raft group.
//
// The operation is idempotent: removing a replica that is already absent
// succeeds.
//
// It returns ErrClusterMutationUnsupported when the client's transport cannot
// mutate membership.
func (cc *ClusterClient) RemoveReplica(ctx context.Context, replicaID uint64) (*ClusterReplicaResponse, error) {
	if cc.mutator == nil {
		return nil, ErrClusterMutationUnsupported
	}
	return cc.mutator.RemoveClusterReplica(ctx, replicaID)
}
