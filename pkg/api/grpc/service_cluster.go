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

package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ==================== Cluster Operations ====================
//
// The cluster surface is read-only and owned by the embedded go-qrdb node.
// These handlers delegate to the unified XKMSService servicer, which reads
// leadership and membership from the node's cluster client and reports a
// single-node, non-clustered status when the node runs standalone.
//
// Reads are gated with the canonical qrdb control-plane permissions
// admin:status and admin:peers, matching the membership mutations below
// (admin:add_member / admin:remove_member). They previously used
// backends:read, which is unrelated to the operation -- a principal granted
// access to read key backends does not thereby need cluster topology.

// GetClusterStatus returns the Raft leadership status for the configured shard.
func (s *Service) GetClusterStatus(ctx context.Context, _ *emptypb.Empty) (*pb.ClusterStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceClusterAdmin, auth.ActionClusterStatus, "cluster-status"); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	st, err := svc.ClusterStatus(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get cluster status: %v", err)
	}

	return &pb.ClusterStatusResponse{
		ShardId:   st.ShardID,
		LeaderId:  st.LeaderID,
		HasLeader: st.HasLeader,
		NodeId:    st.NodeID,
		Clustered: st.Clustered,
	}, nil
}

// ListClusterMembers returns the Raft replicas for the configured shard.
func (s *Service) ListClusterMembers(ctx context.Context, _ *emptypb.Empty) (*pb.ListClusterMembersResponse, error) {
	if err := s.authorize(ctx, auth.ResourceClusterAdmin, auth.ActionClusterPeers, "cluster-members"); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	members, err := svc.ClusterMembers(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list cluster members: %v", err)
	}

	pbMembers := make([]*pb.ClusterMember, len(members))
	for i, m := range members {
		pbMembers[i] = &pb.ClusterMember{
			NodeId:       m.NodeID,
			Address:      m.Address,
			IsLeader:     m.IsLeader,
			ApiEndpoints: m.APIEndpoints,
		}
	}

	return &pb.ListClusterMembersResponse{
		Members: pbMembers,
	}, nil
}

// AddClusterReplica adds a replica to the configured shard's Raft group.
//
// Membership mutation is privileged: unlike GetClusterStatus/ListClusterMembers
// (gated on the read-only "backends:read" grant), it is authorized against the
// canonical qrdb "admin:add_member" permission via authorizeClusterMutation,
// which fails closed rather than defaulting to allow when no authorizer is
// configured on a network listener. See authorizeClusterMutation for the full
// policy.
func (s *Service) AddClusterReplica(ctx context.Context, req *pb.AddClusterReplicaRequest) (*pb.ClusterReplicaResponse, error) {
	if err := s.authorizeClusterMutation(ctx, auth.ActionAddMember, "cluster-replica"); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	if err := svc.AddClusterReplica(ctx, req.GetReplicaId(), req.GetRaftAddress()); err != nil {
		return nil, mapClusterMutationError(err)
	}

	return &pb.ClusterReplicaResponse{
		ShardId:   clusterShardID(ctx, svc),
		ReplicaId: req.GetReplicaId(),
	}, nil
}

// RemoveClusterReplica removes a replica from the configured shard's Raft
// group.
//
// Membership mutation is privileged: it is authorized against the canonical
// qrdb "admin:remove_member" permission via authorizeClusterMutation. See
// authorizeClusterMutation for the fail-closed policy.
func (s *Service) RemoveClusterReplica(ctx context.Context, req *pb.RemoveClusterReplicaRequest) (*pb.ClusterReplicaResponse, error) {
	if err := s.authorizeClusterMutation(ctx, auth.ActionRemoveMember, "cluster-replica"); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	if err := svc.RemoveClusterReplica(ctx, req.GetReplicaId()); err != nil {
		return nil, mapClusterMutationError(err)
	}

	return &pb.ClusterReplicaResponse{
		ShardId:   clusterShardID(ctx, svc),
		ReplicaId: req.GetReplicaId(),
	}, nil
}

// authorizeClusterMutation enforces authorization for the privileged cluster
// membership RPCs (AddClusterReplica, RemoveClusterReplica).
//
// s.authorize's nil-authorizer-means-allow convention (see NewService) exists
// because a nil authorizer already means "this deployment does not enable
// RBAC" -- an acceptable, long-standing default for the read/crypto surface,
// which a deployment opts into by choosing not to wire an authorizer. That
// default is not acceptable here: these two RPCs reconfigure the Raft group,
// and a network-facing gRPC listener that forgot to wire an authorizer must
// not let any caller who can open a connection do that.
//
// The Unix transport is the one legitimate caller of this Service that wants
// to skip RBAC for these RPCs: pkg/api/unix/grpc_server.go constructs it with
// both a nil authorizer AND WithLocalTrust(), because its trust boundary is
// the filesystem socket (mode 0660, directory permissions), not RBAC -- the
// same reasoning that already lets it run every other RPC unauthorized.
//
// The policy:
//   - an authorizer is configured (s.authorizer.Enabled()) -> defer to it,
//     exactly like every other RPC.
//   - no authorizer configured AND s.localTrust -> allow (the Unix socket
//     case).
//   - no authorizer configured AND NOT s.localTrust -> deny with
//     PermissionDenied. A network listener with no authorizer wired is a
//     misconfiguration, and the safe failure mode for a privileged membership
//     mutation is closed, not open.
func (s *Service) authorizeClusterMutation(ctx context.Context, action, resourceID string) error {
	if s.authorizer.Enabled() {
		return s.authorize(ctx, auth.ResourceClusterAdmin, action, resourceID)
	}
	if s.localTrust {
		return nil
	}
	return status.Error(codes.PermissionDenied,
		"cluster membership mutation requires an authorizer on a network listener")
}

// mapClusterMutationError converts an error returned by AddClusterReplica or
// RemoveClusterReplica into a gRPC status. A malformed request (zero or
// otherwise unusable replica id, unparsable Raft address) is the caller's
// fault and maps to InvalidArgument; a standalone node has no Raft group to
// reconfigure and maps to FailedPrecondition; anything else -- the embedded
// qrdb node's own membership change failing -- is Internal.
func mapClusterMutationError(err error) error {
	var invalid *xkms.ClusterReplicaInvalidError
	if errors.As(err, &invalid) {
		return status.Error(codes.InvalidArgument, invalid.Error())
	}
	var notClustered *xkms.ClusterNotClusteredError
	if errors.As(err, &notClustered) {
		return status.Error(codes.FailedPrecondition, notClustered.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// clusterShardID resolves the configured shard id for a membership mutation's
// response envelope. XKMSService does not expose the shard id directly, so
// this reads it off ClusterStatus, which already reports it. A status lookup
// failure here is non-fatal: the mutation itself already succeeded by the time
// this is called, so the response still acknowledges it, with shard_id left
// at zero rather than turning a successful mutation into an error response.
func clusterShardID(ctx context.Context, svc *xkms.XKMSService) uint64 {
	st, err := svc.ClusterStatus(ctx)
	if err != nil {
		return 0
	}
	return st.ShardID
}
