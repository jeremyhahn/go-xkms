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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// ==================== Cluster Operations ====================
//
// The cluster surface is read-only and owned by the embedded go-qrdb node.
// These handlers delegate to the unified XKMSService servicer, which reads
// leadership and membership from the node's cluster client and reports a
// single-node, non-clustered status when the node runs standalone. Gated with
// backends:read, mirroring the read-protection on the REST cluster routes.

// GetClusterStatus returns the Raft leadership status for the configured shard.
func (s *Service) GetClusterStatus(ctx context.Context, _ *emptypb.Empty) (*pb.ClusterStatusResponse, error) {
	if err := s.authorize(ctx, "backends", "read", "cluster-status"); err != nil {
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
	if err := s.authorize(ctx, "backends", "read", "cluster-members"); err != nil {
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
			NodeId:   m.NodeID,
			Address:  m.Address,
			IsLeader: m.IsLeader,
		}
	}

	return &pb.ListClusterMembersResponse{
		Members: pbMembers,
	}, nil
}
