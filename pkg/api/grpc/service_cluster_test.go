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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// grpcFakeClusterReader is a test double for the embedded qrdb cluster client.
// It satisfies the xkms.ClusterReader interface the servicer reads from, so the
// gRPC handler can be exercised against both standalone and clustered nodes.
type grpcFakeClusterReader struct {
	members    []xkms.ClusterMember
	leaderID   uint64
	hasLeader  bool
	membersErr error
	leaderErr  error
}

func (f *grpcFakeClusterReader) Members(_ context.Context, _ uint64) ([]xkms.ClusterMember, error) {
	if f.membersErr != nil {
		return nil, f.membersErr
	}
	return f.members, nil
}

func (f *grpcFakeClusterReader) Leader(_ context.Context, _ uint64) (uint64, bool, error) {
	if f.leaderErr != nil {
		return 0, false, f.leaderErr
	}
	return f.leaderID, f.hasLeader, nil
}

// setClusterClientForTest wires the global servicer with the given cluster
// reader, shard, and node id, and registers cleanup.
func setClusterClientForTest(t *testing.T, reader xkms.ClusterReader, shardID, nodeID uint64) {
	t.Helper()
	setupXKMSForTest(t)
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetClusterClient(reader, shardID, nodeID)
	t.Cleanup(func() { xkms.Reset() })
}

func TestGetClusterStatus_Standalone(t *testing.T) {
	setClusterClientForTest(t, nil, 1, 7)
	svc := NewService(nil, nil)

	resp, err := svc.GetClusterStatus(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.False(t, resp.GetClustered())
	assert.Equal(t, uint64(1), resp.GetShardId())
	assert.Equal(t, uint64(7), resp.GetNodeId())
	assert.Equal(t, uint64(7), resp.GetLeaderId(), "standalone node is its own leader")
	assert.True(t, resp.GetHasLeader())
}

func TestGetClusterStatus_Clustered(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 2, hasLeader: true}
	setClusterClientForTest(t, reader, 3, 1)
	svc := NewService(nil, nil)

	resp, err := svc.GetClusterStatus(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, resp.GetClustered())
	assert.Equal(t, uint64(3), resp.GetShardId())
	assert.Equal(t, uint64(1), resp.GetNodeId())
	assert.Equal(t, uint64(2), resp.GetLeaderId())
	assert.True(t, resp.GetHasLeader())
}

func TestGetClusterStatus_ReaderError(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderErr: errors.New("raft unreachable")}
	setClusterClientForTest(t, reader, 1, 1)
	svc := NewService(nil, nil)

	_, err := svc.GetClusterStatus(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestListClusterMembers_Standalone(t *testing.T) {
	setClusterClientForTest(t, nil, 1, 1)
	svc := NewService(nil, nil)

	resp, err := svc.ListClusterMembers(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetMembers(), "standalone returns no members")
}

func TestListClusterMembers_Clustered(t *testing.T) {
	reader := &grpcFakeClusterReader{
		members: []xkms.ClusterMember{
			{ReplicaID: 1, Address: "10.0.0.1:63001", IsLeader: true},
			{ReplicaID: 2, Address: "10.0.0.2:63001", IsLeader: false},
		},
	}
	setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil)

	resp, err := svc.ListClusterMembers(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, resp.GetMembers(), 2)
	assert.Equal(t, uint64(1), resp.GetMembers()[0].GetNodeId())
	assert.Equal(t, "10.0.0.1:63001", resp.GetMembers()[0].GetAddress())
	assert.True(t, resp.GetMembers()[0].GetIsLeader())
	assert.Equal(t, uint64(2), resp.GetMembers()[1].GetNodeId())
	assert.False(t, resp.GetMembers()[1].GetIsLeader())
}

func TestListClusterMembers_ReaderError(t *testing.T) {
	reader := &grpcFakeClusterReader{membersErr: errors.New("raft unreachable")}
	setClusterClientForTest(t, reader, 2, 1)
	svc := NewService(nil, nil)

	_, err := svc.ListClusterMembers(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
