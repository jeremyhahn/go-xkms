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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// addReplicaCall records the arguments a single AddReplica invocation on
// grpcFakeClusterReader was made with, so tests can assert the servicer
// forwarded the request faithfully.
type addReplicaCall struct {
	shardID   uint64
	replicaID uint64
	raftAddr  string
}

// removeReplicaCall records the arguments a single RemoveReplica invocation
// was made with.
type removeReplicaCall struct {
	shardID   uint64
	replicaID uint64
}

// grpcFakeClusterReader is a test double for the embedded qrdb cluster client.
// It satisfies the full xkms.ClusterClient contract (read, leader-endpoint
// resolution, and membership mutation) the servicer depends on, so the gRPC
// handlers can be exercised against standalone and clustered nodes, including
// the privileged AddClusterReplica/RemoveClusterReplica mutations.
type grpcFakeClusterReader struct {
	members    []xkms.ClusterMember
	leaderID   uint64
	hasLeader  bool
	membersErr error
	leaderErr  error

	leaderEndpoint    string
	leaderEndpointErr error

	addReplicaErr    error
	removeReplicaErr error

	addCalls    []addReplicaCall
	removeCalls []removeReplicaCall
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

func (f *grpcFakeClusterReader) LeaderEndpoint(_ context.Context, _ uint64, _ string) (string, error) {
	if f.leaderEndpointErr != nil {
		return "", f.leaderEndpointErr
	}
	return f.leaderEndpoint, nil
}

func (f *grpcFakeClusterReader) AddReplica(_ context.Context, shardID, replicaID uint64, raftAddr string) error {
	if f.addReplicaErr != nil {
		return f.addReplicaErr
	}
	f.addCalls = append(f.addCalls, addReplicaCall{shardID: shardID, replicaID: replicaID, raftAddr: raftAddr})
	return nil
}

func (f *grpcFakeClusterReader) RemoveReplica(_ context.Context, shardID, replicaID uint64) error {
	if f.removeReplicaErr != nil {
		return f.removeReplicaErr
	}
	f.removeCalls = append(f.removeCalls, removeReplicaCall{shardID: shardID, replicaID: replicaID})
	return nil
}

// setClusterClientForTest wires the global servicer with the given cluster
// client, shard, and node id, registers cleanup, and returns the XKMSService
// so callers can construct a Service with the injected dependency. Pass nil
// for a standalone node.
func setClusterClientForTest(t *testing.T, reader xkms.ClusterClient, shardID, nodeID uint64) *xkms.XKMSService {
	t.Helper()
	setupXKMSForTest(t)
	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)
	xkmsSvc.SetClusterClient(reader, shardID, nodeID)
	t.Cleanup(func() { xkms.Reset() })
	return xkmsSvc
}

// clusterMutationCtx returns a context carrying an authenticated identity, for
// use with an authorizer that is expected to reach a genuine allow/deny
// decision rather than an unauthenticated rejection for a missing identity.
func clusterMutationCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "cluster-admin",
		Roles:   []string{"admin"},
	})
}

func TestGetClusterStatus_Standalone(t *testing.T) {
	xkmsSvc := setClusterClientForTest(t, nil, 1, 7)
	svc := NewService(nil, nil, xkmsSvc)

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
	xkmsSvc := setClusterClientForTest(t, reader, 3, 1)
	svc := NewService(nil, nil, xkmsSvc)

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
	xkmsSvc := setClusterClientForTest(t, reader, 1, 1)
	svc := NewService(nil, nil, xkmsSvc)

	_, err := svc.GetClusterStatus(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestListClusterMembers_Standalone(t *testing.T) {
	xkmsSvc := setClusterClientForTest(t, nil, 1, 1)
	svc := NewService(nil, nil, xkmsSvc)

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
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc)

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
	xkmsSvc := setClusterClientForTest(t, reader, 2, 1)
	svc := NewService(nil, nil, xkmsSvc)

	_, err := svc.ListClusterMembers(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// TestListClusterMembers_APIEndpoints covers both ends of api_endpoints
// advertisement: a member that publishes endpoints carries them on the wire,
// and a member that advertises nothing serializes with an empty/absent map
// rather than an error or a nil-panic.
func TestListClusterMembers_APIEndpoints(t *testing.T) {
	reader := &grpcFakeClusterReader{
		members: []xkms.ClusterMember{
			{
				ReplicaID: 1,
				Address:   "10.0.0.1:63001",
				IsLeader:  true,
				APIEndpoints: map[string]string{
					"grpc": "10.0.0.1:9090",
					"rest": "10.0.0.1:8443",
				},
			},
			{ReplicaID: 2, Address: "10.0.0.2:63001", IsLeader: false},
		},
	}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc)

	resp, err := svc.ListClusterMembers(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, resp.GetMembers(), 2)

	assert.Equal(t, map[string]string{
		"grpc": "10.0.0.1:9090",
		"rest": "10.0.0.1:8443",
	}, resp.GetMembers()[0].GetApiEndpoints())

	assert.Empty(t, resp.GetMembers()[1].GetApiEndpoints(), "a member advertising nothing carries an empty map")
}

// ==================== AddClusterReplica / RemoveClusterReplica ====================
//
// These RPCs are privileged: unlike the read-only status/membership surface
// above, authorization must fail closed on a network listener with no
// authorizer configured. Most success-path tests here use WithLocalTrust(),
// mirroring how the Unix transport actually constructs this Service, to
// isolate the mutation behavior from the authorization policy, which gets its
// own dedicated tests below.

func TestAddClusterReplica_Success(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	resp, err := svc.AddClusterReplica(context.Background(), &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(5), resp.GetShardId())
	assert.Equal(t, uint64(2), resp.GetReplicaId())

	require.Len(t, reader.addCalls, 1)
	assert.Equal(t, addReplicaCall{shardID: 5, replicaID: 2, raftAddr: "10.0.0.2:63001"}, reader.addCalls[0])
}

func TestAddClusterReplica_Idempotent(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	req := &pb.AddClusterReplicaRequest{ReplicaId: 2, RaftAddress: "10.0.0.2:63001"}

	_, err := svc.AddClusterReplica(context.Background(), req)
	require.NoError(t, err)
	_, err = svc.AddClusterReplica(context.Background(), req)
	require.NoError(t, err, "adding an already-present replica must succeed idempotently")

	assert.Len(t, reader.addCalls, 2, "both calls reach the underlying AddReplica")
}

func TestAddClusterReplica_InvalidReplicaID(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	_, err := svc.AddClusterReplica(context.Background(), &pb.AddClusterReplicaRequest{
		ReplicaId:   0,
		RaftAddress: "10.0.0.2:63001",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, reader.addCalls, "an invalid request must never reach the cluster client")
}

func TestAddClusterReplica_Standalone(t *testing.T) {
	xkmsSvc := setClusterClientForTest(t, nil, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	_, err := svc.AddClusterReplica(context.Background(), &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestAddClusterReplica_Unauthorized(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(auth.NewAuthorizer(&denyingRBAC{}), nil, xkmsSvc)

	_, err := svc.AddClusterReplica(clusterMutationCtx(), &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, reader.addCalls, "a denied caller must never reach the cluster client")
}

func TestAddClusterReplica_AuthorizerAllows(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	rbac := &fakeRBACClient{}
	svc := NewService(auth.NewAuthorizer(rbac), nil, xkmsSvc)

	_, err := svc.AddClusterReplica(clusterMutationCtx(), &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	require.NoError(t, err)

	_, resource, action, seen := rbac.Last()
	require.True(t, seen)
	assert.Equal(t, auth.ResourceClusterAdmin, resource)
	assert.Equal(t, auth.ActionAddMember, action)
}

// TestAddClusterReplica_FailClosed_NoAuthorizerNotLocalTrust is the fail-closed
// regression: a Service built with neither an authorizer nor WithLocalTrust()
// -- the shape a misconfigured network listener would produce -- must deny the
// mutation rather than defaulting to allow.
func TestAddClusterReplica_FailClosed_NoAuthorizerNotLocalTrust(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc)

	_, err := svc.AddClusterReplica(context.Background(), &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, reader.addCalls)
}

// TestAddClusterReplica_FailClosed_NoAuthorizerLocalTrust is the counterpart:
// the Unix transport's exact construction (nil authorizer + WithLocalTrust())
// is allowed, because its trust boundary is the socket, not RBAC.
func TestAddClusterReplica_FailClosed_NoAuthorizerLocalTrust(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	_, err := svc.AddClusterReplica(context.Background(), &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	require.NoError(t, err)
	assert.Len(t, reader.addCalls, 1)
}

func TestRemoveClusterReplica_Success(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	resp, err := svc.RemoveClusterReplica(context.Background(), &pb.RemoveClusterReplicaRequest{ReplicaId: 2})
	require.NoError(t, err)
	assert.Equal(t, uint64(5), resp.GetShardId())
	assert.Equal(t, uint64(2), resp.GetReplicaId())

	require.Len(t, reader.removeCalls, 1)
	assert.Equal(t, removeReplicaCall{shardID: 5, replicaID: 2}, reader.removeCalls[0])
}

func TestRemoveClusterReplica_Idempotent(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	req := &pb.RemoveClusterReplicaRequest{ReplicaId: 2}

	_, err := svc.RemoveClusterReplica(context.Background(), req)
	require.NoError(t, err)
	_, err = svc.RemoveClusterReplica(context.Background(), req)
	require.NoError(t, err, "removing an already-absent replica must succeed idempotently")

	assert.Len(t, reader.removeCalls, 2)
}

func TestRemoveClusterReplica_InvalidReplicaID(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	_, err := svc.RemoveClusterReplica(context.Background(), &pb.RemoveClusterReplicaRequest{ReplicaId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, reader.removeCalls)
}

func TestRemoveClusterReplica_Standalone(t *testing.T) {
	xkmsSvc := setClusterClientForTest(t, nil, 5, 1)
	svc := NewService(nil, nil, xkmsSvc, WithLocalTrust())

	_, err := svc.RemoveClusterReplica(context.Background(), &pb.RemoveClusterReplicaRequest{ReplicaId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestRemoveClusterReplica_Unauthorized(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(auth.NewAuthorizer(&denyingRBAC{}), nil, xkmsSvc)

	_, err := svc.RemoveClusterReplica(clusterMutationCtx(), &pb.RemoveClusterReplicaRequest{ReplicaId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, reader.removeCalls)
}

// TestRemoveClusterReplica_FailClosed_NoAuthorizerNotLocalTrust mirrors the Add
// fail-closed regression for Remove.
func TestRemoveClusterReplica_FailClosed_NoAuthorizerNotLocalTrust(t *testing.T) {
	reader := &grpcFakeClusterReader{leaderID: 1, hasLeader: true}
	xkmsSvc := setClusterClientForTest(t, reader, 5, 1)
	svc := NewService(nil, nil, xkmsSvc)

	_, err := svc.RemoveClusterReplica(context.Background(), &pb.RemoveClusterReplicaRequest{ReplicaId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, reader.removeCalls)
}
