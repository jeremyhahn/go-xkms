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
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// clusterMockServer is a KeystoreServiceServer test double covering Health
// (required for Transport.Connect's readiness probe) plus the cluster
// membership/mutation RPCs, with call counters so tests can assert exactly
// which server a request reached.
type clusterMockServer struct {
	pb.UnimplementedKeystoreServiceServer

	addResp *pb.ClusterReplicaResponse
	addErr  error

	removeResp *pb.ClusterReplicaResponse
	removeErr  error

	membersResp *pb.ListClusterMembersResponse

	mu          sync.Mutex
	addCalls    int
	removeCalls int
}

func (s *clusterMockServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Status: "healthy", Version: "test"}, nil
}

func (s *clusterMockServer) AddClusterReplica(_ context.Context, req *pb.AddClusterReplicaRequest) (*pb.ClusterReplicaResponse, error) {
	s.mu.Lock()
	s.addCalls++
	s.mu.Unlock()
	if s.addErr != nil {
		return nil, s.addErr
	}
	return s.addResp, nil
}

func (s *clusterMockServer) RemoveClusterReplica(_ context.Context, req *pb.RemoveClusterReplicaRequest) (*pb.ClusterReplicaResponse, error) {
	s.mu.Lock()
	s.removeCalls++
	s.mu.Unlock()
	if s.removeErr != nil {
		return nil, s.removeErr
	}
	return s.removeResp, nil
}

func (s *clusterMockServer) ListClusterMembers(_ context.Context, _ *emptypb.Empty) (*pb.ListClusterMembersResponse, error) {
	return s.membersResp, nil
}

func (s *clusterMockServer) AddCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addCalls
}

func (s *clusterMockServer) RemoveCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeCalls
}

// notLeaderError builds a gRPC status matching what
// pkg/api/grpc/errors.go's notLeaderStatus produces: FailedPrecondition with
// an ErrorInfo{Reason: NOT_LEADER} detail. leaderAPIAddress is only set on the
// metadata when non-empty, matching the server's "omit rather than emit
// empty" contract.
func notLeaderError(leaderAPIAddress string) error {
	st := status.New(codes.FailedPrecondition, "keystore: not leader for shard 1")
	md := map[string]string{
		"shard_id":  "1",
		"leader_id": "2",
	}
	if leaderAPIAddress != "" {
		md["leader_api_address"] = leaderAPIAddress
	}
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   "NOT_LEADER",
		Domain:   "xkms.cluster",
		Metadata: md,
	})
	if err != nil {
		return st.Err()
	}
	return withDetails.Err()
}

// startClusterTestServer starts srv on a real TCP loopback listener (not
// bufconn) because notLeaderInterceptor redials the leader by real address,
// so the test leader must be reachable that way too. Returns the dialable
// address and registers server shutdown as test cleanup.
func startClusterTestServer(t *testing.T, srv pb.KeystoreServiceServer) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcSrv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()

	t.Cleanup(func() {
		grpcSrv.Stop()
		_ = lis.Close()
	})

	return lis.Addr().String()
}

// connectedClusterTransport dials addr with an insecure Transport, running
// the same Connect() path (and therefore installing notLeaderInterceptor)
// production code uses.
func connectedClusterTransport(t *testing.T, addr string) *Transport {
	t.Helper()

	tr, err := NewWithConfig(&transport.Config{Address: addr})
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { _ = tr.Close() })

	return tr
}

func TestAddClusterReplica_ReachesServicerWithCorrectArgs(t *testing.T) {
	mock := &clusterMockServer{addResp: &pb.ClusterReplicaResponse{ShardId: 5, ReplicaId: 2}}
	addr := startClusterTestServer(t, mock)
	tr := connectedClusterTransport(t, addr)

	resp, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	require.NoError(t, err)
	assert.Equal(t, uint64(5), resp.ShardID)
	assert.Equal(t, uint64(2), resp.ReplicaID)
	assert.Equal(t, 1, mock.AddCalls())
}

func TestRemoveClusterReplica_ReachesServicerWithCorrectArgs(t *testing.T) {
	mock := &clusterMockServer{removeResp: &pb.ClusterReplicaResponse{ShardId: 5, ReplicaId: 2}}
	addr := startClusterTestServer(t, mock)
	tr := connectedClusterTransport(t, addr)

	resp, err := tr.RemoveClusterReplica(context.Background(), 2)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), resp.ShardID)
	assert.Equal(t, uint64(2), resp.ReplicaID)
	assert.Equal(t, 1, mock.RemoveCalls())
}

func TestClusterMembers_PopulatesAPIEndpoints(t *testing.T) {
	mock := &clusterMockServer{
		membersResp: &pb.ListClusterMembersResponse{
			Members: []*pb.ClusterMember{
				{
					NodeId:   1,
					Address:  "10.0.0.1:63001",
					IsLeader: true,
					ApiEndpoints: map[string]string{
						"grpc": "10.0.0.1:9090",
					},
				},
				{NodeId: 2, Address: "10.0.0.2:63001", IsLeader: false},
			},
		},
	}
	addr := startClusterTestServer(t, mock)
	tr := connectedClusterTransport(t, addr)

	resp, err := tr.ClusterMembers(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Members, 2)
	assert.Equal(t, map[string]string{"grpc": "10.0.0.1:9090"}, resp.Members[0].APIEndpoints)
	assert.Empty(t, resp.Members[1].APIEndpoints)
}

// TestNotLeaderInterceptor_RedirectsToLeaderOnce is the transparent-redirect
// happy path: a follower's NOT_LEADER response carrying a resolvable
// leader_api_address causes exactly one retry against the leader, and the
// caller sees the leader's success.
func TestNotLeaderInterceptor_RedirectsToLeaderOnce(t *testing.T) {
	leader := &clusterMockServer{addResp: &pb.ClusterReplicaResponse{ShardId: 5, ReplicaId: 2}}
	leaderAddr := startClusterTestServer(t, leader)

	follower := &clusterMockServer{addErr: notLeaderError(leaderAddr)}
	followerAddr := startClusterTestServer(t, follower)

	tr := connectedClusterTransport(t, followerAddr)

	resp, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	require.NoError(t, err)
	assert.Equal(t, uint64(5), resp.ShardID)
	assert.Equal(t, 1, follower.AddCalls(), "the original RPC must still reach the follower first")
	assert.Equal(t, 1, leader.AddCalls(), "the retry must reach the leader exactly once")
}

// TestNotLeaderInterceptor_NoRedirectWithoutLeaderAddress covers the
// pre-advertisement degrade path: no leader_api_address means nowhere to
// redirect to, so the typed not-leader error surfaces unchanged and no retry
// is attempted.
func TestNotLeaderInterceptor_NoRedirectWithoutLeaderAddress(t *testing.T) {
	follower := &clusterMockServer{addErr: notLeaderError("")}
	followerAddr := startClusterTestServer(t, follower)

	tr := connectedClusterTransport(t, followerAddr)

	_, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, 1, follower.AddCalls())
}

// TestNotLeaderInterceptor_ExactlyOneHop covers the "never a chain" guarantee:
// even if the leader ALSO responds NOT_LEADER (e.g. it stepped down between
// the follower's redirect and the retry landing), the interceptor does not
// chase the second redirect. The leader is hit exactly once and its response
// -- itself a NOT_LEADER -- is returned to the caller verbatim.
func TestNotLeaderInterceptor_ExactlyOneHop(t *testing.T) {
	leader := &clusterMockServer{addErr: notLeaderError("127.0.0.1:1")}
	leaderAddr := startClusterTestServer(t, leader)

	follower := &clusterMockServer{addErr: notLeaderError(leaderAddr)}
	followerAddr := startClusterTestServer(t, follower)

	tr := connectedClusterTransport(t, followerAddr)

	_, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, 1, follower.AddCalls())
	assert.Equal(t, 1, leader.AddCalls(), "leader must be hit exactly once, never re-redirected")
}

// TestNotLeaderInterceptor_UnrelatedErrorsPassThrough confirms the
// interceptor does not interfere with ordinary RPC errors that have nothing
// to do with cluster leadership.
func TestNotLeaderInterceptor_UnrelatedErrorsPassThrough(t *testing.T) {
	follower := &clusterMockServer{addErr: status.Error(codes.InvalidArgument, "replica id must be non-zero")}
	followerAddr := startClusterTestServer(t, follower)

	tr := connectedClusterTransport(t, followerAddr)

	_, err := tr.AddClusterReplica(context.Background(), 0, "10.0.0.2:63001")
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, 1, follower.AddCalls())
}

func TestClusterClient_InterfaceSatisfied(t *testing.T) {
	var _ transport.ClusterClient = (*Transport)(nil)
}
