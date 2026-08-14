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

package unix

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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// unixClusterMockServer is a minimal KeystoreServiceServer double for the
// cluster mutation RPCs, with call counters so tests can assert the request
// reached the servicer with the right arguments.
type unixClusterMockServer struct {
	pb.UnimplementedKeystoreServiceServer

	addResp *pb.ClusterReplicaResponse
	addErr  error

	mu       sync.Mutex
	addCalls int
}

func (s *unixClusterMockServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Status: "healthy"}, nil
}

func (s *unixClusterMockServer) AddClusterReplica(_ context.Context, req *pb.AddClusterReplicaRequest) (*pb.ClusterReplicaResponse, error) {
	s.mu.Lock()
	s.addCalls++
	s.mu.Unlock()
	if s.addErr != nil {
		return nil, s.addErr
	}
	return s.addResp, nil
}

func (s *unixClusterMockServer) RemoveClusterReplica(_ context.Context, req *pb.RemoveClusterReplicaRequest) (*pb.ClusterReplicaResponse, error) {
	return &pb.ClusterReplicaResponse{ShardId: 3, ReplicaId: req.GetReplicaId()}, nil
}

func (s *unixClusterMockServer) AddCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addCalls
}

// unixNotLeaderError mirrors pkg/api/grpc/errors.go's notLeaderStatus wire
// contract: FailedPrecondition with an ErrorInfo{Reason: NOT_LEADER} detail
// carrying a resolvable leader_api_address.
func unixNotLeaderError(leaderAPIAddress string) error {
	st := status.New(codes.FailedPrecondition, "keystore: not leader for shard 1")
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: "NOT_LEADER",
		Domain: "xkms.cluster",
		Metadata: map[string]string{
			"shard_id":           "1",
			"leader_id":          "2",
			"leader_api_address": leaderAPIAddress,
		},
	})
	if err != nil {
		return st.Err()
	}
	return withDetails.Err()
}

// newUnixClusterBufconnTransport dials srv over an in-memory bufconn listener
// and returns a connected Transport wired directly (bypassing Connect, which
// this package's socket-path validation would otherwise reject for a bufconn
// address) plus a cleanup func.
func newUnixClusterBufconnTransport(t *testing.T, srv pb.KeystoreServiceServer) (*Transport, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	grpcSrv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	tr := &Transport{
		config:    transport.DefaultConfig(),
		conn:      conn,
		client:    pb.NewKeystoreServiceClient(conn),
		connected: true,
	}

	cleanup := func() {
		_ = conn.Close()
		grpcSrv.Stop()
		_ = lis.Close()
	}

	return tr, cleanup
}

func TestUnixTransport_AddClusterReplica_ReachesServicer(t *testing.T) {
	mock := &unixClusterMockServer{addResp: &pb.ClusterReplicaResponse{ShardId: 5, ReplicaId: 2}}
	tr, cleanup := newUnixClusterBufconnTransport(t, mock)
	defer cleanup()

	resp, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	require.NoError(t, err)
	assert.Equal(t, uint64(5), resp.ShardID)
	assert.Equal(t, uint64(2), resp.ReplicaID)
	assert.Equal(t, 1, mock.AddCalls())
}

func TestUnixTransport_RemoveClusterReplica_ReachesServicer(t *testing.T) {
	mock := &unixClusterMockServer{}
	tr, cleanup := newUnixClusterBufconnTransport(t, mock)
	defer cleanup()

	resp, err := tr.RemoveClusterReplica(context.Background(), 2)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), resp.ShardID)
	assert.Equal(t, uint64(2), resp.ReplicaID)
}

func TestUnixTransport_AddClusterReplica_NotConnected(t *testing.T) {
	tr := &Transport{}
	_, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnixTransport_RemoveClusterReplica_NotConnected(t *testing.T) {
	tr := &Transport{}
	_, err := tr.RemoveClusterReplica(context.Background(), 2)
	assert.ErrorIs(t, err, ErrNotConnected)
}

// TestUnixTransport_NoLeaderRedirect is the negative counterpart to the gRPC
// transport's transparent-redirect tests: a Unix domain socket client has no
// network credentials to present to a remote leader, so even a NOT_LEADER
// response carrying a resolvable leader_api_address must surface unchanged,
// with no retry attempted. Confirmed here by the fact the mock never serves
// any RPC other than the one on this connection -- if the unix transport
// tried to redirect, it would fail to dial the bogus leader address and the
// test would still need to show the typed error survives; asserting the
// server saw exactly one call is the direct proof no second hop occurred.
func TestUnixTransport_NoLeaderRedirect(t *testing.T) {
	mock := &unixClusterMockServer{addErr: unixNotLeaderError("127.0.0.1:1")}
	tr, cleanup := newUnixClusterBufconnTransport(t, mock)
	defer cleanup()

	_, err := tr.AddClusterReplica(context.Background(), 2, "10.0.0.2:63001")
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, 1, mock.AddCalls(), "no retry: the unix transport must not follow a leader redirect")
}

func TestUnixTransport_ClusterClient_InterfaceSatisfied(t *testing.T) {
	var _ transport.ClusterClient = (*Transport)(nil)
}
