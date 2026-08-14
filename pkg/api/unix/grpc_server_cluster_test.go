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
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// unixFakeClusterClient is a minimal test double for the embedded qrdb
// cluster client, satisfying xkms.ClusterClient so the Unix gRPC server's
// injected XKMSService can be exercised end to end over a real socket.
type unixFakeClusterClient struct {
	leaderID  uint64
	hasLeader bool

	addCalls    int
	removeCalls int
}

func (f *unixFakeClusterClient) Members(_ context.Context, _ uint64) ([]xkms.ClusterMember, error) {
	return nil, nil
}

func (f *unixFakeClusterClient) Leader(_ context.Context, _ uint64) (uint64, bool, error) {
	return f.leaderID, f.hasLeader, nil
}

func (f *unixFakeClusterClient) LeaderEndpoint(_ context.Context, _ uint64, _ string) (string, error) {
	return "", nil
}

func (f *unixFakeClusterClient) AddReplica(_ context.Context, _, _ uint64, _ string) error {
	f.addCalls++
	return nil
}

func (f *unixFakeClusterClient) RemoveReplica(_ context.Context, _, _ uint64) error {
	f.removeCalls++
	return nil
}

// setupXKMSForUnixClusterTest initializes the global xkms service backed by an
// in-memory pkcs8 backend and wires the given cluster client, mirroring
// pkg/api/grpc's setupXKMSForTest. It returns the XKMSService to pass to
// GRPCConfig.XKMSService.
func setupXKMSForUnixClusterTest(t *testing.T, cluster xkms.ClusterClient, shardID, nodeID uint64) *xkms.XKMSService {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := pkcs8.NewBackend(&pkcs8.Config{KeyStorage: keyStorage})
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("failed to create keystore: %v", err)
	}

	if err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": ks},
		DefaultBackend: "test",
	}); err != nil {
		t.Fatalf("failed to initialize xkms: %v", err)
	}

	xkmsSvc, err := xkms.Get()
	if err != nil {
		t.Fatalf("xkms.Get() error = %v", err)
	}
	xkmsSvc.SetClusterClient(cluster, shardID, nodeID)
	return xkmsSvc
}

// startUnixClusterTestServer starts a real Unix-socket gRPC server wired with
// xkmsSvc and returns a connected KeystoreServiceClient plus a cleanup func.
func startUnixClusterTestServer(t *testing.T, xkmsSvc *xkms.XKMSService) pb.KeystoreServiceClient {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "xkms-grpc-cluster-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")
	server, err := NewGRPCServer(&GRPCConfig{
		SocketPath:  socketPath,
		XKMSService: xkmsSvc,
	})
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	go func() { _ = server.Start() }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(socketPath); statErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to connect to gRPC server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = server.Stop(context.Background())
	})

	return pb.NewKeystoreServiceClient(conn)
}

// TestGRPCServer_AddClusterReplica_LocalTrustAllowed is the fail-closed
// counterpart at the transport-integration level: the Unix gRPC server
// constructs its Service with a nil authorizer AND WithLocalTrust() (see
// grpc_server.go's Start), so the privileged AddClusterReplica RPC must
// succeed over the socket even though no authorizer is configured -- the
// socket's file mode is this listener's trust boundary, not RBAC.
func TestGRPCServer_AddClusterReplica_LocalTrustAllowed(t *testing.T) {
	cluster := &unixFakeClusterClient{leaderID: 1, hasLeader: true}
	xkmsSvc := setupXKMSForUnixClusterTest(t, cluster, 5, 1)
	client := startUnixClusterTestServer(t, xkmsSvc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.AddClusterReplica(ctx, &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	if err != nil {
		t.Fatalf("AddClusterReplica() error = %v, want nil (local-trusted listener must allow)", err)
	}
	if resp.GetShardId() != 5 {
		t.Errorf("ShardId = %d, want 5", resp.GetShardId())
	}
	if resp.GetReplicaId() != 2 {
		t.Errorf("ReplicaId = %d, want 2", resp.GetReplicaId())
	}
	if cluster.addCalls != 1 {
		t.Errorf("addCalls = %d, want 1", cluster.addCalls)
	}
}

// TestGRPCServer_RemoveClusterReplica_LocalTrustAllowed mirrors the Add case
// for RemoveClusterReplica.
func TestGRPCServer_RemoveClusterReplica_LocalTrustAllowed(t *testing.T) {
	cluster := &unixFakeClusterClient{leaderID: 1, hasLeader: true}
	xkmsSvc := setupXKMSForUnixClusterTest(t, cluster, 5, 1)
	client := startUnixClusterTestServer(t, xkmsSvc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.RemoveClusterReplica(ctx, &pb.RemoveClusterReplicaRequest{ReplicaId: 2})
	if err != nil {
		t.Fatalf("RemoveClusterReplica() error = %v, want nil (local-trusted listener must allow)", err)
	}
	if resp.GetShardId() != 5 {
		t.Errorf("ShardId = %d, want 5", resp.GetShardId())
	}
	if cluster.removeCalls != 1 {
		t.Errorf("removeCalls = %d, want 1", cluster.removeCalls)
	}
}

// TestGRPCServer_AddClusterReplica_StandaloneFailsPrecondition confirms the
// standalone -> FailedPrecondition mapping survives the full transport round
// trip, not just the in-process Service call.
func TestGRPCServer_AddClusterReplica_StandaloneFailsPrecondition(t *testing.T) {
	xkmsSvc := setupXKMSForUnixClusterTest(t, nil, 5, 1)
	client := startUnixClusterTestServer(t, xkmsSvc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.AddClusterReplica(ctx, &pb.AddClusterReplicaRequest{
		ReplicaId:   2,
		RaftAddress: "10.0.0.2:63001",
	})
	if err == nil {
		t.Fatal("AddClusterReplica() error = nil, want FailedPrecondition")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
	}
}
