// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/peercred"
)

func TestExclusivePeerCredentialPolicy_Allowed(t *testing.T) {
	daemonUID := uint32(os.Geteuid())
	policy := NewExclusivePeerCredentialPolicy([]uint32{4242}, []uint32{4343})

	tests := []struct {
		name    string
		creds   *peercred.Credentials
		allowed bool
	}{
		{name: "allowlisted uid admitted", creds: &peercred.Credentials{UID: 4242, GID: 1}, allowed: true},
		{name: "allowlisted gid admitted", creds: &peercred.Credentials{UID: 7, GID: 4343}, allowed: true},
		{name: "root is not implicitly admitted", creds: &peercred.Credentials{UID: 0, GID: 0}, allowed: false},
		{name: "daemon uid is not implicitly admitted", creds: &peercred.Credentials{UID: daemonUID, GID: 65534}, allowed: daemonUID == 4242},
		{name: "nil credentials refused", creds: nil, allowed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, policy.Allowed(tt.creds))
		})
	}
}

func TestGRPCServer_ExclusivePeersWithoutAllowlistRefusesToStart(t *testing.T) {
	socketPath := filepath.Join(privateSocketDir(t), "exclusive-empty.sock")
	server, err := NewGRPCServer(&GRPCConfig{SocketPath: socketPath, ExclusivePeers: true})
	require.NoError(t, err)

	err = server.Start()
	require.True(t, errors.Is(err, ErrNoAdmittedPeers), "Start error = %v", err)
	_, statErr := os.Stat(socketPath)
	assert.True(t, os.IsNotExist(statErr), "no socket may be bound for a listener that admits no one")
}

// TestGRPCServer_UnaryInterceptorsRunAfterAdmission proves an embedder's
// interceptor sees every unary RPC from an admitted peer and can refuse it.
func TestGRPCServer_UnaryInterceptorsRunAfterAdmission(t *testing.T) {
	socketPath := filepath.Join(privateSocketDir(t), "exclusive-intercept.sock")
	var seen []string
	deny := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		seen = append(seen, info.FullMethod)
		return nil, status.Error(codes.PermissionDenied, "narrowed")
	}
	server, err := NewGRPCServer(&GRPCConfig{
		SocketPath:        socketPath,
		ExclusivePeers:    true,
		AllowedUIDs:       []uint32{uint32(os.Geteuid())},
		UnaryInterceptors: []grpc.UnaryServerInterceptor{deny},
	})
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()
	waitForGRPCServerReady(t, server, socketPath)
	defer func() { _ = server.Stop(context.Background()) }()

	_, err = healthCall(t, socketPath)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, []string{pb.KeystoreService_Health_FullMethodName}, seen)
}

func healthCall(t *testing.T, socketPath string) (*pb.HealthResponse, error) {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return pb.NewKeystoreServiceClient(conn).Health(ctx, &pb.HealthRequest{})
}
