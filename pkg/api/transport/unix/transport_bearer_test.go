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
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// authRecordingServer records the authorization metadata of each Health
// call.
type authRecordingServer struct {
	pb.UnimplementedKeystoreServiceServer
	mu   sync.Mutex
	auth []string
}

func (s *authRecordingServer) Health(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.auth = append(s.auth, md.Get("authorization")...)
	s.mu.Unlock()
	return &pb.HealthResponse{Status: "ok"}, nil
}

// unixSocketServer serves srv on a real Unix socket with no transport
// credentials, as xkmsd's Unix listener does, and returns the socket path.
func unixSocketServer(t *testing.T, srv pb.KeystoreServiceServer) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xkms.sock")
	lis, err := net.Listen("unix", path)
	require.NoError(t, err)
	server := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(server, srv)
	go func() {
		if serveErr := server.Serve(lis); serveErr != nil {
			return
		}
	}()
	t.Cleanup(server.Stop)
	return path
}

// TestConnect_PresentsBearerTokenOverUnixSocket proves the configured login
// JWT reaches the server on every RPC over the Unix socket, as it does on
// the network transports.
func TestConnect_PresentsBearerTokenOverUnixSocket(t *testing.T) {
	srv := &authRecordingServer{}
	path := unixSocketServer(t, srv)

	tr, err := New(transport.WithAddress(path), transport.WithJWTToken("tok-unix"))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })

	_, err = tr.Health(context.Background())
	require.NoError(t, err)

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Equal(t, []string{"Bearer tok-unix", "Bearer tok-unix"}, srv.auth)
}

// TestConnect_NoTokenSendsNoAuthorizationOverUnixSocket proves no
// authorization metadata is invented when no token is configured.
func TestConnect_NoTokenSendsNoAuthorizationOverUnixSocket(t *testing.T) {
	srv := &authRecordingServer{}
	path := unixSocketServer(t, srv)

	tr, err := New(transport.WithAddress(path))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Empty(t, srv.auth)
}
