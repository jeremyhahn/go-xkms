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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// TestGRPCServer_StopWithExpiredContext verifies the forced-shutdown path
// in Stop when the context deadline has already expired.
func TestGRPCServer_StopWithExpiredContext(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "xkms-grpc-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	require.NoError(t, err)

	// Start server
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for socket to exist
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(socketPath); statErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Establish a connection to delay graceful shutdown
	time.Sleep(50 * time.Millisecond)
	conn, dialErr := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if dialErr == nil {
		client := pb.NewKeystoreServiceClient(conn)
		_, _ = client.ListBackends(context.Background(), &pb.ListBackendsRequest{})
		defer func() { _ = conn.Close() }()
	}

	// Stop with already-cancelled context to exercise the ctx.Done() select branch
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = server.Stop(ctx)
	assert.NoError(t, err)
}
