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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

// tenantGRPCTestRegistry creates an initialized and unsealed BarrierRegistry
// backed by in-memory storage, for proving the Unix socket listener accepts
// a BarrierRegistry and still serves RPCs.
func tenantGRPCTestRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		logger,
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	creds := seal.MustCredentials(t.Context(), []byte("test-password"))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	return registry
}

// startTenantTestGRPCServer starts a Unix socket gRPC server with the given
// BarrierRegistry configured and returns a connected client plus a cleanup
// func. It mirrors TestGRPCServer_ClientConnection's setup.
func startTenantTestGRPCServer(t *testing.T, registry *seal.BarrierRegistry) (pb.KeystoreServiceClient, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "xkms-grpc-tenant-test-*")
	require.NoError(t, err)

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath:      socketPath,
		BarrierRegistry: registry,
	}

	server, err := NewGRPCServer(cfg)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()

	waitForGRPCServerReady(t, server, socketPath)

	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	cleanup := func() {
		_ = conn.Close()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(stopCtx)
		_ = os.RemoveAll(tmpDir)
	}

	return pb.NewKeystoreServiceClient(conn), cleanup
}

// TestGRPCServer_TenantInterceptors_WithRegistryPassesThrough proves the
// tenant interceptors (grpcinternal.TenantUnaryInterceptor /
// TenantStreamInterceptor, the same constructors the network gRPC server
// uses) are wired onto the Unix domain socket listener without breaking its
// RPC surface. Every admitted peer carries the listener's unix-peer identity
// in the system tenant, which has no tenant barrier to gate, so
// tenantgate.Access passes through regardless of what tenants the registry
// holds.
func TestGRPCServer_TenantInterceptors_WithRegistryPassesThrough(t *testing.T) {
	registry := tenantGRPCTestRegistry(t)
	_, err := registry.RegisterTenantDefault("tenant-a")
	require.NoError(t, err)

	client, cleanup := startTenantTestGRPCServer(t, registry)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Health(ctx, &pb.HealthRequest{})
	require.NoError(t, err)
	require.Equal(t, "healthy", resp.Status)
}

// TestGRPCServer_TenantInterceptors_NilRegistryPassesThrough proves the Unix
// listener still serves RPCs when no BarrierRegistry is configured (the
// default zero value), matching every other transport's "no registry means
// tenant enforcement disabled" behavior.
func TestGRPCServer_TenantInterceptors_NilRegistryPassesThrough(t *testing.T) {
	client, cleanup := startTenantTestGRPCServer(t, nil)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Health(ctx, &pb.HealthRequest{})
	require.NoError(t, err)
	require.Equal(t, "healthy", resp.Status)
}
