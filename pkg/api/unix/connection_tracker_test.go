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
	"google.golang.org/grpc/credentials/insecure"

	"github.com/prometheus/client_golang/prometheus/testutil"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
)

// activeUnixConnections reads the current xkms_active_connections gauge for
// the "unix" protocol label.
func activeUnixConnections(t *testing.T) float64 {
	t.Helper()
	g, err := metrics.ActiveConnections.GetMetricWithLabelValues(metrics.ProtocolUnix)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q) error = %v", metrics.ProtocolUnix, err)
	}
	return testutil.ToFloat64(g)
}

// TestGRPCServer_ConnectionTracker_ActiveConnectionsGauge drives a real
// client connection through the unix listener's grpc.StatsHandler
// (connMetricsHandler, go-xkms#720) and asserts the ActiveConnections gauge
// tracks it opening and closing. The unix socket has no per-request
// middleware chain the way REST and network gRPC do, so this is the one
// place counting it happens.
func TestGRPCServer_ConnectionTracker_ActiveConnectionsGauge(t *testing.T) {
	metrics.Enable()

	tmpDir, err := os.MkdirTemp("", "xkms-conn-tracker-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-conn-tracker.sock")
	server, err := NewGRPCServer(&GRPCConfig{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(socketPath); statErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	defer func() { _ = server.Stop(context.Background()) }()

	before := activeUnixConnections(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}

	client := pb.NewKeystoreServiceClient(conn)
	// grpc.NewClient dials lazily; an RPC forces the connection (and the
	// stats.Handler's TagConn/HandleConn(ConnBegin) calls) to actually happen
	// before the gauge is read.
	if _, healthErr := client.Health(ctx, &pb.HealthRequest{}); healthErr != nil {
		_ = conn.Close()
		t.Fatalf("Health RPC failed: %v", healthErr)
	}

	duringConn := activeUnixConnections(t)
	if duringConn != before+1 {
		t.Errorf("active_connections{protocol=unix} while connected = %v, want %v", duringConn, before+1)
	}

	if closeErr := conn.Close(); closeErr != nil {
		t.Fatalf("conn.Close() error = %v", closeErr)
	}

	// HandleConn(ConnEnd) runs asynchronously relative to Close() returning;
	// poll instead of asserting immediately.
	closeDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(closeDeadline) {
		if activeUnixConnections(t) == before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("active_connections{protocol=unix} after close = %v, want %v", activeUnixConnections(t), before)
}
