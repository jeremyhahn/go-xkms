// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
)

func TestNewGRPCServer_NilConfig(t *testing.T) {
	_, err := NewGRPCServer(nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
}

func TestNewGRPCServer_DefaultConfig(t *testing.T) {
	cfg := &GRPCConfig{}
	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	if server.config.SocketPath != DefaultSocketPath {
		t.Errorf("SocketPath = %v, want %v", server.config.SocketPath, DefaultSocketPath)
	}

	if server.config.SocketMode != 0660 {
		t.Errorf("SocketMode = %v, want 0660", server.config.SocketMode)
	}

	if server.config.MaxRecvMsgSize != 4*1024*1024 {
		t.Errorf("MaxRecvMsgSize = %v, want 4MB", server.config.MaxRecvMsgSize)
	}

	if server.config.MaxSendMsgSize != 4*1024*1024 {
		t.Errorf("MaxSendMsgSize = %v, want 4MB", server.config.MaxSendMsgSize)
	}

	if server.config.ConnectionTimeout != 120*time.Second {
		t.Errorf("ConnectionTimeout = %v, want 120s", server.config.ConnectionTimeout)
	}

	if server.config.MaxConcurrentStreams != 100 {
		t.Errorf("MaxConcurrentStreams = %v, want 100", server.config.MaxConcurrentStreams)
	}
}

func TestNewGRPCServer_CustomConfig(t *testing.T) {
	cfg := &GRPCConfig{
		SocketPath:           "/tmp/custom-grpc.sock",
		SocketMode:           0600,
		MaxRecvMsgSize:       8 * 1024 * 1024,
		MaxSendMsgSize:       8 * 1024 * 1024,
		ConnectionTimeout:    60 * time.Second,
		MaxConcurrentStreams: 200,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	if server.config.SocketPath != "/tmp/custom-grpc.sock" {
		t.Errorf("SocketPath = %v, want /tmp/custom-grpc.sock", server.config.SocketPath)
	}

	if server.config.SocketMode != 0600 {
		t.Errorf("SocketMode = %v, want 0600", server.config.SocketMode)
	}

	if server.config.MaxRecvMsgSize != 8*1024*1024 {
		t.Errorf("MaxRecvMsgSize = %v, want 8MB", server.config.MaxRecvMsgSize)
	}

	if server.config.MaxSendMsgSize != 8*1024*1024 {
		t.Errorf("MaxSendMsgSize = %v, want 8MB", server.config.MaxSendMsgSize)
	}

	if server.config.ConnectionTimeout != 60*time.Second {
		t.Errorf("ConnectionTimeout = %v, want 60s", server.config.ConnectionTimeout)
	}

	if server.config.MaxConcurrentStreams != 200 {
		t.Errorf("MaxConcurrentStreams = %v, want 200", server.config.MaxConcurrentStreams)
	}
}

func TestGRPCServer_SocketPath(t *testing.T) {
	cfg := &GRPCConfig{
		SocketPath: "/tmp/test-grpc.sock",
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	if server.SocketPath() != "/tmp/test-grpc.sock" {
		t.Errorf("SocketPath() = %v, want /tmp/test-grpc.sock", server.SocketPath())
	}
}

func TestGRPCServer_StartStop(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for socket file to exist (indicating server started)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Check socket file exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("Socket file was not created")
	}

	// Additional wait to ensure gRPC server is fully initialized
	time.Sleep(100 * time.Millisecond)

	// Verify we can get the gRPC server instance
	grpcSrv := server.GRPCServer()
	if grpcSrv == nil {
		t.Error("GRPCServer() returned nil")
	}

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Check for server errors
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Timeout is OK, server stopped
	}
}

func TestGRPCServer_StartExistingSocket(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	// Create an existing socket file
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("Failed to create socket file: %v", err)
	}
	_ = f.Close()

	// Get initial file info
	initialInfo, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Failed to stat initial socket file: %v", err)
	}

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	// Start server in goroutine - should remove existing file
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for socket to be recreated (new socket will have different inode)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		newInfo, err := os.Stat(socketPath)
		if err == nil && !os.SameFile(initialInfo, newInfo) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Additional wait to ensure gRPC server is assigned
	time.Sleep(100 * time.Millisecond)

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGRPCServer_StopWithoutStart(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cfg := &GRPCConfig{
		SocketPath: filepath.Join(tmpDir, "test-grpc.sock"),
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	// Stop server without starting - should not error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGRPCServer_StartInvalidSocketPath(t *testing.T) {
	// Use a path under /dev/null which cannot have subdirectories
	cfg := &GRPCConfig{
		SocketPath: "/dev/null/test-grpc.sock",
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	err = server.Start()
	if err == nil {
		_ = server.Stop(context.Background())
		t.Error("Expected error when creating socket with invalid path")
	}
}

func TestGRPCServer_ClientConnection(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for socket file to exist
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Additional wait to ensure server is ready
	time.Sleep(100 * time.Millisecond)

	// Create a client connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		_ = server.Stop(context.Background())
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Create a client
	client := pb.NewKeystoreServiceClient(conn)

	// Make a simple Health RPC call
	healthReq := &pb.HealthRequest{}
	healthResp, err := client.Health(ctx, healthReq)
	if err != nil {
		_ = server.Stop(context.Background())
		t.Fatalf("Health RPC failed: %v", err)
	}

	if healthResp.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", healthResp.Status)
	}

	// Stop server
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	if err := server.Stop(stopCtx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGRPCServer_MultipleClients(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Wait for socket
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	// Create multiple clients
	numClients := 5
	doneCh := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func(clientID int) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := grpc.NewClient("unix://"+socketPath,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				doneCh <- err
				return
			}
			defer func() { _ = conn.Close() }()

			client := pb.NewKeystoreServiceClient(conn)

			// Make Health RPC call
			_, err = client.Health(ctx, &pb.HealthRequest{})
			doneCh <- err
		}(i)
	}

	// Wait for all clients to finish
	for i := 0; i < numClients; i++ {
		select {
		case err := <-doneCh:
			if err != nil {
				t.Errorf("Client %d error: %v", i, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("Client %d timed out", i)
		}
	}

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGRPCServer_GracefulStopTimeout(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Wait for socket
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	// Stop server with a very short timeout to trigger timeout path
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Should not return error even on timeout
	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGRPCServer_SocketPermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath: socketPath,
		SocketMode: 0640,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Wait for socket
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Check socket permissions
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Failed to stat socket: %v", err)
	}

	mode := info.Mode() & os.ModePerm
	if mode != 0640 {
		t.Errorf("Socket permissions = %o, want 0640", mode)
	}

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGRPCServer_MessageSizeLimits(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	// Set small message size limits for testing
	cfg := &GRPCConfig{
		SocketPath:     socketPath,
		MaxRecvMsgSize: 1024, // 1KB
		MaxSendMsgSize: 1024, // 1KB
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	if server.config.MaxRecvMsgSize != 1024 {
		t.Errorf("MaxRecvMsgSize = %v, want 1024", server.config.MaxRecvMsgSize)
	}

	if server.config.MaxSendMsgSize != 1024 {
		t.Errorf("MaxSendMsgSize = %v, want 1024", server.config.MaxSendMsgSize)
	}

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Wait for socket
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGRPCServer_ConcurrentStreamLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keychain-grpc-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "test-grpc.sock")

	cfg := &GRPCConfig{
		SocketPath:           socketPath,
		MaxConcurrentStreams: 10,
	}

	server, err := NewGRPCServer(cfg)
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}

	if server.config.MaxConcurrentStreams != 10 {
		t.Errorf("MaxConcurrentStreams = %v, want 10", server.config.MaxConcurrentStreams)
	}

	// Start server
	go func() {
		_ = server.Start()
	}()

	// Wait for socket
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}
