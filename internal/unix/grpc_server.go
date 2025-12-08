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

// Package unix provides Unix domain socket servers for local IPC.
package unix

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	grpcinternal "github.com/jeremyhahn/go-keychain/internal/grpc"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
)

// GRPCConfig holds the gRPC Unix socket server configuration
type GRPCConfig struct {
	// SocketPath is the path to the Unix socket file
	SocketPath string

	// SocketMode is the file mode for the socket (default: 0660)
	SocketMode os.FileMode

	// Logger is the logging adapter
	Logger logger.Logger

	// MaxRecvMsgSize is the maximum message size the server can receive (default: 4MB)
	MaxRecvMsgSize int

	// MaxSendMsgSize is the maximum message size the server can send (default: 4MB)
	MaxSendMsgSize int

	// ConnectionTimeout is the maximum duration for connection establishment
	ConnectionTimeout time.Duration

	// MaxConcurrentStreams is the maximum number of concurrent streams per connection
	MaxConcurrentStreams uint32
}

// GRPCServer represents a gRPC server listening on a Unix domain socket
type GRPCServer struct {
	config   *GRPCConfig
	server   *grpc.Server
	listener net.Listener
	logger   logger.Logger
	mu       sync.RWMutex
}

// NewGRPCServer creates a new gRPC Unix socket server
func NewGRPCServer(cfg *GRPCConfig) (*GRPCServer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}

	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0660
	}

	if cfg.Logger == nil {
		// Create a no-op logger that does nothing
		cfg.Logger = &noOpLogger{}
	}

	if cfg.MaxRecvMsgSize == 0 {
		cfg.MaxRecvMsgSize = 4 * 1024 * 1024 // 4MB default
	}

	if cfg.MaxSendMsgSize == 0 {
		cfg.MaxSendMsgSize = 4 * 1024 * 1024 // 4MB default
	}

	if cfg.ConnectionTimeout == 0 {
		cfg.ConnectionTimeout = 120 * time.Second
	}

	if cfg.MaxConcurrentStreams == 0 {
		cfg.MaxConcurrentStreams = 100
	}

	s := &GRPCServer{
		config: cfg,
		logger: cfg.Logger,
	}

	return s, nil
}

// Start starts the gRPC Unix socket server
func (s *GRPCServer) Start() error {
	// Ensure the socket directory exists
	socketDir := filepath.Dir(s.config.SocketPath)
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if present
	if err := os.Remove(s.config.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.config.SocketPath, s.config.SocketMode); err != nil {
		_ = s.listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.logger.Info("gRPC Unix socket created", logger.String("path", s.config.SocketPath))

	// Create gRPC server with options
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.config.MaxSendMsgSize),
		grpc.ConnectionTimeout(s.config.ConnectionTimeout),
		grpc.MaxConcurrentStreams(s.config.MaxConcurrentStreams),
	}

	s.mu.Lock()
	s.server = grpc.NewServer(opts...)

	// Register the keystore service
	// Uses the global keychain service for backend management
	service := grpcinternal.NewService()
	pb.RegisterKeystoreServiceServer(s.server, service)
	s.mu.Unlock()

	s.logger.Info("Starting gRPC Unix socket server", logger.String("socket", s.config.SocketPath))

	// Start serving
	if err := s.server.Serve(s.listener); err != nil {
		return fmt.Errorf("gRPC Unix socket server error: %w", err)
	}

	return nil
}

// Stop gracefully stops the gRPC Unix socket server
func (s *GRPCServer) Stop(ctx context.Context) error {
	s.logger.Info("Stopping gRPC Unix socket server...")

	s.mu.RLock()
	srv := s.server
	s.mu.RUnlock()

	if srv != nil {
		// Create a channel to signal when graceful stop completes
		stopped := make(chan struct{})

		go func() {
			srv.GracefulStop()
			close(stopped)
		}()

		// Wait for graceful stop or context cancellation
		select {
		case <-stopped:
			s.logger.Info("gRPC server stopped gracefully")
		case <-ctx.Done():
			s.logger.Warn("gRPC server graceful stop timeout, forcing shutdown")
			srv.Stop()
		}
	}

	// Remove socket file
	if err := os.Remove(s.config.SocketPath); err != nil && !os.IsNotExist(err) {
		s.logger.Warn("Failed to remove socket file", logger.Error(err))
	}

	s.logger.Info("gRPC Unix socket server stopped")
	return nil
}

// SocketPath returns the path to the Unix socket
func (s *GRPCServer) SocketPath() string {
	return s.config.SocketPath
}

// GRPCServer returns the underlying gRPC server instance
func (s *GRPCServer) GRPCServer() *grpc.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.server
}
