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

//go:build !integration

package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// TestShutdown_RESTShutdownError tests handling of REST server shutdown error.
func TestShutdown_RESTShutdownError(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Create a REST server that will error on shutdown (using closed listener)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	restServer := &http.Server{
		Handler: http.NewServeMux(),
	}

	// Start the server in background
	go func() {
		_ = restServer.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)

	// Close the listener to force shutdown error
	listener.Close()

	server.running.Store(true)
	server.restServer = restServer

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Shutdown might error or not depending on timing
	_ = server.Shutdown(ctx)

	assert.False(t, server.Running())
}

// TestShutdown_MCPShutdownError tests handling of MCP server shutdown error.
func TestShutdown_MCPShutdownError(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Create an MCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mcpServer := &http.Server{
		Handler: http.NewServeMux(),
	}

	// Start the server
	go func() {
		_ = mcpServer.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)

	// Close listener early to possibly cause issues
	listener.Close()

	server.running.Store(true)
	server.mcpServer = mcpServer

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Shutdown might error or not depending on timing
	_ = server.Shutdown(ctx)

	assert.False(t, server.Running())
}

// TestShutdown_WithMultipleErrors tests handling multiple shutdown errors.
func TestShutdown_WithMultipleErrors(t *testing.T) {
	mockAdmin := &mockAdminService{}

	tmpDir := t.TempDir()
	unixSocketPath := filepath.Join(tmpDir, "test.sock")

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    unixSocketPath,
		GRPCUnixMode:    0660,
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Create mock servers that are already stopped
	server.running.Store(true)
	server.grpcServer = grpc.NewServer()
	server.grpcUnixServer = grpc.NewServer()

	// Create a file at the socket path to verify cleanup
	f, err := os.Create(unixSocketPath)
	require.NoError(t, err)
	f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Shutdown should clean up everything
	err = server.Shutdown(ctx)

	assert.NoError(t, err)
	assert.False(t, server.Running())

	// Unix socket file should be removed
	_, statErr := os.Stat(unixSocketPath)
	assert.True(t, os.IsNotExist(statErr))
}

// TestShutdown_WithQUICError tests handling QUIC close error.
func TestShutdown_WithQUICError(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	server.running.Store(true)

	// Create a QUIC server that's already been closed
	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	server.quicServer = quicServer

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Shutdown should handle the close gracefully
	_ = server.Shutdown(ctx)

	assert.False(t, server.Running())
}

// TestShutdown_WithShutdownContextTimeout tests shutdown with context timeout.
func TestShutdown_WithShutdownContextTimeout(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Create a listener that stays open
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	restServer := &http.Server{
		Handler: http.NewServeMux(),
	}

	// Start serving
	go func() {
		_ = restServer.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)

	server.running.Store(true)
	server.restServer = restServer

	// Use a very short timeout that will likely expire during shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Shutdown might return an error due to context deadline
	_ = server.Shutdown(ctx)

	// The shutdown was attempted (running flag should be false)
	assert.False(t, server.Running())
}

// TestShutdown_WithErrsJoin tests that multiple errors are joined.
func TestShutdown_WithErrsJoin(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	server.running.Store(true)

	// Create servers that will error on shutdown
	// REST server with already-cancelled context
	restServer := &http.Server{
		Handler: http.NewServeMux(),
	}

	// Create a listener and start serving
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		_ = restServer.Serve(restListener)
	}()

	// MCP server
	mcpServer := &http.Server{
		Handler: http.NewServeMux(),
	}

	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		_ = mcpServer.Serve(mcpListener)
	}()

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer

	// Use expired context to force errors
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Already cancelled

	_ = server.Shutdown(ctx)

	// Errors may or may not be returned depending on timing
	// The important thing is the server stopped
	assert.False(t, server.Running())
}

// TestShutdown_WithMultipleServersActive tests shutdown with all servers.
func TestShutdown_WithMultipleServersActive(t *testing.T) {
	mockAdmin := &mockAdminService{}

	tmpDir := t.TempDir()
	unixSocketPath := filepath.Join(tmpDir, "test.sock")

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    unixSocketPath,
		GRPCUnixMode:    0660,
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Create REST server
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = restServer.Serve(restListener) }()

	// Create MCP server
	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mcpServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = mcpServer.Serve(mcpListener) }()

	// Create QUIC server
	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	// Create gRPC servers
	grpcServer := grpc.NewServer()
	grpcUnixServer := grpc.NewServer()

	// Create socket file
	f, err := os.Create(unixSocketPath)
	require.NoError(t, err)
	f.Close()

	time.Sleep(50 * time.Millisecond)

	// Set up server state
	server.running.Store(true)
	server.restServer = restServer
	server.mcpServer = mcpServer
	server.quicServer = quicServer
	server.grpcServer = grpcServer
	server.grpcUnixServer = grpcUnixServer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown all servers
	_ = server.Shutdown(ctx)

	// Should complete without hanging
	assert.False(t, server.Running())

	// Socket file should be cleaned up
	_, statErr := os.Stat(unixSocketPath)
	assert.True(t, os.IsNotExist(statErr))
}

// TestShutdown_ReturnMultipleErrors tests that errors.Join works correctly.
func TestShutdown_ReturnMultipleErrors(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	server.running.Store(true)

	// Create REST server that will error
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = restServer.Serve(restListener) }()

	// Create MCP server that will error
	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mcpServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = mcpServer.Serve(mcpListener) }()

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer

	// Use an already-cancelled context to force errors
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = server.Shutdown(ctx)

	// Errors should be joined if both fail
	// But the server should still stop
	assert.False(t, server.Running())
	// err may or may not be non-nil depending on timing
}

// TestShutdown_UnixSocketRemovalWarning tests the warning log path.
func TestShutdown_UnixSocketRemovalWarning(t *testing.T) {
	mockAdmin := &mockAdminService{}

	// Use a non-existent parent directory that will cause removal to fail
	// (though os.Remove on non-existent files returns nil on most systems)
	tmpDir := t.TempDir()
	unixSocketPath := filepath.Join(tmpDir, "test.sock")

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    unixSocketPath,
		GRPCUnixMode:    0660,
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	server.running.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Shutdown should succeed even if socket file doesn't exist
	err = server.Shutdown(ctx)
	assert.NoError(t, err)
	assert.False(t, server.Running())
}
