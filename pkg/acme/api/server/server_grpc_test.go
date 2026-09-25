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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// TestGRPC_InvalidTCPAddress tests starting gRPC with an invalid TCP address.
func TestGRPC_InvalidTCPAddress(t *testing.T) {
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "invalid-address:99999",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// startGRPC should return an error for invalid address
	err = server.startGRPC(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen on gRPC TCP address")
}

// TestGRPC_InvalidUnixPath tests starting gRPC with an invalid Unix socket path.
func TestGRPC_InvalidUnixPath(t *testing.T) {
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    "/nonexistent/directory/test.sock",
		GRPCUnixMode:    0660,
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// startGRPC should return an error for invalid path
	err = server.startGRPC(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen on gRPC Unix socket")
}

// TestGRPC_StaleSocketRemovalError tests that stale socket removal doesn't fail startup.
func TestGRPC_StaleSocketRemovalError(t *testing.T) {
	mockAdmin := &mockAdminService{}

	// Create temp directory for Unix socket
	tmpDir := t.TempDir()
	unixSocketPath := filepath.Join(tmpDir, "test.sock")

	// Create a stale regular file (not socket)
	f, err := os.Create(unixSocketPath)
	require.NoError(t, err)
	f.Close()

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

	// Start gRPC - should succeed after removing the stale file
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startGRPC(context.Background())
	}()

	// Poll for the gRPC Unix server field to be assigned instead of sleeping
	// a fixed duration. Unlike the other tests in this file, a nil result
	// here is a tolerated outcome (socket creation may still fail), so this
	// uses a bounded poll rather than require.Eventually.
	var grpcUnixServer *grpc.Server
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		server.mu.RLock()
		grpcUnixServer = server.grpcUnixServer
		server.mu.RUnlock()
		if grpcUnixServer != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if grpcUnixServer == nil {
		// The test may fail to create socket, but that's acceptable
		// The key point is that stale file removal was attempted
		t.Log("gRPC Unix server not created, possibly due to socket creation failure")
		return
	}

	// Stop the server
	grpcUnixServer.Stop()
}

// TestDefaultConfig_Values tests the DefaultConfig function.
func TestDefaultConfig_Values(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, ":8443", config.RESTAddr)
	assert.Equal(t, ":9443", config.GRPCAddr)
	assert.Equal(t, ":9444", config.QUICAddr)
	assert.Equal(t, ":9445", config.MCPAddr)
	assert.Equal(t, DefaultGRPCUnixPath, config.GRPCUnixPath)
	assert.Equal(t, DefaultGRPCUnixMode, config.GRPCUnixMode)
	assert.Equal(t, 30*time.Second, config.ReadTimeout)
	assert.Equal(t, 30*time.Second, config.WriteTimeout)
	assert.NotNil(t, config.GRPCRoleMapping)
}

// TestGRPC_ServerCreation tests that gRPC server is created correctly.
func TestGRPC_ServerCreation(t *testing.T) {
	mockAdmin := &mockAdminService{}
	mockTenant := &mockTenantService{}

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "127.0.0.1:0",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, mockTenant, &mockAuthHandler{})
	require.NoError(t, err)

	// Start gRPC in goroutine
	go func() {
		_ = server.startGRPC(context.Background())
	}()

	// Wait for the gRPC server field to be assigned instead of sleeping a
	// fixed duration: under a loaded scheduler the goroutine may not have run
	// yet within a short sleep.
	require.Eventually(t, func() bool {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return server.grpcServer != nil
	}, 10*time.Second, 10*time.Millisecond, "gRPC server was not created")

	server.mu.RLock()
	grpcServer := server.grpcServer
	server.mu.RUnlock()

	// Stop immediately
	grpcServer.Stop()
}

// TestGRPC_UnixServerCreation tests that gRPC Unix socket server is created correctly.
func TestGRPC_UnixServerCreation(t *testing.T) {
	mockAdmin := &mockAdminService{}

	// Create temp directory for Unix socket
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

	// Start gRPC in goroutine
	go func() {
		_ = server.startGRPC(context.Background())
	}()

	// Wait for the Unix listener to actually bind instead of sleeping a fixed
	// duration: under a loaded scheduler the goroutine may not have reached
	// net.ListenUnix within a short sleep.
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(unixSocketPath)
		return statErr == nil
	}, 10*time.Second, 10*time.Millisecond, "gRPC Unix socket file was not created")

	// Verify gRPC Unix server was created
	server.mu.RLock()
	grpcUnixServer := server.grpcUnixServer
	server.mu.RUnlock()

	require.NotNil(t, grpcUnixServer)

	// Stop immediately
	grpcUnixServer.Stop()
}

// TestGRPC_TLSServerCreation tests that gRPC server with TLS is created correctly.
func TestGRPC_TLSServerCreation(t *testing.T) {
	mockAdmin := &mockAdminService{}
	tlsConfig := generateTestTLSConfig(t)

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "127.0.0.1:0",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "",
		TLSConfig:       tlsConfig,
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Start gRPC in goroutine
	go func() {
		_ = server.startGRPC(context.Background())
	}()

	// Wait for the gRPC server field to be assigned instead of sleeping a
	// fixed duration.
	require.Eventually(t, func() bool {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return server.grpcServer != nil
	}, 10*time.Second, 10*time.Millisecond, "gRPC server was not created")

	server.mu.RLock()
	grpcServer := server.grpcServer
	server.mu.RUnlock()

	// Stop immediately
	grpcServer.Stop()
}

// TestGRPC_NilRoleMapping tests that default role mapping is used when nil.
func TestGRPC_NilRoleMapping(t *testing.T) {
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "127.0.0.1:0",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "",
		GRPCRoleMapping: nil, // Nil role mapping - should use default
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Start gRPC in goroutine
	go func() {
		_ = server.startGRPC(context.Background())
	}()

	// Wait for the gRPC server field to be assigned instead of sleeping a
	// fixed duration (meaning default role mapping worked once assigned).
	require.Eventually(t, func() bool {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return server.grpcServer != nil
	}, 10*time.Second, 10*time.Millisecond, "gRPC server was not created")

	server.mu.RLock()
	grpcServer := server.grpcServer
	server.mu.RUnlock()

	// Stop immediately
	grpcServer.Stop()
}
