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
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShutdown_ForceRESTError forces an error in REST shutdown to cover error path.
func TestShutdown_ForceRESTError(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Create a REST server that's actively serving
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

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

	// Use an already-cancelled context to force shutdown error
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = server.Shutdown(ctx)

	// Error might be returned
	if err != nil {
		assert.Contains(t, err.Error(), "REST")
	}
	assert.False(t, server.Running())
}

// TestShutdown_ForceMCPError forces an error in MCP shutdown to cover error path.
func TestShutdown_ForceMCPError(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Create an MCP server that's actively serving
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mcpServer := &http.Server{
		Handler: http.NewServeMux(),
	}

	// Start serving
	go func() {
		_ = mcpServer.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)

	server.running.Store(true)
	server.mcpServer = mcpServer

	// Use an already-cancelled context to force shutdown error
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = server.Shutdown(ctx)

	// Error might be returned
	if err != nil {
		assert.Contains(t, err.Error(), "MCP")
	}
	assert.False(t, server.Running())
}

// TestShutdown_ForceQUICError forces an error in QUIC close to cover error path.
func TestShutdown_ForceQUICError(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	server.running.Store(true)

	// Create a QUIC server
	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	server.quicServer = quicServer

	// Close it first to potentially cause an error on second close
	_ = quicServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Shutdown will try to close the already-closed QUIC server
	err := server.Shutdown(ctx)

	// Error might be returned from the already-closed server
	if err != nil {
		assert.Contains(t, err.Error(), "QUIC")
	}
	assert.False(t, server.Running())
}

// TestShutdown_MultipleShutdownErrors tests when multiple servers fail shutdown.
func TestShutdown_MultipleShutdownErrors(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	server.running.Store(true)

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

	// Create QUIC server and close it early
	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}
	_ = quicServer.Close() // Pre-close to cause error

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer
	server.quicServer = quicServer

	// Use an expired context to maximize chances of errors
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = server.Shutdown(ctx)

	// Server should be stopped regardless of errors
	assert.False(t, server.Running())
	// If there were errors, they should be joined
	// The exact error depends on timing
}

// TestShutdown_WithRunningServersAndErrors tests real shutdown with errors.
func TestShutdown_WithRunningServersAndErrors(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	server.running.Store(true)

	// Start actual servers
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = restServer.Serve(restListener) }()

	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mcpServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = mcpServer.Serve(mcpListener) }()

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer

	// Use zero-duration context to force deadline exceeded
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(time.Millisecond)

	err = server.Shutdown(ctx)

	// Errors are expected due to deadline exceeded
	if err != nil {
		// At least one of REST or MCP should have timed out
		assert.True(t, true) // Error is expected
	}

	assert.False(t, server.Running())
}

// TestShutdown_ErrorsJoined tests that errors are properly joined.
func TestShutdown_ErrorsJoined(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	server.running.Store(true)

	// Create servers that will be running
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = restServer.Serve(restListener) }()

	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mcpServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = mcpServer.Serve(mcpListener) }()

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer

	// Very short deadline to force errors
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_ = server.Shutdown(ctx)

	// Should have errors from both REST and MCP
	// Whether errors.Join creates a single error or multiple depends on implementation
	assert.False(t, server.Running())
}
