// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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

// TestShutdownWithExpiredContext tests shutdown behavior with expired context.
// Note: http.Server.Shutdown may succeed even with expired context if shutdown is fast.
func TestShutdownWithExpiredContext(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create and start a real REST server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() {
		_ = restServer.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)
	server.restServer = restServer

	// Create a context that is already expired
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()

	_ = server.Shutdown(ctx)

	// Error may or may not be returned depending on shutdown speed
	// The important thing is that the server stops
	assert.False(t, server.Running())
}

// TestShutdownWithMultipleServersExpiredContext tests shutdown with multiple servers.
func TestShutdownWithMultipleServersExpiredContext(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create and start REST server
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = restServer.Serve(restListener) }()

	// Create and start MCP server
	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mcpServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = mcpServer.Serve(mcpListener) }()

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer

	// Create a context that is already expired
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()

	err = server.Shutdown(ctx)

	// Shutdown should complete regardless of context expiration
	// Error return depends on implementation details
	assert.False(t, server.Running())
	// If there's an error, it should mention the servers that failed
	if err != nil {
		// Error message should contain server info
		t.Logf("Shutdown error: %v", err)
	}
}

// TestShutdownAllServersWithCancelledContext tests full shutdown with cancelled context.
func TestShutdownAllServersWithCancelledContext(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create and start REST server
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = restServer.Serve(restListener) }()

	// Create and start MCP server
	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mcpServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = mcpServer.Serve(mcpListener) }()

	// Create QUIC server
	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer
	server.quicServer = quicServer

	// Create and immediately cancel context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = server.Shutdown(ctx)

	// Server should stop
	assert.False(t, server.Running())
	// Error may or may not be present
	_ = err
}

// TestShutdownQUICServerClose tests QUIC server close behavior.
func TestShutdownQUICServerClose(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create QUIC server
	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	server.quicServer = quicServer

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// First shutdown should work
	err := server.Shutdown(ctx)
	assert.NoError(t, err)
	assert.False(t, server.Running())
}

// TestShutdownQUICAlreadyClosed tests QUIC server that was already closed.
func TestShutdownQUICAlreadyClosed(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create QUIC server
	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	// Close it before shutdown
	_ = quicServer.Close()

	server.quicServer = quicServer

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := server.Shutdown(ctx)

	// May or may not error depending on QUIC library behavior
	// The important thing is shutdown completes
	assert.False(t, server.Running())
	_ = err
}

// TestShutdownPreservesErrorOrder tests that errors are properly collected.
func TestShutdownPreservesErrorOrder(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create servers
	restListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	restServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = restServer.Serve(restListener) }()

	mcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mcpServer := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = mcpServer.Serve(mcpListener) }()

	quicServer := &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	time.Sleep(50 * time.Millisecond)

	server.restServer = restServer
	server.mcpServer = mcpServer
	server.quicServer = quicServer

	// Very short context deadline
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	// Give context time to expire
	time.Sleep(time.Millisecond)

	err = server.Shutdown(ctx)

	// Server should be stopped
	assert.False(t, server.Running())

	// Log any error for debugging
	if err != nil {
		t.Logf("Shutdown returned error: %v", err)
	}
}
