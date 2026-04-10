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

package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

// createTestServer creates a test server with a mock agent.
func createTestServer(t *testing.T, socketPath string) (*Server, *MockClient) {
	t.Helper()

	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ag := &XKMSAgent{
		client:       mockClient,
		backend:      "software",
		requireTouch: false,
		touchHandler: &NoOpTouchHandler{},
		logger:       logger,
		keyCache:     make(map[string]*cachedKey),
	}

	server, err := NewServer(ag, &ServerConfig{
		SocketPath: socketPath,
		Logger:     logger,
	})
	require.NoError(t, err)

	return server, mockClient
}

func TestNewServer(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)
	defer server.Close()

	assert.NotNil(t, server)
	assert.Equal(t, socketPath, server.SocketPath())
}

func TestNewServer_NilConfig(t *testing.T) {
	mockClient := NewMockClient()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ag := &XKMSAgent{
		client:       mockClient,
		backend:      "software",
		requireTouch: false,
		touchHandler: &NoOpTouchHandler{},
		logger:       logger,
		keyCache:     make(map[string]*cachedKey),
	}

	// NewServer with nil config should use defaults
	server, err := NewServer(ag, nil)
	require.NoError(t, err)
	defer server.Close()

	// Should use default socket path
	assert.Contains(t, server.SocketPath(), "xkey")
	assert.Contains(t, server.SocketPath(), "ssh-agent.sock")
}

func TestNewServer_CustomSocketPath(t *testing.T) {
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "custom", "agent.sock")

	mockClient := NewMockClient()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ag := &XKMSAgent{
		client:       mockClient,
		backend:      "software",
		requireTouch: false,
		touchHandler: &NoOpTouchHandler{},
		logger:       logger,
		keyCache:     make(map[string]*cachedKey),
	}

	server, err := NewServer(ag, &ServerConfig{
		SocketPath: customPath,
	})
	require.NoError(t, err)
	defer server.Close()

	assert.Equal(t, customPath, server.SocketPath())
}

func TestNewServer_StaleSocketRemoval(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "stale.sock")

	// Create a stale socket file (not actually listening)
	f, err := os.Create(socketPath)
	require.NoError(t, err)
	f.Close()

	// NewServer should remove the stale socket
	server, _ := createTestServer(t, socketPath)
	defer server.Close()

	assert.NotNil(t, server)
}

func TestNewServer_AlreadyRunning(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "running.sock")

	// Create first server
	server1, _ := createTestServer(t, socketPath)
	defer server1.Close()

	// Start serving in background
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		server1.Serve(ctx)
	}()
	defer cancel()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Try to create second server on same socket
	mockClient := NewMockClient()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ag := &XKMSAgent{
		client:       mockClient,
		backend:      "software",
		requireTouch: false,
		touchHandler: &NoOpTouchHandler{},
		logger:       logger,
		keyCache:     make(map[string]*cachedKey),
	}

	_, err := NewServer(ag, &ServerConfig{
		SocketPath: socketPath,
	})
	assert.ErrorIs(t, err, ErrAgentAlreadyRunning)
}

func TestServer_SocketPath(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)
	defer server.Close()

	assert.Equal(t, socketPath, server.SocketPath())
}

func TestServer_PrintEnvBash(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)
	defer server.Close()

	bashEnv := server.PrintEnvBash()
	assert.Equal(t, "export SSH_AUTH_SOCK="+socketPath, bashEnv)
}

func TestServer_PrintEnvFish(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)
	defer server.Close()

	fishEnv := server.PrintEnvFish()
	assert.Equal(t, "set -gx SSH_AUTH_SOCK "+socketPath, fishEnv)
}

func TestServer_PrintEnvCsh(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)
	defer server.Close()

	cshEnv := server.PrintEnvCsh()
	assert.Equal(t, "setenv SSH_AUTH_SOCK "+socketPath, cshEnv)
}

func TestServer_Close(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	// Close should succeed
	err := server.Close()
	assert.NoError(t, err)

	// Socket file should be removed
	_, err = os.Stat(socketPath)
	assert.True(t, os.IsNotExist(err))
}

func TestServer_CloseIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	// Close multiple times should not panic
	err := server.Close()
	assert.NoError(t, err)

	err = server.Close()
	assert.NoError(t, err) // Should be nil, already closed
}

func TestServer_ServeAndClose(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())

	// Start serving in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop server
	cancel()

	// Wait for server to stop
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_ClientConnection(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start serving in background
	go func() {
		server.Serve(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect as SSH agent client
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Create agent client
	agentClient := agent.NewClient(conn)

	// List keys
	keys, err := agentClient.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "test-key", keys[0].Comment)
}

func TestServer_MultipleClientConnections(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start serving in background
	go func() {
		server.Serve(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect multiple clients
	const numClients = 5
	for i := 0; i < numClients; i++ {
		conn, err := net.Dial("unix", socketPath)
		require.NoError(t, err)

		agentClient := agent.NewClient(conn)

		keys, err := agentClient.List()
		require.NoError(t, err)
		assert.Len(t, keys, 1)

		conn.Close()
	}
}

func TestServer_ClientSignature(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start serving in background
	go func() {
		server.Serve(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect as SSH agent client
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	agentClient := agent.NewClient(conn)

	// List keys
	keys, err := agentClient.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	// Sign data
	data := []byte("test data to sign")
	sig, err := agentClient.Sign(keys[0], data)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
}

func TestServer_ConcurrentRequests(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start serving in background
	go func() {
		server.Serve(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Run concurrent requests
	const numGoroutines = 10
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			conn, err := net.Dial("unix", socketPath)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()

			agentClient := agent.NewClient(conn)
			_, err = agentClient.List()
			errCh <- err
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errCh
		assert.NoError(t, err)
	}
}

func TestDefaultSocketPath_XDGRuntime(t *testing.T) {
	// Save original env
	originalXDG := os.Getenv("XDG_RUNTIME_DIR")
	defer os.Setenv("XDG_RUNTIME_DIR", originalXDG)

	// Set XDG_RUNTIME_DIR
	os.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	path := DefaultSocketPath()
	assert.Equal(t, "/run/user/1000/xkey/ssh-agent.sock", path)
}

func TestDefaultSocketPath_Fallback(t *testing.T) {
	// Save original env
	originalXDG := os.Getenv("XDG_RUNTIME_DIR")
	defer os.Setenv("XDG_RUNTIME_DIR", originalXDG)

	// Unset XDG_RUNTIME_DIR
	os.Unsetenv("XDG_RUNTIME_DIR")

	path := DefaultSocketPath()
	assert.Contains(t, path, "xkey")
	assert.Contains(t, path, "ssh-agent.sock")
}

func TestNewServer_InvalidDirectory(t *testing.T) {
	// Try to create socket in a non-writable directory
	// This test is skipped if running as root
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}

	mockClient := NewMockClient()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ag := &XKMSAgent{
		client:       mockClient,
		backend:      "software",
		requireTouch: false,
		touchHandler: &NoOpTouchHandler{},
		logger:       logger,
		keyCache:     make(map[string]*cachedKey),
	}

	_, err := NewServer(ag, &ServerConfig{
		SocketPath: "/nonexistent/directory/test.sock",
	})
	assert.Error(t, err)
}

func TestServer_HandleConnectionDisconnect(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start serving in background
	go func() {
		server.Serve(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect and immediately close
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	conn.Close()

	// Give server time to handle disconnect
	time.Sleep(50 * time.Millisecond)

	// Server should still be running - connect again
	conn2, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn2.Close()

	agentClient := agent.NewClient(conn2)
	keys, err := agentClient.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

func TestServer_SocketPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)
	defer server.Close()

	// Check socket permissions (should be 0600)
	info, err := os.Stat(socketPath)
	require.NoError(t, err)

	mode := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), mode)
}

func TestServer_GracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())

	// Start serving in background
	doneCh := make(chan struct{})
	go func() {
		server.Serve(ctx)
		close(doneCh)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Open a connection
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for server to stop
	select {
	case <-doneCh:
		// Server stopped
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop in time")
	}

	// Connection should be closed
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	assert.Error(t, err) // Should get EOF or connection reset
	conn.Close()
}

func TestServer_LockUnlock(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server, _ := createTestServer(t, socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start serving in background
	go func() {
		server.Serve(ctx)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect as SSH agent client
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	agentClient := agent.NewClient(conn)

	// Lock the agent
	err = agentClient.Lock([]byte("passphrase"))
	require.NoError(t, err)

	// List should return empty when locked
	keys, err := agentClient.List()
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Unlock the agent
	err = agentClient.Unlock([]byte("passphrase"))
	require.NoError(t, err)

	// List should return keys again
	keys, err = agentClient.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}
