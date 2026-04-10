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
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testSSHProxyClient(t *testing.T) *Client {
	t.Helper()
	cfg := DefaultClientConfig()
	cfg.MasterAddress = "localhost:19999"
	cfg.ReconnectBackoffMax = 0
	client, err := NewClient(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}

func TestNewSSHProxy_Success(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	proxy, err := NewSSHProxy(socketPath, client, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("proxy should not be nil")
	}
}

func TestNewSSHProxy_EmptySocketPath(t *testing.T) {
	client := testSSHProxyClient(t)

	_, err := NewSSHProxy("", client, testLogger())
	if !errors.Is(err, ErrSocketPath) {
		t.Errorf("expected ErrSocketPath, got %v", err)
	}
}

func TestNewSSHProxy_NilClient(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")

	_, err := NewSSHProxy(socketPath, nil, testLogger())
	if !errors.Is(err, ErrNilClient) {
		t.Errorf("expected ErrNilClient, got %v", err)
	}
}

func TestNewSSHProxy_NilLogger(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	_, err := NewSSHProxy(socketPath, client, nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestSSHProxy_StartStop(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	proxy, err := NewSSHProxy(socketPath, client, testLogger())
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	if proxy.IsRunning() {
		t.Error("proxy should not be running before Start")
	}

	if err := proxy.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if !proxy.IsRunning() {
		t.Error("proxy should be running after Start")
	}

	if proxy.SocketPath() != socketPath {
		t.Errorf("expected socket path %q, got %q", socketPath, proxy.SocketPath())
	}

	// Verify socket file exists.
	if _, err := os.Stat(socketPath); err != nil {
		t.Errorf("socket file should exist: %v", err)
	}

	// Verify socket is accessible.
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		t.Errorf("should be able to connect to socket: %v", err)
	} else {
		conn.Close()
	}

	if err := proxy.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	if proxy.IsRunning() {
		t.Error("proxy should not be running after Stop")
	}

	// Verify socket file is removed.
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed after Stop")
	}
}

func TestSSHProxy_DoubleStart(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	proxy, _ := NewSSHProxy(socketPath, client, testLogger())
	if err := proxy.Start(); err != nil {
		t.Fatalf("first start failed: %v", err)
	}
	defer proxy.Stop()

	err := proxy.Start()
	if !errors.Is(err, ErrServerAlreadyRunning) {
		t.Errorf("expected ErrServerAlreadyRunning, got %v", err)
	}
}

func TestSSHProxy_StopWithoutStart(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	proxy, _ := NewSSHProxy(socketPath, client, testLogger())

	err := proxy.Stop()
	if !errors.Is(err, ErrServerNotStarted) {
		t.Errorf("expected ErrServerNotStarted, got %v", err)
	}
}

func TestSSHProxy_CreatesSocketDirectory(t *testing.T) {
	sockDir := filepath.Join(t.TempDir(), "sub", "deep")
	socketPath := filepath.Join(sockDir, "ssh-agent.sock")
	client := testSSHProxyClient(t)

	proxy, _ := NewSSHProxy(socketPath, client, testLogger())
	if err := proxy.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer proxy.Stop()

	info, err := os.Stat(sockDir)
	if err != nil {
		t.Fatalf("socket directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}

func TestSSHProxy_DetectsExistingSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	// Start first proxy.
	proxy1, _ := NewSSHProxy(socketPath, client, testLogger())
	if err := proxy1.Start(); err != nil {
		t.Fatalf("first start failed: %v", err)
	}
	defer proxy1.Stop()

	// Try to start another proxy on the same socket.
	proxy2, _ := NewSSHProxy(socketPath, client, testLogger())
	err := proxy2.Start()
	if !errors.Is(err, ErrServerAlreadyRunning) {
		t.Errorf("expected ErrServerAlreadyRunning for existing live socket, got %v", err)
	}
}

func TestSSHProxy_RemovesStaleSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")

	// Create a stale socket file (not a real listener).
	if err := os.WriteFile(socketPath, []byte("stale"), 0600); err != nil {
		t.Fatalf("failed to create stale socket: %v", err)
	}

	client := testSSHProxyClient(t)
	proxy, _ := NewSSHProxy(socketPath, client, testLogger())

	if err := proxy.Start(); err != nil {
		t.Fatalf("start should succeed after removing stale socket: %v", err)
	}
	defer proxy.Stop()

	if !proxy.IsRunning() {
		t.Error("proxy should be running after replacing stale socket")
	}
}
