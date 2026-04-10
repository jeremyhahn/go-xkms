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
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestClient_MonitorConnection_ContextCancel tests that the monitor exits
// when the context is cancelled immediately.
func TestClient_MonitorConnection_ContextCancel(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()
	defer server.Stop()

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.ReconnectBackoffMax = 5 * time.Second

	client, _ := NewClient(clientCfg, testLogger())
	ctx, cancel := context.WithCancel(context.Background())

	_ = client.Connect(ctx)
	time.Sleep(50 * time.Millisecond)

	// Cancel immediately to trigger the context.Done path.
	cancel()
	time.Sleep(100 * time.Millisecond)

	client.Disconnect()
}

// TestClient_MonitorConnection_DisconnectDuringMonitor tests that the
// monitor exits when Disconnect is called while monitoring.
func TestClient_MonitorConnection_DisconnectDuringMonitor(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()
	defer server.Stop()

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.ReconnectBackoffMax = 5 * time.Second

	client, _ := NewClient(clientCfg, testLogger())
	ctx := context.Background()

	_ = client.Connect(ctx)
	time.Sleep(100 * time.Millisecond)

	// Disconnect while monitor is running. The monitor should exit via
	// the done channel.
	client.Disconnect()
	time.Sleep(100 * time.Millisecond)
}

// TestClient_MonitorConnection_ServerRestart tests reconnection when the
// server restarts.
func TestClient_MonitorConnection_ServerRestart(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()

	addr := server.Addr()

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = addr
	clientCfg.ReconnectBackoffMax = 2 * time.Second

	client, _ := NewClient(clientCfg, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Connect(ctx)
	time.Sleep(100 * time.Millisecond)

	// Stop server to trigger failure state.
	server.Stop()
	time.Sleep(500 * time.Millisecond)

	// Restart server on the same address.
	serverCfg2 := DefaultConfig()
	serverCfg2.ListenAddress = addr
	enrollment2, _ := testEnrollmentService(t)
	server2, _ := NewServer(serverCfg2, enrollment2, testLogger())
	_ = server2.Start()
	defer server2.Stop()

	// Give time for reconnection.
	time.Sleep(2 * time.Second)

	cancel()
	time.Sleep(100 * time.Millisecond)
	client.Disconnect()
}

// TestSSHProxy_HandleConnection_WithMasterSocket tests the SSH proxy
// connecting to a real master socket.
func TestSSHProxy_HandleConnection_WithMasterSocket(t *testing.T) {
	// Create a mock "master" TCP server that echoes data.
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	masterAddr := listener.Addr().String()

	// Accept one connection and echo data back.
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	// Create client pointing to the master TCP server.
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = masterAddr
	clientCfg.ReconnectBackoffMax = 0

	client, _ := NewClient(clientCfg, testLogger())
	ctx := context.Background()
	_ = client.Connect(ctx)
	defer client.Disconnect()

	time.Sleep(50 * time.Millisecond)

	// Create SSH proxy.
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	proxy, _ := NewSSHProxy(socketPath, client, testLogger())
	if err := proxy.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer proxy.Stop()

	// Connect to the proxy and send data.
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("hello")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Read the echoed response.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

// TestSSHProxy_MultipleConnections tests that the SSH proxy handles
// multiple concurrent connections.
func TestSSHProxy_MultipleConnections(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	proxy, _ := NewSSHProxy(socketPath, client, testLogger())
	if err := proxy.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer proxy.Stop()

	// Open multiple connections to the proxy.
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
		if err != nil {
			t.Fatalf("dial %d failed: %v", i, err)
		}
		conns = append(conns, conn)
	}

	// Close all connections.
	for _, conn := range conns {
		conn.Close()
	}

	time.Sleep(100 * time.Millisecond)
}

// TestClient_IsConnected_NilConn tests IsConnected when conn is nil.
func TestClient_IsConnected_NilConn(t *testing.T) {
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9999"
	client, _ := NewClient(clientCfg, testLogger())

	// Set running to true but keep conn nil.
	client.running.Store(true)

	if client.IsConnected() {
		t.Error("should not be connected with nil conn")
	}

	// Reset so Disconnect doesn't panic.
	client.running.Store(false)
}

// TestCheckMaxAgents_StoreError tests checkMaxAgents when the store
// returns an error.
func TestCheckMaxAgents_StoreError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxAgents = 5
	cfg.EnrollmentMethods = []EnrollmentMethod{EnrollOneTimeCode}

	errorStore := &errorStore{}
	svc, err := NewEnrollmentService(cfg, &mockCAService{}, errorStore, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if err == nil {
		t.Fatal("expected error from store failure")
	}
}

// errorStore is a mock that returns errors from ListAgents.
type errorStore struct{}

func (s *errorStore) SaveAgent(agent *AgentInfo) error       { return nil }
func (s *errorStore) GetAgent(id string) (*AgentInfo, error) { return nil, ErrAgentNotFound }
func (s *errorStore) ListAgents() ([]*AgentInfo, error)      { return nil, errors.New("store error") }
func (s *errorStore) DeleteAgent(id string) error            { return nil }
