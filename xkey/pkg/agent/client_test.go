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
	"testing"
	"time"
)

func TestNewClient_NilConfig(t *testing.T) {
	_, err := NewClient(nil, testLogger())
	if !errors.Is(err, ErrNilConfig) {
		t.Errorf("expected ErrNilConfig, got %v", err)
	}
}

func TestNewClient_NilLogger(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.MasterAddress = "localhost:9443"
	_, err := NewClient(cfg, nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestNewClient_Success(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.MasterAddress = "localhost:9443"
	client, err := NewClient(cfg, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestClient_ConnectToServer(t *testing.T) {
	// Start a real server to test connection.
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, err := NewServer(serverCfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	// Create and connect client.
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.ReconnectBackoffMax = 0 // Disable reconnection for test.

	client, err := NewClient(clientCfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Give gRPC time to establish connection.
	time.Sleep(100 * time.Millisecond)

	if !client.IsConnected() {
		t.Error("client should be connected")
	}

	if client.Connection() == nil {
		t.Error("connection should not be nil")
	}

	if err := client.Disconnect(); err != nil {
		t.Fatalf("disconnect failed: %v", err)
	}

	if client.IsConnected() {
		t.Error("client should not be connected after disconnect")
	}
}

func TestClient_DoubleConnect(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()
	defer server.Stop()

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.ReconnectBackoffMax = 0

	client, _ := NewClient(clientCfg, testLogger())
	ctx := context.Background()
	_ = client.Connect(ctx)
	defer client.Disconnect()

	err := client.Connect(ctx)
	if !errors.Is(err, ErrClientAlreadyConnected) {
		t.Errorf("expected ErrClientAlreadyConnected, got %v", err)
	}
}

func TestClient_DisconnectWithoutConnect(t *testing.T) {
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9999"
	client, _ := NewClient(clientCfg, testLogger())

	err := client.Disconnect()
	if !errors.Is(err, ErrClientNotConnected) {
		t.Errorf("expected ErrClientNotConnected, got %v", err)
	}
}

func TestClient_IsConnected_NotStarted(t *testing.T) {
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9999"
	client, _ := NewClient(clientCfg, testLogger())

	if client.IsConnected() {
		t.Error("should not be connected before Connect is called")
	}
}

func TestClient_Connection_NotConnected(t *testing.T) {
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9999"
	client, _ := NewClient(clientCfg, testLogger())

	if client.Connection() != nil {
		t.Error("connection should be nil before Connect")
	}
}

func TestClient_BuildDialOptions_Insecure(t *testing.T) {
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9999"
	client, _ := NewClient(clientCfg, testLogger())

	opts, err := client.buildDialOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) == 0 {
		t.Error("should have at least one dial option")
	}
}

func TestClient_BuildTLSConfig_InvalidCerts(t *testing.T) {
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = "localhost:9999"
	clientCfg.TLSCertFile = "/nonexistent/cert.pem"
	clientCfg.TLSKeyFile = "/nonexistent/key.pem"
	client, _ := NewClient(clientCfg, testLogger())

	_, err := client.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid TLS cert files")
	}
}
