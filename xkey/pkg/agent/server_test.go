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
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0" // Use ephemeral port.
	enrollment, _ := testEnrollmentService(t)

	server, err := NewServer(cfg, enrollment, testLogger())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return server
}

func TestNewServer_NilConfig(t *testing.T) {
	enrollment, _ := testEnrollmentService(t)
	_, err := NewServer(nil, enrollment, testLogger())
	if !errors.Is(err, ErrNilConfig) {
		t.Errorf("expected ErrNilConfig, got %v", err)
	}
}

func TestNewServer_NilEnrollment(t *testing.T) {
	_, err := NewServer(DefaultConfig(), nil, testLogger())
	if !errors.Is(err, ErrNilEnrollmentService) {
		t.Errorf("expected ErrNilEnrollmentService, got %v", err)
	}
}

func TestNewServer_NilLogger(t *testing.T) {
	enrollment, _ := testEnrollmentService(t)
	_, err := NewServer(DefaultConfig(), enrollment, nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestServer_StartStop(t *testing.T) {
	server := testServer(t)

	if server.IsRunning() {
		t.Error("server should not be running before Start")
	}

	if err := server.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if !server.IsRunning() {
		t.Error("server should be running after Start")
	}

	addr := server.Addr()
	if addr == "" {
		t.Error("server should have an address after Start")
	}

	// Allow the goroutine to start.
	time.Sleep(50 * time.Millisecond)

	if err := server.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	if server.IsRunning() {
		t.Error("server should not be running after Stop")
	}
}

func TestServer_DoubleStart(t *testing.T) {
	server := testServer(t)

	if err := server.Start(); err != nil {
		t.Fatalf("first start failed: %v", err)
	}
	defer server.Stop()

	err := server.Start()
	if !errors.Is(err, ErrServerAlreadyRunning) {
		t.Errorf("expected ErrServerAlreadyRunning, got %v", err)
	}
}

func TestServer_StopWithoutStart(t *testing.T) {
	server := testServer(t)

	err := server.Stop()
	if !errors.Is(err, ErrServerNotStarted) {
		t.Errorf("expected ErrServerNotStarted, got %v", err)
	}
}

func TestServer_ConnectedAgents_Empty(t *testing.T) {
	server := testServer(t)

	if err := server.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer server.Stop()

	agents := server.ConnectedAgents()
	if len(agents) != 0 {
		t.Errorf("expected no connected agents, got %d", len(agents))
	}
}

func TestServer_Addr_NotStarted(t *testing.T) {
	server := testServer(t)
	if server.Addr() != "" {
		t.Error("addr should be empty when not started")
	}
}

func TestServer_UpdateAgentActivity(t *testing.T) {
	server := testServer(t)

	if err := server.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer server.Stop()

	// Simulate agent activity.
	server.updateAgentActivity("192.168.1.100:12345")

	agents := server.ConnectedAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 connected agent, got %d", len(agents))
	}
	if agents[0].Info.Address != "192.168.1.100:12345" {
		t.Errorf("expected address 192.168.1.100:12345, got %q", agents[0].Info.Address)
	}

	// Update again should update last activity.
	first := agents[0].LastActivity
	time.Sleep(10 * time.Millisecond)
	server.updateAgentActivity("192.168.1.100:12345")

	agents = server.ConnectedAgents()
	if !agents[0].LastActivity.After(first) {
		t.Error("last activity should have been updated")
	}
}

func TestServer_BuildTLSConfig_NoCerts(t *testing.T) {
	server := testServer(t)

	tlsConfig, err := server.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig != nil {
		t.Error("TLS config should be nil when no cert files are configured")
	}
}

func TestServer_BuildTLSConfig_InvalidCerts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(cfg, enrollment, testLogger())

	_, err := server.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
}
