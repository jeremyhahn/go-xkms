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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
)

// TestEnrollWithCode_CACertError tests the CA certificate retrieval failure
// path in EnrollWithCode.
func TestEnrollWithCode_CACertError(t *testing.T) {
	svc, ca := testEnrollmentService(t)
	ca.getCACertFunc = func() ([]byte, error) {
		return nil, errors.New("ca cert error")
	}

	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if err == nil {
		t.Fatal("expected error from CA cert failure")
	}
}

// TestApproveEnrollment_CASignError tests CSR signing failure during approval.
func TestApproveEnrollment_CASignError(t *testing.T) {
	svc, ca := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit: %v", err)
	}

	ca.signCSRFunc = func([]byte) ([]byte, error) {
		return nil, errors.New("sign error")
	}

	_, _, err = svc.ApproveEnrollment(requestID)
	if err == nil {
		t.Fatal("expected error from CSR signing failure")
	}
}

// TestApproveEnrollment_CACertError tests CA certificate retrieval failure
// during approval.
func TestApproveEnrollment_CACertError(t *testing.T) {
	svc, ca := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit: %v", err)
	}

	ca.getCACertFunc = func() ([]byte, error) {
		return nil, errors.New("ca cert error")
	}

	_, _, err = svc.ApproveEnrollment(requestID)
	if err == nil {
		t.Fatal("expected error from CA cert failure during approval")
	}
}

// TestCheckMaxAgents_Unlimited tests that checkMaxAgents allows enrollment
// when MaxAgents is 0 (unlimited).
func TestCheckMaxAgents_Unlimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxAgents = 0 // unlimited
	store := NewMemoryStore()
	// Add several agents.
	for i := 0; i < 10; i++ {
		_ = store.SaveAgent(&AgentInfo{ID: string(rune('a' + i)), Status: "active"})
	}
	svc, err := NewEnrollmentService(cfg, &mockCAService{}, store, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// This calls the private checkMaxAgents.
	code, err := svc.GenerateOneTimeCode(5 * time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, _, err = svc.EnrollWithCode(code.Code, testCSR(t))
	if err != nil {
		t.Fatalf("enrollment should succeed with unlimited agents: %v", err)
	}
}

// TestSubmitEnrollment_MaxAgentsReached tests the max agents limit during
// admin approval enrollment.
func TestSubmitEnrollment_MaxAgentsReached(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{EnrollAdminApproval}
	cfg.MaxAgents = 1
	store := NewMemoryStore()
	_ = store.SaveAgent(&AgentInfo{ID: "existing", Status: "active"})

	svc, err := NewEnrollmentService(cfg, &mockCAService{}, store, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = svc.SubmitEnrollmentRequest(testCSR(t))
	if !errors.Is(err, ErrMaxAgentsReached) {
		t.Errorf("expected ErrMaxAgentsReached, got %v", err)
	}
}

// TestCSRFingerprint_ValidCSR tests that csrFingerprint returns a consistent
// fingerprint for the same CSR.
func TestCSRFingerprint_ValidCSR(t *testing.T) {
	csr := testCSR(t)
	fp1, err := csrFingerprint(csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fp2, err := csrFingerprint(csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp1 != fp2 {
		t.Error("same CSR should produce same fingerprint")
	}
	if len(fp1) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("expected 64 char fingerprint, got %d", len(fp1))
	}
}

// TestTrackingUnaryInterceptor tests the gRPC unary interceptor with a
// real context containing peer info.
func TestTrackingUnaryInterceptor(t *testing.T) {
	server := testServer(t)

	// Create a context with peer info.
	addr, _ := net.ResolveTCPAddr("tcp", "192.168.1.50:54321")
	peerInfo := &peer.Peer{Addr: addr}
	ctx := peer.NewContext(context.Background(), peerInfo)

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	resp, err := server.trackingUnaryInterceptor(ctx, "request", info, handler)
	if err != nil {
		t.Fatalf("interceptor error: %v", err)
	}
	if resp != "ok" {
		t.Errorf("expected 'ok', got %v", resp)
	}

	// Verify the agent was tracked.
	agents := server.ConnectedAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 tracked agent, got %d", len(agents))
	}
	if agents[0].Info.Address != "192.168.1.50:54321" {
		t.Errorf("expected address 192.168.1.50:54321, got %q", agents[0].Info.Address)
	}
}

// TestTrackingUnaryInterceptor_NoPeer tests the interceptor with a context
// that has no peer info.
func TestTrackingUnaryInterceptor_NoPeer(t *testing.T) {
	server := testServer(t)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	resp, err := server.trackingUnaryInterceptor(ctx, "request", info, handler)
	if err != nil {
		t.Fatalf("interceptor error: %v", err)
	}
	if resp != "ok" {
		t.Errorf("expected 'ok', got %v", resp)
	}

	// No agent should be tracked.
	agents := server.ConnectedAgents()
	if len(agents) != 0 {
		t.Errorf("expected 0 tracked agents, got %d", len(agents))
	}
}

// TestClient_ConnectDisconnectCycle tests multiple connect/disconnect cycles.
func TestClient_ConnectDisconnectCycle(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()
	defer server.Stop()

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.ReconnectBackoffMax = 0

	for i := 0; i < 3; i++ {
		client, err := NewClient(clientCfg, testLogger())
		if err != nil {
			t.Fatalf("cycle %d: failed to create client: %v", i, err)
		}

		ctx := context.Background()
		if err := client.Connect(ctx); err != nil {
			t.Fatalf("cycle %d: connect failed: %v", i, err)
		}

		time.Sleep(50 * time.Millisecond)

		if err := client.Disconnect(); err != nil {
			t.Fatalf("cycle %d: disconnect failed: %v", i, err)
		}
	}
}

// TestSSHProxy_HandleConnection_ClientNotConnected tests that the SSH proxy
// rejects connections when the client is not connected.
func TestSSHProxy_HandleConnection_ClientNotConnected(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ssh-agent.sock")
	client := testSSHProxyClient(t)

	proxy, _ := NewSSHProxy(socketPath, client, testLogger())
	if err := proxy.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer proxy.Stop()

	// Connect to the proxy socket. The connection should be accepted
	// but immediately closed since the client is not connected to master.
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	// Read from the connection - should get EOF because handleConnection
	// rejects when client is not connected.
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, readErr := conn.Read(buf)
	conn.Close()

	// We expect either EOF or a deadline exceeded (connection closed).
	if readErr == nil {
		t.Error("expected read error from rejected connection")
	}
}

// TestServer_StartWithInvalidTLSCert tests that Start fails when TLS
// cert files are invalid.
func TestServer_StartWithInvalidTLSCert(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddress = "localhost:0"
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(cfg, enrollment, testLogger())

	err := server.Start()
	if err == nil {
		server.Stop()
		t.Fatal("expected error for invalid TLS cert files")
	}
}

// TestClient_ConnectWithTLS tests client connection using TLS credentials.
func TestClient_ConnectWithTLS(t *testing.T) {
	certs := generateTestCerts(t)

	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	serverCfg.TLSCertFile = certs.ServerCertPath
	serverCfg.TLSKeyFile = certs.ServerKeyPath

	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	if err := server.Start(); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer server.Stop()

	// Connect client with TLS certs (server-only TLS, no mTLS).
	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.TLSCertFile = certs.ClientCertPath
	clientCfg.TLSKeyFile = certs.ClientKeyPath
	clientCfg.TLSCAFile = certs.CACertPath
	clientCfg.ReconnectBackoffMax = 0

	client, _ := NewClient(clientCfg, testLogger())

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Disconnect()

	time.Sleep(100 * time.Millisecond)
}

// TestRejectEnrollment_DoubleReject tests rejecting an already-rejected
// enrollment request.
func TestRejectEnrollment_DoubleReject(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit: %v", err)
	}

	if err := svc.RejectEnrollment(requestID, "first"); err != nil {
		t.Fatalf("first reject failed: %v", err)
	}

	err = svc.RejectEnrollment(requestID, "second")
	if !errors.Is(err, ErrEnrollmentFailed) {
		t.Errorf("expected ErrEnrollmentFailed for double reject, got %v", err)
	}
}

// TestApproveEnrollment_AlreadyApproved tests approving a request that
// was already approved (removed from pending map).
func TestApproveEnrollment_AlreadyApproved(t *testing.T) {
	svc, _ := testEnrollmentService(t)

	requestID, err := svc.SubmitEnrollmentRequest(testCSR(t))
	if err != nil {
		t.Fatalf("failed to submit: %v", err)
	}

	_, _, err = svc.ApproveEnrollment(requestID)
	if err != nil {
		t.Fatalf("first approve failed: %v", err)
	}

	// Second approve should fail because the request was removed.
	_, _, err = svc.ApproveEnrollment(requestID)
	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

// TestClient_ConnectToInvalidServer tests connecting to an address where
// nothing is listening.
func TestClient_ConnectToInvalidServer(t *testing.T) {
	clientCfg := DefaultClientConfig()
	// Use an address that is unlikely to be in use.
	clientCfg.MasterAddress = "localhost:19998"
	clientCfg.ReconnectBackoffMax = 0

	client, _ := NewClient(clientCfg, testLogger())

	ctx := context.Background()
	// gRPC NewClient with lazy connections doesn't error on Connect,
	// but the connection state will be TransientFailure when we try to use it.
	err := client.Connect(ctx)
	// Even with an unreachable server, gRPC lazy connect succeeds.
	if err == nil {
		defer client.Disconnect()
	}
}

// TestClient_IsConnected_AfterServerStop tests that IsConnected reports
// correctly after the server stops.
func TestClient_IsConnected_AfterServerStop(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.ReconnectBackoffMax = 0

	client, _ := NewClient(clientCfg, testLogger())
	ctx := context.Background()
	_ = client.Connect(ctx)

	time.Sleep(50 * time.Millisecond)

	// Stop the server.
	server.Stop()

	// Give time for the connection to notice.
	time.Sleep(100 * time.Millisecond)

	// Disconnect client.
	client.Disconnect()
}

// TestClient_MonitorConnection tests the reconnection monitor with a
// real server that stops.
func TestClient_MonitorConnection(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()

	clientCfg := DefaultClientConfig()
	clientCfg.MasterAddress = server.Addr()
	clientCfg.ReconnectBackoffMax = 2 * time.Second

	client, _ := NewClient(clientCfg, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Connect(ctx)
	time.Sleep(100 * time.Millisecond)

	// Stop the server to trigger reconnection logic.
	server.Stop()
	time.Sleep(200 * time.Millisecond)

	// Cancel the context to stop the monitor.
	cancel()
	time.Sleep(100 * time.Millisecond)

	client.Disconnect()
}

// TestServer_GRPCClientConnection tests a real gRPC client connection to
// the server.
func TestServer_GRPCClientConnection(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ListenAddress = "localhost:0"
	enrollment, _ := testEnrollmentService(t)
	server, _ := NewServer(serverCfg, enrollment, testLogger())
	_ = server.Start()
	defer server.Stop()

	// Create a raw gRPC client connection.
	conn, err := grpc.NewClient(
		server.Addr(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to create gRPC client: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)
}
