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

package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/embedded"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/grpc"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/mcp"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/quic"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/rest"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/unix"
)

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     string
	}{
		{"unix", ProtocolUnix, "unix"},
		{"unix-grpc", ProtocolUnixGRPC, "unix-grpc"},
		{"rest", ProtocolREST, "rest"},
		{"grpc", ProtocolGRPC, "grpc"},
		{"quic", ProtocolQUIC, "quic"},
		{"mcp", ProtocolMCP, "mcp"},
		{"embedded", ProtocolEmbedded, "embedded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.protocol); got != tt.want {
				t.Errorf("Protocol = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew_DefaultConfig(t *testing.T) {
	// Test with nil config - should use defaults (unix-grpc)
	client, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(nil) returned nil client")
	}

	// Should be a Unix transport by default
	_, ok := client.(*unix.Transport)
	if !ok {
		t.Errorf("Expected unix.Transport, got %T", client)
	}
}

func TestNew_EmptyProtocol(t *testing.T) {
	// Test with empty protocol - should default to Unix gRPC
	cfg := &BackendConfig{
		Protocol: "",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(empty protocol) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(empty protocol) returned nil client")
	}

	// Should be a Unix transport
	_, ok := client.(*unix.Transport)
	if !ok {
		t.Errorf("Expected unix.Transport, got %T", client)
	}
}

func TestNew_UnixProtocol(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolUnix,
		Address:  "/tmp/test.sock",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(Unix) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(Unix) returned nil client")
	}

	_, ok := client.(*unix.Transport)
	if !ok {
		t.Errorf("Expected unix.Transport, got %T", client)
	}
}

func TestNew_UnixGRPCProtocol(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolUnixGRPC,
		Address:  "/tmp/test.sock",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(UnixGRPC) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(UnixGRPC) returned nil client")
	}

	_, ok := client.(*unix.Transport)
	if !ok {
		t.Errorf("Expected unix.Transport, got %T", client)
	}
}

func TestNew_RESTProtocol(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolREST,
		Address:  "http://localhost:8443",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(REST) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(REST) returned nil client")
	}

	_, ok := client.(*rest.Transport)
	if !ok {
		t.Errorf("Expected rest.Transport, got %T", client)
	}
}

func TestNew_GRPCProtocol(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolGRPC,
		Address:  "localhost:9443",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(gRPC) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(gRPC) returned nil client")
	}

	_, ok := client.(*grpc.Transport)
	if !ok {
		t.Errorf("Expected grpc.Transport, got %T", client)
	}
}

func TestNew_QUICProtocol(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolQUIC,
		Address:  "localhost:8444",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(QUIC) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(QUIC) returned nil client")
	}

	_, ok := client.(*quic.Transport)
	if !ok {
		t.Errorf("Expected quic.Transport, got %T", client)
	}
}

func TestNew_MCPProtocol(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolMCP,
		Address:  "localhost:9444",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(MCP) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(MCP) returned nil client")
	}

	_, ok := client.(*mcp.Transport)
	if !ok {
		t.Errorf("Expected mcp.Transport, got %T", client)
	}
}

func TestNew_MCPProtocolWithTLS(t *testing.T) {
	cfg := &BackendConfig{
		Protocol:   ProtocolMCP,
		Address:    "localhost:9444",
		TLSEnabled: true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(MCP with TLS) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(MCP with TLS) returned nil client")
	}

	_, ok := client.(*mcp.Transport)
	if !ok {
		t.Errorf("Expected mcp.Transport, got %T", client)
	}
}

func TestNew_EmbeddedProtocol(t *testing.T) {
	mockService := &mockXKMSService{}
	cfg := &BackendConfig{
		Protocol: ProtocolEmbedded,
		Service:  mockService,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(Embedded) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(Embedded) returned nil client")
	}

	_, ok := client.(*embedded.Transport)
	if !ok {
		t.Errorf("Expected embedded.Transport, got %T", client)
	}
}

func TestNew_EmbeddedProtocolNilService(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolEmbedded,
		Service:  nil,
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("Expected error for nil service with embedded protocol")
	}
	if !errors.Is(err, ErrNilService) {
		t.Errorf("Expected ErrNilService, got %v", err)
	}
}

func TestNew_UnsupportedProtocol(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: Protocol("invalid"),
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("Expected error for unsupported protocol")
	}
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Errorf("Expected ErrUnsupportedProtocol, got %v", err)
	}
}

func TestNew_DefaultAddresses(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		service  XKMSServicer
	}{
		{"unix default", ProtocolUnix, nil},
		{"unix-grpc default", ProtocolUnixGRPC, nil},
		{"rest default", ProtocolREST, nil},
		{"grpc default", ProtocolGRPC, nil},
		{"quic default", ProtocolQUIC, nil},
		{"mcp default", ProtocolMCP, nil},
		{"embedded default", ProtocolEmbedded, &mockXKMSService{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &BackendConfig{
				Protocol: tt.protocol,
				Address:  "", // Empty to use default
				Service:  tt.service,
			}
			client, err := New(cfg)
			if err != nil {
				t.Fatalf("New() returned error: %v", err)
			}
			if client == nil {
				t.Fatal("New() returned nil client")
			}
		})
	}
}

func TestNewFromURL_Empty(t *testing.T) {
	// Empty URL should default to Unix socket with gRPC
	client, err := NewFromURL("")
	if err != nil {
		t.Fatalf("NewFromURL('') returned error: %v", err)
	}
	if client == nil {
		t.Fatal("NewFromURL('') returned nil client")
	}

	_, ok := client.(*unix.Transport)
	if !ok {
		t.Errorf("Expected unix.Transport, got %T", client)
	}
}

func TestNewFromURL_UnixScheme(t *testing.T) {
	client, err := NewFromURL("unix:///var/run/test.sock")
	if err != nil {
		t.Fatalf("NewFromURL(unix://) returned error: %v", err)
	}

	_, ok := client.(*unix.Transport)
	if !ok {
		t.Fatalf("Expected unix.Transport, got %T", client)
	}
}

func TestNewFromURL_HTTPScheme(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"http", "http://localhost:8080"},
		{"https", "https://localhost:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewFromURL(tt.url)
			if err != nil {
				t.Fatalf("NewFromURL(%s) returned error: %v", tt.url, err)
			}

			_, ok := client.(*rest.Transport)
			if !ok {
				t.Fatalf("Expected rest.Transport, got %T", client)
			}
		})
	}
}

func TestNewFromURL_GRPCScheme(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"grpc", "grpc://localhost:9443"},
		{"grpcs", "grpcs://localhost:9443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewFromURL(tt.url)
			if err != nil {
				t.Fatalf("NewFromURL(%s) returned error: %v", tt.url, err)
			}

			_, ok := client.(*grpc.Transport)
			if !ok {
				t.Fatalf("Expected grpc.Transport, got %T", client)
			}
		})
	}
}

func TestNewFromURL_QUICScheme(t *testing.T) {
	client, err := NewFromURL("quic://localhost:8444")
	if err != nil {
		t.Fatalf("NewFromURL(quic://) returned error: %v", err)
	}

	_, ok := client.(*quic.Transport)
	if !ok {
		t.Fatalf("Expected quic.Transport, got %T", client)
	}
}

func TestNewFromURL_MCPScheme(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"mcp", "mcp://localhost:9444"},
		{"mcps", "mcps://localhost:9445"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewFromURL(tt.url)
			if err != nil {
				t.Fatalf("NewFromURL(%s) returned error: %v", tt.url, err)
			}

			_, ok := client.(*mcp.Transport)
			if !ok {
				t.Fatalf("Expected mcp.Transport, got %T", client)
			}
		})
	}
}

func TestNewFromURL_HostPort(t *testing.T) {
	// Plain host:port should default to REST
	client, err := NewFromURL("myhost:8080")
	if err != nil {
		t.Fatalf("NewFromURL(host:port) returned error: %v", err)
	}

	_, ok := client.(*rest.Transport)
	if !ok {
		t.Errorf("Expected rest.Transport for host:port, got %T", client)
	}
}

func TestConfig_TLSSettings(t *testing.T) {
	cfg := &BackendConfig{
		Protocol:    ProtocolREST,
		Address:     "https://localhost:8443",
		TLSEnabled:  true,
		TLSCertFile: "/path/to/cert.pem",
		TLSKeyFile:  "/path/to/key.pem",
		TLSCAFile:   "/path/to/ca.pem",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	_, ok := client.(*rest.Transport)
	if !ok {
		t.Fatalf("Expected rest.Transport, got %T", client)
	}
}

func TestConfig_JWTToken(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolREST,
		Address:  "http://localhost:8443",
		JWTToken: "test-jwt-token",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	_, ok := client.(*rest.Transport)
	if !ok {
		t.Fatalf("Expected rest.Transport, got %T", client)
	}
}

func TestConfig_CustomHeaders(t *testing.T) {
	headers := map[string]string{
		"X-Custom-Header": "custom-value",
		"Authorization":   "Bearer token",
	}

	cfg := &BackendConfig{
		Protocol: ProtocolREST,
		Address:  "http://localhost:8443",
		Headers:  headers,
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	_, ok := client.(*rest.Transport)
	if !ok {
		t.Fatalf("Expected rest.Transport, got %T", client)
	}
}

func TestErrors(t *testing.T) {
	// Test that error variables are defined
	if ErrUnsupportedProtocol == nil {
		t.Error("ErrUnsupportedProtocol is nil")
	}
	if ErrConnectionFailed == nil {
		t.Error("ErrConnectionFailed is nil")
	}
	if ErrNotConnected == nil {
		t.Error("ErrNotConnected is nil")
	}
	if ErrNotSupported == nil {
		t.Error("ErrNotSupported is nil")
	}
	if ErrNilService == nil {
		t.Error("ErrNilService is nil")
	}
	if ErrKeyNotFound == nil {
		t.Error("ErrKeyNotFound is nil")
	}
	if ErrCertificateNotFound == nil {
		t.Error("ErrCertificateNotFound is nil")
	}
	if ErrBackendNotFound == nil {
		t.Error("ErrBackendNotFound is nil")
	}
	if ErrInvalidRequest == nil {
		t.Error("ErrInvalidRequest is nil")
	}
}

func TestErrors_Messages(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{"ErrUnsupportedProtocol", ErrUnsupportedProtocol, "unsupported protocol"},
		{"ErrConnectionFailed", ErrConnectionFailed, "connection failed"},
		{"ErrNotConnected", ErrNotConnected, "client not connected"},
		{"ErrNotSupported", ErrNotSupported, "operation not supported by this protocol"},
		{"ErrNilService", ErrNilService, "xkms service is required"},
		{"ErrKeyNotFound", ErrKeyNotFound, "key not found"},
		{"ErrCertificateNotFound", ErrCertificateNotFound, "certificate not found"},
		{"ErrBackendNotFound", ErrBackendNotFound, "backend not found"},
		{"ErrInvalidRequest", ErrInvalidRequest, "invalid request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.wantMsg {
				t.Errorf("Error message = %q, want %q", tt.err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestDefaultUnixSocketPath(t *testing.T) {
	if DefaultUnixSocketPath != "xkms-data/xkms.sock" {
		t.Errorf("DefaultUnixSocketPath = %v, want xkms-data/xkms.sock",
			DefaultUnixSocketPath)
	}
}

func TestNewEmbedded_Success(t *testing.T) {
	mockService := &mockXKMSService{}
	client, err := NewEmbedded(mockService)
	if err != nil {
		t.Fatalf("NewEmbedded() returned error: %v", err)
	}
	if client == nil {
		t.Fatal("NewEmbedded() returned nil client")
	}

	_, ok := client.(*embedded.Transport)
	if !ok {
		t.Fatalf("Expected embedded.Transport, got %T", client)
	}
}

func TestNewEmbedded_NilService(t *testing.T) {
	_, err := NewEmbedded(nil)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}
	if !errors.Is(err, ErrNilService) {
		t.Errorf("Expected ErrNilService, got %v", err)
	}
}

func TestEmbeddedClient_Connect(t *testing.T) {
	mockService := &mockXKMSService{}
	client, _ := NewEmbedded(mockService)

	// Connect should be a no-op but set connected to true
	err := client.Connect(context.Background())
	if err != nil {
		t.Errorf("Connect() returned error: %v", err)
	}
}

func TestEmbeddedClient_Close(t *testing.T) {
	mockService := &mockXKMSService{}
	client, _ := NewEmbedded(mockService)

	// Close should work without error
	err := client.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestEmbeddedClient_NotConnectedErrors(t *testing.T) {
	mockService := &mockXKMSService{}
	client, _ := NewEmbedded(mockService)
	client.Close() // Disconnect

	ctx := context.Background()

	// All operations should return an error when not connected
	_, err := client.Health(ctx)
	if err == nil {
		t.Error("Health() expected error when not connected")
	}
}

func TestEmbeddedClient_Health(t *testing.T) {
	mockService := &mockXKMSService{
		healthStatus:  "healthy",
		healthVersion: "1.0.0",
	}
	client, _ := NewEmbedded(mockService)

	resp, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() returned error: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("Status = %v, want healthy", resp.Status)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("Version = %v, want 1.0.0", resp.Version)
	}
}

func TestEmbeddedClient_HealthError(t *testing.T) {
	mockService := &mockXKMSService{
		healthErr: errors.New("health check failed"),
	}
	client, _ := NewEmbedded(mockService)

	_, err := client.Health(context.Background())
	if err == nil {
		t.Fatal("Expected error from Health()")
	}
	if err.Error() != "health check failed" {
		t.Errorf("Error = %v, want 'health check failed'", err)
	}
}

func TestEmbeddedClient_ListBackends(t *testing.T) {
	mockService := &mockXKMSService{
		backends: []transport.BackendInfo{
			{ID: "memory", Type: "memory"},
			{ID: "file", Type: "file"},
		},
	}
	client, _ := NewEmbedded(mockService)

	resp, err := client.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends() returned error: %v", err)
	}
	if len(resp.Backends) != 2 {
		t.Errorf("Expected 2 backends, got %d", len(resp.Backends))
	}
}

func TestEmbeddedClient_GetBackend(t *testing.T) {
	expectedBackend := &transport.BackendInfo{ID: "memory", Type: "memory"}
	mockService := &mockXKMSService{
		backend: expectedBackend,
	}
	client, _ := NewEmbedded(mockService)

	backend, err := client.GetBackend(context.Background(), "memory")
	if err != nil {
		t.Fatalf("GetBackend() returned error: %v", err)
	}
	if backend.ID != expectedBackend.ID {
		t.Errorf("Backend ID = %v, want %v", backend.ID, expectedBackend.ID)
	}
}

func TestMCPClient_Creation(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolMCP,
		Address:  "localhost:9444",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(MCP) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(MCP) returned nil")
	}
	_, ok := client.(*mcp.Transport)
	if !ok {
		t.Errorf("Expected mcp.Transport, got %T", client)
	}
}

func TestMCPClient_NotConnectedError(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolMCP,
		Address:  "localhost:9444",
	}
	client, _ := New(cfg)

	// Should not be connected initially
	ctx := context.Background()
	_, err := client.Health(ctx)
	if err == nil {
		t.Error("Health() expected error when not connected")
	}
}

func TestNewFromURL_UnsupportedScheme(t *testing.T) {
	_, err := NewFromURL("ftp://localhost:21")
	if err == nil {
		t.Fatal("Expected error for unsupported scheme")
	}
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Errorf("Expected ErrUnsupportedProtocol, got %v", err)
	}
}

func TestOptsFromConfig_TLSCAFileOnly(t *testing.T) {
	// When only TLSCAFile is set (no cert/key), optsFromConfig should use
	// transport.WithTLS instead of WithMTLS.
	cfg := &BackendConfig{
		Protocol:  ProtocolREST,
		Address:   "http://localhost:8443",
		TLSCAFile: "/path/to/ca.pem",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	_, ok := client.(*rest.Transport)
	if !ok {
		t.Fatalf("Expected rest.Transport, got %T", client)
	}
}

func TestOptsFromConfig_SPKIPin(t *testing.T) {
	cfg := &BackendConfig{
		Protocol: ProtocolREST,
		Address:  "http://localhost:8443",
		SPKIPin:  "abc123",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	_, ok := client.(*rest.Transport)
	if !ok {
		t.Fatalf("Expected rest.Transport, got %T", client)
	}
}

// mockXKMSService is a mock implementation of XKMSServicer for testing
type mockXKMSService struct {
	// Unserved serves the attestation Verifier API, which these tests do
	// not exercise.
	appraisaltest.Unserved

	healthStatus  string
	healthVersion string
	healthErr     error
	backends      []transport.BackendInfo
	backend       *transport.BackendInfo
	backendErr    error
}

func (m *mockXKMSService) Health(ctx context.Context) (string, string, error) {
	return m.healthStatus, m.healthVersion, m.healthErr
}

func (m *mockXKMSService) ListBackends(ctx context.Context, _ ...transport.ListOption) ([]transport.BackendInfo, error) {
	return m.backends, nil
}

func (m *mockXKMSService) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	return m.backend, m.backendErr
}

func (m *mockXKMSService) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return &transport.GenerateKeyResponse{}, nil
}

func (m *mockXKMSService) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return &transport.ListKeysResponse{}, nil
}

func (m *mockXKMSService) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	return &transport.GetKeyResponse{}, nil
}

func (m *mockXKMSService) DeleteKey(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockXKMSService) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	return &transport.SignResponse{}, nil
}

func (m *mockXKMSService) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return &transport.VerifyResponse{}, nil
}

func (m *mockXKMSService) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return &transport.EncryptResponse{}, nil
}

func (m *mockXKMSService) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return &transport.DecryptResponse{}, nil
}

func (m *mockXKMSService) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return &transport.EncryptAsymResponse{}, nil
}

func (m *mockXKMSService) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	return &transport.GetCertificateResponse{}, nil
}

func (m *mockXKMSService) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	return nil
}

func (m *mockXKMSService) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockXKMSService) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

func (m *mockXKMSService) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return &transport.ImportKeyResponse{}, nil
}

func (m *mockXKMSService) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return &transport.ExportKeyResponse{}, nil
}

func (m *mockXKMSService) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return &transport.RotateKeyResponse{}, nil
}

func (m *mockXKMSService) CreateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) RotateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SignOTAImage(ctx context.Context, req *transport.OTAImageSignRequest) (*transport.SignResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return &transport.GetImportParametersResponse{}, nil
}

func (m *mockXKMSService) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return &transport.WrapKeyResponse{}, nil
}

func (m *mockXKMSService) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return &transport.UnwrapKeyResponse{}, nil
}

func (m *mockXKMSService) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return &transport.CopyKeyResponse{}, nil
}

func (m *mockXKMSService) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return &transport.ListCertificatesResponse{}, nil
}

func (m *mockXKMSService) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	return nil
}

func (m *mockXKMSService) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	return &transport.GetCertificateChainResponse{}, nil
}

func (m *mockXKMSService) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	return &transport.GetTLSCertificateResponse{}, nil
}

func (m *mockXKMSService) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	return &transport.SealResponse{}, nil
}

func (m *mockXKMSService) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return &transport.UnsealResponse{}, nil
}

func (m *mockXKMSService) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	return &transport.CanSealResponse{}, nil
}

func (m *mockXKMSService) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, errors.New("attestation not supported in mock")
}

// Authentication flow methods

func (m *mockXKMSService) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return &transport.BeginRegistrationResponse{}, nil
}

func (m *mockXKMSService) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return &transport.FinishRegistrationResponse{}, nil
}

func (m *mockXKMSService) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return &transport.BeginAuthenticationResponse{}, nil
}

func (m *mockXKMSService) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return &transport.FinishAuthenticationResponse{}, nil
}

func (m *mockXKMSService) GetInvite(ctx context.Context, req *transport.GetInviteRequest) (*transport.GetInviteResponse, error) {
	return &transport.GetInviteResponse{}, nil
}

func (m *mockXKMSService) BeginInviteRegistration(ctx context.Context, req *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error) {
	return &transport.BeginInviteRegistrationResponse{}, nil
}

func (m *mockXKMSService) FinishInviteRegistration(ctx context.Context, req *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	return &transport.FinishInviteRegistrationResponse{}, nil
}

func (m *mockXKMSService) ActivateInvitePIV(ctx context.Context, req *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
	return &transport.ActivateInvitePIVResponse{}, nil
}

func (m *mockXKMSService) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return &transport.DeriveKeyResponse{}, nil
}

func (m *mockXKMSService) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return &transport.WrapKeyByIDResponse{
		WrappedKey: []byte("mock-wrapped-key"),
		Algorithm:  req.Algorithm,
	}, nil
}

func (m *mockXKMSService) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return &transport.UnwrapKeyByIDResponse{
		KeyID:   req.TargetKeyID,
		Backend: req.TargetKeyBackend,
		Success: true,
	}, nil
}

func (m *mockXKMSService) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: []byte("mock-key-material"),
		KeyType:     "aes256-gcm",
		KeySize:     256,
	}, nil
}

func (m *mockXKMSService) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	keyLen := req.KeyLength
	if keyLen <= 0 {
		keyLen = 32
	}
	derivedKey := make([]byte, keyLen)
	return &transport.DeriveKeyECDHResponse{
		DerivedKey: derivedKey,
	}, nil
}

func (m *mockXKMSService) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) IssueLAKCertificate(ctx context.Context, req *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
	return nil, nil
}

// PIV operations

func (m *mockXKMSService) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return &transport.ListPIVSlotsResponse{}, nil
}

func (m *mockXKMSService) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}

func (m *mockXKMSService) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return nil
}

func (m *mockXKMSService) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return nil
}

func (m *mockXKMSService) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return &transport.GeneratePIVKeyResponse{}, nil
}

func (m *mockXKMSService) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return nil
}

func (m *mockXKMSService) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}

func (m *mockXKMSService) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return &transport.GeneratePIVCSRResponse{}, nil
}

// Barrier operations

func (m *mockXKMSService) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return &transport.BootstrapListenerKeysResponse{}, nil
}

// PIN operations

func (m *mockXKMSService) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return nil
}

func (m *mockXKMSService) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return nil
}

func (m *mockXKMSService) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return nil
}

func (m *mockXKMSService) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return nil
}

func (m *mockXKMSService) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return nil
}

func (m *mockXKMSService) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return nil
}

func (m *mockXKMSService) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return &transport.LockoutStatusResponse{}, nil
}

func (m *mockXKMSService) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return nil
}

// Password store methods

func (m *mockXKMSService) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) (*transport.PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return nil
}

func (m *mockXKMSService) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return nil
}

func (m *mockXKMSService) PasswordStoreLock(ctx context.Context) error {
	return nil
}

func (m *mockXKMSService) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (m *mockXKMSService) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordVaultStatus(context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordVaultEnroll(context.Context, *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordVaultRotate(context.Context, *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) PasswordVaultRemoveFactor(context.Context, *transport.PasswordVaultRemoveFactorRequest) error {
	return nil
}

func (m *mockXKMSService) PasswordVaultRecover(context.Context, *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

// Platform store methods

func (m *mockXKMSService) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return nil
}

func (m *mockXKMSService) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return nil
}

func (m *mockXKMSService) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return nil
}

func (m *mockXKMSService) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) EscrowKey(ctx context.Context, req *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, nil
}

func (m *mockXKMSService) RecoverKey(ctx context.Context, req *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) ListEscrowed(ctx context.Context) ([]transport.EscrowRecord, error) {
	return nil, nil
}

func (m *mockXKMSService) RevokeEscrow(ctx context.Context, escrowID string) error {
	return nil
}

// Policy methods

func (m *mockXKMSService) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return nil
}

func (m *mockXKMSService) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

// OIDC credential operations are not exercised by this double.
func (*mockXKMSService) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockXKMSService) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockXKMSService) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockXKMSService) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, nil
}
func (*mockXKMSService) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	return nil, nil
}
func (*mockXKMSService) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockXKMSService) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	return nil, nil
}
func (*mockXKMSService) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockXKMSService) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	return nil
}
func (*mockXKMSService) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	return nil
}
func (*mockXKMSService) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockXKMSService) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, nil
}
func (*mockXKMSService) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockXKMSService) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

// Extended barrier operations

// Backup operations

// Custodian group operations

// Share operations

// Tenant operations

func (m *mockXKMSService) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) DeleteTenant(ctx context.Context, tenantID string) error {
	return nil
}

func (m *mockXKMSService) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// InitCeremonyService methods

// CredentialManagementService methods

func (m *mockXKMSService) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) ListUsers(ctx context.Context, opts ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) DeleteUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockXKMSService) EnableUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockXKMSService) DisableUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockXKMSService) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	return nil
}

func (m *mockXKMSService) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	return nil, nil
}

func (*mockXKMSService) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockXKMSService) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockXKMSService) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*mockXKMSService) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*mockXKMSService) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
func (*mockXKMSService) SignCoRIM(context.Context, *transport.SignCoRIMRequest) (*transport.SignedCoRIM, error) {
	return nil, nil
}

func (*mockXKMSService) SignImage(context.Context, *transport.SignImageRequest) (*transport.SignedImage, error) {
	return nil, nil
}
