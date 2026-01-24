// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package keychain

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/sdk/go/transport"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/embedded"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/grpc"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/mcp"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/quic"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/rest"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/unix"
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
	cfg := &Config{
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
	cfg := &Config{
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
	cfg := &Config{
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
	cfg := &Config{
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
	cfg := &Config{
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
	cfg := &Config{
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
	cfg := &Config{
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
	cfg := &Config{
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
	mockService := &mockKeychainService{}
	cfg := &Config{
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
	cfg := &Config{
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
	cfg := &Config{
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
		service  KeychainServicer
	}{
		{"unix default", ProtocolUnix, nil},
		{"unix-grpc default", ProtocolUnixGRPC, nil},
		{"rest default", ProtocolREST, nil},
		{"grpc default", ProtocolGRPC, nil},
		{"quic default", ProtocolQUIC, nil},
		{"mcp default", ProtocolMCP, nil},
		{"embedded default", ProtocolEmbedded, &mockKeychainService{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
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
	cfg := &Config{
		Protocol:              ProtocolREST,
		Address:               "https://localhost:8443",
		TLSEnabled:            true,
		TLSInsecureSkipVerify: true,
		TLSCertFile:           "/path/to/cert.pem",
		TLSKeyFile:            "/path/to/key.pem",
		TLSCAFile:             "/path/to/ca.pem",
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
	cfg := &Config{
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

	cfg := &Config{
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
		{"ErrNilService", ErrNilService, "keychain service is required"},
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
	if DefaultUnixSocketPath != "keychain-data/keychain.sock" {
		t.Errorf("DefaultUnixSocketPath = %v, want keychain-data/keychain.sock",
			DefaultUnixSocketPath)
	}
}

func TestNewEmbedded_Success(t *testing.T) {
	mockService := &mockKeychainService{}
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
	mockService := &mockKeychainService{}
	client, _ := NewEmbedded(mockService)

	// Connect should be a no-op but set connected to true
	err := client.Connect(context.Background())
	if err != nil {
		t.Errorf("Connect() returned error: %v", err)
	}
}

func TestEmbeddedClient_Close(t *testing.T) {
	mockService := &mockKeychainService{}
	client, _ := NewEmbedded(mockService)

	// Close should work without error
	err := client.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestEmbeddedClient_NotConnectedErrors(t *testing.T) {
	mockService := &mockKeychainService{}
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
	mockService := &mockKeychainService{
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
	mockService := &mockKeychainService{
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
	mockService := &mockKeychainService{
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
	mockService := &mockKeychainService{
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
	cfg := &Config{
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
	cfg := &Config{
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

// mockKeychainService is a mock implementation of KeychainServicer for testing
type mockKeychainService struct {
	healthStatus  string
	healthVersion string
	healthErr     error
	backends      []transport.BackendInfo
	backend       *transport.BackendInfo
	backendErr    error
}

func (m *mockKeychainService) Health(ctx context.Context) (string, string, error) {
	return m.healthStatus, m.healthVersion, m.healthErr
}

func (m *mockKeychainService) ListBackends(ctx context.Context) ([]transport.BackendInfo, error) {
	return m.backends, nil
}

func (m *mockKeychainService) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	return m.backend, m.backendErr
}

func (m *mockKeychainService) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return &transport.GenerateKeyResponse{}, nil
}

func (m *mockKeychainService) ListKeys(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
	return &transport.ListKeysResponse{}, nil
}

func (m *mockKeychainService) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	return &transport.GetKeyResponse{}, nil
}

func (m *mockKeychainService) DeleteKey(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockKeychainService) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	return &transport.SignResponse{}, nil
}

func (m *mockKeychainService) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return &transport.VerifyResponse{}, nil
}

func (m *mockKeychainService) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return &transport.EncryptResponse{}, nil
}

func (m *mockKeychainService) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return &transport.DecryptResponse{}, nil
}

func (m *mockKeychainService) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return &transport.EncryptAsymResponse{}, nil
}

func (m *mockKeychainService) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	return &transport.GetCertificateResponse{}, nil
}

func (m *mockKeychainService) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	return nil
}

func (m *mockKeychainService) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockKeychainService) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

func (m *mockKeychainService) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return &transport.ImportKeyResponse{}, nil
}

func (m *mockKeychainService) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return &transport.ExportKeyResponse{}, nil
}

func (m *mockKeychainService) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return &transport.RotateKeyResponse{}, nil
}

func (m *mockKeychainService) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return &transport.ListKeyVersionsResponse{}, nil
}

func (m *mockKeychainService) EnableKeyVersion(ctx context.Context, req *transport.EnableKeyVersionRequest) (*transport.EnableKeyVersionResponse, error) {
	return &transport.EnableKeyVersionResponse{}, nil
}

func (m *mockKeychainService) DisableKeyVersion(ctx context.Context, req *transport.DisableKeyVersionRequest) (*transport.DisableKeyVersionResponse, error) {
	return &transport.DisableKeyVersionResponse{}, nil
}

func (m *mockKeychainService) EnableAllKeyVersions(ctx context.Context, req *transport.EnableAllKeyVersionsRequest) (*transport.EnableAllKeyVersionsResponse, error) {
	return &transport.EnableAllKeyVersionsResponse{}, nil
}

func (m *mockKeychainService) DisableAllKeyVersions(ctx context.Context, req *transport.DisableAllKeyVersionsRequest) (*transport.DisableAllKeyVersionsResponse, error) {
	return &transport.DisableAllKeyVersionsResponse{}, nil
}

func (m *mockKeychainService) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return &transport.GetImportParametersResponse{}, nil
}

func (m *mockKeychainService) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return &transport.WrapKeyResponse{}, nil
}

func (m *mockKeychainService) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return &transport.UnwrapKeyResponse{}, nil
}

func (m *mockKeychainService) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return &transport.CopyKeyResponse{}, nil
}

func (m *mockKeychainService) ListCertificates(ctx context.Context, backend string) (*transport.ListCertificatesResponse, error) {
	return &transport.ListCertificatesResponse{}, nil
}

func (m *mockKeychainService) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	return nil
}

func (m *mockKeychainService) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	return &transport.GetCertificateChainResponse{}, nil
}

func (m *mockKeychainService) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	return &transport.GetTLSCertificateResponse{}, nil
}

func (m *mockKeychainService) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	return &transport.SealResponse{}, nil
}

func (m *mockKeychainService) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return &transport.UnsealResponse{}, nil
}

func (m *mockKeychainService) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	return &transport.CanSealResponse{}, nil
}

// User management methods

func (m *mockKeychainService) ListUsers(ctx context.Context) (*transport.ListUsersResponse, error) {
	return &transport.ListUsersResponse{}, nil
}

func (m *mockKeychainService) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	return &transport.GetUserResponse{}, nil
}

func (m *mockKeychainService) DeleteUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockKeychainService) EnableUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockKeychainService) DisableUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockKeychainService) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	return &transport.ListUserCredentialsResponse{}, nil
}

// Authentication flow methods

func (m *mockKeychainService) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return &transport.BeginRegistrationResponse{}, nil
}

func (m *mockKeychainService) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return &transport.FinishRegistrationResponse{}, nil
}

func (m *mockKeychainService) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return &transport.BeginAuthenticationResponse{}, nil
}

func (m *mockKeychainService) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return &transport.FinishAuthenticationResponse{}, nil
}
