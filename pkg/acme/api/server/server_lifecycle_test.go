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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// generateTestTLSConfig creates a self-signed certificate for testing.
func generateTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
}

// TestLifecycle_ShutdownWithQUICServer tests shutdown with QUIC server active.
func TestLifecycle_ShutdownWithQUICServer(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Manually set up the server state
	server.running.Store(true)
	server.quicServer = &http3.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.NewServeMux(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := server.Shutdown(ctx)

	assert.NoError(t, err)
	assert.False(t, server.Running())
}

// TestLifecycle_ShutdownWithGRPCUnixServer tests shutdown with gRPC Unix socket server.
func TestLifecycle_ShutdownWithGRPCUnixServer(t *testing.T) {
	mockAdmin := &mockAdminService{}

	// Create temp directory for Unix socket
	tmpDir := t.TempDir()
	unixSocketPath := filepath.Join(tmpDir, "test.sock")

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    unixSocketPath,
		GRPCUnixMode:    0660,
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Manually set up the server state
	server.running.Store(true)
	server.grpcUnixServer = grpc.NewServer()

	// Create a socket file to test cleanup
	_, err = os.Create(unixSocketPath)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)

	assert.NoError(t, err)
	assert.False(t, server.Running())

	// Verify socket file was removed
	_, err = os.Stat(unixSocketPath)
	assert.True(t, os.IsNotExist(err))
}

// TestLifecycle_ShutdownWithAllServers tests shutdown with all protocol servers active.
func TestLifecycle_ShutdownWithAllServers(t *testing.T) {
	mockAdmin := &mockAdminService{}

	// Create temp directory for Unix socket
	tmpDir := t.TempDir()
	unixSocketPath := filepath.Join(tmpDir, "test.sock")

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    unixSocketPath,
		GRPCUnixMode:    0660,
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Manually set up all server states
	server.running.Store(true)
	server.restServer = &http.Server{Addr: "127.0.0.1:0"}
	server.grpcServer = grpc.NewServer()
	server.grpcUnixServer = grpc.NewServer()
	server.quicServer = &http3.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}
	server.mcpServer = &http.Server{Addr: "127.0.0.1:0"}

	// Create a socket file to test cleanup
	_, err = os.Create(unixSocketPath)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)

	assert.NoError(t, err)
	assert.False(t, server.Running())
}

// TestLifecycle_SocketFileRemovalError tests the case where socket file removal fails.
func TestLifecycle_SocketFileRemovalError(t *testing.T) {
	mockAdmin := &mockAdminService{}

	// Use a path that doesn't exist - removal should still succeed
	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    "/tmp/nonexistent-socket-file-12345.sock",
		GRPCUnixMode:    0660,
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	server.running.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)

	// Should not error even though socket file doesn't exist
	assert.NoError(t, err)
	assert.False(t, server.Running())
}

// TestLifecycle_NewServerWithNilConfig tests server creation with nil config.
func TestLifecycle_NewServerWithNilConfig(t *testing.T) {
	mockAdmin := &mockAdminService{}

	server, err := NewMultiProtocolServer(nil, mockAdmin, nil, &mockAuthHandler{})

	require.NoError(t, err)
	require.NotNil(t, server)

	// Should use default config
	assert.Equal(t, ":8443", server.config.RESTAddr)
	assert.Equal(t, ":9443", server.config.GRPCAddr)
}

// TestLifecycle_NewServerWithTenantService tests server creation with tenant service.
func TestLifecycle_NewServerWithTenantService(t *testing.T) {
	mockAdmin := &mockAdminService{}
	mockTenant := &mockTenantService{}

	config := &ServerConfig{
		RESTAddr:        ":0",
		GRPCAddr:        ":0",
		QUICAddr:        ":0",
		MCPAddr:         ":0",
		GRPCUnixPath:    "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, mockTenant, &mockAuthHandler{})

	require.NoError(t, err)
	require.NotNil(t, server)
	assert.NotNil(t, server.tenantService)
}

// TestLifecycle_DefaultGRPCUnixMode tests default Unix mode is set.
func TestLifecycle_DefaultGRPCUnixMode(t *testing.T) {
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        ":0",
		GRPCAddr:        ":0",
		GRPCUnixPath:    "/tmp/test.sock",
		GRPCUnixMode:    0, // Zero should be replaced with default
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})

	require.NoError(t, err)
	assert.Equal(t, DefaultGRPCUnixMode, server.config.GRPCUnixMode)
}

// TestLifecycle_RunningState tests the Running method.
func TestLifecycle_RunningState(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Initially not running
	assert.False(t, server.Running())

	// Set running
	server.running.Store(true)
	assert.True(t, server.Running())

	// Set not running
	server.running.Store(false)
	assert.False(t, server.Running())
}

// TestLifecycle_RouterBuilt tests that the router is built correctly.
func TestLifecycle_RouterBuilt(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Router should be built during NewMultiProtocolServer
	assert.NotNil(t, server.router)
}

// TestLifecycle_RouterWithTenantHandlers tests router building with tenant handlers.
func TestLifecycle_RouterWithTenantHandlers(t *testing.T) {
	mockAdmin := &mockAdminService{}
	mockTenant := &mockTenantService{}

	config := &ServerConfig{
		RESTAddr:        ":0",
		GRPCAddr:        ":0",
		QUICAddr:        ":0",
		MCPAddr:         ":0",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, mockTenant, &mockAuthHandler{})

	require.NoError(t, err)
	assert.NotNil(t, server.router)
}

// TestLifecycle_HealthEndpoint tests the health check endpoint.
func TestLifecycle_HealthEndpoint(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	// Make a request to the health endpoint
	req, err := http.NewRequest(http.MethodGet, "/health", nil)
	require.NoError(t, err)

	rr := newLifecycleTestRecorder()
	server.router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "healthy")
}

// lifecycleTestRecorder is a custom response recorder for testing.
type lifecycleTestRecorder struct {
	Code int
	Body *lifecycleSafeBuffer
}

func newLifecycleTestRecorder() *lifecycleTestRecorder {
	return &lifecycleTestRecorder{
		Code: 200,
		Body: &lifecycleSafeBuffer{},
	}
}

func (r *lifecycleTestRecorder) Header() http.Header {
	return http.Header{}
}

func (r *lifecycleTestRecorder) Write(b []byte) (int, error) {
	return r.Body.Write(b)
}

func (r *lifecycleTestRecorder) WriteHeader(code int) {
	r.Code = code
}

// lifecycleSafeBuffer is a thread-safe buffer for testing.
type lifecycleSafeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *lifecycleSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *lifecycleSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// TestLifecycle_ConcurrentShutdown tests that multiple concurrent shutdown calls are safe.
func TestLifecycle_ConcurrentShutdown(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)
	server.running.Store(true)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
		}()
	}

	wg.Wait()
	assert.False(t, server.Running())
}

// TestLifecycle_NilLogger tests that a nil logger is replaced with default.
func TestLifecycle_NilLogger(t *testing.T) {
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        ":0",
		GRPCAddr:        "",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          nil, // Nil logger
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})

	require.NoError(t, err)
	assert.NotNil(t, server.logger)
}

// TestLifecycle_StartMethods tests the startREST, startMCP, startQUIC methods directly.
func TestLifecycle_StartMethods(t *testing.T) {
	// Test that startQUIC returns error when TLS is nil
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    "",
		QUICAddr:        "127.0.0.1:0",
		MCPAddr:         "",
		TLSConfig:       nil, // No TLS
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// startQUIC should return error when TLS is nil
	ctx := context.Background()
	err = server.startQUIC(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS configuration required")
}

// TestLifecycle_DirectServerStartAndShutdown tests starting and stopping REST directly.
func TestLifecycle_DirectServerStartAndShutdown(t *testing.T) {
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        "127.0.0.1:0",
		GRPCAddr:        "",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Start REST server directly in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startREST(context.Background())
	}()

	// Give time to start
	time.Sleep(100 * time.Millisecond)

	// Verify restServer was created
	server.mu.RLock()
	restServer := server.restServer
	server.mu.RUnlock()
	require.NotNil(t, restServer)

	// Shutdown REST server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = restServer.Shutdown(ctx)
	assert.NoError(t, err)

	// Wait for server goroutine to finish
	select {
	case err := <-errCh:
		// Should be http.ErrServerClosed or nil
		if err != nil {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("REST server did not shutdown in time")
	}
}

// TestLifecycle_DirectMCPStartAndShutdown tests starting and stopping MCP directly.
func TestLifecycle_DirectMCPStartAndShutdown(t *testing.T) {
	mockAdmin := &mockAdminService{}

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "127.0.0.1:0",
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Start MCP server directly in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startMCP(context.Background())
	}()

	// Give time to start
	time.Sleep(100 * time.Millisecond)

	// Verify mcpServer was created
	server.mu.RLock()
	mcpServer := server.mcpServer
	server.mu.RUnlock()
	require.NotNil(t, mcpServer)

	// Shutdown MCP server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = mcpServer.Shutdown(ctx)
	assert.NoError(t, err)

	// Wait for server goroutine to finish
	select {
	case err := <-errCh:
		// Should be http.ErrServerClosed or nil
		if err != nil {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("MCP server did not shutdown in time")
	}
}

// TestLifecycle_DirectRESTWithTLS tests starting REST with TLS.
func TestLifecycle_DirectRESTWithTLS(t *testing.T) {
	mockAdmin := &mockAdminService{}
	tlsConfig := generateTestTLSConfig(t)

	config := &ServerConfig{
		RESTAddr:        "127.0.0.1:0",
		GRPCAddr:        "",
		GRPCUnixPath:    "",
		QUICAddr:        "",
		MCPAddr:         "",
		TLSConfig:       tlsConfig,
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Start REST server with TLS directly in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startREST(context.Background())
	}()

	// Give time to start
	time.Sleep(100 * time.Millisecond)

	// Verify restServer was created
	server.mu.RLock()
	restServer := server.restServer
	server.mu.RUnlock()
	require.NotNil(t, restServer)

	// Shutdown REST server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = restServer.Shutdown(ctx)
	assert.NoError(t, err)
}

// TestLifecycle_DirectQUICStartAndShutdown tests starting and stopping QUIC directly.
func TestLifecycle_DirectQUICStartAndShutdown(t *testing.T) {
	mockAdmin := &mockAdminService{}
	tlsConfig := generateTestTLSConfig(t)

	config := &ServerConfig{
		RESTAddr:        "",
		GRPCAddr:        "",
		GRPCUnixPath:    "",
		QUICAddr:        "127.0.0.1:0",
		MCPAddr:         "",
		TLSConfig:       tlsConfig,
		Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
		GRPCRoleMapping: DefaultRoleMapping(),
	}

	server, err := NewMultiProtocolServer(config, mockAdmin, nil, &mockAuthHandler{})
	require.NoError(t, err)

	// Start QUIC server directly in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startQUIC(context.Background())
	}()

	// Give time to start
	time.Sleep(100 * time.Millisecond)

	// Verify quicServer was created
	server.mu.RLock()
	quicServer := server.quicServer
	server.mu.RUnlock()
	require.NotNil(t, quicServer)

	// Close QUIC server
	err = quicServer.Close()
	assert.NoError(t, err)
}
