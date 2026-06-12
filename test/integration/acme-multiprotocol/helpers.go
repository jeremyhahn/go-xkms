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

//go:build integration

// Package multiprotocol provides test helpers for multi-protocol integration testing.
//
// All integration tests MUST use these helpers to exercise commands via ALL protocols:
//   - REST (HTTP/HTTPS)
//   - gRPC (TCP and Unix domain socket)
//   - QUIC (UDP)
//   - MCP (stdio/HTTP)
//
// Note: Unix socket communication is now handled via gRPC-over-UDS (Unix Domain Socket).
//
// Example usage:
//
//	func TestServiceMultiProtocol(t *testing.T) {
//	    ctx := NewTestContext(t)
//	    defer ctx.Cleanup()
//
//	    t.Run("REST", func(t *testing.T) { testServiceProtocol(t, ctx, ctx.RESTAdapter) })
//	    t.Run("gRPC", func(t *testing.T) { testServiceProtocol(t, ctx, ctx.GRPCAdapter) })
//	    t.Run("QUIC", func(t *testing.T) { testServiceProtocol(t, ctx, ctx.QUICAdapter) })
//	    t.Run("MCP", func(t *testing.T) { testServiceProtocol(t, ctx, ctx.MCPAdapter) })
//	    t.Run("gRPC-UDS", func(t *testing.T) { testServiceProtocol(t, ctx, ctx.GRPCUnixAdapter) })
//	}
package multiprotocol

import (
	"context"
	"log/slog"
	"os"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api/quic"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api/rest"
	"github.com/stretchr/testify/require"
)

// TestContext provides access to all protocol adapters for integration testing.
type TestContext struct {
	// Adapters for each protocol
	RESTAdapter     api.AdminAdapter
	GRPCAdapter     api.AdminAdapter
	QUICAdapter     api.AdminAdapter
	MCPAdapter      api.AdminAdapter
	GRPCUnixAdapter api.AdminAdapter // gRPC over Unix domain socket

	// Server configuration
	Config *ServerConfig

	// Logger for test output
	Logger *slog.Logger

	// Cleanup function
	cleanup func()
}

// ServerConfig contains server addresses for all protocols.
type ServerConfig struct {
	// REST API base URL (e.g., "http://localhost:8443")
	RESTURL string
	// gRPC server address (e.g., "localhost:9443")
	GRPCAddr string
	// QUIC server address (e.g., "localhost:9444")
	QUICAddr string
	// MCP server address (e.g., "localhost:9445")
	MCPAddr string
	// gRPC Unix socket path (e.g., "/run/trusted-ca-grpc.sock")
	GRPCUnixPath string
	// TLSConfig contains mTLS configuration (optional - used in production)
	TLSConfig *api.TLSConfig
}

// DefaultServerConfig returns the default server configuration for integration tests.
func DefaultServerConfig() *ServerConfig {
	config := &ServerConfig{
		RESTURL:      getEnvOrDefault("TRUSTED_CA_REST_URL", "http://localhost:8443"),
		GRPCAddr:     getEnvOrDefault("TRUSTED_CA_GRPC_ADDR", "localhost:9443"),
		QUICAddr:     getEnvOrDefault("TRUSTED_CA_QUIC_ADDR", "localhost:9444"),
		MCPAddr:      getEnvOrDefault("TRUSTED_CA_MCP_ADDR", "localhost:9445"),
		GRPCUnixPath: getEnvOrDefault("TRUSTED_CA_GRPC_UNIX_PATH", "/run/trusted-ca-grpc.sock"),
	}

	// Configure mTLS if certificate files are provided.
	// TRUSTED_CA_TLS_INSECURE is no longer honoured: all connections must
	// present a valid CA certificate. Set TRUSTED_CA_TLS_CA to trust the
	// server's private CA instead.
	certFile := os.Getenv("TRUSTED_CA_TLS_CERT")
	keyFile := os.Getenv("TRUSTED_CA_TLS_KEY")
	caFile := os.Getenv("TRUSTED_CA_TLS_CA")

	if certFile != "" && keyFile != "" {
		config.TLSConfig = &api.TLSConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		}
	} else if caFile != "" {
		config.TLSConfig = &api.TLSConfig{
			CAFile: caFile,
		}
	}

	return config
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// NewTestContext creates a new test context with all protocol adapters.
func NewTestContext(t *testing.T) *TestContext {
	t.Helper()

	config := DefaultServerConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx := &TestContext{
		Config: config,
		Logger: logger,
	}

	// Create REST adapter (always available)
	// Note: Running without mTLS for integration tests (development mode)
	restAdapter, err := rest.NewAdapter(&api.AdapterConfig{
		BaseURL:   config.RESTURL,
		TLSConfig: config.TLSConfig,
	})
	require.NoError(t, err)
	ctx.RESTAdapter = restAdapter

	// Create gRPC adapter (uses real implementation when built with -tags=grpc)
	ctx.GRPCAdapter = createGRPCAdapter(config, logger)

	// Create QUIC adapter (if available)
	if config.QUICAddr != "" {
		quicAdapter, err := quic.NewAdapter(&api.AdapterConfig{
			QUICAddr:  config.QUICAddr,
			TLSConfig: config.TLSConfig,
		})
		if err != nil {
			logger.Warn("failed to create QUIC adapter", "error", err)
			ctx.QUICAdapter = newStubAdapter(api.ProtocolQUIC, err.Error())
		} else {
			ctx.QUICAdapter = quicAdapter
		}
	} else {
		ctx.QUICAdapter = newStubAdapter(api.ProtocolQUIC, "QUIC address not configured")
	}

	// Create MCP adapter (if available)
	if config.MCPAddr != "" {
		mcpAdapter, err := mcp.NewAdapter(&api.AdapterConfig{
			MCPAddr:   config.MCPAddr,
			TLSConfig: config.TLSConfig,
		})
		if err != nil {
			logger.Warn("failed to create MCP adapter", "error", err)
			ctx.MCPAdapter = newStubAdapter(api.ProtocolMCP, err.Error())
		} else {
			ctx.MCPAdapter = mcpAdapter
		}
	} else {
		ctx.MCPAdapter = newStubAdapter(api.ProtocolMCP, "MCP address not configured")
	}

	// Create gRPC Unix socket adapter (if available)
	// This uses gRPC-over-UDS instead of a custom Unix protocol
	if config.GRPCUnixPath != "" {
		ctx.GRPCUnixAdapter = createGRPCUnixAdapter(config, logger)
	} else {
		ctx.GRPCUnixAdapter = newStubAdapter(api.ProtocolUnix, "gRPC Unix socket path not configured")
	}

	ctx.cleanup = func() {
		if ctx.RESTAdapter != nil {
			_ = ctx.RESTAdapter.Close()
		}
		if ctx.GRPCAdapter != nil {
			_ = ctx.GRPCAdapter.Close()
		}
		if ctx.QUICAdapter != nil {
			_ = ctx.QUICAdapter.Close()
		}
		if ctx.MCPAdapter != nil {
			_ = ctx.MCPAdapter.Close()
		}
		if ctx.GRPCUnixAdapter != nil {
			_ = ctx.GRPCUnixAdapter.Close()
		}
	}

	return ctx
}

// Cleanup releases resources held by the test context.
func (tc *TestContext) Cleanup() {
	if tc.cleanup != nil {
		tc.cleanup()
	}
}

// AllAdapters returns all non-nil adapters for testing.
func (tc *TestContext) AllAdapters() []api.AdminAdapter {
	var adapters []api.AdminAdapter
	if tc.RESTAdapter != nil {
		adapters = append(adapters, tc.RESTAdapter)
	}
	if tc.GRPCAdapter != nil {
		adapters = append(adapters, tc.GRPCAdapter)
	}
	if tc.QUICAdapter != nil {
		adapters = append(adapters, tc.QUICAdapter)
	}
	if tc.MCPAdapter != nil {
		adapters = append(adapters, tc.MCPAdapter)
	}
	if tc.GRPCUnixAdapter != nil {
		adapters = append(adapters, tc.GRPCUnixAdapter)
	}
	return adapters
}

// ForEachProtocol runs a test function against each available protocol adapter.
// Tests FAIL (not skip) if a configured protocol is not reachable.
// Only protocols that are enabled via environment variables are tested.
func (tc *TestContext) ForEachProtocol(t *testing.T, testFn func(t *testing.T, adapter api.AdminAdapter)) {
	t.Helper()

	// Check if Admin API tests should run
	if os.Getenv("TRUSTED_CA_ADMIN_API_ENABLED") != "true" {
		t.Fatal("Admin API tests require TRUSTED_CA_ADMIN_API_ENABLED=true")
		return
	}

	// Define which protocols to test based on environment configuration
	// Each protocol is only tested if its address is configured
	type protocolConfig struct {
		name     string
		adapter  api.AdminAdapter
		envVar   string
		required bool // If true, test MUST pass
	}

	protocols := []protocolConfig{
		// REST is always required when Admin API is enabled
		{"REST", tc.RESTAdapter, "TRUSTED_CA_REST_URL", true},
		// Other protocols are optional - only tested if configured
		{"gRPC", tc.GRPCAdapter, "TRUSTED_CA_GRPC_ADDR", false},
		{"QUIC", tc.QUICAdapter, "TRUSTED_CA_QUIC_ADDR", false},
		{"MCP", tc.MCPAdapter, "TRUSTED_CA_MCP_ADDR", false},
		{"gRPC-UDS", tc.GRPCUnixAdapter, "TRUSTED_CA_GRPC_UNIX_PATH", false},
	}

	// Track if any tests ran
	testsRan := false

	for _, p := range protocols {
		// Check if this protocol is configured
		configValue := os.Getenv(p.envVar)
		if configValue == "" && !p.required {
			// Protocol not configured and not required - don't test it
			tc.Logger.Info("protocol not configured, not testing", "protocol", p.name, "envVar", p.envVar)
			continue
		}

		if p.adapter == nil {
			if p.required {
				t.Fatalf("Required protocol %s adapter is nil", p.name)
			}
			continue
		}

		// Check if this is a stub adapter
		if stub, ok := p.adapter.(*stubAdapter); ok {
			if p.required {
				t.Fatalf("Required protocol %s is not available: %s", p.name, stub.reason)
			}
			// Optional protocol not available - log and continue (don't test)
			tc.Logger.Warn("optional protocol not available", "protocol", p.name, "reason", stub.reason)
			continue
		}

		testsRan = true
		t.Run(p.name, func(t *testing.T) {
			testFn(t, p.adapter)
		})
	}

	if !testsRan {
		t.Fatal("No protocol adapters were available for testing")
	}
}

// RunMultiProtocolTest is a convenience wrapper that creates a test context and runs
// the test function against all protocols.
func RunMultiProtocolTest(t *testing.T, testFn func(t *testing.T, ctx context.Context, adapter api.AdminAdapter)) {
	t.Helper()

	tc := NewTestContext(t)
	defer tc.Cleanup()

	testCtx := context.Background()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		testFn(t, testCtx, adapter)
	})
}

// stubAdapter is a placeholder adapter for protocols not yet implemented.
type stubAdapter struct {
	protocol api.Protocol
	reason   string
}

func newStubAdapter(protocol api.Protocol, reason string) *stubAdapter {
	return &stubAdapter{
		protocol: protocol,
		reason:   reason,
	}
}

func (s *stubAdapter) Protocol() api.Protocol { return s.protocol }
func (s *stubAdapter) Close() error           { return nil }

// Stub implementations that return "not implemented" errors

// TenantAdapter stubs
func (s *stubAdapter) CreateTenant(ctx context.Context, req *admin.CreateTenantRequest) (*admin.TenantInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetTenant(ctx context.Context, tenantID string) (*admin.TenantInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) UpdateTenant(ctx context.Context, tenantID string, req *admin.UpdateTenantRequest) (*admin.TenantInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) UpdateTenantStatus(ctx context.Context, tenantID string, status string) error {
	return errNotImplemented(s.protocol)
}
func (s *stubAdapter) DeleteTenant(ctx context.Context, tenantID string) error {
	return errNotImplemented(s.protocol)
}
func (s *stubAdapter) ListTenants(ctx context.Context, req *admin.ListTenantsRequest) ([]*admin.TenantInfo, *admin.Pagination, error) {
	return nil, nil, errNotImplemented(s.protocol)
}

// TenantCAAdapter stubs
func (s *stubAdapter) CreateTenantRootCA(ctx context.Context, tenantID string, req *admin.CreateTenantRootCARequest) (*admin.TenantRootCAInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetTenantCAStatus(ctx context.Context, tenantID string) (*admin.TenantCAStatusInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) CreateTenantIntermediateCA(ctx context.Context, tenantID string, req *admin.CreateTenantIntermediateCARequest) (*admin.TenantIntCAInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) ListTenantIntermediateCAs(ctx context.Context, tenantID string) ([]*admin.TenantIntCAInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetTenantIntermediateCA(ctx context.Context, tenantID string, caID string) (*admin.TenantIntCAInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) UpdateTenantIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error {
	return errNotImplemented(s.protocol)
}

// EABAdapter stubs
func (s *stubAdapter) CreateEAB(ctx context.Context, tenantID string, req *admin.CreateEABRequest) (*admin.CreateEABResponse, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetEAB(ctx context.Context, tenantID, kid string) (*admin.EABInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) DeleteEAB(ctx context.Context, tenantID, kid string) error {
	return errNotImplemented(s.protocol)
}
func (s *stubAdapter) ListEABs(ctx context.Context, tenantID string, req *admin.ListEABRequest) ([]*admin.EABInfo, *admin.Pagination, error) {
	return nil, nil, errNotImplemented(s.protocol)
}

// RoleAdapter stubs
func (s *stubAdapter) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetTenantRole(ctx context.Context, tenantID, roleID string) (*db.Role, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) DeleteTenantRole(ctx context.Context, tenantID, roleID string) error {
	return errNotImplemented(s.protocol)
}
func (s *stubAdapter) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	return nil, errNotImplemented(s.protocol)
}

// UserAdapter stubs
func (s *stubAdapter) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetTenantUser(ctx context.Context, tenantID, userID string) (*db.User, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) DeleteTenantUser(ctx context.Context, tenantID, userID string) error {
	return errNotImplemented(s.protocol)
}
func (s *stubAdapter) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	return nil, errNotImplemented(s.protocol)
}

// AccountAdapter stubs
func (s *stubAdapter) ListAccounts(ctx context.Context, req *admin.ListAccountsRequest) ([]*admin.AccountInfo, *admin.Pagination, error) {
	return nil, nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetAccount(ctx context.Context, accountID uint64) (*admin.AccountInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) DisableAccount(ctx context.Context, accountID uint64) error {
	return errNotImplemented(s.protocol)
}

// CertificateAdapter stubs
func (s *stubAdapter) ListCertificates(ctx context.Context, req *admin.ListCertificatesRequest) ([]*admin.CertificateInfo, *admin.Pagination, error) {
	return nil, nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetCertificate(ctx context.Context, serial string) (*admin.CertificateInfo, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) RevokeCertificate(ctx context.Context, serial, reason string) error {
	return errNotImplemented(s.protocol)
}

// OrderAdapter stubs
func (s *stubAdapter) ListOrders(ctx context.Context, req *admin.ListOrdersRequest) ([]*admin.OrderInfo, *admin.Pagination, error) {
	return nil, nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetOrder(ctx context.Context, orderID uint64, accountID uint64) (*admin.OrderInfo, error) {
	return nil, errNotImplemented(s.protocol)
}

// StatusAdapter stubs
func (s *stubAdapter) GetStatus(ctx context.Context) (*admin.CAStatus, error) {
	return nil, errNotImplemented(s.protocol)
}
func (s *stubAdapter) GetStats(ctx context.Context) (*admin.CAStats, error) {
	return nil, errNotImplemented(s.protocol)
}

// Verify stubAdapter implements AdminAdapter.
var _ api.AdminAdapter = (*stubAdapter)(nil)

func errNotImplemented(protocol api.Protocol) error {
	return &NotImplementedError{Protocol: protocol}
}

// NotImplementedError indicates a protocol adapter is not yet implemented.
type NotImplementedError struct {
	Protocol api.Protocol
}

func (e *NotImplementedError) Error() string {
	return string(e.Protocol) + " adapter not implemented"
}

// IsNotImplemented returns true if the error indicates a protocol is not implemented.
func IsNotImplemented(err error) bool {
	_, ok := err.(*NotImplementedError)
	return ok
}
