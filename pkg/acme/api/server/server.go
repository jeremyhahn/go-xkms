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

// Package server provides multi-protocol server support for Admin API.
// It supports REST, gRPC (TCP and Unix socket), HTTP over Unix socket, QUIC, and MCP protocols.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api/swagger"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/webui"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/correlation"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Protocol server ports and paths
const (
	DefaultRESTPort     = 8443
	DefaultGRPCPort     = 9443
	DefaultQUICPort     = 9444
	DefaultMCPPort      = 9445
	DefaultGRPCUnixPath = "/run/trusted-ca-grpc.sock"
	DefaultHTTPUnixPath = "/run/trusted-ca-rest.sock"
	DefaultGRPCUnixMode = os.FileMode(0660)
	DefaultHTTPUnixMode = os.FileMode(0660)
)

// mcpHandler is the function signature for MCP method dispatch handlers.
type mcpHandler func(ctx context.Context, params json.RawMessage) (interface{}, error)

// ErrMethodNotFound is returned when an MCP method is not found in the dispatch map.
var ErrMethodNotFound = errors.New("method not found")

// ServerConfig holds configuration for multi-protocol server.
type ServerConfig struct {
	// REST/HTTPS configuration
	RESTAddr string
	// gRPC configuration
	GRPCAddr string
	// gRPC Unix socket path (empty to disable)
	GRPCUnixPath string
	// gRPC Unix socket permissions (default: 0660)
	GRPCUnixMode os.FileMode
	// HTTP Unix socket path for REST over Unix domain socket (empty to disable)
	HTTPUnixPath string
	// HTTP Unix socket permissions (default: 0660)
	HTTPUnixMode os.FileMode
	// QUIC/HTTP3 configuration
	QUICAddr string
	// MCP configuration
	MCPAddr string
	// TLS configuration
	TLSConfig *tls.Config
	// Logger
	Logger *slog.Logger
	// Read timeout
	ReadTimeout time.Duration
	// Write timeout
	WriteTimeout time.Duration
	// Idle timeout
	IdleTimeout time.Duration
	// Role mapping for gRPC Unix socket authentication
	GRPCRoleMapping *RoleMapping

	// Authorizer is the qrdb-backed authorization seam every ACME admin
	// protocol surface (REST, gRPC, MCP) delegates its decisions to. It is
	// the same *auth.Authorizer the xkms REST/gRPC/QUIC/MCP transports use, so
	// a role grant means the same thing on the ACME admin API as it does
	// everywhere else in the stack.
	//
	// A nil Authorizer (or one built without an RBAC client) leaves
	// authorization disabled and every authenticated caller allowed, matching
	// the documented stack-wide "RBAC disabled => allow all" behavior.
	// Authentication is mandatory either way.
	Authorizer *auth.Authorizer

	// AuditQuerier serves GET /admin/audit. It must read the same trail the
	// ACME server writes — construct it from the same audit configuration the
	// FileAuditLogger was built from (see NewFileQuerier). When nil the
	// endpoint reports that no audit trail is configured rather than claiming
	// the trail is empty.
	AuditQuerier audit.Querier
}

// DefaultConfig returns a default server configuration.
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		RESTAddr:        fmt.Sprintf(":%d", DefaultRESTPort),
		GRPCAddr:        fmt.Sprintf(":%d", DefaultGRPCPort),
		GRPCUnixPath:    DefaultGRPCUnixPath,
		GRPCUnixMode:    DefaultGRPCUnixMode,
		HTTPUnixPath:    DefaultHTTPUnixPath,
		HTTPUnixMode:    DefaultHTTPUnixMode,
		QUICAddr:        fmt.Sprintf(":%d", DefaultQUICPort),
		MCPAddr:         fmt.Sprintf(":%d", DefaultMCPPort),
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     120 * time.Second,
		GRPCRoleMapping: DefaultRoleMapping(),
	}
}

// MultiProtocolServer provides Admin API over multiple protocols.
type MultiProtocolServer struct {
	config         *ServerConfig
	logger         *slog.Logger
	adminService   admin.Service
	tenantService  admin.TenantService
	authMiddleware admin.AuthHandler
	gate           *admin.PermissionGate
	router         *mux.Router

	// MCP method dispatch map for O(1) routing
	mcpHandlers map[string]mcpHandler

	// Protocol servers
	restServer       *http.Server
	grpcServer       *grpc.Server
	grpcUnixServer   *grpc.Server // Separate server for Unix socket (no TLS)
	grpcListener     net.Listener
	grpcUnixListener net.Listener
	httpUnixServer   *http.Server // HTTP/REST over Unix domain socket
	httpUnixListener net.Listener
	quicServer       *http3.Server
	mcpServer        *http.Server

	// Lifecycle
	running atomic.Bool
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

// NewMultiProtocolServer creates a new multi-protocol server.
func NewMultiProtocolServer(
	config *ServerConfig,
	adminService admin.Service,
	tenantService admin.TenantService,
	authMiddleware admin.AuthHandler,
) (*MultiProtocolServer, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Set default gRPC Unix mode if not set
	if config.GRPCUnixMode == 0 {
		config.GRPCUnixMode = DefaultGRPCUnixMode
	}

	// Set default HTTP Unix mode if not set
	if config.HTTPUnixMode == 0 {
		config.HTTPUnixMode = DefaultHTTPUnixMode
	}

	server := &MultiProtocolServer{
		config:         config,
		logger:         config.Logger,
		adminService:   adminService,
		tenantService:  tenantService,
		authMiddleware: authMiddleware,
		gate:           admin.NewPermissionGate(config.Authorizer, config.Logger),
	}

	// Initialize MCP method dispatch map
	server.initMCPHandlers()

	// Build the shared router with all Admin API routes
	server.buildRouter()

	return server, nil
}

// initMCPHandlers initializes the MCP method dispatch map for O(1) routing.
func (s *MultiProtocolServer) initMCPHandlers() {
	s.mcpHandlers = map[string]mcpHandler{
		// Status operations
		"admin.getStatus": s.mcpGetStatus,
		"admin.getStats":  s.mcpGetStats,

		// Certificate operations
		"admin.listCertificates":  s.mcpListCertificates,
		"admin.getCertificate":    s.mcpGetCertificate,
		"admin.revokeCertificate": s.mcpRevokeCertificate,

		// Account operations
		"admin.listAccounts":   s.mcpListAccounts,
		"admin.getAccount":     s.mcpGetAccount,
		"admin.disableAccount": s.mcpDisableAccount,

		// Tenant operations
		"admin.createTenant": s.mcpCreateTenant,
		"admin.getTenant":    s.mcpGetTenant,
		"admin.updateTenant": s.mcpUpdateTenant,
		"admin.deleteTenant": s.mcpDeleteTenant,
		"admin.listTenants":  s.mcpListTenants,

		// EAB operations
		"admin.createEAB": s.mcpCreateEAB,
		"admin.getEAB":    s.mcpGetEAB,
		"admin.deleteEAB": s.mcpDeleteEAB,
		"admin.listEABs":  s.mcpListEABs,

		// Role operations (RBAC)
		"admin.createRole": s.mcpCreateRole,
		"admin.getRole":    s.mcpGetRole,
		"admin.updateRole": s.mcpUpdateRole,
		"admin.deleteRole": s.mcpDeleteRole,
		"admin.listRoles":  s.mcpListRoles,

		// User operations (RBAC)
		"admin.createUser": s.mcpCreateUser,
		"admin.getUser":    s.mcpGetUser,
		"admin.updateUser": s.mcpUpdateUser,
		"admin.deleteUser": s.mcpDeleteUser,
		"admin.listUsers":  s.mcpListUsers,
	}
}

// MCP handler methods

func (s *MultiProtocolServer) mcpGetStatus(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	return s.adminService.GetStatus(ctx)
}

func (s *MultiProtocolServer) mcpGetStats(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	return s.adminService.GetStats(ctx)
}

func (s *MultiProtocolServer) mcpListCertificates(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req admin.ListCertificatesRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	certs, pagination, err := s.adminService.ListCertificates(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"certificates": certs, "pagination": pagination}, nil
}

func (s *MultiProtocolServer) mcpGetCertificate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Serial string `json:"serial"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.adminService.GetCertificate(ctx, p.Serial)
}

func (s *MultiProtocolServer) mcpRevokeCertificate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Serial string `json:"serial"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return nil, s.adminService.RevokeCertificate(ctx, p.Serial, p.Reason)
}

func (s *MultiProtocolServer) mcpListAccounts(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req admin.ListAccountsRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	accounts, pagination, err := s.adminService.ListAccounts(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"accounts": accounts, "pagination": pagination}, nil
}

func (s *MultiProtocolServer) mcpGetAccount(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		AccountID uint64 `json:"account_id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.adminService.GetAccount(ctx, p.AccountID)
}

func (s *MultiProtocolServer) mcpDisableAccount(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		AccountID uint64 `json:"account_id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return nil, s.adminService.DisableAccount(ctx, p.AccountID)
}

func (s *MultiProtocolServer) mcpCreateTenant(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var req admin.CreateTenantRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	// Auto-generate ID if not provided (matches REST handler behavior)
	if req.ID == "" {
		req.ID = fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	}
	return s.tenantService.CreateTenant(ctx, req)
}

func (s *MultiProtocolServer) mcpGetTenant(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.GetTenant(ctx, p.TenantID)
}

func (s *MultiProtocolServer) mcpUpdateTenant(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string                    `json:"tenantId"`
		Name     string                    `json:"name"`
		Settings *admin.TenantSettingsInfo `json:"settings"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.UpdateTenant(ctx, p.TenantID, admin.UpdateTenantRequest{
		Name:     p.Name,
		Settings: p.Settings,
	})
}

func (s *MultiProtocolServer) mcpDeleteTenant(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return nil, s.tenantService.DeleteTenant(ctx, p.TenantID)
}

func (s *MultiProtocolServer) mcpListTenants(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var req admin.ListTenantsRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	tenants, pagination, err := s.tenantService.ListTenants(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"tenants": tenants, "pagination": pagination}, nil
}

func (s *MultiProtocolServer) mcpCreateEAB(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID          string                  `json:"tenantId"`
		Purpose           string                  `json:"purpose"`
		ExpiresInDays     int                     `json:"expires_in_days"`
		Contact           []string                `json:"contact"`
		ExternalAccountID string                  `json:"external_account_id"`
		DeviceInfo        *admin.EABDeviceInfoDTO `json:"device_info"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.CreateTenantEAB(ctx, p.TenantID, admin.CreateEABRequest{
		Purpose:           p.Purpose,
		ExpiresInDays:     p.ExpiresInDays,
		Contact:           p.Contact,
		ExternalAccountID: p.ExternalAccountID,
		DeviceInfo:        p.DeviceInfo,
	})
}

func (s *MultiProtocolServer) mcpGetEAB(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
		KID      string `json:"kid"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.GetTenantEAB(ctx, p.TenantID, p.KID)
}

func (s *MultiProtocolServer) mcpDeleteEAB(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
		KID      string `json:"kid"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return nil, s.tenantService.DeleteTenantEAB(ctx, p.TenantID, p.KID)
}

func (s *MultiProtocolServer) mcpListEABs(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
		Page     int    `json:"page"`
		PerPage  int    `json:"per_page"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	eabs, pagination, err := s.tenantService.ListTenantEABs(ctx, p.TenantID, admin.ListEABRequest{
		Page:    p.Page,
		PerPage: p.PerPage,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"eabs": eabs, "pagination": pagination}, nil
}

// Role MCP handler methods (RBAC)

func (s *MultiProtocolServer) mcpCreateRole(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string                `json:"tenantId"`
		Role     *db.CreateRoleRequest `json:"role"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.CreateTenantRole(ctx, p.TenantID, p.Role)
}

func (s *MultiProtocolServer) mcpGetRole(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
		RoleID   string `json:"roleId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.GetTenantRole(ctx, p.TenantID, p.RoleID)
}

func (s *MultiProtocolServer) mcpUpdateRole(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string                `json:"tenantId"`
		Role     *db.UpdateRoleRequest `json:"role"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.UpdateTenantRole(ctx, p.TenantID, p.Role)
}

func (s *MultiProtocolServer) mcpDeleteRole(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
		RoleID   string `json:"roleId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return nil, s.tenantService.DeleteTenantRole(ctx, p.TenantID, p.RoleID)
}

func (s *MultiProtocolServer) mcpListRoles(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string               `json:"tenantId"`
		Role     *db.ListRolesRequest `json:"request"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.ListTenantRoles(ctx, p.TenantID, p.Role)
}

// User MCP handler methods (RBAC)

func (s *MultiProtocolServer) mcpCreateUser(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string                `json:"tenantId"`
		User     *db.CreateUserRequest `json:"user"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.CreateTenantUser(ctx, p.TenantID, p.User)
}

func (s *MultiProtocolServer) mcpGetUser(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
		UserID   string `json:"userId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.GetTenantUser(ctx, p.TenantID, p.UserID)
}

func (s *MultiProtocolServer) mcpUpdateUser(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string                `json:"tenantId"`
		User     *db.UpdateUserRequest `json:"user"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.UpdateTenantUser(ctx, p.TenantID, p.User)
}

func (s *MultiProtocolServer) mcpDeleteUser(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string `json:"tenantId"`
		UserID   string `json:"userId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return nil, s.tenantService.DeleteTenantUser(ctx, p.TenantID, p.UserID)
}

func (s *MultiProtocolServer) mcpListUsers(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if s.tenantService == nil {
		return nil, caerrors.InternalServerError("tenant service not available")
	}
	var p struct {
		TenantID string               `json:"tenantId"`
		User     *db.ListUsersRequest `json:"request"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	return s.tenantService.ListTenantUsers(ctx, p.TenantID, p.User)
}

// buildRouter creates the shared HTTP router for Admin API.
func (s *MultiProtocolServer) buildRouter() {
	s.router = mux.NewRouter()

	// Create admin handlers. The audit querier is only supplied when the
	// deployment actually keeps a trail, so GET /admin/audit reports the truth
	// either way.
	var adminOpts []admin.HandlerOption
	if s.config.AuditQuerier != nil {
		adminOpts = append(adminOpts, admin.WithAuditQuerier(s.config.AuditQuerier))
	}
	adminHandlers := admin.NewHandlers(s.adminService, s.logger, adminOpts...)
	adminHandlers.RegisterRoutes(s.router, s.authMiddleware, s.gate)

	// Create tenant handlers if tenant service is available
	if s.tenantService != nil {
		tenantHandlers := admin.NewTenantHandlers(s.tenantService, s.logger)
		tenantHandlers.RegisterRoutes(s.router, s.authMiddleware, s.gate)
	}

	// Register barrier handlers if the admin service supports them
	if taSvc, ok := s.adminService.(admin.TenantAwareService); ok {
		if barrierSvc := taSvc.BarrierSvc(); barrierSvc != nil {
			admin.NewBarrierHandlers(barrierSvc, s.logger).RegisterRoutes(s.router, s.authMiddleware, s.gate)
		}
	}

	// Health check endpoint (no auth required)
	s.router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"healthy"}`)); err != nil {
			s.logger.Error("failed to write health check response", slog.String("error", err.Error()))
		}
	}).Methods("GET")

	// MCP endpoint for JSON-RPC over HTTP. It carries the same authentication
	// middleware as the REST admin routes; per-method authorization happens in
	// handleMCP against MCPMethodPermissions.
	mcpRouter := s.router.PathPrefix("/mcp").Subrouter()
	if s.authMiddleware != nil {
		mcpRouter.Use(s.authMiddleware.Authenticate)
	}
	mcpRouter.HandleFunc("", s.handleMCP).Methods("POST")

	// Swagger UI (/docs) and the OpenAPI specs it renders (/openapi/{spec}).
	// Gated behind the same admin authentication and admin:capabilities
	// grant as GET /admin/algorithms: the specs describe every admin route,
	// parameter and permission this deployment exposes, so they carry the
	// same fail-closed registration the rest of the admin surface uses
	// rather than being served publicly.
	swagger.NewHandler(&swagger.Config{
		Title:       "go-xkms Admin API Documentation",
		DefaultSpec: "admin-api",
		Logger:      s.logger,
	}).RegisterRoutes(s.router, s.authMiddleware, s.gate)

	// Admin web UI (SPA) - registered last so API routes take priority
	if err := webui.RegisterRoutes(s.router, webui.AdminAssets, s.logger); err != nil {
		s.logger.Warn("failed to register admin web UI", slog.String("error", err.Error()))
	}
}

// Start starts all protocol servers.
func (s *MultiProtocolServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return caerrors.InternalServerError("server already running")
	}
	s.running.Store(true)

	errCh := make(chan error, 5)

	// Start REST server
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.startREST(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- caerrors.InternalServerError("REST server error: %v", err)
		}
	}()

	// Start gRPC server (handles both TCP and Unix socket)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.startGRPC(ctx); err != nil {
			errCh <- caerrors.InternalServerError("gRPC server error: %v", err)
		}
	}()

	// Start HTTP Unix socket server (REST over Unix domain socket)
	if s.config.HTTPUnixPath != "" {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.startHTTPUnix(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- caerrors.InternalServerError("HTTP Unix socket server error: %v", err)
			}
		}()
	}

	// Start QUIC server (requires TLS)
	if s.config.TLSConfig != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.startQUIC(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- caerrors.InternalServerError("QUIC server error: %v", err)
			}
		}()
	} else {
		s.logger.Warn("QUIC server disabled: TLS configuration required")
	}

	// Start MCP server
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.startMCP(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- caerrors.InternalServerError("MCP server error: %v", err)
		}
	}()

	// Log startup
	s.logger.Info("multi-protocol Admin API server started",
		slog.String("rest_addr", s.config.RESTAddr),
		slog.String("grpc_addr", s.config.GRPCAddr),
		slog.String("grpc_unix_path", s.config.GRPCUnixPath),
		slog.String("http_unix_path", s.config.HTTPUnixPath),
		slog.String("quic_addr", s.config.QUICAddr),
		slog.String("mcp_addr", s.config.MCPAddr))

	// Check for immediate startup errors
	select {
	case err := <-errCh:
		s.running.Store(false)
		return err
	case <-time.After(100 * time.Millisecond):
		// Servers started successfully
	}

	return nil
}

// startREST starts the REST/HTTPS server.
func (s *MultiProtocolServer) startREST(ctx context.Context) error {
	s.mu.Lock()
	s.restServer = &http.Server{
		Addr:         s.config.RESTAddr,
		Handler:      s.router,
		TLSConfig:    s.config.TLSConfig,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}
	s.mu.Unlock()

	s.logger.Info("REST server listening", slog.String("address", s.config.RESTAddr))

	if s.config.TLSConfig != nil {
		return s.restServer.ListenAndServeTLS("", "")
	}
	return s.restServer.ListenAndServe()
}

// startGRPC starts the gRPC server with both TCP and Unix socket listeners.
// TCP uses TLS if configured, Unix socket uses insecure credentials (kernel-enforced SO_PEERCRED).
func (s *MultiProtocolServer) startGRPC(_ context.Context) error {
	// Role mapping for Unix socket authentication
	roleMapping := s.config.GRPCRoleMapping
	if roleMapping == nil {
		roleMapping = DefaultRoleMapping()
	}

	// Create shared AdminService implementation
	adminService := NewAdminServiceServer(
		s.adminService,
		s.tenantService,
		s.logger,
	)

	// Error channel for listener failures
	listenerErrs := make(chan error, 2)

	// Start TCP listener with TLS (if configured)
	if s.config.GRPCAddr != "" {
		var tcpOpts []grpc.ServerOption
		if s.config.TLSConfig != nil {
			creds := credentials.NewTLS(s.config.TLSConfig)
			tcpOpts = append(tcpOpts, grpc.Creds(creds))
		}

		// Add interceptors. The mTLS identity interceptor is the
		// authentication layer for TCP callers; without it the authorization
		// interceptor would have no identity to evaluate and would deny.
		tcpOpts = append(tcpOpts, grpc.ChainUnaryInterceptor(
			UnaryPeerCredentialsInterceptor(),
			UnaryMTLSIdentityInterceptor(nil, nil, s.logger),
			UnaryAuthorizationInterceptor(roleMapping, s.gate, s.logger),
		))

		// Create gRPC server for TCP
		grpcServer := grpc.NewServer(tcpOpts...)
		adminv1.RegisterAdminServiceServer(grpcServer, adminService)

		s.mu.Lock()
		s.grpcServer = grpcServer
		s.mu.Unlock()

		tcpListener, err := net.Listen("tcp", s.config.GRPCAddr)
		if err != nil {
			return caerrors.ConnectionFailureError("failed to listen on gRPC TCP address: %v", err)
		}

		s.mu.Lock()
		s.grpcListener = tcpListener
		s.mu.Unlock()

		s.logger.Info("gRPC server listening on TCP", slog.String("address", s.config.GRPCAddr))

		go func() {
			if err := grpcServer.Serve(tcpListener); err != nil {
				listenerErrs <- caerrors.ConnectionFailureError("gRPC TCP listener error: %v", err)
			}
		}()
	}

	// Start Unix socket listener WITHOUT TLS (uses SO_PEERCRED for authentication)
	if s.config.GRPCUnixPath != "" {
		// The Unix socket server carries no TLS; the kernel-verified SO_PEERCRED
		// identity extracted during the transport handshake is the only
		// authentication for this listener, so it must fail closed at
		// construction on a platform this package cannot verify credentials on.
		peerCreds, err := NewUnixPeerCredentials()
		if err != nil {
			return err
		}

		unixOpts := []grpc.ServerOption{grpc.Creds(peerCreds)}

		// Add interceptors for Unix socket authentication
		unixOpts = append(unixOpts, grpc.ChainUnaryInterceptor(
			UnaryPeerCredentialsInterceptor(),
			UnaryAuthorizationInterceptor(roleMapping, s.gate, s.logger),
		))

		// Create separate gRPC server for Unix socket (no TLS)
		grpcUnixServer := grpc.NewServer(unixOpts...)
		adminv1.RegisterAdminServiceServer(grpcUnixServer, adminService)

		s.mu.Lock()
		s.grpcUnixServer = grpcUnixServer
		s.mu.Unlock()

		// Remove stale socket file if it exists
		if err := os.Remove(s.config.GRPCUnixPath); err != nil && !os.IsNotExist(err) {
			return caerrors.StorageFailureError("failed to remove stale gRPC Unix socket: %v", err)
		}

		unixAddr := &net.UnixAddr{Name: s.config.GRPCUnixPath, Net: "unix"}
		unixListener, err := net.ListenUnix("unix", unixAddr)
		if err != nil {
			return caerrors.ConnectionFailureError("failed to listen on gRPC Unix socket: %v", err)
		}

		// Set socket file permissions
		if err := os.Chmod(s.config.GRPCUnixPath, s.config.GRPCUnixMode); err != nil {
			return errors.Join(
				caerrors.StorageFailureError("failed to set gRPC Unix socket permissions: %v", err),
				unixListener.Close())
		}

		s.mu.Lock()
		s.grpcUnixListener = unixListener
		s.mu.Unlock()

		s.logger.Info("gRPC server listening on Unix socket",
			slog.String("path", s.config.GRPCUnixPath),
			slog.String("mode", fmt.Sprintf("%04o", s.config.GRPCUnixMode)))

		go func() {
			if err := grpcUnixServer.Serve(unixListener); err != nil {
				listenerErrs <- caerrors.ConnectionFailureError("gRPC Unix listener error: %v", err)
			}
		}()
	}

	// Wait for any listener errors (blocking)
	// The server runs until GracefulStop is called
	err := <-listenerErrs
	return err
}

// startHTTPUnix starts the HTTP/REST server on a Unix domain socket.
// This allows SDK clients to communicate with the REST API over a local Unix socket
// without TLS, relying on filesystem permissions for access control.
func (s *MultiProtocolServer) startHTTPUnix(_ context.Context) error {
	// Remove stale socket file if it exists
	if err := os.Remove(s.config.HTTPUnixPath); err != nil && !os.IsNotExist(err) {
		return caerrors.StorageFailureError("failed to remove stale HTTP Unix socket: %v", err)
	}

	unixAddr := &net.UnixAddr{Name: s.config.HTTPUnixPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", unixAddr)
	if err != nil {
		return caerrors.ConnectionFailureError("failed to listen on HTTP Unix socket: %v", err)
	}

	// Set socket file permissions
	if err := os.Chmod(s.config.HTTPUnixPath, s.config.HTTPUnixMode); err != nil {
		return errors.Join(
			caerrors.StorageFailureError("failed to set HTTP Unix socket permissions: %v", err),
			listener.Close())
	}

	s.mu.Lock()
	s.httpUnixServer = &http.Server{
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}
	s.httpUnixListener = listener
	s.mu.Unlock()

	s.logger.Info("HTTP server listening on Unix socket",
		slog.String("path", s.config.HTTPUnixPath),
		slog.String("mode", fmt.Sprintf("%04o", s.config.HTTPUnixMode)))

	return s.httpUnixServer.Serve(listener)
}

// startQUIC starts the QUIC/HTTP3 server.
func (s *MultiProtocolServer) startQUIC(ctx context.Context) error {
	if s.config.TLSConfig == nil {
		return caerrors.TLSErrorCreate("TLS configuration required for QUIC")
	}

	s.mu.Lock()
	s.quicServer = &http3.Server{
		Addr:      s.config.QUICAddr,
		Handler:   s.router,
		TLSConfig: s.config.TLSConfig,
	}
	s.mu.Unlock()

	s.logger.Info("QUIC/HTTP3 server listening", slog.String("address", s.config.QUICAddr))

	return s.quicServer.ListenAndServe()
}

// startMCP starts the MCP (Model Context Protocol) server.
func (s *MultiProtocolServer) startMCP(ctx context.Context) error {
	s.mu.Lock()
	s.mcpServer = &http.Server{
		Addr:         s.config.MCPAddr,
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}
	s.mu.Unlock()

	s.logger.Info("MCP server listening", slog.String("address", s.config.MCPAddr))

	return s.mcpServer.ListenAndServe()
}

// Shutdown gracefully shuts down all protocol servers.
func (s *MultiProtocolServer) Shutdown(ctx context.Context) error {
	if !s.running.Load() {
		return nil
	}
	s.running.Store(false)

	var errs []error

	s.mu.Lock()

	// Shutdown REST server
	if s.restServer != nil {
		if err := s.restServer.Shutdown(ctx); err != nil {
			errs = append(errs, caerrors.InternalServerError("REST shutdown: %v", err))
		}
		s.logger.Info("REST server stopped")
	}

	// Stop gRPC TCP server gracefully
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		s.logger.Info("gRPC TCP server stopped")
	}

	// Stop gRPC Unix socket server gracefully
	if s.grpcUnixServer != nil {
		s.grpcUnixServer.GracefulStop()
		s.logger.Info("gRPC Unix socket server stopped")
	}

	// Clean up gRPC Unix socket file
	if s.config.GRPCUnixPath != "" {
		if err := os.Remove(s.config.GRPCUnixPath); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("failed to remove gRPC Unix socket file", slog.String("error", err.Error()))
		}
	}

	// Shutdown HTTP Unix socket server
	if s.httpUnixServer != nil {
		if err := s.httpUnixServer.Shutdown(ctx); err != nil {
			errs = append(errs, caerrors.InternalServerError("HTTP Unix socket shutdown: %v", err))
		}
		s.logger.Info("HTTP Unix socket server stopped")
	}

	// Clean up HTTP Unix socket file
	if s.config.HTTPUnixPath != "" {
		if err := os.Remove(s.config.HTTPUnixPath); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("failed to remove HTTP Unix socket file", slog.String("error", err.Error()))
		}
	}

	// Close QUIC server
	if s.quicServer != nil {
		if err := s.quicServer.Close(); err != nil {
			errs = append(errs, caerrors.InternalServerError("QUIC shutdown: %v", err))
		}
		s.logger.Info("QUIC server stopped")
	}

	// Shutdown MCP server
	if s.mcpServer != nil {
		if err := s.mcpServer.Shutdown(ctx); err != nil {
			errs = append(errs, caerrors.InternalServerError("MCP shutdown: %v", err))
		}
		s.logger.Info("MCP server stopped")
	}

	s.mu.Unlock()

	// Wait for all goroutines to complete
	s.wg.Wait()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	s.logger.Info("multi-protocol server shutdown complete")
	return nil
}

// MCP JSON-RPC types

// MCPRequest represents a JSON-RPC 2.0 request for MCP.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

// MCPResponse represents a JSON-RPC 2.0 response for MCP.
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// MCPError represents a JSON-RPC 2.0 error.
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// handleMCP handles MCP JSON-RPC requests.
func (s *MultiProtocolServer) handleMCP(w http.ResponseWriter, r *http.Request) {
	var req MCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeMCPError(w, nil, -32700, "Parse error", nil)
		return
	}

	if req.JSONRPC != "2.0" {
		s.writeMCPError(w, req.ID, -32600, "Invalid Request", nil)
		return
	}

	// Authorize before dispatch. A denial never reaches service code.
	if err := s.authorizeMCPMethod(r.Context(), req.Method); err != nil {
		code := -32003
		message := "Forbidden"
		if errors.Is(err, auth.ErrUnauthenticated) {
			code = -32002
			message = "Unauthorized"
		}
		// The denial reason stays server-side: it can carry RBAC or
		// user-store detail that is not the caller's to see (go-xkms#1118,
		// mirroring the gRPC fix in go-xkms#1103).
		s.logMCPError(r, req.Method, "ACME admin MCP request denied", err)
		s.writeMCPError(w, req.ID, code, message, nil)
		return
	}

	// Route method to appropriate handler
	result, err := s.routeMCPMethod(r.Context(), req.Method, req.Params)
	if err != nil {
		var code int
		var message string
		switch {
		case errors.Is(err, admin.ErrCertificateNotFound),
			errors.Is(err, admin.ErrAccountNotFound),
			errors.Is(err, admin.ErrOrderNotFound),
			errors.Is(err, admin.ErrTenantNotFound):
			code = -32001
			message = "Not found"
		case errors.Is(err, admin.ErrUnauthorized):
			code = -32002
			message = "Unauthorized"
		default:
			// An unclassified fault: its text is withheld from the client
			// and logged server-side instead (go-xkms#1118).
			s.logMCPError(r, req.Method, "ACME admin MCP internal error withheld from client", err)
			s.writeMCPError(w, req.ID, -32603, "Internal error", nil)
			return
		}
		s.writeMCPError(w, req.ID, code, message, err.Error())
		return
	}

	s.writeMCPResponse(w, req.ID, result)
}

// logMCPError logs err, whose text an MCP error response withholds from the
// client, with the method, the request path and the request's correlation
// ID.
func (s *MultiProtocolServer) logMCPError(r *http.Request, method, msg string, err error) {
	attrs := []any{
		slog.String("method", method),
		slog.String("path", r.URL.Path),
		slog.Any("error", err),
	}
	if id := correlation.GetCorrelationID(r.Context()); id != "" {
		attrs = append(attrs, slog.String("request_id", id))
	}
	s.logger.ErrorContext(r.Context(), msg, attrs...)
}

// routeMCPMethod routes MCP method calls to the appropriate service method
// using O(1) map-based dispatch.
func (s *MultiProtocolServer) routeMCPMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	handler, ok := s.mcpHandlers[method]
	if !ok {
		return nil, caerrors.NotFoundError("method not found: %s", method)
	}
	return handler(ctx, params)
}

// writeMCPResponse writes a successful MCP response.
func (s *MultiProtocolServer) writeMCPResponse(w http.ResponseWriter, id interface{}, result interface{}) {
	resp := MCPResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Headers are already written; there is no way to report this to
		// the client, so it's only logged.
		s.logger.Error("failed to write MCP response", slog.String("error", err.Error()))
	}
}

// writeMCPError writes an MCP error response.
func (s *MultiProtocolServer) writeMCPError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
	resp := MCPResponse{
		JSONRPC: "2.0",
		Error: &MCPError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to write MCP error response", slog.String("error", err.Error()))
	}
}

// Running returns true if the server is running.
func (s *MultiProtocolServer) Running() bool {
	return s.running.Load()
}
