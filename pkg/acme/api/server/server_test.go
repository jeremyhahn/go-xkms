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

//go:build !integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// --- Mock Implementations ---

// mockAdminService implements admin.Service for testing.
type mockAdminService struct {
	// Response values
	certificates    []*admin.CertificateInfo
	certificate     *admin.CertificateInfo
	pagination      *admin.Pagination
	caStatus        *admin.CAStatus
	caStats         *admin.CAStats
	accounts        []*admin.AccountInfo
	account         *admin.AccountInfo
	orders          []*admin.OrderInfo
	order           *admin.OrderInfo
	revokeErr       error
	disableErr      error
	listCertsErr    error
	getCertErr      error
	getStatusErr    error
	getStatsErr     error
	listAccountsErr error
	getAccountErr   error
	listOrdersErr   error
	getOrderErr     error
}

func (m *mockAdminService) ListCertificates(ctx context.Context, req admin.ListCertificatesRequest) ([]*admin.CertificateInfo, *admin.Pagination, error) {
	if m.listCertsErr != nil {
		return nil, nil, m.listCertsErr
	}
	return m.certificates, m.pagination, nil
}

func (m *mockAdminService) GetCertificate(ctx context.Context, serial string) (*admin.CertificateInfo, error) {
	if m.getCertErr != nil {
		return nil, m.getCertErr
	}
	return m.certificate, nil
}

func (m *mockAdminService) RevokeCertificate(ctx context.Context, serial string, reason string) error {
	return m.revokeErr
}

func (m *mockAdminService) ListExpiringCertificates(ctx context.Context, days int, page, perPage int) ([]*admin.CertificateInfo, *admin.Pagination, error) {
	return m.certificates, m.pagination, nil
}

func (m *mockAdminService) ListAccounts(ctx context.Context, req admin.ListAccountsRequest) ([]*admin.AccountInfo, *admin.Pagination, error) {
	if m.listAccountsErr != nil {
		return nil, nil, m.listAccountsErr
	}
	return m.accounts, m.pagination, nil
}

func (m *mockAdminService) GetAccount(ctx context.Context, accountID uint64) (*admin.AccountInfo, error) {
	if m.getAccountErr != nil {
		return nil, m.getAccountErr
	}
	return m.account, nil
}

func (m *mockAdminService) DisableAccount(ctx context.Context, accountID uint64) error {
	return m.disableErr
}

func (m *mockAdminService) ListOrders(ctx context.Context, req admin.ListOrdersRequest) ([]*admin.OrderInfo, *admin.Pagination, error) {
	if m.listOrdersErr != nil {
		return nil, nil, m.listOrdersErr
	}
	return m.orders, m.pagination, nil
}

func (m *mockAdminService) GetOrder(ctx context.Context, orderID uint64, accountID uint64) (*admin.OrderInfo, error) {
	if m.getOrderErr != nil {
		return nil, m.getOrderErr
	}
	return m.order, nil
}

func (m *mockAdminService) GetStatus(ctx context.Context) (*admin.CAStatus, error) {
	if m.getStatusErr != nil {
		return nil, m.getStatusErr
	}
	return m.caStatus, nil
}

func (m *mockAdminService) GetStats(ctx context.Context) (*admin.CAStats, error) {
	if m.getStatsErr != nil {
		return nil, m.getStatsErr
	}
	return m.caStats, nil
}

// mockTenantService implements admin.TenantService for testing.
type mockTenantService struct {
	tenant               *admin.TenantInfo
	tenants              []*admin.TenantInfo
	rootCA               *admin.TenantRootCAInfo
	intCA                *admin.TenantIntCAInfo
	intCAs               []*admin.TenantIntCAInfo
	caStatus             *admin.TenantCAStatusInfo
	eab                  *admin.EABInfo
	eabs                 []*admin.EABInfo
	createEABResp        *admin.CreateEABResponse
	pagination           *admin.Pagination
	role                 *db.Role
	roles                *db.ListRolesResponse
	user                 *db.User
	users                *db.ListUsersResponse
	createTenantErr      error
	getTenantErr         error
	updateTenantErr      error
	updateStatusErr      error
	deleteTenantErr      error
	listTenantsErr       error
	createRootCAErr      error
	createIntCAErr       error
	getIntCAErr          error
	listIntCAsErr        error
	updateIntCAErr       error
	setDefaultCAErr      error
	getTenantCAStatusErr error
	createEABErr         error
	getEABErr            error
	deleteEABErr         error
	listEABsErr          error
	createRoleErr        error
	getRoleErr           error
	updateRoleErr        error
	deleteRoleErr        error
	listRolesErr         error
	createUserErr        error
	getUserErr           error
	updateUserErr        error
	deleteUserErr        error
	listUsersErr         error
}

func (m *mockTenantService) CreateTenant(ctx context.Context, req admin.CreateTenantRequest) (*admin.TenantInfo, error) {
	if m.createTenantErr != nil {
		return nil, m.createTenantErr
	}
	return m.tenant, nil
}

func (m *mockTenantService) GetTenant(ctx context.Context, tenantID string) (*admin.TenantInfo, error) {
	if m.getTenantErr != nil {
		return nil, m.getTenantErr
	}
	return m.tenant, nil
}

func (m *mockTenantService) UpdateTenant(ctx context.Context, tenantID string, req admin.UpdateTenantRequest) (*admin.TenantInfo, error) {
	if m.updateTenantErr != nil {
		return nil, m.updateTenantErr
	}
	return m.tenant, nil
}

func (m *mockTenantService) UpdateTenantStatus(ctx context.Context, tenantID string, status string) error {
	return m.updateStatusErr
}

func (m *mockTenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	return m.deleteTenantErr
}

func (m *mockTenantService) ListTenants(ctx context.Context, req admin.ListTenantsRequest) ([]*admin.TenantInfo, *admin.Pagination, error) {
	if m.listTenantsErr != nil {
		return nil, nil, m.listTenantsErr
	}
	return m.tenants, m.pagination, nil
}

func (m *mockTenantService) CreateTenantRootCA(ctx context.Context, tenantID string, req admin.CreateTenantRootCARequest) (*admin.TenantRootCAInfo, error) {
	if m.createRootCAErr != nil {
		return nil, m.createRootCAErr
	}
	return m.rootCA, nil
}

func (m *mockTenantService) CreateTenantIntermediateCA(ctx context.Context, tenantID string, req admin.CreateTenantIntermediateCARequest) (*admin.TenantIntCAInfo, error) {
	if m.createIntCAErr != nil {
		return nil, m.createIntCAErr
	}
	return m.intCA, nil
}

func (m *mockTenantService) GetTenantIntermediateCA(ctx context.Context, tenantID string, caID string) (*admin.TenantIntCAInfo, error) {
	if m.getIntCAErr != nil {
		return nil, m.getIntCAErr
	}
	return m.intCA, nil
}

func (m *mockTenantService) ListTenantIntermediateCAs(ctx context.Context, tenantID string) ([]*admin.TenantIntCAInfo, error) {
	if m.listIntCAsErr != nil {
		return nil, m.listIntCAsErr
	}
	return m.intCAs, nil
}

func (m *mockTenantService) UpdateTenantIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error {
	return m.updateIntCAErr
}

func (m *mockTenantService) SetTenantDefaultIntermediateCA(ctx context.Context, tenantID string, caID string) error {
	return m.setDefaultCAErr
}

func (m *mockTenantService) GetTenantCAStatus(ctx context.Context, tenantID string) (*admin.TenantCAStatusInfo, error) {
	if m.getTenantCAStatusErr != nil {
		return nil, m.getTenantCAStatusErr
	}
	return m.caStatus, nil
}

func (m *mockTenantService) CreateTenantEAB(ctx context.Context, tenantID string, req admin.CreateEABRequest) (*admin.CreateEABResponse, error) {
	if m.createEABErr != nil {
		return nil, m.createEABErr
	}
	return m.createEABResp, nil
}

func (m *mockTenantService) GetTenantEAB(ctx context.Context, tenantID string, kid string) (*admin.EABInfo, error) {
	if m.getEABErr != nil {
		return nil, m.getEABErr
	}
	return m.eab, nil
}

func (m *mockTenantService) DeleteTenantEAB(ctx context.Context, tenantID string, kid string) error {
	return m.deleteEABErr
}

func (m *mockTenantService) ListTenantEABs(ctx context.Context, tenantID string, req admin.ListEABRequest) ([]*admin.EABInfo, *admin.Pagination, error) {
	if m.listEABsErr != nil {
		return nil, nil, m.listEABsErr
	}
	return m.eabs, m.pagination, nil
}

func (m *mockTenantService) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	if m.createRoleErr != nil {
		return nil, m.createRoleErr
	}
	return m.role, nil
}

func (m *mockTenantService) GetTenantRole(ctx context.Context, tenantID string, roleID string) (*db.Role, error) {
	if m.getRoleErr != nil {
		return nil, m.getRoleErr
	}
	return m.role, nil
}

func (m *mockTenantService) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	if m.updateRoleErr != nil {
		return nil, m.updateRoleErr
	}
	return m.role, nil
}

func (m *mockTenantService) DeleteTenantRole(ctx context.Context, tenantID string, roleID string) error {
	return m.deleteRoleErr
}

func (m *mockTenantService) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	if m.listRolesErr != nil {
		return nil, m.listRolesErr
	}
	return m.roles, nil
}

func (m *mockTenantService) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	if m.createUserErr != nil {
		return nil, m.createUserErr
	}
	return m.user, nil
}

func (m *mockTenantService) GetTenantUser(ctx context.Context, tenantID string, userID string) (*db.User, error) {
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	return m.user, nil
}

func (m *mockTenantService) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	if m.updateUserErr != nil {
		return nil, m.updateUserErr
	}
	return m.user, nil
}

func (m *mockTenantService) DeleteTenantUser(ctx context.Context, tenantID string, userID string) error {
	return m.deleteUserErr
}

func (m *mockTenantService) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	if m.listUsersErr != nil {
		return nil, m.listUsersErr
	}
	return m.users, nil
}

// mockAuthHandler implements admin.AuthHandler for testing.
type mockAuthHandler struct{}

func (m *mockAuthHandler) Authenticate(next http.Handler) http.Handler {
	// Pass-through for testing (no actual auth check)
	return next
}

// --- Helper Functions ---

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestServer(adminSvc admin.Service, tenantSvc admin.TenantService) *MultiProtocolServer {
	server, _ := NewMultiProtocolServer(
		&ServerConfig{
			RESTAddr:     ":0",
			GRPCAddr:     ":0",
			QUICAddr:     ":0",
			MCPAddr:      ":0",
			GRPCUnixPath: "/tmp/test.sock",
			Logger:       newTestLogger(),
		},
		adminSvc,
		tenantSvc,
		&mockAuthHandler{},
	)
	return server
}

// --- Server Tests ---

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, ":8443", config.RESTAddr)
	assert.Equal(t, ":9443", config.GRPCAddr)
	assert.Equal(t, ":9444", config.QUICAddr)
	assert.Equal(t, ":9445", config.MCPAddr)
	assert.Equal(t, DefaultGRPCUnixPath, config.GRPCUnixPath)
	assert.Equal(t, DefaultGRPCUnixMode, config.GRPCUnixMode)
	assert.Equal(t, 30*time.Second, config.ReadTimeout)
	assert.Equal(t, 30*time.Second, config.WriteTimeout)
	assert.Equal(t, 120*time.Second, config.IdleTimeout)
}

func TestNewMultiProtocolServer(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		mockAdmin := &mockAdminService{}
		server, err := NewMultiProtocolServer(nil, mockAdmin, nil, nil)

		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.NotNil(t, server.config)
		assert.NotNil(t, server.router)
	})

	t.Run("with all services", func(t *testing.T) {
		mockAdmin := &mockAdminService{}
		mockTenant := &mockTenantService{}
		mockAuth := &mockAuthHandler{}

		server, err := NewMultiProtocolServer(
			DefaultConfig(),
			mockAdmin,
			mockTenant,
			mockAuth,
		)

		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.Equal(t, mockAdmin, server.adminService)
		assert.Equal(t, mockTenant, server.tenantService)
	})

	t.Run("config without logger uses default", func(t *testing.T) {
		config := DefaultConfig()
		config.Logger = nil

		server, err := NewMultiProtocolServer(config, &mockAdminService{}, nil, nil)

		require.NoError(t, err)
		assert.NotNil(t, server.logger)
	})
}

func TestRunning(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	assert.False(t, server.Running())

	// Manually set running state for testing
	server.running.Store(true)
	assert.True(t, server.Running())
}

// --- MCP Handler Tests ---

func TestHandleMCP_ParseError(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("invalid json")))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32700, resp.Error.Code)
	assert.Equal(t, "Parse error", resp.Error.Message)
}

func TestHandleMCP_InvalidJSONRPCVersion(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	mcpReq := MCPRequest{
		JSONRPC: "1.0", // Wrong version
		Method:  "admin.getStatus",
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Equal(t, "Invalid Request", resp.Error.Message)
}

func TestHandleMCP_GetStatus_Success(t *testing.T) {
	mockAdmin := &mockAdminService{
		caStatus: &admin.CAStatus{
			Identity:    "test-ca",
			Initialized: true,
			Version:     "1.0.0",
			StartedAt:   time.Now(),
		},
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStatus",
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, float64(1), resp.ID)
	assert.NotNil(t, resp.Result)
}

func TestHandleMCP_GetStats_Success(t *testing.T) {
	mockAdmin := &mockAdminService{
		caStats: &admin.CAStats{
			TotalCertificates:   100,
			ValidCertificates:   95,
			RevokedCertificates: 5,
		},
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStats",
		ID:      2,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

func TestHandleMCP_ListCertificates(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		certificates: []*admin.CertificateInfo{
			{
				ID:           1,
				SerialNumber: "123456",
				Subject:      "CN=test",
				NotBefore:    now,
				NotAfter:     now.AddDate(1, 0, 0),
			},
		},
		pagination: &admin.Pagination{Page: 1, PerPage: 10, Total: 1},
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"page":     1,
		"per_page": 10,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listCertificates",
		Params:  paramsJSON,
		ID:      3,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

func TestHandleMCP_GetCertificate(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		certificate: &admin.CertificateInfo{
			ID:           1,
			SerialNumber: "123456",
			Subject:      "CN=test",
			NotBefore:    now,
			NotAfter:     now.AddDate(1, 0, 0),
		},
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]string{"serial": "123456"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getCertificate",
		Params:  paramsJSON,
		ID:      4,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_RevokeCertificate(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	params := map[string]string{"serial": "123456", "reason": "key compromise"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.revokeCertificate",
		Params:  paramsJSON,
		ID:      5,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_NotFoundError(t *testing.T) {
	mockAdmin := &mockAdminService{
		getCertErr: admin.ErrCertificateNotFound,
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]string{"serial": "notfound"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getCertificate",
		Params:  paramsJSON,
		ID:      6,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
	assert.Equal(t, "Not found", resp.Error.Message)
}

func TestHandleMCP_UnauthorizedError(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatusErr: admin.ErrUnauthorized,
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStatus",
		ID:      7,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32002, resp.Error.Code)
	assert.Equal(t, "Unauthorized", resp.Error.Message)
}

func TestHandleMCP_MethodNotFound(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.unknownMethod",
		ID:      8,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

// --- Tenant MCP Operations ---

func TestHandleMCP_TenantOperations_NoTenantService(t *testing.T) {
	// Server without tenant service
	server := newTestServer(&mockAdminService{}, nil)

	testCases := []string{
		"admin.createTenant",
		"admin.getTenant",
		"admin.updateTenant",
		"admin.deleteTenant",
		"admin.listTenants",
		"admin.createEAB",
		"admin.getEAB",
		"admin.deleteEAB",
		"admin.listEABs",
		"admin.createRole",
		"admin.getRole",
		"admin.updateRole",
		"admin.deleteRole",
		"admin.listRoles",
		"admin.createUser",
		"admin.getUser",
		"admin.updateUser",
		"admin.deleteUser",
		"admin.listUsers",
	}

	for _, method := range testCases {
		t.Run(method, func(t *testing.T) {
			params := map[string]string{"tenant_id": "test-tenant"}
			paramsJSON, _ := json.Marshal(params)

			mcpReq := MCPRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  paramsJSON,
				ID:      1,
			}
			body, _ := json.Marshal(mcpReq)

			req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
			rec := httptest.NewRecorder()

			server.handleMCP(rec, req)

			var resp MCPResponse
			err := json.NewDecoder(rec.Body).Decode(&resp)
			require.NoError(t, err)

			assert.NotNil(t, resp.Error)
			assert.Equal(t, -32603, resp.Error.Code)
		})
	}
}

func TestHandleMCP_CreateTenant(t *testing.T) {
	mockTenant := &mockTenantService{
		tenant: &admin.TenantInfo{
			ID:     "test-tenant",
			Name:   "Test Tenant",
			Status: "active",
		},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"id":   "test-tenant",
		"name": "Test Tenant",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_CreateTenant_AutoGenerateID(t *testing.T) {
	mockTenant := &mockTenantService{
		tenant: &admin.TenantInfo{
			Name:   "Test Tenant",
			Status: "active",
		},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	// No ID provided - should be auto-generated
	params := map[string]string{
		"name": "Test Tenant",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_GetTenant(t *testing.T) {
	mockTenant := &mockTenantService{
		tenant: &admin.TenantInfo{
			ID:     "test-tenant",
			Name:   "Test Tenant",
			Status: "active",
		},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "test-tenant"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_UpdateTenant(t *testing.T) {
	mockTenant := &mockTenantService{
		tenant: &admin.TenantInfo{
			ID:     "test-tenant",
			Name:   "Updated Tenant",
			Status: "active",
		},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenant_id": "test-tenant",
		"name":      "Updated Tenant",
		"settings": map[string]interface{}{
			"max_certificates": 1000,
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_DeleteTenant(t *testing.T) {
	mockTenant := &mockTenantService{}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "test-tenant"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_ListTenants(t *testing.T) {
	mockTenant := &mockTenantService{
		tenants: []*admin.TenantInfo{
			{ID: "tenant-1", Name: "Tenant 1"},
			{ID: "tenant-2", Name: "Tenant 2"},
		},
		pagination: &admin.Pagination{Page: 1, PerPage: 20, Total: 2},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{"page": 1, "per_page": 20}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listTenants",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

// --- EAB MCP Operations ---

func TestHandleMCP_CreateEAB(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour)
	mockTenant := &mockTenantService{
		createEABResp: &admin.CreateEABResponse{
			ID:        "eab-123",
			MACKey:    "mac-key-base64",
			Algorithm: "HS256",
			ExpiresAt: &expiry,
		},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenant_id":       "test-tenant",
		"purpose":         "account-binding",
		"expires_in_days": 30,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_GetEAB(t *testing.T) {
	mockTenant := &mockTenantService{
		eab: &admin.EABInfo{
			ID:       "eab-123",
			TenantID: "test-tenant",
			Status:   "active",
			Purpose:  "account-binding",
		},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenant_id": "test-tenant",
		"kid":       "eab-123",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_DeleteEAB(t *testing.T) {
	mockTenant := &mockTenantService{}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenant_id": "test-tenant",
		"kid":       "eab-123",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

func TestHandleMCP_ListEABs(t *testing.T) {
	mockTenant := &mockTenantService{
		eabs: []*admin.EABInfo{
			{ID: "eab-1", TenantID: "test-tenant"},
			{ID: "eab-2", TenantID: "test-tenant"},
		},
		pagination: &admin.Pagination{Page: 1, PerPage: 20, Total: 2},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenant_id": "test-tenant",
		"page":      1,
		"per_page":  20,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listEABs",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

// --- MCP Parse Error Tests ---

func TestHandleMCP_InvalidParamsUnmarshal(t *testing.T) {
	// Test that invalid JSON structure in params causes an error.
	// Go's JSON unmarshal is lenient with type mismatches, so we test
	// with completely wrong structure that breaks unmarshaling.
	server := newTestServer(&mockAdminService{}, &mockTenantService{})

	testCases := []struct {
		name   string
		method string
		params string
	}{
		// Use array where object is expected
		{"listCertificates_array", "admin.listCertificates", `[1, 2, 3]`},
		{"getCertificate_array", "admin.getCertificate", `["serial"]`},
		{"getTenant_array", "admin.getTenant", `["tenant"]`},
		// Nested invalid structure
		{"createTenant_nested_invalid", "admin.createTenant", `{"id": {"nested": "value"}}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mcpReq := MCPRequest{
				JSONRPC: "2.0",
				Method:  tc.method,
				Params:  json.RawMessage(tc.params),
				ID:      1,
			}
			body, err := json.Marshal(mcpReq)
			require.NoError(t, err)

			req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
			rec := httptest.NewRecorder()

			server.handleMCP(rec, req)

			var resp MCPResponse
			err = json.NewDecoder(rec.Body).Decode(&resp)
			require.NoError(t, err)

			// Should return an error (either internal error -32603 or specific error)
			assert.NotNil(t, resp.Error, "Expected error for invalid params")
		})
	}
}

func TestHandleMCP_MalformedRequestBody(t *testing.T) {
	// Test that completely malformed JSON request body returns parse error
	server := newTestServer(&mockAdminService{}, nil)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"invalid json`)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32700, resp.Error.Code)
	assert.Equal(t, "Parse error", resp.Error.Message)
}

// --- Write Response Tests ---

func TestWriteMCPResponse(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	rec := httptest.NewRecorder()
	server.writeMCPResponse(rec, "test-id", map[string]string{"key": "value"})

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, "test-id", resp.ID)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestWriteMCPError(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	rec := httptest.NewRecorder()
	server.writeMCPError(rec, "test-id", -32600, "Test error", "Additional data")

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, "test-id", resp.ID)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Equal(t, "Test error", resp.Error.Message)
	assert.Equal(t, "Additional data", resp.Error.Data)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// --- Health Check Test ---

func TestHealthCheckEndpoint(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "healthy")
}

// --- gRPC Service Tests ---

func TestNewAdminServiceServer(t *testing.T) {
	mockAdmin := &mockAdminService{}
	mockTenant := &mockTenantService{}
	logger := newTestLogger()

	server := NewAdminServiceServer(mockAdmin, mockTenant, logger)

	assert.NotNil(t, server)
}

func TestGRPC_CreateTenant(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.CreateTenant(context.Background(), &adminv1.CreateTenantRequest{
			Name: "test",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("success", func(t *testing.T) {
		now := time.Now()
		mockTenant := &mockTenantService{
			tenant: &admin.TenantInfo{
				ID:        "test-tenant",
				Name:      "Test Tenant",
				Status:    "active",
				CreatedAt: now,
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.CreateTenant(context.Background(), &adminv1.CreateTenantRequest{
			Id:   "test-tenant",
			Name: "Test Tenant",
		})

		require.NoError(t, err)
		assert.Equal(t, "test-tenant", resp.Id)
		assert.Equal(t, "Test Tenant", resp.Name)
	})

	t.Run("auto-generate ID", func(t *testing.T) {
		mockTenant := &mockTenantService{
			tenant: &admin.TenantInfo{
				Name:   "Test Tenant",
				Status: "active",
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.CreateTenant(context.Background(), &adminv1.CreateTenantRequest{
			Name: "Test Tenant",
		})

		require.NoError(t, err)
		assert.NotEmpty(t, resp.Name)
	})

	t.Run("with settings", func(t *testing.T) {
		mockTenant := &mockTenantService{
			tenant: &admin.TenantInfo{
				Name: "Test Tenant",
				Settings: &admin.TenantSettingsInfo{
					MaxCertificates: 1000,
				},
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.CreateTenant(context.Background(), &adminv1.CreateTenantRequest{
			Name: "Test Tenant",
			Settings: &adminv1.TenantSettings{
				MaxCertificates: 1000,
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("error from service", func(t *testing.T) {
		mockTenant := &mockTenantService{
			createTenantErr: admin.ErrTenantAlreadyExists,
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.CreateTenant(context.Background(), &adminv1.CreateTenantRequest{
			Name: "Test Tenant",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})
}

func TestGRPC_GetTenant(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.GetTenant(context.Background(), &adminv1.GetTenantRequest{
			TenantId: "test-tenant",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("success", func(t *testing.T) {
		mockTenant := &mockTenantService{
			tenant: &admin.TenantInfo{
				ID:     "test-tenant",
				Name:   "Test Tenant",
				Status: "active",
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.GetTenant(context.Background(), &adminv1.GetTenantRequest{
			TenantId: "test-tenant",
		})

		require.NoError(t, err)
		assert.Equal(t, "test-tenant", resp.Id)
	})

	t.Run("not found", func(t *testing.T) {
		mockTenant := &mockTenantService{
			getTenantErr: admin.ErrTenantNotFound,
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.GetTenant(context.Background(), &adminv1.GetTenantRequest{
			TenantId: "nonexistent",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

func TestGRPC_UpdateTenant(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.UpdateTenant(context.Background(), &adminv1.UpdateTenantRequest{
			TenantId: "test-tenant",
			Name:     "Updated",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("success", func(t *testing.T) {
		mockTenant := &mockTenantService{
			tenant: &admin.TenantInfo{
				ID:   "test-tenant",
				Name: "Updated Tenant",
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.UpdateTenant(context.Background(), &adminv1.UpdateTenantRequest{
			TenantId: "test-tenant",
			Name:     "Updated Tenant",
		})

		require.NoError(t, err)
		assert.Equal(t, "Updated Tenant", resp.Name)
	})

	t.Run("with settings", func(t *testing.T) {
		mockTenant := &mockTenantService{
			tenant: &admin.TenantInfo{
				ID: "test-tenant",
				Settings: &admin.TenantSettingsInfo{
					MaxCertificates: 2000,
				},
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.UpdateTenant(context.Background(), &adminv1.UpdateTenantRequest{
			TenantId: "test-tenant",
			Settings: &adminv1.TenantSettings{
				MaxCertificates: 2000,
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

func TestGRPC_DeleteTenant(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.DeleteTenant(context.Background(), &adminv1.DeleteTenantRequest{
			TenantId: "test-tenant",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("success", func(t *testing.T) {
		mockTenant := &mockTenantService{}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.DeleteTenant(context.Background(), &adminv1.DeleteTenantRequest{
			TenantId: "test-tenant",
		})

		require.NoError(t, err)
		assert.IsType(t, &emptypb.Empty{}, resp)
	})
}

func TestGRPC_ListTenants(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.ListTenants(context.Background(), &adminv1.ListTenantsRequest{})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("success", func(t *testing.T) {
		mockTenant := &mockTenantService{
			tenants: []*admin.TenantInfo{
				{ID: "tenant-1", Name: "Tenant 1"},
				{ID: "tenant-2", Name: "Tenant 2"},
			},
			pagination: &admin.Pagination{Page: 1, PerPage: 20, Total: 2},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.ListTenants(context.Background(), &adminv1.ListTenantsRequest{
			Page:    1,
			PerPage: 20,
		})

		require.NoError(t, err)
		assert.Len(t, resp.Tenants, 2)
		assert.Equal(t, int32(2), resp.Pagination.Total)
	})
}

// --- gRPC EAB Operations ---

func TestGRPC_CreateEAB(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.CreateEAB(context.Background(), &adminv1.CreateEABRequest{
			TenantId: "test-tenant",
		})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("success", func(t *testing.T) {
		expiry := time.Now().Add(24 * time.Hour)
		mockTenant := &mockTenantService{
			createEABResp: &admin.CreateEABResponse{
				ID:        "eab-123",
				MACKey:    "mac-key",
				Algorithm: "HS256",
				ExpiresAt: &expiry,
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.CreateEAB(context.Background(), &adminv1.CreateEABRequest{
			TenantId:      "test-tenant",
			Purpose:       "account-binding",
			ExpiresInDays: 30,
		})

		require.NoError(t, err)
		assert.Equal(t, "eab-123", resp.Id)
		assert.NotNil(t, resp.ExpiresAt)
	})

	t.Run("with device info", func(t *testing.T) {
		mockTenant := &mockTenantService{
			createEABResp: &admin.CreateEABResponse{
				ID:        "eab-123",
				MACKey:    "mac-key",
				Algorithm: "HS256",
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.CreateEAB(context.Background(), &adminv1.CreateEABRequest{
			TenantId: "test-tenant",
			DeviceInfo: &adminv1.EABDeviceInfo{
				DeviceId:     "device-1",
				Manufacturer: "TestCorp",
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "eab-123", resp.Id)
	})

	t.Run("without expiry", func(t *testing.T) {
		mockTenant := &mockTenantService{
			createEABResp: &admin.CreateEABResponse{
				ID:        "eab-123",
				MACKey:    "mac-key",
				Algorithm: "HS256",
				ExpiresAt: nil,
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.CreateEAB(context.Background(), &adminv1.CreateEABRequest{
			TenantId: "test-tenant",
		})

		require.NoError(t, err)
		assert.Nil(t, resp.ExpiresAt)
	})
}

func TestGRPC_GetEAB(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.GetEAB(context.Background(), &adminv1.GetEABRequest{
			TenantId: "test-tenant",
			Kid:      "eab-123",
		})

		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		mockTenant := &mockTenantService{
			eab: &admin.EABInfo{
				ID:       "eab-123",
				TenantID: "test-tenant",
				Status:   "active",
			},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.GetEAB(context.Background(), &adminv1.GetEABRequest{
			TenantId: "test-tenant",
			Kid:      "eab-123",
		})

		require.NoError(t, err)
		assert.Equal(t, "eab-123", resp.Id)
	})
}

func TestGRPC_DeleteEAB(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.DeleteEAB(context.Background(), &adminv1.DeleteEABRequest{
			TenantId: "test-tenant",
			Kid:      "eab-123",
		})

		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		mockTenant := &mockTenantService{}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.DeleteEAB(context.Background(), &adminv1.DeleteEABRequest{
			TenantId: "test-tenant",
			Kid:      "eab-123",
		})

		require.NoError(t, err)
		assert.IsType(t, &emptypb.Empty{}, resp)
	})
}

func TestGRPC_ListEABs(t *testing.T) {
	t.Run("tenant service not available", func(t *testing.T) {
		server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		_, err := grpcServer.ListEABs(context.Background(), &adminv1.ListEABsRequest{
			TenantId: "test-tenant",
		})

		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		mockTenant := &mockTenantService{
			eabs: []*admin.EABInfo{
				{ID: "eab-1"},
				{ID: "eab-2"},
			},
			pagination: &admin.Pagination{Page: 1, PerPage: 20, Total: 2},
		}
		server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
		grpcServer := server.(*adminServiceServer)

		resp, err := grpcServer.ListEABs(context.Background(), &adminv1.ListEABsRequest{
			TenantId: "test-tenant",
		})

		require.NoError(t, err)
		assert.Len(t, resp.Eabs, 2)
	})
}

// --- gRPC Certificate Operations ---

func TestGRPC_ListCertificates(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		certificates: []*admin.CertificateInfo{
			{
				ID:           1,
				SerialNumber: "123456",
				Subject:      "CN=test",
				NotBefore:    now,
				NotAfter:     now.AddDate(1, 0, 0),
				IssuedAt:     now,
			},
		},
		pagination: &admin.Pagination{Page: 1, PerPage: 10, Total: 1},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.ListCertificates(context.Background(), &adminv1.ListCertificatesRequest{
		Page:    1,
		PerPage: 10,
	})

	require.NoError(t, err)
	assert.Len(t, resp.Certificates, 1)
	assert.Equal(t, "123456", resp.Certificates[0].SerialNumber)
}

func TestGRPC_GetCertificate(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		certificate: &admin.CertificateInfo{
			ID:           1,
			SerialNumber: "123456",
			Subject:      "CN=test",
			NotBefore:    now,
			NotAfter:     now.AddDate(1, 0, 0),
		},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.GetCertificate(context.Background(), &adminv1.GetCertificateRequest{
		Serial: "123456",
	})

	require.NoError(t, err)
	assert.Equal(t, "123456", resp.SerialNumber)
}

func TestGRPC_GetCertificate_NotFound(t *testing.T) {
	mockAdmin := &mockAdminService{
		getCertErr: admin.ErrCertificateNotFound,
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.GetCertificate(context.Background(), &adminv1.GetCertificateRequest{
		Serial: "notfound",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGRPC_RevokeCertificate(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.RevokeCertificate(context.Background(), &adminv1.RevokeCertificateRequest{
		Serial: "123456",
		Reason: "key compromise",
	})

	require.NoError(t, err)
	assert.IsType(t, &emptypb.Empty{}, resp)
}

func TestGRPC_RevokeCertificate_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		revokeErr: admin.ErrCertificateNotFound,
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.RevokeCertificate(context.Background(), &adminv1.RevokeCertificateRequest{
		Serial: "notfound",
	})

	assert.Error(t, err)
}

// --- gRPC Status Operations ---

func TestGRPC_GetStatus(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		caStatus: &admin.CAStatus{
			Identity:    "test-ca",
			Initialized: true,
			Version:     "1.0.0",
			StartedAt:   now,
		},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.GetStatus(context.Background(), &emptypb.Empty{})

	require.NoError(t, err)
	assert.Equal(t, "test-ca", resp.Identity)
	assert.True(t, resp.Initialized)
	assert.NotNil(t, resp.StartedAt)
}

func TestGRPC_GetStatus_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatusErr: errors.New("internal error"),
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.GetStatus(context.Background(), &emptypb.Empty{})

	assert.Error(t, err)
}

func TestGRPC_GetStats(t *testing.T) {
	mockAdmin := &mockAdminService{
		caStats: &admin.CAStats{
			TotalCertificates:   100,
			ValidCertificates:   95,
			RevokedCertificates: 3,
			ExpiredCertificates: 2,
			TotalAccounts:       50,
			ActiveAccounts:      45,
			TotalOrders:         200,
			PendingOrders:       5,
			CompletedOrders:     195,
		},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.GetStats(context.Background(), &emptypb.Empty{})

	require.NoError(t, err)
	assert.Equal(t, int32(100), resp.TotalCertificates)
	assert.Equal(t, int32(95), resp.ValidCertificates)
}

func TestGRPC_GetStats_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatsErr: errors.New("internal error"),
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.GetStats(context.Background(), &emptypb.Empty{})

	assert.Error(t, err)
}

// --- Conversion Helper Tests ---

func TestConvertAdminErrorToGRPC(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected codes.Code
	}{
		{"not found - certificate", admin.ErrCertificateNotFound, codes.NotFound},
		{"not found - account", admin.ErrAccountNotFound, codes.NotFound},
		{"not found - tenant", admin.ErrTenantNotFound, codes.NotFound},
		{"validation - invalid request", admin.ErrInvalidRequest, codes.InvalidArgument},
		{"validation - invalid tenant id", admin.ErrInvalidTenantID, codes.InvalidArgument},
		{"already exists - tenant", admin.ErrTenantAlreadyExists, codes.AlreadyExists},
		{"unauthorized", admin.ErrUnauthorized, codes.PermissionDenied},
		{"forbidden", admin.ErrForbidden, codes.PermissionDenied},
		{"internal - generic", errors.New("some error"), codes.Internal},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grpcErr := convertAdminErrorToGRPC(tc.err)
			st, ok := status.FromError(grpcErr)
			require.True(t, ok)
			assert.Equal(t, tc.expected, st.Code())
		})
	}
}

func TestConvertAdminTenantToProto_Nil(t *testing.T) {
	result := convertAdminTenantToProto(nil)
	assert.Nil(t, result)
}

func TestConvertAdminTenantToProto_Full(t *testing.T) {
	now := time.Now()
	tenant := &admin.TenantInfo{
		ID:                      "test-tenant",
		Name:                    "Test Tenant",
		Status:                  "active",
		DefaultIntermediateCAID: "int-ca-1",
		CreatedBy:               "admin",
		CreatedAt:               now,
		UpdatedAt:               now,
		RootCA: &admin.TenantRootCAInfo{
			CommonName:   "Root CA",
			SerialNumber: "123",
			KeyAlgorithm: "RSA",
			NotBefore:    now,
			NotAfter:     now.AddDate(10, 0, 0),
			Status:       "active",
			CreatedAt:    now,
		},
		IntermediateCAs: []*admin.TenantIntCAInfo{
			{
				ID:           "int-ca-1",
				CommonName:   "Int CA 1",
				SerialNumber: "456",
				ParentType:   "tenant",
				Purpose:      "general",
				KeyAlgorithm: "ECDSA",
				NotBefore:    now,
				NotAfter:     now.AddDate(5, 0, 0),
				Status:       "active",
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		Settings: &admin.TenantSettingsInfo{
			MaxCertificates:         1000,
			MaxAccounts:             100,
			AllowedKeyAlgorithms:    []string{"RSA", "ECDSA"},
			AllowedChallengeTypes:   []string{"http-01", "dns-01"},
			CertificateValidityDays: 365,
			RequireEAB:              true,
			AllowEndorse01:          true,
			AllowEnroll01:           true,
		},
	}

	result := convertAdminTenantToProto(tenant)

	assert.Equal(t, "test-tenant", result.Id)
	assert.Equal(t, "Test Tenant", result.Name)
	assert.Equal(t, "active", result.Status)
	assert.NotNil(t, result.RootCa)
	assert.Len(t, result.IntermediateCas, 1)
	assert.NotNil(t, result.Settings)
	assert.Equal(t, int32(1000), result.Settings.MaxCertificates)
	assert.True(t, result.Settings.RequireEab)
}

func TestConvertProtoSettingsToAdmin_Nil(t *testing.T) {
	result := convertProtoSettingsToAdmin(nil)
	assert.Nil(t, result)
}

func TestConvertProtoSettingsToAdmin(t *testing.T) {
	settings := &adminv1.TenantSettings{
		MaxCertificates:         1000,
		MaxAccounts:             100,
		AllowedKeyAlgorithms:    []string{"RSA"},
		AllowedChallengeTypes:   []string{"http-01"},
		CertificateValidityDays: 365,
		RequireEab:              true,
		AllowEndorse_01:         true,
		AllowEnroll_01:          false,
	}

	result := convertProtoSettingsToAdmin(settings)

	assert.Equal(t, 1000, result.MaxCertificates)
	assert.Equal(t, 100, result.MaxAccounts)
	assert.True(t, result.RequireEAB)
	assert.True(t, result.AllowEndorse01)
}

func TestConvertProtoSettingsToAdminInfo_Nil(t *testing.T) {
	result := convertProtoSettingsToAdminInfo(nil)
	assert.Nil(t, result)
}

func TestConvertProtoDeviceInfoToAdmin_Nil(t *testing.T) {
	result := convertProtoDeviceInfoToAdmin(nil)
	assert.Nil(t, result)
}

func TestConvertProtoDeviceInfoToAdmin(t *testing.T) {
	deviceInfo := &adminv1.EABDeviceInfo{
		DeviceId:           "device-1",
		Manufacturer:       "TestCorp",
		Model:              "Model1",
		EkPublicKeyHash:    "hash123",
		TpmManufacturer:    "TPMCorp",
		TpmFirmwareVersion: "1.0",
		Metadata:           map[string]string{"key": "value"},
	}

	result := convertProtoDeviceInfoToAdmin(deviceInfo)

	assert.Equal(t, "device-1", result.DeviceID)
	assert.Equal(t, "TestCorp", result.Manufacturer)
	assert.Equal(t, "hash123", result.EKPublicKeyHash)
}

func TestConvertAdminEABToProto_Nil(t *testing.T) {
	result := convertAdminEABToProto(nil)
	assert.Nil(t, result)
}

func TestConvertAdminEABToProto_Full(t *testing.T) {
	now := time.Now()
	usedAt := now.Add(-time.Hour)
	expiresAt := now.Add(24 * time.Hour)

	eab := &admin.EABInfo{
		ID:                "eab-123",
		TenantID:          "test-tenant",
		Purpose:           "account-binding",
		Status:            "active",
		AccountID:         123,
		ExternalAccountID: "ext-123",
		Contact:           []string{"admin@example.com"},
		CreatedBy:         "admin",
		CreatedAt:         now,
		UsedAt:            &usedAt,
		ExpiresAt:         &expiresAt,
		DeviceInfo: &admin.EABDeviceInfoDTO{
			DeviceID:     "device-1",
			Manufacturer: "TestCorp",
		},
	}

	result := convertAdminEABToProto(eab)

	assert.Equal(t, "eab-123", result.Id)
	assert.Equal(t, "test-tenant", result.TenantId)
	assert.NotNil(t, result.UsedAt)
	assert.NotNil(t, result.ExpiresAt)
	assert.NotNil(t, result.DeviceInfo)
}

func TestConvertAdminPaginationToProto_Nil(t *testing.T) {
	result := convertAdminPaginationToProto(nil)
	assert.Nil(t, result)
}

func TestConvertAdminPaginationToProto(t *testing.T) {
	pagination := &admin.Pagination{
		Page:    1,
		PerPage: 20,
		Total:   100,
	}

	result := convertAdminPaginationToProto(pagination)

	assert.Equal(t, int32(1), result.Page)
	assert.Equal(t, int32(20), result.PerPage)
	assert.Equal(t, int32(100), result.Total)
}

func TestConvertAdminCertToProto_Nil(t *testing.T) {
	result := convertAdminCertToProto(nil)
	assert.Nil(t, result)
}

func TestConvertAdminCertToProto_Full(t *testing.T) {
	now := time.Now()
	cert := &admin.CertificateInfo{
		ID:           1,
		SerialNumber: "123456",
		Subject:      "CN=test",
		Issuer:       "CN=issuer",
		Status:       "valid",
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		IssuedAt:     now,
		CertURL:      "https://example.com/cert",
	}

	result := convertAdminCertToProto(cert)

	assert.Equal(t, "123456", result.SerialNumber)
	assert.Equal(t, "CN=test", result.Subject)
	assert.NotNil(t, result.NotBefore)
	assert.NotNil(t, result.NotAfter)
}

// --- Error Path Tests ---

func TestHandleMCP_AccountNotFoundError(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatusErr: admin.ErrAccountNotFound,
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStatus",
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
}

func TestHandleMCP_OrderNotFoundError(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatusErr: admin.ErrOrderNotFound,
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStatus",
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
}

func TestHandleMCP_TenantNotFoundError(t *testing.T) {
	mockTenant := &mockTenantService{
		getTenantErr: admin.ErrTenantNotFound,
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "nonexistent"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
}

// --- Additional Edge Cases ---

func TestConvertAdminTenantToProto_ZeroTimes(t *testing.T) {
	tenant := &admin.TenantInfo{
		ID:   "test-tenant",
		Name: "Test",
		// CreatedAt and UpdatedAt are zero values
	}

	result := convertAdminTenantToProto(tenant)

	assert.Nil(t, result.CreatedAt)
	assert.Nil(t, result.UpdatedAt)
}

func TestConvertAdminTenantToProto_RootCAZeroTimes(t *testing.T) {
	tenant := &admin.TenantInfo{
		ID:   "test-tenant",
		Name: "Test",
		RootCA: &admin.TenantRootCAInfo{
			CommonName: "Root",
			// NotBefore, NotAfter, CreatedAt are zero
		},
	}

	result := convertAdminTenantToProto(tenant)

	assert.NotNil(t, result.RootCa)
	assert.Nil(t, result.RootCa.NotBefore)
	assert.Nil(t, result.RootCa.NotAfter)
}

func TestConvertAdminEABToProto_ZeroTimes(t *testing.T) {
	eab := &admin.EABInfo{
		ID:       "eab-123",
		TenantID: "test",
		// CreatedAt is zero, UsedAt and ExpiresAt are nil
	}

	result := convertAdminEABToProto(eab)

	assert.Nil(t, result.CreatedAt)
	assert.Nil(t, result.UsedAt)
	assert.Nil(t, result.ExpiresAt)
}

func TestConvertAdminEABToProto_ZeroUsedAtTime(t *testing.T) {
	zeroTime := time.Time{}
	eab := &admin.EABInfo{
		ID:     "eab-123",
		UsedAt: &zeroTime,
	}

	result := convertAdminEABToProto(eab)

	assert.Nil(t, result.UsedAt)
}

func TestConvertAdminEABToProto_ZeroExpiresAtTime(t *testing.T) {
	zeroTime := time.Time{}
	eab := &admin.EABInfo{
		ID:        "eab-123",
		ExpiresAt: &zeroTime,
	}

	result := convertAdminEABToProto(eab)

	assert.Nil(t, result.ExpiresAt)
}

func TestConvertAdminCertToProto_ZeroTimes(t *testing.T) {
	cert := &admin.CertificateInfo{
		SerialNumber: "123",
		// NotBefore, NotAfter, IssuedAt are zero
	}

	result := convertAdminCertToProto(cert)

	assert.Nil(t, result.NotBefore)
	assert.Nil(t, result.NotAfter)
	assert.Nil(t, result.IssuedAt)
}

func TestGRPC_GetStatus_ZeroStartedAt(t *testing.T) {
	mockAdmin := &mockAdminService{
		caStatus: &admin.CAStatus{
			Identity:    "test-ca",
			Initialized: true,
			// StartedAt is zero
		},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.GetStatus(context.Background(), &emptypb.Empty{})

	require.NoError(t, err)
	assert.Nil(t, resp.StartedAt)
}

// --- Additional gRPC Error Path Tests ---

func TestGRPC_UpdateTenant_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		updateTenantErr: admin.ErrTenantNotFound,
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.UpdateTenant(context.Background(), &adminv1.UpdateTenantRequest{
		TenantId: "nonexistent",
		Name:     "Updated",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGRPC_DeleteTenant_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteTenantErr: admin.ErrTenantNotFound,
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.DeleteTenant(context.Background(), &adminv1.DeleteTenantRequest{
		TenantId: "nonexistent",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGRPC_ListTenants_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		listTenantsErr: errors.New("storage error"),
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.ListTenants(context.Background(), &adminv1.ListTenantsRequest{})

	assert.Error(t, err)
}

func TestGRPC_CreateEAB_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		createEABErr: errors.New("failed to create EAB"),
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.CreateEAB(context.Background(), &adminv1.CreateEABRequest{
		TenantId: "test-tenant",
	})

	assert.Error(t, err)
}

func TestGRPC_GetEAB_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		getEABErr: admin.ErrEABNotFound,
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.GetEAB(context.Background(), &adminv1.GetEABRequest{
		TenantId: "test-tenant",
		Kid:      "nonexistent",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGRPC_DeleteEAB_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteEABErr: admin.ErrEABNotFound,
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.DeleteEAB(context.Background(), &adminv1.DeleteEABRequest{
		TenantId: "test-tenant",
		Kid:      "nonexistent",
	})

	assert.Error(t, err)
}

func TestGRPC_ListEABs_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		listEABsErr: errors.New("storage error"),
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.ListEABs(context.Background(), &adminv1.ListEABsRequest{
		TenantId: "test-tenant",
	})

	assert.Error(t, err)
}

func TestGRPC_ListCertificates_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		listCertsErr: errors.New("storage error"),
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.ListCertificates(context.Background(), &adminv1.ListCertificatesRequest{})

	assert.Error(t, err)
}

// --- Additional MCP Tests ---

func TestHandleMCP_ListCertificates_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		listCertsErr: errors.New("storage error"),
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{"page": 1}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listCertificates",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestHandleMCP_CreateTenant_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		createTenantErr: admin.ErrTenantAlreadyExists,
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"id": "existing-tenant", "name": "Test"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_UpdateTenant_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		updateTenantErr: admin.ErrTenantNotFound,
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "nonexistent", "name": "Updated"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_DeleteTenant_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteTenantErr: admin.ErrTenantNotFound,
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "nonexistent"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_ListTenants_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		listTenantsErr: errors.New("storage error"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{"page": 1}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listTenants",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_CreateEAB_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		createEABErr: errors.New("failed to create EAB"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "test-tenant"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_GetEAB_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		getEABErr: admin.ErrEABNotFound,
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "test-tenant", "kid": "nonexistent"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_DeleteEAB_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteEABErr: admin.ErrEABNotFound,
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenant_id": "test-tenant", "kid": "nonexistent"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_ListEABs_Error(t *testing.T) {
	mockTenant := &mockTenantService{
		listEABsErr: errors.New("storage error"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{"tenant_id": "test-tenant", "page": 1}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listEABs",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestHandleMCP_RevokeCertificate_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		revokeErr: admin.ErrCertificateNotFound,
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]string{"serial": "nonexistent", "reason": "test"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.revokeCertificate",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
}

// --- Additional Conversion Tests ---

func TestConvertAdminTenantToProto_IntermediateCAZeroTimes(t *testing.T) {
	tenant := &admin.TenantInfo{
		ID:   "test-tenant",
		Name: "Test",
		IntermediateCAs: []*admin.TenantIntCAInfo{
			{
				ID:         "int-ca-1",
				CommonName: "Int CA",
				// NotBefore, NotAfter, CreatedAt, UpdatedAt are zero
			},
		},
	}

	result := convertAdminTenantToProto(tenant)

	assert.Len(t, result.IntermediateCas, 1)
	assert.Nil(t, result.IntermediateCas[0].NotBefore)
	assert.Nil(t, result.IntermediateCas[0].NotAfter)
	assert.Nil(t, result.IntermediateCas[0].CreatedAt)
	assert.Nil(t, result.IntermediateCas[0].UpdatedAt)
}

func TestConvertAdminTenantToProto_NoSettings(t *testing.T) {
	tenant := &admin.TenantInfo{
		ID:       "test-tenant",
		Name:     "Test",
		Settings: nil,
	}

	result := convertAdminTenantToProto(tenant)

	assert.Nil(t, result.Settings)
}

func TestConvertAdminTenantToProto_NoIntermediateCAs(t *testing.T) {
	tenant := &admin.TenantInfo{
		ID:              "test-tenant",
		Name:            "Test",
		IntermediateCAs: nil,
	}

	result := convertAdminTenantToProto(tenant)

	assert.Nil(t, result.IntermediateCas)
}

func TestConvertAdminEABToProto_NoDeviceInfo(t *testing.T) {
	eab := &admin.EABInfo{
		ID:         "eab-123",
		DeviceInfo: nil,
	}

	result := convertAdminEABToProto(eab)

	assert.Nil(t, result.DeviceInfo)
}

func TestConvertAdminEABToProto_WithCreatedAtNonZero(t *testing.T) {
	now := time.Now()
	eab := &admin.EABInfo{
		ID:        "eab-123",
		CreatedAt: now,
	}

	result := convertAdminEABToProto(eab)

	assert.NotNil(t, result.CreatedAt)
}

// --- Build Router Test ---

func TestBuildRouter_WithTenantService(t *testing.T) {
	mockAdmin := &mockAdminService{}
	mockTenant := &mockTenantService{}
	mockAuth := &mockAuthHandler{}

	server, err := NewMultiProtocolServer(
		DefaultConfig(),
		mockAdmin,
		mockTenant,
		mockAuth,
	)

	require.NoError(t, err)
	assert.NotNil(t, server.router)

	// Verify /mcp endpoint is registered
	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", nil))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	// Should get a response (even if error due to empty body)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}

func TestBuildRouter_WithoutTenantService(t *testing.T) {
	mockAdmin := &mockAdminService{}
	mockAuth := &mockAuthHandler{}

	server, err := NewMultiProtocolServer(
		DefaultConfig(),
		mockAdmin,
		nil, // No tenant service
		mockAuth,
	)

	require.NoError(t, err)
	assert.NotNil(t, server.router)
}

// --- Additional EAB MCP Tests with DeviceInfo ---

func TestHandleMCP_CreateEAB_WithDeviceInfo(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour)
	mockTenant := &mockTenantService{
		createEABResp: &admin.CreateEABResponse{
			ID:        "eab-123",
			MACKey:    "mac-key",
			Algorithm: "HS256",
			ExpiresAt: &expiry,
		},
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenant_id":           "test-tenant",
		"purpose":             "endorse-01",
		"expires_in_days":     30,
		"contact":             []string{"admin@example.com"},
		"external_account_id": "ext-123",
		"device_info": map[string]interface{}{
			"device_id":            "device-1",
			"manufacturer":         "TestCorp",
			"model":                "Model1",
			"ek_public_key_hash":   "hash123",
			"tpm_manufacturer":     "TPMCorp",
			"tpm_firmware_version": "1.0",
			"metadata": map[string]string{
				"key": "value",
			},
		},
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

// --- Test GetStatus and GetStats errors ---

func TestHandleMCP_GetStatus_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatusErr: errors.New("internal error"),
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStatus",
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestHandleMCP_GetStats_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatsErr: errors.New("internal error"),
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStats",
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestHandleMCP_GetCertificate_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		getCertErr: errors.New("internal error"),
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]string{"serial": "123"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getCertificate",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := mcpAuthenticatedRequest(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body)))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

// --- Additional CreateEAB Tests ---

func TestGRPC_CreateEAB_WithoutExpiry(t *testing.T) {
	mockTenant := &mockTenantService{
		createEABResp: &admin.CreateEABResponse{
			ID:        "eab-123",
			MACKey:    "mac-key",
			Algorithm: "HS256",
			ExpiresAt: nil, // No expiry
		},
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.CreateEAB(context.Background(), &adminv1.CreateEABRequest{
		TenantId: "test-tenant",
	})

	require.NoError(t, err)
	assert.Nil(t, resp.ExpiresAt)
}

func TestGRPC_CreateEAB_ZeroExpiry(t *testing.T) {
	zeroTime := time.Time{}
	mockTenant := &mockTenantService{
		createEABResp: &admin.CreateEABResponse{
			ID:        "eab-123",
			MACKey:    "mac-key",
			Algorithm: "HS256",
			ExpiresAt: &zeroTime, // Zero time
		},
	}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.CreateEAB(context.Background(), &adminv1.CreateEABRequest{
		TenantId: "test-tenant",
	})

	require.NoError(t, err)
	// Zero time should not be set
	assert.Nil(t, resp.ExpiresAt)
}

// --- Server Lifecycle Tests (Without Network Operations) ---

func TestStart_AlreadyRunning(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	// Manually set running state
	server.running.Store(true)

	err := server.Start(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestShutdown_NotRunning(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	// Server is not running, shutdown should be no-op
	err := server.Shutdown(context.Background())

	assert.NoError(t, err)
}

func TestShutdown_NilServers(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	// Manually set running state but leave all servers nil
	server.running.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := server.Shutdown(ctx)

	assert.NoError(t, err)
	assert.False(t, server.Running())
}

// --- Test Proto conversion with times ---

func TestConvertAdminTenantToProto_WithAllTimestamps(t *testing.T) {
	now := time.Now()
	tenant := &admin.TenantInfo{
		ID:        "test-tenant",
		Name:      "Test",
		CreatedAt: now,
		UpdatedAt: now.Add(time.Hour),
		RootCA: &admin.TenantRootCAInfo{
			CommonName: "Root",
			NotBefore:  now,
			NotAfter:   now.AddDate(10, 0, 0),
			CreatedAt:  now,
		},
		IntermediateCAs: []*admin.TenantIntCAInfo{
			{
				ID:         "int-1",
				CommonName: "Int CA",
				NotBefore:  now,
				NotAfter:   now.AddDate(5, 0, 0),
				CreatedAt:  now,
				UpdatedAt:  now.Add(time.Hour),
			},
		},
	}

	result := convertAdminTenantToProto(tenant)

	assert.NotNil(t, result.CreatedAt)
	assert.NotNil(t, result.UpdatedAt)
	assert.NotNil(t, result.RootCa.NotBefore)
	assert.NotNil(t, result.RootCa.NotAfter)
	assert.NotNil(t, result.RootCa.CreatedAt)
	assert.NotNil(t, result.IntermediateCas[0].NotBefore)
	assert.NotNil(t, result.IntermediateCas[0].NotAfter)
	assert.NotNil(t, result.IntermediateCas[0].CreatedAt)
	assert.NotNil(t, result.IntermediateCas[0].UpdatedAt)
}
