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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// --- gRPC Account Operations Tests ---

func TestGRPC_ListAccounts_Success(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		accounts: []*admin.AccountInfo{
			{
				ID:                   123,
				Status:               "valid",
				Contact:              []string{"admin@example.com"},
				TermsOfServiceAgreed: true,
				OrdersURL:            "https://acme.example.com/orders/123",
				OrderCount:           5,
				CreatedAt:            now,
			},
			{
				ID:                   456,
				Status:               "deactivated",
				Contact:              []string{"user@example.com"},
				TermsOfServiceAgreed: true,
				OrdersURL:            "https://acme.example.com/orders/456",
				OrderCount:           10,
				CreatedAt:            now.Add(-24 * time.Hour),
			},
		},
		pagination: &admin.Pagination{Page: 1, PerPage: 20, Total: 2},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.ListAccounts(context.Background(), &adminv1.ListAccountsRequest{
		Page:    1,
		PerPage: 20,
	})

	require.NoError(t, err)
	assert.Len(t, resp.Accounts, 2)
	assert.Equal(t, uint64(123), resp.Accounts[0].Id)
	assert.Equal(t, "valid", resp.Accounts[0].Status)
	assert.Equal(t, int32(5), resp.Accounts[0].OrderCount)
	assert.NotNil(t, resp.Pagination)
	assert.Equal(t, int32(2), resp.Pagination.Total)
}

func TestGRPC_ListAccounts_WithStatusFilter(t *testing.T) {
	mockAdmin := &mockAdminService{
		accounts: []*admin.AccountInfo{
			{
				ID:     789,
				Status: "valid",
			},
		},
		pagination: &admin.Pagination{Page: 1, PerPage: 10, Total: 1},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.ListAccounts(context.Background(), &adminv1.ListAccountsRequest{
		Page:    1,
		PerPage: 10,
		Status:  "valid",
	})

	require.NoError(t, err)
	assert.Len(t, resp.Accounts, 1)
}

func TestGRPC_ListAccounts_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		listAccountsErr: errors.New("database connection failed"),
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.ListAccounts(context.Background(), &adminv1.ListAccountsRequest{
		Page:    1,
		PerPage: 20,
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestGRPC_ListAccounts_EmptyResult(t *testing.T) {
	mockAdmin := &mockAdminService{
		accounts:   []*admin.AccountInfo{},
		pagination: &admin.Pagination{Page: 1, PerPage: 20, Total: 0},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.ListAccounts(context.Background(), &adminv1.ListAccountsRequest{
		Page:    1,
		PerPage: 20,
	})

	require.NoError(t, err)
	assert.Empty(t, resp.Accounts)
	assert.Equal(t, int32(0), resp.Pagination.Total)
}

func TestGRPC_GetAccount_Success(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		account: &admin.AccountInfo{
			ID:                   123,
			Status:               "valid",
			Contact:              []string{"admin@example.com", "backup@example.com"},
			TermsOfServiceAgreed: true,
			OrdersURL:            "https://acme.example.com/orders/123",
			OrderCount:           15,
			CreatedAt:            now,
		},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.GetAccount(context.Background(), &adminv1.GetAccountRequest{
		AccountId: 123,
	})

	require.NoError(t, err)
	assert.Equal(t, uint64(123), resp.Id)
	assert.Equal(t, "valid", resp.Status)
	assert.Len(t, resp.Contact, 2)
	assert.True(t, resp.TermsOfServiceAgreed)
	assert.Equal(t, "https://acme.example.com/orders/123", resp.OrdersUrl)
	assert.Equal(t, int32(15), resp.OrderCount)
	assert.NotNil(t, resp.CreatedAt)
}

func TestGRPC_GetAccount_NotFound(t *testing.T) {
	mockAdmin := &mockAdminService{
		getAccountErr: admin.ErrAccountNotFound,
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.GetAccount(context.Background(), &adminv1.GetAccountRequest{
		AccountId: 999,
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGRPC_GetAccount_InternalError(t *testing.T) {
	mockAdmin := &mockAdminService{
		getAccountErr: errors.New("database error"),
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.GetAccount(context.Background(), &adminv1.GetAccountRequest{
		AccountId: 123,
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestGRPC_DisableAccount_Success(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.DisableAccount(context.Background(), &adminv1.DisableAccountRequest{
		AccountId: 123,
	})

	require.NoError(t, err)
	assert.IsType(t, &emptypb.Empty{}, resp)
}

func TestGRPC_DisableAccount_NotFound(t *testing.T) {
	mockAdmin := &mockAdminService{
		disableErr: admin.ErrAccountNotFound,
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.DisableAccount(context.Background(), &adminv1.DisableAccountRequest{
		AccountId: 999,
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGRPC_DisableAccount_InternalError(t *testing.T) {
	mockAdmin := &mockAdminService{
		disableErr: errors.New("database error"),
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.DisableAccount(context.Background(), &adminv1.DisableAccountRequest{
		AccountId: 123,
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// --- MCP Account Operations Tests ---

func TestMCP_ListAccounts_Success(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		accounts: []*admin.AccountInfo{
			{
				ID:        123,
				Status:    "valid",
				CreatedAt: now,
			},
		},
		pagination: &admin.Pagination{Page: 1, PerPage: 10, Total: 1},
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"page":     1,
		"per_page": 10,
		"status":   "valid",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listAccounts",
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
	assert.NotNil(t, resp.Result)

	result, ok := resp.Result.(map[string]interface{})
	require.True(t, ok)
	accounts, ok := result["accounts"].([]interface{})
	require.True(t, ok)
	assert.Len(t, accounts, 1)
}

func TestMCP_ListAccounts_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		listAccountsErr: errors.New("database error"),
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"page":     1,
		"per_page": 10,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listAccounts",
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

func TestMCP_ListAccounts_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	// Invalid params - array instead of object
	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listAccounts",
		Params:  json.RawMessage(`[1, 2, 3]`),
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

func TestMCP_GetAccount_Success(t *testing.T) {
	now := time.Now()
	mockAdmin := &mockAdminService{
		account: &admin.AccountInfo{
			ID:                   123,
			Status:               "valid",
			Contact:              []string{"admin@example.com"},
			TermsOfServiceAgreed: true,
			CreatedAt:            now,
		},
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"account_id": 123,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getAccount",
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
	assert.NotNil(t, resp.Result)
}

func TestMCP_GetAccount_NotFound(t *testing.T) {
	mockAdmin := &mockAdminService{
		getAccountErr: admin.ErrAccountNotFound,
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"account_id": 999,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getAccount",
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

func TestMCP_GetAccount_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	// Invalid params - array instead of object
	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getAccount",
		Params:  json.RawMessage(`["not", "an", "object"]`),
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

func TestMCP_DisableAccount_Success(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"account_id": 123,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.disableAccount",
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

func TestMCP_DisableAccount_Error(t *testing.T) {
	mockAdmin := &mockAdminService{
		disableErr: errors.New("disable failed"),
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"account_id": 123,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.disableAccount",
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

func TestMCP_DisableAccount_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	// Invalid params - array instead of object
	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.disableAccount",
		Params:  json.RawMessage(`[123]`),
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

// --- convertAdminAccountToProto Tests ---

func TestConvertAdminAccountToProto_Nil(t *testing.T) {
	result := convertAdminAccountToProto(nil)
	assert.Nil(t, result)
}

func TestConvertAdminAccountToProto_Full(t *testing.T) {
	now := time.Now()
	account := &admin.AccountInfo{
		ID:                   123,
		Status:               "valid",
		Contact:              []string{"admin@example.com", "backup@example.com"},
		TermsOfServiceAgreed: true,
		OrdersURL:            "https://acme.example.com/orders/123",
		OrderCount:           25,
		CreatedAt:            now,
	}

	result := convertAdminAccountToProto(account)

	require.NotNil(t, result)
	assert.Equal(t, uint64(123), result.Id)
	assert.Equal(t, "valid", result.Status)
	assert.Len(t, result.Contact, 2)
	assert.Equal(t, "admin@example.com", result.Contact[0])
	assert.Equal(t, "backup@example.com", result.Contact[1])
	assert.True(t, result.TermsOfServiceAgreed)
	assert.Equal(t, "https://acme.example.com/orders/123", result.OrdersUrl)
	assert.Equal(t, int32(25), result.OrderCount)
	assert.NotNil(t, result.CreatedAt)
}

func TestConvertAdminAccountToProto_EmptyContact(t *testing.T) {
	now := time.Now()
	account := &admin.AccountInfo{
		ID:        123,
		Status:    "valid",
		Contact:   []string{},
		CreatedAt: now,
	}

	result := convertAdminAccountToProto(account)

	require.NotNil(t, result)
	assert.Empty(t, result.Contact)
}

func TestConvertAdminAccountToProto_ZeroCreatedAt(t *testing.T) {
	account := &admin.AccountInfo{
		ID:     123,
		Status: "valid",
		// CreatedAt is zero value
	}

	result := convertAdminAccountToProto(account)

	require.NotNil(t, result)
	assert.Equal(t, uint64(123), result.Id)
	// CreatedAt should be nil when the time is zero
	assert.Nil(t, result.CreatedAt)
}

func TestConvertAdminAccountToProto_Deactivated(t *testing.T) {
	now := time.Now()
	account := &admin.AccountInfo{
		ID:        456,
		Status:    "deactivated",
		Contact:   []string{"user@example.com"},
		CreatedAt: now,
	}

	result := convertAdminAccountToProto(account)

	require.NotNil(t, result)
	assert.Equal(t, "deactivated", result.Status)
}

// --- MCP Order Not Found Error Test ---

func TestMCP_OrderNotFoundError(t *testing.T) {
	mockAdmin := &mockAdminService{
		getAccountErr: admin.ErrOrderNotFound,
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{
		"account_id": 123,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getAccount",
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

	// ErrOrderNotFound should map to "Not found" error code
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
	assert.Equal(t, "Not found", resp.Error.Message)
}

// --- MCP Tenant Not Found Error Test ---

func TestMCP_TenantNotFoundError(t *testing.T) {
	mockTenant := &mockTenantService{
		getTenantErr: admin.ErrTenantNotFound,
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenantId": "nonexistent"}
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

	// ErrTenantNotFound should map to "Not found" error code
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
	assert.Equal(t, "Not found", resp.Error.Message)
}
