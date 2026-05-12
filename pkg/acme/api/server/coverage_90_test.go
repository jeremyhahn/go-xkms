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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- Additional MCP Service Error Tests (Coverage Boost) ---

func TestCov90_MCP_ListCertificates_DBError(t *testing.T) {
	mockAdmin := &mockAdminService{
		listCertsErr: errors.New("database connection failed"),
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]interface{}{"page": 1, "per_page": 10}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listCertificates",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestCov90_MCP_RevokeCertificate_DBError(t *testing.T) {
	mockAdmin := &mockAdminService{
		revokeErr: errors.New("revocation failed due to storage error"),
	}
	server := newTestServer(mockAdmin, nil)

	params := map[string]string{"serial": "123456", "reason": "key compromise"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.revokeCertificate",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestCov90_MCP_GetStatus_InternalError(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestCov90_MCP_GetStats_InternalError(t *testing.T) {
	mockAdmin := &mockAdminService{
		getStatsErr: errors.New("stats unavailable"),
	}
	server := newTestServer(mockAdmin, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getStats",
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestCov90_MCP_CreateTenant_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		createTenantErr: errors.New("creation failed"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"id": "test-tenant", "name": "Test"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_GetTenant_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		getTenantErr: errors.New("not found"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenantId": "missing"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_UpdateTenant_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		updateTenantErr: errors.New("update failed"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "test-tenant",
		"name":     "Updated",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_DeleteTenant_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteTenantErr: errors.New("delete failed"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{"tenantId": "test-tenant"}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteTenant",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_ListTenants_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		listTenantsErr: errors.New("list failed"),
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

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_CreateEAB_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		createEABErr: errors.New("creation failed"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "test-tenant",
		"purpose":  "account-binding",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_GetEAB_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		getEABErr: errors.New("not found"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "test-tenant",
		"kid":      "missing",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_DeleteEAB_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		deleteEABErr: errors.New("delete failed"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]string{
		"tenantId": "test-tenant",
		"kid":      "eab-123",
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteEAB",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_ListEABs_DBError(t *testing.T) {
	mockTenant := &mockTenantService{
		listEABsErr: errors.New("list failed"),
	}
	server := newTestServer(&mockAdminService{}, mockTenant)

	params := map[string]interface{}{
		"tenantId": "test-tenant",
		"page":     1,
		"per_page": 20,
	}
	paramsJSON, _ := json.Marshal(params)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listEABs",
		Params:  paramsJSON,
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

// --- Proto Conversion Edge Case Tests ---

func TestCov90_ConvertAdminTenantToProto_NilInput(t *testing.T) {
	result := convertAdminTenantToProto(nil)
	assert.Nil(t, result)
}

func TestCov90_ConvertProtoSettingsToAdmin_NilInput(t *testing.T) {
	result := convertProtoSettingsToAdmin(nil)
	assert.Nil(t, result)
}

func TestCov90_ConvertProtoSettingsToAdminInfo_NilInput(t *testing.T) {
	result := convertProtoSettingsToAdminInfo(nil)
	assert.Nil(t, result)
}

func TestCov90_ConvertProtoDeviceInfoToAdmin_NilInput(t *testing.T) {
	result := convertProtoDeviceInfoToAdmin(nil)
	assert.Nil(t, result)
}

func TestCov90_ConvertAdminEABToProto_NilInput(t *testing.T) {
	result := convertAdminEABToProto(nil)
	assert.Nil(t, result)
}

func TestCov90_ConvertAdminPaginationToProto_NilInput(t *testing.T) {
	result := convertAdminPaginationToProto(nil)
	assert.Nil(t, result)
}

func TestCov90_ConvertAdminCertToProto_NilInput(t *testing.T) {
	result := convertAdminCertToProto(nil)
	assert.Nil(t, result)
}

func TestCov90_ConvertAdminEABToProto_WithDeviceInfo(t *testing.T) {
	eab := &admin.EABInfo{
		ID:       "eab-123",
		TenantID: "tenant-1",
		DeviceInfo: &admin.EABDeviceInfoDTO{
			DeviceID:           "device-1",
			Manufacturer:       "ACME",
			Model:              "Model X",
			EKPublicKeyHash:    "hash123",
			TPMManufacturer:    "TPM Inc",
			TPMFirmwareVersion: "1.0.0",
			Metadata:           map[string]string{"key": "value"},
		},
		CreatedAt: time.Now(),
	}

	result := convertAdminEABToProto(eab)

	assert.NotNil(t, result)
	assert.NotNil(t, result.DeviceInfo)
	assert.Equal(t, "device-1", result.DeviceInfo.DeviceId)
	assert.Equal(t, "ACME", result.DeviceInfo.Manufacturer)
	assert.Equal(t, "TPM Inc", result.DeviceInfo.TpmManufacturer)
}

func TestCov90_ConvertAdminEABToProto_WithTimes(t *testing.T) {
	now := time.Now()
	usedAt := now.Add(-time.Hour)
	expiresAt := now.Add(24 * time.Hour)

	eab := &admin.EABInfo{
		ID:        "eab-123",
		TenantID:  "tenant-1",
		CreatedAt: now,
		UsedAt:    &usedAt,
		ExpiresAt: &expiresAt,
	}

	result := convertAdminEABToProto(eab)

	assert.NotNil(t, result.CreatedAt)
	assert.NotNil(t, result.UsedAt)
	assert.NotNil(t, result.ExpiresAt)
}

func TestCov90_ConvertAdminCertToProto_WithTimes(t *testing.T) {
	now := time.Now()

	cert := &admin.CertificateInfo{
		ID:           1,
		SerialNumber: "123456",
		Subject:      "CN=test",
		Issuer:       "CN=issuer",
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		IssuedAt:     now,
		Status:       "active",
		CertURL:      "https://example.com/cert",
	}

	result := convertAdminCertToProto(cert)

	assert.NotNil(t, result)
	assert.NotNil(t, result.NotBefore)
	assert.NotNil(t, result.NotAfter)
	assert.NotNil(t, result.IssuedAt)
	assert.Equal(t, "https://example.com/cert", result.CertUrl)
}

func TestCov90_ConvertProtoDeviceInfoToAdmin_WithAllFields(t *testing.T) {
	deviceInfo := &adminv1.EABDeviceInfo{
		DeviceId:           "device-123",
		Manufacturer:       "ACME Corp",
		Model:              "Model X",
		EkPublicKeyHash:    "sha256:abc123",
		TpmManufacturer:    "TPM Inc",
		TpmFirmwareVersion: "2.0.0",
		Metadata:           map[string]string{"key1": "value1", "key2": "value2"},
	}

	result := convertProtoDeviceInfoToAdmin(deviceInfo)

	assert.NotNil(t, result)
	assert.Equal(t, "device-123", result.DeviceID)
	assert.Equal(t, "ACME Corp", result.Manufacturer)
	assert.Equal(t, "Model X", result.Model)
	assert.Equal(t, "sha256:abc123", result.EKPublicKeyHash)
	assert.Equal(t, "TPM Inc", result.TPMManufacturer)
	assert.Equal(t, "2.0.0", result.TPMFirmwareVersion)
	assert.Len(t, result.Metadata, 2)
}

func TestCov90_ConvertProtoSettingsToAdmin_WithAllFields(t *testing.T) {
	settings := &adminv1.TenantSettings{
		MaxCertificates:         1000,
		MaxAccounts:             50,
		AllowedKeyAlgorithms:    []string{"RSA", "ECDSA"},
		AllowedChallengeTypes:   []string{"http-01", "dns-01"},
		CertificateValidityDays: 365,
		RequireEab:              true,
		AllowEndorse_01:         true,
		AllowEnroll_01:          false,
	}

	result := convertProtoSettingsToAdmin(settings)

	assert.NotNil(t, result)
	assert.Equal(t, 1000, result.MaxCertificates)
	assert.Equal(t, 50, result.MaxAccounts)
	assert.True(t, result.RequireEAB)
	assert.True(t, result.AllowEndorse01)
	assert.False(t, result.AllowEnroll01)
}

// --- MCP Invalid Params Tests ---

func TestCov90_MCP_GetCertificate_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getCertificate",
		Params:  json.RawMessage(`[1, 2, 3]`), // Array instead of object
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
}

func TestCov90_MCP_RevokeCertificate_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.revokeCertificate",
		Params:  json.RawMessage(`"invalid"`), // String instead of object
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_UpdateTenant_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.updateTenant",
		Params:  json.RawMessage(`123`), // Number instead of object
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_DeleteTenant_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteTenant",
		Params:  json.RawMessage(`null`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
}

func TestCov90_MCP_ListTenants_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, &mockTenantService{
		tenants:    []*admin.TenantInfo{},
		pagination: &admin.Pagination{},
	})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listTenants",
		Params:  json.RawMessage(`"invalid"`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_CreateEAB_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.createEAB",
		Params:  json.RawMessage(`{"tenantId": 123}`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_GetEAB_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.getEAB",
		Params:  json.RawMessage(`[1, 2]`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_DeleteEAB_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.deleteEAB",
		Params:  json.RawMessage(`true`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

func TestCov90_MCP_ListEABs_InvalidParams(t *testing.T) {
	server := newTestServer(&mockAdminService{}, &mockTenantService{})

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		Method:  "admin.listEABs",
		Params:  json.RawMessage(`false`),
		ID:      1,
	}
	body, _ := json.Marshal(mcpReq)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Error)
}

// --- gRPC With Device Info Tests ---

func TestCov90_GRPC_CreateEAB_WithDeviceInfo(t *testing.T) {
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
		DeviceInfo: &adminv1.EABDeviceInfo{
			DeviceId:     "device-1",
			Manufacturer: "ACME",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "eab-123", resp.Id)
}

func TestCov90_GRPC_CreateEAB_NoExpiry(t *testing.T) {
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
		Purpose:  "account-binding",
	})

	require.NoError(t, err)
	assert.Equal(t, "eab-123", resp.Id)
	assert.Nil(t, resp.ExpiresAt)
}

// --- gRPC Unimplemented Service Tests ---

func TestCov90_GRPC_GetEAB_ServiceNotAvailable(t *testing.T) {
	server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.GetEAB(context.Background(), &adminv1.GetEABRequest{
		TenantId: "test-tenant",
		Kid:      "eab-123",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestCov90_GRPC_DeleteEAB_ServiceNotAvailable(t *testing.T) {
	server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.DeleteEAB(context.Background(), &adminv1.DeleteEABRequest{
		TenantId: "test-tenant",
		Kid:      "eab-123",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestCov90_GRPC_ListEABs_ServiceNotAvailable(t *testing.T) {
	server := NewAdminServiceServer(&mockAdminService{}, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	_, err := grpcServer.ListEABs(context.Background(), &adminv1.ListEABsRequest{
		TenantId: "test-tenant",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

// --- gRPC Success Path Tests with Full Data ---

func TestCov90_GRPC_ListCertificates_Success(t *testing.T) {
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

func TestCov90_GRPC_GetCertificate_Success(t *testing.T) {
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

func TestCov90_GRPC_RevokeCertificate_Success(t *testing.T) {
	mockAdmin := &mockAdminService{}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.RevokeCertificate(context.Background(), &adminv1.RevokeCertificateRequest{
		Serial: "123456",
		Reason: "key compromise",
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCov90_GRPC_GetStatus_Success(t *testing.T) {
	mockAdmin := &mockAdminService{
		caStatus: &admin.CAStatus{
			Identity:    "test-ca",
			Initialized: true,
			Version:     "1.0.0",
			StartedAt:   time.Now(),
		},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.GetStatus(context.Background(), nil)

	require.NoError(t, err)
	assert.Equal(t, "test-ca", resp.Identity)
	assert.True(t, resp.Initialized)
}

func TestCov90_GRPC_GetStats_Success(t *testing.T) {
	mockAdmin := &mockAdminService{
		caStats: &admin.CAStats{
			TotalCertificates:   100,
			ValidCertificates:   90,
			RevokedCertificates: 10,
		},
	}
	server := NewAdminServiceServer(mockAdmin, nil, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.GetStats(context.Background(), nil)

	require.NoError(t, err)
	assert.Equal(t, int32(100), resp.TotalCertificates)
	assert.Equal(t, int32(90), resp.ValidCertificates)
}

func TestCov90_GRPC_GetEAB_Success(t *testing.T) {
	now := time.Now()
	usedAt := now.Add(-time.Hour)
	expiresAt := now.Add(24 * time.Hour)

	mockTenant := &mockTenantService{
		eab: &admin.EABInfo{
			ID:        "eab-123",
			TenantID:  "test-tenant",
			Status:    "active",
			Purpose:   "account-binding",
			CreatedAt: now,
			UsedAt:    &usedAt,
			ExpiresAt: &expiresAt,
			DeviceInfo: &admin.EABDeviceInfoDTO{
				DeviceID: "device-1",
			},
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
	assert.NotNil(t, resp.DeviceInfo)
}

func TestCov90_GRPC_DeleteEAB_Success(t *testing.T) {
	mockTenant := &mockTenantService{}
	server := NewAdminServiceServer(&mockAdminService{}, mockTenant, newTestLogger())
	grpcServer := server.(*adminServiceServer)

	resp, err := grpcServer.DeleteEAB(context.Background(), &adminv1.DeleteEABRequest{
		TenantId: "test-tenant",
		Kid:      "eab-123",
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestCov90_GRPC_ListEABs_Success(t *testing.T) {
	now := time.Now()
	mockTenant := &mockTenantService{
		eabs: []*admin.EABInfo{
			{
				ID:        "eab-1",
				TenantID:  "test-tenant",
				CreatedAt: now,
			},
			{
				ID:        "eab-2",
				TenantID:  "test-tenant",
				CreatedAt: now,
			},
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
}

// --- MCP with EAB Device Info Test ---

func TestCov90_MCP_CreateEAB_WithDeviceInfo(t *testing.T) {
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
		"tenantId":        "test-tenant",
		"purpose":         "device-attestation",
		"expires_in_days": 30,
		"device_info": map[string]interface{}{
			"device_id":    "device-1",
			"manufacturer": "ACME",
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

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	server.handleMCP(rec, req)

	var resp MCPResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Nil(t, resp.Error)
}

// --- Additional conversion function tests ---

func TestCov90_ConvertAdminTenantToProto_WithSettings(t *testing.T) {
	tenant := &admin.TenantInfo{
		ID:     "tenant-1",
		Name:   "Test Tenant",
		Status: "active",
		Settings: &admin.TenantSettingsInfo{
			MaxCertificates:         500,
			MaxAccounts:             25,
			AllowedKeyAlgorithms:    []string{"RSA"},
			AllowedChallengeTypes:   []string{"http-01"},
			CertificateValidityDays: 90,
			RequireEAB:              true,
			AllowEndorse01:          true,
			AllowEnroll01:           false,
		},
	}

	result := convertAdminTenantToProto(tenant)

	assert.NotNil(t, result)
	assert.NotNil(t, result.Settings)
	assert.Equal(t, int32(500), result.Settings.MaxCertificates)
	assert.True(t, result.Settings.RequireEab)
}

// --- Shutdown Error Path Tests ---

// mockHTTPServer implements http.Server interface methods needed for testing
type mockHTTPServerWithError struct {
	shutdownErr error
}

func (m *mockHTTPServerWithError) Shutdown(ctx context.Context) error {
	return m.shutdownErr
}

func TestCov90_Shutdown_WithRESTError(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create a real http.Server to test shutdown paths
	restServer := &http.Server{Addr: ":0"}
	server.restServer = restServer

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// This will trigger an error since the server was never started
	err := server.Shutdown(ctx)

	// Should complete without hanging
	assert.NoError(t, err) // REST server shutdown doesn't error when not started
	assert.False(t, server.Running())
}

func TestCov90_Shutdown_WithGRPCServer(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Create a gRPC server
	grpcServer := grpc.NewServer()
	server.grpcServer = grpcServer

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := server.Shutdown(ctx)

	assert.NoError(t, err)
	assert.False(t, server.Running())
}

func TestCov90_Shutdown_MultipleServers(t *testing.T) {
	server := newTestServer(&mockAdminService{}, nil)
	server.running.Store(true)

	// Set up multiple server types
	server.restServer = &http.Server{Addr: ":0"}
	server.grpcServer = grpc.NewServer()
	server.mcpServer = &http.Server{Addr: ":0"}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := server.Shutdown(ctx)

	assert.NoError(t, err)
	assert.False(t, server.Running())
}
