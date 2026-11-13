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

// Package mcp provides Model Context Protocol adapter for go-xkms services.
// MCP enables AI/LLM integration with the CA through a standardized tool interface.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Adapter implements AdminAdapter using MCP (Model Context Protocol).
type Adapter struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
	requestID  atomic.Int64
}

// NewAdapter creates a new MCP adapter.
// Note: MCP uses HTTP transport (not HTTPS). TLSConfig is only used for
// client certificate authentication if the MCP server supports it, not
// for transport encryption.
func NewAdapter(config *api.AdapterConfig) (*Adapter, error) {
	if config.MCPAddr == "" {
		return nil, caerrors.MalformedError("MCP address is required")
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 10,
	}

	// MCP is always HTTP-based. TLSConfig is only for client cert auth, not HTTPS.
	// This is unlike REST/gRPC/QUIC which use TLS for transport encryption.

	return &Adapter{
		baseURL:   "http://" + config.MCPAddr,
		authToken: config.AuthToken,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}, nil
}

// Protocol returns the protocol this adapter uses.
func (a *Adapter) Protocol() api.Protocol {
	return api.ProtocolMCP
}

// Close closes the MCP connection.
func (a *Adapter) Close() error {
	a.httpClient.CloseIdleConnections()
	return nil
}

// call performs a JSON-RPC call to the MCP server.
func (a *Adapter) call(ctx context.Context, method string, params interface{}, result interface{}) error {
	reqID := a.requestID.Add(1)

	rpcReq := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      reqID,
	}

	bodyBytes, err := json.Marshal(rpcReq)
	if err != nil {
		return caerrors.SerializationFailureError("failed to marshal request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/mcp", bytes.NewReader(bodyBytes))
	if err != nil {
		return caerrors.ConnectionFailureError("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return caerrors.ConnectionFailureError("failed to send request: %v", err)
	}
	defer api.CloseResponseBody(resp)

	if resp.StatusCode >= 400 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return caerrors.ConnectionFailureError(
				"request failed with status %d; response body could not be read: %v", resp.StatusCode, readErr)
		}
		return caerrors.ConnectionFailureError("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var rpcResp JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return caerrors.SerializationFailureError("failed to decode response: %v", err)
	}

	if rpcResp.Error != nil {
		return caerrors.InternalServerError("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return caerrors.SerializationFailureError("failed to unmarshal result: %v", err)
		}
	}

	return nil
}

// Tenant Operations

// CreateTenant creates a new tenant.
func (a *Adapter) CreateTenant(ctx context.Context, req *admin.CreateTenantRequest) (*admin.TenantInfo, error) {
	var result admin.TenantInfo
	if err := a.call(ctx, "admin.createTenant", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTenant retrieves a tenant by ID.
func (a *Adapter) GetTenant(ctx context.Context, tenantID string) (*admin.TenantInfo, error) {
	var result admin.TenantInfo
	params := map[string]string{"tenantId": tenantID}
	if err := a.call(ctx, "admin.getTenant", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateTenant updates an existing tenant.
func (a *Adapter) UpdateTenant(ctx context.Context, tenantID string, req *admin.UpdateTenantRequest) (*admin.TenantInfo, error) {
	var result admin.TenantInfo
	params := map[string]interface{}{
		"tenantId": tenantID,
		"name":     req.Name,
		"settings": req.Settings,
	}
	if err := a.call(ctx, "admin.updateTenant", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteTenant deletes a tenant.
func (a *Adapter) DeleteTenant(ctx context.Context, tenantID string) error {
	params := map[string]string{"tenantId": tenantID}
	return a.call(ctx, "admin.deleteTenant", params, nil)
}

// ListTenants lists all tenants.
func (a *Adapter) ListTenants(ctx context.Context, req *admin.ListTenantsRequest) ([]*admin.TenantInfo, *admin.Pagination, error) {
	if req.Status != "" {
		return nil, nil, admin.TenantStatusUnsupported()
	}
	var result struct {
		Tenants    []*admin.TenantInfo `json:"tenants"`
		Pagination *admin.Pagination   `json:"pagination"`
	}
	if err := a.call(ctx, "admin.listTenants", req, &result); err != nil {
		return nil, nil, err
	}
	return result.Tenants, result.Pagination, nil
}

// EAB Operations

// CreateEAB creates a new External Account Binding.
func (a *Adapter) CreateEAB(ctx context.Context, tenantID string, req *admin.CreateEABRequest) (*admin.CreateEABResponse, error) {
	var result admin.CreateEABResponse
	params := map[string]interface{}{
		"tenantId":            tenantID,
		"purpose":             req.Purpose,
		"expires_in_days":     req.ExpiresInDays,
		"contact":             req.Contact,
		"external_account_id": req.ExternalAccountID,
		"device_info":         req.DeviceInfo,
	}
	if err := a.call(ctx, "admin.createEAB", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetEAB retrieves an EAB by ID.
func (a *Adapter) GetEAB(ctx context.Context, tenantID, kid string) (*admin.EABInfo, error) {
	var result admin.EABInfo
	params := map[string]string{"tenantId": tenantID, "kid": kid}
	if err := a.call(ctx, "admin.getEAB", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteEAB deletes an EAB.
func (a *Adapter) DeleteEAB(ctx context.Context, tenantID, kid string) error {
	params := map[string]string{"tenantId": tenantID, "kid": kid}
	return a.call(ctx, "admin.deleteEAB", params, nil)
}

// ListEABs lists all EABs for a tenant.
func (a *Adapter) ListEABs(ctx context.Context, tenantID string, req *admin.ListEABRequest) ([]*admin.EABInfo, *admin.Pagination, error) {
	var result struct {
		EABs       []*admin.EABInfo  `json:"eabs"`
		Pagination *admin.Pagination `json:"pagination"`
	}
	params := map[string]interface{}{
		"tenantId": tenantID,
		"page":     req.Page,
		"per_page": req.PerPage,
	}
	if err := a.call(ctx, "admin.listEABs", params, &result); err != nil {
		return nil, nil, err
	}
	return result.EABs, result.Pagination, nil
}

// Role Operations

// CreateTenantRole creates a new role within a tenant.
func (a *Adapter) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	var result db.Role
	params := map[string]interface{}{"tenantId": tenantID, "role": req}
	if err := a.call(ctx, "admin.createRole", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTenantRole retrieves a role by ID.
func (a *Adapter) GetTenantRole(ctx context.Context, tenantID, roleID string) (*db.Role, error) {
	var result db.Role
	params := map[string]string{"tenantId": tenantID, "roleId": roleID}
	if err := a.call(ctx, "admin.getRole", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateTenantRole updates an existing role.
func (a *Adapter) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	var result db.Role
	params := map[string]interface{}{"tenantId": tenantID, "role": req}
	if err := a.call(ctx, "admin.updateRole", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteTenantRole deletes a role.
func (a *Adapter) DeleteTenantRole(ctx context.Context, tenantID, roleID string) error {
	params := map[string]string{"tenantId": tenantID, "roleId": roleID}
	return a.call(ctx, "admin.deleteRole", params, nil)
}

// ListTenantRoles lists all roles for a tenant.
func (a *Adapter) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	var result db.ListRolesResponse
	params := map[string]interface{}{"tenantId": tenantID, "request": req}
	if err := a.call(ctx, "admin.listRoles", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// User Operations

// CreateTenantUser creates a new user within a tenant.
func (a *Adapter) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	var result db.User
	params := map[string]interface{}{"tenantId": tenantID, "user": req}
	if err := a.call(ctx, "admin.createUser", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTenantUser retrieves a user by ID.
func (a *Adapter) GetTenantUser(ctx context.Context, tenantID, userID string) (*db.User, error) {
	var result db.User
	params := map[string]string{"tenantId": tenantID, "userId": userID}
	if err := a.call(ctx, "admin.getUser", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateTenantUser updates an existing user.
func (a *Adapter) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	var result db.User
	params := map[string]interface{}{"tenantId": tenantID, "user": req}
	if err := a.call(ctx, "admin.updateUser", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteTenantUser deletes a user.
func (a *Adapter) DeleteTenantUser(ctx context.Context, tenantID, userID string) error {
	params := map[string]string{"tenantId": tenantID, "userId": userID}
	return a.call(ctx, "admin.deleteUser", params, nil)
}

// ListTenantUsers lists all users for a tenant.
func (a *Adapter) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	var result db.ListUsersResponse
	params := map[string]interface{}{"tenantId": tenantID, "request": req}
	if err := a.call(ctx, "admin.listUsers", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Certificate Operations

// ListCertificates lists certificates with optional filtering.
func (a *Adapter) ListCertificates(ctx context.Context, req *admin.ListCertificatesRequest) ([]*admin.CertificateInfo, *admin.Pagination, error) {
	var result struct {
		Certificates []*admin.CertificateInfo `json:"certificates"`
		Pagination   *admin.Pagination        `json:"pagination"`
	}
	if err := a.call(ctx, "admin.listCertificates", req, &result); err != nil {
		return nil, nil, err
	}
	return result.Certificates, result.Pagination, nil
}

// GetCertificate retrieves a certificate by serial number.
func (a *Adapter) GetCertificate(ctx context.Context, serial string) (*admin.CertificateInfo, error) {
	var result admin.CertificateInfo
	params := map[string]string{"serial": serial}
	if err := a.call(ctx, "admin.getCertificate", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeCertificate revokes a certificate.
func (a *Adapter) RevokeCertificate(ctx context.Context, serial, reason string) error {
	params := map[string]string{"serial": serial, "reason": reason}
	return a.call(ctx, "admin.revokeCertificate", params, nil)
}

// Account Operations

// ListAccounts lists ACME accounts with optional filtering.
func (a *Adapter) ListAccounts(ctx context.Context, req *admin.ListAccountsRequest) ([]*admin.AccountInfo, *admin.Pagination, error) {
	var result struct {
		Accounts   []*admin.AccountInfo `json:"accounts"`
		Pagination *admin.Pagination    `json:"pagination"`
	}
	if err := a.call(ctx, "admin.listAccounts", req, &result); err != nil {
		return nil, nil, err
	}
	return result.Accounts, result.Pagination, nil
}

// GetAccount retrieves an ACME account by ID.
func (a *Adapter) GetAccount(ctx context.Context, accountID uint64) (*admin.AccountInfo, error) {
	var result admin.AccountInfo
	params := map[string]interface{}{"account_id": accountID}
	if err := a.call(ctx, "admin.getAccount", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DisableAccount disables an ACME account.
func (a *Adapter) DisableAccount(ctx context.Context, accountID uint64) error {
	params := map[string]interface{}{"account_id": accountID}
	return a.call(ctx, "admin.disableAccount", params, nil)
}

// Status Operations

// GetStatus returns the CA status.
func (a *Adapter) GetStatus(ctx context.Context) (*admin.CAStatus, error) {
	var result admin.CAStatus
	if err := a.call(ctx, "admin.getStatus", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetStats returns CA statistics.
func (a *Adapter) GetStats(ctx context.Context) (*admin.CAStats, error) {
	var result admin.CAStats
	if err := a.call(ctx, "admin.getStats", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Verify interface compliance.

// Order Operations

// ListOrders lists orders with optional filtering.
func (a *Adapter) ListOrders(_ context.Context, _ *admin.ListOrdersRequest) ([]*admin.OrderInfo, *admin.Pagination, error) {
	return nil, nil, admin.ErrRESTOnly
}

// GetOrder retrieves an order by ID.
func (a *Adapter) GetOrder(_ context.Context, _ uint64, _ uint64) (*admin.OrderInfo, error) {
	return nil, admin.ErrRESTOnly
}

// Tenant CA Operations

// UpdateTenantStatus updates a tenant's status.
func (a *Adapter) UpdateTenantStatus(_ context.Context, _ string, _ string) error {
	return admin.TenantStatusUnsupported()
}

// CreateTenantRootCA creates a root CA for a tenant.
func (a *Adapter) CreateTenantRootCA(_ context.Context, _ string, _ *admin.CreateTenantRootCARequest) (*admin.TenantRootCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// GetTenantCAStatus retrieves the CA status for a tenant.
func (a *Adapter) GetTenantCAStatus(_ context.Context, _ string) (*admin.TenantCAStatusInfo, error) {
	return nil, admin.ErrRESTOnly
}

// CreateTenantIntermediateCA creates an intermediate CA for a tenant.
func (a *Adapter) CreateTenantIntermediateCA(_ context.Context, _ string, _ *admin.CreateTenantIntermediateCARequest) (*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// ListTenantIntermediateCAs lists all intermediate CAs for a tenant.
func (a *Adapter) ListTenantIntermediateCAs(_ context.Context, _ string) ([]*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// GetTenantIntermediateCA retrieves a specific intermediate CA.
func (a *Adapter) GetTenantIntermediateCA(_ context.Context, _ string, _ string) (*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// UpdateTenantIntermediateCAStatus updates an intermediate CA's status.
func (a *Adapter) UpdateTenantIntermediateCAStatus(_ context.Context, _ string, _ string, _ string) error {
	return admin.ErrRESTOnly
}

var _ api.AdminAdapter = (*Adapter)(nil)
