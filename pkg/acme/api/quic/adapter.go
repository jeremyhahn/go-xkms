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

// Package quic provides QUIC/HTTP3 protocol adapter for go-trusted-ca services.
package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/quic-go/quic-go/http3"
)

// problemDetail represents an RFC 7807 problem detail response.
type problemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// paginatedResponse is the server's paginated list response format.
type paginatedResponse struct {
	Items   json.RawMessage `json:"items"`
	Total   int             `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
}

// Adapter implements AdminAdapter using QUIC/HTTP3.
type Adapter struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewAdapter creates a new QUIC adapter.
func NewAdapter(config *api.AdapterConfig) (*Adapter, error) {
	if config.QUICAddr == "" {
		return nil, caerrors.MalformedError("QUIC address is required")
	}

	// TLS 1.3 is required for QUIC
	tlsConfig := &tls.Config{
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}

	if config.TLSConfig != nil {
		tlsConfig.InsecureSkipVerify = config.TLSConfig.InsecureSkipVerify

		// Load client certificate if provided
		if config.TLSConfig.CertFile != "" && config.TLSConfig.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(config.TLSConfig.CertFile, config.TLSConfig.KeyFile)
			if err != nil {
				return nil, caerrors.TLSErrorCreate("failed to load client certificate: %v", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		// Load CA certificate if provided
		if config.TLSConfig.CAFile != "" {
			caCert, err := os.ReadFile(config.TLSConfig.CAFile)
			if err != nil {
				return nil, caerrors.TLSErrorCreate("failed to read CA certificate: %v", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &Adapter{
		baseURL:   "https://" + config.QUICAddr,
		authToken: config.AuthToken,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}, nil
}

// Protocol returns the protocol this adapter uses.
func (a *Adapter) Protocol() api.Protocol {
	return api.ProtocolQUIC
}

// Close closes the QUIC connection.
func (a *Adapter) Close() error {
	a.httpClient.CloseIdleConnections()
	return nil
}

// doRequest performs an HTTP3 request with authentication.
func (a *Adapter) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, caerrors.SerializationFailureError("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, bodyReader)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
	}

	return a.httpClient.Do(req)
}

// parseErrorBody parses an RFC 7807 problem detail error response body and
// returns a descriptive error. If the body cannot be parsed as problem detail,
// a generic error with the HTTP status is returned.
func parseErrorBody(statusCode int, body []byte) error {
	var problem problemDetail
	if len(body) > 0 {
		if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != "" {
			return caerrors.ConnectionFailureError("%s: %s (status %d)", problem.Title, problem.Detail, statusCode)
		}
	}
	return caerrors.ConnectionFailureError("request failed with status %d: %s", statusCode, string(body))
}

// decodeResponse reads the response body, checks for errors using HTTP status
// codes and RFC 7807 problem detail, and decodes the JSON body directly into
// the target. The server returns data directly without an envelope wrapper.
func decodeResponse(resp *http.Response, target interface{}) error {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return caerrors.ConnectionFailureError("failed to read response body: %v", err)
	}

	if resp.StatusCode >= 400 {
		return parseErrorBody(resp.StatusCode, bodyBytes)
	}

	if target == nil {
		return nil
	}

	if len(bodyBytes) == 0 {
		return nil
	}

	return json.Unmarshal(bodyBytes, target)
}

// decodeListResponse reads the response body, checks for errors using HTTP
// status codes and RFC 7807 problem detail, and decodes the paginated list
// response. The server returns: {"items":[...],"total":N,"page":N,"per_page":N}
func decodeListResponse(resp *http.Response, target interface{}) (*admin.Pagination, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to read response body: %v", err)
	}

	if resp.StatusCode >= 400 {
		return nil, parseErrorBody(resp.StatusCode, bodyBytes)
	}

	if len(bodyBytes) == 0 {
		return nil, nil
	}

	var paged paginatedResponse
	if err := json.Unmarshal(bodyBytes, &paged); err != nil {
		return nil, caerrors.SerializationFailureError("failed to decode paginated response: %v", err)
	}

	if target != nil && len(paged.Items) > 0 {
		if err := json.Unmarshal(paged.Items, target); err != nil {
			return nil, caerrors.SerializationFailureError("failed to decode items: %v", err)
		}
	}

	pagination := &admin.Pagination{
		Page:    paged.Page,
		PerPage: paged.PerPage,
		Total:   paged.Total,
	}

	return pagination, nil
}

// Tenant Operations

// CreateTenant creates a new tenant.
func (a *Adapter) CreateTenant(ctx context.Context, req *admin.CreateTenantRequest) (*admin.TenantInfo, error) {
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/v1/tenants", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var tenant admin.TenantInfo
	if err := decodeResponse(resp, &tenant); err != nil {
		return nil, err
	}
	return &tenant, nil
}

// GetTenant retrieves a tenant by ID.
func (a *Adapter) GetTenant(ctx context.Context, tenantID string) (*admin.TenantInfo, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/v1/tenants/"+tenantID, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var tenant admin.TenantInfo
	if err := decodeResponse(resp, &tenant); err != nil {
		return nil, err
	}
	return &tenant, nil
}

// UpdateTenant updates an existing tenant.
func (a *Adapter) UpdateTenant(ctx context.Context, tenantID string, req *admin.UpdateTenantRequest) (*admin.TenantInfo, error) {
	resp, err := a.doRequest(ctx, http.MethodPut, "/api/v1/tenants/"+tenantID, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var tenant admin.TenantInfo
	if err := decodeResponse(resp, &tenant); err != nil {
		return nil, err
	}
	return &tenant, nil
}

// DeleteTenant deletes a tenant.
func (a *Adapter) DeleteTenant(ctx context.Context, tenantID string) error {
	resp, err := a.doRequest(ctx, http.MethodDelete, "/api/v1/tenants/"+tenantID, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return decodeResponse(resp, nil)
}

// ListTenants lists all tenants.
func (a *Adapter) ListTenants(ctx context.Context, req *admin.ListTenantsRequest) ([]*admin.TenantInfo, *admin.Pagination, error) {
	path := fmt.Sprintf("/api/v1/tenants?page=%d&per_page=%d", req.Page, req.PerPage)
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var tenants []*admin.TenantInfo
	pagination, err := decodeListResponse(resp, &tenants)
	if err != nil {
		return nil, nil, err
	}
	return tenants, pagination, nil
}

// EAB Operations

// CreateEAB creates a new External Account Binding.
func (a *Adapter) CreateEAB(ctx context.Context, tenantID string, req *admin.CreateEABRequest) (*admin.CreateEABResponse, error) {
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/v1/tenants/"+tenantID+"/eab", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var eab admin.CreateEABResponse
	if err := decodeResponse(resp, &eab); err != nil {
		return nil, err
	}
	return &eab, nil
}

// GetEAB retrieves an EAB by ID.
func (a *Adapter) GetEAB(ctx context.Context, tenantID, kid string) (*admin.EABInfo, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/v1/tenants/"+tenantID+"/eab/"+kid, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var eab admin.EABInfo
	if err := decodeResponse(resp, &eab); err != nil {
		return nil, err
	}
	return &eab, nil
}

// DeleteEAB deletes an EAB.
func (a *Adapter) DeleteEAB(ctx context.Context, tenantID, kid string) error {
	resp, err := a.doRequest(ctx, http.MethodDelete, "/api/v1/tenants/"+tenantID+"/eab/"+kid, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return decodeResponse(resp, nil)
}

// ListEABs lists all EABs for a tenant.
func (a *Adapter) ListEABs(ctx context.Context, tenantID string, req *admin.ListEABRequest) ([]*admin.EABInfo, *admin.Pagination, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/eab?page=%d&per_page=%d", tenantID, req.Page, req.PerPage)
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var eabs []*admin.EABInfo
	pagination, err := decodeListResponse(resp, &eabs)
	if err != nil {
		return nil, nil, err
	}
	return eabs, pagination, nil
}

// Role Operations

// CreateTenantRole creates a new role within a tenant.
func (a *Adapter) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/v1/tenants/"+tenantID+"/roles", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var role db.Role
	if err := decodeResponse(resp, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// GetTenantRole retrieves a role by ID.
func (a *Adapter) GetTenantRole(ctx context.Context, tenantID, roleID string) (*db.Role, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/v1/tenants/"+tenantID+"/roles/"+roleID, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var role db.Role
	if err := decodeResponse(resp, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateTenantRole updates an existing role.
func (a *Adapter) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	resp, err := a.doRequest(ctx, http.MethodPut, "/api/v1/tenants/"+tenantID+"/roles/"+req.ID, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var role db.Role
	if err := decodeResponse(resp, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// DeleteTenantRole deletes a role.
func (a *Adapter) DeleteTenantRole(ctx context.Context, tenantID, roleID string) error {
	resp, err := a.doRequest(ctx, http.MethodDelete, "/api/v1/tenants/"+tenantID+"/roles/"+roleID, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return decodeResponse(resp, nil)
}

// ListTenantRoles lists all roles for a tenant.
func (a *Adapter) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/roles?page=%d&per_page=%d", tenantID, req.Page, req.PageSize)
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var listResp db.ListRolesResponse
	if err := decodeResponse(resp, &listResp); err != nil {
		return nil, err
	}
	return &listResp, nil
}

// User Operations

// CreateTenantUser creates a new user within a tenant.
func (a *Adapter) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	resp, err := a.doRequest(ctx, http.MethodPost, "/api/v1/tenants/"+tenantID+"/users", req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var user db.User
	if err := decodeResponse(resp, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// GetTenantUser retrieves a user by ID.
func (a *Adapter) GetTenantUser(ctx context.Context, tenantID, userID string) (*db.User, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/v1/tenants/"+tenantID+"/users/"+userID, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var user db.User
	if err := decodeResponse(resp, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateTenantUser updates an existing user.
func (a *Adapter) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	resp, err := a.doRequest(ctx, http.MethodPut, "/api/v1/tenants/"+tenantID+"/users/"+req.ID, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var user db.User
	if err := decodeResponse(resp, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// DeleteTenantUser deletes a user.
func (a *Adapter) DeleteTenantUser(ctx context.Context, tenantID, userID string) error {
	resp, err := a.doRequest(ctx, http.MethodDelete, "/api/v1/tenants/"+tenantID+"/users/"+userID, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return decodeResponse(resp, nil)
}

// ListTenantUsers lists all users for a tenant.
func (a *Adapter) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/users?page=%d&per_page=%d", tenantID, req.Page, req.PageSize)
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var listResp db.ListUsersResponse
	if err := decodeResponse(resp, &listResp); err != nil {
		return nil, err
	}
	return &listResp, nil
}

// Certificate Operations

// ListCertificates lists certificates with optional filtering.
func (a *Adapter) ListCertificates(ctx context.Context, req *admin.ListCertificatesRequest) ([]*admin.CertificateInfo, *admin.Pagination, error) {
	path := fmt.Sprintf("/admin/certificates?page=%d&per_page=%d", req.Page, req.PerPage)
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var certs []*admin.CertificateInfo
	pagination, err := decodeListResponse(resp, &certs)
	if err != nil {
		return nil, nil, err
	}
	return certs, pagination, nil
}

// GetCertificate retrieves a certificate by serial number.
func (a *Adapter) GetCertificate(ctx context.Context, serial string) (*admin.CertificateInfo, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/admin/certificates/"+serial, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var cert admin.CertificateInfo
	if err := decodeResponse(resp, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

// RevokeCertificate revokes a certificate.
func (a *Adapter) RevokeCertificate(ctx context.Context, serial, reason string) error {
	body := map[string]string{"reason": reason}
	resp, err := a.doRequest(ctx, http.MethodPost, "/admin/certificates/"+serial+"/revoke", body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return decodeResponse(resp, nil)
}

// Account Operations

// ListAccounts lists ACME accounts with optional filtering.
func (a *Adapter) ListAccounts(ctx context.Context, req *admin.ListAccountsRequest) ([]*admin.AccountInfo, *admin.Pagination, error) {
	path := fmt.Sprintf("/admin/accounts?page=%d&per_page=%d", req.Page, req.PerPage)
	if req.Status != "" {
		path += "&status=" + req.Status
	}
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var accounts []*admin.AccountInfo
	pagination, err := decodeListResponse(resp, &accounts)
	if err != nil {
		return nil, nil, err
	}
	return accounts, pagination, nil
}

// GetAccount retrieves an ACME account by ID.
func (a *Adapter) GetAccount(ctx context.Context, accountID uint64) (*admin.AccountInfo, error) {
	path := fmt.Sprintf("/admin/accounts/%d", accountID)
	resp, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var account admin.AccountInfo
	if err := decodeResponse(resp, &account); err != nil {
		return nil, err
	}
	return &account, nil
}

// DisableAccount disables an ACME account.
func (a *Adapter) DisableAccount(ctx context.Context, accountID uint64) error {
	path := fmt.Sprintf("/admin/accounts/%d/disable", accountID)
	resp, err := a.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return decodeResponse(resp, nil)
}

// Status Operations

// GetStatus returns the CA status.
func (a *Adapter) GetStatus(ctx context.Context) (*admin.CAStatus, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/admin/status", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var status admin.CAStatus
	if err := decodeResponse(resp, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetStats returns CA statistics.
func (a *Adapter) GetStats(ctx context.Context) (*admin.CAStats, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/admin/stats", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var stats admin.CAStats
	if err := decodeResponse(resp, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

// Verify interface compliance.

// Order Operations

// ListOrders lists orders with optional filtering.
func (a *Adapter) ListOrders(_ context.Context, _ *admin.ListOrdersRequest) ([]*admin.OrderInfo, *admin.Pagination, error) {
	return nil, nil, admin.ErrNotImplemented
}

// GetOrder retrieves an order by ID.
func (a *Adapter) GetOrder(_ context.Context, _ uint64, _ uint64) (*admin.OrderInfo, error) {
	return nil, admin.ErrNotImplemented
}

// Tenant CA Operations

// UpdateTenantStatus updates a tenant's status.
func (a *Adapter) UpdateTenantStatus(_ context.Context, _ string, _ string) error {
	return admin.ErrNotImplemented
}

// CreateTenantRootCA creates a root CA for a tenant.
func (a *Adapter) CreateTenantRootCA(_ context.Context, _ string, _ *admin.CreateTenantRootCARequest) (*admin.TenantRootCAInfo, error) {
	return nil, admin.ErrNotImplemented
}

// GetTenantCAStatus retrieves the CA status for a tenant.
func (a *Adapter) GetTenantCAStatus(_ context.Context, _ string) (*admin.TenantCAStatusInfo, error) {
	return nil, admin.ErrNotImplemented
}

// CreateTenantIntermediateCA creates an intermediate CA for a tenant.
func (a *Adapter) CreateTenantIntermediateCA(_ context.Context, _ string, _ *admin.CreateTenantIntermediateCARequest) (*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrNotImplemented
}

// ListTenantIntermediateCAs lists all intermediate CAs for a tenant.
func (a *Adapter) ListTenantIntermediateCAs(_ context.Context, _ string) ([]*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrNotImplemented
}

// GetTenantIntermediateCA retrieves a specific intermediate CA.
func (a *Adapter) GetTenantIntermediateCA(_ context.Context, _ string, _ string) (*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrNotImplemented
}

// UpdateTenantIntermediateCAStatus updates an intermediate CA's status.
func (a *Adapter) UpdateTenantIntermediateCAStatus(_ context.Context, _ string, _ string, _ string) error {
	return admin.ErrNotImplemented
}

var _ api.AdminAdapter = (*Adapter)(nil)
