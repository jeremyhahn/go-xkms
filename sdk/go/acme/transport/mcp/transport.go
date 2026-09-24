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

// Package mcp provides an MCP (Model Context Protocol) transport implementation
// for the Trusted CA SDK.
//
// The MCP transport enables AI/LLM integration with the CA server using JSON-RPC 2.0
// over HTTP. This allows language models and AI assistants to interact with the CA
// for certificate management operations.
//
// MCP uses HTTP (not HTTPS) by default, as per the MCP specification. The transport
// sends JSON-RPC 2.0 formatted requests to the /mcp endpoint on the server.
//
// Example usage:
//
//	cfg := &transport.Config{
//	    Address: "localhost:9445",
//	}
//	t, err := mcp.NewTransport(cfg)
//	if err != nil {
//	    return err
//	}
//	defer t.Close()
//
//	resp, err := t.Request(ctx, "directory", "get", nil)
package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxIdleConns is the default maximum number of idle connections.
	DefaultMaxIdleConns = 100

	// DefaultIdleConnTimeout is the default idle connection timeout.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultMaxIdleConnsPerHost is the default maximum idle connections per host.
	DefaultMaxIdleConnsPerHost = 10

	// JSONRPCVersion is the JSON-RPC protocol version.
	JSONRPCVersion = "2.0"

	// MCPEndpoint is the MCP endpoint path.
	MCPEndpoint = "/mcp"
)

// JSON-RPC 2.0 error codes per specification.
const (
	// ErrorCodeParse indicates invalid JSON was received by the server.
	ErrorCodeParse = -32700

	// ErrorCodeInvalidRequest indicates the JSON sent is not a valid Request object.
	ErrorCodeInvalidRequest = -32600

	// ErrorCodeMethodNotFound indicates the method does not exist or is not available.
	ErrorCodeMethodNotFound = -32601

	// ErrorCodeInvalidParams indicates invalid method parameter(s).
	ErrorCodeInvalidParams = -32602

	// ErrorCodeInternal indicates an internal JSON-RPC error.
	ErrorCodeInternal = -32603
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
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// MethodHandler is a function type for handling method dispatch.
type MethodHandler func(service, method string) string

// methodMappings provides O(1) lookup for service-level method patterns.
var methodMappings = map[string]MethodHandler{
	// ACME services
	"directory":     directoryMethods,
	"nonce":         nonceMethods,
	"account":       accountMethods,
	"order":         orderMethods,
	"authorization": authorizationMethods,
	"challenge":     challengeMethods,
	"certificate":   certificateMethods,
	"admin":         adminMethods,

	// Admin services (dotted names from SDK admin client)
	"admin.tenant":      adminTenantMethods,
	"admin.eab":         adminEABMethods,
	"admin.role":        adminRoleMethods,
	"admin.user":        adminUserMethods,
	"admin.certificate": adminCertificateMethods,
	"admin.account":     adminAccountMethods,
	"admin.status":      adminStatusMethods,
	"admin.order":       adminOrderMethods,
	"admin.tenant.ca":   adminTenantCAMethods,
}

// Service-specific method handlers for O(1) routing.
func directoryMethods(service, method string) string {
	methods := map[string]string{
		"get": "acme.directory.get",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "acme.directory." + method
}

func nonceMethods(service, method string) string {
	methods := map[string]string{
		"new": "acme.nonce.new",
		"get": "acme.nonce.get",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "acme.nonce." + method
}

func accountMethods(service, method string) string {
	methods := map[string]string{
		"create":     "acme.account.create",
		"get":        "acme.account.get",
		"update":     "acme.account.update",
		"deactivate": "acme.account.deactivate",
		"keyChange":  "acme.account.keyChange",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "acme.account." + method
}

func orderMethods(service, method string) string {
	methods := map[string]string{
		"create":   "acme.order.create",
		"get":      "acme.order.get",
		"list":     "acme.order.list",
		"finalize": "acme.order.finalize",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "acme.order." + method
}

func authorizationMethods(service, method string) string {
	methods := map[string]string{
		"get":        "acme.authorization.get",
		"deactivate": "acme.authorization.deactivate",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "acme.authorization." + method
}

func challengeMethods(service, method string) string {
	methods := map[string]string{
		"get":    "acme.challenge.get",
		"submit": "acme.challenge.submit",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "acme.challenge." + method
}

func certificateMethods(service, method string) string {
	methods := map[string]string{
		"get":      "acme.certificate.get",
		"revoke":   "acme.certificate.revoke",
		"list":     "acme.certificate.list",
		"download": "acme.certificate.download",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "acme.certificate." + method
}

func adminMethods(service, method string) string {
	methods := map[string]string{
		"createTenant":      "admin.createTenant",
		"getTenant":         "admin.getTenant",
		"updateTenant":      "admin.updateTenant",
		"deleteTenant":      "admin.deleteTenant",
		"listTenants":       "admin.listTenants",
		"createEAB":         "admin.createEAB",
		"getEAB":            "admin.getEAB",
		"deleteEAB":         "admin.deleteEAB",
		"listEABs":          "admin.listEABs",
		"createPolicy":      "admin.createPolicy",
		"getPolicy":         "admin.getPolicy",
		"updatePolicy":      "admin.updatePolicy",
		"deletePolicy":      "admin.deletePolicy",
		"listPolicies":      "admin.listPolicies",
		"listCertificates":  "admin.listCertificates",
		"getCertificate":    "admin.getCertificate",
		"revokeCertificate": "admin.revokeCertificate",
		"getStatus":         "admin.getStatus",
		"getStats":          "admin.getStats",
	}
	if m, ok := methods[method]; ok {
		return m
	}
	return "admin." + method
}

// adminTenantMethods maps admin.tenant service methods to server-side JSON-RPC method names.
// The server registers methods in admin.{verb}{Resource} format (e.g., admin.createTenant).
func adminTenantMethods(service, method string) string {
	tenantMap := map[string]string{
		"create":       "admin.createTenant",
		"get":          "admin.getTenant",
		"update":       "admin.updateTenant",
		"delete":       "admin.deleteTenant",
		"list":         "admin.listTenants",
		"updateStatus": "admin.updateTenantStatus",
	}
	if mapped, ok := tenantMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminEABMethods maps admin.eab service methods to server-side JSON-RPC method names.
func adminEABMethods(service, method string) string {
	eabMap := map[string]string{
		"create": "admin.createEAB",
		"get":    "admin.getEAB",
		"delete": "admin.deleteEAB",
		"list":   "admin.listEABs",
	}
	if mapped, ok := eabMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminRoleMethods maps admin.role service methods to server-side JSON-RPC method names.
func adminRoleMethods(service, method string) string {
	roleMap := map[string]string{
		"create": "admin.createRole",
		"get":    "admin.getRole",
		"update": "admin.updateRole",
		"delete": "admin.deleteRole",
		"list":   "admin.listRoles",
	}
	if mapped, ok := roleMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminUserMethods maps admin.user service methods to server-side JSON-RPC method names.
func adminUserMethods(service, method string) string {
	userMap := map[string]string{
		"create": "admin.createUser",
		"get":    "admin.getUser",
		"update": "admin.updateUser",
		"delete": "admin.deleteUser",
		"list":   "admin.listUsers",
	}
	if mapped, ok := userMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminCertificateMethods maps admin.certificate service methods to server-side JSON-RPC method names.
func adminCertificateMethods(service, method string) string {
	certMap := map[string]string{
		"listCertificates":  "admin.listCertificates",
		"getCertificate":    "admin.getCertificate",
		"revokeCertificate": "admin.revokeCertificate",
		// Short-form aliases used by SDK admin clients
		"list":   "admin.listCertificates",
		"get":    "admin.getCertificate",
		"revoke": "admin.revokeCertificate",
	}
	if mapped, ok := certMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminAccountMethods maps admin.account service methods to server-side JSON-RPC method names.
func adminAccountMethods(service, method string) string {
	accountMap := map[string]string{
		"listAccounts":   "admin.listAccounts",
		"getAccount":     "admin.getAccount",
		"disableAccount": "admin.disableAccount",
		// Short-form aliases used by SDK admin clients
		"list":    "admin.listAccounts",
		"get":     "admin.getAccount",
		"disable": "admin.disableAccount",
	}
	if mapped, ok := accountMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminStatusMethods maps admin.status service methods to server-side JSON-RPC method names.
func adminStatusMethods(service, method string) string {
	statusMap := map[string]string{
		"status": "admin.getStatus",
		"stats":  "admin.getStats",
	}
	if mapped, ok := statusMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminOrderMethods maps admin.order service methods to server-side JSON-RPC method names.
func adminOrderMethods(service, method string) string {
	orderMap := map[string]string{
		"listOrders": "admin.listOrders",
		"getOrder":   "admin.getOrder",
		// Short-form aliases used by SDK admin clients
		"list": "admin.listOrders",
		"get":  "admin.getOrder",
	}
	if mapped, ok := orderMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// adminTenantCAMethods maps admin.tenant.ca service methods to server-side JSON-RPC method names.
func adminTenantCAMethods(service, method string) string {
	tenantCAMap := map[string]string{
		"createRootCA":               "admin.createRootCA",
		"status":                     "admin.getTenantCAStatus",
		"createIntermediateCA":       "admin.createIntermediateCA",
		"listIntermediateCAs":        "admin.listIntermediateCAs",
		"getIntermediateCA":          "admin.getIntermediateCA",
		"updateIntermediateCAStatus": "admin.updateIntermediateCAStatus",
	}
	if mapped, ok := tenantCAMap[method]; ok {
		return mapped
	}
	return "admin." + method
}

// mapMethodName maps a service/method pair to an MCP method name using O(1) lookup.
func mapMethodName(service, method string) string {
	if handler, ok := methodMappings[service]; ok {
		return handler(service, method)
	}
	// Default fallback: service.method
	return service + "." + method
}

// jsonRPCCodeToErrorCode maps JSON-RPC error codes to SDK error codes.
var jsonRPCCodeToErrorCode = map[int]errors.ErrorCode{
	ErrorCodeParse:          errors.CodeInvalidInput,
	ErrorCodeInvalidRequest: errors.CodeInvalidInput,
	ErrorCodeMethodNotFound: errors.CodeNotFound,
	ErrorCodeInvalidParams:  errors.CodeInvalidInput,
	ErrorCodeInternal:       errors.CodeInternal,
}

// Transport implements transport.Transport using MCP protocol (JSON-RPC 2.0 over HTTP).
type Transport struct {
	cfg        *transport.Config
	httpClient *http.Client
	baseURL    string
	requestID  atomic.Int64
	closed     atomic.Bool
	authToken  string
}

// Option is a functional option for configuring the transport.
type Option func(*Transport)

// WithAuthToken sets the authentication token for requests.
func WithAuthToken(token string) Option {
	return func(t *Transport) {
		t.authToken = token
	}
}

// NewTransport creates a new MCP transport with the given configuration.
func NewTransport(cfg *transport.Config, opts ...Option) (transport.Transport, error) {
	if cfg == nil {
		return nil, errors.NewInvalidInput("mcp.NewTransport", "config cannot be nil")
	}

	if cfg.Address == "" {
		return nil, errors.NewInvalidInput("mcp.NewTransport", "address cannot be empty")
	}

	// Parse the address to determine the base URL
	parsed := transport.ParseAddress(cfg.Address)
	cfg.AddressType = parsed.Type

	baseURL := buildBaseURL(parsed, cfg.Insecure)

	// Insecure mode without an explicit TLSConfig is forbidden; callers must
	// supply a root CA pool or an SPKI-pinned config. Return an error so the
	// misconfiguration is caught at construction time rather than silently
	// connecting without certificate verification.
	if cfg.Insecure && cfg.TLSConfig == nil {
		return nil, errors.NewInvalidInput("mcp.NewTransport",
			"Insecure=true requires an explicit TLSConfig with RootCAs or VerifyConnection; InsecureSkipVerify is forbidden")
	}

	// Configure HTTP transport with TLS.
	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
	httpTransport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        DefaultMaxIdleConns,
		IdleConnTimeout:     DefaultIdleConnTimeout,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: DefaultMaxIdleConnsPerHost,
	}

	// Set timeout
	timeout := DefaultTimeout
	if cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}

	t := &Transport{
		cfg:     cfg,
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: httpTransport,
			Timeout:   timeout,
		},
	}

	// Apply options
	for _, opt := range opts {
		opt(t)
	}

	return t, nil
}

// buildBaseURL constructs the base URL from the parsed address.
func buildBaseURL(parsed *transport.ParsedAddress, insecure bool) string {
	switch parsed.Type {
	case transport.AddressTypeHTTP:
		return parsed.Scheme + "://" + parsed.Address
	case transport.AddressTypeHTTPS:
		return parsed.Scheme + "://" + parsed.Address
	default:
		// For TCP addresses without scheme, default to HTTP (MCP convention)
		return "http://" + parsed.Address
	}
}

// Request sends a unary JSON-RPC request and returns the response.
func (t *Transport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	const op = "mcp.Transport.Request"

	if t.closed.Load() {
		return nil, errors.NewUnavailable(op, "transport is closed")
	}

	if service == "" {
		return nil, errors.NewInvalidInput(op, "service cannot be empty")
	}

	if method == "" {
		return nil, errors.NewInvalidInput(op, "method cannot be empty")
	}

	// Map service/method to MCP method name
	mcpMethod := mapMethodName(service, method)

	// Generate unique request ID
	reqID := t.requestID.Add(1)

	// Create JSON-RPC request
	rpcReq := JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  mcpMethod,
		Params:  req,
		ID:      reqID,
	}

	// Marshal request
	bodyBytes, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidInput, op, "failed to marshal request")
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+MCPEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to create HTTP request")
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	if t.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.authToken)
	}

	// Send request
	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, errors.Wrap(err, errors.CodeTimeout, op, "request timed out")
			}
			return nil, errors.Wrap(err, errors.CodeCanceled, op, "request canceled")
		}
		return nil, errors.Wrap(err, errors.CodeConnection, op, "failed to send request")
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle HTTP-level errors
	if resp.StatusCode >= 400 {
		return nil, t.handleHTTPError(op, resp)
	}

	// Parse JSON-RPC response
	var rpcResp JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to decode response")
	}

	// Handle JSON-RPC error
	if rpcResp.Error != nil {
		return nil, t.handleJSONRPCError(op, rpcResp.Error)
	}

	// Verify response ID matches request ID
	if rpcResp.ID != reqID {
		return nil, errors.NewInternal(op, "response ID does not match request ID")
	}

	// Return raw result for caller to unmarshal
	return rpcResp.Result, nil
}

// handleHTTPError converts HTTP errors to SDK errors.
func (t *Transport) handleHTTPError(op string, resp *http.Response) error {
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return errors.NewInvalidInput(op, "bad request: "+bodyStr)
	case http.StatusUnauthorized:
		return errors.NewUnauthorized(op, "unauthorized: "+bodyStr)
	case http.StatusForbidden:
		return errors.NewForbidden(op, "forbidden: "+bodyStr)
	case http.StatusNotFound:
		return errors.NewNotFound(op, "not found: "+bodyStr)
	case http.StatusConflict:
		return errors.NewConflict(op, "conflict: "+bodyStr)
	case http.StatusTooManyRequests:
		return errors.NewRateLimited(op, "rate limited: "+bodyStr)
	case http.StatusInternalServerError:
		return errors.NewInternal(op, "internal server error: "+bodyStr)
	case http.StatusServiceUnavailable:
		return errors.NewUnavailable(op, "service unavailable: "+bodyStr)
	case http.StatusGatewayTimeout:
		return errors.NewTimeout(op, "gateway timeout: "+bodyStr)
	default:
		return errors.NewTransport(op, "HTTP error "+resp.Status+": "+bodyStr)
	}
}

// handleJSONRPCError converts JSON-RPC errors to SDK errors.
func (t *Transport) handleJSONRPCError(op string, rpcErr *JSONRPCError) error {
	code := errors.CodeInternal

	// Map known JSON-RPC error codes
	if c, ok := jsonRPCCodeToErrorCode[rpcErr.Code]; ok {
		code = c
	}

	// Check for server-defined error codes (application errors)
	if rpcErr.Code >= -32099 && rpcErr.Code <= -32000 {
		// Server error range, treat as internal
		code = errors.CodeInternal
	}

	return errors.New(code, op, rpcErr.Message)
}

// Conn returns the underlying HTTP client.
func (t *Transport) Conn() interface{} {
	return t.httpClient
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	if t.closed.Swap(true) {
		// Already closed
		return nil
	}
	t.httpClient.CloseIdleConnections()
	return nil
}

// Healthy returns true if the transport is healthy (not closed).
func (t *Transport) Healthy() bool {
	return !t.closed.Load()
}

// Factory creates MCP transports.
type Factory struct {
	opts []Option
}

// NewFactory creates a new MCP transport factory.
func NewFactory(opts ...Option) transport.Factory {
	return &Factory{opts: opts}
}

// Create creates a new MCP transport with the given configuration.
func (f *Factory) Create(cfg *transport.Config) (transport.Transport, error) {
	return NewTransport(cfg, f.opts...)
}

// Verify interface compliance at compile time.
var (
	_ transport.Transport = (*Transport)(nil)
	_ transport.Factory   = (*Factory)(nil)
)
