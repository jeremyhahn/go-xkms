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

// Package unix provides a Unix domain socket transport implementation for the Trusted CA SDK.
//
// The Unix socket transport offers local IPC communication with the CA server
// via Unix domain sockets using HTTP over UDS. It supports both standard Unix sockets
// and Linux abstract sockets for CLI and local service integration.
//
// Since ACME is fundamentally REST-based, this transport uses HTTP over Unix sockets
// to communicate with the CA server. Service/method pairs are mapped to ACME REST
// and Admin API endpoints using O(1) map-based dispatch.
//
// Example usage:
//
//	cfg := &transport.Config{
//	    Address: "/run/trusted-ca-grpc.sock",
//	    Timeout: 30 * time.Second,
//	}
//	t, err := unix.NewTransport(cfg)
//	if err != nil {
//	    return err
//	}
//	defer t.Close()
//
//	// Make a request
//	resp, err := t.Request(ctx, "directory", "get", nil)
package unix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultKeepaliveTime is the default keepalive ping interval.
	DefaultKeepaliveTime = 30 * time.Second

	// DefaultKeepaliveTimeout is the default keepalive ping timeout.
	DefaultKeepaliveTimeout = 10 * time.Second

	// DefaultMaxIdleConns is the default maximum number of idle connections.
	DefaultMaxIdleConns = 10

	// DefaultIdleConnTimeout is the default idle connection timeout.
	DefaultIdleConnTimeout = 90 * time.Second

	// httpHostPlaceholder is used as the Host header for Unix socket connections.
	// The actual connection is made through the socket, but HTTP requires a Host header.
	httpHostPlaceholder = "localhost"
)

// EndpointInfo contains metadata about an ACME or Admin endpoint.
type EndpointInfo struct {
	// Path is the URL path for the endpoint.
	Path string

	// Method is the HTTP method to use.
	Method string

	// RequiresBody indicates if the request should include a body.
	RequiresBody bool
}

// endpointKey creates a lookup key from service and method.
func endpointKey(service, method string) string {
	return service + "/" + method
}

// endpointRegistry maps service/method pairs to REST endpoints.
// This provides O(1) constant-time lookup for routing.
var endpointRegistry = map[string]EndpointInfo{
	// Directory operations
	endpointKey("directory", "get"): {Path: "/directory", Method: http.MethodGet, RequiresBody: false},

	// Nonce operations
	endpointKey("nonce", "new"):  {Path: "/acme/new-nonce", Method: http.MethodHead, RequiresBody: false},
	endpointKey("nonce", "head"): {Path: "/acme/new-nonce", Method: http.MethodHead, RequiresBody: false},
	endpointKey("nonce", "get"):  {Path: "/acme/new-nonce", Method: http.MethodGet, RequiresBody: false},

	// Account operations
	endpointKey("account", "create"): {Path: "/acme/new-acct", Method: http.MethodPost, RequiresBody: true},
	endpointKey("account", "new"):    {Path: "/acme/new-acct", Method: http.MethodPost, RequiresBody: true},
	endpointKey("account", "get"):    {Path: "/acme/acct/{id}", Method: http.MethodPost, RequiresBody: true},
	endpointKey("account", "update"): {Path: "/acme/acct/{id}", Method: http.MethodPost, RequiresBody: true},
	endpointKey("account", "lookup"): {Path: "/acme/new-acct", Method: http.MethodPost, RequiresBody: true},

	// Order operations
	endpointKey("order", "create"): {Path: "/acme/new-order", Method: http.MethodPost, RequiresBody: true},
	endpointKey("order", "new"):    {Path: "/acme/new-order", Method: http.MethodPost, RequiresBody: true},
	endpointKey("order", "get"):    {Path: "/acme/order/{id}", Method: http.MethodPost, RequiresBody: true},
	endpointKey("order", "list"):   {Path: "/acme/orders", Method: http.MethodPost, RequiresBody: true},

	// Authorization operations
	endpointKey("authorization", "get"): {Path: "/acme/authz/{id}", Method: http.MethodPost, RequiresBody: true},

	// Challenge operations
	endpointKey("challenge", "get"):      {Path: "/acme/chall/{id}", Method: http.MethodPost, RequiresBody: true},
	endpointKey("challenge", "respond"):  {Path: "/acme/chall/{id}", Method: http.MethodPost, RequiresBody: true},
	endpointKey("challenge", "complete"): {Path: "/acme/chall/{id}", Method: http.MethodPost, RequiresBody: true},

	// Finalize operations
	endpointKey("finalize", "order"):  {Path: "/acme/order/{id}/finalize", Method: http.MethodPost, RequiresBody: true},
	endpointKey("finalize", "submit"): {Path: "/acme/order/{id}/finalize", Method: http.MethodPost, RequiresBody: true},

	// Certificate operations
	endpointKey("certificate", "get"):      {Path: "/acme/cert/{id}", Method: http.MethodPost, RequiresBody: true},
	endpointKey("certificate", "revoke"):   {Path: "/acme/revoke-cert", Method: http.MethodPost, RequiresBody: true},
	endpointKey("certificate", "download"): {Path: "/acme/cert/{id}", Method: http.MethodPost, RequiresBody: true},

	// Key change operations
	endpointKey("keychange", "change"):   {Path: "/acme/key-change", Method: http.MethodPost, RequiresBody: true},
	endpointKey("keychange", "rollover"): {Path: "/acme/key-change", Method: http.MethodPost, RequiresBody: true},

	// Health check operations
	endpointKey("health", "check"):     {Path: "/health", Method: http.MethodGet, RequiresBody: false},
	endpointKey("health", "ready"):     {Path: "/ready", Method: http.MethodGet, RequiresBody: false},
	endpointKey("health", "live"):      {Path: "/live", Method: http.MethodGet, RequiresBody: false},
	endpointKey("health", "liveness"):  {Path: "/live", Method: http.MethodGet, RequiresBody: false},
	endpointKey("health", "readiness"): {Path: "/ready", Method: http.MethodGet, RequiresBody: false},
}

// Transport implements transport.Transport using HTTP over Unix domain sockets.
type Transport struct {
	cfg           *transport.Config
	client        *http.Client
	httpTransport *http.Transport
	socketPath    string
	isAbstract    bool
	closed        atomic.Bool
	healthy       atomic.Bool
}

// NewTransport creates a new Unix socket transport with the given configuration.
func NewTransport(cfg *transport.Config) (transport.Transport, error) {
	if cfg == nil {
		return nil, caerrors.NewInvalidInput("unix.NewTransport", "config cannot be nil")
	}

	if cfg.Address == "" {
		return nil, caerrors.NewInvalidInput("unix.NewTransport", "address cannot be empty")
	}

	// Parse the address to determine socket type
	parsed := transport.ParseAddress(cfg.Address)
	if !parsed.IsUnix() {
		return nil, caerrors.NewInvalidInput(
			"unix.NewTransport",
			"address must be a Unix socket path",
		).WithContext("address", cfg.Address).WithContext("type", parsed.Type.String())
	}

	socketPath := parsed.Address
	isAbstract := parsed.Type == transport.AddressTypeUnixAbstract

	// For abstract sockets, prepend the null byte
	if isAbstract {
		socketPath = "\x00" + socketPath
	}

	// Configure timeouts with defaults
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	keepaliveTime := cfg.KeepaliveTime
	if keepaliveTime == 0 {
		keepaliveTime = DefaultKeepaliveTime
	}

	// Create HTTP transport with Unix socket dialer
	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			d.Timeout = timeout
			d.KeepAlive = keepaliveTime
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:       DefaultMaxIdleConns,
		IdleConnTimeout:    DefaultIdleConnTimeout,
		DisableCompression: false,
		DisableKeepAlives:  false,
		ForceAttemptHTTP2:  false, // HTTP/2 not typically used over Unix sockets
	}

	// Apply TLS configuration if provided (for TLS over Unix socket)
	if cfg.TLSConfig != nil && !cfg.Insecure {
		httpTransport.TLSClientConfig = cfg.TLSConfig
	}

	t := &Transport{
		cfg:           cfg,
		httpTransport: httpTransport,
		client: &http.Client{
			Transport: httpTransport,
			Timeout:   timeout,
		},
		socketPath: socketPath,
		isAbstract: isAbstract,
	}

	// Perform initial health check
	if err := t.checkHealth(); err != nil {
		// Log the error but don't fail - socket may not be ready yet
		t.healthy.Store(false)
	} else {
		t.healthy.Store(true)
	}

	return t, nil
}

// Request sends a unary HTTP request over the Unix socket and returns the response.
func (t *Transport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	const op = "unix.Transport.Request"

	if t.closed.Load() {
		return nil, caerrors.NewUnavailable(op, "transport is closed")
	}

	if service == "" {
		return nil, caerrors.NewInvalidInput(op, "service cannot be empty")
	}

	if method == "" {
		return nil, caerrors.NewInvalidInput(op, "method cannot be empty")
	}

	// Look up the endpoint using O(1) map dispatch
	endpoint, ok := endpointRegistry[endpointKey(service, method)]
	if !ok {
		return nil, caerrors.NewNotFound(op, "unknown service/method").
			WithContext("service", service).
			WithContext("method", method)
	}

	// Build the request URL
	// For Unix sockets, we use http:// with localhost as the host
	// The actual connection goes through the socket via our custom dialer
	url := "http://" + httpHostPlaceholder + endpoint.Path

	// Handle path parameters by extracting fields from the request
	url = substitutePathParams(url, req)

	// Build the HTTP request
	var body io.Reader
	if endpoint.RequiresBody && req != nil {
		jsonBytes, err := json.Marshal(req)
		if err != nil {
			return nil, caerrors.Wrap(err, caerrors.CodeInvalidInput, op, "failed to marshal request body")
		}
		body = bytes.NewReader(jsonBytes)
	}

	httpReq, err := http.NewRequestWithContext(ctx, endpoint.Method, url, body)
	if err != nil {
		return nil, caerrors.Wrap(err, caerrors.CodeInternal, op, "failed to create HTTP request")
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/jose+json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "go-trusted-ca-sdk/1.0")

	// Execute the request
	resp, err := t.client.Do(httpReq)
	if err != nil {
		t.healthy.Store(false)
		if ctx.Err() == context.Canceled {
			return nil, caerrors.NewCanceled(op, "request was canceled")
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, caerrors.NewTimeout(op, "request timed out")
		}
		return nil, caerrors.Wrap(err, caerrors.CodeConnection, op, "failed to execute request")
	}
	defer resp.Body.Close()

	// Mark as healthy on successful connection
	t.healthy.Store(true)

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, caerrors.Wrap(err, caerrors.CodeTransport, op, "failed to read response body")
	}

	// Build the response
	response := &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
	}

	// Extract nonce from response headers if present
	if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
		response.Nonce = nonce
	}

	// Extract location from response headers if present
	if location := resp.Header.Get("Location"); location != "" {
		response.Location = location
	}

	// Check for error responses
	if resp.StatusCode >= 400 {
		return response, t.parseErrorResponse(op, resp.StatusCode, respBody)
	}

	return response, nil
}

// substitutePathParams replaces path parameter placeholders with values extracted
// from the request. It supports both map[string]interface{} and struct requests
// by marshaling to JSON if needed.
func substitutePathParams(url string, req interface{}) string {
	if req == nil || !strings.Contains(url, "{") {
		return url
	}

	// Try map[string]interface{} first (most common in existing ACME code)
	if reqMap, ok := req.(map[string]interface{}); ok {
		for key, val := range reqMap {
			placeholder := "{" + key + "}"
			if strings.Contains(url, placeholder) {
				url = strings.ReplaceAll(url, placeholder, toString(val))
			}
		}
		return url
	}

	// For struct types (admin requests), marshal to map and substitute
	data, err := json.Marshal(req)
	if err != nil {
		return url
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return url
	}
	for key, val := range m {
		placeholder := "{" + key + "}"
		if strings.Contains(url, placeholder) {
			url = strings.ReplaceAll(url, placeholder, toString(val))
		}
	}
	return url
}

// RequestStream initiates a streaming request.
// Note: Streaming is not natively supported over HTTP/1.1 Unix sockets.
// For streaming operations, consider using the gRPC transport.
func (t *Transport) RequestStream(ctx context.Context, service, method string, req interface{}) (transport.Stream, error) {
	const op = "unix.Transport.RequestStream"

	if t.closed.Load() {
		return nil, caerrors.NewUnavailable(op, "transport is closed")
	}

	// Unix socket transport over HTTP does not support streaming
	// Return a specific error indicating this limitation
	return nil, caerrors.NewUnimplemented(op, "streaming not supported for HTTP over Unix socket transport; use gRPC transport for streaming operations")
}

// Conn returns the underlying HTTP client.
func (t *Transport) Conn() interface{} {
	return t.client
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	if t.closed.Swap(true) {
		// Already closed
		return nil
	}

	t.healthy.Store(false)

	// Close idle connections in the HTTP transport
	if t.httpTransport != nil {
		t.httpTransport.CloseIdleConnections()
	}

	return nil
}

// Healthy returns true if the transport is healthy.
func (t *Transport) Healthy() bool {
	return !t.closed.Load() && t.healthy.Load()
}

// SocketPath returns the Unix socket path being used.
func (t *Transport) SocketPath() string {
	return t.socketPath
}

// IsAbstract returns true if the transport uses a Linux abstract socket.
func (t *Transport) IsAbstract() bool {
	return t.isAbstract
}

// checkHealth performs a health check by attempting to connect to the socket.
func (t *Transport) checkHealth() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to get the directory as a simple health check
	_, err := t.Request(ctx, "health", "check", nil)
	if err != nil {
		// If health endpoint doesn't exist, try the directory endpoint
		_, err = t.Request(ctx, "directory", "get", nil)
	}
	return err
}

// parseErrorResponse parses an error response body and returns an appropriate error.
func (t *Transport) parseErrorResponse(op string, statusCode int, body []byte) *caerrors.CAError {
	// Try to parse as ACME error response
	var acmeErr struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
		Status int    `json:"status"`
	}

	if err := json.Unmarshal(body, &acmeErr); err == nil && acmeErr.Type != "" {
		// Parse ACME error type to our error code
		code := caerrors.ParseACMEErrorType(acmeErr.Type)
		if code == caerrors.CodeUnknown {
			code = httpStatusToErrorCode(statusCode)
		}
		return caerrors.New(code, op, acmeErr.Detail).
			WithContext("type", acmeErr.Type).
			WithContext("status", statusCode)
	}

	// Fall back to HTTP status code mapping
	code := httpStatusToErrorCode(statusCode)
	return caerrors.New(code, op, string(body)).WithContext("status", statusCode)
}

// httpStatusToErrorCode maps HTTP status codes to error codes.
func httpStatusToErrorCode(statusCode int) caerrors.ErrorCode {
	statusCodeMap := map[int]caerrors.ErrorCode{
		http.StatusBadRequest:          caerrors.CodeInvalidInput,
		http.StatusUnauthorized:        caerrors.CodeUnauthorized,
		http.StatusForbidden:           caerrors.CodeForbidden,
		http.StatusNotFound:            caerrors.CodeNotFound,
		http.StatusMethodNotAllowed:    caerrors.CodeInvalidInput,
		http.StatusConflict:            caerrors.CodeConflict,
		http.StatusGone:                caerrors.CodeNotFound,
		http.StatusPreconditionFailed:  caerrors.CodePreconditionFailed,
		http.StatusTooManyRequests:     caerrors.CodeRateLimited,
		http.StatusInternalServerError: caerrors.CodeInternal,
		http.StatusNotImplemented:      caerrors.CodeUnimplemented,
		http.StatusBadGateway:          caerrors.CodeUnavailable,
		http.StatusServiceUnavailable:  caerrors.CodeUnavailable,
		http.StatusGatewayTimeout:      caerrors.CodeTimeout,
	}

	if code, ok := statusCodeMap[statusCode]; ok {
		return code
	}

	if statusCode >= 400 && statusCode < 500 {
		return caerrors.CodeInvalidInput
	}
	if statusCode >= 500 {
		return caerrors.CodeInternal
	}
	return caerrors.CodeUnknown
}

// toString converts an interface value to a string.
func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case float64:
		return fmt.Sprintf("%d", int64(val))
	default:
		// Use JSON marshaling for complex types
		b, _ := json.Marshal(val)
		return strings.Trim(string(b), "\"")
	}
}

// Response represents an HTTP response from the Unix socket transport.
type Response struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Headers contains the response headers.
	Headers http.Header

	// Body contains the raw response body.
	Body []byte

	// Nonce is the replay nonce from the response headers.
	Nonce string

	// Location is the resource location from the response headers.
	Location string
}

// JSON unmarshals the response body into the provided value.
func (r *Response) JSON(v interface{}) error {
	return json.Unmarshal(r.Body, v)
}

// String returns the response body as a string.
func (r *Response) String() string {
	return string(r.Body)
}

// IsSuccess returns true if the response indicates success (2xx status code).
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// Factory creates Unix socket transports.
type Factory struct{}

// NewFactory creates a new Unix socket transport factory.
func NewFactory() transport.Factory {
	return &Factory{}
}

// Create creates a new Unix socket transport with the given configuration.
func (f *Factory) Create(cfg *transport.Config) (transport.Transport, error) {
	return NewTransport(cfg)
}

// Compile-time interface compliance check.
var (
	_ transport.Transport = (*Transport)(nil)
	_ transport.Factory   = (*Factory)(nil)
)
