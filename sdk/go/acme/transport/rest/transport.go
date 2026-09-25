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

// Package rest provides a REST/HTTP transport implementation for the Trusted CA SDK.
//
// The REST transport offers HTTP/HTTPS communication with the ACME CA server,
// implementing RFC 8555 ACME protocol over HTTP. It also supports Admin API
// endpoints for tenant, certificate, account, and CA management operations.
//
// Example usage:
//
//	cfg := &transport.Config{
//	    Address:   "https://localhost:8443",
//	    TLSConfig: tlsConfig,
//	}
//	t, err := rest.NewTransport(cfg)
//	if err != nil {
//	    return err
//	}
//	defer t.Close()
package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	// ContentTypeJSON is the ACME JSON content type.
	ContentTypeJSON = "application/json"
	// ContentTypeProblemJSON is the ACME problem JSON content type.
	ContentTypeProblemJSON = "application/problem+json"
	// ContentTypePEM is the PEM certificate content type.
	ContentTypePEM = "application/pem-certificate-chain"
	// ContentTypeJOSE is the ACME JOSE+JSON content type for signed requests.
	ContentTypeJOSE = "application/jose+json"

	// HeaderReplayNonce is the ACME Replay-Nonce header.
	HeaderReplayNonce = "Replay-Nonce"
	// HeaderLocation is the Location header for resource URLs.
	HeaderLocation = "Location"
	// HeaderLink is the Link header for related resources.
	HeaderLink = "Link"
	// HeaderContentType is the Content-Type header.
	HeaderContentType = "Content-Type"
	// HeaderRetryAfter is the Retry-After header for rate limiting.
	HeaderRetryAfter = "Retry-After"

	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxIdleConns is the default maximum idle connections.
	DefaultMaxIdleConns = 100

	// DefaultIdleConnTimeout is the default idle connection timeout.
	DefaultIdleConnTimeout = 90 * time.Second
)

// HTTPMethod represents an HTTP method.
type HTTPMethod string

const (
	MethodGET  HTTPMethod = http.MethodGet
	MethodPOST HTTPMethod = http.MethodPost
	MethodHEAD HTTPMethod = http.MethodHead
)

// RouteInfo contains endpoint routing information.
type RouteInfo struct {
	Method      HTTPMethod
	PathBuilder PathBuilder
	// RequiresJWS indicates if the request requires JWS signing.
	RequiresJWS bool
	// ExtractID indicates if the endpoint requires an ID from the request.
	ExtractID bool
}

// PathBuilder is a function that builds the endpoint path from request data.
type PathBuilder func(baseURL string, req interface{}) string

// Transport implements transport.Transport using HTTP/REST.
type Transport struct {
	cfg       *transport.Config
	client    *http.Client
	baseURL   string
	closed    atomic.Bool
	healthy   atomic.Bool
	lastNonce atomic.Value
	routes    map[string]RouteInfo
}

// NewTransport creates a new REST transport with the given configuration.
func NewTransport(cfg *transport.Config) (transport.Transport, error) {
	if cfg == nil {
		return nil, errors.NewInvalidInput("rest.NewTransport", "config cannot be nil")
	}

	parsed := transport.ParseAddress(cfg.Address)
	if !parsed.IsHTTP() && !parsed.IsTCP() {
		return nil, errors.NewInvalidInput("rest.NewTransport",
			"address must be an HTTP/HTTPS URL or TCP address")
	}

	routes := buildRouteMap()
	for k, v := range buildAdminRouteMap() {
		routes[k] = v
	}

	t := &Transport{
		cfg:    cfg,
		routes: routes,
	}

	if err := t.initHTTPClient(); err != nil {
		return nil, err
	}

	t.baseURL = buildBaseURL(parsed, cfg)
	t.healthy.Store(true)

	return t, nil
}

// initHTTPClient initializes the HTTP client with the configured TLS and timeout settings.
func (t *Transport) initHTTPClient() error {
	timeout := t.cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Insecure mode without an explicit TLSConfig is forbidden; callers must
	// supply a root CA pool or an SPKI-pinned config.
	if t.cfg.Insecure && t.cfg.TLSConfig == nil {
		return errors.NewInvalidInput("rest.initHTTPClient",
			"Insecure=true requires an explicit TLSConfig with RootCAs or VerifyConnection; InsecureSkipVerify is forbidden")
	}

	tlsConfig := t.cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: t.cfg.KeepaliveTime,
		}).DialContext,
		MaxIdleConns:        DefaultMaxIdleConns,
		IdleConnTimeout:     DefaultIdleConnTimeout,
		TLSHandshakeTimeout: timeout,
		ForceAttemptHTTP2:   true,
	}

	t.client = &http.Client{
		Transport: httpTransport,
		Timeout:   timeout,
	}

	return nil
}

// buildBaseURL constructs the base URL from the parsed address.
func buildBaseURL(parsed *transport.ParsedAddress, cfg *transport.Config) string {
	if parsed.IsHTTP() {
		return parsed.FullURL()
	}

	// When the address already specifies HTTPS, keep it even in insecure mode
	// (insecure means skip TLS verification, not downgrade to HTTP).
	// Only use plain HTTP for non-URL addresses with insecure mode.
	scheme := "https"
	if cfg.Insecure && parsed.Type != transport.AddressTypeHTTPS {
		scheme = "http"
	}
	return scheme + "://" + parsed.Address
}

// buildRouteMap creates the map-based dispatch table for ACME endpoints.
func buildRouteMap() map[string]RouteInfo {
	return map[string]RouteInfo{
		// Directory service
		"directory/get": {
			Method:      MethodGET,
			PathBuilder: pathDirectory,
			RequiresJWS: false,
		},

		// Nonce service
		"nonce/new": {
			Method:      MethodHEAD,
			PathBuilder: pathNewNonce,
			RequiresJWS: false,
		},

		// Account service
		"account/create": {
			Method:      MethodPOST,
			PathBuilder: pathNewAccount,
			RequiresJWS: true,
		},
		"account/get": {
			Method:      MethodPOST,
			PathBuilder: pathAccountByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},
		"account/update": {
			Method:      MethodPOST,
			PathBuilder: pathAccountByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},
		"account/deactivate": {
			Method:      MethodPOST,
			PathBuilder: pathAccountByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},
		"account/keychange": {
			Method:      MethodPOST,
			PathBuilder: pathKeyChange,
			RequiresJWS: true,
		},

		// Order service
		"order/create": {
			Method:      MethodPOST,
			PathBuilder: pathNewOrder,
			RequiresJWS: true,
		},
		"order/get": {
			Method:      MethodPOST,
			PathBuilder: pathOrderByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},
		"order/list": {
			Method:      MethodGET,
			PathBuilder: pathOrdersList,
			RequiresJWS: false,
		},
		"order/finalize": {
			Method:      MethodPOST,
			PathBuilder: pathFinalizeByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},

		// Authorization service
		"authorization/get": {
			Method:      MethodPOST,
			PathBuilder: pathAuthorizationByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},
		"authorization/deactivate": {
			Method:      MethodPOST,
			PathBuilder: pathAuthorizationByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},

		// Challenge service
		"challenge/get": {
			Method:      MethodPOST,
			PathBuilder: pathChallengeByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},
		"challenge/respond": {
			Method:      MethodPOST,
			PathBuilder: pathChallengeByURL,
			RequiresJWS: true,
			ExtractID:   true,
		},

		// Certificate service
		"certificate/get": {
			Method:      MethodGET,
			PathBuilder: pathCertificateByURL,
			RequiresJWS: false,
			ExtractID:   true,
		},
		"certificate/revoke": {
			Method:      MethodPOST,
			PathBuilder: pathRevokeCert,
			RequiresJWS: true,
		},
	}
}

// Path builder functions for ACME endpoints.

func pathDirectory(baseURL string, _ interface{}) string {
	return baseURL + "/directory"
}

func pathNewNonce(baseURL string, _ interface{}) string {
	return baseURL + "/acme/new-nonce"
}

func pathNewAccount(baseURL string, _ interface{}) string {
	return baseURL + "/acme/new-acct"
}

func pathAccountByURL(_ string, req interface{}) string {
	if r, ok := req.(URLExtractor); ok {
		return r.ExtractURL()
	}
	return ""
}

func pathKeyChange(baseURL string, _ interface{}) string {
	return baseURL + "/acme/key-change"
}

func pathNewOrder(baseURL string, _ interface{}) string {
	return baseURL + "/acme/new-order"
}

func pathOrderByURL(_ string, req interface{}) string {
	if r, ok := req.(URLExtractor); ok {
		return r.ExtractURL()
	}
	return ""
}

func pathOrdersList(baseURL string, req interface{}) string {
	if r, ok := req.(URLExtractor); ok {
		url := r.ExtractURL()
		if url != "" {
			return url
		}
	}
	return baseURL + "/acme/orders"
}

func pathFinalizeByURL(_ string, req interface{}) string {
	if r, ok := req.(URLExtractor); ok {
		return r.ExtractURL()
	}
	return ""
}

func pathAuthorizationByURL(_ string, req interface{}) string {
	if r, ok := req.(URLExtractor); ok {
		return r.ExtractURL()
	}
	return ""
}

func pathChallengeByURL(_ string, req interface{}) string {
	if r, ok := req.(URLExtractor); ok {
		return r.ExtractURL()
	}
	return ""
}

func pathCertificateByURL(_ string, req interface{}) string {
	if r, ok := req.(URLExtractor); ok {
		return r.ExtractURL()
	}
	return ""
}

func pathRevokeCert(baseURL string, _ interface{}) string {
	return baseURL + "/acme/revoke-cert"
}

// URLExtractor is an interface for request types that can provide a URL.
type URLExtractor interface {
	ExtractURL() string
}

// Request sends a unary HTTP request and returns the response.
func (t *Transport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	if t.closed.Load() {
		return nil, errors.NewUnavailable("rest.Transport.Request", "transport is closed")
	}

	routeKey := service + "/" + method
	route, ok := t.routes[routeKey]
	if !ok {
		return nil, errors.NewInvalidInput("rest.Transport.Request",
			"unknown route: "+routeKey)
	}

	path := route.PathBuilder(t.baseURL, req)
	if path == "" {
		return nil, errors.NewInvalidInput("rest.Transport.Request",
			"failed to build path for route: "+routeKey)
	}

	return t.executeRequest(ctx, route, path, req, routeKey)
}

// executeRequest performs the HTTP request with retry logic.
func (t *Transport) executeRequest(ctx context.Context, route RouteInfo, path string, req interface{}, routeKey string) (interface{}, error) {
	var lastErr error
	maxRetries := t.cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 1
	}

	backoff := t.cfg.RetryBackoff
	if backoff == 0 {
		backoff = 100 * time.Millisecond
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			if err := t.waitWithBackoff(ctx, backoff, attempt); err != nil {
				return nil, err
			}
		}

		resp, err := t.doRequest(ctx, route, path, req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// Return non-retryable errors immediately
		if !errors.IsRetryable(err) {
			return nil, err
		}

		// If only 1 attempt is configured (no retries), return the original error
		// This allows direct testing of error codes without retry wrapping
		if maxRetries == 1 {
			return nil, err
		}

		// For badNonce, try to refresh the nonce before retrying
		if errors.Is(err, errors.CodeACMEBadNonce) {
			if nonceErr := t.refreshNonce(ctx); nonceErr != nil {
				return nil, errors.Wrap(nonceErr, errors.CodeTransport, "rest.Transport.executeRequest",
					"failed to refresh nonce after badNonce error")
			}
		}
	}

	// All retries exhausted, wrap the error
	return nil, errors.Wrap(lastErr, errors.CodeTransport, "rest.Transport.executeRequest",
		"max retries exceeded")
}

// waitWithBackoff waits with exponential backoff.
func (t *Transport) waitWithBackoff(ctx context.Context, baseBackoff time.Duration, attempt int) error {
	wait := baseBackoff * time.Duration(1<<uint(attempt))
	if t.cfg.MaxRetryBackoff > 0 && wait > t.cfg.MaxRetryBackoff {
		wait = t.cfg.MaxRetryBackoff
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), errors.CodeCanceled, "rest.Transport.waitWithBackoff",
			"context canceled during retry backoff")
	case <-timer.C:
		return nil
	}
}

// doRequest performs a single HTTP request.
func (t *Transport) doRequest(ctx context.Context, route RouteInfo, url string, req interface{}) (interface{}, error) {
	var body io.Reader

	if hasBody(route.Method) && req != nil {
		bodyBytes, err := json.Marshal(req)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInvalidInput, "rest.Transport.doRequest",
				"failed to marshal request body")
		}
		body = bytes.NewReader(bodyBytes)
	}

	httpReq, err := http.NewRequestWithContext(ctx, string(route.Method), url, body)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeTransport, "rest.Transport.doRequest",
			"failed to create HTTP request")
	}

	t.setRequestHeaders(httpReq, route)

	resp, err := t.client.Do(httpReq)
	if err != nil {
		t.healthy.Store(false)
		return nil, t.wrapHTTPError(err)
	}
	defer transport.CloseResponseBody(resp)

	t.healthy.Store(true)

	if nonce := resp.Header.Get(HeaderReplayNonce); nonce != "" {
		t.lastNonce.Store(nonce)
	}

	return t.parseResponse(resp, route)
}

// setRequestHeaders sets the appropriate headers for the request.
func (t *Transport) setRequestHeaders(req *http.Request, route RouteInfo) {
	if hasBody(route.Method) {
		if route.RequiresJWS {
			req.Header.Set(HeaderContentType, ContentTypeJOSE)
		} else {
			req.Header.Set(HeaderContentType, ContentTypeJSON)
		}
	}
	req.Header.Set("Accept", ContentTypeJSON+", "+ContentTypePEM)
}

// parseResponse parses the HTTP response based on status code and content type.
func (t *Transport) parseResponse(resp *http.Response, route RouteInfo) (interface{}, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeTransport, "rest.Transport.parseResponse",
			"failed to read response body")
	}

	if resp.StatusCode >= 400 {
		return nil, t.parseErrorResponse(resp, bodyBytes)
	}

	result := &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       bodyBytes,
	}

	if location := resp.Header.Get(HeaderLocation); location != "" {
		result.Location = location
	}

	if nonce := resp.Header.Get(HeaderReplayNonce); nonce != "" {
		result.Nonce = nonce
	}

	if route.Method == MethodHEAD {
		return result, nil
	}

	contentType := resp.Header.Get(HeaderContentType)
	if strings.Contains(contentType, "application/pem") {
		result.IsPEM = true
		return result, nil
	}

	if len(bodyBytes) > 0 && strings.Contains(contentType, "json") {
		var data map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			return nil, errors.Wrap(err, errors.CodeTransport, "rest.Transport.parseResponse",
				"failed to parse JSON response")
		}
		result.Data = data
	}

	return result, nil
}

// parseErrorResponse parses an ACME error response.
func (t *Transport) parseErrorResponse(resp *http.Response, body []byte) error {
	acmeErr := &ACMEError{}
	if err := json.Unmarshal(body, acmeErr); err != nil {
		return errors.New(t.httpStatusToErrorCode(resp.StatusCode),
			"rest.Transport.parseErrorResponse",
			"HTTP "+resp.Status)
	}

	code := errors.ParseACMEErrorType(acmeErr.Type)
	if code == errors.CodeUnknown {
		code = t.httpStatusToErrorCode(resp.StatusCode)
	}

	caErr := errors.New(code, "rest.Transport.parseErrorResponse", acmeErr.Detail)
	_ = caErr.WithContext("type", acmeErr.Type)
	_ = caErr.WithContext("status", acmeErr.Status)

	if len(acmeErr.Subproblems) > 0 {
		_ = caErr.WithContext("subproblems", acmeErr.Subproblems)
	}

	return caErr
}

// httpStatusToErrorCode maps HTTP status codes to error codes.
func (t *Transport) httpStatusToErrorCode(status int) errors.ErrorCode {
	statusCodeMap := map[int]errors.ErrorCode{
		http.StatusBadRequest:          errors.CodeInvalidInput,
		http.StatusUnauthorized:        errors.CodeUnauthorized,
		http.StatusForbidden:           errors.CodeForbidden,
		http.StatusNotFound:            errors.CodeNotFound,
		http.StatusConflict:            errors.CodeConflict,
		http.StatusTooManyRequests:     errors.CodeRateLimited,
		http.StatusInternalServerError: errors.CodeInternal,
		http.StatusBadGateway:          errors.CodeUnavailable,
		http.StatusServiceUnavailable:  errors.CodeUnavailable,
		http.StatusGatewayTimeout:      errors.CodeTimeout,
	}

	if code, ok := statusCodeMap[status]; ok {
		return code
	}

	if status >= 400 && status < 500 {
		return errors.CodeInvalidInput
	}
	if status >= 500 {
		return errors.CodeInternal
	}

	return errors.CodeUnknown
}

// wrapHTTPError wraps an HTTP client error in a CAError.
func (t *Transport) wrapHTTPError(err error) error {
	if err == nil {
		return nil
	}

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return errors.Wrap(err, errors.CodeTimeout, "rest.Transport",
				"request timed out")
		}
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "connection refused"):
		return errors.Wrap(err, errors.CodeConnection, "rest.Transport",
			"connection refused")
	case strings.Contains(errStr, "no such host"):
		return errors.Wrap(err, errors.CodeConnection, "rest.Transport",
			"host not found")
	case strings.Contains(errStr, "context canceled"):
		return errors.Wrap(err, errors.CodeCanceled, "rest.Transport",
			"request canceled")
	case strings.Contains(errStr, "context deadline exceeded"):
		return errors.Wrap(err, errors.CodeTimeout, "rest.Transport",
			"request deadline exceeded")
	case strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:"):
		return errors.Wrap(err, errors.CodeConfiguration, "rest.Transport",
			"TLS error")
	default:
		return errors.Wrap(err, errors.CodeTransport, "rest.Transport",
			"HTTP request failed")
	}
}

// refreshNonce fetches a new nonce from the server.
func (t *Transport) refreshNonce(ctx context.Context) error {
	route := t.routes["nonce/new"]
	path := route.PathBuilder(t.baseURL, nil)

	_, err := t.doRequest(ctx, route, path, nil)
	return err
}

// GetNonce returns the current nonce value.
func (t *Transport) GetNonce() string {
	if v := t.lastNonce.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Conn returns the underlying HTTP client.
func (t *Transport) Conn() interface{} {
	return t.client
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	t.healthy.Store(false)

	if t.client != nil {
		if tr, ok := t.client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}

	return nil
}

// Healthy returns true if the transport is healthy.
func (t *Transport) Healthy() bool {
	return !t.closed.Load() && t.healthy.Load()
}

// BaseURL returns the base URL for the transport.
func (t *Transport) BaseURL() string {
	return t.baseURL
}

// Response represents a parsed HTTP response.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Data       map[string]interface{}
	Location   string
	Nonce      string
	IsPEM      bool
}

// ACMEError represents an ACME error response per RFC 8555.
type ACMEError struct {
	Type        string      `json:"type"`
	Detail      string      `json:"detail"`
	Status      int         `json:"status"`
	Subproblems []ACMEError `json:"subproblems,omitempty"`
	Identifier  *Identifier `json:"identifier,omitempty"`
}

// Identifier represents an ACME identifier.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Factory creates REST transports.
type Factory struct{}

// NewFactory creates a new REST transport factory.
func NewFactory() transport.Factory {
	return &Factory{}
}

// Create creates a new REST transport with the given configuration.
func (f *Factory) Create(cfg *transport.Config) (transport.Transport, error) {
	return NewTransport(cfg)
}
