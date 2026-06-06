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

// Package quic provides a QUIC/HTTP3 transport implementation for the Trusted CA SDK.
//
// The QUIC transport offers low-latency, multiplexed communication with the CA
// server using HTTP/3 over QUIC protocol (RFC 9000). It provides built-in TLS 1.3,
// connection migration, and 0-RTT connection establishment. It supports both ACME
// protocol operations and Admin API endpoints.
//
// Example usage:
//
//	cfg := &transport.Config{
//	    Address:   "https://localhost:9444",
//	    TLSConfig: tlsConfig,
//	}
//	t, err := quic.NewTransport(cfg)
//	if err != nil {
//	    return err
//	}
//	defer t.Close()
package quic

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/account"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/authorization"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/certificate"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/challenge"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/directory"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/nonce"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/order"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const (
	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second

	// HeaderReplayNonce is the ACME replay nonce header.
	HeaderReplayNonce = "Replay-Nonce"

	// HeaderContentType is the content type header.
	HeaderContentType = "Content-Type"

	// HeaderLocation is the location header.
	HeaderLocation = "Location"

	// ContentTypeJSON is the JSON content type.
	ContentTypeJSON = "application/json"

	// ContentTypeJoseJSON is the JOSE+JSON content type for ACME.
	ContentTypeJoseJSON = "application/jose+json"

	// ContentTypeProblemJSON is the problem+json content type for errors.
	ContentTypeProblemJSON = "application/problem+json"

	// ContentTypePEM is the PEM content type for certificates.
	ContentTypePEM = "application/pem-certificate-chain"
)

// routeKey uniquely identifies a service/method combination.
type routeKey struct {
	service string
	method  string
}

// routeConfig defines how to handle a specific route.
type routeConfig struct {
	httpMethod  string
	path        string
	bodyEncoder func(req interface{}) ([]byte, error)
	respDecoder func(body []byte, headers http.Header) (interface{}, error)
}

// Transport implements transport.Transport using QUIC/HTTP3.
type Transport struct {
	cfg        *transport.Config
	client     *http.Client
	h3Trans    *http3.Transport
	baseURL    string
	routes     map[routeKey]*routeConfig
	directory  *directory.Directory
	dirMu      sync.RWMutex
	healthy    atomic.Bool
	lastNonce  atomic.Value
	nonceMu    sync.Mutex
	closedOnce sync.Once
	closed     atomic.Bool
}

// NewTransport creates a new QUIC/HTTP3 transport with the given configuration.
func NewTransport(cfg *transport.Config) (transport.Transport, error) {
	if cfg == nil {
		return nil, errors.NewInvalidInput("quic.NewTransport", "config cannot be nil")
	}

	if cfg.Address == "" {
		return nil, errors.NewInvalidInput("quic.NewTransport", "address cannot be empty")
	}

	// QUIC requires an explicit TLS configuration. The Insecure flag only
	// affects verification when applied to a caller-supplied TLS config; it
	// does not authorize auto-fabricating one.
	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		return nil, errors.NewConfiguration("quic.NewTransport", "TLS configuration required for QUIC transport")
	}

	tlsConfig = tlsConfig.Clone()
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h3"}
	}

	h3Trans := &http3.Transport{
		TLSClientConfig: tlsConfig,
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	client := &http.Client{
		Transport: h3Trans,
		Timeout:   timeout,
	}

	baseURL := normalizeBaseURL(cfg.Address)

	t := &Transport{
		cfg:     cfg,
		client:  client,
		h3Trans: h3Trans,
		baseURL: baseURL,
	}

	// Build combined route map with ACME and admin routes.
	routes := buildRouteMap(t)
	for k, v := range buildAdminRouteMap() {
		routes[k] = v
	}
	t.routes = routes
	t.healthy.Store(true)

	return t, nil
}

// normalizeBaseURL ensures the base URL has proper scheme and no trailing slash.
func normalizeBaseURL(address string) string {
	if !strings.HasPrefix(address, "https://") && !strings.HasPrefix(address, "http://") {
		address = "https://" + address
	}
	return strings.TrimSuffix(address, "/")
}

// buildRouteMap constructs the map-based dispatch table for O(1) routing.
func buildRouteMap(t *Transport) map[routeKey]*routeConfig {
	return map[routeKey]*routeConfig{
		// Directory
		{service: "directory", method: "get"}: {
			httpMethod:  http.MethodGet,
			path:        "/directory",
			bodyEncoder: nil,
			respDecoder: decodeDirectoryResponse,
		},

		// Nonce
		{service: "nonce", method: "new"}: {
			httpMethod:  http.MethodHead,
			path:        "/acme/new-nonce",
			bodyEncoder: nil,
			respDecoder: decodeNonceResponse,
		},

		// Account
		{service: "account", method: "create"}: {
			httpMethod:  http.MethodPost,
			path:        "/acme/new-acct",
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeAccountResponse,
		},
		{service: "account", method: "get"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeAccountResponse,
		},
		{service: "account", method: "update"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeAccountResponse,
		},
		{service: "account", method: "deactivate"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeAccountResponse,
		},
		{service: "account", method: "key-change"}: {
			httpMethod:  http.MethodPost,
			path:        "/acme/key-change",
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeAccountResponse,
		},

		// Order
		{service: "order", method: "create"}: {
			httpMethod:  http.MethodPost,
			path:        "/acme/new-order",
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeOrderResponse,
		},
		{service: "order", method: "get"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeOrderResponse,
		},
		{service: "order", method: "list"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeOrderListResponse,
		},
		{service: "order", method: "finalize"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeOrderResponse,
		},

		// Authorization
		{service: "authorization", method: "get"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeAuthorizationResponse,
		},
		{service: "authorization", method: "deactivate"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeAuthorizationResponse,
		},

		// Challenge
		{service: "challenge", method: "get"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeChallengeResponse,
		},
		{service: "challenge", method: "respond"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeChallengeResponse,
		},

		// Certificate
		{service: "certificate", method: "get"}: {
			httpMethod:  http.MethodPost,
			path:        "", // URL from request
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeCertificateResponse,
		},
		{service: "certificate", method: "revoke"}: {
			httpMethod:  http.MethodPost,
			path:        "/acme/revoke-cert",
			bodyEncoder: encodeJSONBody,
			respDecoder: decodeRevokeResponse,
		},
	}
}

// Request sends a unary HTTP/3 request and returns the response.
func (t *Transport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	const op = "quic.Transport.Request"

	if t.closed.Load() {
		return nil, errors.NewConnection(op, "transport is closed")
	}

	key := routeKey{service: service, method: method}
	route, ok := t.routes[key]
	if !ok {
		return nil, errors.NewInvalidInput(op, "unknown service/method: "+service+"/"+method)
	}

	// Resolve the URL: admin routes use dynamic path resolution, ACME uses existing logic.
	var url string
	if isAdminRoute(service) {
		if route.path != "" {
			url = t.baseURL + route.path
		} else {
			url = resolveAdminURL(t.baseURL, key, req)
		}
		if url == "" {
			return nil, errors.NewInvalidInput(op, "failed to resolve URL for admin route: "+service+"/"+method)
		}
	} else {
		url = t.resolveURL(route.path, service, method, req)
	}

	var body []byte
	var err error
	if route.bodyEncoder != nil && req != nil {
		body, err = route.bodyEncoder(req)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInvalidInput, op, "failed to encode request body")
		}
	}

	httpReq, err := t.createHTTPRequest(ctx, route.httpMethod, url, body)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to create HTTP request")
	}

	resp, err := t.client.Do(httpReq)
	if err != nil {
		t.healthy.Store(false)
		return nil, errors.Wrap(err, errors.CodeConnection, op, "HTTP/3 request failed")
	}
	defer resp.Body.Close()

	t.healthy.Store(true)

	if nonceVal := resp.Header.Get(HeaderReplayNonce); nonceVal != "" {
		t.lastNonce.Store(nonceVal)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to read response body")
	}

	if resp.StatusCode >= 400 {
		return nil, t.parseACMEError(op, resp.StatusCode, respBody)
	}

	if route.respDecoder == nil {
		return nil, nil
	}

	return route.respDecoder(respBody, resp.Header)
}

// resolveURL determines the final URL for the request.
func (t *Transport) resolveURL(path, service, method string, req interface{}) string {
	if path != "" {
		return t.baseURL + path
	}

	switch service {
	case "account":
		switch method {
		case "get":
			if r, ok := req.(*account.GetRequest); ok && r.AccountURL != "" {
				return r.AccountURL
			}
		case "update":
			if r, ok := req.(*account.UpdateRequest); ok && r.AccountURL != "" {
				return r.AccountURL
			}
		case "deactivate":
			if r, ok := req.(*account.DeactivateRequest); ok && r.AccountURL != "" {
				return r.AccountURL
			}
		}
	case "order":
		switch method {
		case "get":
			if r, ok := req.(*order.GetRequest); ok && r.OrderURL != "" {
				return r.OrderURL
			}
		case "list":
			if r, ok := req.(*order.ListRequest); ok && r.AccountURL != "" {
				return r.AccountURL + "/orders"
			}
		case "finalize":
			if r, ok := req.(*order.FinalizeRequest); ok && r.FinalizeURL != "" {
				return r.FinalizeURL
			}
		}
	case "authorization":
		switch method {
		case "get":
			if r, ok := req.(*authorization.GetRequest); ok && r.AuthorizationURL != "" {
				return r.AuthorizationURL
			}
		case "deactivate":
			if r, ok := req.(*authorization.DeactivateRequest); ok && r.AuthorizationURL != "" {
				return r.AuthorizationURL
			}
		}
	case "challenge":
		switch method {
		case "get":
			if r, ok := req.(*challenge.GetRequest); ok && r.ChallengeURL != "" {
				return r.ChallengeURL
			}
		case "respond":
			if r, ok := req.(*challenge.RespondRequest); ok && r.ChallengeURL != "" {
				return r.ChallengeURL
			}
		}
	case "certificate":
		if method == "get" {
			if r, ok := req.(*certificate.GetRequest); ok && r.CertificateURL != "" {
				return r.CertificateURL
			}
		}
	}

	return t.baseURL
}

// createHTTPRequest creates an HTTP request with proper headers.
func (t *Transport) createHTTPRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	if len(body) > 0 {
		req.Header.Set(HeaderContentType, ContentTypeJoseJSON)
	}

	req.Header.Set("Accept", ContentTypeJSON+", "+ContentTypePEM+", "+ContentTypeProblemJSON)

	return req, nil
}

// parseACMEError parses an ACME error response.
func (t *Transport) parseACMEError(op string, statusCode int, body []byte) error {
	var acmeErr struct {
		Type        string `json:"type"`
		Detail      string `json:"detail"`
		Status      int    `json:"status"`
		Instance    string `json:"instance,omitempty"`
		Subproblems []struct {
			Type       string `json:"type"`
			Detail     string `json:"detail"`
			Identifier *struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifier,omitempty"`
		} `json:"subproblems,omitempty"`
	}

	if len(body) > 0 {
		if err := json.Unmarshal(body, &acmeErr); err == nil && acmeErr.Type != "" {
			code := errors.ParseACMEErrorType(acmeErr.Type)
			detail := acmeErr.Detail
			if detail == "" {
				detail = acmeErr.Type
			}

			caErr := errors.NewACMEError(code, op, detail)
			if acmeErr.Instance != "" {
				caErr.WithInstance(acmeErr.Instance)
			}

			for _, sp := range acmeErr.Subproblems {
				subproblem := errors.ACMESubproblem{
					Type:   sp.Type,
					Detail: sp.Detail,
				}
				if sp.Identifier != nil {
					subproblem.Identifier = &errors.ACMEIdentifier{
						Type:  sp.Identifier.Type,
						Value: sp.Identifier.Value,
					}
				}
				caErr.AddSubproblem(subproblem)
			}

			return caErr
		}
	}

	return httpStatusToError(op, statusCode, string(body))
}

// httpStatusToError converts an HTTP status code to a typed error.
func httpStatusToError(op string, statusCode int, message string) error {
	if message == "" {
		message = http.StatusText(statusCode)
	}

	switch statusCode {
	case http.StatusBadRequest:
		return errors.NewInvalidInput(op, message)
	case http.StatusUnauthorized:
		return errors.NewUnauthorized(op, message)
	case http.StatusForbidden:
		return errors.NewForbidden(op, message)
	case http.StatusNotFound:
		return errors.NewNotFound(op, message)
	case http.StatusConflict:
		return errors.NewConflict(op, message)
	case http.StatusTooManyRequests:
		return errors.NewRateLimited(op, message)
	case http.StatusInternalServerError:
		return errors.NewInternal(op, message)
	case http.StatusServiceUnavailable:
		return errors.NewUnavailable(op, message)
	case http.StatusGatewayTimeout:
		return errors.NewTimeout(op, message)
	default:
		if statusCode >= 500 {
			return errors.NewInternal(op, message)
		}
		return errors.NewInvalidInput(op, message)
	}
}

// RequestStream initiates a streaming request (not fully supported for HTTP/3 REST).
// For ACME, streaming is typically not used, but this provides basic support
// for potential future extensions like server-sent events.
func (t *Transport) RequestStream(ctx context.Context, service, method string, req interface{}) (transport.Stream, error) {
	return nil, errors.NewUnimplemented("quic.Transport.RequestStream", "streaming not fully supported for QUIC/HTTP3 transport")
}

// Conn returns the underlying HTTP client.
func (t *Transport) Conn() interface{} {
	return t.client
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	var closeErr error

	t.closedOnce.Do(func() {
		t.closed.Store(true)
		t.healthy.Store(false)

		if t.h3Trans != nil {
			closeErr = t.h3Trans.Close()
		}
	})

	return closeErr
}

// Healthy returns true if the transport is healthy.
func (t *Transport) Healthy() bool {
	return t.healthy.Load() && !t.closed.Load()
}

// GetLastNonce returns the last received nonce value.
func (t *Transport) GetLastNonce() string {
	if v := t.lastNonce.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// FetchNonce explicitly fetches a new nonce from the server.
func (t *Transport) FetchNonce(ctx context.Context) (string, error) {
	resp, err := t.Request(ctx, "nonce", "new", nil)
	if err != nil {
		return "", err
	}

	if nonceResp, ok := resp.(*nonce.NewResponse); ok {
		return nonceResp.Nonce, nil
	}

	return t.GetLastNonce(), nil
}

// GetDirectory returns the cached directory or fetches it.
func (t *Transport) GetDirectory(ctx context.Context) (*directory.Directory, error) {
	t.dirMu.RLock()
	if t.directory != nil {
		dir := t.directory
		t.dirMu.RUnlock()
		return dir, nil
	}
	t.dirMu.RUnlock()

	t.dirMu.Lock()
	defer t.dirMu.Unlock()

	if t.directory != nil {
		return t.directory, nil
	}

	resp, err := t.Request(ctx, "directory", "get", nil)
	if err != nil {
		return nil, err
	}

	if dirResp, ok := resp.(*directory.GetResponse); ok && dirResp.Directory != nil {
		t.directory = dirResp.Directory
		return t.directory, nil
	}

	return nil, errors.NewInternal("quic.Transport.GetDirectory", "unexpected response type")
}

// Body encoders

// encodeJSONBody encodes a request body to JSON.
func encodeJSONBody(req interface{}) ([]byte, error) {
	if req == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(req)
}

// Response decoders

// decodeDirectoryResponse decodes a directory response.
func decodeDirectoryResponse(body []byte, headers http.Header) (interface{}, error) {
	var dir directory.Directory
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "decodeDirectoryResponse", "failed to decode directory")
	}

	return &directory.GetResponse{
		Directory: &dir,
		Nonce:     headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeNonceResponse decodes a nonce response (from headers only).
func decodeNonceResponse(body []byte, headers http.Header) (interface{}, error) {
	return &nonce.NewResponse{
		Nonce: headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeAccountResponse decodes an account response.
func decodeAccountResponse(body []byte, headers http.Header) (interface{}, error) {
	var acct account.Account
	if len(body) > 0 {
		if err := json.Unmarshal(body, &acct); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "decodeAccountResponse", "failed to decode account")
		}
	}

	acct.URL = headers.Get(HeaderLocation)
	if acct.URL == "" {
		acct.URL = headers.Get("Link")
	}

	return &account.CreateResponse{
		Account:  &acct,
		Location: headers.Get(HeaderLocation),
		Nonce:    headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeOrderResponse decodes an order response.
func decodeOrderResponse(body []byte, headers http.Header) (interface{}, error) {
	var ord order.Order
	if len(body) > 0 {
		if err := json.Unmarshal(body, &ord); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "decodeOrderResponse", "failed to decode order")
		}
	}

	ord.URL = headers.Get(HeaderLocation)

	return &order.CreateResponse{
		Order:    &ord,
		Location: headers.Get(HeaderLocation),
		Nonce:    headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeOrderListResponse decodes an order list response.
func decodeOrderListResponse(body []byte, headers http.Header) (interface{}, error) {
	var resp struct {
		Orders []string `json:"orders"`
	}

	if len(body) > 0 {
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "decodeOrderListResponse", "failed to decode order list")
		}
	}

	return &order.ListResponse{
		Orders: resp.Orders,
		Nonce:  headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeAuthorizationResponse decodes an authorization response.
func decodeAuthorizationResponse(body []byte, headers http.Header) (interface{}, error) {
	var authz authorization.Authorization
	if len(body) > 0 {
		if err := json.Unmarshal(body, &authz); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "decodeAuthorizationResponse", "failed to decode authorization")
		}
	}

	authz.URL = headers.Get(HeaderLocation)

	return &authorization.GetResponse{
		Authorization: &authz,
		Nonce:         headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeChallengeResponse decodes a challenge response.
func decodeChallengeResponse(body []byte, headers http.Header) (interface{}, error) {
	var chal challenge.Challenge
	if len(body) > 0 {
		if err := json.Unmarshal(body, &chal); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "decodeChallengeResponse", "failed to decode challenge")
		}
	}

	return &challenge.GetResponse{
		Challenge: &chal,
		Nonce:     headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeCertificateResponse decodes a certificate response.
func decodeCertificateResponse(body []byte, headers http.Header) (interface{}, error) {
	cert := &certificate.Certificate{
		URL: headers.Get(HeaderLocation),
		PEM: string(body),
	}

	var alternateLinks []string
	for _, link := range headers.Values("Link") {
		if strings.Contains(link, "alternate") {
			start := strings.Index(link, "<")
			end := strings.Index(link, ">")
			if start >= 0 && end > start {
				alternateLinks = append(alternateLinks, link[start+1:end])
			}
		}
	}

	return &certificate.GetResponse{
		Certificate:    cert,
		Chain:          string(body),
		AlternateLinks: alternateLinks,
		Nonce:          headers.Get(HeaderReplayNonce),
	}, nil
}

// decodeRevokeResponse decodes a revoke response.
func decodeRevokeResponse(body []byte, headers http.Header) (interface{}, error) {
	return &certificate.RevokeResponse{
		Nonce: headers.Get(HeaderReplayNonce),
	}, nil
}

// Factory creates QUIC transports.
type Factory struct{}

// NewFactory creates a new QUIC transport factory.
func NewFactory() transport.Factory {
	return &Factory{}
}

// Create creates a new QUIC transport with the given configuration.
func (f *Factory) Create(cfg *transport.Config) (transport.Transport, error) {
	return NewTransport(cfg)
}
