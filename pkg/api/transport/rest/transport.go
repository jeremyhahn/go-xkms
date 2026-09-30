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

// Package rest provides a REST/HTTP transport implementation for the xkms SDK.
package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	wire "github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
)

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = errors.New("connection failed")
)

// ErrMalformedLeaderAddress indicates the leader API address advertised in
// the X-XKMS-Leader-API-Address header of a 421 Misdirected Request response
// could not be parsed into a dialable host:port. The transport refuses to
// guess at a redirect target from malformed data; the caller gets this error
// instead of a request silently sent nowhere (or somewhere wrong).
type ErrMalformedLeaderAddress struct {
	// Address is the raw, unparseable header value.
	Address string
	// Err is the underlying parse failure.
	Err error
}

// Error returns the error message.
func (e *ErrMalformedLeaderAddress) Error() string {
	return fmt.Sprintf("rest: malformed leader API address %q: %v", e.Address, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrMalformedLeaderAddress) Unwrap() error { return e.Err }

// Transport implements the transport.Client interface using HTTP/REST.
type Transport struct {
	config     *transport.Config
	httpClient *http.Client
	baseURL    string
	connected  bool
}

// New creates a new REST transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return NewWithConfig(cfg)
}

// NewWithConfig creates a new REST transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	// Parse and normalize the base URL
	baseURL := cfg.Address
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		if cfg.TLSEnabled {
			baseURL = "https://" + baseURL
		} else {
			baseURL = "http://" + baseURL
		}
	}

	// Remove trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Transport{
		config:  cfg,
		baseURL: baseURL,
	}, nil
}

// Connect establishes a connection to the xkms server via REST.
func (t *Transport) Connect(ctx context.Context) error {
	// Create TLS config if needed
	var tlsConfig *tls.Config
	if t.config.TLSEnabled {
		if t.config.TLSConfig != nil {
			// Use pre-built TLS config (e.g., PKCS#11-backed)
			tlsConfig = t.config.TLSConfig
		} else {
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
			}

			// Load CA certificate if specified
			if t.config.TLSCAFile != "" {
				caCert, err := os.ReadFile(t.config.TLSCAFile)
				if err != nil {
					return &errs.Wrapped{Msg: "failed to read CA certificate", Err: err}
				}
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					return &errs.Message{Msg: "failed to parse CA certificate"}
				}
				tlsConfig.RootCAs = caCertPool
			}

			// Load client certificate if specified (mTLS)
			if t.config.TLSCertFile != "" && t.config.TLSKeyFile != "" {
				cert, err := tls.LoadX509KeyPair(t.config.TLSCertFile, t.config.TLSKeyFile)
				if err != nil {
					return &errs.Wrapped{Msg: "failed to load client certificate", Err: err}
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
			}

			// SPKI pin verification
			if t.config.SPKIPin != "" {
				if t.config.TLSCAFile == "" && tlsConfig.RootCAs == nil {
					// Trust bootstrap: no CA cert available, SPKI pin IS the trust anchor
					tlsConfig = spki.NewPinnedTLSConfig(t.config.SPKIPin)
				} else {
					// Additive: CA chain validated first, pin adds extra verification
					tlsConfig.VerifyConnection = spki.VerifyConnection(t.config.SPKIPin)
				}
			}
		}
	}

	// Create HTTP client
	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	t.httpClient = &http.Client{
		Transport: httpTransport,
	}

	// Test connection with health check
	_, err := t.Health(ctx)
	if err != nil {
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
	}

	t.connected = true
	return nil
}

// Close closes the REST client.
func (t *Transport) Close() error {
	if t.httpClient != nil {
		t.httpClient.CloseIdleConnections()
	}
	t.connected = false
	return nil
}

// Healthy checks if the transport can communicate with the server.
func (t *Transport) Healthy(ctx context.Context) bool {
	if t.httpClient == nil {
		return false
	}

	reqURL := t.baseURL + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("failed to close response body: %v", closeErr)
		}
	}()

	return resp.StatusCode == http.StatusOK
}

// Conn returns the underlying HTTP client.
func (t *Transport) Conn() interface{} {
	return t.httpClient
}

// HTTPClient returns the HTTP client for direct access.
func (t *Transport) HTTPClient() *http.Client {
	return t.httpClient
}

// BaseURL returns the base URL for the REST API.
func (t *Transport) BaseURL() string {
	return t.baseURL
}

// IsConnected returns whether the transport is connected.
func (t *Transport) IsConnected() bool {
	return t.connected
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Request performs an HTTP request to the REST server.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	if t.httpClient == nil {
		return ErrNotConnected
	}

	// For REST, the method is the HTTP path
	return t.DoRequest(ctx, http.MethodPost, method, req, resp)
}

// DoRequest performs an HTTP request and unmarshals the response.
func (t *Transport) DoRequest(ctx context.Context, httpMethod, path string, body interface{}, result interface{}) error {
	respBody, err := t.DoRawRequest(ctx, httpMethod, path, body)
	if err != nil {
		return err
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return &errs.Wrapped{Msg: "failed to parse response", Err: err}
		}
	}

	return nil
}

// DoRawRequest performs an HTTP request and returns the raw response body.
//
// Transparent leader redirect: a clustered write that reaches a Raft
// follower comes back as 421 Misdirected Request with the leader's dialable
// REST address in the X-XKMS-Leader-API-Address header (see
// pkg/api/rest.writeNotLeader). When that header is present, DoRawRequest
// retries the identical request — same method, path, query, headers, and
// body — against the leader's address exactly once, reusing this
// Transport's own *http.Client so its TLS configuration (including any
// client certificate) is presented to the leader unchanged.
//
// The retry is a client-side redirect rather than the follower forwarding
// the request itself: forwarding would mean the follower re-presents ITS
// OWN credentials to the leader on the caller's behalf, silently delegating
// the caller's identity to a peer node. Retrying from here means the
// caller's own credentials reach the leader directly, so authorization on
// the write is evaluated against the identity that actually made the
// request.
//
// A 421 from the retry is returned to the caller as-is: exactly one hop is
// attempted, never chased further. A 421 with no address header is also
// returned as-is, unchanged from the pre-redirect behavior.
func (t *Transport) DoRawRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	if t.httpClient == nil {
		return nil, ErrNotConnected
	}

	var bodyBytes []byte
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to marshal request body", Err: err}
		}
		bodyBytes = data
	}

	respBody, statusCode, header, err := t.doRawRequestOnce(ctx, method, t.baseURL, path, bodyBytes)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusMisdirectedRequest {
		if leaderAddr := header.Get("X-XKMS-Leader-API-Address"); leaderAddr != "" {
			leaderBaseURL, addrErr := t.leaderBaseURL(leaderAddr)
			if addrErr != nil {
				return nil, addrErr
			}
			// Exactly one hop: whatever the leader returns (including another
			// 421) is what the caller gets back.
			respBody, statusCode, _, err = t.doRawRequestOnce(ctx, method, leaderBaseURL, path, bodyBytes)
			if err != nil {
				return nil, err
			}
		}
	}

	if statusCode >= 400 {
		return nil, parseRESTErrorResponse(statusCode, respBody)
	}

	return respBody, nil
}

// doRawRequestOnce sends a single HTTP request to baseURL+path and returns
// the raw response status, headers, and body without interpreting the status
// code. It is the one place a request is actually built and sent, used both
// for a request's initial attempt and its one-hop leader retry so the two
// attempts are identical apart from scheme+host.
func (t *Transport) doRawRequestOnce(ctx context.Context, method, baseURL, path string, bodyBytes []byte) ([]byte, int, http.Header, error) {
	var reqBody io.Reader
	if bodyBytes != nil {
		reqBody = bytes.NewReader(bodyBytes)
	}

	reqURL := baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, 0, nil, &errs.Wrapped{Msg: "failed to create request", Err: err}
	}

	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add JWT token if configured (Bearer authentication)
	if t.config.JWTToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.JWTToken)
	}

	// Add custom headers
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, &errs.Wrapped{Msg: "request failed", Err: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("failed to close response body: %v", closeErr)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, nil, &errs.Wrapped{Msg: "failed to read response body", Err: err}
	}

	return respBody, resp.StatusCode, resp.Header, nil
}

// leaderBaseURL turns a leader's advertised "host:port" API address into a
// base URL a retry can dial, reusing this Transport's own scheme so only
// scheme+host change between the original request and the retry — the path,
// query, and headers are untouched.
func (t *Transport) leaderBaseURL(addr string) (string, error) {
	if strings.Contains(addr, "://") {
		return "", &ErrMalformedLeaderAddress{Address: addr, Err: errors.New("must be a bare host:port, not a URL")}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", &ErrMalformedLeaderAddress{Address: addr, Err: err}
	}
	if host == "" || port == "" {
		return "", &ErrMalformedLeaderAddress{Address: addr, Err: errors.New("host and port must both be present")}
	}

	u, err := url.Parse(t.baseURL)
	if err != nil {
		return "", &ErrMalformedLeaderAddress{Address: addr, Err: err}
	}

	return u.Scheme + "://" + addr, nil
}

// parseRESTErrorResponse renders a non-2xx REST response body into the
// client-facing error, preferring the server's structured "error"/"message"
// field over the raw body.
func parseRESTErrorResponse(statusCode int, respBody []byte) error {
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
		return &errs.Message{Msg: fmt.Sprintf("server error: %s", errResp.Error)}
	}
	if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
		return &errs.Message{Msg: fmt.Sprintf("server error: %s", errResp.Message)}
	}
	return &errs.Message{Msg: fmt.Sprintf("server returned status %d: %s", statusCode, string(respBody))}
}

// DoRequestWithHeaders performs an HTTP request and returns response headers.
func (t *Transport) DoRequestWithHeaders(ctx context.Context, method, path string, body interface{}, reqHeaders map[string]string) ([]byte, http.Header, error) {
	if t.httpClient == nil {
		return nil, nil, ErrNotConnected
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, nil, &errs.Wrapped{Msg: "failed to marshal request body", Err: err}
		}
		reqBody = bytes.NewReader(data)
	}

	reqURL := t.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to create request", Err: err}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add JWT token if configured (Bearer authentication)
	if t.config.JWTToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.JWTToken)
	}

	// Add custom headers from config
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	// Add request-specific headers
	for k, v := range reqHeaders {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "request failed", Err: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("failed to close response body: %v", closeErr)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to read response body", Err: err}
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return nil, resp.Header, &errs.Message{Msg: fmt.Sprintf("server error: %s", errResp.Error)}
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return nil, resp.Header, &errs.Message{Msg: fmt.Sprintf("server error: %s", errResp.Message)}
		}
		return nil, resp.Header, &errs.Message{Msg: fmt.Sprintf("server returned status %d: %s", resp.StatusCode, string(respBody))}
	}

	return respBody, resp.Header, nil
}

// DoHeadRequest performs a HEAD request to check if a resource exists.
func (t *Transport) DoHeadRequest(ctx context.Context, path string) (bool, error) {
	if t.httpClient == nil {
		return false, ErrNotConnected
	}

	reqURL := t.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqURL, nil)
	if err != nil {
		return false, &errs.Wrapped{Msg: "failed to create request", Err: err}
	}

	// Add JWT token if configured (Bearer authentication)
	if t.config.JWTToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.JWTToken)
	}

	// Add custom headers
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return false, &errs.Wrapped{Msg: "request failed", Err: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("failed to close response body: %v", closeErr)
		}
	}()

	return resp.StatusCode == http.StatusOK, nil
}

// Health checks the health of the server.
func (t *Transport) Health(ctx context.Context) (*transport.HealthResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.HealthResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ListBackends returns a list of available backends.
func (t *Transport) ListBackends(ctx context.Context, opts ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	path := transport.AppendPaginationQuery("/api/v1/backends", transport.BuildPageRequest(opts...), false)
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListBackendsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetBackend returns information about a specific backend.
func (t *Transport) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	path := fmt.Sprintf("/api/v1/backends/%s", url.PathEscape(backendID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.BackendInfo
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Algorithms reports the algorithms the server supports.
func (t *Transport) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/algorithms", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.AlgorithmsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GenerateKey generates a new key.
func (t *Transport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys", req)
	if err != nil {
		return nil, err
	}

	var resp transport.GenerateKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ListKeys returns a list of keys in the specified backend.
func (t *Transport) ListKeys(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListKeysResponse, error) {
	path := fmt.Sprintf("/api/v1/keys?backend=%s", url.QueryEscape(backend))
	path = transport.AppendPaginationQuery(path, transport.BuildPageRequest(opts...), true)
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetKey returns information about a specific key.
func (t *Transport) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// DeleteKey deletes a key.
func (t *Transport) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	data, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.DeleteKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Sign signs data with the specified key.
func (t *Transport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/sign?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"data": req.Data,
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}
	if req.Padding != "" {
		body["padding"] = req.Padding
	}
	if req.SaltLength != 0 {
		body["salt_length"] = req.SaltLength
	}
	if req.DataIsDigest {
		body["data_is_digest"] = true
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.SignResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Verify verifies a signature.
func (t *Transport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/verify?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"data":      req.Data,
		"signature": req.Signature,
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}
	if req.Padding != "" {
		body["padding"] = req.Padding
	}
	if req.SaltLength != 0 {
		body["salt_length"] = req.SaltLength
	}
	if req.DataIsDigest {
		body["data_is_digest"] = true
	}
	if req.KeyVersion != 0 {
		body["key_version"] = req.KeyVersion
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.VerifyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Encrypt encrypts data with the specified key.
func (t *Transport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/encrypt?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"plaintext": req.Plaintext,
	}
	if len(req.AdditionalData) > 0 {
		body["additional_data"] = req.AdditionalData
	}
	if len(req.Nonce) > 0 {
		body["nonce"] = req.Nonce
	}
	if req.Mode != "" {
		body["mode"] = req.Mode
	}
	if len(req.IV) > 0 {
		body["iv"] = req.IV
	}
	if req.TagSize != 0 {
		body["tag_size"] = req.TagSize
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.EncryptResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Decrypt decrypts data with the specified key.
func (t *Transport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/decrypt?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"ciphertext": req.Ciphertext,
	}
	if len(req.Nonce) > 0 {
		body["nonce"] = req.Nonce
	}
	if len(req.Tag) > 0 {
		body["tag"] = req.Tag
	}
	if len(req.AdditionalData) > 0 {
		body["additional_data"] = req.AdditionalData
	}
	if req.GCMNonceMode != "" {
		body["gcm_nonce_mode"] = req.GCMNonceMode
	}
	if req.Mode != "" {
		body["mode"] = req.Mode
	}
	if len(req.IV) > 0 {
		body["iv"] = req.IV
	}
	if req.TagSize != 0 {
		body["tag_size"] = req.TagSize
	}

	if req.Padding != "" {
		body["padding"] = req.Padding
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}
	if len(req.Label) > 0 {
		body["label"] = req.Label
	}
	if req.KeyVersion != 0 {
		body["key_version"] = req.KeyVersion
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.DecryptResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (t *Transport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/encrypt-asym?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"plaintext": req.Plaintext,
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}
	// The OAEP label travels with the request or the round trip cannot close:
	// the matching Decrypt sends it, so an encryption that silently dropped it
	// produced a ciphertext neither this token nor any peer could decrypt.
	if len(req.Label) > 0 {
		body["label"] = req.Label
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.EncryptAsymResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// DeriveKey derives a key using the specified algorithm and parameters.
func (t *Transport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/derive?backend=%s", url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"algorithm":  req.Algorithm,
		"key_length": req.KeyLength,
	}
	if req.KeyID != "" {
		body["key_id"] = req.KeyID
	}
	if len(req.InputKeyMaterial) > 0 {
		body["input_key_material"] = req.InputKeyMaterial
	}
	if len(req.Salt) > 0 {
		body["salt"] = req.Salt
	}
	if len(req.Info) > 0 {
		body["info"] = req.Info
	}
	if len(req.PeerPublicKey) > 0 {
		body["peer_public_key"] = req.PeerPublicKey
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}
	if req.Iterations > 0 {
		body["iterations"] = req.Iterations
	}
	if req.PRF != "" {
		body["prf"] = req.PRF
	}
	if len(req.Label) > 0 {
		body["label"] = req.Label
	}
	if len(req.Context) > 0 {
		body["context"] = req.Context
	}
	if req.Counter > 0 {
		body["counter"] = req.Counter
	}
	if req.UseCofactor {
		body["use_cofactor"] = req.UseCofactor
	}
	if req.StoreResult {
		body["store_result"] = req.StoreResult
	}
	if req.DerivedKeyID != "" {
		body["derived_key_id"] = req.DerivedKeyID
	}
	if req.DerivedKeyType != "" {
		body["derived_key_type"] = req.DerivedKeyType
	}

	if req.KeyVersion != 0 {
		body["key_version"] = req.KeyVersion
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.DeriveKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetCertificate returns the certificate for a key.
func (t *Transport) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	path := fmt.Sprintf("/api/v1/certs/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SaveCertificate saves a certificate for a key.
func (t *Transport) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	path := fmt.Sprintf("/api/v1/certs?key_id=%s&backend=%s", url.QueryEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"certificate_pem": req.CertificatePEM,
	}

	_, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	return err
}

// DeleteCertificate deletes a certificate.
func (t *Transport) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	path := fmt.Sprintf("/api/v1/certs/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	_, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// CertificateExists checks if a certificate exists for a key.
func (t *Transport) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	path := fmt.Sprintf("/api/v1/certs/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	return t.DoHeadRequest(ctx, path)
}

// ImportKey imports a key.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/import", wire.NewImportKeyRequest(req))
	if err != nil {
		return nil, err
	}

	var resp transport.ImportKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ExportKey exports a key.
func (t *Transport) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/export?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"algorithm": req.Algorithm,
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.ExportKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// RotateKey rotates a key.
func (t *Transport) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/rotate?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.RotateKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	// The REST body and its response spell the ceremony's fields differently
	// from the transport contract; see pkg/api/rest/wire_byok.go.
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/import-params", wire.NewGetImportParametersRequest(req))
	if err != nil {
		return nil, err
	}

	var resp wire.GetImportParametersResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return resp.Transport()
}

// WrapKey wraps key material for secure transport.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	body, err := wire.NewWrapKeyRequest(req)
	if err != nil {
		return nil, err
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/wrap", body)
	if err != nil {
		return nil, err
	}

	var resp wire.WrapKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return resp.Transport(), nil
}

// UnwrapKey unwraps key material.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	body, err := wire.NewUnwrapKeyRequest(req)
	if err != nil {
		return nil, err
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/unwrap", body)
	if err != nil {
		return nil, err
	}

	var resp transport.UnwrapKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// WrapKeyByID wraps a key using another key, both identified by their IDs.
// This is a server-side key wrap operation where both keys exist in the xkms.
func (t *Transport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/wrap-by-id", req)
	if err != nil {
		return nil, err
	}

	var resp transport.WrapKeyByIDResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
// This is a server-side key unwrap operation.
func (t *Transport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/unwrap-by-id", req)
	if err != nil {
		return nil, err
	}

	var resp transport.UnwrapKeyByIDResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ExportKeyMaterial exports raw symmetric key material.
// SECURITY WARNING: This exports plaintext key material without cryptographic protection.
func (t *Transport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/export-material?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ExportKeyMaterialResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a key using a KDF.
func (t *Transport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/derive-ecdh", req)
	if err != nil {
		return nil, err
	}

	var resp transport.DeriveKeyECDHResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// CopyKey copies a key from one backend to another.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/copy", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CopyKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	path := fmt.Sprintf("/api/v1/certs?backend=%s", url.QueryEscape(backend))
	path = transport.AppendPaginationQuery(path, transport.BuildPageRequest(opts...), true)

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListCertificatesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (t *Transport) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	path := fmt.Sprintf("/api/v1/certs/%s/chain?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	_, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// GetCertificateChain returns the certificate chain for a key.
func (t *Transport) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	path := fmt.Sprintf("/api/v1/certs/%s/chain?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCertificateChainResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (t *Transport) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	path := fmt.Sprintf("/api/v1/tls/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetTLSCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Seal seals data using the backend's sealing mechanism.
func (t *Transport) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/seal", req)
	if err != nil {
		return nil, err
	}

	var resp transport.SealResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Unseal unseals previously sealed data.
func (t *Transport) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/unseal", req)
	if err != nil {
		return nil, err
	}

	var resp transport.UnsealResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// CanSeal checks if the backend supports sealing operations.
func (t *Transport) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/seal/capability?backend=%s", url.QueryEscape(backend))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.CanSealResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// AttestKey requests key attestation from a backend, proving the key
// is stored in hardware (TPM2, Android TEE/StrongBox, etc.).
func (t *Transport) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/attest", req)
	if err != nil {
		return nil, err
	}

	var resp transport.AttestKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Authentication Flow Operations - WebAuthn/FIDO2 server-side operations

// BeginRegistration begins a WebAuthn registration flow.
// Requires the server to have WebAuthn enabled. It returns the JSON-marshaled
// WebAuthn options together with an opaque session ID; the caller drives an
// authenticator with the options and echoes the session ID back to
// FinishRegistration. This is the lossless SDK ceremony that mirrors the
// browser ceremony served by pkg/webauthn/http.
func (t *Transport) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, _, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/sdk/registration/begin", req, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.BeginRegistrationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// FinishRegistration completes a WebAuthn registration flow.
// Requires the server to have WebAuthn enabled. The request carries the session
// ID from BeginRegistration and the authenticator attestation as WebAuthn
// PublicKeyCredential JSON.
func (t *Transport) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, _, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/sdk/registration/finish", req, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.FinishRegistrationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BeginAuthentication begins a WebAuthn authentication (login) flow.
// Requires the server to have WebAuthn enabled. It returns the JSON-marshaled
// WebAuthn assertion options together with an opaque session ID; the caller
// drives an authenticator with the options and echoes the session ID back to
// FinishAuthentication. This is the lossless SDK ceremony that mirrors the
// browser ceremony served by pkg/webauthn/http, symmetric to BeginRegistration.
func (t *Transport) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, _, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/sdk/authentication/begin", req, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.BeginAuthenticationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// FinishAuthentication completes a WebAuthn authentication (login) flow.
// Requires the server to have WebAuthn enabled. The request carries the session
// ID from BeginAuthentication and the authenticator assertion as WebAuthn
// PublicKeyCredential JSON.
func (t *Transport) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, _, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/sdk/authentication/finish", req, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.FinishAuthenticationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// Invitation redemption (go-xkms#1294 part B). Every route is public,
// mirroring the server's own /api/v1/invites/{tenant_id}/{token}... surface
// (pkg/api/rest/handlers_invite.go) byte-for-byte.

// GetInvite resolves a still-usable invitation's metadata without consuming it.
func (t *Transport) GetInvite(ctx context.Context, req *transport.GetInviteRequest) (*transport.GetInviteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	path := "/api/v1/invites/" + url.PathEscape(req.TenantID) + "/" + url.PathEscape(req.Token)
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp transport.GetInviteResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BeginInviteRegistration opens the invite-authorized WebAuthn registration ceremony.
func (t *Transport) BeginInviteRegistration(ctx context.Context, req *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	path := "/api/v1/invites/" + url.PathEscape(req.TenantID) + "/" + url.PathEscape(req.Token) + "/fido2/begin"
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}
	var resp transport.BeginInviteRegistrationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// FinishInviteRegistration completes the invite-authorized WebAuthn registration ceremony.
func (t *Transport) FinishInviteRegistration(ctx context.Context, req *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	path := "/api/v1/invites/" + url.PathEscape(req.TenantID) + "/" + url.PathEscape(req.Token) + "/fido2/finish"
	body := map[string]string{
		"session_id":       req.SessionID,
		"attestation_json": req.AttestationJSON,
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	var resp transport.FinishInviteRegistrationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// ActivateInvitePIV activates the account by verifying a presented PIV certificate.
func (t *Transport) ActivateInvitePIV(ctx context.Context, req *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	path := "/api/v1/invites/" + url.PathEscape(req.TenantID) + "/" + url.PathEscape(req.Token) + "/piv/activate"
	body := map[string]string{"cert_pem": req.CertPEM}
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	var resp transport.ActivateInvitePIVResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// CA Operations

// GetCABundle retrieves the CA certificate bundle.
func (t *Transport) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	path := "/api/v1/ca/bundle"
	params := url.Values{}
	if req.StoreType != "" {
		params.Set("store_type", req.StoreType)
	}
	if req.Algorithm != "" {
		params.Set("algorithm", req.Algorithm)
	}
	if req.TenantID != "" {
		params.Set("tenant_id", req.TenantID)
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCABundleResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetCACertificate retrieves the CA certificate.
func (t *Transport) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	path := "/api/v1/ca/certificate"
	params := url.Values{}
	if req.Identity != "" {
		params.Set("identity", req.Identity)
	}
	if req.TenantID != "" {
		params.Set("tenant_id", req.TenantID)
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCACertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SignCSR signs a certificate signing request.
func (t *Transport) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	body := map[string]interface{}{
		"csr_pem": req.CSRPEM,
	}
	if req.Profile != "" {
		body["profile"] = req.Profile
	}
	if req.ValidityDays > 0 {
		body["validity_days"] = req.ValidityDays
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/sign-csr", body)
	if err != nil {
		return nil, err
	}

	var resp transport.SignCSRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// IssueCertificate issues a new certificate.
func (t *Transport) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	body := map[string]interface{}{
		"common_name": req.CommonName,
		"profile":     req.Profile,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if len(req.SANs) > 0 {
		body["sans"] = req.SANs
	}
	if req.ValidityDays > 0 {
		body["validity_days"] = req.ValidityDays
	}
	if req.Algorithm != "" {
		body["algorithm"] = req.Algorithm
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/issue", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// RevokeCertificate revokes a certificate.
func (t *Transport) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	body := map[string]interface{}{
		"serial_number": req.SerialNumber,
		"reason":        req.Reason,
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/revoke", body)
	if err != nil {
		return nil, err
	}

	var resp transport.RevokeCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GenerateCRL generates a certificate revocation list.
func (t *Transport) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	var body map[string]interface{}
	if req.TenantID != "" {
		body = map[string]interface{}{
			"tenant_id": req.TenantID,
		}
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/crl", body)
	if err != nil {
		return nil, err
	}

	var resp transport.GenerateCRLResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// IsRevoked checks if a certificate is revoked.
func (t *Transport) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	path := fmt.Sprintf("/api/v1/ca/revoked/%s", url.PathEscape(req.SerialNumber))
	if req.TenantID != "" {
		path += "?tenant_id=" + url.QueryEscape(req.TenantID)
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.IsRevokedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// TCG CA Operations

// IssueEKCertificate issues an Endorsement Key certificate via the TCG CA.
func (t *Transport) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	body := map[string]interface{}{
		"common_name":   req.CommonName,
		"ek_public_key": req.EKPublicKey,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/tcg/ek", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueEKCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// IssueAKCertificate issues an Attestation Key certificate via the TCG CA.
func (t *Transport) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	body := map[string]interface{}{
		"common_name": req.CommonName,
		"public_key":  req.PublicKey,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/tcg/ak", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueAKCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SignTCGCSR signs a TCG-CSR-IDEVID for device identity enrollment.
func (t *Transport) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	body := map[string]interface{}{
		"common_name": req.CommonName,
		"tcg_csr":     req.TCGCSR,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/tcg/sign-csr", body)
	if err != nil {
		return nil, err
	}

	var resp transport.SignTCGCSRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// EnrollDevice performs complete TCG device enrollment via the TCG CA.
func (t *Transport) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	body := map[string]interface{}{
		"common_name": req.CommonName,
		"packed_csr":  req.PackedCSR,
	}
	if req.Organization != "" {
		body["organization"] = req.Organization
	}
	if req.TenantID != "" {
		body["tenant_id"] = req.TenantID
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/ca/tcg/enroll", body)
	if err != nil {
		return nil, err
	}

	var resp transport.EnrollDeviceResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// PIV Operations

// ListPIVSlots returns the list of PIV slots and their status for the specified backend.
func (t *Transport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots?backend=%s", url.QueryEscape(req.Backend))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListPIVSlotsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetPIVCertificate retrieves the certificate stored in a specific PIV slot.
func (t *Transport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots/%s/certificate?backend=%s&format=%s",
		url.PathEscape(req.Slot), url.QueryEscape(req.Backend), url.QueryEscape(req.Format))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetPIVCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// StorePIVCertificate stores a certificate into a specific PIV slot.
func (t *Transport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots/%s/certificate", url.PathEscape(req.Slot))
	_, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// DeletePIVCertificate removes the certificate from a specific PIV slot.
func (t *Transport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots/%s/certificate?backend=%s",
		url.PathEscape(req.Slot), url.QueryEscape(req.Backend))
	_, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// GeneratePIVKey generates a new key pair in a specific PIV slot and returns
// a self-signed certificate and the public key.
func (t *Transport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots/%s/generate", url.PathEscape(req.Slot))
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.GeneratePIVKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ImportPIVCertificate imports an externally issued certificate into a PIV slot.
func (t *Transport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots/%s/import", url.PathEscape(req.Slot))
	_, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// ExportPIVCertificate exports the certificate from a PIV slot in the requested format.
func (t *Transport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots/%s/export?backend=%s&format=%s",
		url.PathEscape(req.Slot), url.QueryEscape(req.Backend), url.QueryEscape(req.Format))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetPIVCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GeneratePIVCSR generates a Certificate Signing Request for a key in a PIV slot.
func (t *Transport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/piv/slots/%s/csr", url.PathEscape(req.Slot))
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.GeneratePIVCSRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Barrier Operations

// BarrierInitialize initializes the barrier by generating a root key and sealing it.
func (t *Transport) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/initialize", req)
	return err
}

// BarrierUnseal unseals the barrier by loading and decrypting the root key.
func (t *Transport) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/unseal", req)
	return err
}

// BarrierSeal transitions the barrier to sealed state, zeroing the DEK.
func (t *Transport) BarrierSeal(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/seal", nil)
	return err
}

// BarrierStatus returns the current barrier status including seal state and active strategy.
func (t *Transport) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/barrier/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.BarrierStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// BootstrapListenerKeys returns the running trust-bootstrap listener's
// public static keys.
func (t *Transport) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/bootstrap/keys", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.BootstrapListenerKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// BarrierInitializeShamir initializes the barrier using Shamir secret sharing.
func (t *Transport) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/shamir/initialize", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierInitializeShamirResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BarrierUnsealWithShare submits a single Shamir share toward the quorum.
func (t *Transport) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/shamir/unseal-share", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierUnsealShareResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BarrierUnsealWithShares submits all Shamir shares at once for batch unsealing.
func (t *Transport) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/shamir/unseal-shares", req)
	return err
}

// BarrierRekey rotates Shamir shares while keeping the same root key.
func (t *Transport) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/rekey", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierRekeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys for disaster recovery.
func (t *Transport) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/recovery/generate", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierRecoveryKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BarrierEnableEncryption migrates a previously-unencrypted barrier to a keyed
// strategy in place.
func (t *Transport) BarrierEnableEncryption(ctx context.Context, req *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/enable-encryption", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierEnableEncryptionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BarrierRecoverWithKeys unseals the barrier using recovery keys.
func (t *Transport) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/recovery/recover", req)
	return err
}

// BarrierDeleteRecoveryKeys deletes stored recovery key metadata.
func (t *Transport) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodDelete, "/api/v1/barrier/recovery/keys", nil)
	return err
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (t *Transport) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/barrier/recovery/keys", nil)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierHasRecoveryKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// BarrierGenerateRootToken generates a one-time root token by proving
// knowledge of the master key through Shamir share reconstruction.
func (t *Transport) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/barrier/recovery/root-token", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierRootTokenResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// PIN Operations

// SetSOPIN sets the Security Officer PIN.
func (t *Transport) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/pin/so/set", req)
	return err
}

// SetUserPIN sets the user PIN. Requires SO PIN authorization.
func (t *Transport) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/pin/user/set", req)
	return err
}

// ChangeSOPIN changes the Security Officer PIN.
func (t *Transport) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/pin/so/change", req)
	return err
}

// ChangeUserPIN changes the user PIN.
func (t *Transport) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/pin/user/change", req)
	return err
}

// VerifySOPIN verifies the Security Officer PIN.
func (t *Transport) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/pin/so/verify", req)
	return err
}

// VerifyUserPIN verifies the user PIN.
func (t *Transport) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/pin/user/verify", req)
	return err
}

// GetLockoutStatus returns the current PIN lockout status.
func (t *Transport) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/pin/lockout", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.LockoutStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ResetLockout resets the PIN lockout counter using SO PIN authorization.
func (t *Transport) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/pin/lockout/reset", req)
	return err
}

// Password Store Operations

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/passwords/", req)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordAddResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/passwords/%s", url.PathEscape(req.ID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordGetResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := "/api/v1/passwords/"
	params := url.Values{}
	if req != nil {
		if req.FolderPath != "" {
			params.Set("folder", req.FolderPath)
		}
		if req.Scope != "" {
			params.Set("scope", req.Scope)
		}
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/passwords/%s", url.PathEscape(req.ID))
	_, err := t.DoRawRequest(ctx, http.MethodPut, path, req)
	return err
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/passwords/%s", url.PathEscape(req.ID))
	_, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/passwords/unlock", req)
	return err
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/passwords/lock", nil)
	return err
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/passwords/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordStoreStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/passwords/access-mode", req)
	return err
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/passwords/generate", req)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordGenerateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SealStorePut stores a secret in the platform-sealed store.
func (t *Transport) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	path := fmt.Sprintf("/api/v1/platform/secrets/%s", url.PathEscape(req.Name))
	_, err := t.DoRawRequest(ctx, http.MethodPut, path, req)
	return err
}

// SealStoreGet retrieves a secret from the platform-sealed store.
func (t *Transport) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	path := fmt.Sprintf("/api/v1/platform/secrets/%s", url.PathEscape(req.Name))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.SealStoreGetResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// SealStoreDelete deletes a secret from the platform-sealed store.
func (t *Transport) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	path := fmt.Sprintf("/api/v1/platform/secrets/%s", url.PathEscape(req.Name))
	_, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// SealStoreList lists all stored secret names in the platform-sealed store.
func (t *Transport) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/platform/secrets", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.SealStoreListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// SealStoreReseal reseals a secret with the current platform sealing key.
func (t *Transport) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	path := fmt.Sprintf("/api/v1/platform/secrets/%s/reseal", url.PathEscape(req.Name))
	_, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	return err
}

// SealStoreStatus returns the platform-sealed store status.
func (t *Transport) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/platform/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.SealStoreStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// External key escrow (pkg/escrow) is embedded-only (go-xkms#692): its RBAC
// model is undecided, so Transport does not implement EscrowKey/RecoverKey/
// ListEscrowed/RevokeEscrow at all. transport.EscrowService is no longer
// part of transport.Client — see docs/escrow/architecture.md.

// Key Version Operations
//
// The key-version API is served by wire.KeyVersionClient, shared with the
// QUIC transport, over the REST routes.

// ListKeyVersions lists a key's versions.
func (t *Transport) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.KeyVersionClient{Do: t.DoRawRequest}.ListKeyVersions(ctx, req)
}

// EnableKeyVersion enables a version of a key.
func (t *Transport) EnableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.KeyVersionClient{Do: t.DoRawRequest}.EnableKeyVersion(ctx, req)
}

// DisableKeyVersion disables a version of a key.
func (t *Transport) DisableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.KeyVersionClient{Do: t.DoRawRequest}.DisableKeyVersion(ctx, req)
}

// RetireKeyVersion retires a version of a key.
func (t *Transport) RetireKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.KeyVersionClient{Do: t.DoRawRequest}.RetireKeyVersion(ctx, req)
}

// EnableAllKeyVersions enables every disabled version of a key.
func (t *Transport) EnableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.KeyVersionClient{Do: t.DoRawRequest}.EnableAllKeyVersions(ctx, req)
}

// DisableAllKeyVersions disables every non-current version of a key.
func (t *Transport) DisableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.KeyVersionClient{Do: t.DoRawRequest}.DisableAllKeyVersions(ctx, req)
}

// RotateScopeKeys rotates every key of a tenant.
func (t *Transport) RotateScopeKeys(ctx context.Context, req *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.KeyVersionClient{Do: t.DoRawRequest}.RotateScopeKeys(ctx, req)
}

// TPM Policy Operations
//
// The TPM policy API is served by wire.TPMPolicyClient, shared with the
// QUIC transport, over the REST routes.

// TPMPolicyCreate creates a named TPM policy.
func (t *Transport) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyCreate(ctx, req)
}

// TPMPolicyGet returns a named TPM policy.
func (t *Transport) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyGet(ctx, req)
}

// TPMPolicyList returns a tenant's TPM policies.
func (t *Transport) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyList(ctx, req)
}

// TPMPolicyUpdate re-captures and re-approves a TPM policy.
func (t *Transport) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyUpdate(ctx, req)
}

// TPMPolicyRevoke withdraws a TPM policy's approval.
func (t *Transport) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyRevoke(ctx, req)
}

// TPMPolicyVerify compares a TPM policy's PCR values with the live ones.
func (t *Transport) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyVerify(ctx, req)
}

// TPMPolicyDelete deletes a TPM policy no object is assigned to.
func (t *Transport) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyDelete(ctx, req)
}

// TPMPolicyObjects lists the objects assigned to a TPM policy.
func (t *Transport) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyObjects(ctx, req)
}

// TPMPolicySetAutoUnseal sets or clears a TPM policy's auto-unseal mark.
func (t *Transport) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicySetAutoUnseal(ctx, req)
}

// TPMPolicySetDescription replaces a TPM policy's description.
func (t *Transport) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicySetDescription(ctx, req)
}

// TPMObjectPolicy returns the TPM policy a key or sealed object was created under.
func (t *Transport) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMObjectPolicy(ctx, req)
}

// TPMPolicyRotateAuthority rotates a tenant's TPM policy authority.
func (t *Transport) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TPMPolicyRotateAuthority(ctx, req)
}

// GetTenantTPMMode returns a tenant's TPM mode.
func (t *Transport) GetTenantTPMMode(ctx context.Context, tenantID string) (*transport.TenantTPMModeResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.GetTenantTPMMode(ctx, tenantID)
}

// SetTenantTPMMode changes a tenant's TPM mode.
func (t *Transport) SetTenantTPMMode(ctx context.Context, req *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.SetTenantTPMMode(ctx, req)
}

// TenantVTPMStatus reports a tenant's virtual TPM.
func (t *Transport) TenantVTPMStatus(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TenantVTPMStatus(ctx, tenantID)
}

// TenantVTPMStart starts a tenant's virtual TPM.
func (t *Transport) TenantVTPMStart(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TenantVTPMStart(ctx, tenantID)
}

// TenantVTPMStop stops a tenant's virtual TPM.
func (t *Transport) TenantVTPMStop(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return wire.TPMPolicyClient{Do: t.DoRawRequest}.TenantVTPMStop(ctx, tenantID)
}

// CustodianGroupService methods.

// CreateCustodianGroup creates a new custodian group.
func (t *Transport) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/custodian/groups/", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CreateCustodianGroupResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetCustodianGroup retrieves a custodian group by ID.
func (t *Transport) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s", url.PathEscape(groupID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCustodianGroupResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ListCustodianGroups returns all custodian groups.
func (t *Transport) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/custodian/groups/", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListCustodianGroupsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// DeleteCustodianGroup deletes a custodian group by ID.
func (t *Transport) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	_, err := t.DoRawRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/custodian/groups/%s", url.PathEscape(groupID)), nil)
	return err
}

// AddCustodianMember adds a member to a custodian group.
func (t *Transport) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s/members", url.PathEscape(req.GroupID))
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.AddCustodianMemberResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (t *Transport) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s/members/%s", url.PathEscape(req.GroupID), url.PathEscape(req.UserID))
	_, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// DistributeShares triggers share distribution for a custodian group.
func (t *Transport) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s/distribute", url.PathEscape(req.GroupID))
	data, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.DistributeSharesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ShareService methods.

// SubmitShare submits a Shamir share for storage.
func (t *Transport) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/shares/submit", req)
	if err != nil {
		return nil, err
	}

	var resp transport.SubmitShareResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ListShares returns all stored shares.
func (t *Transport) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/shares/", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListSharesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetShare returns a single stored share. Share material is never included
// in the response — the server returns metadata only.
func (t *Transport) GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*transport.ShareInfo, error) {
	data, err := t.DoRawRequest(ctx, http.MethodGet, sharePath(serverURL, groupID, shareIndex), nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ShareInfo
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// DeleteShare removes a single stored share.
func (t *Transport) DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	_, err := t.DoRawRequest(ctx, http.MethodDelete, sharePath(serverURL, groupID, shareIndex), nil)
	return err
}

// sharePath builds the per-share REST path. The server URL is a URL itself,
// so it is escaped as a single path segment.
func sharePath(serverURL, groupID string, shareIndex int) string {
	return fmt.Sprintf("/api/v1/shares/%s/%s/%d",
		url.PathEscape(serverURL), url.PathEscape(groupID), shareIndex)
}

// QueryAudit returns one page of audit events from the tamper-evident audit
// chain owned by the embedded qrdb node, filtered by the given AuditFilter.
// The filter is carried entirely in the query string; zero/empty fields are
// omitted rather than sent as blanks so a zero From/To stays unbounded.
func (t *Transport) QueryAudit(ctx context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	if filter == nil {
		return nil, transport.ErrInvalidRequest
	}

	q := url.Values{}
	if !filter.From.IsZero() {
		q.Set("from", filter.From.Format(time.RFC3339))
	}
	if !filter.To.IsZero() {
		q.Set("to", filter.To.Format(time.RFC3339))
	}
	if filter.Actor != "" {
		q.Set("actor", filter.Actor)
	}
	if filter.Resource != "" {
		q.Set("resource", filter.Resource)
	}
	if filter.Action != "" {
		q.Set("action", filter.Action)
	}
	if filter.Outcome != "" {
		q.Set("outcome", filter.Outcome)
	}
	if filter.TenantID != "" {
		q.Set("tenant_id", filter.TenantID)
	}
	if filter.Limit > 0 {
		q.Set("limit", strconv.Itoa(filter.Limit))
	}
	if filter.Cursor != "" {
		q.Set("cursor", filter.Cursor)
	}

	path := "/api/v1/audit/"
	if encoded := q.Encode(); encoded != "" {
		path = path + "?" + encoded
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.AuditPage
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetShareCollectionStatus returns the share collection status for a group.
func (t *Transport) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	path := fmt.Sprintf("/api/v1/shares/status/%s", url.PathEscape(groupID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ShareCollectionStatus
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// TenantService methods.

// CreateTenant creates a new tenant.
//
// The trailing slash matters: pkg/api/rest/routes.go registers every
// collection-root route in this file's resource families with one
// (permIf("POST", "/tenants/", ...), matching "/custodian/groups/",
// "/shares/", "/passwords/"), to distinguish the collection from
// "/tenants/{tenantID}". Omitting it here used to still reach the handler
// because nothing else on the unified listener claimed the bare
// "/api/v1/tenants" path, so chi's slash redirect silently bridged the
// gap. It stopped working the moment something else registered that exact
// literal path too (the ACME admin plane's own, unrelated
// "/api/v1/tenants" tenant surface, pkg/apimodule/admin_module.go +
// cmd/xkmsd/admin.go's adminAPIPrefixes): that registration is an exact,
// non-redirecting match, so it now answers first, and this client
// silently unmarshals that handler's differently-shaped response body
// into transport.CreateTenantResponse — every field comes back its zero
// value, with no error, because the JSON simply has no "tenant" key at
// its top level. See transport_tenant_test.go's
// TestCreateTenant_CollectionRootRequiresTrailingSlash for the regression
// coverage.
func (t *Transport) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/tenants/", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CreateTenantResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetTenant retrieves a tenant by ID.
func (t *Transport) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s", url.PathEscape(tenantID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetTenantResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ListTenants returns all tenants.
//
// See CreateTenant's doc comment: the trailing slash is required for the
// same reason.
func (t *Transport) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/tenants/", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListTenantsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// DeleteTenant deletes a tenant by ID.
func (t *Transport) DeleteTenant(ctx context.Context, tenantID string) error {
	_, err := t.DoRawRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/tenants/%s", url.PathEscape(tenantID)), nil)
	return err
}

// TenantBarrierInit initializes the barrier for a tenant.
func (t *Transport) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	path := fmt.Sprintf("/api/v1/tenants/%s/barrier/init", url.PathEscape(req.TenantID))
	_, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// TenantBarrierUnseal unseals the barrier for a tenant.
func (t *Transport) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	path := fmt.Sprintf("/api/v1/tenants/%s/barrier/unseal", url.PathEscape(req.TenantID))
	_, err := t.DoRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// TenantBarrierStatus reports the status of a per-tenant barrier.
func (t *Transport) TenantBarrierStatus(ctx context.Context, tenantID string) (*transport.TenantBarrierStatusResponse, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/barrier/status", url.PathEscape(tenantID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp transport.TenantBarrierStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// UpdateTenantEntitlements updates a tenant's feature entitlements.
func (t *Transport) UpdateTenantEntitlements(ctx context.Context, req *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/entitlements", url.PathEscape(req.TenantID))
	data, err := t.DoRawRequest(ctx, http.MethodPut, path, req)
	if err != nil {
		return nil, err
	}
	var resp transport.UpdateTenantEntitlementsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas.
func (t *Transport) UpdateTenantQuotas(ctx context.Context, req *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/quotas", url.PathEscape(req.TenantID))
	data, err := t.DoRawRequest(ctx, http.MethodPut, path, req)
	if err != nil {
		return nil, err
	}
	var resp transport.UpdateTenantQuotasResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}
	return &resp, nil
}

// Init Ceremony methods.

// GetInitStatus returns the current init ceremony state.
func (t *Transport) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/init/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.InitStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (t *Transport) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-cert/begin", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimCertBeginResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimCertComplete completes the certificate claim by verifying the officer's
// signature over the challenge nonce.
func (t *Transport) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-cert/complete", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimCertCompleteResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimShare retrieves the Shamir share for the named officer.
func (t *Transport) ClaimShareBegin(ctx context.Context, req *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-share/begin", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimShareBeginResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ClaimShareComplete completes the Shamir share claim handshake for the named
// officer.
func (t *Transport) ClaimShareComplete(ctx context.Context, req *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-share/complete", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimShareCompleteResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// SignCSRInit signs a CSR during initialization with SO authorization.
func (t *Transport) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/init/sign-csr", req)
	if err != nil {
		return nil, err
	}

	var resp transport.SignCSRInitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// Credential Management methods.

// SubmitCredential submits a credential for manual mode.
func (t *Transport) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/credentials/submit", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CredentialSubmitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetCredentialStrategy returns the configured credential strategy.
func (t *Transport) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/credentials/strategy", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.CredentialStrategyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ==================== User Operations ====================
//
// The REST transport reaches the xkms user API exposed under /api/v1/users.

// CreateUser creates a new xkms user.
func (t *Transport) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	// map[string]any, NOT map[string]string: WithoutEmailLoginKey is a bool and
	// a string-valued map cannot carry it, so the certificate-authenticated
	// admin's exemption was dropped on the wire. The server then saw an empty
	// email with no declaration and refused the request — a create that works
	// over gRPC/unix and fails over this transport (Codex, go-xkms #190).
	body := map[string]any{
		"username":                req.Username,
		"email":                   req.Email,
		"without_email_login_key": req.WithoutEmailLoginKey,
		"display_name":            req.DisplayName,
		"role":                    req.Role,
		"tenant_id":               req.TenantID,
		"invite_ttl_seconds":      req.InviteTTLSeconds,
	}

	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/users/", body)
	if err != nil {
		return nil, err
	}

	// The full response, not just UserInfo: an invited create carries the
	// one-time activation invitation (go-xkms#1294 part B), returned exactly
	// once and unrecoverable afterwards.
	var resp transport.GetUserResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// ListUsers lists xkms users.
func (t *Transport) ListUsers(ctx context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/users/", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListUsersResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &resp, nil
}

// GetUser retrieves a single xkms user by username.
func (t *Transport) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(username))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var user transport.UserInfo
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	return &transport.GetUserResponse{User: user}, nil
}

// DeleteUser removes an xkms user by username.
func (t *Transport) DeleteUser(ctx context.Context, username string) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(username))
	if _, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil); err != nil {
		return err
	}

	return nil
}

// EnableUser enables an xkms user by username.
func (t *Transport) EnableUser(ctx context.Context, username string) error {
	return t.setUserEnabled(ctx, username, true)
}

// DisableUser disables an xkms user by username.
func (t *Transport) DisableUser(ctx context.Context, username string) error {
	return t.setUserEnabled(ctx, username, false)
}

// setUserEnabled toggles the enabled state of an xkms user via its own
// per-direction route (POST .../enable or .../disable), gated on qrdb's own
// users:enable/users:disable rather than the coarser users:update
// (go-xkms#1249).
func (t *Transport) setUserEnabled(ctx context.Context, username string, enabled bool) error {
	if !t.connected {
		return ErrNotConnected
	}

	verb := "disable"
	if enabled {
		verb = "enable"
	}
	path := fmt.Sprintf("/api/v1/users/%s/%s", url.PathEscape(username), verb)
	if _, err := t.DoRawRequest(ctx, http.MethodPost, path, nil); err != nil {
		return err
	}

	return nil
}

// BindUserCert binds an mTLS certificate SPKI thumbprint to an xkms user.
func (t *Transport) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s/cert-bindings", url.PathEscape(username))
	body := map[string]any{
		"thumbprint":     thumbprint,
		"not_after_unix": notAfterUnix,
	}
	if _, err := t.DoRawRequest(ctx, http.MethodPost, path, body); err != nil {
		return err
	}

	return nil
}

// ListUserCredentials lists the credentials registered to an xkms user.
func (t *Transport) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s/credentials", url.PathEscape(username))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Credentials []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse response", Err: err}
	}

	resp := &transport.ListUserCredentialsResponse{
		Credentials: make([]transport.CredentialInfo, 0, len(raw.Credentials)),
	}
	for _, c := range raw.Credentials {
		resp.Credentials = append(resp.Credentials, transport.CredentialInfo{
			ID:          c.ID,
			DisplayName: c.Name,
		})
	}

	return resp, nil
}
