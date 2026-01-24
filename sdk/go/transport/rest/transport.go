// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package rest provides a REST/HTTP transport implementation for the keychain SDK.
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
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jeremyhahn/go-keychain/sdk/go/transport"
)

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = errors.New("connection failed")
)

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

// Connect establishes a connection to the keychain server via REST.
func (t *Transport) Connect(ctx context.Context) error {
	// Create TLS config if needed
	var tlsConfig *tls.Config
	if t.config.TLSEnabled {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: t.config.TLSInsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}

		// Load CA certificate if specified
		if t.config.TLSCAFile != "" {
			caCert, err := os.ReadFile(t.config.TLSCAFile)
			if err != nil {
				return fmt.Errorf("failed to read CA certificate: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		// Load client certificate if specified (mTLS)
		if t.config.TLSCertFile != "" && t.config.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(t.config.TLSCertFile, t.config.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
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
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
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

// RequestStream opens a bidirectional stream (not supported for REST).
func (t *Transport) RequestStream(ctx context.Context, method string, req interface{}) (transport.Stream, error) {
	return nil, transport.ErrStreamNotSupported
}

// DoRequest performs an HTTP request and unmarshals the response.
func (t *Transport) DoRequest(ctx context.Context, httpMethod, path string, body interface{}, result interface{}) error {
	respBody, err := t.DoRawRequest(ctx, httpMethod, path, body)
	if err != nil {
		return err
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// DoRawRequest performs an HTTP request and returns the raw response body.
func (t *Transport) DoRawRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	if t.httpClient == nil {
		return nil, ErrNotConnected
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	reqURL := t.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
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
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("failed to close response body: %v", closeErr)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("server error: %s", errResp.Error)
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return nil, fmt.Errorf("server error: %s", errResp.Message)
		}
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
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
			return nil, nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	reqURL := t.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
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
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("failed to close response body: %v", closeErr)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return nil, resp.Header, fmt.Errorf("server error: %s", errResp.Error)
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return nil, resp.Header, fmt.Errorf("server error: %s", errResp.Message)
		}
		return nil, resp.Header, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
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
		return false, fmt.Errorf("failed to create request: %w", err)
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
		return false, fmt.Errorf("request failed: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListBackends returns a list of available backends.
func (t *Transport) ListBackends(ctx context.Context) (*transport.ListBackendsResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/backends", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListBackendsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListKeys returns a list of keys in the specified backend.
func (t *Transport) ListKeys(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
	path := fmt.Sprintf("/api/v1/keys?backend=%s", url.QueryEscape(backend))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.SignResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.VerifyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.EncryptResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.DecryptResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.EncryptAsymResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/import", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ImportKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListKeyVersions lists all versions of a key.
func (t *Transport) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListKeyVersionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// EnableKeyVersion enables a specific version of a key.
func (t *Transport) EnableKeyVersion(ctx context.Context, req *transport.EnableKeyVersionRequest) (*transport.EnableKeyVersionResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/%d/enable?backend=%s", url.PathEscape(req.KeyID), req.Version, url.QueryEscape(req.Backend))

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.EnableKeyVersionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DisableKeyVersion disables a specific version of a key.
func (t *Transport) DisableKeyVersion(ctx context.Context, req *transport.DisableKeyVersionRequest) (*transport.DisableKeyVersionResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/%d/disable?backend=%s", url.PathEscape(req.KeyID), req.Version, url.QueryEscape(req.Backend))

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.DisableKeyVersionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// EnableAllKeyVersions enables all versions of a key.
func (t *Transport) EnableAllKeyVersions(ctx context.Context, req *transport.EnableAllKeyVersionsRequest) (*transport.EnableAllKeyVersionsResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/enable-all?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.EnableAllKeyVersionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DisableAllKeyVersions disables all versions of a key.
func (t *Transport) DisableAllKeyVersions(ctx context.Context, req *transport.DisableAllKeyVersionsRequest) (*transport.DisableAllKeyVersionsResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/disable-all?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := t.DoRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.DisableAllKeyVersionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/import-params", req)
	if err != nil {
		return nil, err
	}

	var resp transport.GetImportParametersResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// WrapKey wraps key material for secure transport.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/wrap", req)
	if err != nil {
		return nil, err
	}

	var resp transport.WrapKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// UnwrapKey unwraps key material.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	data, err := t.DoRawRequest(ctx, http.MethodPost, "/api/v1/keys/unwrap", req)
	if err != nil {
		return nil, err
	}

	var resp transport.UnwrapKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string) (*transport.ListCertificatesResponse, error) {
	path := fmt.Sprintf("/api/v1/certs?backend=%s", url.QueryEscape(backend))

	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListCertificatesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
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
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListUsers returns a list of all users.
// Requires the server to have user management enabled.
func (t *Transport) ListUsers(ctx context.Context) (*transport.ListUsersResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.DoRawRequest(ctx, http.MethodGet, "/api/v1/users/", nil)
	if err != nil {
		return nil, err
	}

	// The server returns UserListResponse with "users" and "total" fields
	var serverResp struct {
		Users []struct {
			ID              string `json:"id"`
			Username        string `json:"username"`
			DisplayName     string `json:"display_name"`
			Role            string `json:"role"`
			Enabled         bool   `json:"enabled"`
			CredentialCount int    `json:"credential_count"`
			CreatedAt       string `json:"created_at"`
			LastLoginAt     string `json:"last_login_at,omitempty"`
		} `json:"users"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(data, &serverResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Convert to SDK response format
	users := make([]transport.UserInfo, len(serverResp.Users))
	for i, u := range serverResp.Users {
		users[i] = transport.UserInfo{
			Username:    u.Username,
			DisplayName: u.DisplayName,
			Role:        u.Role,
			Enabled:     u.Enabled,
		}
	}

	return &transport.ListUsersResponse{
		Users: users,
	}, nil
}

// GetUser returns information about a specific user.
// The userID parameter should be the base64url-encoded user ID.
// Requires the server to have user management enabled.
func (t *Transport) GetUser(ctx context.Context, userID string) (*transport.GetUserResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(userID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	// The server returns UserDetailResponse
	var serverResp struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		Enabled     bool   `json:"enabled"`
		Credentials []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			CreatedAt  string `json:"created_at"`
			LastUsedAt string `json:"last_used_at,omitempty"`
		} `json:"credentials"`
		CreatedAt   string `json:"created_at"`
		LastLoginAt string `json:"last_login_at,omitempty"`
	}
	if err := json.Unmarshal(data, &serverResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &transport.GetUserResponse{
		User: transport.UserInfo{
			Username:    serverResp.Username,
			DisplayName: serverResp.DisplayName,
			Role:        serverResp.Role,
			Enabled:     serverResp.Enabled,
		},
	}, nil
}

// DeleteUser deletes a user.
// The userID parameter should be the base64url-encoded user ID.
// Requires the server to have user management enabled.
func (t *Transport) DeleteUser(ctx context.Context, userID string) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(userID))
	_, err := t.DoRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// EnableUser enables a user account.
// The userID parameter should be the base64url-encoded user ID.
// Requires the server to have user management enabled.
func (t *Transport) EnableUser(ctx context.Context, userID string) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(userID))
	body := map[string]interface{}{
		"enabled": true,
	}
	_, err := t.DoRawRequest(ctx, http.MethodPut, path, body)
	return err
}

// DisableUser disables a user account.
// The userID parameter should be the base64url-encoded user ID.
// Requires the server to have user management enabled.
func (t *Transport) DisableUser(ctx context.Context, userID string) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(userID))
	body := map[string]interface{}{
		"enabled": false,
	}
	_, err := t.DoRawRequest(ctx, http.MethodPut, path, body)
	return err
}

// ListUserCredentials returns a list of credentials for a user.
// The userID parameter should be the base64url-encoded user ID.
// Requires the server to have user management enabled.
func (t *Transport) ListUserCredentials(ctx context.Context, userID string) (*transport.ListUserCredentialsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	// The user detail endpoint includes credentials
	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(userID))
	data, err := t.DoRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	// Parse credentials from user detail response
	var serverResp struct {
		Credentials []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			CreatedAt  string `json:"created_at"`
			LastUsedAt string `json:"last_used_at,omitempty"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(data, &serverResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	credentials := make([]transport.CredentialInfo, len(serverResp.Credentials))
	for i, cred := range serverResp.Credentials {
		credentials[i] = transport.CredentialInfo{
			ID:          cred.ID,
			DisplayName: cred.Name,
		}
	}

	return &transport.ListUserCredentialsResponse{
		Credentials: credentials,
	}, nil
}

// Authentication Flow Operations - WebAuthn/FIDO2 server-side operations

// BeginRegistration begins a WebAuthn registration flow.
// Requires the server to have WebAuthn enabled.
func (t *Transport) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	// Build the WebAuthn request body
	body := map[string]interface{}{
		"email": req.Username,
	}
	if req.DisplayName != "" {
		body["display_name"] = req.DisplayName
	}

	data, respHeaders, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/registration/begin", body, nil)
	if err != nil {
		return nil, err
	}

	// Parse the WebAuthn PublicKeyCredentialCreationOptions response
	var options struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		RelyingParty struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		PubKeyCredParams []struct {
			Type string `json:"type"`
			Alg  int    `json:"alg"`
		} `json:"pubKeyCredParams"`
	}
	if err := json.Unmarshal(data, &options); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Get session ID from response header (needed for FinishRegistration)
	sessionID := respHeaders.Get("X-Session-Id")
	_ = sessionID // Session ID is returned in headers, client should track it

	// Convert to SDK response format
	credParams := make([]transport.CredentialParam, len(options.PubKeyCredParams))
	for i, param := range options.PubKeyCredParams {
		credParams[i] = transport.CredentialParam{
			Type: param.Type,
			Alg:  param.Alg,
		}
	}

	return &transport.BeginRegistrationResponse{
		Challenge:        options.Challenge,
		UserID:           options.User.ID,
		RPID:             options.RelyingParty.ID,
		RPName:           options.RelyingParty.Name,
		CredentialParams: credParams,
	}, nil
}

// FinishRegistration completes a WebAuthn registration flow.
// Requires the server to have WebAuthn enabled.
func (t *Transport) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	// Build the attestation response body that the WebAuthn server expects
	// This matches the format from navigator.credentials.create()
	body := map[string]interface{}{
		"id":    req.CredentialID,
		"rawId": req.CredentialID,
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    req.ClientDataJSON,
			"attestationObject": req.AttestationData,
		},
	}

	// The session ID should be passed in a header
	reqHeaders := map[string]string{
		"X-Session-Id": req.Username, // Username is used as session lookup key
	}

	data, _, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/registration/finish", body, reqHeaders)
	if err != nil {
		return nil, err
	}

	// Parse the auth response
	var authResp struct {
		Token  string `json:"token"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(data, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &transport.FinishRegistrationResponse{
		Success:      true,
		CredentialID: req.CredentialID,
		Message:      "Registration successful",
	}, nil
}

// BeginAuthentication begins a WebAuthn authentication flow.
// Requires the server to have WebAuthn enabled.
func (t *Transport) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	// Build the request body
	body := map[string]interface{}{}
	if req.Username != "" {
		body["email"] = req.Username
	}

	data, respHeaders, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/login/begin", body, nil)
	if err != nil {
		return nil, err
	}

	// Parse the WebAuthn PublicKeyCredentialRequestOptions response
	var options struct {
		Challenge        string `json:"challenge"`
		RelyingPartyID   string `json:"rpId"`
		AllowCredentials []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"allowCredentials"`
	}
	if err := json.Unmarshal(data, &options); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Get session ID and user ID from response headers
	_ = respHeaders.Get("X-Session-Id")
	_ = respHeaders.Get("X-User-Id")

	// Extract credential IDs
	credentialIDs := make([]string, len(options.AllowCredentials))
	for i, cred := range options.AllowCredentials {
		credentialIDs[i] = cred.ID
	}

	return &transport.BeginAuthenticationResponse{
		Challenge:     options.Challenge,
		RPID:          options.RelyingPartyID,
		CredentialIDs: credentialIDs,
	}, nil
}

// FinishAuthentication completes a WebAuthn authentication flow.
// Requires the server to have WebAuthn enabled.
func (t *Transport) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	// Build the assertion response body that the WebAuthn server expects
	// This matches the format from navigator.credentials.get()
	body := map[string]interface{}{
		"id":    req.CredentialID,
		"rawId": req.CredentialID,
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    req.ClientDataJSON,
			"authenticatorData": req.AuthenticatorData,
			"signature":         req.Signature,
		},
	}

	// The session ID and user ID should be passed in headers
	reqHeaders := map[string]string{
		"X-Session-Id": req.Username, // Username is used as session lookup key
	}

	data, _, err := t.DoRequestWithHeaders(ctx, http.MethodPost, "/api/v1/webauthn/login/finish", body, reqHeaders)
	if err != nil {
		return nil, err
	}

	// Parse the auth response
	var authResp struct {
		Token  string `json:"token"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(data, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &transport.FinishAuthenticationResponse{
		Success: true,
		Token:   authResp.Token,
		Message: "Authentication successful",
	}, nil
}
