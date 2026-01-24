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

// Package quic provides a QUIC/HTTP3 transport implementation for the keychain SDK.
package quic

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
	"github.com/quic-go/quic-go/http3"
)

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = errors.New("connection failed")
)

// Transport implements the transport.Client interface using HTTP/3 over QUIC.
type Transport struct {
	config     *transport.Config
	httpClient *http.Client
	baseURL    string
	connected  bool
}

// New creates a new QUIC transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return NewWithConfig(cfg)
}

// NewWithConfig creates a new QUIC transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	// Build the base URL
	baseURL := cfg.Address
	if !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	// Remove trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Transport{
		config:  cfg,
		baseURL: baseURL,
	}, nil
}

// Connect establishes a connection to the keychain server via QUIC.
func (t *Transport) Connect(ctx context.Context) error {
	// Create TLS config (QUIC always uses TLS)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: t.config.TLSInsecureSkipVerify,
		MinVersion:         tls.VersionTLS13, // QUIC requires TLS 1.3
		NextProtos:         []string{"h3"},
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

	// Create HTTP/3 transport
	h3Transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
	}

	t.httpClient = &http.Client{
		Transport: h3Transport,
	}

	// Test connection with health check
	_, err := t.Health(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	t.connected = true
	return nil
}

// Close closes the QUIC client.
func (t *Transport) Close() error {
	if t.httpClient != nil {
		if h3Transport, ok := t.httpClient.Transport.(*http3.Transport); ok {
			if err := h3Transport.Close(); err != nil {
				return err
			}
		}
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

// BaseURL returns the base URL for the QUIC API.
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

// Request performs an HTTP/3 request to the QUIC server.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	if t.httpClient == nil {
		return ErrNotConnected
	}

	return t.DoRequest(ctx, http.MethodPost, method, req, resp)
}

// RequestStream opens a bidirectional stream (not fully supported for HTTP/3).
func (t *Transport) RequestStream(ctx context.Context, method string, req interface{}) (transport.Stream, error) {
	return nil, transport.ErrStreamNotSupported
}

// DoRequest performs an HTTP/3 request and unmarshals the response.
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

// DoRawRequest performs an HTTP/3 request and returns the raw response body.
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
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) ListUsers(_ context.Context) (*transport.ListUsersResponse, error) {
	return nil, ErrNotSupported
}

// GetUser returns information about a specific user.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, ErrNotSupported
}

// DeleteUser deletes a user.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) DeleteUser(_ context.Context, _ string) error {
	return ErrNotSupported
}

// EnableUser enables a user account.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) EnableUser(_ context.Context, _ string) error {
	return ErrNotSupported
}

// DisableUser disables a user account.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) DisableUser(_ context.Context, _ string) error {
	return ErrNotSupported
}

// ListUserCredentials returns a list of credentials for a user.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, ErrNotSupported
}

// BeginRegistration begins a WebAuthn registration flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) BeginRegistration(_ context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, ErrNotSupported
}

// FinishRegistration completes a WebAuthn registration flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) FinishRegistration(_ context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, ErrNotSupported
}

// BeginAuthentication begins a WebAuthn authentication flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) BeginAuthentication(_ context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, ErrNotSupported
}

// FinishAuthentication completes a WebAuthn authentication flow.
// Note: This is a stub implementation that returns ErrNotSupported.
// Authentication flow will be implemented in a future version.
func (t *Transport) FinishAuthentication(_ context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, ErrNotSupported
}
