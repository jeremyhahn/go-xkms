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

// Package quic provides an HTTP/3 over QUIC transport implementation for the
// xkms SDK. It communicates with the same REST API endpoints as the REST
// transport but uses the QUIC protocol for transport, providing reduced
// latency through 0-RTT connection establishment and multiplexed streams.
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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
	"github.com/quic-go/quic-go/http3"
)

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = errors.New("connection failed")
	// ErrNotImplemented is returned when an operation has not been implemented yet.
	ErrNotImplemented = errors.New("not implemented")
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

// Connect establishes a connection to the xkms server via QUIC.
func (t *Transport) Connect(ctx context.Context) error {
	// Create TLS config (QUIC always uses TLS)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, // QUIC requires TLS 1.3
		NextProtos: []string{"h3"},
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

// doRawRequest is an unexported alias for DoRawRequest used by service methods.
func (t *Transport) doRawRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	return t.DoRawRequest(ctx, method, path, body)
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
	data, err := t.doRawRequest(ctx, http.MethodGet, "/health", nil)
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
func (t *Transport) ListBackends(ctx context.Context, opts ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	path := transport.AppendPaginationQuery("/api/v1/backends", transport.BuildPageRequest(opts...), false)
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys", req)
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
func (t *Transport) ListKeys(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListKeysResponse, error) {
	path := fmt.Sprintf("/api/v1/keys?backend=%s", url.QueryEscape(backend))
	path = transport.AppendPaginationQuery(path, transport.BuildPageRequest(opts...), true)
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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
	data, err := t.doRawRequest(ctx, http.MethodDelete, path, nil)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, body)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, body)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, body)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, body)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, body)
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
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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

	_, err := t.doRawRequest(ctx, http.MethodPost, path, body)
	return err
}

// DeleteCertificate deletes a certificate.
func (t *Transport) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	path := fmt.Sprintf("/api/v1/certs/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	_, err := t.doRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// CertificateExists checks if a certificate exists for a key.
func (t *Transport) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	path := fmt.Sprintf("/api/v1/certs/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	return t.DoHeadRequest(ctx, path)
}

// ImportKey imports a key.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/import", req)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, body)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.RotateKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/import-params", req)
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
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/wrap", req)
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
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/unwrap", req)
	if err != nil {
		return nil, err
	}

	var resp transport.UnwrapKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// WrapKeyByID wraps a key using another key, both identified by their IDs.
func (t *Transport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/wrap-by-id", req)
	if err != nil {
		return nil, err
	}

	var resp transport.WrapKeyByIDResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (t *Transport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/unwrap-by-id", req)
	if err != nil {
		return nil, err
	}

	var resp transport.UnwrapKeyByIDResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ExportKeyMaterial exports raw symmetric key material.
func (t *Transport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/export-material?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := t.doRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ExportKeyMaterialResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp transport.DeriveKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a key using a KDF.
func (t *Transport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/derive-ecdh", req)
	if err != nil {
		return nil, err
	}

	var resp transport.DeriveKeyECDHResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// CopyKey copies a key from one backend to another.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/keys/copy", req)
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
func (t *Transport) ListCertificates(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	path := fmt.Sprintf("/api/v1/certs?backend=%s", url.QueryEscape(backend))
	path = transport.AppendPaginationQuery(path, transport.BuildPageRequest(opts...), true)

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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

	_, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// GetCertificateChain returns the certificate chain for a key.
func (t *Transport) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	path := fmt.Sprintf("/api/v1/certs/%s/chain?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/seal", req)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/unseal", req)
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
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.CanSealResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// AttestKey requests key attestation from a backend.
func (t *Transport) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/attest", body)
	if err != nil {
		return nil, err
	}

	var resp transport.AttestKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListUsers returns a list of all users.
// Note: This is a stub implementation that returns ErrNotSupported.
// User management will be implemented in a future version.
func (t *Transport) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
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

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCABundleResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCACertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/ca/sign-csr", body)
	if err != nil {
		return nil, err
	}

	var resp transport.SignCSRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/ca/issue", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/ca/revoke", body)
	if err != nil {
		return nil, err
	}

	var resp transport.RevokeCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/ca/crl", body)
	if err != nil {
		return nil, err
	}

	var resp transport.GenerateCRLResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// IsRevoked checks if a certificate is revoked.
func (t *Transport) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	path := fmt.Sprintf("/api/v1/ca/revoked/%s", url.PathEscape(req.SerialNumber))
	if req.TenantID != "" {
		path += "?tenant_id=" + url.QueryEscape(req.TenantID)
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.IsRevokedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// TCG CA Operations

// IssueEKCertificate issues an Endorsement Key certificate.
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/issue-ek-cert", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueEKCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// IssueAKCertificate issues an Attestation Key certificate.
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/issue-ak-cert", body)
	if err != nil {
		return nil, err
	}

	var resp transport.IssueAKCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/sign-tcg-csr", body)
	if err != nil {
		return nil, err
	}

	var resp transport.SignTCGCSRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// EnrollDevice performs complete TCG device enrollment.
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

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tcg-ca/enroll-device", body)
	if err != nil {
		return nil, err
	}

	var resp transport.EnrollDeviceResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// PIV Operations

// ListPIVSlots returns the list of PIV slots and their status.
func (t *Transport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots?backend=%s", url.QueryEscape(req.Backend))
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListPIVSlotsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetPIVCertificate retrieves the certificate stored in a specific PIV slot.
func (t *Transport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots/%s/certificate?backend=%s&format=%s",
		url.PathEscape(req.Slot), url.QueryEscape(req.Backend), url.QueryEscape(req.Format))
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetPIVCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// StorePIVCertificate stores a certificate into a specific PIV slot.
func (t *Transport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots/%s/certificate", url.PathEscape(req.Slot))
	_, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// DeletePIVCertificate removes the certificate from a specific PIV slot.
func (t *Transport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots/%s/certificate?backend=%s",
		url.PathEscape(req.Slot), url.QueryEscape(req.Backend))
	_, err := t.doRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// GeneratePIVKey generates a new key pair in a specific PIV slot.
func (t *Transport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots/%s/generate", url.PathEscape(req.Slot))
	data, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.GeneratePIVKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ImportPIVCertificate imports an externally issued certificate into a PIV slot.
func (t *Transport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots/%s/import", url.PathEscape(req.Slot))
	_, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// ExportPIVCertificate exports the certificate from a PIV slot.
func (t *Transport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots/%s/export?backend=%s&format=%s",
		url.PathEscape(req.Slot), url.QueryEscape(req.Backend), url.QueryEscape(req.Format))
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetPIVCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GeneratePIVCSR generates a Certificate Signing Request for a key in a PIV slot.
func (t *Transport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/v1/piv/slots/%s/csr", url.PathEscape(req.Slot))
	data, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.GeneratePIVCSRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Barrier Operations

// BarrierInitialize initializes the barrier by generating a root key and sealing it.
func (t *Transport) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/initialize", req)
	return err
}

// BarrierUnseal unseals the barrier by loading and decrypting the root key.
func (t *Transport) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/unseal", req)
	return err
}

// BarrierSeal transitions the barrier to sealed state, zeroing the DEK.
func (t *Transport) BarrierSeal(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/seal", nil)
	return err
}

// BarrierStatus returns the current barrier status including seal state and active strategy.
func (t *Transport) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, "/v1/barrier/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.BarrierStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// BarrierInitializeShamir initializes the barrier using Shamir secret sharing.
func (t *Transport) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/initialize-shamir", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierInitializeShamirResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}

// BarrierUnsealWithShare submits a single Shamir share toward the quorum.
func (t *Transport) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/unseal-share", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierUnsealShareResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}

// BarrierUnsealWithShares submits all Shamir shares at once for batch unsealing.
func (t *Transport) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/unseal-shares", req)
	return err
}

// BarrierShamirListShares returns metadata about stored Shamir shares.
func (t *Transport) BarrierShamirListShares(ctx context.Context) (*transport.BarrierShamirSharesResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodGet, "/v1/barrier/shamir/shares", nil)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierShamirSharesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (t *Transport) BarrierShamirDeleteShare(ctx context.Context, req *transport.BarrierShamirDeleteShareRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodDelete, fmt.Sprintf("/v1/barrier/shamir/shares/%d", req.Index), nil)
	return err
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (t *Transport) BarrierShamirDeleteAllShares(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodDelete, "/v1/barrier/shamir/shares", nil)
	return err
}

// BarrierShamirVerify verifies the integrity of stored Shamir shares.
func (t *Transport) BarrierShamirVerify(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/shamir/verify", nil)
	return err
}

// BarrierRekey rotates Shamir shares while keeping the same root key.
func (t *Transport) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/rekey", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierRekeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys for disaster recovery.
func (t *Transport) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/recovery-keys/generate", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierRecoveryKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}

// BarrierRecoverWithKeys unseals the barrier using recovery keys.
func (t *Transport) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/recovery-keys/recover", req)
	return err
}

// BarrierDeleteRecoveryKeys deletes stored recovery key metadata.
func (t *Transport) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodDelete, "/v1/barrier/recovery-keys", nil)
	return err
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (t *Transport) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodGet, "/v1/barrier/recovery-keys", nil)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierHasRecoveryKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}

// BarrierGenerateRootToken generates a one-time root token by proving
// knowledge of the master key through Shamir share reconstruction.
func (t *Transport) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, "/v1/barrier/root-token", req)
	if err != nil {
		return nil, err
	}
	var resp transport.BarrierRootTokenResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}

// PIN Operations

// SetSOPIN sets the Security Officer PIN.
func (t *Transport) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/pin/so-pin", req)
	return err
}

// SetUserPIN sets the user PIN. Requires SO PIN authorization.
func (t *Transport) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/pin/user-pin", req)
	return err
}

// ChangeSOPIN changes the Security Officer PIN.
func (t *Transport) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/pin/so-pin/change", req)
	return err
}

// ChangeUserPIN changes the user PIN.
func (t *Transport) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/pin/user-pin/change", req)
	return err
}

// VerifySOPIN verifies the Security Officer PIN.
func (t *Transport) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/pin/so-pin/verify", req)
	return err
}

// VerifyUserPIN verifies the user PIN.
func (t *Transport) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/pin/user-pin/verify", req)
	return err
}

// GetLockoutStatus returns the current PIN lockout status.
func (t *Transport) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, "/v1/pin/lockout", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.LockoutStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ResetLockout resets the PIN lockout counter using SO PIN authorization.
func (t *Transport) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	_, err := t.doRawRequest(ctx, http.MethodPost, "/v1/pin/lockout/reset", req)
	return err
}

// Password Store Operations

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/passwords", req)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordAddResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/passwords/%s", url.PathEscape(req.ID))
	params := url.Values{}
	if req.Decrypt {
		params.Set("decrypt", "true")
	}
	if req.UserPIN != "" {
		params.Set("user_pin", req.UserPIN)
	}
	if req.TenantID != "" {
		params.Set("tenant_id", req.TenantID)
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordGetResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	path := "/api/v1/passwords"
	params := url.Values{}
	if req != nil {
		if req.FolderPath != "" {
			params.Set("folder_path", req.FolderPath)
		}
		if req.TenantID != "" {
			params.Set("tenant_id", req.TenantID)
		}
		if req.Scope != "" {
			params.Set("scope", req.Scope)
		}
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/passwords/%s", url.PathEscape(req.ID))
	_, err := t.doRawRequest(ctx, http.MethodPut, path, req)
	return err
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	path := fmt.Sprintf("/api/v1/passwords/%s", url.PathEscape(req.ID))
	if req.TenantID != "" {
		path += "?tenant_id=" + url.QueryEscape(req.TenantID)
	}
	_, err := t.doRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/passwords/unlock", req)
	return err
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/passwords/lock", nil)
	return err
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/passwords/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordStoreStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}

	_, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/passwords/access-mode", req)
	return err
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/passwords/generate", req)
	if err != nil {
		return nil, err
	}

	var resp transport.PasswordGenerateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Platform Store Operations

// SealStorePut stores a secret in the platform store.
func (t *Transport) SealStorePut(_ context.Context, _ *transport.SealStorePutRequest) error {
	return ErrNotSupported
}

// SealStoreGet retrieves a secret from the platform store.
func (t *Transport) SealStoreGet(_ context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, ErrNotSupported
}

// SealStoreDelete deletes a secret from the platform store.
func (t *Transport) SealStoreDelete(_ context.Context, _ *transport.SealStoreDeleteRequest) error {
	return ErrNotSupported
}

// SealStoreList lists all stored secret names.
func (t *Transport) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return nil, ErrNotSupported
}

// SealStoreReseal reseals a secret with the current sealing key.
func (t *Transport) SealStoreReseal(_ context.Context, _ *transport.SealStoreResealRequest) error {
	return ErrNotSupported
}

// SealStoreStatus returns the platform store status.
func (t *Transport) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, ErrNotSupported
}

// Policy Operations

// PolicyCreate creates a new PCR policy.
func (t *Transport) PolicyCreate(_ context.Context, _ *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, ErrNotSupported
}

// PolicyGet retrieves a policy by name.
func (t *Transport) PolicyGet(_ context.Context, _ *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, ErrNotSupported
}

// PolicyList lists all policies.
func (t *Transport) PolicyList(_ context.Context) (*transport.PolicyListResponse, error) {
	return nil, ErrNotSupported
}

// PolicyDelete deletes a policy.
func (t *Transport) PolicyDelete(_ context.Context, _ *transport.PolicyDeleteRequest) error {
	return ErrNotSupported
}

// PolicyRefresh refreshes a policy with current PCR values.
func (t *Transport) PolicyRefresh(_ context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, ErrNotSupported
}

// PolicyVerify verifies a policy against current PCR values.
func (t *Transport) PolicyVerify(_ context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, ErrNotSupported
}

// PolicyExport exports a policy.
func (t *Transport) PolicyExport(_ context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, ErrNotSupported
}

// CustodianGroupService methods.

// CreateCustodianGroup creates a new custodian group.
func (t *Transport) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/custodian/groups", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CreateCustodianGroupResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetCustodianGroup retrieves a custodian group by ID.
func (t *Transport) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s", url.PathEscape(groupID))
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetCustodianGroupResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListCustodianGroups returns all custodian groups.
func (t *Transport) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/custodian/groups", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListCustodianGroupsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DeleteCustodianGroup deletes a custodian group by ID.
func (t *Transport) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	_, err := t.doRawRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/custodian/groups/%s", url.PathEscape(groupID)), nil)
	return err
}

// AddCustodianMember adds a member to a custodian group.
func (t *Transport) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s/members", url.PathEscape(req.GroupID))
	data, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp transport.AddCustodianMemberResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (t *Transport) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s/members/%s", url.PathEscape(req.GroupID), url.PathEscape(req.UserID))
	_, err := t.doRawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// DistributeShares triggers share distribution for a custodian group.
func (t *Transport) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	path := fmt.Sprintf("/api/v1/custodian/groups/%s/distribute", url.PathEscape(req.GroupID))
	data, err := t.doRawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.DistributeSharesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ShareService methods.

// SubmitShare submits a Shamir share for storage.
func (t *Transport) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/shares/submit", req)
	if err != nil {
		return nil, err
	}

	var resp transport.SubmitShareResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListShares returns all stored shares.
func (t *Transport) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/shares", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListSharesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetShareCollectionStatus returns the share collection status for a group.
func (t *Transport) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	path := fmt.Sprintf("/api/v1/shares/status/%s", url.PathEscape(groupID))
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ShareCollectionStatus
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// TenantService methods.

// CreateTenant creates a new tenant.
func (t *Transport) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/tenants", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CreateTenantResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetTenant retrieves a tenant by ID.
func (t *Transport) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s", url.PathEscape(tenantID))
	data, err := t.doRawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp transport.GetTenantResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListTenants returns all tenants.
func (t *Transport) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/tenants", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.ListTenantsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DeleteTenant deletes a tenant by ID.
func (t *Transport) DeleteTenant(ctx context.Context, tenantID string) error {
	_, err := t.doRawRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/tenants/%s", url.PathEscape(tenantID)), nil)
	return err
}

// TenantBarrierInit initializes the barrier for a tenant.
func (t *Transport) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	path := fmt.Sprintf("/api/v1/tenants/%s/barrier/init", url.PathEscape(req.TenantID))
	_, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// TenantBarrierUnseal unseals the barrier for a tenant.
func (t *Transport) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	path := fmt.Sprintf("/api/v1/tenants/%s/barrier/unseal", url.PathEscape(req.TenantID))
	_, err := t.doRawRequest(ctx, http.MethodPost, path, req)
	return err
}

// Init Ceremony methods.

// GetInitStatus returns the current init ceremony state.
func (t *Transport) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/init/status", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.InitStatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (t *Transport) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-cert/begin", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimCertBeginResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ClaimCertComplete completes the certificate claim by verifying the officer's
// signature over the challenge nonce.
func (t *Transport) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-cert/complete", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimCertCompleteResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ClaimShare retrieves the Shamir share for the named officer.
func (t *Transport) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/claim-share", req)
	if err != nil {
		return nil, err
	}

	var resp transport.ClaimShareResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// SignCSRInit signs a CSR during initialization with SO authorization.
func (t *Transport) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/init/sign-csr", req)
	if err != nil {
		return nil, err
	}

	var resp transport.SignCSRInitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Credential Management methods.

// SubmitCredential submits a credential for manual mode.
func (t *Transport) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodPost, "/api/v1/credentials/submit", req)
	if err != nil {
		return nil, err
	}

	var resp transport.CredentialSubmitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetCredentialStrategy returns the configured credential strategy.
func (t *Transport) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}

	data, err := t.doRawRequest(ctx, http.MethodGet, "/api/v1/credentials/strategy", nil)
	if err != nil {
		return nil, err
	}

	var resp transport.CredentialStrategyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Compile-time assertion that Transport implements transport.Client.
var _ transport.Client = (*Transport)(nil)
