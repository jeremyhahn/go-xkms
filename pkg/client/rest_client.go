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

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// restClient implements the Client interface using HTTP/REST.
type restClient struct {
	config     *Config
	httpClient *http.Client
	baseURL    string
	connected  bool
}

// newRESTClient creates a new REST client.
func newRESTClient(cfg *Config) (*restClient, error) {
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

	return &restClient{
		config:  cfg,
		baseURL: baseURL,
	}, nil
}

// Connect establishes a connection to the keychain server via REST.
func (c *restClient) Connect(ctx context.Context) error {
	// Create TLS config if needed
	var tlsConfig *tls.Config
	if c.config.TLSEnabled {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: c.config.TLSInsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}

		// Load CA certificate if specified
		if c.config.TLSCAFile != "" {
			caCert, err := os.ReadFile(c.config.TLSCAFile)
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
		if c.config.TLSCertFile != "" && c.config.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(c.config.TLSCertFile, c.config.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	c.httpClient = &http.Client{
		Transport: transport,
	}

	// Test connection with health check
	_, err := c.Health(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	c.connected = true
	return nil
}

// Close closes the REST client.
func (c *restClient) Close() error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	c.connected = false
	return nil
}

// doRequest performs an HTTP request to the REST server.
func (c *restClient) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	if c.httpClient == nil {
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

	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add API key if configured
	if c.config.APIKey != "" {
		req.Header.Set("X-API-Key", c.config.APIKey)
	}

	// Add JWT token if configured
	if c.config.JWTToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.JWTToken)
	}

	// Add custom headers
	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
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

// Health checks the health of the server.
func (c *restClient) Health(ctx context.Context) (*HealthResponse, error) {
	data, err := c.doRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}

	var resp HealthResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListBackends returns a list of available backends.
func (c *restClient) ListBackends(ctx context.Context) (*ListBackendsResponse, error) {
	data, err := c.doRequest(ctx, http.MethodGet, "/api/v1/backends", nil)
	if err != nil {
		return nil, err
	}

	var resp ListBackendsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetBackend returns information about a specific backend.
func (c *restClient) GetBackend(ctx context.Context, backendID string) (*BackendInfo, error) {
	path := fmt.Sprintf("/api/v1/backends/%s", url.PathEscape(backendID))
	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp BackendInfo
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GenerateKey generates a new key.
func (c *restClient) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	data, err := c.doRequest(ctx, http.MethodPost, "/api/v1/keys", req)
	if err != nil {
		return nil, err
	}

	var resp GenerateKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListKeys returns a list of keys in the specified backend.
func (c *restClient) ListKeys(ctx context.Context, backend string) (*ListKeysResponse, error) {
	path := fmt.Sprintf("/api/v1/keys?backend=%s", url.QueryEscape(backend))
	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp ListKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetKey returns information about a specific key.
func (c *restClient) GetKey(ctx context.Context, backend, keyID string) (*GetKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp GetKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DeleteKey deletes a key.
func (c *restClient) DeleteKey(ctx context.Context, backend, keyID string) (*DeleteKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	data, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp DeleteKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Sign signs data with the specified key.
func (c *restClient) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/sign?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"data": req.Data,
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}

	data, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp SignResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Verify verifies a signature.
func (c *restClient) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/verify?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"data":      req.Data,
		"signature": req.Signature,
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}

	data, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp VerifyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Encrypt encrypts data with the specified key.
func (c *restClient) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/encrypt?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"plaintext": req.Plaintext,
	}
	if len(req.AdditionalData) > 0 {
		body["additional_data"] = req.AdditionalData
	}

	data, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp EncryptResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Decrypt decrypts data with the specified key.
func (c *restClient) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
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

	data, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp DecryptResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (c *restClient) EncryptAsym(ctx context.Context, req *EncryptAsymRequest) (*EncryptAsymResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/encrypt-asym?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"plaintext": req.Plaintext,
	}
	if req.Hash != "" {
		body["hash"] = req.Hash
	}

	data, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp EncryptAsymResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetCertificate returns the certificate for a key.
func (c *restClient) GetCertificate(ctx context.Context, backend, keyID string) (*GetCertificateResponse, error) {
	path := fmt.Sprintf("/api/v1/certs/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp GetCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// SaveCertificate saves a certificate for a key.
func (c *restClient) SaveCertificate(ctx context.Context, req *SaveCertificateRequest) error {
	path := fmt.Sprintf("/api/v1/certs?key_id=%s&backend=%s", url.QueryEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"certificate_pem": req.CertificatePEM,
	}

	_, err := c.doRequest(ctx, http.MethodPost, path, body)
	return err
}

// DeleteCertificate deletes a certificate.
func (c *restClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	path := fmt.Sprintf("/api/v1/certs/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))
	_, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// ImportKey imports a key.
func (c *restClient) ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error) {
	data, err := c.doRequest(ctx, http.MethodPost, "/api/v1/keys/import", req)
	if err != nil {
		return nil, err
	}

	var resp ImportKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ExportKey exports a key.
func (c *restClient) ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/export?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))
	body := map[string]interface{}{
		"algorithm": req.Algorithm,
	}

	data, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var resp ExportKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// RotateKey rotates a key.
func (c *restClient) RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/rotate?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var resp RotateKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListKeyVersions lists all versions of a key.
func (c *restClient) ListKeyVersions(ctx context.Context, req *ListKeyVersionsRequest) (*ListKeyVersionsResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp ListKeyVersionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// EnableKeyVersion enables a specific version of a key.
func (c *restClient) EnableKeyVersion(ctx context.Context, req *EnableKeyVersionRequest) (*EnableKeyVersionResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/%d/enable?backend=%s", url.PathEscape(req.KeyID), req.Version, url.QueryEscape(req.Backend))

	data, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp EnableKeyVersionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DisableKeyVersion disables a specific version of a key.
func (c *restClient) DisableKeyVersion(ctx context.Context, req *DisableKeyVersionRequest) (*DisableKeyVersionResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/%d/disable?backend=%s", url.PathEscape(req.KeyID), req.Version, url.QueryEscape(req.Backend))

	data, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp DisableKeyVersionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// EnableAllKeyVersions enables all versions of a key.
func (c *restClient) EnableAllKeyVersions(ctx context.Context, req *EnableAllKeyVersionsRequest) (*EnableAllKeyVersionsResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/enable-all?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp EnableAllKeyVersionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// DisableAllKeyVersions disables all versions of a key.
func (c *restClient) DisableAllKeyVersions(ctx context.Context, req *DisableAllKeyVersionsRequest) (*DisableAllKeyVersionsResponse, error) {
	path := fmt.Sprintf("/api/v1/keys/%s/versions/disable-all?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	data, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp DisableAllKeyVersionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (c *restClient) GetImportParameters(ctx context.Context, req *GetImportParametersRequest) (*GetImportParametersResponse, error) {
	data, err := c.doRequest(ctx, http.MethodPost, "/api/v1/keys/import-params", req)
	if err != nil {
		return nil, err
	}

	var resp GetImportParametersResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// WrapKey wraps key material for secure transport.
func (c *restClient) WrapKey(ctx context.Context, req *WrapKeyRequest) (*WrapKeyResponse, error) {
	data, err := c.doRequest(ctx, http.MethodPost, "/api/v1/keys/wrap", req)
	if err != nil {
		return nil, err
	}

	var resp WrapKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// UnwrapKey unwraps key material.
func (c *restClient) UnwrapKey(ctx context.Context, req *UnwrapKeyRequest) (*UnwrapKeyResponse, error) {
	data, err := c.doRequest(ctx, http.MethodPost, "/api/v1/keys/unwrap", req)
	if err != nil {
		return nil, err
	}

	var resp UnwrapKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// CopyKey copies a key from one backend to another.
func (c *restClient) CopyKey(ctx context.Context, req *CopyKeyRequest) (*CopyKeyResponse, error) {
	data, err := c.doRequest(ctx, http.MethodPost, "/api/v1/keys/copy", req)
	if err != nil {
		return nil, err
	}

	var resp CopyKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListCertificates lists all certificates in the specified backend.
func (c *restClient) ListCertificates(ctx context.Context, backend string) (*ListCertificatesResponse, error) {
	path := fmt.Sprintf("/api/v1/certs?backend=%s", url.QueryEscape(backend))

	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp ListCertificatesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (c *restClient) SaveCertificateChain(ctx context.Context, req *SaveCertificateChainRequest) error {
	path := fmt.Sprintf("/api/v1/certs/%s/chain?backend=%s", url.PathEscape(req.KeyID), url.QueryEscape(req.Backend))

	_, err := c.doRequest(ctx, http.MethodPost, path, req)
	return err
}

// GetCertificateChain returns the certificate chain for a key.
func (c *restClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*GetCertificateChainResponse, error) {
	path := fmt.Sprintf("/api/v1/certs/%s/chain?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))

	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp GetCertificateChainResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (c *restClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*GetTLSCertificateResponse, error) {
	path := fmt.Sprintf("/api/v1/tls/%s?backend=%s", url.PathEscape(keyID), url.QueryEscape(backend))

	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp GetTLSCertificateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}
