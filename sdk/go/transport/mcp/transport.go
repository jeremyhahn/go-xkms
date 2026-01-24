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

// Package mcp provides a JSON-RPC 2.0 over TCP transport implementation for the keychain SDK.
// MCP stands for Model Context Protocol.
package mcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-keychain/sdk/go/transport"
)

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = errors.New("connection failed")
	// ErrBackendNotFound is returned when a backend is not found.
	ErrBackendNotFound = errors.New("backend not found")
)

// JSON-RPC 2.0 error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// Transport implements the transport.Client interface using JSON-RPC 2.0 over TCP.
type Transport struct {
	config    *transport.Config
	conn      net.Conn
	encoder   *json.Encoder
	scanner   *bufio.Scanner
	connected bool
	mu        sync.Mutex
	requestID uint64
}

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      uint64      `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      uint64          `json:"id,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// New creates a new MCP transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return &Transport{
		config: cfg,
	}, nil
}

// NewWithConfig creates a new MCP transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	return &Transport{
		config: cfg,
	}, nil
}

// Connect establishes a connection to the keychain server via MCP (JSON-RPC over TCP).
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var conn net.Conn
	var err error

	if t.config.TLSEnabled {
		tlsConfig := &tls.Config{
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

		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{},
			Config:    tlsConfig,
		}
		conn, err = dialer.DialContext(ctx, "tcp", t.config.Address)
	} else {
		dialer := &net.Dialer{}
		conn, err = dialer.DialContext(ctx, "tcp", t.config.Address)
	}

	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	t.conn = conn
	t.encoder = json.NewEncoder(conn)
	t.scanner = bufio.NewScanner(conn)
	// Set a larger buffer for potentially large responses
	t.scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	// Test connection with health check
	t.connected = true
	if !t.healthyLocked(ctx) {
		t.conn.Close()
		t.connected = false
		return fmt.Errorf("%w: health check failed", ErrConnectionFailed)
	}

	return nil
}

// Close closes the MCP client connection.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.connected = false
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// Healthy checks if the transport can communicate with the server.
func (t *Transport) Healthy(ctx context.Context) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.healthyLocked(ctx)
}

func (t *Transport) healthyLocked(ctx context.Context) bool {
	if !t.connected || t.conn == nil {
		return false
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := t.callLocked(ctx, "health", nil, &result); err != nil {
		return false
	}
	return result.Status == "healthy" || result.Status == "ok"
}

// Conn returns the underlying network connection.
func (t *Transport) Conn() interface{} {
	return t.conn
}

// NetConn returns the network connection for direct access.
func (t *Transport) NetConn() net.Conn {
	return t.conn
}

// IsConnected returns whether the transport is connected.
func (t *Transport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Request performs a JSON-RPC 2.0 call.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.callLocked(ctx, method, req, resp)
}

// RequestStream opens a bidirectional stream (not supported for MCP).
func (t *Transport) RequestStream(ctx context.Context, method string, req interface{}) (transport.Stream, error) {
	return nil, transport.ErrStreamNotSupported
}

// Call performs a thread-safe JSON-RPC call.
func (t *Transport) Call(ctx context.Context, method string, params interface{}, result interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.callLocked(ctx, method, params, result)
}

// callLocked performs a JSON-RPC 2.0 call (must be called with lock held).
func (t *Transport) callLocked(ctx context.Context, method string, params interface{}, result interface{}) error {
	if !t.connected || t.conn == nil {
		return ErrNotConnected
	}

	// Generate unique request ID
	reqID := atomic.AddUint64(&t.requestID, 1)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      reqID,
	}

	// Send request
	if err := t.encoder.Encode(req); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read response (line-delimited JSON)
	if !t.scanner.Scan() {
		if err := t.scanner.Err(); err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}
		return errors.New("connection closed")
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(t.scanner.Bytes(), &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for JSON-RPC error
	if resp.Error != nil {
		return resp.Error
	}

	// Unmarshal result if provided
	if result != nil && resp.Result != nil {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("failed to parse result: %w", err)
		}
	}

	return nil
}

// doCall performs a thread-safe JSON-RPC call.
func (t *Transport) doCall(ctx context.Context, method string, params interface{}, result interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.callLocked(ctx, method, params, result)
}

// Health checks the health of the server.
func (t *Transport) Health(ctx context.Context) (*transport.HealthResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var result struct {
		Status string `json:"status"`
	}
	if err := t.callLocked(ctx, "health", nil, &result); err != nil {
		return nil, err
	}
	return &transport.HealthResponse{
		Status:  result.Status,
		Version: "1.0.0", // MCP doesn't return version in health check
	}, nil
}

// ListBackends returns a list of available backends.
func (t *Transport) ListBackends(ctx context.Context) (*transport.ListBackendsResponse, error) {
	var result struct {
		Backends []string `json:"backends"`
	}
	if err := t.doCall(ctx, "keychain.listBackends", nil, &result); err != nil {
		return nil, err
	}

	backends := make([]transport.BackendInfo, len(result.Backends))
	for i, b := range result.Backends {
		backends[i] = transport.BackendInfo{
			ID:   b,
			Type: b,
		}
	}
	return &transport.ListBackendsResponse{Backends: backends}, nil
}

// GetBackend returns information about a specific backend.
func (t *Transport) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	// MCP doesn't have a specific getBackend endpoint, use listBackends
	resp, err := t.ListBackends(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range resp.Backends {
		if b.ID == backendID {
			return &b, nil
		}
	}
	return nil, ErrBackendNotFound
}

// GenerateKey generates a new key.
func (t *Transport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	params := map[string]interface{}{
		"key_id":   req.KeyID,
		"backend":  req.Backend,
		"key_type": req.KeyType,
	}
	if req.KeySize > 0 {
		params["key_size"] = req.KeySize
	}
	if req.Curve != "" {
		params["curve"] = req.Curve
	}
	if req.Algorithm != "" {
		params["algorithm"] = req.Algorithm
	}
	if req.Exportable {
		params["exportable"] = req.Exportable
	}

	var result struct {
		KeyID        string `json:"key_id"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := t.doCall(ctx, "keychain.generateKey", params, &result); err != nil {
		return nil, err
	}

	return &transport.GenerateKeyResponse{
		KeyID:        result.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: result.PublicKeyPEM,
	}, nil
}

// ListKeys returns a list of keys in the specified backend.
func (t *Transport) ListKeys(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
	params := map[string]interface{}{
		"backend": backend,
	}

	var result struct {
		Keys []struct {
			CN string `json:"cn"`
		} `json:"keys"`
	}
	if err := t.doCall(ctx, "keychain.listKeys", params, &result); err != nil {
		return nil, err
	}

	keys := make([]transport.KeyInfo, len(result.Keys))
	for i, k := range result.Keys {
		keys[i] = transport.KeyInfo{
			KeyID:   k.CN,
			Backend: backend,
		}
	}
	return &transport.ListKeysResponse{Keys: keys}, nil
}

// GetKey returns information about a specific key.
func (t *Transport) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	params := map[string]interface{}{
		"backend": backend,
		"key_id":  keyID,
	}

	var result struct {
		KeyID        string `json:"key_id"`
		PublicKeyPEM string `json:"public_key_pem"`
		Backend      string `json:"backend"`
	}
	if err := t.doCall(ctx, "keychain.getKey", params, &result); err != nil {
		return nil, err
	}

	return &transport.GetKeyResponse{
		KeyInfo: transport.KeyInfo{
			KeyID:        result.KeyID,
			Backend:      result.Backend,
			PublicKeyPEM: result.PublicKeyPEM,
		},
	}, nil
}

// DeleteKey deletes a key.
func (t *Transport) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	params := map[string]interface{}{
		"backend": backend,
		"key_id":  keyID,
	}

	if err := t.doCall(ctx, "keychain.deleteKey", params, nil); err != nil {
		return nil, err
	}

	return &transport.DeleteKeyResponse{Success: true}, nil
}

// Sign signs data with the specified key.
func (t *Transport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	params := map[string]interface{}{
		"backend": req.Backend,
		"key_id":  req.KeyID,
		"data":    req.Data,
		"hash":    req.Hash,
	}

	var result struct {
		Signature interface{} `json:"signature"`
	}
	if err := t.doCall(ctx, "keychain.sign", params, &result); err != nil {
		return nil, err
	}

	// Handle signature which may be base64 string or byte array
	var sig []byte
	switch v := result.Signature.(type) {
	case string:
		// JSON encodes []byte as base64, so decode it
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			// Not valid base64, treat as raw string (unlikely but handle gracefully)
			sig = []byte(v)
		} else {
			sig = decoded
		}
	case []byte:
		sig = v
	case []interface{}:
		sig = make([]byte, len(v))
		for i, b := range v {
			if n, ok := b.(float64); ok {
				sig[i] = byte(n)
			}
		}
	}

	return &transport.SignResponse{Signature: sig}, nil
}

// Verify verifies a signature.
func (t *Transport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	params := map[string]interface{}{
		"backend":   req.Backend,
		"key_id":    req.KeyID,
		"data":      req.Data,
		"signature": req.Signature,
		"hash":      req.Hash,
	}

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := t.doCall(ctx, "keychain.verify", params, &result); err != nil {
		return nil, err
	}

	return &transport.VerifyResponse{Valid: result.Valid}, nil
}

// Encrypt encrypts data with the specified key.
func (t *Transport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	params := map[string]interface{}{
		"backend":   req.Backend,
		"key_id":    req.KeyID,
		"plaintext": req.Plaintext,
	}
	if len(req.AdditionalData) > 0 {
		params["additional_data"] = req.AdditionalData
	}

	var result struct {
		Ciphertext []byte `json:"ciphertext"`
		Nonce      []byte `json:"nonce"`
		Tag        []byte `json:"tag"`
	}
	if err := t.doCall(ctx, "keychain.encrypt", params, &result); err != nil {
		return nil, err
	}

	return &transport.EncryptResponse{
		Ciphertext: result.Ciphertext,
		Nonce:      result.Nonce,
		Tag:        result.Tag,
	}, nil
}

// Decrypt decrypts data with the specified key.
func (t *Transport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	params := map[string]interface{}{
		"backend":    req.Backend,
		"key_id":     req.KeyID,
		"ciphertext": req.Ciphertext,
	}
	if len(req.Nonce) > 0 {
		params["nonce"] = req.Nonce
	}
	if len(req.Tag) > 0 {
		params["tag"] = req.Tag
	}
	if len(req.AdditionalData) > 0 {
		params["additional_data"] = req.AdditionalData
	}

	var result struct {
		Plaintext []byte `json:"plaintext"`
	}
	if err := t.doCall(ctx, "keychain.decrypt", params, &result); err != nil {
		return nil, err
	}

	return &transport.DecryptResponse{Plaintext: result.Plaintext}, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (t *Transport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	params := map[string]interface{}{
		"backend":   req.Backend,
		"key_id":    req.KeyID,
		"plaintext": req.Plaintext,
	}

	var result struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := t.doCall(ctx, "keychain.asymmetricEncrypt", params, &result); err != nil {
		return nil, err
	}

	return &transport.EncryptAsymResponse{Ciphertext: result.Ciphertext}, nil
}

// GetCertificate returns the certificate for a key.
func (t *Transport) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	params := map[string]interface{}{
		"key_id": keyID,
	}

	var result struct {
		KeyID   string `json:"key_id"`
		CertPEM string `json:"cert_pem"`
	}
	if err := t.doCall(ctx, "keychain.getCert", params, &result); err != nil {
		return nil, err
	}

	return &transport.GetCertificateResponse{
		KeyID:          result.KeyID,
		CertificatePEM: result.CertPEM,
	}, nil
}

// SaveCertificate saves a certificate for a key.
func (t *Transport) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	params := map[string]interface{}{
		"key_id":   req.KeyID,
		"cert_pem": req.CertificatePEM,
	}

	return t.doCall(ctx, "keychain.saveCert", params, nil)
}

// DeleteCertificate deletes a certificate.
func (t *Transport) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	params := map[string]interface{}{
		"key_id": keyID,
	}

	return t.doCall(ctx, "keychain.deleteCert", params, nil)
}

// CertificateExists checks if a certificate exists for a key.
func (t *Transport) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	params := map[string]interface{}{
		"key_id": keyID,
	}

	var result struct {
		Exists bool `json:"exists"`
	}
	if err := t.doCall(ctx, "keychain.certExists", params, &result); err != nil {
		return false, err
	}

	return result.Exists, nil
}

// ImportKey imports a key.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	params := map[string]interface{}{
		"backend":     req.Backend,
		"key_id":      req.KeyID,
		"wrapped_key": req.WrappedKeyMaterial,
		"algorithm":   req.Algorithm,
	}
	if req.KeyType != "" {
		params["key_type"] = req.KeyType
	}
	if req.KeySize > 0 {
		params["key_size"] = req.KeySize
	}
	if req.Curve != "" {
		params["curve"] = req.Curve
	}

	if err := t.doCall(ctx, "keychain.importKey", params, nil); err != nil {
		return nil, err
	}

	return &transport.ImportKeyResponse{
		Success: true,
		KeyID:   req.KeyID,
	}, nil
}

// ExportKey exports a key.
func (t *Transport) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	params := map[string]interface{}{
		"backend":   req.Backend,
		"key_id":    req.KeyID,
		"algorithm": req.Algorithm,
	}

	var result struct {
		WrappedKey []byte `json:"wrapped_key"`
		Algorithm  string `json:"algorithm"`
	}
	if err := t.doCall(ctx, "keychain.exportKey", params, &result); err != nil {
		return nil, err
	}

	return &transport.ExportKeyResponse{
		KeyID:              req.KeyID,
		WrappedKeyMaterial: result.WrappedKey,
		Algorithm:          result.Algorithm,
	}, nil
}

// RotateKey rotates a key by generating a new version.
func (t *Transport) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	params := map[string]interface{}{
		"backend": req.Backend,
		"key_id":  req.KeyID,
	}

	var result struct {
		KeyID        string `json:"key_id"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := t.doCall(ctx, "keychain.rotateKey", params, &result); err != nil {
		return nil, err
	}

	return &transport.RotateKeyResponse{
		Success:      true,
		KeyID:        result.KeyID,
		PublicKeyPEM: result.PublicKeyPEM,
	}, nil
}

// ListKeyVersions lists all versions of a key.
func (t *Transport) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	params := map[string]interface{}{
		"key_id": req.KeyID,
	}
	if req.Backend != "" {
		params["backend"] = req.Backend
	}

	if err := t.doCall(ctx, "keychain.listKeyVersions", params, nil); err != nil {
		return nil, err
	}

	return &transport.ListKeyVersionsResponse{KeyID: req.KeyID}, nil
}

// EnableKeyVersion enables a specific version of a key.
func (t *Transport) EnableKeyVersion(ctx context.Context, req *transport.EnableKeyVersionRequest) (*transport.EnableKeyVersionResponse, error) {
	params := map[string]interface{}{
		"key_id":  req.KeyID,
		"version": req.Version,
	}
	if req.Backend != "" {
		params["backend"] = req.Backend
	}

	if err := t.doCall(ctx, "keychain.enableKeyVersion", params, nil); err != nil {
		return nil, err
	}

	return &transport.EnableKeyVersionResponse{KeyID: req.KeyID}, nil
}

// DisableKeyVersion disables a specific version of a key.
func (t *Transport) DisableKeyVersion(ctx context.Context, req *transport.DisableKeyVersionRequest) (*transport.DisableKeyVersionResponse, error) {
	params := map[string]interface{}{
		"key_id":  req.KeyID,
		"version": req.Version,
	}
	if req.Backend != "" {
		params["backend"] = req.Backend
	}

	if err := t.doCall(ctx, "keychain.disableKeyVersion", params, nil); err != nil {
		return nil, err
	}

	return &transport.DisableKeyVersionResponse{KeyID: req.KeyID}, nil
}

// EnableAllKeyVersions enables all versions of a key.
func (t *Transport) EnableAllKeyVersions(ctx context.Context, req *transport.EnableAllKeyVersionsRequest) (*transport.EnableAllKeyVersionsResponse, error) {
	params := map[string]interface{}{
		"key_id": req.KeyID,
	}
	if req.Backend != "" {
		params["backend"] = req.Backend
	}

	if err := t.doCall(ctx, "keychain.enableAllKeyVersions", params, nil); err != nil {
		return nil, err
	}

	return &transport.EnableAllKeyVersionsResponse{KeyID: req.KeyID}, nil
}

// DisableAllKeyVersions disables all versions of a key.
func (t *Transport) DisableAllKeyVersions(ctx context.Context, req *transport.DisableAllKeyVersionsRequest) (*transport.DisableAllKeyVersionsResponse, error) {
	params := map[string]interface{}{
		"key_id": req.KeyID,
	}
	if req.Backend != "" {
		params["backend"] = req.Backend
	}

	if err := t.doCall(ctx, "keychain.disableAllKeyVersions", params, nil); err != nil {
		return nil, err
	}

	return &transport.DisableAllKeyVersionsResponse{KeyID: req.KeyID}, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	params := map[string]interface{}{
		"backend":   req.Backend,
		"key_id":    req.KeyID,
		"algorithm": req.Algorithm,
	}

	var result struct {
		WrappingPublicKey []byte `json:"wrapping_public_key"`
		ImportToken       []byte `json:"import_token"`
		Algorithm         string `json:"algorithm"`
		ExpiresAt         string `json:"expires_at"`
	}
	if err := t.doCall(ctx, "keychain.getImportParameters", params, &result); err != nil {
		return nil, err
	}

	return &transport.GetImportParametersResponse{
		WrappingPublicKey: result.WrappingPublicKey,
		ImportToken:       result.ImportToken,
		Algorithm:         result.Algorithm,
		ExpiresAt:         result.ExpiresAt,
	}, nil
}

// WrapKey wraps key material for secure transport.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	params := map[string]interface{}{
		"key_material":        req.KeyMaterial,
		"wrapping_public_key": req.WrappingPublicKey,
		"algorithm":           req.Algorithm,
	}
	if len(req.ImportToken) > 0 {
		params["import_token"] = req.ImportToken
	}

	var result struct {
		WrappedKeyMaterial []byte `json:"wrapped_key"`
		Algorithm          string `json:"algorithm"`
	}
	if err := t.doCall(ctx, "keychain.wrapKey", params, &result); err != nil {
		return nil, err
	}

	return &transport.WrapKeyResponse{
		WrappedKeyMaterial: result.WrappedKeyMaterial,
		Algorithm:          result.Algorithm,
	}, nil
}

// UnwrapKey unwraps key material.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	params := map[string]interface{}{
		"wrapped_key": req.WrappedKeyMaterial,
		"algorithm":   req.Algorithm,
	}
	if len(req.ImportToken) > 0 {
		params["import_token"] = req.ImportToken
	}

	var result struct {
		KeyMaterial []byte `json:"key_material"`
	}
	if err := t.doCall(ctx, "keychain.unwrapKey", params, &result); err != nil {
		return nil, err
	}

	return &transport.UnwrapKeyResponse{
		KeyMaterial: result.KeyMaterial,
	}, nil
}

// CopyKey copies a key from one backend to another.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	params := map[string]interface{}{
		"source_backend": req.SourceBackend,
		"source_key_id":  req.SourceKeyID,
		"dest_backend":   req.DestBackend,
		"dest_key_id":    req.DestKeyID,
		"algorithm":      req.Algorithm,
	}
	if req.KeyType != "" {
		params["key_type"] = req.KeyType
	}
	if req.KeySize > 0 {
		params["key_size"] = req.KeySize
	}
	if req.Curve != "" {
		params["curve"] = req.Curve
	}

	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := t.doCall(ctx, "keychain.copyKey", params, &result); err != nil {
		return nil, err
	}

	return &transport.CopyKeyResponse{
		Success: result.Success,
		Message: result.Message,
	}, nil
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string) (*transport.ListCertificatesResponse, error) {
	var result struct {
		KeyIDs []string `json:"key_ids"`
	}
	if err := t.doCall(ctx, "keychain.listCerts", nil, &result); err != nil {
		return nil, err
	}

	certs := make([]transport.CertificateInfo, len(result.KeyIDs))
	for i, keyID := range result.KeyIDs {
		certs[i] = transport.CertificateInfo{
			KeyID: keyID,
		}
	}
	return &transport.ListCertificatesResponse{Certificates: certs}, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (t *Transport) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	params := map[string]interface{}{
		"key_id":     req.KeyID,
		"chain_pems": req.ChainPEM,
	}

	return t.doCall(ctx, "keychain.saveCertChain", params, nil)
}

// GetCertificateChain returns the certificate chain for a key.
func (t *Transport) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	params := map[string]interface{}{
		"key_id": keyID,
	}

	var result struct {
		KeyID    string   `json:"key_id"`
		ChainPEM []string `json:"chain_pems"`
	}
	if err := t.doCall(ctx, "keychain.getCertChain", params, &result); err != nil {
		return nil, err
	}

	return &transport.GetCertificateChainResponse{
		KeyID:    result.KeyID,
		ChainPEM: result.ChainPEM,
	}, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (t *Transport) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	params := map[string]interface{}{
		"backend": backend,
		"key_id":  keyID,
	}

	var result struct {
		CertPEM   string   `json:"cert_pem"`
		ChainPEMs []string `json:"chain_pems"`
	}
	if err := t.doCall(ctx, "keychain.getTLSCertificate", params, &result); err != nil {
		return nil, err
	}

	// Join chain PEMs into a single string
	chainPEM := ""
	for _, pem := range result.ChainPEMs {
		chainPEM += pem
	}

	return &transport.GetTLSCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: result.CertPEM,
		ChainPEM:       chainPEM,
	}, nil
}

// Seal seals data using the backend's sealing mechanism.
func (t *Transport) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	params := map[string]interface{}{
		"data": req.Data,
	}
	if req.Backend != "" {
		params["backend"] = req.Backend
	}
	if req.KeyID != "" {
		params["key_id"] = req.KeyID
	}
	if len(req.AAD) > 0 {
		params["aad"] = req.AAD
	}

	var result struct {
		Backend    string `json:"backend"`
		Ciphertext []byte `json:"ciphertext"`
		Nonce      []byte `json:"nonce"`
		Tag        []byte `json:"tag"`
	}
	if err := t.doCall(ctx, "keychain.seal", params, &result); err != nil {
		return nil, err
	}

	return &transport.SealResponse{
		Backend:    result.Backend,
		Ciphertext: result.Ciphertext,
		Nonce:      result.Nonce,
		Tag:        result.Tag,
	}, nil
}

// Unseal unseals previously sealed data.
func (t *Transport) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	params := map[string]interface{}{
		"ciphertext": req.Ciphertext,
	}
	if req.Backend != "" {
		params["backend"] = req.Backend
	}
	if req.KeyID != "" {
		params["key_id"] = req.KeyID
	}
	if len(req.Nonce) > 0 {
		params["nonce"] = req.Nonce
	}
	if len(req.Tag) > 0 {
		params["tag"] = req.Tag
	}
	if len(req.AAD) > 0 {
		params["aad"] = req.AAD
	}

	var result struct {
		Plaintext []byte `json:"plaintext"`
	}
	if err := t.doCall(ctx, "keychain.unseal", params, &result); err != nil {
		return nil, err
	}

	return &transport.UnsealResponse{Plaintext: result.Plaintext}, nil
}

// CanSeal checks if the backend supports sealing operations.
func (t *Transport) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	params := map[string]interface{}{}
	if backend != "" {
		params["backend"] = backend
	}

	var result struct {
		CanSeal bool `json:"can_seal"`
	}
	if err := t.doCall(ctx, "keychain.canSeal", params, &result); err != nil {
		return nil, err
	}

	return &transport.CanSealResponse{
		CanSeal: result.CanSeal,
		Backend: backend,
	}, nil
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
