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

// Package mcp provides an MCP transport implementation for the xkms SDK.
// The MCP transport communicates with the xkms MCP server using JSON-RPC 2.0
// over raw TCP with newline-delimited JSON framing.
package mcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

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
	// ErrNotImplemented is returned when an operation has not been implemented yet.
	ErrNotImplemented = errors.New("not implemented")
)

// jsonrpcRequest represents a JSON-RPC 2.0 request.
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      int64           `json:"id"`
}

// jsonrpcResponse represents a JSON-RPC 2.0 response.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
	ID      int64           `json:"id,omitempty"`
}

// jsonrpcError represents a JSON-RPC 2.0 error.
type jsonrpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Error implements the error interface for jsonrpcError.
func (e *jsonrpcError) Error() string {
	if len(e.Data) > 0 {
		return fmt.Sprintf("JSON-RPC error %d: %s (data: %s)", e.Code, e.Message, string(e.Data))
	}
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// RPCError is a typed error for JSON-RPC server errors returned to callers.
type RPCError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	if len(e.Data) > 0 {
		return fmt.Sprintf("rpc error %d: %s (data: %s)", e.Code, e.Message, string(e.Data))
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// MarshalError is a typed error for JSON marshaling failures.
type MarshalError struct {
	Operation string
	Err       error
}

// Error implements the error interface.
func (e *MarshalError) Error() string {
	return fmt.Sprintf("failed to marshal %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *MarshalError) Unwrap() error {
	return e.Err
}

// UnmarshalError is a typed error for JSON unmarshaling failures.
type UnmarshalError struct {
	Operation string
	Err       error
}

// Error implements the error interface.
func (e *UnmarshalError) Error() string {
	return fmt.Sprintf("failed to unmarshal %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *UnmarshalError) Unwrap() error {
	return e.Err
}

// SendError is a typed error for TCP write failures.
type SendError struct {
	Err error
}

// Error implements the error interface.
func (e *SendError) Error() string {
	return fmt.Sprintf("failed to send request: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *SendError) Unwrap() error {
	return e.Err
}

// ReceiveError is a typed error for TCP read failures.
type ReceiveError struct {
	Err error
}

// Error implements the error interface.
func (e *ReceiveError) Error() string {
	return fmt.Sprintf("failed to receive response: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ReceiveError) Unwrap() error {
	return e.Err
}

// TLSSetupError is a typed error for TLS configuration failures.
type TLSSetupError struct {
	Detail string
	Err    error
}

// Error implements the error interface.
func (e *TLSSetupError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("TLS setup: %s: %v", e.Detail, e.Err)
	}
	return fmt.Sprintf("TLS setup: %s", e.Detail)
}

// Unwrap returns the underlying error.
func (e *TLSSetupError) Unwrap() error {
	return e.Err
}

// methodMapping maps REST-style SDK paths to JSON-RPC method names.
// The SDK client calls Request with REST paths; this table translates them
// to the JSON-RPC method names that the MCP server expects.
var methodMapping = map[string]string{
	// Health
	"/health": "health",

	// Backends
	"/api/v1/backends": "xkms.listBackends",

	// Keys
	"/api/v1/keys":               "xkms.generateKey",
	"/api/v1/keys/import":        "xkms.importKey",
	"/api/v1/keys/copy":          "xkms.copyKey",
	"/api/v1/keys/wrap":          "xkms.wrapKey",
	"/api/v1/keys/unwrap":        "xkms.unwrapKey",
	"/api/v1/keys/wrap-by-id":    "xkms.wrapKey",
	"/api/v1/keys/unwrap-by-id":  "xkms.unwrapKey",
	"/api/v1/keys/import-params": "xkms.getImportParameters",

	// Certificates
	"/api/v1/certs": "xkms.saveCert",

	// Seal
	"/api/v1/seal":   "xkms.seal",
	"/api/v1/unseal": "xkms.unseal",

	// CA
	"/api/v1/ca/bundle":      "xkms.ca.bundle",
	"/api/v1/ca/certificate": "xkms.ca.certificate",
	"/api/v1/ca/sign-csr":    "xkms.ca.sign-csr",
	"/api/v1/ca/issue":       "xkms.ca.issue",
	"/api/v1/ca/revoke":      "xkms.ca.revoke",
	"/api/v1/ca/crl":         "xkms.ca.crl",

	// TCG CA
	"/api/v1/tcg-ca/issue-ek-cert": "xkms.ca.tcg.issue-ek",
	"/api/v1/tcg-ca/issue-ak-cert": "xkms.ca.tcg.issue-ak",
	"/api/v1/tcg-ca/sign-tcg-csr":  "xkms.ca.tcg.sign-csr",
	"/api/v1/tcg-ca/enroll-device": "xkms.ca.tcg.enroll",

	// Barrier
	"/v1/barrier/initialize":             "barrier.initialize",
	"/v1/barrier/initialize-shamir":      "barrier.initializeShamir",
	"/v1/barrier/unseal":                 "barrier.unseal",
	"/v1/barrier/unseal-share":           "barrier.unsealShare",
	"/v1/barrier/unseal-shares":          "barrier.unsealShares",
	"/v1/barrier/seal":                   "barrier.seal",
	"/v1/barrier/status":                 "barrier.status",
	"/v1/barrier/rekey":                  "barrier.rekey",
	"/v1/barrier/shamir/verify":          "barrier.shamirVerify",
	"/v1/barrier/shamir/shares":          "barrier.shamirListShares",
	"/v1/barrier/root-token":             "barrier.generateRootToken",
	"/v1/barrier/recovery-keys":          "barrier.deleteRecoveryKeys",
	"/v1/barrier/recovery-keys/generate": "barrier.generateRecoveryKeys",
	"/v1/barrier/recovery-keys/recover":  "barrier.recoverWithKeys",

	// Attestation
	"/api/v1/attest": "xkms.attestKey",

	// Init Ceremony
	"/api/v1/init/status":              "init.getStatus",
	"/api/v1/init/claim-cert/begin":    "init.claimCertBegin",
	"/api/v1/init/claim-cert/complete": "init.claimCertComplete",
	"/api/v1/init/claim-share":         "init.claimShare",
	"/api/v1/init/sign-csr":            "init.signCSR",

	// Credentials
	"/api/v1/credentials/submit":   "credentials.submit",
	"/api/v1/credentials/strategy": "credentials.strategy",

	// PIN Operations
	"/v1/pin/so-pin":          "xkms.setSOPIN",
	"/v1/pin/user-pin":        "xkms.setUserPIN",
	"/v1/pin/so-pin/change":   "xkms.changeSOPIN",
	"/v1/pin/user-pin/change": "xkms.changeUserPIN",
	"/v1/pin/so-pin/verify":   "xkms.verifySOPIN",
	"/v1/pin/user-pin/verify": "xkms.verifyUserPIN",
	"/v1/pin/lockout":         "xkms.getLockoutStatus",
	"/v1/pin/lockout/reset":   "xkms.resetLockout",

	// Password Store
	"/api/v1/passwords":             "xkms.passwordList",
	"/api/v1/passwords/unlock":      "xkms.passwordStoreUnlock",
	"/api/v1/passwords/lock":        "xkms.passwordStoreLock",
	"/api/v1/passwords/status":      "xkms.passwordStoreStatus",
	"/api/v1/passwords/access-mode": "xkms.passwordStoreSetAccessMode",
	"/api/v1/passwords/generate":    "xkms.passwordGenerate",

	// Key derivation
	"/api/v1/keys/derive":      "xkms.deriveKey",
	"/api/v1/keys/derive-ecdh": "xkms.deriveKeyECDH",

	// Custodian Groups
	"/api/v1/custodian/groups": "xkms.listCustodianGroups",

	// Shares
	"/api/v1/shares/submit": "xkms.submitShare",
	"/api/v1/shares":        "xkms.listShares",

	// Tenants
	"/api/v1/tenants": "xkms.listTenants",

	// Users
	"/api/v1/users/": "xkms.listUsers",
}

// pathPatterns maps REST path patterns with dynamic segments to JSON-RPC methods.
// These are checked when an exact match is not found in methodMapping.
// The key is a path prefix pattern, the value contains the suffix and method.
type pathPattern struct {
	suffix string
	method string
}

var dynamicPatterns = []struct {
	prefix   string
	patterns []pathPattern
}{
	{
		prefix: "/api/v1/keys/",
		patterns: []pathPattern{
			{suffix: "/sign", method: "xkms.sign"},
			{suffix: "/verify", method: "xkms.verify"},
			{suffix: "/encrypt", method: "xkms.encrypt"},
			{suffix: "/decrypt", method: "xkms.decrypt"},
			{suffix: "/encrypt-asym", method: "xkms.asymmetricEncrypt"},
			{suffix: "/decrypt-asym", method: "xkms.asymmetricDecrypt"},
			{suffix: "/rotate", method: "xkms.rotateKey"},
			{suffix: "/export", method: "xkms.exportKey"},
			{suffix: "/export-material", method: "xkms.exportKeyMaterial"},
			{suffix: "", method: "xkms.getKey"},
		},
	},
	{
		prefix: "/api/v1/certs/",
		patterns: []pathPattern{
			{suffix: "/chain", method: "xkms.getCertChain"},
			{suffix: "", method: "xkms.getCert"},
		},
	},
	{
		prefix: "/api/v1/tls/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getTLSCertificate"},
		},
	},
	{
		prefix: "/api/v1/seal/capability",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.canSeal"},
		},
	},
	{
		prefix: "/api/v1/ca/revoked/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.ca.is-revoked"},
		},
	},
	{
		prefix: "/api/v1/users/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getUser"},
		},
	},
	{
		prefix: "/api/v1/backends/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getBackend"},
		},
	},
	{
		prefix: "/api/v1/passwords/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.passwordGet"},
		},
	},
	{
		prefix: "/v1/piv/slots",
		patterns: []pathPattern{
			{suffix: "/certificate", method: "xkms.getPIVCertificate"},
			{suffix: "/generate", method: "xkms.generatePIVKey"},
			{suffix: "/import", method: "xkms.importPIVCertificate"},
			{suffix: "/export", method: "xkms.exportPIVCertificate"},
			{suffix: "/csr", method: "xkms.generatePIVCSR"},
			{suffix: "", method: "xkms.listPIVSlots"},
		},
	},
	{
		prefix: "/v1/barrier/shamir/shares/",
		patterns: []pathPattern{
			{suffix: "", method: "barrier.shamirDeleteShare"},
		},
	},
	{
		prefix: "/api/v1/custodian/groups/",
		patterns: []pathPattern{
			{suffix: "/distribute", method: "xkms.distributeShares"},
			{suffix: "/members", method: "xkms.addCustodianMember"},
			{suffix: "", method: "xkms.getCustodianGroup"},
		},
	},
	{
		prefix: "/api/v1/tenants/",
		patterns: []pathPattern{
			{suffix: "/barrier/init", method: "xkms.tenantBarrierInit"},
			{suffix: "/barrier/unseal", method: "xkms.tenantBarrierUnseal"},
			{suffix: "", method: "xkms.getTenant"},
		},
	},
	{
		prefix: "/api/v1/shares/status/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getShareCollectionStatus"},
		},
	},
}

// resolveMethod maps a REST-style path to a JSON-RPC method name.
// It strips query parameters before matching.
func resolveMethod(path string) (string, bool) {
	// Strip query parameters
	cleanPath := path
	if idx := strings.IndexByte(cleanPath, '?'); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}

	// Try exact match first (O(1) lookup)
	if method, ok := methodMapping[cleanPath]; ok {
		return method, true
	}

	// Try dynamic path patterns
	for _, dp := range dynamicPatterns {
		if !strings.HasPrefix(cleanPath, dp.prefix) {
			continue
		}
		for _, p := range dp.patterns {
			if p.suffix == "" {
				// Catch-all pattern for this prefix
				return p.method, true
			}
			if strings.HasSuffix(cleanPath, p.suffix) {
				return p.method, true
			}
		}
	}

	return "", false
}

// Transport implements the transport.Client interface using JSON-RPC 2.0
// over raw TCP with newline-delimited JSON framing.
type Transport struct {
	config    *transport.Config
	conn      net.Conn
	encoder   *json.Encoder
	scanner   *bufio.Scanner
	connected bool
	requestID atomic.Int64

	// writeMu serializes writes to the TCP connection.
	// TCP is not safe for concurrent writes from multiple goroutines.
	writeMu sync.Mutex

	// readMu serializes reads from the TCP connection.
	// The scanner is stateful and cannot be shared concurrently.
	readMu sync.Mutex
}

// New creates a new MCP transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return NewWithConfig(cfg)
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

// Connect establishes a TCP connection to the xkms MCP server.
func (t *Transport) Connect(ctx context.Context) error {
	addr := t.config.Address

	// Strip any http/https scheme prefix if present
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")

	var conn net.Conn
	var dialErr error

	if t.config.TLSEnabled {
		tlsConfig, tlsErr := t.buildTLSConfig()
		if tlsErr != nil {
			return tlsErr
		}

		dialer := &tls.Dialer{
			Config: tlsConfig,
		}
		conn, dialErr = dialer.DialContext(ctx, "tcp", addr)
	} else {
		dialer := &net.Dialer{}
		conn, dialErr = dialer.DialContext(ctx, "tcp", addr)
	}

	if dialErr != nil {
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("%v", dialErr)}
	}

	t.conn = conn
	t.encoder = json.NewEncoder(conn)
	t.scanner = bufio.NewScanner(conn)
	// Allow up to 10 MB for large responses (certificate chains, etc.)
	t.scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	// Mark connected before health check so rpcCall doesn't reject the request
	t.connected = true

	// Test connection with health check
	_, healthErr := t.Health(ctx)
	if healthErr != nil {
		t.connected = false
		closeErr := conn.Close()
		if closeErr != nil {
			return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("health check failed: %v (close error: %v)", healthErr, closeErr)}
		}
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("health check failed: %v", healthErr)}
	}
	return nil
}

// buildTLSConfig constructs the TLS configuration from transport options.
func (t *Transport) buildTLSConfig() (*tls.Config, error) {
	if t.config.TLSConfig != nil {
		return t.config.TLSConfig, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load CA certificate if specified
	if t.config.TLSCAFile != "" {
		caCert, err := os.ReadFile(t.config.TLSCAFile)
		if err != nil {
			return nil, &TLSSetupError{Detail: "failed to read CA certificate", Err: err}
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, &TLSSetupError{Detail: "failed to parse CA certificate"}
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if specified (mTLS)
	if t.config.TLSCertFile != "" && t.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.config.TLSCertFile, t.config.TLSKeyFile)
		if err != nil {
			return nil, &TLSSetupError{Detail: "failed to load client certificate", Err: err}
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

	return tlsConfig, nil
}

// Close closes the TCP connection.
func (t *Transport) Close() error {
	t.connected = false
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// Healthy checks if the transport can communicate with the server.
func (t *Transport) Healthy(ctx context.Context) bool {
	if t.conn == nil {
		return false
	}

	_, err := t.Health(ctx)
	return err == nil
}

// Conn returns the underlying net.Conn.
func (t *Transport) Conn() interface{} {
	return t.conn
}

// IsConnected returns whether the transport is connected.
func (t *Transport) IsConnected() bool {
	return t.connected
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Request performs a JSON-RPC 2.0 request to the MCP server.
// The method parameter is a REST-style path that gets mapped to a JSON-RPC method name.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	if t.conn == nil {
		return ErrNotConnected
	}

	rpcMethod, ok := resolveMethod(method)
	if !ok {
		return &transport.TransportError{
			Code:    transport.ErrCodeMethodNotFound,
			Message: "no JSON-RPC mapping for path: " + method,
		}
	}

	return t.rpcCall(ctx, rpcMethod, req, resp)
}

// RequestStream opens a bidirectional stream (not supported for MCP).
func (t *Transport) RequestStream(ctx context.Context, _ string, _ interface{}) (transport.Stream, error) {
	return nil, transport.ErrStreamNotSupported
}

// rpcCall sends a JSON-RPC 2.0 request and reads the response.
func (t *Transport) rpcCall(ctx context.Context, method string, params interface{}, result interface{}) error {
	if !t.connected {
		return ErrNotConnected
	}

	id := t.requestID.Add(1)

	var rawParams json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return &MarshalError{Operation: "request params", Err: err}
		}
		rawParams = data
	}

	req := &jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  rawParams,
		ID:      id,
	}

	// Serialize write access
	t.writeMu.Lock()
	sendErr := t.encoder.Encode(req)
	t.writeMu.Unlock()

	if sendErr != nil {
		return &SendError{Err: sendErr}
	}

	// Serialize read access
	t.readMu.Lock()
	defer t.readMu.Unlock()

	if !t.scanner.Scan() {
		if err := t.scanner.Err(); err != nil {
			return &ReceiveError{Err: err}
		}
		return &ReceiveError{Err: errors.New("connection closed by server")}
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal(t.scanner.Bytes(), &resp); err != nil {
		return &UnmarshalError{Operation: "response", Err: err}
	}

	if resp.Error != nil {
		return &RPCError{
			Code:    resp.Error.Code,
			Message: resp.Error.Message,
			Data:    resp.Error.Data,
		}
	}

	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return &UnmarshalError{Operation: "result", Err: err}
		}
	}

	return nil
}

// Health checks the health of the server.
func (t *Transport) Health(ctx context.Context) (*transport.HealthResponse, error) {
	var result transport.HealthResponse
	if err := t.rpcCall(ctx, "health", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListBackends returns a list of available backends.
func (t *Transport) ListBackends(ctx context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	var result transport.ListBackendsResponse
	if err := t.rpcCall(ctx, "xkms.listBackends", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBackend returns information about a specific backend.
func (t *Transport) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	params := map[string]string{"backend": backendID}
	var result transport.BackendInfo
	if err := t.rpcCall(ctx, "xkms.getBackend", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GenerateKey generates a new key.
func (t *Transport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	var result transport.GenerateKeyResponse
	if err := t.rpcCall(ctx, "xkms.generateKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListKeys returns a list of keys in the specified backend.
func (t *Transport) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	params := map[string]string{"backend": backend}
	var result transport.ListKeysResponse
	if err := t.rpcCall(ctx, "xkms.listKeys", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetKey returns information about a specific key.
func (t *Transport) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetKeyResponse
	if err := t.rpcCall(ctx, "xkms.getKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteKey deletes a key.
func (t *Transport) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.DeleteKeyResponse
	if err := t.rpcCall(ctx, "xkms.deleteKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Sign signs data with the specified key.
func (t *Transport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	var result transport.SignResponse
	if err := t.rpcCall(ctx, "xkms.sign", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Verify verifies a signature.
func (t *Transport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	var result transport.VerifyResponse
	if err := t.rpcCall(ctx, "xkms.verify", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Encrypt encrypts data with the specified key.
func (t *Transport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	var result transport.EncryptResponse
	if err := t.rpcCall(ctx, "xkms.encrypt", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Decrypt decrypts data with the specified key.
func (t *Transport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	var result transport.DecryptResponse
	if err := t.rpcCall(ctx, "xkms.decrypt", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (t *Transport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	var result transport.EncryptAsymResponse
	if err := t.rpcCall(ctx, "xkms.asymmetricEncrypt", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeriveKey derives a key using the specified algorithm and parameters.
func (t *Transport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	var result transport.DeriveKeyResponse
	if err := t.rpcCall(ctx, "xkms.deriveKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a key using a KDF.
func (t *Transport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	var result transport.DeriveKeyECDHResponse
	if err := t.rpcCall(ctx, "xkms.deriveKeyECDH", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AttestKey requests key attestation from a backend.
func (t *Transport) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.AttestKeyResponse
	if err := t.rpcCall(ctx, "xkms.attestKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCertificate returns the certificate for a key.
func (t *Transport) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetCertificateResponse
	if err := t.rpcCall(ctx, "xkms.getCert", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SaveCertificate saves a certificate for a key.
func (t *Transport) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	return t.rpcCall(ctx, "xkms.saveCert", req, nil)
}

// DeleteCertificate deletes a certificate.
func (t *Transport) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	params := map[string]string{"key_id": keyID, "backend": backend}
	return t.rpcCall(ctx, "xkms.deleteCert", params, nil)
}

// CertificateExists checks if a certificate exists for a key.
func (t *Transport) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result struct {
		Exists bool `json:"exists"`
	}
	if err := t.rpcCall(ctx, "xkms.certExists", params, &result); err != nil {
		return false, err
	}
	return result.Exists, nil
}

// ImportKey imports a key.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	var result transport.ImportKeyResponse
	if err := t.rpcCall(ctx, "xkms.importKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportKey exports a key.
func (t *Transport) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	var result transport.ExportKeyResponse
	if err := t.rpcCall(ctx, "xkms.exportKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RotateKey rotates a key.
func (t *Transport) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	var result transport.RotateKeyResponse
	if err := t.rpcCall(ctx, "xkms.rotateKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetImportParameters gets the parameters needed to import a key.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	var result transport.GetImportParametersResponse
	if err := t.rpcCall(ctx, "xkms.getImportParameters", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WrapKey wraps key material for secure transport.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	var result transport.WrapKeyResponse
	if err := t.rpcCall(ctx, "xkms.wrapKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UnwrapKey unwraps key material.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	var result transport.UnwrapKeyResponse
	if err := t.rpcCall(ctx, "xkms.unwrapKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WrapKeyByID wraps a key using another key, both identified by their IDs.
func (t *Transport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	var result transport.WrapKeyByIDResponse
	if err := t.rpcCall(ctx, "xkms.wrapKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (t *Transport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	var result transport.UnwrapKeyByIDResponse
	if err := t.rpcCall(ctx, "xkms.unwrapKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportKeyMaterial exports raw symmetric key material.
func (t *Transport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	var result transport.ExportKeyMaterialResponse
	if err := t.rpcCall(ctx, "xkms.exportKeyMaterial", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CopyKey copies a key from one backend to another.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	var result transport.CopyKeyResponse
	if err := t.rpcCall(ctx, "xkms.copyKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	params := map[string]string{"backend": backend}
	var result transport.ListCertificatesResponse
	if err := t.rpcCall(ctx, "xkms.listCerts", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (t *Transport) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	return t.rpcCall(ctx, "xkms.saveCertChain", req, nil)
}

// GetCertificateChain returns the certificate chain for a key.
func (t *Transport) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetCertificateChainResponse
	if err := t.rpcCall(ctx, "xkms.getCertChain", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (t *Transport) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetTLSCertificateResponse
	if err := t.rpcCall(ctx, "xkms.getTLSCertificate", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Seal seals data using the backend's sealing mechanism.
func (t *Transport) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.SealResponse
	if err := t.rpcCall(ctx, "xkms.seal", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Unseal unseals previously sealed data.
func (t *Transport) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.UnsealResponse
	if err := t.rpcCall(ctx, "xkms.unseal", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CanSeal checks if the backend supports sealing operations.
func (t *Transport) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	params := map[string]string{"backend": backend}
	var result transport.CanSealResponse
	if err := t.rpcCall(ctx, "xkms.canSeal", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WebAuthn/FIDO2 Operations

// BeginRegistration begins a WebAuthn registration flow.
func (t *Transport) BeginRegistration(ctx context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, ErrNotSupported
}

// FinishRegistration completes a WebAuthn registration flow.
func (t *Transport) FinishRegistration(ctx context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, ErrNotSupported
}

// BeginAuthentication begins a WebAuthn authentication flow.
func (t *Transport) BeginAuthentication(ctx context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, ErrNotSupported
}

// FinishAuthentication completes a WebAuthn authentication flow.
func (t *Transport) FinishAuthentication(ctx context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, ErrNotSupported
}

// CA Operations

// GetCABundle retrieves the CA certificate bundle.
func (t *Transport) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	var result transport.GetCABundleResponse
	if err := t.rpcCall(ctx, "xkms.ca.bundle", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCACertificate retrieves the CA certificate.
func (t *Transport) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	var result transport.GetCACertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.certificate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignCSR signs a certificate signing request.
func (t *Transport) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	var result transport.SignCSRResponse
	if err := t.rpcCall(ctx, "xkms.ca.sign-csr", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IssueCertificate issues a new certificate.
func (t *Transport) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	var result transport.IssueCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.issue", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeCertificate revokes a certificate.
func (t *Transport) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	var result transport.RevokeCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.revoke", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GenerateCRL generates a certificate revocation list.
func (t *Transport) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	var result transport.GenerateCRLResponse
	if err := t.rpcCall(ctx, "xkms.ca.crl", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IsRevoked checks if a certificate is revoked.
func (t *Transport) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	var result transport.IsRevokedResponse
	if err := t.rpcCall(ctx, "xkms.ca.is-revoked", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TCG CA Operations

// IssueEKCertificate issues an Endorsement Key certificate.
func (t *Transport) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	var result transport.IssueEKCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.issue-ek", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IssueAKCertificate issues an Attestation Key certificate.
func (t *Transport) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	var result transport.IssueAKCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.issue-ak", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignTCGCSR signs a TCG-CSR-IDEVID for device identity enrollment.
func (t *Transport) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	var result transport.SignTCGCSRResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.sign-csr", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EnrollDevice performs complete TCG device enrollment.
func (t *Transport) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	var result transport.EnrollDeviceResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.enroll", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PIV Operations

// ListPIVSlots returns the list of PIV slots and their status.
func (t *Transport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.ListPIVSlotsResponse
	if err := t.rpcCall(ctx, "xkms.listPIVSlots", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPIVCertificate retrieves the certificate from a PIV slot.
func (t *Transport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.GetPIVCertificateResponse
	if err := t.rpcCall(ctx, "xkms.getPIVCertificate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StorePIVCertificate stores a certificate into a PIV slot.
func (t *Transport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.storePIVCertificate", req, nil)
}

// DeletePIVCertificate removes the certificate from a PIV slot.
func (t *Transport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.deletePIVCertificate", req, nil)
}

// GeneratePIVKey generates a new key pair in a PIV slot.
func (t *Transport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.GeneratePIVKeyResponse
	if err := t.rpcCall(ctx, "xkms.generatePIVKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ImportPIVCertificate imports a certificate into a PIV slot.
func (t *Transport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.importPIVCertificate", req, nil)
}

// ExportPIVCertificate exports the certificate from a PIV slot.
func (t *Transport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.GetPIVCertificateResponse
	if err := t.rpcCall(ctx, "xkms.exportPIVCertificate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GeneratePIVCSR generates a Certificate Signing Request for a PIV slot key.
func (t *Transport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.GeneratePIVCSRResponse
	if err := t.rpcCall(ctx, "xkms.generatePIVCSR", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Barrier Operations

// BarrierInitialize initializes the barrier by generating a root key and sealing it.
func (t *Transport) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.initialize", req, nil)
}

// BarrierUnseal unseals the barrier by loading and decrypting the root key.
func (t *Transport) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.unseal", req, nil)
}

// BarrierSeal transitions the barrier to sealed state, zeroing the DEK.
func (t *Transport) BarrierSeal(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.seal", nil, nil)
}

// BarrierStatus returns the current barrier status.
func (t *Transport) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierStatusResponse
	if err := t.rpcCall(ctx, "barrier.status", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierInitializeShamir initializes the barrier using Shamir secret sharing.
func (t *Transport) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierInitializeShamirResponse
	if err := t.rpcCall(ctx, "barrier.initializeShamir", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierUnsealWithShare submits a single Shamir share toward the quorum.
func (t *Transport) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierUnsealShareResponse
	if err := t.rpcCall(ctx, "barrier.unsealShare", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierUnsealWithShares submits all Shamir shares at once.
func (t *Transport) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.unsealShares", req, nil)
}

// BarrierRekey rotates Shamir shares while keeping the same root key.
func (t *Transport) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierRekeyResponse
	if err := t.rpcCall(ctx, "barrier.rekey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys for disaster recovery.
func (t *Transport) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierRecoveryKeysResponse
	if err := t.rpcCall(ctx, "barrier.generateRecoveryKeys", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierEnableEncryption migrates a previously-unencrypted barrier to a keyed
// strategy in place.
func (t *Transport) BarrierEnableEncryption(ctx context.Context, req *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierEnableEncryptionResponse
	if err := t.rpcCall(ctx, "barrier.enableEncryption", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierRecoverWithKeys unseals the barrier using recovery keys.
func (t *Transport) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.recoverWithKeys", req, nil)
}

// BarrierDeleteRecoveryKeys deletes stored recovery key metadata.
func (t *Transport) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.deleteRecoveryKeys", nil, nil)
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (t *Transport) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierHasRecoveryKeysResponse
	if err := t.rpcCall(ctx, "barrier.hasRecoveryKeys", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierGenerateRootToken generates a one-time root token.
func (t *Transport) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.BarrierRootTokenResponse
	if err := t.rpcCall(ctx, "barrier.generateRootToken", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PIN Operations

// SetSOPIN sets the Security Officer PIN.
func (t *Transport) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.setSOPIN", req, nil)
}

// SetUserPIN sets the user PIN.
func (t *Transport) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.setUserPIN", req, nil)
}

// ChangeSOPIN changes the Security Officer PIN.
func (t *Transport) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.changeSOPIN", req, nil)
}

// ChangeUserPIN changes the user PIN.
func (t *Transport) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.changeUserPIN", req, nil)
}

// VerifySOPIN verifies the Security Officer PIN.
func (t *Transport) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.verifySOPIN", req, nil)
}

// VerifyUserPIN verifies the user PIN.
func (t *Transport) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.verifyUserPIN", req, nil)
}

// GetLockoutStatus returns the current PIN lockout status.
func (t *Transport) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.LockoutStatusResponse
	if err := t.rpcCall(ctx, "xkms.getLockoutStatus", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ResetLockout resets the PIN lockout counter.
func (t *Transport) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.resetLockout", req, nil)
}

// Password Store Operations

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PasswordAddResponse
	if err := t.rpcCall(ctx, "xkms.passwordAdd", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PasswordGetResponse
	if err := t.rpcCall(ctx, "xkms.passwordGet", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PasswordListResponse
	if err := t.rpcCall(ctx, "xkms.passwordList", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.passwordUpdate", req, nil)
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.passwordDelete", req, nil)
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.passwordStoreUnlock", req, nil)
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.passwordStoreLock", nil, nil)
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PasswordStoreStatusResponse
	if err := t.rpcCall(ctx, "xkms.passwordStoreStatus", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.passwordStoreSetAccessMode", req, nil)
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PasswordGenerateResponse
	if err := t.rpcCall(ctx, "xkms.passwordGenerate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Platform Store Operations

// SealStorePut stores a secret in the platform store.
func (t *Transport) SealStorePut(ctx context.Context, _ *transport.SealStorePutRequest) error {
	return ErrNotSupported
}

// SealStoreGet retrieves a secret from the platform store.
func (t *Transport) SealStoreGet(ctx context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, ErrNotSupported
}

// SealStoreDelete deletes a secret from the platform store.
func (t *Transport) SealStoreDelete(ctx context.Context, _ *transport.SealStoreDeleteRequest) error {
	return ErrNotSupported
}

// SealStoreList lists all stored secret names.
func (t *Transport) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, ErrNotSupported
}

// SealStoreReseal reseals a secret with the current sealing key.
func (t *Transport) SealStoreReseal(ctx context.Context, _ *transport.SealStoreResealRequest) error {
	return ErrNotSupported
}

// SealStoreStatus returns the platform store status.
func (t *Transport) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, ErrNotSupported
}

// Policy Operations

// PolicyCreate creates a new PCR policy.
func (t *Transport) PolicyCreate(ctx context.Context, _ *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, ErrNotSupported
}

// PolicyGet retrieves a policy by name.
func (t *Transport) PolicyGet(ctx context.Context, _ *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, ErrNotSupported
}

// PolicyList lists all policies.
func (t *Transport) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	return nil, ErrNotSupported
}

// PolicyDelete deletes a policy.
func (t *Transport) PolicyDelete(ctx context.Context, _ *transport.PolicyDeleteRequest) error {
	return ErrNotSupported
}

// PolicyRefresh refreshes a policy with current PCR values.
func (t *Transport) PolicyRefresh(ctx context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, ErrNotSupported
}

// PolicyVerify verifies a policy against current PCR values.
func (t *Transport) PolicyVerify(ctx context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, ErrNotSupported
}

// PolicyExport exports a policy.
func (t *Transport) PolicyExport(ctx context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, ErrNotSupported
}

// CustodianGroupService methods.

// CreateCustodianGroup creates a new custodian group.
func (t *Transport) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	var result transport.CreateCustodianGroupResponse
	if err := t.rpcCall(ctx, "xkms.createCustodianGroup", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCustodianGroup retrieves a custodian group by ID.
func (t *Transport) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	params := map[string]string{"group_id": groupID}
	var result transport.GetCustodianGroupResponse
	if err := t.rpcCall(ctx, "xkms.getCustodianGroup", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListCustodianGroups returns all custodian groups.
func (t *Transport) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	var result transport.ListCustodianGroupsResponse
	if err := t.rpcCall(ctx, "xkms.listCustodianGroups", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteCustodianGroup deletes a custodian group by ID.
func (t *Transport) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	params := map[string]string{"group_id": groupID}
	return t.rpcCall(ctx, "xkms.deleteCustodianGroup", params, nil)
}

// AddCustodianMember adds a member to a custodian group.
func (t *Transport) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	var result transport.AddCustodianMemberResponse
	if err := t.rpcCall(ctx, "xkms.addCustodianMember", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (t *Transport) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	return t.rpcCall(ctx, "xkms.removeCustodianMember", req, nil)
}

// DistributeShares triggers share distribution for a custodian group.
func (t *Transport) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	var result transport.DistributeSharesResponse
	if err := t.rpcCall(ctx, "xkms.distributeShares", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ShareService methods.

// SubmitShare submits a Shamir share for storage.
func (t *Transport) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	var result transport.SubmitShareResponse
	if err := t.rpcCall(ctx, "xkms.submitShare", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListShares returns all stored shares.
func (t *Transport) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	var result transport.ListSharesResponse
	if err := t.rpcCall(ctx, "xkms.listShares", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetShareCollectionStatus returns the share collection status for a group.
func (t *Transport) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	params := map[string]string{"group_id": groupID}
	var result transport.ShareCollectionStatus
	if err := t.rpcCall(ctx, "xkms.getShareCollectionStatus", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TenantService methods.

// CreateTenant creates a new tenant.
func (t *Transport) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	var result transport.CreateTenantResponse
	if err := t.rpcCall(ctx, "xkms.createTenant", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTenant retrieves a tenant by ID.
func (t *Transport) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	params := map[string]string{"tenant_id": tenantID}
	var result transport.GetTenantResponse
	if err := t.rpcCall(ctx, "xkms.getTenant", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListTenants returns all tenants.
func (t *Transport) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	var result transport.ListTenantsResponse
	if err := t.rpcCall(ctx, "xkms.listTenants", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteTenant deletes a tenant by ID.
func (t *Transport) DeleteTenant(ctx context.Context, tenantID string) error {
	params := map[string]string{"tenant_id": tenantID}
	return t.rpcCall(ctx, "xkms.deleteTenant", params, nil)
}

// TenantBarrierInit initializes the barrier for a tenant.
func (t *Transport) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	return t.rpcCall(ctx, "xkms.tenantBarrierInit", req, nil)
}

// TenantBarrierUnseal unseals the barrier for a tenant.
func (t *Transport) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	return t.rpcCall(ctx, "xkms.tenantBarrierUnseal", req, nil)
}

// TenantBarrierStatus reports the status of a per-tenant barrier.
func (t *Transport) TenantBarrierStatus(ctx context.Context, tenantID string) (*transport.TenantBarrierStatusResponse, error) {
	params := map[string]string{"tenant_id": tenantID}
	var result transport.TenantBarrierStatusResponse
	if err := t.rpcCall(ctx, "xkms.tenantBarrierStatus", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateTenantEntitlements updates a tenant's feature entitlements.
func (t *Transport) UpdateTenantEntitlements(ctx context.Context, req *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	var result transport.UpdateTenantEntitlementsResponse
	if err := t.rpcCall(ctx, "xkms.updateTenantEntitlements", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas.
func (t *Transport) UpdateTenantQuotas(ctx context.Context, req *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	var result transport.UpdateTenantQuotasResponse
	if err := t.rpcCall(ctx, "xkms.updateTenantQuotas", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Init Ceremony Methods

// GetInitStatus returns the current init ceremony state.
func (t *Transport) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	var result transport.InitStatusResponse
	if err := t.rpcCall(ctx, "init.getStatus", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (t *Transport) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	var result transport.ClaimCertBeginResponse
	if err := t.rpcCall(ctx, "init.claimCertBegin", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimCertComplete completes the certificate claim by verifying the officer's signature.
func (t *Transport) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	var result transport.ClaimCertCompleteResponse
	if err := t.rpcCall(ctx, "init.claimCertComplete", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimShare retrieves the Shamir share for the named officer.
func (t *Transport) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	var result transport.ClaimShareResponse
	if err := t.rpcCall(ctx, "init.claimShare", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignCSRInit signs a CSR during initialization with SO authorization.
func (t *Transport) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	var result transport.SignCSRInitResponse
	if err := t.rpcCall(ctx, "init.signCSR", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Credential Management Methods

// SubmitCredential submits a credential for manual mode.
func (t *Transport) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	var result transport.CredentialSubmitResponse
	if err := t.rpcCall(ctx, "credentials.submit", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCredentialStrategy returns the configured credential strategy.
func (t *Transport) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	var result transport.CredentialStrategyResponse
	if err := t.rpcCall(ctx, "credentials.strategy", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ==================== User Operations ====================
//
// User management over the MCP transport is not yet wired; the CLI/webui
// reach xkms user management via the REST transport. These stubs keep the
// Client interface satisfied.

// CreateUser is not supported over the MCP transport.
func (t *Transport) CreateUser(ctx context.Context, _ *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, ErrNotSupported
}

// ListUsers is not supported over the MCP transport.
func (t *Transport) ListUsers(ctx context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, ErrNotSupported
}

// GetUser is not supported over the MCP transport.
func (t *Transport) GetUser(ctx context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, ErrNotSupported
}

// DeleteUser is not supported over the MCP transport.
func (t *Transport) DeleteUser(ctx context.Context, _ string) error {
	return ErrNotSupported
}

// EnableUser is not supported over the MCP transport.
func (t *Transport) EnableUser(ctx context.Context, _ string) error {
	return ErrNotSupported
}

// DisableUser is not supported over the MCP transport.
func (t *Transport) DisableUser(ctx context.Context, _ string) error {
	return ErrNotSupported
}

// BindUserCert is not supported over the MCP transport.
func (t *Transport) BindUserCert(ctx context.Context, _, _ string, _ int64) error {
	return ErrNotSupported
}

// ListUserCredentials is not supported over the MCP transport.
func (t *Transport) ListUserCredentials(ctx context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, ErrNotSupported
}

// Compile-time interface assertion.
var _ transport.Client = (*Transport)(nil)
