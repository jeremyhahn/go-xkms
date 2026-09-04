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
// The MCP transport speaks the real Model Context Protocol over Streamable
// HTTP (github.com/mark3labs/mcp-go): every xkms operation is invoked as an
// MCP tool call against the unified qrdb MCP server, mTLS-authenticated and
// TLS-only. The tool name is "xkms_" plus the legacy JSON-RPC method name
// with its dots replaced by underscores (see xkmsmcp.ToolName), and each
// tool takes one optional string argument, "params_json", carrying the
// method's params encoded exactly as the legacy JSON-RPC request carried
// them. The tool's result is a single JSON text content item; tool-level
// failures come back as an MCP tool error (IsError=true with a text
// message).
package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	mcpclient "github.com/mark3labs/mcp-go/client"
	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
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

// RPCError is a typed error for a failed MCP tool call: either a tool-level
// failure (a CallToolResult with IsError=true, whose text content becomes
// Message) or a legacy-formatted server error text that still embeds a
// JSON-RPC 2.0 code. See newToolError for how Code is recovered from the
// tool's text content.
type RPCError struct {
	Code    int
	Message string
}

// Error implements the error interface.
func (e *RPCError) Error() string {
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

// ReceiveError is a typed error for MCP tool-call failures that never
// produced a usable result: a transport/network failure, a protocol-level
// JSON-RPC error on the "tools/call" request itself (e.g. an unknown tool
// name), or any other failure CallTool reports before a CallToolResult is
// available. It is the Streamable HTTP analogue of the previous transport's
// TCP read failure: the previous implementation could distinguish a failed
// write from a failed read because it owned the socket directly; the MCP
// client library performs the request and reads the response as one
// operation, so both failure modes collapse into ReceiveError here.
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

// SendError is a typed error retained for API compatibility with the
// previous TCP transport, whose rpcCall could observe a request-write
// failure distinct from a response-read failure. The Streamable HTTP
// client library performs a tool call as one send-and-receive operation, so
// rpcCall no longer has a distinct write-phase failure to report here; any
// such failure now surfaces as ReceiveError. SendError is unused by rpcCall
// but kept so callers that still type-assert against it (e.g. the sdk/go
// re-export) continue to compile.
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
	"/api/v1/keys/wrap-by-id":    "xkms.wrapKeyByID",
	"/api/v1/keys/unwrap-by-id":  "xkms.unwrapKeyByID",
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

	// Audit
	"/api/v1/audit": "xkms.queryAudit",

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

// mcpEndpointPath is the Streamable HTTP path the unified qrdb MCP server
// mounts the xkms tool surface under.
const mcpEndpointPath = "/mcp"

// clientName and clientVersion identify this SDK to the MCP server during
// the "initialize" handshake.
const (
	clientName    = "go-xkms-sdk"
	clientVersion = "1.0.0"
)

// Transport implements the transport.Client interface over the Model
// Context Protocol's Streamable HTTP transport. Every xkms operation is
// invoked as a "tools/call" request against the unified qrdb MCP server;
// see the package doc for the tool-naming and argument convention.
type Transport struct {
	config    *transport.Config
	client    *mcpclient.Client
	connected bool
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

// Connect establishes an MCP Streamable HTTP session with the xkms server:
// it builds the mTLS HTTP client, starts the Streamable HTTP transport,
// negotiates the MCP protocol version with Initialize, and confirms the
// session is usable with an "xkms_health" tool call before returning.
func (t *Transport) Connect(ctx context.Context) error {
	addr := t.config.Address
	// Strip any http/https scheme prefix if present; the scheme is derived
	// from TLSEnabled below instead.
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimSuffix(addr, "/")

	var tlsConfig *tls.Config
	scheme := "http://"
	if t.config.TLSEnabled {
		cfg, err := t.buildTLSConfig()
		if err != nil {
			return err
		}
		tlsConfig = cfg
		scheme = "https://"
	}
	baseURL := scheme + addr + mcpEndpointPath

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	mcpClient, err := mcpclient.NewStreamableHttpClient(baseURL, mcptransport.WithHTTPBasicClient(httpClient))
	if err != nil {
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
	}

	if startErr := mcpClient.Start(ctx); startErr != nil {
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("%v", startErr)}
	}

	initReq := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: clientName, Version: clientVersion},
			Capabilities:    mcp.ClientCapabilities{},
		},
	}
	if _, initErr := mcpClient.Initialize(ctx, initReq); initErr != nil {
		if closeErr := mcpClient.Close(); closeErr != nil {
			return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("initialize failed: %v (close error: %v)", initErr, closeErr)}
		}
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("initialize failed: %v", initErr)}
	}

	t.client = mcpClient
	// Mark connected before the health check so rpcCall doesn't reject the
	// request with ErrNotConnected.
	t.connected = true

	if _, healthErr := t.Health(ctx); healthErr != nil {
		t.connected = false
		if closeErr := mcpClient.Close(); closeErr != nil {
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

// Close closes the MCP session.
func (t *Transport) Close() error {
	t.connected = false
	if t.client != nil {
		return t.client.Close()
	}
	return nil
}

// Healthy checks if the transport can communicate with the server.
func (t *Transport) Healthy(ctx context.Context) bool {
	if t.client == nil {
		return false
	}

	_, err := t.Health(ctx)
	return err == nil
}

// Conn returns the underlying MCP client.
func (t *Transport) Conn() interface{} {
	return t.client
}

// IsConnected returns whether the transport is connected.
func (t *Transport) IsConnected() bool {
	return t.connected
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Request performs an MCP tool call to the xkms server.
// The method parameter is a REST-style path that gets mapped to a JSON-RPC
// method name, which in turn addresses an MCP tool.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	if !t.connected {
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

// rpcErrorPattern recovers a JSON-RPC-style error code from a tool-error
// message, for a server that still embeds the legacy "<label> error <code>:
// <message>" text (e.g. the format the previous TCP transport's RPCError
// and jsonrpcError types rendered) inside the MCP tool result.
var rpcErrorPattern = regexp.MustCompile(`^(?:JSON-RPC|rpc) error (-?\d+): (.*)$`)

// toolErrorCode classifies a tool-error message into a JSON-RPC 2.0 error
// code by best-effort keyword matching. It mirrors the sentinel-to-code
// mapping the xkms MCP server applies server-side when it turns a service
// error into wire text (see pkg/api/mcp/errors_keyops.go mapKeyOpError):
// not-found and validation failures read back as Invalid params, capability
// gaps and unsupported operations read back as Method not found, and
// authorization failures read back as their dedicated xkms extension codes.
// Anything unrecognized is an Internal error, the same default the old
// transport used for opaque server failures.
func toolErrorCode(message string) int {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "not supported"), strings.Contains(lower, "unimplemented"), strings.Contains(lower, "method not found"):
		return xkmsmcp.ErrCodeMethodNotFound
	case strings.Contains(lower, "unauthorized"), strings.Contains(lower, "unauthenticated"):
		return xkmsmcp.ErrCodeUnauthorized
	case strings.Contains(lower, "forbidden"), strings.Contains(lower, "permission denied"):
		return xkmsmcp.ErrCodeForbidden
	case strings.Contains(lower, "unavailable"):
		return xkmsmcp.ErrCodeServiceUnavailable
	case strings.Contains(lower, "not found"), strings.Contains(lower, "invalid"), strings.Contains(lower, "validation"):
		return xkmsmcp.ErrCodeInvalidParams
	default:
		return xkmsmcp.ErrCodeInternalError
	}
}

// newToolError converts a tool-level MCP error result (IsError=true) into an
// *RPCError. The MCP tool surface carries the failure as a text message
// rather than a structured JSON-RPC error object, so the code is recovered
// two ways: rpcErrorPattern first, in case the server still embeds a
// legacy-formatted code; otherwise toolErrorCode classifies the message by
// keyword, matching xkms's own sentinel-to-code table.
func newToolError(result *mcp.CallToolResult) error {
	message := "tool call failed"
	if len(result.Content) > 0 {
		if text, ok := mcp.AsTextContent(result.Content[0]); ok && text.Text != "" {
			message = text.Text
		}
	}
	if m := rpcErrorPattern.FindStringSubmatch(message); m != nil {
		if code, err := strconv.Atoi(m[1]); err == nil {
			return &RPCError{Code: code, Message: m[2]}
		}
	}
	return &RPCError{Code: toolErrorCode(message), Message: message}
}

// rpcCall invokes method as an MCP tool call. params, when non-nil, is
// marshaled to JSON and passed as the tool's single "params_json" string
// argument, exactly as the legacy JSON-RPC request carried it. On success,
// the tool's first text content item is unmarshaled into result (when
// result is non-nil); a tool-level failure (IsError=true) becomes an
// *RPCError, and any failure to complete the tool call at all becomes a
// *ReceiveError.
func (t *Transport) rpcCall(ctx context.Context, method string, params interface{}, result interface{}) error {
	if !t.connected {
		return ErrNotConnected
	}

	args := map[string]any{}
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return &MarshalError{Operation: "request params", Err: err}
		}
		args["params_json"] = string(data)
	}

	toolResult, err := t.client.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      xkmsmcp.ToolName(method),
			Arguments: args,
		},
	})
	if err != nil {
		return &ReceiveError{Err: err}
	}

	if toolResult.IsError {
		return newToolError(toolResult)
	}

	if result == nil || len(toolResult.Content) == 0 {
		return nil
	}

	text, ok := mcp.AsTextContent(toolResult.Content[0])
	if !ok {
		return &UnmarshalError{Operation: "result", Err: errors.New("tool result content is not text")}
	}
	if text.Text == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(text.Text), result); err != nil {
		return &UnmarshalError{Operation: "result", Err: err}
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

// Algorithms reports the algorithms the server supports.
func (t *Transport) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
	var result transport.AlgorithmsResponse
	if err := t.rpcCall(ctx, "xkms.algorithms", nil, &result); err != nil {
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
// ImportKey sends the import to the MCP server.
//
// The params value is built field by field into the handler's own
// xkmsmcp.ImportKeyParams rather than marshalling req directly. Marshalling req
// looked equivalent and was not: the two structs name the key material
// differently ("wrapped_key_material" here, "wrapped_key" there), so every
// import over this transport arrived with no key at all, and aes_key_size,
// hash and partition were dropped with it (go-xkms#159). Naming the struct
// makes a rename on either side a compile error instead of a silent runtime
// break, which is the property the old code lacked.
//
// TenantID is deliberately not forwarded: this transport's handlers take the
// tenant from the authenticated caller (see tenantForRequest in pkg/api/mcp)
// and reject a wire-supplied one. Stamping it on the imported key is go-xkms
// #163/#222 and is not settled here.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.ImportKeyParams{
		KeyID:       req.KeyID,
		Backend:     req.Backend,
		KeyType:     req.KeyType,
		KeySize:     req.KeySize,
		Curve:       req.Curve,
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   req.Algorithm,
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
		AESKeySize:  req.AESKeySize,
		Hash:        req.Hash,
		Partition:   req.Partition,
	}

	var result transport.ImportKeyResponse
	if err := t.rpcCall(ctx, "xkms.importKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportKey exports a key.
// ExportKey exports a key in wrapped form.
//
// The audit in go-xkms#255 found this pair already agreeing, so building the
// params by name changes nothing that travels. It is done anyway so that a
// later rename on either side is a compile error rather than a silent drop,
// which is the failure mode the other four ops were in.
func (t *Transport) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.ExportKeyParams{
		KeyID:     req.KeyID,
		Backend:   req.Backend,
		Algorithm: req.Algorithm,
	}

	var result transport.ExportKeyResponse
	if err := t.rpcCall(ctx, "xkms.exportKey", params, &result); err != nil {
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

// pemEncodePKIXPublicKey renders a DER-encoded PKIX public key as the PEM text
// the MCP handlers expect, and returns "" for no key at all.
//
// The wrapping public key crosses this boundary in two different encodings:
// transport.WrapKeyRequest and UnwrapKeyRequest carry DER bytes, while the MCP
// params carry PEM text that the handler feeds to pem.Decode and
// x509.ParsePKIXPublicKey. Assigning the DER into the string field marshals it
// as base64 — non-empty, plausible-looking, and rejected by pem.Decode with a
// bare "invalid wrapping public key PEM" (go-xkms#255).
//
// An empty input yields an empty string rather than an empty PEM block, so an
// omitted optional key stays omitted instead of becoming a value the handler
// would try to parse.
func pemEncodePKIXPublicKey(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// WrapKey wraps key material for secure transport.
//
// Params are built by name into the handler's own struct rather than
// marshalled from req: the two disagree on the wrapping key's field name AND
// its encoding, so marshalling req sent nothing the handler could read, and
// dropped backend and key_spec besides. See pemEncodePKIXPublicKey.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.WrapKeyParams{
		KeyMaterial:          req.KeyMaterial,
		WrappingPublicKeyPEM: pemEncodePKIXPublicKey(req.WrappingPublicKey),
		ImportToken:          req.ImportToken,
		Algorithm:            req.Algorithm,
		Backend:              req.Backend,
		KeySpec:              req.KeySpec,
	}

	var result transport.WrapKeyResponse
	if err := t.rpcCall(ctx, "xkms.wrapKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UnwrapKey unwraps key material.
//
// Params are built by name for the reason WrapKey gives. The material itself is
// "wrapped_key_material" on the request and "wrapped_key" in the params, which
// is the go-xkms#159 defect repeated verbatim on this path.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.UnwrapKeyParams{
		WrappedKey:        req.WrappedKeyMaterial,
		Algorithm:         req.Algorithm,
		ImportToken:       req.ImportToken,
		WrappingPublicKey: pemEncodePKIXPublicKey(req.WrappingPublicKey),
		Metadata:          req.Metadata,
		Backend:           req.Backend,
		KeySpec:           req.KeySpec,
	}

	var result transport.UnwrapKeyResponse
	if err := t.rpcCall(ctx, "xkms.unwrapKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WrapKeyByID wraps a key using another key, both identified by their IDs.
func (t *Transport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	var result transport.WrapKeyByIDResponse
	if err := t.rpcCall(ctx, "xkms.wrapKeyByID", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (t *Transport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	var result transport.UnwrapKeyByIDResponse
	if err := t.rpcCall(ctx, "xkms.unwrapKeyByID", req, &result); err != nil {
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
// CopyKey copies a key from one backend to another.
//
// Params are built by name so the pair cannot drift. Note what this does NOT
// fix: xkmsmcp.CopyKeyParams carries hash and aes_key_size, and
// transport.CopyKeyRequest has no field for either, so no caller of this
// transport can populate them. That gap is go-xkms#155 and closing it means
// deciding whether the request struct gains the fields on every transport --
// the gRPC CopyKeyRequest message would need them too. Left alone deliberately
// rather than papered over here.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.CopyKeyParams{
		SourceBackend: req.SourceBackend,
		SourceKeyID:   req.SourceKeyID,
		DestBackend:   req.DestBackend,
		DestKeyID:     req.DestKeyID,
		KeyType:       req.KeyType,
		Algorithm:     req.Algorithm,
		KeySize:       req.KeySize,
		Curve:         req.Curve,
	}

	var result transport.CopyKeyResponse
	if err := t.rpcCall(ctx, "xkms.copyKey", params, &result); err != nil {
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

// GetShare returns a single stored share. Share material is never included
// in the response — the server returns metadata only.
func (t *Transport) GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*transport.ShareInfo, error) {
	var result transport.ShareInfo
	if err := t.rpcCall(ctx, "xkms.getShare", shareParams(serverURL, groupID, shareIndex), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteShare removes a single stored share.
func (t *Transport) DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	var result struct{}
	return t.rpcCall(ctx, "xkms.deleteShare", shareParams(serverURL, groupID, shareIndex), &result)
}

// shareParams builds the JSON-RPC parameter object addressing a single share.
func shareParams(serverURL, groupID string, shareIndex int) map[string]any {
	return map[string]any{
		"server_url":  serverURL,
		"group_id":    groupID,
		"share_index": shareIndex,
	}
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

// AuditService methods.

// QueryAudit returns one page of audit events from the tamper-evident audit
// chain owned by the embedded qrdb node.
func (t *Transport) QueryAudit(ctx context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	if filter == nil {
		return nil, transport.ErrInvalidRequest
	}
	var result transport.AuditPage
	if err := t.rpcCall(ctx, "xkms.queryAudit", filter, &result); err != nil {
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
func (t *Transport) ClaimShareBegin(ctx context.Context, req *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	var result transport.ClaimShareBeginResponse
	if err := t.rpcCall(ctx, "init.claimShareBegin", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimShareComplete completes the Shamir share claim handshake for the named
// officer.
func (t *Transport) ClaimShareComplete(ctx context.Context, req *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	var result transport.ClaimShareCompleteResponse
	if err := t.rpcCall(ctx, "init.claimShareComplete", req, &result); err != nil {
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
