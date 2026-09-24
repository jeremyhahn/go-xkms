// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package mcptool provides the transport-agnostic machinery for talking to
// the unified qrdb MCP server's Streamable HTTP "tools/call" surface:
// connection setup (including mTLS and SPKI-pinned TLS), the MCP protocol
// handshake, marshaling a params/result pair through one MCP tool call per
// method, and decoding a failing call's go-qrdb wire.ErrorEnvelope.
//
// It exists as its own leaf package, with no dependency on pkg/api/mcp's
// dispatch core or its xkms-specific error taxonomy, so that every client in
// this module can build on the same session and tool-call code without risk
// of an import cycle. That risk is not hypothetical: pkg/api/mcp's Server
// holds an sdk/go/client/ssh.Client for its SSH sub-system
// (Config.SSHClient), so a client package that both (a) is reachable from
// sdk/go/client/ssh and (b) depends on pkg/api/mcp would cycle back through
// it. pkg/api/transport/mcp (the REST-style xkms SDK transport) and
// sdk/go/client/ssh's MCP client both build on this package instead of
// keeping their own copy of the connection and tool-call code.
//
// # Error classification is envelope-only
//
// A failing tool call is classified from go-qrdb's wire.ErrorEnvelope in the
// result's StructuredContent (see wire.DecodeErrorPayload) and from nothing
// else. go-qrdb#438 deleted the fail-open pattern of guessing a
// classification from the failure's prose; this package does not bring it
// back. A result with no envelope is reported as *EnvelopeMissingError, a
// protocol error, never degraded into a guess.
//
// RPCError.WireCode carries go-qrdb's raw classification untranslated;
// RPCError.Code carries a caller-specific numeric code translated from it by
// an optional ErrorClassifier (see WithErrorClassifier), for callers that
// need parity with a legacy vocabulary (pkg/api/transport/mcp's xkms
// JSON-RPC codes). A Client with no classifier leaves Code at 0 and expects
// callers to branch on WireCode instead.
package mcptool

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	mcpclient "github.com/mark3labs/mcp-go/client"
	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// endpointPath is the Streamable HTTP path the unified qrdb MCP server
// mounts its tool surface under.
const endpointPath = "/mcp"

// clientName and clientVersion identify this module's clients to the MCP
// server during the "initialize" handshake.
const (
	clientName    = "go-xkms-sdk"
	clientVersion = "1.0.0"
)

// ToolName maps a JSON-RPC-style method name onto its MCP tool name: dots
// become underscores and the name is prefixed with "xkms_" unless the
// method already carries the xkms namespace. This is the single canonical
// implementation of the xkms tool-naming convention; pkg/api/mcp.ToolName
// delegates to it rather than keeping a second copy.
func ToolName(method string) string {
	name := strings.ReplaceAll(method, ".", "_")
	if !strings.HasPrefix(name, "xkms_") {
		name = "xkms_" + name
	}
	return name
}

var (
	// ErrNotConnected is returned when a Call or Healthy is attempted on a
	// Client that has not completed Connect.
	ErrNotConnected = errors.New("mcptool: client not connected")

	// ErrConnectionFailed is returned when Connect fails to establish or
	// negotiate the MCP session.
	ErrConnectionFailed = errors.New("mcptool: connection failed")
)

// RPCError is a typed error for a failed MCP tool call whose result carried
// go-qrdb's wire.ErrorEnvelope in its StructuredContent. WireCode is the
// envelope's raw classification (go-qrdb's shared 17-code vocabulary), never
// guessed from prose; Code is WireCode translated onto a caller-specific
// numeric vocabulary via an optional ErrorClassifier, or 0 when the Client
// carries none. Message is the envelope's message.
type RPCError struct {
	Code     int
	WireCode wire.Code
	Message  string
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d (%s): %s", e.Code, e.WireCode, e.Message)
}

// EnvelopeMissingError is returned when an MCP tool call fails but its
// result carries no go-qrdb wire.ErrorEnvelope in StructuredContent. A
// server built on pkg/apimodule/module_mcp.go's codedToolResult stamps one
// onto every failing xkms tool result, so a missing envelope means the
// response did not come from that contract; it is reported as a protocol
// error rather than degraded into a guess parsed from text
// (go-qrdb#438, go-xkms#797).
type EnvelopeMissingError struct {
	Tool    string
	Message string
}

// Error implements the error interface.
func (e *EnvelopeMissingError) Error() string {
	return fmt.Sprintf("mcp: tool %s failed with no error envelope: %s", e.Tool, e.Message)
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
func (e *MarshalError) Unwrap() error { return e.Err }

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
func (e *UnmarshalError) Unwrap() error { return e.Err }

// ReceiveError is a typed error for MCP tool-call failures that never
// produced a usable result: a transport/network failure, a protocol-level
// JSON-RPC error on the "tools/call" request itself (e.g. an unknown tool
// name), or any other failure CallTool reports before a CallToolResult is
// available.
type ReceiveError struct {
	Err error
}

// Error implements the error interface.
func (e *ReceiveError) Error() string {
	return fmt.Sprintf("failed to receive response: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ReceiveError) Unwrap() error { return e.Err }

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
func (e *TLSSetupError) Unwrap() error { return e.Err }

// ErrorClassifier turns go-qrdb's wire.Code into a caller-specific numeric
// code (pkg/api/transport/mcp's xkms JSON-RPC vocabulary, via its
// wireCodeToRPCCode table). A Client without a classifier leaves RPCError.Code
// at 0; callers should branch on RPCError.WireCode instead in that case.
type ErrorClassifier func(code wire.Code) int

// ClientOption configures a Client at construction.
type ClientOption func(*Client)

// WithErrorClassifier sets the Client's ErrorClassifier.
func WithErrorClassifier(classify ErrorClassifier) ClientOption {
	return func(c *Client) { c.classify = classify }
}

// Client is a session against the unified qrdb MCP server's Streamable HTTP
// tool-call surface. It owns the underlying mcp-go client and connection
// state; Call is the sole request path once Connect succeeds.
type Client struct {
	config    *transport.Config
	client    *mcpclient.Client
	connected bool
	classify  ErrorClassifier
}

// NewClient constructs a Client for cfg. cfg must be non-nil; callers apply
// transport.Option values to a transport.DefaultConfig() (or their own
// config) before calling NewClient, exactly as pkg/api/transport/mcp.New
// does today.
func NewClient(cfg *transport.Config, opts ...ClientOption) *Client {
	c := &Client{config: cfg}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewClientWithSession wraps an already-started mcp-go client (one whose
// Start/Initialize the caller has already run, e.g.
// mcpclient.NewInProcessClient for an in-process test) as a Client in the
// connected state, skipping Connect's HTTP dial and MCP handshake. This is a
// deliberate escape hatch for exactly that scenario, not a general
// constructor: production callers use NewClient and Connect.
func NewClientWithSession(cfg *transport.Config, session *mcpclient.Client, opts ...ClientOption) *Client {
	c := NewClient(cfg, opts...)
	c.client = session
	c.connected = true
	return c
}

// Connect establishes an MCP Streamable HTTP session: it builds the mTLS
// HTTP client, starts the Streamable HTTP transport, and negotiates the MCP
// protocol version with Initialize. It does not perform an application-level
// health check; callers that want one (e.g. Transport.Connect's "xkms_health"
// tool call) issue it themselves once Connect returns successfully.
func (c *Client) Connect(ctx context.Context) error {
	addr := c.config.Address
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimSuffix(addr, "/")

	var tlsConfig *tls.Config
	scheme := "http://"
	if c.config.TLSEnabled {
		cfg, err := c.buildTLSConfig()
		if err != nil {
			return err
		}
		tlsConfig = cfg
		scheme = "https://"
	}
	baseURL := scheme + addr + endpointPath

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

	c.client = mcpClient
	c.connected = true
	return nil
}

// buildTLSConfig constructs the TLS configuration from the client's
// transport.Config.
func (c *Client) buildTLSConfig() (*tls.Config, error) {
	if c.config.TLSConfig != nil {
		return c.config.TLSConfig, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if c.config.TLSCAFile != "" {
		caCert, err := os.ReadFile(c.config.TLSCAFile)
		if err != nil {
			return nil, &TLSSetupError{Detail: "failed to read CA certificate", Err: err}
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, &TLSSetupError{Detail: "failed to parse CA certificate"}
		}
		tlsConfig.RootCAs = caCertPool
	}

	if c.config.TLSCertFile != "" && c.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.config.TLSCertFile, c.config.TLSKeyFile)
		if err != nil {
			return nil, &TLSSetupError{Detail: "failed to load client certificate", Err: err}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if c.config.SPKIPin != "" {
		if c.config.TLSCAFile == "" && tlsConfig.RootCAs == nil {
			// Trust bootstrap: no CA cert available, SPKI pin IS the trust anchor.
			tlsConfig = spki.NewPinnedTLSConfig(c.config.SPKIPin)
		} else {
			// Additive: CA chain validated first, pin adds extra verification.
			tlsConfig.VerifyConnection = spki.VerifyConnection(c.config.SPKIPin)
		}
	}

	return tlsConfig, nil
}

// Close closes the MCP session. It is safe to call on a Client that never
// connected, and on a nil *Client (a zero-value Transport embeds a nil
// core; see pkg/api/transport/mcp's not-connected coverage tests).
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.connected = false
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Conn returns the underlying mcp-go client, or nil for a nil *Client.
func (c *Client) Conn() interface{} {
	if c == nil {
		return nil
	}
	return c.client
}

// IsConnected returns whether Connect has completed successfully and Close
// has not since been called. It is nil-receiver-safe for the same reason
// Close is.
func (c *Client) IsConnected() bool {
	return c != nil && c.connected
}

// Config returns the Client's transport configuration, or nil for a nil
// *Client.
func (c *Client) Config() *transport.Config {
	if c == nil {
		return nil
	}
	return c.config
}

// Call invokes method as an MCP tool call. params, when non-nil, is
// marshaled to JSON and passed as the tool's single "params_json" string
// argument. On success, the tool's first text content item is unmarshaled
// into result (when result is non-nil); a tool-level failure (IsError=true)
// is classified from its go-qrdb wire.ErrorEnvelope into an *RPCError, or
// into an *EnvelopeMissingError when the result carries no envelope, and any
// failure to complete the tool call at all becomes a *ReceiveError.
func (c *Client) Call(ctx context.Context, method string, params, result interface{}) error {
	if !c.IsConnected() {
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

	toolName := ToolName(method)
	toolResult, err := c.client.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		},
	})
	if err != nil {
		return &ReceiveError{Err: err}
	}

	if toolResult.IsError {
		return c.newToolError(toolName, toolResult)
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

// newToolError converts a tool-level MCP error result (IsError=true) into a
// typed error: a result carrying go-qrdb's wire.ErrorEnvelope in its
// StructuredContent becomes an *RPCError classified by CODE, via c.classify
// when set; a result with no envelope becomes an *EnvelopeMissingError. There
// is no text-based fallback classification (go-qrdb#438, go-xkms#797) --
// "Don't invent a text channel."
func (c *Client) newToolError(tool string, result *mcp.CallToolResult) error {
	payload, ok := wire.DecodeErrorPayload(result.StructuredContent)
	if !ok {
		return &EnvelopeMissingError{Tool: tool, Message: extractToolErrorText(result)}
	}

	var code int
	if c.classify != nil {
		code = c.classify(payload.Code)
	}
	return &RPCError{Code: code, WireCode: payload.Code, Message: payload.Message}
}

// extractToolErrorText returns the first text content item's text from a
// failing tool result, or a fallback when the result carries no content at
// all.
func extractToolErrorText(result *mcp.CallToolResult) string {
	if len(result.Content) > 0 {
		if text, ok := mcp.AsTextContent(result.Content[0]); ok && text.Text != "" {
			return text.Text
		}
	}
	return "tool call failed"
}
