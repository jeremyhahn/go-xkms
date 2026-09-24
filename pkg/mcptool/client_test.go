// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcptool

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// ----------------------------------------------------------------------------
// ToolName.
// ----------------------------------------------------------------------------

func TestToolName_PrefixesAndReplacesDots(t *testing.T) {
	if got, want := ToolName("xkms.generateKey"), "xkms_generateKey"; got != want {
		t.Errorf("ToolName(%q) = %q, want %q", "xkms.generateKey", got, want)
	}
	if got, want := ToolName("ssh.keys.sign"), "xkms_ssh_keys_sign"; got != want {
		t.Errorf("ToolName(%q) = %q, want %q", "ssh.keys.sign", got, want)
	}
}

func TestToolName_AlreadyNamespacedIsNotDoublePrefixed(t *testing.T) {
	if got, want := ToolName("xkms_health"), "xkms_health"; got != want {
		t.Errorf("ToolName(%q) = %q, want %q (must not double-prefix)", "xkms_health", got, want)
	}
}

// ----------------------------------------------------------------------------
// buildTLSConfig.
// ----------------------------------------------------------------------------

func TestBuildTLSConfig_PreConfigured(t *testing.T) {
	expected := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := transport.DefaultConfig()
	cfg.TLSConfig = expected

	c := NewClient(cfg)
	result, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if result != expected {
		t.Errorf("buildTLSConfig() did not return the pre-configured *tls.Config")
	}
}

func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = "/nonexistent/path/ca.pem"

	c := NewClient(cfg)
	_, err := c.buildTLSConfig()
	if err == nil {
		t.Fatal("expected an error for an unreadable CA file")
	}
	var tlsErr *TLSSetupError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("expected *TLSSetupError, got %T: %v", err, err)
	}
	if !strings.Contains(tlsErr.Error(), "failed to read CA certificate") {
		t.Errorf("Error() = %q", tlsErr.Error())
	}
}

func TestBuildTLSConfig_DefaultPath(t *testing.T) {
	cfg := transport.DefaultConfig()
	c := NewClient(cfg)

	result, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if result.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want tls.VersionTLS13", result.MinVersion)
	}
}

// ----------------------------------------------------------------------------
// Call / Connect, against a real in-process MCP Streamable HTTP server.
// ----------------------------------------------------------------------------

// serverResponse is what a fake tool handler returns: exactly one of Result
// (success) or ErrorMessage (a failing tool result) should be set. When
// ErrorMessage is set alongside a non-zero Envelope, the result also carries
// go-qrdb's wire.ErrorEnvelope in StructuredContent; ErrorMessage alone
// (Envelope left at wire.CodeOK) produces an uncoded tool failure.
type serverResponse struct {
	Result       string
	ErrorMessage string
	Envelope     wire.Code
}

// newTestServer starts a real mcp-go Streamable HTTP server exposing one
// tool per name in handlers.
func newTestServer(t *testing.T, handlers map[string]func(args map[string]any) serverResponse) (string, func()) {
	t.Helper()
	srv := mcpserver.NewMCPServer("mcptool-test", "1.0.0")
	for name, handler := range handlers {
		handler := handler
		srv.AddTool(mcpgo.Tool{Name: name}, func(_ context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			resp := handler(req.GetArguments())
			switch {
			case resp.ErrorMessage != "" && resp.Envelope != wire.CodeOK:
				res := mcpgo.NewToolResultError(resp.ErrorMessage)
				res.StructuredContent = wire.NewErrorEnvelope(name, resp.Envelope, resp.ErrorMessage)
				return res, nil
			case resp.ErrorMessage != "":
				return mcpgo.NewToolResultError(resp.ErrorMessage), nil
			default:
				return mcpgo.NewToolResultText(resp.Result), nil
			}
		})
	}
	httpServer := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath(endpointPath))
	testServer := httptest.NewServer(httpServer)
	return strings.TrimPrefix(testServer.URL, "http://"), testServer.Close
}

func connectedClient(t *testing.T, addr string, opts ...ClientOption) *Client {
	t.Helper()
	cfg := transport.DefaultConfig()
	cfg.Address = addr
	c := NewClient(cfg, opts...)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClient_ConnectAndCall_Success(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{"status":"ok"}`} },
	})
	defer cleanup()

	c := connectedClient(t, addr)
	if !c.IsConnected() {
		t.Fatal("expected IsConnected() to be true after Connect")
	}

	var result map[string]string
	if err := c.Call(context.Background(), "health", nil, &result); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("result = %v", result)
	}
}

func TestClient_Call_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "127.0.0.1:0"
	c := NewClient(cfg)

	err := c.Call(context.Background(), "health", nil, nil)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

func TestClient_Call_ToolErrorWithoutClassifier(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
		"xkms_ssh_keys_get": func(map[string]any) serverResponse {
			return serverResponse{ErrorMessage: "key not found", Envelope: wire.CodeNotFound}
		},
	})
	defer cleanup()

	c := connectedClient(t, addr)

	err := c.Call(context.Background(), "ssh.keys.get", nil, nil)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected *RPCError, got %T: %v", err, err)
	}
	if rpcErr.Message != "key not found" {
		t.Errorf("Message = %q", rpcErr.Message)
	}
	if rpcErr.WireCode != wire.CodeNotFound {
		t.Errorf("WireCode = %v, want CodeNotFound", rpcErr.WireCode)
	}
	if rpcErr.Code != 0 {
		t.Errorf("Code = %d, want 0 (no classifier configured)", rpcErr.Code)
	}
}

func TestClient_Call_ToolErrorWithClassifier(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
		"xkms_ssh_keys_get": func(map[string]any) serverResponse {
			return serverResponse{ErrorMessage: "key not found", Envelope: wire.CodeNotFound}
		},
	})
	defer cleanup()

	classify := func(code wire.Code) int {
		if code == wire.CodeNotFound {
			return -32004
		}
		return -32000
	}
	c := connectedClient(t, addr, WithErrorClassifier(classify))

	err := c.Call(context.Background(), "ssh.keys.get", nil, nil)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected *RPCError, got %T: %v", err, err)
	}
	if rpcErr.Code != -32004 {
		t.Errorf("Code = %d, want -32004", rpcErr.Code)
	}
	if rpcErr.WireCode != wire.CodeNotFound {
		t.Errorf("WireCode = %v, want CodeNotFound", rpcErr.WireCode)
	}
}

func TestClient_Call_UnmarshalErrorOnMistypedResult(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health":       func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
		"xkms_ssh_keys_get": func(map[string]any) serverResponse { return serverResponse{Result: `"surprise"`} },
	})
	defer cleanup()

	c := connectedClient(t, addr)

	var out map[string]string
	err := c.Call(context.Background(), "ssh.keys.get", nil, &out)
	var unmarshalErr *UnmarshalError
	if !errors.As(err, &unmarshalErr) {
		t.Fatalf("expected *UnmarshalError, got %T: %v", err, err)
	}
	if unmarshalErr.Unwrap() == nil {
		t.Error("the underlying json error should be unwrappable")
	}
}

func TestClient_Call_MarshalErrorOnUnmarshalableParams(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
	})
	defer cleanup()

	c := connectedClient(t, addr)

	err := c.Call(context.Background(), "health", make(chan int), nil)
	var marshalErr *MarshalError
	if !errors.As(err, &marshalErr) {
		t.Fatalf("expected *MarshalError, got %T: %v", err, err)
	}
}

func TestClient_Call_EnvelopeMissingBecomesProtocolError(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health":       func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
		"xkms_ssh_keys_get": func(map[string]any) serverResponse { return serverResponse{ErrorMessage: "boom, no envelope"} },
	})
	defer cleanup()

	c := connectedClient(t, addr)

	err := c.Call(context.Background(), "ssh.keys.get", nil, nil)
	var envErr *EnvelopeMissingError
	if !errors.As(err, &envErr) {
		t.Fatalf("expected *EnvelopeMissingError, got %T: %v", err, err)
	}
	if envErr.Message != "boom, no envelope" {
		t.Errorf("Message = %q", envErr.Message)
	}
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		t.Error("an uncoded failure must not be reported as a classified *RPCError")
	}
}

func TestClient_Connect_DialFailure(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "127.0.0.1:1" // reserved, nothing listens here
	c := NewClient(cfg)

	err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("expected a connect failure against an unreachable address")
	}
	if !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("expected ErrConnectionFailed in the chain, got %v", err)
	}
}

func TestClient_Close_Idempotent(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
	})
	defer cleanup()

	cfg := transport.DefaultConfig()
	cfg.Address = addr
	c := NewClient(cfg)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close must also be nil: %v", err)
	}
	if c.IsConnected() {
		t.Error("IsConnected() must be false after Close")
	}
}

func TestClient_Close_NeverConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	c := NewClient(cfg)
	if err := c.Close(); err != nil {
		t.Fatalf("Close on a never-connected client must be a no-op, got: %v", err)
	}
}

func TestClient_Conn_ReturnsUnderlyingClient(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
	})
	defer cleanup()

	c := connectedClient(t, addr)
	if c.Conn() == nil {
		t.Error("Conn() must be non-nil once connected")
	}
}

func TestClient_Config_ReturnsConstructorConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "example:1234"
	c := NewClient(cfg)
	if c.Config() != cfg {
		t.Error("Config() must return the same *transport.Config passed to NewClient")
	}
}

type discardParams struct {
	Name string `json:"name"`
}

func TestClient_Call_ParamsRoundTrip(t *testing.T) {
	var gotArgs map[string]any
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
		"xkms_ssh_keys_get": func(args map[string]any) serverResponse {
			gotArgs = args
			return serverResponse{Result: `{"ok":true}`}
		},
	})
	defer cleanup()

	c := connectedClient(t, addr)
	if err := c.Call(context.Background(), "ssh.keys.get", discardParams{Name: "laptop"}, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}

	paramsJSON, _ := gotArgs["params_json"].(string)
	var decoded discardParams
	if err := json.Unmarshal([]byte(paramsJSON), &decoded); err != nil {
		t.Fatalf("decode params_json: %v", err)
	}
	if decoded.Name != "laptop" {
		t.Errorf("Name = %q", decoded.Name)
	}
}

// TestNewClientWithSession proves the in-process-test escape hatch marks the
// Client connected without a Connect dial.
func TestNewClientWithSession(t *testing.T) {
	cfg := transport.DefaultConfig()
	c := NewClientWithSession(cfg, nil)
	if !c.IsConnected() {
		t.Error("NewClientWithSession must leave the Client connected")
	}
}
