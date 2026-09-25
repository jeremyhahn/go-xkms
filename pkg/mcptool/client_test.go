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
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
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

func TestBuildTLSConfig_ValidCAFile(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca.CertPEM, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caPath
	c := NewClient(cfg)

	result, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if result.RootCAs == nil {
		t.Error("RootCAs must be populated from a valid CA file")
	}
}

func TestBuildTLSConfig_UnparseableCAPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("this is not a PEM certificate"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caPath
	c := NewClient(cfg)

	_, err := c.buildTLSConfig()
	var tlsErr *TLSSetupError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("expected *TLSSetupError, got %T: %v", err, err)
	}
	if !strings.Contains(tlsErr.Error(), "failed to parse CA certificate") {
		t.Errorf("Error() = %q", tlsErr.Error())
	}
}

func TestBuildTLSConfig_ValidClientCert(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
	if err != nil {
		t.Fatalf("GenerateTestClientCert: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, clientCert.CertPEM, 0o600); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
	if err := os.WriteFile(keyPath, clientCert.KeyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	cfg := transport.DefaultConfig()
	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath
	c := NewClient(cfg)

	result, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1", len(result.Certificates))
	}
}

func TestBuildTLSConfig_InvalidClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	cfg := transport.DefaultConfig()
	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath
	c := NewClient(cfg)

	_, err := c.buildTLSConfig()
	var tlsErr *TLSSetupError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("expected *TLSSetupError, got %T: %v", err, err)
	}
	if !strings.Contains(tlsErr.Error(), "failed to load client certificate") {
		t.Errorf("Error() = %q", tlsErr.Error())
	}
}

func TestBuildTLSConfig_SPKIPinWithoutCAFileIsTrustBootstrap(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.SPKIPin = "deadbeef"
	c := NewClient(cfg)

	result, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !result.InsecureSkipVerify {
		t.Error("an SPKI pin with no CA file must produce the trust-bootstrap config (InsecureSkipVerify with pin-only verification)")
	}
	if result.VerifyConnection == nil {
		t.Error("VerifyConnection must be set to enforce the pin")
	}
}

func TestBuildTLSConfig_SPKIPinWithCAFileIsAdditive(t *testing.T) {
	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca.CertPEM, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := transport.DefaultConfig()
	cfg.TLSCAFile = caPath
	cfg.SPKIPin = "deadbeef"
	c := NewClient(cfg)

	result, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if result.InsecureSkipVerify {
		t.Error("an SPKI pin alongside a CA file must not skip CA chain validation")
	}
	if result.RootCAs == nil {
		t.Error("the CA file's pool must still be populated")
	}
	if result.VerifyConnection == nil {
		t.Error("VerifyConnection must add the pin check on top of chain validation")
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

// newRawToolServer starts a real mcp-go Streamable HTTP server whose tool
// handlers return a *mcpgo.CallToolResult directly, for shapes newTestServer's
// serverResponse abstraction cannot express (non-text content, a failing
// result carrying no content at all).
func newRawToolServer(t *testing.T, handlers map[string]mcpserver.ToolHandlerFunc) (string, func()) {
	t.Helper()
	srv := mcpserver.NewMCPServer("mcptool-raw-test", "1.0.0")
	for name, handler := range handlers {
		srv.AddTool(mcpgo.Tool{Name: name}, handler)
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

// TestClient_Connect_InvalidURLFailsBeforeDialing proves an address that
// cannot form a valid URL (an embedded control character, rejected by
// net/url.Parse) is reported through the same ErrConnectionFailed family as
// a dial failure, from the transport-construction step rather than a dial.
func TestClient_Connect_InvalidURLFailsBeforeDialing(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "exa\x00mple.com"
	c := NewClient(cfg)

	err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("expected a connect failure for an address that cannot form a valid URL")
	}
	if !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("expected ErrConnectionFailed in the chain, got %v", err)
	}
}

// TestClient_Connect_TLSSetupFailurePropagates proves Connect surfaces a
// buildTLSConfig failure directly rather than attempting to dial with a
// broken TLS configuration.
func TestClient_Connect_TLSSetupFailurePropagates(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = "/nonexistent/path/ca.pem"
	c := NewClient(cfg)

	err := c.Connect(context.Background())
	var tlsErr *TLSSetupError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("expected *TLSSetupError from buildTLSConfig, got %T: %v", err, err)
	}
}

// TestClient_ConnectAndCall_TLSSuccess proves Connect's TLSEnabled path
// (mTLS/SPKI-pinned "https://" dial) completes a real handshake and tool
// call end to end, using SPKI trust bootstrap so no CA file is needed.
func TestClient_ConnectAndCall_TLSSuccess(t *testing.T) {
	srv := mcpserver.NewMCPServer("mcptool-tls-test", "1.0.0")
	srv.AddTool(mcpgo.Tool{Name: "xkms_health"}, func(_ context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		return mcpgo.NewToolResultText(`{"status":"ok"}`), nil
	})
	httpServer := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath(endpointPath))
	testServer := httptest.NewTLSServer(httpServer)
	defer testServer.Close()

	leaf := testServer.Certificate()
	pin, err := spki.ComputePin(leaf)
	if err != nil {
		t.Fatalf("ComputePin: %v", err)
	}

	cfg := transport.DefaultConfig()
	cfg.Address = strings.TrimPrefix(testServer.URL, "https://")
	cfg.TLSEnabled = true
	cfg.SPKIPin = pin
	c := NewClient(cfg)

	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Close() }()

	var result map[string]string
	if err := c.Call(context.Background(), "health", nil, &result); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("result = %v", result)
	}
}

// TestClient_Call_ReceiveErrorOnTransportFailure proves a transport-level
// failure from CallTool itself (the server having gone away, as distinct
// from a tool-level IsError result) becomes a *ReceiveError.
func TestClient_Call_ReceiveErrorOnTransportFailure(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: `{}`} },
	})
	c := connectedClient(t, addr)
	cleanup() // the server is gone; the next call must fail at the transport

	err := c.Call(context.Background(), "health", nil, nil)
	var recvErr *ReceiveError
	if !errors.As(err, &recvErr) {
		t.Fatalf("expected *ReceiveError, got %T: %v", err, err)
	}
}

// TestClient_Call_NonTextContentBecomesUnmarshalError proves a successful
// tool result whose first content item is not text (e.g. an image) is
// reported as *UnmarshalError rather than passed to json.Unmarshal.
func TestClient_Call_NonTextContentBecomesUnmarshalError(t *testing.T) {
	addr, cleanup := newRawToolServer(t, map[string]mcpserver.ToolHandlerFunc{
		"xkms_health": func(_ context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return &mcpgo.CallToolResult{
				Content: []mcpgo.Content{
					mcpgo.ImageContent{Type: mcpgo.ContentTypeImage, Data: "YQ==", MIMEType: "image/png"},
				},
			}, nil
		},
	})
	defer cleanup()

	c := connectedClient(t, addr)
	var out map[string]string
	err := c.Call(context.Background(), "health", nil, &out)
	var unmarshalErr *UnmarshalError
	if !errors.As(err, &unmarshalErr) {
		t.Fatalf("expected *UnmarshalError, got %T: %v", err, err)
	}
	if !strings.Contains(unmarshalErr.Error(), "not text") {
		t.Errorf("Error() = %q, want it to name the non-text content", unmarshalErr.Error())
	}
}

// TestClient_Call_EmptyTextResultReturnsNil proves a successful tool result
// carrying an empty text payload is treated as "nothing to decode" rather
// than a json.Unmarshal failure on an empty string.
func TestClient_Call_EmptyTextResultReturnsNil(t *testing.T) {
	addr, cleanup := newTestServer(t, map[string]func(args map[string]any) serverResponse{
		"xkms_health": func(map[string]any) serverResponse { return serverResponse{Result: ""} },
	})
	defer cleanup()

	c := connectedClient(t, addr)
	var out map[string]string
	if err := c.Call(context.Background(), "health", nil, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out != nil {
		t.Errorf("out = %v, want nil (no decode attempted on empty text)", out)
	}
}

// TestClient_Call_ErrorResultWithNoContentUsesFallbackMessage proves a
// failing tool result that carries no content at all (so there is no text to
// report) still surfaces a stable, non-empty message rather than the empty
// string.
func TestClient_Call_ErrorResultWithNoContentUsesFallbackMessage(t *testing.T) {
	addr, cleanup := newRawToolServer(t, map[string]mcpserver.ToolHandlerFunc{
		"xkms_health": func(_ context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return &mcpgo.CallToolResult{IsError: true}, nil
		},
	})
	defer cleanup()

	c := connectedClient(t, addr)
	err := c.Call(context.Background(), "health", nil, nil)
	var envErr *EnvelopeMissingError
	if !errors.As(err, &envErr) {
		t.Fatalf("expected *EnvelopeMissingError, got %T: %v", err, err)
	}
	if envErr.Message != "tool call failed" {
		t.Errorf("Message = %q, want the fallback \"tool call failed\"", envErr.Message)
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
