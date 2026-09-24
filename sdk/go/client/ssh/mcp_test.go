// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package ssh_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	"github.com/jeremyhahn/go-xkms/pkg/mcptool"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ----------------------------------------------------------------------------
// Fake MCP server: a real mcp-go Streamable HTTP server exposing the ssh.*
// tool surface, matching what the unified qrdb MCP server serves in
// production (pkg/apimodule.RegisterMCP registers one tool per
// xkmsmcp.ModuleMethods() entry, dispatching to pkg/api/mcp.Server.
// InvokeMethod, whose SSH errors pass through mapSSHError onto a real
// go-qrdb wire.ErrorEnvelope). sdkssh.NewMCP reaches this exact tool-call
// framing through pkg/mcptool, so this fixture is the same shape as
// pkg/mcptool's own client_test.go newTestServer / pkg/api/transport/mcp's
// startMockServer.
// ----------------------------------------------------------------------------

// sshMethods is every JSON-RPC method the SDK's MCP SSH client calls, plus
// "health". Each is pre-registered as an MCP tool at server construction
// (mcp-go has no wildcard tool registration), so tests toggle behavior
// through fakeMCPServer.handle/ok/fail rather than registering tools
// per-test.
var sshMethods = []string{
	"health",
	"ssh.keys.generate",
	"ssh.keys.import",
	"ssh.keys.get",
	"ssh.keys.list",
	"ssh.keys.delete",
	"ssh.keys.export",
	"ssh.keys.sign",
	"ssh.knownHosts.add",
	"ssh.knownHosts.list",
	"ssh.knownHosts.remove",
	"ssh.knownHosts.verify",
	"ssh.authorizedKeys.add",
	"ssh.authorizedKeys.get",
	"ssh.authorizedKeys.list",
	"ssh.authorizedKeys.remove",
	"ssh.authorizedKeys.emit",
	"ssh.authorizedKeys.verify",
}

// mcpCall is one recorded tool call as it arrived, decoded back to its
// JSON-RPC method name and params.
type mcpCall struct {
	Method string
	Params json.RawMessage
}

// mcpHandler produces the JSON-RPC-shaped result for a method. A non-empty
// message makes the server answer with a tool-level error instead; when
// code is non-zero (not wire.CodeOK) the error also carries a go-qrdb
// wire.ErrorEnvelope, exactly as the real server's mapSSHError-backed
// dispatch does.
type mcpHandler func(params json.RawMessage) (result interface{}, message string, code wire.Code)

type fakeMCPServer struct {
	t          *testing.T
	testServer *httptest.Server

	handlers map[string]mcpHandler

	// rawResponse, when set for a method, is returned verbatim as the tool's
	// text content instead of a marshaled handler result — used to exercise
	// a server whose response body is malformed or the wrong shape.
	rawResponse map[string]string

	mu    sync.Mutex
	calls []mcpCall
}

func newFakeMCPServer(t *testing.T) *fakeMCPServer {
	t.Helper()
	s := &fakeMCPServer{
		t:           t,
		handlers:    map[string]mcpHandler{},
		rawResponse: map[string]string{},
	}
	// Health always succeeds unless a test overrides it.
	s.handlers["health"] = func(json.RawMessage) (interface{}, string, wire.Code) {
		return map[string]string{"status": "ok"}, "", wire.CodeOK
	}

	mcpSrv := mcpserver.NewMCPServer("xkms-ssh-test", "1.0.0")
	for _, method := range sshMethods {
		method := method
		mcpSrv.AddTool(mcpgo.Tool{Name: mcptool.ToolName(method)}, func(_ context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			paramsJSON, _ := req.GetArguments()["params_json"].(string)
			var params json.RawMessage
			if paramsJSON != "" {
				params = json.RawMessage(paramsJSON)
			}

			s.mu.Lock()
			s.calls = append(s.calls, mcpCall{Method: method, Params: params})
			raw, hasRaw := s.rawResponse[method]
			handler, hasHandler := s.handlers[method]
			s.mu.Unlock()

			if hasRaw {
				return mcpgo.NewToolResultText(raw), nil
			}
			if !hasHandler {
				res := mcpgo.NewToolResultError("method not found: " + method)
				res.StructuredContent = wire.NewErrorEnvelope(mcptool.ToolName(method), wire.CodeUnimplemented, "method not found: "+method)
				return res, nil
			}
			result, message, code := handler(params)
			if message != "" {
				res := mcpgo.NewToolResultError(message)
				if code != wire.CodeOK {
					res.StructuredContent = wire.NewErrorEnvelope(mcptool.ToolName(method), code, message)
				}
				return res, nil
			}
			body, err := json.Marshal(result)
			if err != nil {
				res := mcpgo.NewToolResultError(err.Error())
				res.StructuredContent = wire.NewErrorEnvelope(mcptool.ToolName(method), wire.CodeInternal, err.Error())
				return res, nil
			}
			return mcpgo.NewToolResultText(string(body)), nil
		})
	}

	httpServer := mcpserver.NewStreamableHTTPServer(mcpSrv)
	s.testServer = httptest.NewServer(httpServer)
	t.Cleanup(s.testServer.Close)
	return s
}

// close shuts the server down immediately, for tests that need the server
// to become unreachable mid-test rather than at cleanup.
func (s *fakeMCPServer) close() { s.testServer.Close() }

func (s *fakeMCPServer) addr() string { return strings.TrimPrefix(s.testServer.URL, "http://") }

func (s *fakeMCPServer) handle(method string, fn mcpHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = fn
}

func (s *fakeMCPServer) ok(method string, result interface{}) {
	s.handle(method, func(json.RawMessage) (interface{}, string, wire.Code) { return result, "", wire.CodeOK })
}

// fail registers method to answer with a coded tool error, exactly as the
// real server's mapSSHError-backed dispatch classifies an SSH failure.
func (s *fakeMCPServer) fail(method string, code wire.Code, message string) {
	s.handle(method, func(json.RawMessage) (interface{}, string, wire.Code) { return nil, message, code })
}

// failUncoded registers method to answer with a tool error carrying no
// go-qrdb wire envelope at all — a response that did not come from the
// real server's classification contract.
func (s *fakeMCPServer) failUncoded(method string, message string) {
	s.handle(method, func(json.RawMessage) (interface{}, string, wire.Code) { return nil, message, wire.CodeOK })
}

// lastCall returns the most recent recorded call for method.
func (s *fakeMCPServer) lastCall(method string) *mcpCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.calls) - 1; i >= 0; i-- {
		if s.calls[i].Method == method {
			c := s.calls[i]
			return &c
		}
	}
	return nil
}

func (s *fakeMCPServer) allCalls() []mcpCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]mcpCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// newMCPFixture returns a connected SDK MCP client for srv.
func newMCPFixture(t *testing.T, srv *fakeMCPServer) sdkssh.Client {
	t.Helper()
	client, err := sdkssh.NewMCP(sdkssh.MCPOptions{Addr: srv.addr()})
	if err != nil {
		t.Fatalf("NewMCP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// paramsOf decodes the recorded params of the last call to method.
func paramsOf(t *testing.T, srv *fakeMCPServer, method string) map[string]interface{} {
	t.Helper()
	call := srv.lastCall(method)
	if call == nil {
		t.Fatalf("server never received %s (saw %v)", method, methodNames(srv.allCalls()))
	}
	var out map[string]interface{}
	if err := json.Unmarshal(call.Params, &out); err != nil {
		t.Fatalf("decode params of %s: %v", method, err)
	}
	return out
}

func methodNames(calls []mcpCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.Method)
	}
	return out
}

// ----------------------------------------------------------------------------
// Constructor / connection lifecycle.
// ----------------------------------------------------------------------------

func TestNewMCP_MissingAddr(t *testing.T) {
	_, err := sdkssh.NewMCP(sdkssh.MCPOptions{})
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
	if nilErr.Field != "Addr" {
		t.Errorf("Field = %q", nilErr.Field)
	}
}

func TestNewMCP_DialFailure(t *testing.T) {
	// Bind and immediately close to get an address nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}

	_, err = sdkssh.NewMCP(sdkssh.MCPOptions{Addr: addr})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if !strings.Contains(protoErr.Message, "connect") {
		t.Errorf("Message = %q, want a connect failure", protoErr.Message)
	}
	if !errors.Is(err, mcptool.ErrConnectionFailed) {
		t.Errorf("expected mcptool.ErrConnectionFailed in the chain, got %v", err)
	}
}

// TestNewMCP_HealthCheckPerformed pins the connect-time health probe: without
// it, a server that never serves the ssh.* tools would only be detected on
// the first real call.
func TestNewMCP_HealthCheckPerformed(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)
	_ = client

	call := srv.lastCall("health")
	if call == nil {
		t.Fatal("NewMCP did not perform a health check")
	}
}

func TestNewMCP_HealthCheckFailureIsFatal(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("health", wire.CodeUnavailable, "not ready")

	_, err := sdkssh.NewMCP(sdkssh.MCPOptions{Addr: srv.addr()})
	if err == nil {
		t.Fatal("a failing health check must abort the connect")
	}
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if !strings.Contains(protoErr.Error(), "health check") {
		t.Errorf("error should name the health check: %v", err)
	}
}

// TestMCP_RepeatedCallsReachServer pins that each call on the connected
// client reaches the server with its own recorded params, independent of
// how many calls preceded it.
func TestMCP_RepeatedCallsReachServer(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.list", map[string]interface{}{"items": []interface{}{}})
	client := newMCPFixture(t, srv)

	for i := 0; i < 3; i++ {
		if _, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{}); err != nil {
			t.Fatalf("List: %v", err)
		}
	}

	calls := srv.allCalls()
	listCalls := 0
	for _, c := range calls {
		if c.Method == "ssh.keys.list" {
			listCalls++
		}
	}
	if listCalls != 3 {
		t.Errorf("server saw %d ssh.keys.list calls, want 3", listCalls)
	}
}

func TestMCPClose_Idempotent(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// A second Close on an already-closed session must not panic, whatever
	// the underlying HTTP client reports.
	_ = client.Close()
}

// ----------------------------------------------------------------------------
// Error surfaces.
// ----------------------------------------------------------------------------

func TestMCP_ServerErrorBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.get", wire.CodeInvalidArgument, "key not found")
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	// wire.CodeInvalidArgument reconstitutes as *InvalidRequestError, the
	// bucket a not-found/duplicate/mismatch/validation failure all share --
	// see mcp.go's package doc comment.
	var invalidErr *sdkssh.InvalidRequestError
	if !errors.As(err, &invalidErr) {
		t.Fatalf("expected *InvalidRequestError in the chain, got %T %v", err, err)
	}
	if invalidErr.Message != "key not found" {
		t.Errorf("Message = %q", invalidErr.Message)
	}
}

// TestMCP_NotFoundCodeBecomesNotFoundError proves a store NotFound error
// (issue #769: "keys-store errors fall through to Internal") reconstructs as
// *NotFoundError instead of the generic *ProtocolError every SSH store error
// used to collapse into. go-qrdb's wire.ErrorEnvelope carries only Code and
// Message (no Resource field -- see mcp.go's package doc comment), so
// Resource stays empty; Message survives intact.
func TestMCP_NotFoundCodeBecomesNotFoundError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.get", wire.CodeNotFound, "ssh/keys: key not found: ghost")
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"})
	var notFound *sdkssh.NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *NotFoundError, got %T %v", err, err)
	}
	if notFound.Message != "ssh/keys: key not found: ghost" {
		t.Errorf("Message = %q", notFound.Message)
	}
}

// TestMCP_DuplicateCodeBecomesDuplicateError covers the known_hosts/
// authorized_keys "Add called twice" case, which REST reports as 409.
func TestMCP_DuplicateCodeBecomesDuplicateError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.knownHosts.add", wire.CodeAlreadyExists, "pin already exists")
	client := newMCPFixture(t, srv)

	err := client.KnownHosts().Add(context.Background(), sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com", PublicKey: "ssh-ed25519 AAAA",
	})
	var dupErr *sdkssh.DuplicateError
	if !errors.As(err, &dupErr) {
		t.Fatalf("expected *DuplicateError, got %T %v", err, err)
	}
	if dupErr.Message != "pin already exists" {
		t.Errorf("Message = %q", dupErr.Message)
	}
}

// TestMCP_MismatchCodeBecomesMismatchError proves a known_hosts host-key
// mismatch (the MITM-indicating case the issue calls out by name) round-trips
// as *MismatchError, not a bare *ProtocolError a caller cannot branch on.
// Host and Received come from Verify's own parameters (mcpKnownHostsClient.
// Verify fills them in locally -- see mcp.go); Expected has no wire source
// and stays empty, a real, documented gap rather than a fabrication.
func TestMCP_MismatchCodeBecomesMismatchError(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.fail("ssh.knownHosts.verify", wire.CodeFailedPrecondition, "host key mismatch for git.example.com")
	client := newMCPFixture(t, srv)

	err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub)
	var mismatch *sdkssh.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchError, got %T %v", err, err)
	}
	if mismatch.Host != "git.example.com" {
		t.Errorf("Host = %q, want %q", mismatch.Host, "git.example.com")
	}
	if mismatch.Received != gossh.FingerprintSHA256(sshPub) {
		t.Errorf("Received = %q, want the presented key's own fingerprint", mismatch.Received)
	}
	if mismatch.Expected != "" {
		t.Errorf("Expected = %q, want empty (the wire has no field for it)", mismatch.Expected)
	}
}

// TestMCP_UnknownCodeStaysProtocolErrorNotLeaked proves a code this SDK does
// not recognize still surfaces as *ProtocolError (never as one of the typed
// store errors) and carries only the server's own message -- it must not
// synthesize additional internal detail the server never sent.
func TestMCP_UnknownCodeStaysProtocolErrorNotLeaked(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.get", wire.Code(-32099), "opaque failure")
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	var notFound *sdkssh.NotFoundError
	if errors.As(err, &notFound) {
		t.Fatal("an unrecognized code must never be classified as NotFound")
	}
	if !strings.Contains(protoErr.Error(), "opaque failure") {
		t.Errorf("server message lost: %v", protoErr)
	}
}

func TestMCP_MalformedResponseBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.mu.Lock()
	srv.rawResponse["ssh.keys.list"] = "{this is not json"
	srv.mu.Unlock()
	client := newMCPFixture(t, srv)

	_, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	var unmarshalErr *mcptool.UnmarshalError
	if !errors.As(err, &unmarshalErr) {
		t.Fatalf("expected *mcptool.UnmarshalError in the chain, got %T %v", err, err)
	}
	if unmarshalErr.Unwrap() == nil {
		t.Error("the underlying decode error should be unwrappable")
	}
}

func TestMCP_WronglyTypedResultBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	// Well-formed JSON, but the wrong shape for the expected result.
	srv.mu.Lock()
	srv.rawResponse["ssh.keys.get"] = `"surprise"`
	srv.mu.Unlock()
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "k"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	var unmarshalErr *mcptool.UnmarshalError
	if !errors.As(err, &unmarshalErr) {
		t.Fatalf("expected *mcptool.UnmarshalError in the chain, got %T %v", err, err)
	}
}

// TestMCP_UncodedFailureBecomesEnvelopeMissingError proves a tool failure
// with no go-qrdb wire envelope -- one that did not come from the real
// server's mapSSHError-backed dispatch -- surfaces as a protocol error, per
// the project's no-backward-compatibility rule: there is no text-based
// fallback classification (go-xkms#797).
func TestMCP_UncodedFailureBecomesEnvelopeMissingError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.failUncoded("ssh.keys.get", "boom, no envelope")
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	var envErr *mcptool.EnvelopeMissingError
	if !errors.As(err, &envErr) {
		t.Fatalf("expected *mcptool.EnvelopeMissingError in the chain, got %T %v", err, err)
	}
}

// TestMCP_ServerUnreachableMidSessionBecomesProtocolError asserts that once
// the server goes away after a successful connect, the next call surfaces a
// typed error rather than hanging or panicking.
func TestMCP_ServerUnreachableMidSessionBecomesProtocolError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.list", map[string]interface{}{"items": []interface{}{}})
	client := newMCPFixture(t, srv)

	srv.close()

	_, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	var receiveErr *mcptool.ReceiveError
	if !errors.As(err, &receiveErr) {
		t.Fatalf("expected *mcptool.ReceiveError in the chain, got %T %v", err, err)
	}
}

// ----------------------------------------------------------------------------
// Wire-code classification (classifyMCPError, mcp.go).
// ----------------------------------------------------------------------------

func TestMCP_WireCodeClassification(t *testing.T) {
	tests := []struct {
		name string
		code wire.Code
		want func(*testing.T, error)
	}{
		{"unauthenticated", wire.CodeUnauthenticated, func(t *testing.T, err error) {
			var authErr *sdkssh.AuthError
			if !errors.As(err, &authErr) || authErr.StatusCode != 401 {
				t.Fatalf("expected *AuthError{StatusCode:401}, got %#v", err)
			}
		}},
		{"permission denied", wire.CodePermissionDenied, func(t *testing.T, err error) {
			var authErr *sdkssh.AuthError
			if !errors.As(err, &authErr) || authErr.StatusCode != 403 {
				t.Fatalf("expected *AuthError{StatusCode:403}, got %#v", err)
			}
		}},
		{"unimplemented", wire.CodeUnimplemented, func(t *testing.T, err error) {
			var niErr *sdkssh.NotImplementedError
			if !errors.As(err, &niErr) || niErr.Transport != "mcp" {
				t.Fatalf("expected *NotImplementedError{Transport:\"mcp\"}, got %#v", err)
			}
		}},
		{"unavailable", wire.CodeUnavailable, func(t *testing.T, err error) {
			var srvErr *sdkssh.ServerError
			if !errors.As(err, &srvErr) || srvErr.StatusCode != 503 {
				t.Fatalf("expected *ServerError{StatusCode:503}, got %#v", err)
			}
		}},
		{"not found (forward compatibility)", wire.CodeNotFound, func(t *testing.T, err error) {
			var nfErr *sdkssh.NotFoundError
			if !errors.As(err, &nfErr) {
				t.Fatalf("expected *NotFoundError, got %#v", err)
			}
		}},
		{"already exists (forward compatibility)", wire.CodeAlreadyExists, func(t *testing.T, err error) {
			var dupErr *sdkssh.DuplicateError
			if !errors.As(err, &dupErr) {
				t.Fatalf("expected *DuplicateError, got %#v", err)
			}
		}},
		{"invalid argument", wire.CodeInvalidArgument, func(t *testing.T, err error) {
			var invErr *sdkssh.InvalidRequestError
			if !errors.As(err, &invErr) {
				t.Fatalf("expected *InvalidRequestError, got %#v", err)
			}
		}},
		{"internal falls back to RPCError", wire.CodeInternal, func(t *testing.T, err error) {
			var rpcErr *mcptool.RPCError
			if !errors.As(err, &rpcErr) {
				t.Fatalf("expected *mcptool.RPCError, got %#v", err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeMCPServer(t)
			srv.fail("ssh.keys.get", tt.code, "classified failure")
			client := newMCPFixture(t, srv)

			_, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Name: "k"})
			if err == nil {
				t.Fatal("expected an error")
			}
			tt.want(t, err)
		})
	}
}

// ----------------------------------------------------------------------------
// Keys.
// ----------------------------------------------------------------------------

func TestMCPKeys_GenerateMethodAndParams(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.generate", map[string]interface{}{
		"scope": "user", "owner": "alice", "name": "laptop",
		"algorithm": "ed25519", "fingerprint": "SHA256:abc",
		"backend": "tpm2", "backend_key_id": "ssh-user-alice-laptop",
	})
	client := newMCPFixture(t, srv)

	key, err := client.Keys().Generate(context.Background(), sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
		Algorithm: "rsa", RSABits: 4096, Comment: "c", Backend: "tpm2",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	p := paramsOf(t, srv, "ssh.keys.generate")
	if p["algorithm"] != "rsa" {
		t.Errorf("wire algorithm = %v", p["algorithm"])
	}
	if p["rsa_bits"] != float64(4096) {
		t.Errorf("wire rsa_bits = %v, want 4096", p["rsa_bits"])
	}
	if p["backend"] != "tpm2" {
		t.Errorf("wire backend = %v", p["backend"])
	}

	if key.BackendKeyID != "ssh-user-alice-laptop" || key.Backend != "tpm2" {
		t.Errorf("backend correlation lost: %+v", key)
	}
	if key.Fingerprint != "SHA256:abc" {
		t.Errorf("Fingerprint = %q", key.Fingerprint)
	}
}

func TestMCPKeys_GenerateError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.generate", wire.CodeInvalidArgument, "unsupported algorithm")
	client := newMCPFixture(t, srv)

	if _, err := client.Keys().Generate(context.Background(), sdkssh.GenerateRequest{Algorithm: "rot13"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPKeys_ImportForwardsPEMWithoutPassphrase(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.import", map[string]interface{}{"name": "imported"})
	client := newMCPFixture(t, srv)

	pemBytes := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
	key, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Scope: "user", Owner: "alice", Name: "imported", PEM: pemBytes,
	}, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if key.Name != "imported" {
		t.Errorf("Name = %q", key.Name)
	}

	p := paramsOf(t, srv, "ssh.keys.import")
	// With no provider, no passphrase member may appear on the wire.
	if _, present := p["passphrase"]; present {
		t.Error("passphrase must be omitted when no provider is supplied")
	}
	if p["pem"] == nil {
		t.Error("pem missing from the wire body")
	}
}

func TestMCPKeys_ImportSendsProviderPassphrase(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.import", map[string]interface{}{"name": "imported"})
	client := newMCPFixture(t, srv)

	const secret = "correct horse battery staple"
	provider := secure.NewCallbackProvider(func(context.Context, string) ([]byte, error) {
		return []byte(secret), nil
	})

	if _, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Name: "imported", PEM: []byte("pem"),
	}, provider); err != nil {
		t.Fatalf("Import: %v", err)
	}

	p := paramsOf(t, srv, "ssh.keys.import")
	encoded, ok := p["passphrase"].(string)
	if !ok {
		t.Fatalf("passphrase missing/not base64 string: %v", p["passphrase"])
	}
	// []byte marshals as base64; decode and compare so a truncation bug
	// (e.g. wrong Size()) is caught.
	raw, err := json.Marshal(p["passphrase"])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded []byte
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode passphrase: %v", err)
	}
	if string(decoded) != secret {
		t.Errorf("passphrase on wire = %q, want %q (encoded %q)", decoded, secret, encoded)
	}
}

func TestMCPKeys_ImportProviderFailureAborts(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.import", map[string]interface{}{"name": "imported"})
	client := newMCPFixture(t, srv)

	wantErr := errors.New("user cancelled")
	provider := secure.NewCallbackProvider(func(context.Context, string) ([]byte, error) {
		return nil, wantErr
	})

	_, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Name: "imported", PEM: []byte("pem"),
	}, provider)
	if err == nil {
		t.Fatal("expected the provider failure to abort the import")
	}
	// Nothing may have been sent to the server.
	if srv.lastCall("ssh.keys.import") != nil {
		t.Error("import must not reach the server when the passphrase prompt fails")
	}
}

func TestMCPKeys_GetAndList(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.get", map[string]interface{}{"name": "laptop", "algorithm": "ed25519"})
	srv.ok("ssh.keys.list", map[string]interface{}{"items": []interface{}{
		map[string]interface{}{"name": "one"},
		map[string]interface{}{"name": "two"},
	}})
	client := newMCPFixture(t, srv)

	key, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if key.Name != "laptop" || key.Algorithm != "ed25519" {
		t.Errorf("key = %+v", key)
	}
	gp := paramsOf(t, srv, "ssh.keys.get")
	if gp["scope"] != "user" || gp["owner"] != "alice" || gp["name"] != "laptop" {
		t.Errorf("get params = %v", gp)
	}

	keys, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{Scope: "user"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// The items envelope must be unwrapped, in order.
	if len(keys) != 2 || keys[0].Name != "one" || keys[1].Name != "two" {
		t.Errorf("keys = %+v", keys)
	}
}

func TestMCPKeys_DeleteAndExport(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.delete", map[string]interface{}{})
	srv.ok("ssh.keys.export", map[string]interface{}{
		"algorithm": "ed25519", "line": "ssh-ed25519 AAAA x", "fingerprint": "SHA256:q",
	})
	client := newMCPFixture(t, srv)

	if err := client.Keys().Delete(context.Background(), sdkssh.DeleteKeyRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	dp := paramsOf(t, srv, "ssh.keys.delete")
	if dp["name"] != "laptop" {
		t.Errorf("delete params = %v", dp)
	}

	pub, err := client.Keys().ExportPublic(context.Background(), sdkssh.ExportRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("ExportPublic: %v", err)
	}
	if pub.Line != "ssh-ed25519 AAAA x" || pub.Fingerprint != "SHA256:q" {
		t.Errorf("pub = %+v", pub)
	}
}

func TestMCPKeys_DeleteError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.delete", wire.CodeInvalidArgument, "no such key")
	client := newMCPFixture(t, srv)

	if err := client.Keys().Delete(context.Background(), sdkssh.DeleteKeyRequest{Name: "ghost"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPKeys_SignerForwardsDigest(t *testing.T) {
	line, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.export", map[string]interface{}{"line": line, "algorithm": "ed25519"})
	srv.ok("ssh.keys.sign", map[string]interface{}{
		"format": "ssh-ed25519",
		"blob":   []byte("sig-blob"),
	})
	client := newMCPFixture(t, srv)

	signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if string(signer.PublicKey().Marshal()) != string(sshPub.Marshal()) {
		t.Error("signer public key does not match the exported key")
	}

	sig, err := signer.Sign(nil, []byte("digest-bytes"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Format != "ssh-ed25519" || string(sig.Blob) != "sig-blob" {
		t.Errorf("signature = %+v", sig)
	}

	p := paramsOf(t, srv, "ssh.keys.sign")
	var digest []byte
	rawDigest, _ := json.Marshal(p["digest"])
	if err := json.Unmarshal(rawDigest, &digest); err != nil {
		t.Fatalf("decode digest: %v", err)
	}
	if string(digest) != "digest-bytes" {
		t.Errorf("digest on wire = %q", digest)
	}
	if p["name"] != "laptop" || p["owner"] != "alice" {
		t.Errorf("sign addressed the wrong key: %v", p)
	}
}

func TestMCPKeys_SignerUnparsablePublicKey(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.export", map[string]interface{}{"line": "not-a-key"})
	client := newMCPFixture(t, srv)

	_, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if protoErr.Message != "parse exported public key" {
		t.Errorf("Message = %q", protoErr.Message)
	}
}

func TestMCPKeys_SignerExportFailure(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.keys.export", wire.CodeInvalidArgument, "no key")
	client := newMCPFixture(t, srv)

	if _, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPSigner_SignServerError(t *testing.T) {
	line, _ := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.keys.export", map[string]interface{}{"line": line})
	srv.fail("ssh.keys.sign", wire.CodeInternal, "hardware locked")
	client := newMCPFixture(t, srv)

	signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if _, err := signer.Sign(nil, []byte("x")); err == nil {
		t.Fatal("expected the server-side signing failure to propagate")
	}
}

// ----------------------------------------------------------------------------
// KnownHosts.
// ----------------------------------------------------------------------------

func TestMCPKnownHosts_AddListRemove(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.knownHosts.add", map[string]interface{}{})
	srv.ok("ssh.knownHosts.list", map[string]interface{}{"items": []interface{}{
		map[string]interface{}{"host": "git.example.com", "fingerprint": "SHA256:pin", "source": "tofu"},
	}})
	srv.ok("ssh.knownHosts.remove", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	if err := client.KnownHosts().Add(context.Background(), sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
		Fingerprint: "SHA256:pin", Algorithm: "ssh-ed25519", Source: "tofu",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ap := paramsOf(t, srv, "ssh.knownHosts.add")
	if ap["fingerprint"] != "SHA256:pin" || ap["source"] != "tofu" || ap["algorithm"] != "ssh-ed25519" {
		t.Errorf("add params = %v", ap)
	}

	pins, err := client.KnownHosts().List(context.Background(), sdkssh.ListKnownHostsRequest{Scope: "user"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 1 || pins[0].Fingerprint != "SHA256:pin" || pins[0].Source != "tofu" {
		t.Errorf("pins = %+v", pins)
	}

	if err := client.KnownHosts().Remove(context.Background(), sdkssh.RemoveKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
	}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	rp := paramsOf(t, srv, "ssh.knownHosts.remove")
	if rp["host"] != "git.example.com" {
		t.Errorf("remove params = %v", rp)
	}
}

func TestMCPKnownHosts_ListError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.knownHosts.list", wire.CodeInternal, "store offline")
	client := newMCPFixture(t, srv)

	if _, err := client.KnownHosts().List(context.Background(), sdkssh.ListKnownHostsRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

// TestMCPKnownHosts_VerifySendsPresentedKey pins the client-side wire
// encoding of the presented host key. The server must receive the actual
// key bytes (authorized_keys format), never a caller-computed fingerprint
// it would have to trust blindly.
func TestMCPKnownHosts_VerifySendsPresentedKey(t *testing.T) {
	line, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.knownHosts.verify", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	if err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	p := paramsOf(t, srv, "ssh.knownHosts.verify")
	if p["public_key"] != strings.TrimRight(line, "\n") {
		t.Errorf("public_key = %v, want %v", p["public_key"], strings.TrimRight(line, "\n"))
	}
	if _, spoofable := p["fingerprint"]; spoofable {
		t.Error("wire params must not carry a client-claimed fingerprint")
	}
	if p["host"] != "git.example.com" {
		t.Errorf("host = %v", p["host"])
	}
}

func TestMCPKnownHosts_VerifyRejectsNilKey(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	err := client.KnownHosts().Verify(context.Background(), "user", "alice", "h", nil)
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
	if srv.lastCall("ssh.knownHosts.verify") != nil {
		t.Error("a nil key must be rejected before any server round-trip")
	}
}

// TestMCPKnownHosts_VerifyServerRejectionPropagates proves a server-side
// host-key mismatch reaches the caller as an error carrying the server's
// message -- classified as *InvalidRequestError, the same bucket a
// not-found or duplicate lands on (see mapSSHError's doc comment for why
// the wire has no dedicated code for it) -- never silent trust.
func TestMCPKnownHosts_VerifyServerRejectionPropagates(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.fail("ssh.knownHosts.verify", wire.CodeInvalidArgument, "host key mismatch")
	client := newMCPFixture(t, srv)

	err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub)
	if err == nil {
		t.Fatal("a server-reported mismatch must not be treated as trust")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("error detail lost: %v", err)
	}
	var invalidErr *sdkssh.InvalidRequestError
	if !errors.As(err, &invalidErr) {
		t.Fatalf("expected *InvalidRequestError in the chain, got %T %v", err, err)
	}
}

func TestMCPKnownHosts_CallbackStripsPort(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.knownHosts.verify", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	cb := client.KnownHosts().Callback(context.Background(), "user", "alice")
	if err := cb("git.example.com:2222", &net.TCPAddr{}, sshPub); err != nil {
		t.Fatalf("callback: %v", err)
	}
	p := paramsOf(t, srv, "ssh.knownHosts.verify")
	if p["host"] != "git.example.com" {
		t.Errorf("host sent as %v; the :port suffix must be stripped", p["host"])
	}
}

// ----------------------------------------------------------------------------
// AuthorizedKeys.
// ----------------------------------------------------------------------------

func TestMCPAuthorizedKeys_AddGetListRemove(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.authorizedKeys.add", map[string]interface{}{})
	srv.ok("ssh.authorizedKeys.get", map[string]interface{}{"name": "deploy", "line": "ssh-ed25519 AAAA"})
	srv.ok("ssh.authorizedKeys.list", map[string]interface{}{"items": []interface{}{
		map[string]interface{}{"name": "deploy", "options": []interface{}{"no-pty"}},
	}})
	srv.ok("ssh.authorizedKeys.remove", map[string]interface{}{})
	client := newMCPFixture(t, srv)

	if err := client.AuthorizedKeys().Add(context.Background(), sdkssh.AddAuthorizedKeyRequest{
		Scope: "service", Owner: "svc", Name: "deploy",
		Line: "ssh-ed25519 AAAA", Options: []string{"no-pty", "command=\"/bin/deploy\""},
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ap := paramsOf(t, srv, "ssh.authorizedKeys.add")
	opts, _ := ap["options"].([]interface{})
	if len(opts) != 2 {
		t.Errorf("restriction options lost on the wire: %v", ap["options"])
	}

	entry, err := client.AuthorizedKeys().Get(context.Background(), "service", "svc", "deploy")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Name != "deploy" {
		t.Errorf("entry = %+v", entry)
	}
	gp := paramsOf(t, srv, "ssh.authorizedKeys.get")
	if gp["scope"] != "service" || gp["owner"] != "svc" || gp["name"] != "deploy" {
		t.Errorf("get params = %v", gp)
	}

	entries, err := client.AuthorizedKeys().List(context.Background(), sdkssh.ListAuthorizedKeysRequest{Scope: "service"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || len(entries[0].Options) != 1 {
		t.Errorf("entries = %+v", entries)
	}

	if err := client.AuthorizedKeys().Remove(context.Background(), "service", "svc", "deploy"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	rp := paramsOf(t, srv, "ssh.authorizedKeys.remove")
	if rp["name"] != "deploy" || rp["scope"] != "service" {
		t.Errorf("remove params = %v", rp)
	}
}

func TestMCPAuthorizedKeys_GetNotFound(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.get", wire.CodeInvalidArgument, "no entry")
	client := newMCPFixture(t, srv)

	if _, err := client.AuthorizedKeys().Get(context.Background(), "service", "svc", "ghost"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPAuthorizedKeys_ListError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.list", wire.CodeInternal, "store offline")
	client := newMCPFixture(t, srv)

	if _, err := client.AuthorizedKeys().List(context.Background(), sdkssh.ListAuthorizedKeysRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPAuthorizedKeys_RemoveError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.remove", wire.CodeInvalidArgument, "no entry")
	client := newMCPFixture(t, srv)

	if err := client.AuthorizedKeys().Remove(context.Background(), "service", "svc", "ghost"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMCPAuthorizedKeys_Emit(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.ok("ssh.authorizedKeys.emit", map[string]interface{}{"line": "no-pty ssh-ed25519 AAAA restricted"})
	client := newMCPFixture(t, srv)

	line, err := client.AuthorizedKeys().Emit(context.Background(), sdkssh.EmitRequest{
		PublicKey: "ssh-ed25519 AAAA", Options: []string{"no-pty"}, Comment: "restricted",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if line != "no-pty ssh-ed25519 AAAA restricted" {
		t.Errorf("line = %q", line)
	}
	p := paramsOf(t, srv, "ssh.authorizedKeys.emit")
	if p["public_key"] != "ssh-ed25519 AAAA" || p["comment"] != "restricted" {
		t.Errorf("emit params = %v", p)
	}
}

func TestMCPAuthorizedKeys_EmitError(t *testing.T) {
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.emit", wire.CodeInvalidArgument, "unparsable public key")
	client := newMCPFixture(t, srv)

	line, err := client.AuthorizedKeys().Emit(context.Background(), sdkssh.EmitRequest{PublicKey: "junk"})
	if err == nil {
		t.Fatal("expected error")
	}
	if line != "" {
		t.Errorf("a failed Emit must return an empty line, got %q", line)
	}
}

func TestMCPAuthorizedKeys_VerifyComputesFingerprint(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.ok("ssh.authorizedKeys.verify", map[string]interface{}{"name": "deploy"})
	client := newMCPFixture(t, srv)

	entry, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", sshPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if entry.Name != "deploy" {
		t.Errorf("entry = %+v", entry)
	}
	p := paramsOf(t, srv, "ssh.authorizedKeys.verify")
	if p["fingerprint"] != gossh.FingerprintSHA256(sshPub) {
		t.Errorf("fingerprint = %v", p["fingerprint"])
	}
	if p["algorithm"] != sshPub.Type() {
		t.Errorf("algorithm = %v", p["algorithm"])
	}
}

func TestMCPAuthorizedKeys_VerifyRejectsNilKey(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	_, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", nil)
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
	if srv.lastCall("ssh.authorizedKeys.verify") != nil {
		t.Error("a nil key must be rejected before any server round-trip")
	}
}

func TestMCPAuthorizedKeys_VerifyRejectionPropagates(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	srv := newFakeMCPServer(t)
	srv.fail("ssh.authorizedKeys.verify", wire.CodeInvalidArgument, "key not authorized")
	client := newMCPFixture(t, srv)

	entry, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", sshPub)
	if err == nil {
		t.Fatal("an unauthorized key must not be accepted")
	}
	if entry != nil {
		t.Error("no entry may be returned on rejection")
	}
}

// ----------------------------------------------------------------------------
// Unsupported capabilities.
// ----------------------------------------------------------------------------

func TestMCPConsole_Unsupported(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	_, err := client.Console(context.Background(),
		sdkssh.ConsoleConnectRequest{Host: "h", User: "u"}, sdkssh.ConsoleConfig{})
	var unsupported *sdkssh.ConsoleUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected *ConsoleUnsupportedError, got %T %v", err, err)
	}
	if unsupported.Transport != "mcp" {
		t.Errorf("Transport = %q", unsupported.Transport)
	}
}

// TestMCPSession_DialPropagatesSignerFailure exercises Session.Dial against
// the bare fakeMCPServer (no ssh.keys.* handlers registered — see
// mcp_dial_test.go for the genuine end-to-end dial/handshake coverage over a
// server wired to a real embedded client). Session.Dial resolves the
// remote-signer proxy through ssh.keys.export before it ever reaches the
// target host. The fake server answers that call with a wire.CodeUnimplemented
// envelope for the unregistered method, which the client decodes into a
// typed *NotImplementedError (go-xkms#769) naming ssh.keys.export: the
// signer lookup failed, not Dial.
func TestMCPSession_DialPropagatesSignerFailure(t *testing.T) {
	srv := newFakeMCPServer(t)
	client := newMCPFixture(t, srv)

	_, err := client.Session().Dial(context.Background(), sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: "ssh", Host: "h", User: "u",
	})
	var ni *sdkssh.NotImplementedError
	if !errors.As(err, &ni) {
		t.Fatalf("expected *NotImplementedError, got %T %v", err, err)
	}
	if !strings.Contains(ni.Error(), "ssh.keys.export") {
		t.Fatalf("expected the signer lookup to be named, got: %v", ni)
	}
}
