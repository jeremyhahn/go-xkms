// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	mcpserver "github.com/mark3labs/mcp-go/server"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Error type tests ---

func TestRPCError_Error(t *testing.T) {
	e := &RPCError{Code: -32600, WireCode: wire.CodeInvalidArgument, Message: "invalid request"}
	got := e.Error()
	assert.Contains(t, got, "-32600")
	assert.Contains(t, got, "invalid request")
	assert.Contains(t, got, "INVALID_ARGUMENT")
}

func TestMarshalError_Error(t *testing.T) {
	e := &MarshalError{Operation: "request", Err: errors.New("bad json")}
	assert.Contains(t, e.Error(), "marshal request")
	assert.Contains(t, e.Error(), "bad json")
}

func TestMarshalError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &MarshalError{Operation: "test", Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestUnmarshalError_Error(t *testing.T) {
	e := &UnmarshalError{Operation: "response", Err: errors.New("unexpected EOF")}
	assert.Contains(t, e.Error(), "unmarshal response")
	assert.Contains(t, e.Error(), "unexpected EOF")
}

func TestUnmarshalError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &UnmarshalError{Operation: "test", Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestReceiveError_Error(t *testing.T) {
	e := &ReceiveError{Err: errors.New("connection reset")}
	assert.Contains(t, e.Error(), "receive response")
	assert.Contains(t, e.Error(), "connection reset")
}

func TestReceiveError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &ReceiveError{Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestTLSSetupError_Error(t *testing.T) {
	e := &TLSSetupError{Detail: "bad CA", Err: errors.New("parse failed")}
	assert.Contains(t, e.Error(), "TLS setup")
	assert.Contains(t, e.Error(), "bad CA")
	assert.Contains(t, e.Error(), "parse failed")
}

func TestTLSSetupError_Error_NoUnderlying(t *testing.T) {
	e := &TLSSetupError{Detail: "missing cert"}
	assert.Equal(t, "TLS setup: missing cert", e.Error())
}

func TestTLSSetupError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &TLSSetupError{Detail: "test", Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

// --- Constructor tests ---

func TestNew_DefaultConfig(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.config)
}

func TestNew_WithAddress(t *testing.T) {
	tr, err := New(transport.WithAddress("localhost:9090"))
	require.NoError(t, err)
	assert.Equal(t, "localhost:9090", tr.config.Address)
}

func TestNew_InvalidOption(t *testing.T) {
	_, err := New(transport.WithAddress(""))
	require.Error(t, err)
}

func TestNewWithConfig_NilConfig(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestNewWithConfig_CustomConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "custom:1234"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "custom:1234", tr.config.Address)
}

// --- resolveMethod tests ---

func TestResolveMethod_ExactMatch(t *testing.T) {
	tests := []struct {
		path   string
		method string
	}{
		{"/health", "health"},
		{"/api/v1/backends", "xkms.listBackends"},
		{"/api/v1/keys", "xkms.generateKey"},
		{"/api/v1/keys/import", "xkms.importKey"},
		{"/api/v1/seal", "xkms.seal"},
		{"/api/v1/unseal", "xkms.unseal"},
		{"/api/v1/ca/bundle", "xkms.ca.bundle"},
		{"/v1/barrier/initialize", "barrier.initialize"},
		{"/v1/barrier/status", "barrier.status"},
		{"/api/v1/init/status", "init.getStatus"},
		{"/api/v1/credentials/submit", "credentials.submit"},
		{"/api/v1/shares/submit", "xkms.submitShare"},
		{"/api/v1/tenants", "xkms.listTenants"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			method, ok := resolveMethod(tt.path)
			assert.True(t, ok, "expected match for %s", tt.path)
			assert.Equal(t, tt.method, method)
		})
	}
}

func TestResolveMethod_DynamicPatterns(t *testing.T) {
	tests := []struct {
		path   string
		method string
	}{
		{"/api/v1/keys/software/test-key/sign", "xkms.sign"},
		{"/api/v1/keys/software/test-key/verify", "xkms.verify"},
		{"/api/v1/keys/software/test-key/encrypt", "xkms.encrypt"},
		{"/api/v1/keys/software/test-key/decrypt", "xkms.decrypt"},
		{"/api/v1/keys/software/test-key", "xkms.getKey"},
		{"/api/v1/certs/software/test-key/chain", "xkms.getCertChain"},
		{"/api/v1/certs/software/test-key", "xkms.getCert"},
		{"/api/v1/backends/software", "xkms.getBackend"},
		{"/api/v1/users/admin", "xkms.getUser"},
		{"/api/v1/custodian/groups/g1", "xkms.getCustodianGroup"},
		{"/api/v1/custodian/groups/g1/distribute", "xkms.distributeShares"},
		{"/api/v1/tenants/t1", "xkms.getTenant"},
		{"/api/v1/tenants/t1/barrier/init", "xkms.tenantBarrierInit"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			method, ok := resolveMethod(tt.path)
			assert.True(t, ok, "expected match for %s", tt.path)
			assert.Equal(t, tt.method, method)
		})
	}
}

func TestResolveMethod_QueryParams(t *testing.T) {
	method, ok := resolveMethod("/health?verbose=true")
	assert.True(t, ok)
	assert.Equal(t, "health", method)
}

func TestResolveMethod_NotFound(t *testing.T) {
	_, ok := resolveMethod("/api/v1/nonexistent")
	assert.False(t, ok)
}

// --- Connection tests ---

func TestConnect_NotConnected_MethodsReturnError(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = tr.Health(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListBackends(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BootstrapListenerKeys(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBootstrapListenerKeys_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BootstrapListenerKeys(context.Background())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "aa", resp.NoisePublicKey)
}

func TestClose_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
}

func TestConnect_HealthCheck(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	assert.True(t, tr.IsConnected())
}

func TestConnect_FailedDial(t *testing.T) {
	tr, err := New(transport.WithAddress("127.0.0.1:1"))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrConnectionFailed))
}

// --- Conn and Config ---

func TestConn_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

func TestConn_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	assert.NotNil(t, tr.Conn())
}

func TestConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "test:1234"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test:1234", tr.Config().Address)
}

func TestIsConnected_Default(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.IsConnected())
}

// --- Request without connection ---

func TestRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	err = tr.Request(context.Background(), "/health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRequest_UnknownPath(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.Request(context.Background(), "/nonexistent/path", nil, nil)
	assert.Error(t, err)
	var te *transport.TransportError
	require.True(t, errors.As(err, &te))
	assert.Equal(t, transport.ErrCodeMethodNotFound, te.Code)
}

// --- Healthy ---

func TestHealthy_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.Healthy(context.Background()))
}

// --- rpcCall with a real in-process MCP server ---

// jsonrpcRequest and jsonrpcResponse are test-only stand-ins for the
// method name and JSON-RPC-shaped result/error a mock tool handler works
// with. They are not part of the wire protocol any more (the wire protocol
// is MCP's CallToolRequest/CallToolResult); they exist purely so the mock
// server's handler callback keeps the same convenient shape the previous
// TCP transport's tests used.
type jsonrpcRequest struct {
	// Method is the legacy JSON-RPC method name the tool was registered
	// under (see startMockServer): the mock server hands it back to the
	// handler unchanged so the handler can switch on it exactly as before.
	Method string
	// Params is the raw "params_json" argument the client sent, or empty
	// when the call carried no params.
	Params json.RawMessage
}

// jsonrpcResponse is what a mock tool handler returns: exactly one of
// Result (success) or ErrorText (a failing tool result's text content)
// should be set. When ErrorText is set alongside a non-zero Envelope, the
// result also carries go-qrdb's wire.ErrorEnvelope in StructuredContent,
// exercising classifyToolError's coded path; ErrorText alone (Envelope left
// at its zero value, wire.CodeOK) produces an UNCODED tool failure, exercising
// the *EnvelopeMissingError protocol-error path go-xkms#797 added.
type jsonrpcResponse struct {
	Result    json.RawMessage
	ErrorText string
	Envelope  wire.Code
	// EmptyError forces a tool error result with no content and no envelope
	// at all, exercising classifyToolError's *EnvelopeMissingError fallback
	// message.
	EmptyError bool
}

// mockToolMethods is every JSON-RPC method name transport.go's rpcCall
// call sites address, plus "test", a method name a couple of unit tests
// below use directly. xkmsmcp.ModuleMethods() is deliberately not used
// here: it only reports the subset of methods pkg/api/mcp's own dispatcher
// already implements server-side, which currently lags the client method
// surface this transport exposes, and a test double for the client belongs
// to the client's contract, not the server's current implementation state.
var mockToolMethods = []string{
	"test",
	"health",
	"barrier.deleteRecoveryKeys",
	"barrier.enableEncryption",
	"barrier.generateRecoveryKeys",
	"barrier.generateRootToken",
	"barrier.hasRecoveryKeys",
	"barrier.initialize",
	"barrier.initializeShamir",
	"barrier.recoverWithKeys",
	"barrier.rekey",
	"barrier.seal",
	"barrier.status",
	"barrier.unseal",
	"barrier.unsealShare",
	"barrier.unsealShares",
	"bootstrap.showKeys",
	"credentials.strategy",
	"credentials.submit",
	"init.claimCertBegin",
	"init.claimCertComplete",
	"init.claimShareBegin",
	"init.claimShareComplete",
	"init.getStatus",
	"init.signCSR",
	"password.add",
	"password.delete",
	"password.generate",
	"password.get",
	"password.list",
	"password.lock",
	"password.setAccessMode",
	"password.status",
	"password.unlock",
	"password.update",
	"xkms.addCustodianMember",
	"xkms.algorithms",
	"xkms.asymmetricEncrypt",
	"xkms.attestKey",
	"xkms.ca.bundle",
	"xkms.ca.certificate",
	"xkms.ca.crl",
	"xkms.ca.is-revoked",
	"xkms.ca.issue",
	"xkms.canSeal",
	"xkms.ca.revoke",
	"xkms.ca.sign-csr",
	"xkms.ca.tcg.enroll",
	"xkms.ca.tcg.issue-ak",
	"xkms.ca.tcg.issue-ek",
	"xkms.ca.tcg.sign-csr",
	"xkms.certExists",
	"xkms.changeSOPIN",
	"xkms.changeUserPIN",
	"xkms.copyKey",
	"xkms.createCustodianGroup",
	"xkms.createTenant",
	"xkms.decrypt",
	"xkms.deleteCert",
	"xkms.deleteCustodianGroup",
	"xkms.deleteKey",
	"xkms.deletePIVCertificate",
	"xkms.deleteShare",
	"xkms.deleteTenant",
	"xkms.deriveKey",
	"xkms.deriveKeyECDH",
	"xkms.distributeShares",
	"xkms.encrypt",
	"xkms.exportKey",
	"xkms.exportKeyMaterial",
	"xkms.exportPIVCertificate",
	"xkms.generateKey",
	"xkms.generatePIVCSR",
	"xkms.generatePIVKey",
	"xkms.getBackend",
	"xkms.getCert",
	"xkms.getCertChain",
	"xkms.getCustodianGroup",
	"xkms.getImportParameters",
	"xkms.getKey",
	"xkms.getLockoutStatus",
	"xkms.getPIVCertificate",
	"xkms.getShare",
	"xkms.getShareCollectionStatus",
	"xkms.getTenant",
	"xkms.getTLSCertificate",
	"xkms.importKey",
	"xkms.importPIVCertificate",
	"xkms.listBackends",
	"xkms.listCerts",
	"xkms.listCustodianGroups",
	"xkms.listKeys",
	"xkms.listPIVSlots",
	"xkms.listShares",
	"xkms.listTenants",
	"tpm.policy.create",
	"tpm.policy.get",
	"tpm.policy.list",
	"tpm.policy.update",
	"tpm.policy.revoke",
	"tpm.policy.verify",
	"tpm.policy.delete",
	"tpm.policy.objects",
	"tpm.policy.autoUnseal",
	"tpm.object.policy",
	"tpm.authority.rotate",
	"xkms.getTenantTPMMode",
	"xkms.setTenantTPMMode",
	"xkms.tenantVTPMStatus",
	"xkms.tenantVTPMStart",
	"xkms.tenantVTPMStop",
	"xkms.queryAudit",
	"xkms.removeCustodianMember",
	"xkms.resetLockout",
	"xkms.rotateKey",
	"xkms.saveCert",
	"xkms.saveCertChain",
	"xkms.seal",
	"sealStore.put",
	"sealStore.get",
	"sealStore.delete",
	"sealStore.list",
	"sealStore.reseal",
	"sealStore.status",
	"xkms.setSOPIN",
	"xkms.setUserPIN",
	"xkms.sign",
	"xkms.storePIVCertificate",
	"xkms.submitShare",
	"xkms.tenantBarrierInit",
	"xkms.tenantBarrierStatus",
	"xkms.tenantBarrierUnseal",
	"user.bindCert",
	"user.create",
	"user.delete",
	"user.disable",
	"user.enable",
	"user.get",
	"user.list",
	"user.listCredentials",
	"xkms.unseal",
	"xkms.unwrapKey",
	"xkms.unwrapKeyByID",
	"xkms.updateTenantEntitlements",
	"xkms.updateTenantQuotas",
	"xkms.verify",
	"xkms.verifySOPIN",
	"xkms.verifyUserPIN",
	"xkms.wrapKey",
	"xkms.wrapKeyByID",
}

// startMockServer starts a real, in-process MCP Streamable HTTP server
// (github.com/mark3labs/mcp-go/server) exposing one tool per entry in
// mockToolMethods, named via xkmsmcp.ToolName — the same authoritative
// method-to-tool-name mapping rpcCall uses against the real unified qrdb
// MCP server. Each tool decodes its "params_json" argument into a
// jsonrpcRequest and asks handler for a JSON-RPC-shaped response, which
// becomes a text CallToolResult (or a tool error, when handler reports
// one). It returns the "host:port" of the server, without a scheme, so
// callers can plug it directly into transport.WithAddress the same way the
// previous TCP transport's mock server address worked.
func startMockServer(t *testing.T, handler func(req jsonrpcRequest) jsonrpcResponse) (string, func()) {
	t.Helper()

	srv := mcpserver.NewMCPServer("xkms-test", "1.0.0")

	for _, method := range mockToolMethods {
		srv.AddTool(mcp.Tool{Name: xkmsmcp.ToolName(method)}, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			paramsJSON, _ := req.GetArguments()["params_json"].(string)
			resp := handler(jsonrpcRequest{Method: method, Params: json.RawMessage(paramsJSON)})
			switch {
			case resp.EmptyError:
				return &mcp.CallToolResult{IsError: true}, nil
			case resp.ErrorText != "" && resp.Envelope != wire.CodeOK:
				res := mcp.NewToolResultError(resp.ErrorText)
				res.StructuredContent = wire.NewErrorEnvelope(xkmsmcp.ToolName(method), resp.Envelope, resp.ErrorText)
				return res, nil
			case resp.ErrorText != "":
				return mcp.NewToolResultError(resp.ErrorText), nil
			default:
				return mcp.NewToolResultText(string(resp.Result)), nil
			}
		})
	}

	httpServer := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath(mcpEndpointPath))
	testServer := httptest.NewServer(httpServer)

	return strings.TrimPrefix(testServer.URL, "http://"), testServer.Close
}

// connectToMockServer connects a Transport to a mock server address
// returned by startMockServer/newCatchAllMCPServer, over plain HTTP (TLS
// itself is exercised separately by TestConnect_MutualTLS).
func connectToMockServer(t *testing.T, addr string) *Transport {
	t.Helper()
	tr, err := New(transport.WithAddress(addr))
	require.NoError(t, err)
	err = tr.Connect(context.Background())
	require.NoError(t, err)
	return tr
}

func TestRpcCall_Success(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		result := map[string]string{"method": req.Method}
		data, _ := json.Marshal(result)
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	var result map[string]string
	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, "xkms.listBackends", result["method"])
}

func TestRpcCall_RPCError(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		// First call is the health check from Connect().
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		return jsonrpcResponse{
			ErrorText: "invalid request",
			Envelope:  wire.CodeInvalidArgument,
		}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, nil)
	require.Error(t, err)
	var rpcErr *RPCError
	require.True(t, errors.As(err, &rpcErr))
	assert.Equal(t, xkmsmcp.ErrCodeInvalidParams, rpcErr.Code)
	assert.Equal(t, "invalid request", rpcErr.Message)
}

func TestRpcCall_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	err = tr.rpcCall(context.Background(), "health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRpcCall_WithParams(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		data, _ := json.Marshal(map[string]string{"echo": string(req.Params)})
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	params := map[string]string{"key": "value"}
	var result map[string]string
	err := tr.rpcCall(context.Background(), "test", params, &result)
	require.NoError(t, err)
	assert.Contains(t, result["echo"], "value")
}
