// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package apimodule

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newMCPBackendWithBarrier builds the same minimal xkms MCP server as
// newMCPBackend, plus an initialized, unsealed *seal.BarrierRegistry with no
// tenants registered in it -- so a caller identity scoped to any tenant is
// deterministically unregistered, exercising tenantAccess's ErrCodeForbidden
// path (see pkg/api/mcp/tenant.go) without the weight of a real qrdb node.
func newMCPBackendWithBarrier(t *testing.T) *xkmsmcp.Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	backend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: backend, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	barrier, err := seal.NewBarrier(
		logger,
		storage.NewMemory(),
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)
	creds := seal.MustCredentials([]byte("test-password"))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(context.Background(), creds))
	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	srv, err := xkmsmcp.NewServer(&xkmsmcp.Config{
		XKMSService:     svc,
		Authenticator:   auth.NewNoOpAuthenticator(),
		BarrierRegistry: registry,
	})
	require.NoError(t, err)
	return srv
}

// newInProcessMCPClient wires a real mcp-go client against srv over the
// library's in-process transport (the same mechanism go-qrdb's own SDK uses
// for its in-process tests -- sdk/go/transport/mcp.NewInProcess) and
// completes the MCP handshake, so a test call exercises the actual
// marshal/dispatch/unmarshal path a network client would.
func newInProcessMCPClient(t *testing.T, srv *mcpserver.MCPServer) *mcpclient.Client {
	t.Helper()
	client, err := mcpclient.NewInProcessClient(srv)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	require.NoError(t, client.Start(ctx))

	initReq := mcpgo.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcpgo.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcpgo.Implementation{Name: "xkms-mcp-error-codes-test", Version: "1.0.0"}
	_, err = client.Initialize(ctx, initReq)
	require.NoError(t, err)

	return client
}

// callXKMSTool invokes tool on client with params encoded as the tool's
// "params_json" argument, exactly as a real MCP client would.
func callXKMSTool(t *testing.T, client *mcpclient.Client, ctx context.Context, tool string, params any) *mcpgo.CallToolResult {
	t.Helper()

	req := mcpgo.CallToolRequest{}
	req.Params.Name = tool
	if params != nil {
		raw, err := json.Marshal(params)
		require.NoError(t, err)
		req.Params.Arguments = map[string]any{"params_json": string(raw)}
	}

	res, err := client.CallTool(ctx, req)
	require.NoError(t, err, "CallTool must answer a tool result, never a JSON-RPC protocol error, for a dispatch failure")
	require.NotNil(t, res)
	return res
}

// decodeToolErrorCode asserts res is a coded tool failure and returns its
// go-qrdb wire.Code, the classification a real SDK client branches on.
func decodeToolErrorCode(t *testing.T, res *mcpgo.CallToolResult) *wire.ErrorPayload {
	t.Helper()
	require.True(t, res.IsError, "expected a tool-level error result")
	payload, ok := wire.DecodeErrorPayload(res.StructuredContent)
	require.True(t, ok, "expected a classified error envelope in StructuredContent, got %#v", res.StructuredContent)
	return payload
}

// TestWireCodeForKeyOp_MapsEveryDeclaredRowAndFallsBackOnUnknown is the
// direct unit test for keyOpCodeToWire's lookup, including the three
// sdkssh.JSONRPCCode* rows (NotFound, Duplicate, Mismatch) the end-to-end
// MCP error-code test above does not reach — those three are produced only
// by SSH tool dispatch (mapSSHError), not by the xkms.* methods that test
// drives. It also pins the documented fallback: a code the table does not
// declare renders as wire.CodeInternal rather than panicking or losing its
// classification.
func TestWireCodeForKeyOp_MapsEveryDeclaredRowAndFallsBackOnUnknown(t *testing.T) {
	for code, want := range keyOpCodeToWire {
		assert.Equal(t, want, wireCodeForKeyOp(code), "code %d", code)
	}

	const undeclaredCode = -999999
	_, declared := keyOpCodeToWire[undeclaredCode]
	require.False(t, declared, "test fixture assumption: this code must not collide with a real table entry")
	assert.Equal(t, wire.CodeInternal, wireCodeForKeyOp(undeclaredCode),
		"a code with no table entry must fall back to CodeInternal rather than panicking or losing its classification")
}

// TestMCPToolHandler_ErrorCodesReachCaller proves, through the real
// unified-server MCP path (a genuine mcp-go server and in-process client,
// exactly as go-qrdb's own SDK client exercises it), that mcpToolHandler
// carries a *KeyOpError's JSON-RPC code to the caller as go-qrdb's wire.Code
// envelope instead of collapsing it to prose -- issue #791.
func TestMCPToolHandler_ErrorCodesReachCaller(t *testing.T) {
	backend := newMCPBackendWithBarrier(t)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithMCPServer(func() *xkmsmcp.Server { return backend }))
	require.NoError(t, err)

	srv := mcpserver.NewMCPServer("xkms-mcp-error-codes-test", "0.0.0", mcpserver.WithToolCapabilities(true))
	m.RegisterMCP(srv)

	client := newInProcessMCPClient(t, srv)

	t.Run("capability boundary reaches caller as Unimplemented", func(t *testing.T) {
		// The software backend cannot attest (pkg/xkms/servicer_crypto.go's
		// AttestKey), so this fails fast on the KeyProvider type assertion with
		// xkms.ErrOperationNotSupported -- errors_keyops.go's only sentinel with
		// a code distinct from ErrCodeInternalError.
		res := callXKMSTool(t, client, context.Background(), "xkms_attestKey", map[string]any{
			"backend": "software",
			"key_id":  "does-not-matter",
		})
		payload := decodeToolErrorCode(t, res)
		assert.Equal(t, wire.CodeUnimplemented, payload.Code)
		assert.NotEmpty(t, payload.Message)
	})

	t.Run("validation failure reaches caller as InvalidArgument (-32602 locally)", func(t *testing.T) {
		ctx := context.Background()
		genRes := callXKMSTool(t, client, ctx, "xkms_generateKey", map[string]any{
			"key_id":    "mcp-error-codes-rsa",
			"backend":   "software",
			"key_type":  "rsa",
			"algorithm": "rsa",
			"key_size":  2048,
		})
		require.False(t, genRes.IsError, "key generation must succeed for the sign call below to reach validation")

		// Signing a non-Ed25519 key with no data reaches
		// XKMSService.Sign's "data is required" *xkms.ErrValidation, which
		// mapKeyOpError renders as ErrCodeInvalidParams (-32602).
		res := callXKMSTool(t, client, ctx, "xkms_sign", map[string]any{
			"key_id": "mcp-error-codes-rsa",
			"hash":   "SHA256",
		})
		payload := decodeToolErrorCode(t, res)
		assert.Equal(t, wire.CodeInvalidArgument, payload.Code)
		assert.NotEmpty(t, payload.Message)
	})

	t.Run("unregistered tenant reaches caller as PermissionDenied", func(t *testing.T) {
		identity := &auth.Identity{
			Subject:  "tester",
			TenantID: "tenant-does-not-exist",
			Roles:    []string{"user"},
		}
		ctx := auth.WithIdentity(context.Background(), identity)

		res := callXKMSTool(t, client, ctx, "xkms_listBackends", nil)
		payload := decodeToolErrorCode(t, res)
		assert.Equal(t, wire.CodePermissionDenied, payload.Code)
	})

	// The untagged build's routeFrostMethods "not compiled in" refusal --
	// before go-xkms#930 a bare *errs.Message that mcpToolHandler could only
	// report as the generic internal-fault floor below -- is now a
	// *KeyOpError carrying ErrCodeMethodNotFound and reaches the caller as
	// wire.CodeUnimplemented. That behaviour is build-tag-dependent (it
	// flips to a real FROST call under -tags frost), so it is pinned in
	// pkg/api/mcp's own build-tagged tests
	// (server_frost_stub_test.go's TestServer_HandleRequest_FrostMethodWithError)
	// rather than duplicated in this frost-tag-portable file.

	t.Run("unclassified error degrades to a generic internal fault", func(t *testing.T) {
		// go-xkms#930 closed every known bare-error path in pkg/api/mcp's
		// registered handler set (see that package's own
		// TestEveryRegisteredHandler_ReturnsKeyOpErrorOrNil guard), so this
		// fallback in mcpToolHandler (module_mcp.go) currently has no live
		// production trigger left to drive it end-to-end through a real MCP
		// call. The branch itself -- "an error InvokeMethod did not classify
		// reports wire.CodeInternal with no detail" -- is still load-bearing
		// defense-in-depth for a future handler that regresses, so it stays
		// in module_mcp.go; it is no longer exercised here because doing so
		// requires reintroducing the exact bug this issue fixed.
	})
}

// TestWireCodeForKeyOp_UnknownCodeFallsBackToInternal proves the defensive
// floor wireCodeForKeyOp's doc comment describes: a *KeyOpError code this
// package's table does not declare — none exist today, which is exactly why
// this has to be exercised directly rather than through a live tool call —
// answers wire.CodeInternal instead of a zero value or a panic, so a future
// xkms code added to pkg/api/mcp without a matching row here still reaches
// callers as a classified fault.
func TestWireCodeForKeyOp_UnknownCodeFallsBackToInternal(t *testing.T) {
	const noSuchCode = -999999
	assert.Equal(t, wire.CodeInternal, wireCodeForKeyOp(noSuchCode))
}
