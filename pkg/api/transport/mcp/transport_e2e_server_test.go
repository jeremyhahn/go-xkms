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

package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/apimodule"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/mcptool"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ---------------------------------------------------------------------------
// End to end, against the real unified-server MCP dispatch path
//
// Everything in transport_rpc_error_test.go drives classifyToolError against
// a mock tool result built by hand. These tests drive the REAL
// pkg/apimodule.mcpToolHandler, the real pkg/api/mcp.InvokeMethod dispatch
// and gates, and the real mcp-go in-process transport, because the mapper
// agreeing with itself proves nothing about what the unified server actually
// puts on the wire (mirrors go-qrdb's sdk/go/transport/mcp/status_test.go
// TestE2E_* style; see go-xkms#797).
// ---------------------------------------------------------------------------

// newE2EBackendWithBarrier builds the same minimal xkms MCP server as
// pkg/apimodule's newMCPBackendWithBarrier test helper: an in-memory
// software backend, plus an initialized, unsealed *seal.BarrierRegistry with
// no tenants registered in it, so a caller identity scoped to any tenant is
// deterministically unregistered -- exercising the tenant gate's
// ErrCodeForbidden path (wire.CodePermissionDenied) without the weight of a
// real qrdb node.
func newE2EBackendWithBarrier(t *testing.T) *xkmsmcp.Server {
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

// connectInProcessToModule registers backend's real MCP tool surface on a
// real mcp-go server via pkg/apimodule.RegisterMCP -- the production
// dispatch path -- and wires this package's own Transport to it over
// mcp-go's in-process client transport, so a call through tr.* exercises
// exactly the client code path a network caller uses, with no HTTP loopback
// (which would drop the request-scoped auth.Identity these tests inject).
func connectInProcessToModule(t *testing.T, backend *xkmsmcp.Server) *Transport {
	t.Helper()

	m, err := apimodule.NewModule(func() *xkms.XKMSService { return nil },
		apimodule.WithMCPServer(func() *xkmsmcp.Server { return backend }))
	require.NoError(t, err)

	srv := mcpserver.NewMCPServer("xkms-mcp-e2e-test", "0.0.0", mcpserver.WithToolCapabilities(true))
	m.RegisterMCP(srv)

	client, err := mcpclient.NewInProcessClient(srv)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	require.NoError(t, client.Start(ctx))

	initReq := mcpgo.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcpgo.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcpgo.Implementation{Name: "xkms-mcp-e2e-test", Version: "1.0.0"}
	_, err = client.Initialize(ctx, initReq)
	require.NoError(t, err)

	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	tr.core = mcptool.NewClientWithSession(tr.config, client, mcptool.WithErrorClassifier(classifyWireCode))
	return tr
}

// TestE2E_CapabilityBoundaryIsUnimplemented proves the "unimplemented"
// mapping end to end: the software backend cannot attest
// (pkg/xkms/servicer_crypto.go's AttestKey), which fails on the KeyProvider
// type assertion with xkms.ErrOperationNotSupported -- the one
// errors_keyops.go sentinel with a code distinct from ErrCodeInternalError
// -- and reaches this SDK's caller as an *RPCError classified
// ErrCodeMethodNotFound, go-qrdb's wire.CodeUnimplemented reconstituted.
func TestE2E_CapabilityBoundaryIsUnimplemented(t *testing.T) {
	backend := newE2EBackendWithBarrier(t)
	tr := connectInProcessToModule(t, backend)

	_, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "software",
		KeyID:   "does-not-matter",
	})
	require.Error(t, err)

	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	require.Equal(t, xkmsmcp.ErrCodeMethodNotFound, rpcErr.Code)
}

// TestE2E_ValidationFailureIsInvalidArgument proves the "invalid argument"
// mapping end to end, through the real server: signing a non-Ed25519 key
// with no data reaches XKMSService.Sign's "data is required"
// *xkms.ErrValidation, which mapKeyOpError renders as ErrCodeInvalidParams
// (wire.CodeInvalidArgument on the wire), and this SDK reconstitutes it as
// an *RPCError carrying that same code -- go-xkms#797.
func TestE2E_ValidationFailureIsInvalidArgument(t *testing.T) {
	backend := newE2EBackendWithBarrier(t)
	tr := connectInProcessToModule(t, backend)
	ctx := context.Background()

	genResp, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:     "mcp-e2e-rsa",
		Backend:   "software",
		KeyType:   "rsa",
		Algorithm: "rsa",
		KeySize:   2048,
	})
	require.NoError(t, err)
	require.NotNil(t, genResp)

	// Signing with no Data reaches XKMSService.Sign's "data is required"
	// *xkms.ErrValidation.
	_, err = tr.Sign(ctx, &transport.SignRequest{
		KeyID: "mcp-e2e-rsa",
		Hash:  "SHA256",
	})
	require.Error(t, err)

	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	require.Equal(t, xkmsmcp.ErrCodeInvalidParams, rpcErr.Code)
}

// TestE2E_UnregisteredTenantIsPermissionDenied proves the "permission
// denied" mapping end to end: a caller identity scoped to a tenant the
// barrier registry has never heard of is refused by the tenant gate
// (pkg/api/mcp/tenant.go), which mapKeyOpError-adjacent tenantAccess renders
// as ErrCodeForbidden (wire.CodePermissionDenied on the wire), and this SDK
// reconstitutes it as an *RPCError carrying ErrCodeForbidden.
func TestE2E_UnregisteredTenantIsPermissionDenied(t *testing.T) {
	backend := newE2EBackendWithBarrier(t)
	tr := connectInProcessToModule(t, backend)

	identity := &auth.Identity{
		Subject:  "tester",
		TenantID: "tenant-does-not-exist",
		Roles:    []string{"user"},
	}
	ctx := auth.WithIdentity(context.Background(), identity)

	_, err := tr.ListBackends(ctx)
	require.Error(t, err)

	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	require.Equal(t, xkmsmcp.ErrCodeForbidden, rpcErr.Code)
}

// TestE2E_NotFoundIsClassifiedByCode is the not-found cell of the same
// matrix, run against a real mcp-go server and this SDK's real rpcCall/
// classifyToolError path rather than against production dispatch: a hand-
// built tool result carrying wire.CodeNotFound -- exactly the shape
// codedToolResult produces -- is received by the real Streamable-HTTP-shaped
// in-process transport and reconstituted by this client as an *RPCError
// carrying both WireCode (go-qrdb's raw classification) and Code
// (sdkssh.JSONRPCCodeNotFound, wireCodeToRPCCode's row for wire.CodeNotFound;
// go-xkms#814). TestE2E_MissingKeyIsClassifiedNotFound below proves the same
// outcome end to end through production dispatch, closing the gap this
// test's predecessor documented (before go-xkms#814, no xkms tool call
// reached wire.CodeNotFound at all, so only the client's reconstruction in
// isolation could be exercised).
func TestE2E_NotFoundIsClassifiedByCode(t *testing.T) {
	srv := mcpserver.NewMCPServer("xkms-mcp-e2e-notfound-test", "0.0.0", mcpserver.WithToolCapabilities(true))
	const toolName = "xkms_getKey"
	srv.AddTool(mcpgo.Tool{Name: toolName}, func(_ context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		res := mcpgo.NewToolResultError("key not found: does-not-exist")
		res.StructuredContent = wire.NewErrorEnvelope(toolName, wire.CodeNotFound, "key not found: does-not-exist")
		return res, nil
	})

	client, err := mcpclient.NewInProcessClient(srv)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	require.NoError(t, client.Start(ctx))
	initReq := mcpgo.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcpgo.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcpgo.Implementation{Name: "xkms-mcp-e2e-notfound-test", Version: "1.0.0"}
	_, err = client.Initialize(ctx, initReq)
	require.NoError(t, err)

	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	tr.core = mcptool.NewClientWithSession(tr.config, client, mcptool.WithErrorClassifier(classifyWireCode))

	_, err = tr.GetKey(ctx, "software", "does-not-exist")
	require.Error(t, err)

	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	require.Equal(t, sdkssh.JSONRPCCodeNotFound, rpcErr.Code)
	require.Equal(t, wire.CodeNotFound, rpcErr.WireCode)
}

// TestE2E_MissingKeyIsClassifiedNotFound proves the "not found" mapping end
// to end, through the real server: xkms.getKey for a key that does not
// exist reaches XKMSService.GetKey's xkms.ErrKeyNotFound
// (pkg/xkms/servicer_helpers.go's findKeyAttrs), which pkg/api/mcp's
// handleGetKey now runs through mapKeyOpError (errors_keyops.go's
// keyOpSentinelCodes) instead of the bare *errs.Wrapped it used to return,
// so it renders as sdkssh.JSONRPCCodeNotFound (wire.CodeNotFound on the
// wire, via pkg/apimodule's keyOpCodeToWire), and this SDK reconstitutes it
// as an *RPCError carrying that same Code and WireCode -- go-xkms#814.
func TestE2E_MissingKeyIsClassifiedNotFound(t *testing.T) {
	backend := newE2EBackendWithBarrier(t)
	tr := connectInProcessToModule(t, backend)

	_, err := tr.GetKey(context.Background(), "software", "does-not-exist")
	require.Error(t, err)

	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	require.Equal(t, sdkssh.JSONRPCCodeNotFound, rpcErr.Code)
	require.Equal(t, wire.CodeNotFound, rpcErr.WireCode)
}
