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

package apimodule

import (
	"context"
	"testing"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newMCPBackend builds a minimal xkms MCP server over an in-memory software
// backend, mirroring pkg/api/mcp's own test wiring.
func newMCPBackend(t *testing.T) *xkmsmcp.Server {
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

	srv, err := xkmsmcp.NewServer(&xkmsmcp.Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return srv
}

// toolCallRequest builds a CallToolRequest carrying the given params_json.
func toolCallRequest(paramsJSON string) mcpgo.CallToolRequest {
	req := mcpgo.CallToolRequest{}
	if paramsJSON != "" {
		req.Params.Arguments = map[string]any{"params_json": paramsJSON}
	}
	return req
}

// TestRegisterMCP_RegistersFullToolSurface proves every module method
// registers as a tool on the shared mcp-go server, and that a module
// without a resolver registers nothing.
func TestRegisterMCP_RegistersFullToolSurface(t *testing.T) {
	backend := newMCPBackend(t)

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithMCPServer(func() *xkmsmcp.Server { return backend }))
	require.NoError(t, err)

	srv := mcpserver.NewMCPServer("test", "0.0.0", mcpserver.WithToolCapabilities(true))
	// Registration must not panic and must accept the full surface.
	m.RegisterMCP(srv)

	// Without a resolver: no-op.
	bare, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)
	bare.RegisterMCP(mcpserver.NewMCPServer("bare", "0.0.0"))
}

// TestModule_MCPToolPermissions_MatchesMethodSpecs proves every module MCP
// tool gets exactly one permission entry, derived from its MethodSpec: a
// spec carrying a resource:action gets that permission, and one carrying
// neither (public or handler-gated) gets qrdb's identity-gated sentinel —
// the mapping qrdb's MCP authorization path relies on to decide, per tool,
// whether authorization is enforced here or deferred to the module's own
// dispatch gates.
func TestModule_MCPToolPermissions_MatchesMethodSpecs(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	specs := xkmsmcp.ModuleMethods()
	perms := m.MCPToolPermissions()
	require.Len(t, perms, len(specs), "one permission entry per declared tool, no more, no fewer")

	var sawResourceMapped, sawIdentityGated bool
	for _, spec := range specs {
		got, ok := perms[spec.Tool]
		require.True(t, ok, "tool %q missing a permission entry", spec.Tool)

		if !spec.Public {
			assert.Equal(t, spec.Permission, got,
				"tool %q must carry its resource:action permission", spec.Tool)
			sawResourceMapped = true
		} else {
			assert.Equal(t, qrdbsdk.PermissionIdentityGated, got,
				"tool %q with no resource:action must carry the identity-gated sentinel", spec.Tool)
			sawIdentityGated = true
		}
	}
	assert.True(t, sawResourceMapped, "test fixture assumption: at least one tool carries a resource:action permission")
	assert.True(t, sawIdentityGated, "test fixture assumption: at least one tool carries the identity-gated sentinel")
}

// TestMCPToolHandler_LazyAndDispatch proves the tool handler answers a tool
// error while unresolved, dispatches a real method once resolved, and
// rejects invalid params JSON.
func TestMCPToolHandler_LazyAndDispatch(t *testing.T) {
	var backend *xkmsmcp.Server
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithMCPServer(func() *xkmsmcp.Server { return backend }))
	require.NoError(t, err)

	spec := xkmsmcp.MethodSpec{Method: "health", Tool: "xkms_health"}
	handler := m.mcpToolHandler(spec)

	// Unresolved: tool error, not a protocol error.
	res, err := handler(context.Background(), toolCallRequest(""))
	require.NoError(t, err)
	require.True(t, res.IsError)

	// Resolved: dispatches the real method.
	backend = newMCPBackend(t)
	res, err = handler(context.Background(), toolCallRequest(""))
	require.NoError(t, err)
	assert.False(t, res.IsError)

	// Invalid params JSON: tool error.
	res, err = handler(context.Background(), toolCallRequest("{not-json"))
	require.NoError(t, err)
	assert.True(t, res.IsError)
}

// TestMCPToolHandler_GapMethods_RoundTrip proves the go-xkms#773 PIN,
// custodian, tenant, and non-ECDH deriveKey methods reach InvokeMethod
// through the real mcp-go tool-call boundary (ToolName translation, tool
// registration, and params_json plumbing), one representative per group.
// None of the backing sub-systems (PIN backend, custodian client, tenant
// service) are composed on this fixture, so every call answers the
// not-configured tool error rather than success; what this proves is that
// dispatch reaches the handler at all, which is exactly the gap #773 found
// (the method was previously "method not found" -- unreachable, not merely
// unconfigured).
func TestMCPToolHandler_GapMethods_RoundTrip(t *testing.T) {
	backend := newMCPBackend(t)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithMCPServer(func() *xkmsmcp.Server { return backend }))
	require.NoError(t, err)

	for _, method := range []string{
		"xkms.getLockoutStatus",
		"xkms.listTenants",
		"xkms.deriveKey",
	} {
		t.Run(method, func(t *testing.T) {
			spec := xkmsmcp.MethodSpec{Method: method, Tool: xkmsmcp.ToolName(method)}
			handler := m.mcpToolHandler(spec)

			res, err := handler(context.Background(), toolCallRequest(""))

			require.NoError(t, err, "the tool call itself must not fail transport-level")
			require.True(t, res.IsError, "no sub-system is composed on this fixture")
			require.NotEmpty(t, res.Content)
			text, ok := mcpgo.AsTextContent(res.Content[0])
			require.True(t, ok)
			assert.NotContains(t, text.Text, "method not found",
				"the method must be dispatchable, not merely reported as unknown")
		})
	}
}
