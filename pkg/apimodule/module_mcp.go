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
	"encoding/json"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
)

// MCPResolver returns the xkms MCP method surface backing the module's real
// MCP tools, or nil while the host is still composing it. It is a resolver
// for the same construction-order reason as ServiceResolver.
type MCPResolver func() *xkmsmcp.Server

// WithMCPServer wires the MCP surface resolver consumed by RegisterMCP.
// Without it the module registers no MCP tools.
func WithMCPServer(resolve MCPResolver) Option {
	return func(m *Module) {
		m.resolveMCP = resolve
	}
}

// RegisterMCP registers every xkms JSON-RPC method as a real MCP tool on
// the unified server's shared mcp-go server. Each tool takes one optional
// "params_json" argument — the JSON-RPC params object, verbatim — and
// returns the method's JSON result, so the real MCP surface is
// wire-equivalent to the legacy JSON-RPC plane method for method.
//
// Dispatch late-binds through the resolver exactly like the gRPC and HTTP
// surfaces: until the MCP wiring composes, every tool answers a tool error.
// Authorization is layered: qrdb's MCP middleware authorizes each tool call
// against the permissions this module declares via MCPToolPermissions
// (below), and the xkms-internal tenant + RBAC gates run inside
// InvokeMethod.
func (m *Module) RegisterMCP(srv *mcpserver.MCPServer) {
	if m.resolveMCP == nil {
		return
	}

	for _, spec := range xkmsmcp.ModuleMethods() {
		spec := spec
		tool := mcpgo.NewTool(spec.Tool,
			mcpgo.WithDescription("xkms "+spec.Method+" (JSON-RPC parity tool; params_json carries the method's params object)"),
			mcpgo.WithString("params_json",
				mcpgo.Description("JSON-encoded params object for "+spec.Method+"; omit for methods without params."),
			),
		)
		srv.AddTool(tool, m.mcpToolHandler(spec))
	}
}

// Compile-time check: the module declares its MCP tool permissions into the
// unified server's single MCP authorization path.
var _ qrdbsdk.ModuleMCPToolPermissioner = (*Module)(nil)

// MCPToolPermissions declares every module tool's permission for the
// unified server's MCP tool registry: permission-mapped methods carry their
// resource:action, and public or handler-gated methods carry the
// identity-gated sentinel (authenticated at qrdb's gate, authorization
// deferred to the module's own dispatch gates in InvokeMethod).
func (m *Module) MCPToolPermissions() map[string]qrdbsdk.Permission {
	specs := xkmsmcp.ModuleMethods()
	perms := make(map[string]qrdbsdk.Permission, len(specs))
	for _, spec := range specs {
		if spec.Resource != "" && spec.Action != "" {
			perms[spec.Tool] = qrdbsdk.Permission(spec.Resource + ":" + spec.Action)
			continue
		}
		perms[spec.Tool] = qrdbsdk.PermissionIdentityGated
	}
	return perms
}

// mcpToolHandler adapts one JSON-RPC method to an mcp-go tool handler with
// lazy backend resolution.
func (m *Module) mcpToolHandler(spec xkmsmcp.MethodSpec) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
		backend := m.resolveMCP()
		if backend == nil {
			return mcpgo.NewToolResultError(
				"xkms mcp surface is not yet available (server still composing)"), nil
		}

		paramsJSON := mcpgo.ParseString(req, "params_json", "")
		var params json.RawMessage
		if paramsJSON != "" {
			if !json.Valid([]byte(paramsJSON)) {
				return mcpgo.NewToolResultError("params_json is not valid JSON"), nil
			}
			params = json.RawMessage(paramsJSON)
		}

		result, err := backend.InvokeMethod(ctx, spec.Method, params)
		if err != nil {
			return mcpgo.NewToolResultError(err.Error()), nil
		}
		out, err := json.Marshal(result)
		if err != nil {
			return mcpgo.NewToolResultError("result encoding failed: " + err.Error()), nil
		}
		return mcpgo.NewToolResultText(string(out)), nil
	}
}
