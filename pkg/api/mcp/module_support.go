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

package mcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/mcptool"
)

// MethodSpec describes one JSON-RPC method of the xkms MCP surface for the
// unified-API-server module (pkg/apimodule): the wire method name, the tool
// name it registers under on the real MCP server, and its authorization
// contract from the methodPermissions table.
type MethodSpec struct {
	// Method is the JSON-RPC method name (e.g. "xkms.generateKey").
	Method string
	// Tool is the MCP tool name: "xkms" + "_"-joined method segments
	// (e.g. "xkms_generateKey", "xkms_barrier_unseal") — MCP tool names
	// do not admit dots.
	Tool string
	// Resource and Action carry the method's RBAC permission; empty for
	// public methods.
	Resource string
	Action   string
	// Public marks the unauthenticated discovery/health methods.
	Public bool
}

// ModuleMethods returns the full xkms JSON-RPC method surface, sorted by
// method name: every entry of the dispatch table plus the build-tagged
// frost.* namespace (enumerated from the permission table so a frost-tagged
// build and an untagged build expose the identical tool list; on an
// untagged build the frost tools answer "method not found", exactly as the
// wire path does). The connection-bound xkms.subscribe is excluded: MCP
// tools are request/response.
func ModuleMethods() []MethodSpec {
	seen := map[string]struct{}{}
	var specs []MethodSpec

	add := func(method string) {
		if _, dup := seen[method]; dup {
			return
		}
		seen[method] = struct{}{}
		spec := MethodSpec{Method: method, Tool: ToolName(method)}
		if _, public := publicMethods[method]; public {
			spec.Public = true
		} else if perm, ok := methodPermissions[method]; ok {
			spec.Resource = perm.resource
			spec.Action = perm.action
		}
		specs = append(specs, spec)
	}

	for method := range rpcMethodHandlers {
		add(method)
	}
	for method := range methodPermissions {
		if strings.HasPrefix(method, "frost.") {
			add(method)
		}
	}

	sort.Slice(specs, func(i, j int) bool { return specs[i].Method < specs[j].Method })
	return specs
}

// ToolName maps a JSON-RPC method name onto its MCP tool name: dots become
// underscores and the name is prefixed with "xkms_" unless the method
// already carries the xkms namespace. It delegates to pkg/mcptool.ToolName,
// the single canonical implementation shared with every MCP client in this
// module (see that package's doc comment for why the naming convention
// lives there rather than here).
func ToolName(method string) string {
	return mcptool.ToolName(method)
}

// UnknownMethodError reports an InvokeMethod call for a method the
// dispatcher does not serve.
type UnknownMethodError struct{ Method string }

// Error implements the error interface.
func (e *UnknownMethodError) Error() string { return "mcp: method not found: " + e.Method }

// InvokeMethod dispatches one JSON-RPC method against s, running the tenant-
// scoping and authorization gates every dispatch path shares. It is the
// package's sole production entry point: it backs the unified-API-server
// module's real MCP tools (pkg/apimodule RegisterMCP). On that server,
// per-tool authorization additionally belongs to go-qrdb's MCP tool
// registry once module tools gain registry coverage there.
func (s *Server) InvokeMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	ctx, err := s.tenantAccess(ctx, method)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeMethod(ctx, method); err != nil {
		return nil, err
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: params}
	if result, ferr, handled := s.routeFrostMethods(ctx, req); handled {
		return result, ferr
	}
	handler, ok := rpcMethodHandlers[method]
	if !ok {
		return nil, &KeyOpError{Code: ErrCodeMethodNotFound, Err: &UnknownMethodError{Method: method}}
	}
	return handler(s, ctx, req)
}
