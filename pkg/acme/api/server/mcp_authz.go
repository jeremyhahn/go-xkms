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

package server

import (
	"context"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
)

// The ACME admin MCP surface reports its tool permissions in go-qrdb's
// module contract.
var _ qrdbserver.ModuleMCPToolPermissioner = (*MultiProtocolServer)(nil)

// MCPToolPermissions returns the permission every dispatchable ACME admin MCP
// method requires: the qrdb.v1.permission option of the AdminService RPC the
// method mirrors (initMCPHandlers), so revoking a grant revokes it on MCP and
// gRPC at once. A method whose RPC declares no permission is left out, and
// authorizeMCPMethod denies it.
func (s *MultiProtocolServer) MCPToolPermissions() map[string]qrdbsdk.Permission {
	perms := make(map[string]qrdbsdk.Permission, len(s.mcpHandlers))
	for method, entry := range s.mcpHandlers {
		if perm, ok := adminRPCPermissions[entry.rpc]; ok {
			perms[method] = perm
		}
	}
	return perms
}

// authorizeMCPMethod gates an ACME admin JSON-RPC method against the
// qrdb-backed PermissionGate.
//
// An unknown method (one with no handler) is allowed through so the dispatcher
// can answer "method not found" — it reaches no service code. A dispatchable
// method whose mirrored RPC declares no permission is a registration bug and
// is denied. The /mcp endpoint once carried no authentication and no
// authorization at all, so every admin operation was reachable by any caller
// that could open a TCP connection to the admin listener.
func (s *MultiProtocolServer) authorizeMCPMethod(ctx context.Context, method string) error {
	entry, dispatchable := s.mcpHandlers[method]
	if !dispatchable {
		return nil
	}
	perm, mapped := adminRPCPermissions[entry.rpc]
	if !mapped {
		s.logger.ErrorContext(ctx, "ACME admin MCP method has no permission mapping; denying",
			slog.String("method", method))
		return admin.ErrOperationUnmapped
	}

	return s.gate.Authorize(ctx, qrdbsdk.PermissionResource(perm), qrdbsdk.PermissionAction(perm),
		slog.String("method", method))
}
