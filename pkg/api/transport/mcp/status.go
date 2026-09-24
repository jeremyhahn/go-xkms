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
	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
)

// wireCodeToRPCCode maps go-qrdb's MCP wire.Code -- the classification the
// unified server's mcpToolHandler stamps into a failing xkms tool result's
// StructuredContent (see pkg/apimodule/module_mcp_errors.go's
// keyOpCodeToWire, the server-side half of this contract) -- back onto the
// JSON-RPC error codes RPCError has always carried.
//
// It is the reverse of keyOpCodeToWire, not the reverse of nothing: xkms's
// JSON-RPC vocabulary has no dedicated NotFound member (mapKeyOpError's own
// doc comment says so, in pkg/api/mcp/errors_keyops.go), so wire.CodeNotFound
// joins wire.CodeInvalidArgument in ErrCodeInvalidParams here -- the same
// bucket the deleted keyword matcher put a "not found" message in, so the
// classification a caller observes does not move even though the mechanism
// producing it did (go-qrdb#438, go-xkms#797).
//
// A map rather than a switch, so a wire code added without a row here is a
// missing entry a reviewer can see instead of a default branch that silently
// downgrades it.
var wireCodeToRPCCode = map[wire.Code]int{
	wire.CodeUnauthenticated:  xkmsmcp.ErrCodeUnauthorized,
	wire.CodePermissionDenied: xkmsmcp.ErrCodeForbidden,
	wire.CodeNotFound:         xkmsmcp.ErrCodeInvalidParams,
	wire.CodeUnavailable:      xkmsmcp.ErrCodeServiceUnavailable,
	wire.CodeInvalidArgument:  xkmsmcp.ErrCodeInvalidParams,
	wire.CodeUnimplemented:    xkmsmcp.ErrCodeMethodNotFound,
	wire.CodeInternal:         xkmsmcp.ErrCodeInternalError,
}

// classifyWireCode implements mcptool.ErrorClassifier: it looks up code in
// wireCodeToRPCCode, defaulting to ErrCodeInternalError for a code the table
// does not declare (a code with no JSON-RPC counterpart, or a number a
// future server sends that predates this table) -- the same floor
// mapKeyOpError itself uses server-side ("anything else is an internal
// fault"). This is the sole place this package's Transport still classifies
// by CODE; the envelope decoding itself belongs to pkg/mcptool now (see
// mcptool.Client.newToolError), shared with sdk/go/client/ssh's MCP client.
func classifyWireCode(code wire.Code) int {
	if c, ok := wireCodeToRPCCode[code]; ok {
		return c
	}
	return xkmsmcp.ErrCodeInternalError
}
