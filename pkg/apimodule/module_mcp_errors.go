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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	mcpgo "github.com/mark3labs/mcp-go/mcp"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// keyOpCodeToWire maps pkg/api/mcp's JSON-RPC error codes (the numbering
// *KeyOpError carries) onto go-qrdb's MCP qrdbsdk.MCPCode, the classification go-
// qrdb's own MCP server puts in a failed tool result's StructuredContent (see
// go-qrdb pkg/api/mcp/wire and pkg/api/mcp/status.go's classifyToolError).
// This is the same contract, adopted rather than re-invented: go-qrdb's own
// SDK client (sdk/go/transport/mcp) reads a tool failure's classification
// from exactly this envelope, and never from the tool result's text.
//
// The three sdkssh.JSONRPCCode* rows are defined in sdk/go/client/ssh/
// mcp_status.go. JSONRPCCodeNotFound is shared by every not-found producer
// in pkg/api/mcp, not only the SSH sub-system: mapSSHError (errors_ssh.go),
// mapKeyOpError's keyOpSentinelCodes (errors_keyops.go, for
// xkms.ErrKeyNotFound/ErrBackendNotFound), and mapUserError
// (handlers_user.go, for a *qrdbsdk.UserNotFoundError) all stamp it rather
// than each minting a separate not-found code (go-xkms#814). Duplicate and
// Mismatch remain SSH-specific: mapSSHError is still their only producer,
// so a duplicate and a host-key mismatch reach the wire on their own
// distinct qrdbsdk.MCPCode instead of sharing ErrCodeInvalidParams the way the
// xkms.* method family's coarser eight-code vocabulary still does for
// everything but NotFound (go-xkms#792). qrdbsdk.MCPCodeFailedPrecondition is the
// closest go-qrdb code for Mismatch: it renders codes.FailedPrecondition,
// and sdk/go/client/ssh/grpc_status.go's GRPCCodeForError already uses that
// same gRPC code for the identical condition, so MCP and gRPC agree.
//
// A map rather than a switch, so an xkms code added without a row here is a
// missing entry a reviewer can see instead of a default branch that
// silently downgrades it to CodeInternal.
var keyOpCodeToWire = map[int]qrdbsdk.MCPCode{
	xkmsmcp.ErrCodeParseError:         qrdbsdk.MCPCodeInvalidArgument,
	xkmsmcp.ErrCodeInvalidRequest:     qrdbsdk.MCPCodeInvalidArgument,
	xkmsmcp.ErrCodeMethodNotFound:     qrdbsdk.MCPCodeUnimplemented,
	xkmsmcp.ErrCodeInvalidParams:      qrdbsdk.MCPCodeInvalidArgument,
	xkmsmcp.ErrCodeInternalError:      qrdbsdk.MCPCodeInternal,
	xkmsmcp.ErrCodeUnauthorized:       qrdbsdk.MCPCodeUnauthenticated,
	xkmsmcp.ErrCodeForbidden:          qrdbsdk.MCPCodePermissionDenied,
	xkmsmcp.ErrCodeServiceUnavailable: qrdbsdk.MCPCodeUnavailable,
	sdkssh.JSONRPCCodeNotFound:        qrdbsdk.MCPCodeNotFound,
	sdkssh.JSONRPCCodeDuplicate:       qrdbsdk.MCPCodeAlreadyExists,
	sdkssh.JSONRPCCodeMismatch:        qrdbsdk.MCPCodeFailedPrecondition,
}

// wireCodeForKeyOp renders a *KeyOpError's local code as go-qrdb's qrdbsdk.MCPCode.
// A code this table does not declare (there is none today; the floor exists
// so a future xkms code added to pkg/api/mcp without a row here still
// answers a classified fault rather than panicking or silently losing its
// code) falls back to qrdbsdk.MCPCodeInternal, the same defensive floor go-qrdb's
// own classifyToolError uses for a gRPC code its table does not cover.
func wireCodeForKeyOp(code int) qrdbsdk.MCPCode {
	if c, ok := keyOpCodeToWire[code]; ok {
		return c
	}
	return qrdbsdk.MCPCodeInternal
}

// codedToolResult renders a failed tool call as an MCP tool result carrying
// both the prose a human reads and the go-qrdb wire code a client branches
// on, in the exact shape go-qrdb's own MCP server produces (toolErrorResult
// in pkg/api/mcp/status.go): the text content is the client-facing message
// (xkmsmcp.ClientError's, which withholds an internal error's detail), and
// the structured content is the classified envelope.
func codedToolResult(tool string, code qrdbsdk.MCPCode, message string) *mcpgo.CallToolResult {
	res := mcpgo.NewToolResultError(message)
	res.StructuredContent = qrdbsdk.NewMCPErrorEnvelope(tool, code, message)
	return res
}
