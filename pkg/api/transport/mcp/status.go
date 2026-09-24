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
	"github.com/mark3labs/mcp-go/mcp"

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

// classifyToolError turns a failing MCP tool result into the typed error an
// SDK caller sees.
//
// A result carrying go-qrdb's wire.ErrorEnvelope in its StructuredContent is
// classified by CODE, never by its prose: this is the fail-open
// classification go-qrdb#438 deleted from go-qrdb's own SDK client, adopted
// here rather than re-invented (go-xkms#797). A code this build does not
// have a JSON-RPC counterpart for (DeadlineExceeded, ResourceExhausted,
// FailedPrecondition, Canceled, AlreadyExists, Aborted, OutOfRange, DataLoss,
// Unknown, or a number a future server sends that predates this table)
// degrades to ErrCodeInternalError: the caller still gets the server's
// message, it is simply not distinguished from an unclassified fault --
// exactly the floor mapKeyOpError itself uses server-side ("anything else is
// an internal fault").
//
// A failing result with NO envelope is not a degraded guess parsed from
// text. The unified server stamps one onto every failing xkms tool result
// (pkg/apimodule/module_mcp.go's codedToolResult), so a response with none
// did not come from that contract, and is reported as a protocol error
// (*EnvelopeMissingError) instead. There is no text fallback here, per the
// project's no-backward-compatibility rule.
func classifyToolError(tool string, result *mcp.CallToolResult) error {
	payload, ok := wire.DecodeErrorPayload(result.StructuredContent)
	if !ok {
		return &EnvelopeMissingError{Tool: tool, Message: extractToolErrorText(result)}
	}

	code, known := wireCodeToRPCCode[payload.Code]
	if !known {
		code = xkmsmcp.ErrCodeInternalError
	}
	return &RPCError{Code: code, Message: payload.Message}
}

// extractToolErrorText returns the first text content item's text from a
// failing tool result, or a fallback when the result carries no content at
// all.
func extractToolErrorText(result *mcp.CallToolResult) string {
	if len(result.Content) > 0 {
		if text, ok := mcp.AsTextContent(result.Content[0]); ok && text.Text != "" {
			return text.Text
		}
	}
	return "tool call failed"
}
