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
)

// invokeRequest drives req through Server.InvokeMethod -- the package's
// single production dispatch entry point, which now backs both the retired
// wire path's tests and the unified-API-server module's real MCP tools --
// and wraps the result in a *JSONRPCResponse. It exists so tests written
// against the pre-network-removal wire envelope keep their existing
// assertions (resp.Error.Code, resp.Result, ...) while actually exercising
// InvokeMethod's tenant-scoping, authorization, and dispatch, exactly as the
// module backend does. The error code and message are ClientError's, the
// same rendering pkg/apimodule's tool handler puts on the wire, so a test
// sees only what a real client sees (go-xkms#1118).
func invokeRequest(s *Server, ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	result, err := s.InvokeMethod(ctx, req.Method, req.Params)
	if err != nil {
		code, message := ClientError(err)
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: code, Message: message},
		}
	}
	return &JSONRPCResponse{JSONRPC: "2.0", Result: result, ID: req.ID}
}
