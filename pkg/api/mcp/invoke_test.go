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
	"errors"
)

// invokeRequest drives req through Server.InvokeMethod -- the package's
// single production dispatch entry point, which now backs both the retired
// wire path's tests and the unified-API-server module's real MCP tools --
// and wraps the result in a *JSONRPCResponse. It exists so tests written
// against the pre-network-removal wire envelope keep their existing
// assertions (resp.Error.Code, resp.Result, ...) while actually exercising
// InvokeMethod's tenant-scoping, authorization, and dispatch, exactly as the
// module backend does.
func invokeRequest(s *Server, ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	result, err := s.InvokeMethod(ctx, req.Method, req.Params)
	if err != nil {
		code := ErrCodeInternalError
		var keyOpErr *KeyOpError
		if errors.As(err, &keyOpErr) {
			code = keyOpErr.Code
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: code, Message: err.Error()},
		}
	}
	return &JSONRPCResponse{JSONRPC: "2.0", Result: result, ID: req.ID}
}
