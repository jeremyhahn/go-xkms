// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRpcCall_ServerUnavailable exercises the ReceiveError path: the tool
// call cannot complete at all because the server has gone away after a
// successful Connect. This is the Streamable HTTP analogue of the previous
// TCP transport's "server closes the connection mid-call" test — the
// previous transport could distinguish that from every other socket
// failure; the MCP client library reports both as one CallTool error, which
// rpcCall wraps as ReceiveError.
func TestRpcCall_ServerUnavailable(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	// Shut the server down after a successful Connect so the next call
	// fails to reach it.
	cleanup()

	var result map[string]string
	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, &result)
	require.Error(t, err)
	var recvErr *ReceiveError
	assert.True(t, errors.As(err, &recvErr))
}

// TestRpcCall_InvalidJSONResponse exercises the unmarshal response error path
// where the tool's text content is not valid JSON for the requested result
// type.
func TestRpcCall_InvalidJSONResponse(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		return jsonrpcResponse{Result: json.RawMessage(`{invalid-json`)}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	var result map[string]string
	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, &result)
	require.Error(t, err)
	var unmarshalErr *UnmarshalError
	assert.True(t, errors.As(err, &unmarshalErr))
}

// TestRequest_InvalidMethod exercises the method-not-found error path
// in Request when the REST-to-RPC mapping fails.
func TestRequest_InvalidMethod(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.Request(context.Background(), "/unknown/path", nil, nil)
	assert.Error(t, err)
}

// TestHealthy_Connected exercises the Healthy method when connected to a
// healthy server.
func TestHealthy_Connected_Success(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	ok := tr.Healthy(context.Background())
	assert.True(t, ok)
}

// TestRpcCall_ToolError_KeywordMapping exercises newToolError's best-effort
// classification of a tool-error message that carries no legacy JSON-RPC
// code (the real unified qrdb MCP server's tool errors are plain text, not
// a structured error object): toolErrorCode's keyword table must recover
// the same codes the xkms MCP server's own mapKeyOpError would have used
// server-side (see pkg/api/mcp/errors_keyops.go).
func TestRpcCall_ToolError_KeywordMapping(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		wantCode int
	}{
		{"not found", "key k1 not found", xkmsmcp.ErrCodeInvalidParams},
		{"validation", "validation failed: weak hash refused", xkmsmcp.ErrCodeInvalidParams},
		{"not supported", "operation not supported by this backend", xkmsmcp.ErrCodeMethodNotFound},
		{"unauthorized", "unauthorized: missing credential", xkmsmcp.ErrCodeUnauthorized},
		{"forbidden", "forbidden: role required", xkmsmcp.ErrCodeForbidden},
		{"unavailable", "backend unavailable", xkmsmcp.ErrCodeServiceUnavailable},
		{"opaque", "boom", xkmsmcp.ErrCodeInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
				if req.Method == "health" {
					data, _ := json.Marshal(map[string]string{"status": "ok"})
					return jsonrpcResponse{Result: data}
				}
				return jsonrpcResponse{ErrorText: tt.message}
			})
			defer cleanup()

			tr := connectToMockServer(t, addr)
			defer tr.Close()

			err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, nil)
			require.Error(t, err)
			var rpcErr *RPCError
			require.True(t, errors.As(err, &rpcErr))
			assert.Equal(t, tt.wantCode, rpcErr.Code)
			assert.Equal(t, tt.message, rpcErr.Message)
		})
	}
}

// TestNewToolError_NoContent exercises newToolError's fallback message when
// the server reports a tool error with no text content at all.
func TestNewToolError_NoContent(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		return jsonrpcResponse{EmptyError: true}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, nil)
	require.Error(t, err)
	var rpcErr *RPCError
	require.True(t, errors.As(err, &rpcErr))
	assert.Equal(t, xkmsmcp.ErrCodeInternalError, rpcErr.Code)
}
