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

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
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

// TestRpcCall_ToolError_ClassifiedByCode proves classifyToolError branches on
// the wire.Code carried in a failing result's StructuredContent, mapping
// every code the server's keyOpCodeToWire table can produce (plus
// wire.CodeNotFound, go-qrdb#438's addition) onto the JSON-RPC error code
// this SDK has always exposed as *RPCError.Code — never by matching the
// message text, which the server is free to phrase however it likes.
//
// wire.CodeNotFound classifies onto sdkssh.JSONRPCCodeNotFound, not
// xkmsmcp.ErrCodeInvalidParams (go-xkms#814): a missing key or user is
// reported distinctly from a malformed request, matching go-qrdb's own
// MCP/gRPC/QUIC transports' NotFound classification for the same
// conditions ("lower layers win").
func TestRpcCall_ToolError_ClassifiedByCode(t *testing.T) {
	tests := []struct {
		name     string
		code     wire.Code
		message  string
		wantCode int
	}{
		{"unauthenticated", wire.CodeUnauthenticated, "missing credential", xkmsmcp.ErrCodeUnauthorized},
		{"permission denied", wire.CodePermissionDenied, "role required", xkmsmcp.ErrCodeForbidden},
		{"not found", wire.CodeNotFound, "key k1 not found", sdkssh.JSONRPCCodeNotFound},
		{"unavailable", wire.CodeUnavailable, "backend unavailable", xkmsmcp.ErrCodeServiceUnavailable},
		{"invalid argument", wire.CodeInvalidArgument, "validation failed: weak hash refused", xkmsmcp.ErrCodeInvalidParams},
		{"unimplemented", wire.CodeUnimplemented, "operation not supported by this backend", xkmsmcp.ErrCodeMethodNotFound},
		{"internal", wire.CodeInternal, "xkms: internal error", xkmsmcp.ErrCodeInternalError},
		// A code with no JSON-RPC counterpart degrades to ErrCodeInternalError
		// rather than being dropped or panicking.
		{"unmapped code degrades to internal", wire.CodeResourceExhausted, "quota exceeded", xkmsmcp.ErrCodeInternalError},
		{"unrecognized future code degrades to internal", wire.Code(-32098), "from a later server", xkmsmcp.ErrCodeInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
				if req.Method == "health" {
					data, _ := json.Marshal(map[string]string{"status": "ok"})
					return jsonrpcResponse{Result: data}
				}
				return jsonrpcResponse{ErrorText: tt.message, Envelope: tt.code}
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

// TestRpcCall_ToolError_TriggerWordWithDifferentCode is the regression the
// deleted keyword matcher could not pass: a message containing a word the
// old toolErrorCode would have matched ("not found") but carrying an
// UNRELATED wire code must classify by the code, not the word.
func TestRpcCall_ToolError_TriggerWordWithDifferentCode(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		// The message says "not found" and "forbidden", words the deleted
		// keyword matcher would have read as InvalidParams or Forbidden. The
		// envelope says Internal, and Internal is what must reach the caller.
		return jsonrpcResponse{
			ErrorText: "raft apply failed: key not found while forbidden path was retried",
			Envelope:  wire.CodeInternal,
		}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, nil)
	require.Error(t, err)
	var rpcErr *RPCError
	require.True(t, errors.As(err, &rpcErr))
	assert.Equal(t, xkmsmcp.ErrCodeInternalError, rpcErr.Code,
		"a fault whose prose happened to contain classifier trigger words was misclassified by text")
}

// TestRpcCall_ToolError_NoEnvelope proves a failing result with no
// go-qrdb wire envelope is reported as a protocol error, per the project's
// no-backward-compatibility rule: there is no text-based fallback
// classification any more (go-xkms#797).
func TestRpcCall_ToolError_NoEnvelope(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		// ErrorText with no Envelope: an uncoded tool failure.
		return jsonrpcResponse{ErrorText: "boom, no envelope"}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, nil)
	require.Error(t, err)
	var envErr *EnvelopeMissingError
	require.True(t, errors.As(err, &envErr))
	assert.Equal(t, "boom, no envelope", envErr.Message)

	var rpcErr *RPCError
	assert.False(t, errors.As(err, &rpcErr), "an uncoded failure must not be reported as a classified *RPCError")
}

// TestRpcCall_ToolError_NoContent exercises classifyToolError's fallback
// message when the server reports a tool error with no content and no
// envelope at all; it is still a protocol error, not an internal *RPCError.
func TestRpcCall_ToolError_NoContent(t *testing.T) {
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
	var envErr *EnvelopeMissingError
	require.True(t, errors.As(err, &envErr))
	assert.Equal(t, "tool call failed", envErr.Message)
}
