// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRpcCall_ServerClosesConnection exercises the scanner.Scan() == false
// path where the server closes the connection after the health check.
func TestRpcCall_ServerClosesConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					var req jsonrpcRequest
					if unmarshalErr := json.Unmarshal(scanner.Bytes(), &req); unmarshalErr != nil {
						c.Close()
						return
					}
					if req.Method == "health" {
						resp := jsonrpcResponse{
							JSONRPC: "2.0",
							ID:      req.ID,
							Result:  json.RawMessage(`{"status":"ok"}`),
						}
						data, _ := json.Marshal(resp)
						data = append(data, '\n')
						_, _ = c.Write(data)
					} else {
						// Close connection for non-health requests
						c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	tr, err := New(transport.WithAddress(ln.Addr().String()))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	defer tr.Close()

	// This call should hit the "connection closed by server" path
	var result map[string]string
	err = tr.rpcCall(context.Background(), "xkms.listBackends", nil, &result)
	require.Error(t, err)
	var recvErr *ReceiveError
	assert.True(t, errors.As(err, &recvErr))
}

// TestRpcCall_InvalidJSONResponse exercises the unmarshal response error path
// where the server returns invalid JSON.
func TestRpcCall_InvalidJSONResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					var req jsonrpcRequest
					if unmarshalErr := json.Unmarshal(scanner.Bytes(), &req); unmarshalErr != nil {
						return
					}
					if req.Method == "health" {
						resp := jsonrpcResponse{
							JSONRPC: "2.0",
							ID:      req.ID,
							Result:  json.RawMessage(`{"status":"ok"}`),
						}
						data, _ := json.Marshal(resp)
						data = append(data, '\n')
						_, _ = c.Write(data)
					} else {
						// Write invalid JSON
						_, _ = c.Write([]byte("{invalid-json\n"))
					}
				}
			}(conn)
		}
	}()

	tr, err := New(transport.WithAddress(ln.Addr().String()))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	defer tr.Close()

	var result map[string]string
	err = tr.rpcCall(context.Background(), "xkms.listBackends", nil, &result)
	require.Error(t, err)
	var unmarshalErr *UnmarshalError
	assert.True(t, errors.As(err, &unmarshalErr))
}

// TestRequest_InvalidMethod exercises the method-not-found error path
// in Request when the REST-to-RPC mapping fails.
func TestRequest_InvalidMethod(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		return jsonrpcResponse{Result: json.RawMessage(`{}`)}
	})
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
