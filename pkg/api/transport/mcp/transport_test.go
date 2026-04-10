// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Error type tests ---

func TestRPCError_Error(t *testing.T) {
	e := &RPCError{Code: -32600, Message: "invalid request"}
	assert.Equal(t, "rpc error -32600: invalid request", e.Error())
}

func TestRPCError_Error_WithData(t *testing.T) {
	e := &RPCError{Code: -32600, Message: "invalid", Data: json.RawMessage(`{"detail":"bad"}`)}
	assert.Contains(t, e.Error(), "data:")
	assert.Contains(t, e.Error(), "bad")
}

func TestMarshalError_Error(t *testing.T) {
	e := &MarshalError{Operation: "request", Err: errors.New("bad json")}
	assert.Contains(t, e.Error(), "marshal request")
	assert.Contains(t, e.Error(), "bad json")
}

func TestMarshalError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &MarshalError{Operation: "test", Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestUnmarshalError_Error(t *testing.T) {
	e := &UnmarshalError{Operation: "response", Err: errors.New("unexpected EOF")}
	assert.Contains(t, e.Error(), "unmarshal response")
	assert.Contains(t, e.Error(), "unexpected EOF")
}

func TestUnmarshalError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &UnmarshalError{Operation: "test", Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestSendError_Error(t *testing.T) {
	e := &SendError{Err: errors.New("broken pipe")}
	assert.Contains(t, e.Error(), "send request")
	assert.Contains(t, e.Error(), "broken pipe")
}

func TestSendError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &SendError{Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestReceiveError_Error(t *testing.T) {
	e := &ReceiveError{Err: errors.New("connection reset")}
	assert.Contains(t, e.Error(), "receive response")
	assert.Contains(t, e.Error(), "connection reset")
}

func TestReceiveError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &ReceiveError{Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestTLSSetupError_Error(t *testing.T) {
	e := &TLSSetupError{Detail: "bad CA", Err: errors.New("parse failed")}
	assert.Contains(t, e.Error(), "TLS setup")
	assert.Contains(t, e.Error(), "bad CA")
	assert.Contains(t, e.Error(), "parse failed")
}

func TestTLSSetupError_Error_NoUnderlying(t *testing.T) {
	e := &TLSSetupError{Detail: "missing cert"}
	assert.Equal(t, "TLS setup: missing cert", e.Error())
}

func TestTLSSetupError_Unwrap(t *testing.T) {
	cause := errors.New("cause")
	e := &TLSSetupError{Detail: "test", Err: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestJsonrpcError_Error(t *testing.T) {
	e := &jsonrpcError{Code: -32601, Message: "method not found"}
	assert.Equal(t, "JSON-RPC error -32601: method not found", e.Error())
}

func TestJsonrpcError_Error_WithData(t *testing.T) {
	e := &jsonrpcError{Code: -32602, Message: "invalid params", Data: json.RawMessage(`"detail"`)}
	assert.Contains(t, e.Error(), "data:")
}

// --- Constructor tests ---

func TestNew_DefaultConfig(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.config)
}

func TestNew_WithAddress(t *testing.T) {
	tr, err := New(transport.WithAddress("localhost:9090"))
	require.NoError(t, err)
	assert.Equal(t, "localhost:9090", tr.config.Address)
}

func TestNew_InvalidOption(t *testing.T) {
	_, err := New(transport.WithAddress(""))
	require.Error(t, err)
}

func TestNewWithConfig_NilConfig(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestNewWithConfig_CustomConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "custom:1234"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "custom:1234", tr.config.Address)
}

// --- resolveMethod tests ---

func TestResolveMethod_ExactMatch(t *testing.T) {
	tests := []struct {
		path   string
		method string
	}{
		{"/health", "health"},
		{"/api/v1/backends", "xkms.listBackends"},
		{"/api/v1/keys", "xkms.generateKey"},
		{"/api/v1/keys/import", "xkms.importKey"},
		{"/api/v1/seal", "xkms.seal"},
		{"/api/v1/unseal", "xkms.unseal"},
		{"/api/v1/ca/bundle", "xkms.ca.bundle"},
		{"/v1/barrier/initialize", "barrier.initialize"},
		{"/v1/barrier/status", "barrier.status"},
		{"/api/v1/init/status", "init.getStatus"},
		{"/api/v1/credentials/submit", "credentials.submit"},
		{"/api/v1/shares/submit", "xkms.submitShare"},
		{"/api/v1/tenants", "xkms.listTenants"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			method, ok := resolveMethod(tt.path)
			assert.True(t, ok, "expected match for %s", tt.path)
			assert.Equal(t, tt.method, method)
		})
	}
}

func TestResolveMethod_DynamicPatterns(t *testing.T) {
	tests := []struct {
		path   string
		method string
	}{
		{"/api/v1/keys/software/test-key/sign", "xkms.sign"},
		{"/api/v1/keys/software/test-key/verify", "xkms.verify"},
		{"/api/v1/keys/software/test-key/encrypt", "xkms.encrypt"},
		{"/api/v1/keys/software/test-key/decrypt", "xkms.decrypt"},
		{"/api/v1/keys/software/test-key", "xkms.getKey"},
		{"/api/v1/certs/software/test-key/chain", "xkms.getCertChain"},
		{"/api/v1/certs/software/test-key", "xkms.getCert"},
		{"/api/v1/backends/software", "xkms.getBackend"},
		{"/api/v1/users/admin", "xkms.getUser"},
		{"/api/v1/custodian/groups/g1", "xkms.getCustodianGroup"},
		{"/api/v1/custodian/groups/g1/distribute", "xkms.distributeShares"},
		{"/api/v1/tenants/t1", "xkms.getTenant"},
		{"/api/v1/tenants/t1/barrier/init", "xkms.tenantBarrierInit"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			method, ok := resolveMethod(tt.path)
			assert.True(t, ok, "expected match for %s", tt.path)
			assert.Equal(t, tt.method, method)
		})
	}
}

func TestResolveMethod_QueryParams(t *testing.T) {
	method, ok := resolveMethod("/health?verbose=true")
	assert.True(t, ok)
	assert.Equal(t, "health", method)
}

func TestResolveMethod_NotFound(t *testing.T) {
	_, ok := resolveMethod("/api/v1/nonexistent")
	assert.False(t, ok)
}

// --- Connection tests ---

func TestConnect_NotConnected_MethodsReturnError(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = tr.Health(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListBackends(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClose_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
}

func TestConnect_HealthCheck(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return
		}

		var req jsonrpcRequest
		if unmarshalErr := json.Unmarshal(buf[:n], &req); unmarshalErr != nil {
			return
		}

		resp := jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`{"status":"ok","version":"1.0.0"}`),
		}
		data, marshalErr := json.Marshal(resp)
		if marshalErr != nil {
			return
		}
		data = append(data, '\n')
		if _, writeErr := conn.Write(data); writeErr != nil {
			return
		}
	}()

	tr, err := New(transport.WithAddress(listener.Addr().String()))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	defer tr.Close()

	assert.True(t, tr.connected)
}

func TestConnect_FailedDial(t *testing.T) {
	tr, err := New(transport.WithAddress("127.0.0.1:1"))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrConnectionFailed))
}

// --- Conn and Config ---

func TestConn_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

func TestConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "test:1234"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test:1234", tr.Config().Address)
}

func TestIsConnected_Default(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.IsConnected())
}

// --- Request without connection ---

func TestRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	err = tr.Request(context.Background(), "/health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRequest_UnknownPath(t *testing.T) {
	// Create a connected transport to test path resolution
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		// Health check response
		buf := make([]byte, 4096)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return
		}
		var req jsonrpcRequest
		if unmarshalErr := json.Unmarshal(buf[:n], &req); unmarshalErr != nil {
			return
		}
		resp := jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{"status":"ok"}`)}
		data, _ := json.Marshal(resp)
		data = append(data, '\n')
		conn.Write(data)
	}()

	tr, err := New(transport.WithAddress(listener.Addr().String()))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()
	defer listener.Close()

	err = tr.Request(context.Background(), "/nonexistent/path", nil, nil)
	assert.Error(t, err)
	var te *transport.TransportError
	require.True(t, errors.As(err, &te))
	assert.Equal(t, transport.ErrCodeMethodNotFound, te.Code)
}

// --- RequestStream ---

func TestRequestStream_NotSupported(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	_, err = tr.RequestStream(context.Background(), "test", nil)
	assert.ErrorIs(t, err, transport.ErrStreamNotSupported)
}

// --- Healthy ---

func TestHealthy_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.Healthy(context.Background()))
}

// --- rpcCall with mock server ---

func startMockServer(t *testing.T, handler func(req jsonrpcRequest) jsonrpcResponse) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 65536)
				for {
					n, readErr := c.Read(buf)
					if readErr != nil {
						return
					}
					var req jsonrpcRequest
					if unmarshalErr := json.Unmarshal(buf[:n], &req); unmarshalErr != nil {
						return
					}
					resp := handler(req)
					resp.JSONRPC = "2.0"
					resp.ID = req.ID
					data, marshalErr := json.Marshal(resp)
					if marshalErr != nil {
						return
					}
					data = append(data, '\n')
					if _, writeErr := c.Write(data); writeErr != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		listener.Close()
		<-done
	}
}

func connectToMockServer(t *testing.T, addr string) *Transport {
	t.Helper()
	tr, err := New(transport.WithAddress(addr))
	require.NoError(t, err)
	err = tr.Connect(context.Background())
	require.NoError(t, err)
	return tr
}

func TestRpcCall_Success(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		result := map[string]string{"method": req.Method}
		data, _ := json.Marshal(result)
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	var result map[string]string
	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, "xkms.listBackends", result["method"])
}

func TestRpcCall_RPCError(t *testing.T) {
	callCount := 0
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		callCount++
		// First call is health check from Connect()
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		return jsonrpcResponse{
			Error: &jsonrpcError{Code: -32600, Message: "invalid request"},
		}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	err := tr.rpcCall(context.Background(), "xkms.listBackends", nil, nil)
	require.Error(t, err)
	var rpcErr *RPCError
	assert.True(t, errors.As(err, &rpcErr))
	assert.Equal(t, -32600, rpcErr.Code)
}

func TestRpcCall_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	err = tr.rpcCall(context.Background(), "health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRpcCall_WithParams(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		data, _ := json.Marshal(map[string]string{"echo": string(req.Params)})
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	params := map[string]string{"key": "value"}
	var result map[string]string
	err := tr.rpcCall(context.Background(), "test", params, &result)
	require.NoError(t, err)
	assert.Contains(t, result["echo"], "value")
}
