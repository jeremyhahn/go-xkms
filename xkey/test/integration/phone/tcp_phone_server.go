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

//go:build integration

package phone

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// HandlerFunc is a function that processes a JSON-RPC request and returns a
// JSON-RPC response. Used for map-based dispatch of JSON-RPC methods.
type HandlerFunc func(req *phone.Request) *phone.Response

// MockPhoneRequestHandler implements phone.PeripheralRequestHandler for use
// with the TCPPairingServer. Unlike MockPhone, this handler operates on
// plaintext JSON-RPC because the TCPPairingServer handles Noise encryption
// and decryption at the TCP connection level.
type MockPhoneRequestHandler struct {
	mu           sync.Mutex
	keys         map[string]*mockKey
	capabilities phone.GetInfoResult
	handlers     map[string]HandlerFunc
}

// NewMockPhoneRequestHandler creates a new plaintext JSON-RPC handler for
// testing the TCP pairing server. It maintains its own key store and
// supports the same methods as MockPhone.
func NewMockPhoneRequestHandler() *MockPhoneRequestHandler {
	h := &MockPhoneRequestHandler{
		keys: make(map[string]*mockKey),
		capabilities: phone.GetInfoResult{
			Version:             "1.0.0-mock-tcp",
			DeviceName:          "Mock Phone (TCP)",
			SupportedAlgorithms: []int{phone.COSEAlgES256, phone.COSEAlgES384, phone.COSEAlgES512},
			MaxCredentials:      100,
			CurrentCredentials:  0,
		},
	}
	h.handlers = map[string]HandlerFunc{
		phone.MethodPing:        h.handlePing,
		phone.MethodGetInfo:     h.handleGetInfo,
		phone.MethodGenerateKey: h.handleGenerateKey,
		phone.MethodSign:        h.handleSign,
		phone.MethodDeleteKey:   h.handleDeleteKey,
		phone.MethodLoadKey:     h.handleLoadKey,
	}
	return h
}

// HandleRequest implements phone.PeripheralRequestHandler. It receives
// plaintext JSON-RPC bytes, dispatches to the appropriate handler, and
// returns plaintext JSON-RPC response bytes.
func (h *MockPhoneRequestHandler) HandleRequest(_ context.Context, request []byte) ([]byte, error) {
	var req phone.Request
	if err := json.Unmarshal(request, &req); err != nil {
		errResp := &phone.Response{
			JSONRPC: phone.JSONRPCVersion,
			Error: &phone.RPCError{
				Code:    phone.ErrorCodeInvalidRequest,
				Message: "invalid JSON-RPC request",
			},
		}
		return json.Marshal(errResp)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	handler, ok := h.handlers[req.Method]
	if !ok {
		resp := &phone.Response{
			JSONRPC: phone.JSONRPCVersion,
			ID:      req.ID,
			Error: &phone.RPCError{
				Code:    phone.ErrorCodeMethodNotFound,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			},
		}
		return json.Marshal(resp)
	}

	resp := handler(&req)
	return json.Marshal(resp)
}

// KeyCount returns the number of stored keys. Safe for concurrent access.
func (h *MockPhoneRequestHandler) KeyCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.keys)
}

func (h *MockPhoneRequestHandler) handlePing(req *phone.Request) *phone.Response {
	return &phone.Response{
		JSONRPC: phone.JSONRPCVersion,
		ID:      req.ID,
		Result:  mustMarshal(phone.PingResult{Pong: true}),
	}
}

func (h *MockPhoneRequestHandler) handleGetInfo(req *phone.Request) *phone.Response {
	h.capabilities.CurrentCredentials = len(h.keys)
	return &phone.Response{
		JSONRPC: phone.JSONRPCVersion,
		ID:      req.ID,
		Result:  mustMarshal(h.capabilities),
	}
}

func (h *MockPhoneRequestHandler) handleGenerateKey(req *phone.Request) *phone.Response {
	resp := &phone.Response{
		JSONRPC: phone.JSONRPCVersion,
		ID:      req.ID,
	}

	var params phone.GenerateKeyParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	curve := curveForAlgorithm(params.Algorithm)
	if curve == nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeUnsupportedAlg,
			Message: "unsupported algorithm",
		}
		return resp
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInternalError,
			Message: "key generation failed",
		}
		return resp
	}

	credID := hex.EncodeToString(params.CredentialID)
	h.keys[credID] = &mockKey{
		privateKey: privateKey,
		algorithm:  params.Algorithm,
	}

	coseKey := encodeCOSEKey(privateKey, params.Algorithm)
	resp.Result = mustMarshal(phone.GenerateKeyResult{
		PublicKeyCOSE: coseKey,
	})
	return resp
}

func (h *MockPhoneRequestHandler) handleSign(req *phone.Request) *phone.Response {
	resp := &phone.Response{
		JSONRPC: phone.JSONRPCVersion,
		ID:      req.ID,
	}

	var params phone.SignParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	credID := hex.EncodeToString(params.CredentialID)
	key, ok := h.keys[credID]
	if !ok {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	r, s, err := ecdsa.Sign(rand.Reader, key.privateKey, params.DataHash)
	if err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInternalError,
			Message: "signing failed",
		}
		return resp
	}

	signature := encodeSignature(r, s, key.privateKey.Curve)
	resp.Result = mustMarshal(phone.SignResult{
		Signature: signature,
	})
	return resp
}

func (h *MockPhoneRequestHandler) handleDeleteKey(req *phone.Request) *phone.Response {
	resp := &phone.Response{
		JSONRPC: phone.JSONRPCVersion,
		ID:      req.ID,
	}

	var params phone.DeleteKeyParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	credID := hex.EncodeToString(params.CredentialID)
	if _, ok := h.keys[credID]; !ok {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	delete(h.keys, credID)
	resp.Result = mustMarshal(phone.DeleteKeyResult{Deleted: true})
	return resp
}

func (h *MockPhoneRequestHandler) handleLoadKey(req *phone.Request) *phone.Response {
	resp := &phone.Response{
		JSONRPC: phone.JSONRPCVersion,
		ID:      req.ID,
	}

	var params phone.LoadKeyParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	credID := hex.EncodeToString(params.CredentialID)
	key, ok := h.keys[credID]
	if !ok {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	coseKey := encodeCOSEKey(key.privateKey, key.algorithm)
	resp.Result = mustMarshal(phone.LoadKeyResult{
		PublicKeyCOSE: coseKey,
	})
	return resp
}

// TCPPhoneServer wraps a TCPPairingServer with a MockPhoneRequestHandler
// for E2E integration testing of the full TCP wire protocol. The TCP server
// handles Noise XX handshake and encryption, while the handler processes
// plaintext JSON-RPC requests.
type TCPPhoneServer struct {
	server  *phone.TCPPairingServer
	handler *MockPhoneRequestHandler
}

// NewTCPPhoneServer creates a new TCP phone server bound to a random port
// (":0"). The server is not started; call Start() to begin accepting
// connections.
func NewTCPPhoneServer() (*TCPPhoneServer, error) {
	handler := NewMockPhoneRequestHandler()

	server, err := phone.NewTCPPairingServer(&phone.TCPPairingConfig{
		ListenAddr:     ":0",
		RequestHandler: handler,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP pairing server: %w", err)
	}

	return &TCPPhoneServer{
		server:  server,
		handler: handler,
	}, nil
}

// Start begins listening for TCP connections and accepting them in the
// background. Each connection performs a Noise XX handshake followed by
// encrypted JSON-RPC request/response processing.
func (s *TCPPhoneServer) Start() error {
	return s.server.Start()
}

// Stop gracefully stops the TCP server, closing the listener and draining
// active connections.
func (s *TCPPhoneServer) Stop() error {
	return s.server.Stop()
}

// Addr returns the listener address. This is useful for discovering the
// randomly assigned port when listening on ":0".
func (s *TCPPhoneServer) Addr() string {
	return s.server.Addr()
}

// LocalStaticPublicKey returns the server's Noise static public key. Clients
// can use this to verify the server's identity during the handshake.
func (s *TCPPhoneServer) LocalStaticPublicKey() []byte {
	return s.server.LocalStaticPublicKey()
}

// KeyCount returns the number of keys stored in the mock handler.
func (s *TCPPhoneServer) KeyCount() int {
	return s.handler.KeyCount()
}

// Ensure MockPhoneRequestHandler implements PeripheralRequestHandler.
var _ phone.PeripheralRequestHandler = (*MockPhoneRequestHandler)(nil)
