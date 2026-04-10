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

package phone

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// MockPhone simulates the Android phone's behavior for integration testing.
// It implements the same protocol as the real phone app but runs in-process.
type MockPhone struct {
	mu           sync.Mutex
	noiseSession *phone.NoiseSession
	keys         map[string]*mockKey
	capabilities phone.GetInfoResult
}

type mockKey struct {
	privateKey *ecdsa.PrivateKey
	algorithm  int
}

// NewMockPhone creates a new mock phone for testing.
func NewMockPhone() *MockPhone {
	return &MockPhone{
		keys: make(map[string]*mockKey),
		capabilities: phone.GetInfoResult{
			Version:             "1.0.0-mock",
			DeviceName:          "Mock Phone",
			SupportedAlgorithms: []int{phone.COSEAlgES256, phone.COSEAlgES384, phone.COSEAlgES512},
			MaxCredentials:      100,
			CurrentCredentials:  0,
		},
	}
}

// InitNoiseSession initializes the Noise session as responder.
func (m *MockPhone) InitNoiseSession() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		IsInitiator: false,
	})
	if err != nil {
		return err
	}

	if err := session.InitHandshake(); err != nil {
		return err
	}

	m.noiseSession = session
	return nil
}

// ProcessHandshakeMessage processes a Noise handshake message.
func (m *MockPhone) ProcessHandshakeMessage(incoming []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.noiseSession == nil {
		return nil, false, fmt.Errorf("noise session not initialized")
	}

	return m.noiseSession.HandshakeMessage(incoming)
}

// ProcessRequest decrypts and handles a JSON-RPC request.
func (m *MockPhone) ProcessRequest(encrypted []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.noiseSession == nil || !m.noiseSession.IsHandshakeComplete() {
		return nil, phone.ErrNoiseHandshakeFailed
	}

	// Decrypt request
	plaintext, err := m.noiseSession.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}

	// Parse JSON-RPC request
	var req phone.Request
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, err
	}

	// Handle request
	resp := m.handleRequest(&req)

	// Encode response
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	// Encrypt response
	return m.noiseSession.Encrypt(respBytes)
}

func (m *MockPhone) handleRequest(req *phone.Request) *phone.Response {
	resp := &phone.Response{
		JSONRPC: phone.JSONRPCVersion,
		ID:      req.ID,
	}

	switch req.Method {
	case phone.MethodPing:
		resp.Result = mustMarshal(phone.PingResult{Pong: true})

	case phone.MethodGetInfo:
		m.capabilities.CurrentCredentials = len(m.keys)
		resp.Result = mustMarshal(m.capabilities)

	case phone.MethodGenerateKey:
		resp = m.handleGenerateKey(req)

	case phone.MethodSign:
		resp = m.handleSign(req)

	case phone.MethodDeleteKey:
		resp = m.handleDeleteKey(req)

	case phone.MethodLoadKey:
		resp = m.handleLoadKey(req)

	default:
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeMethodNotFound,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		}
	}

	return resp
}

func (m *MockPhone) handleGenerateKey(req *phone.Request) *phone.Response {
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

	// Get curve for algorithm
	curve := curveForAlgorithm(params.Algorithm)
	if curve == nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeUnsupportedAlg,
			Message: "unsupported algorithm",
		}
		return resp
	}

	// Generate key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInternalError,
			Message: "key generation failed",
		}
		return resp
	}

	// Store key
	credID := hex.EncodeToString(params.CredentialID)
	m.keys[credID] = &mockKey{
		privateKey: privateKey,
		algorithm:  params.Algorithm,
	}

	// Return COSE-encoded public key
	coseKey := encodeCOSEKey(privateKey, params.Algorithm)
	resp.Result = mustMarshal(phone.GenerateKeyResult{
		PublicKeyCOSE: coseKey,
	})

	return resp
}

func (m *MockPhone) handleSign(req *phone.Request) *phone.Response {
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

	// Find key
	credID := hex.EncodeToString(params.CredentialID)
	key, ok := m.keys[credID]
	if !ok {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	// DataHash is already the hash of the data to sign
	// Sign using the stored private key
	r, s, err := ecdsa.Sign(rand.Reader, key.privateKey, params.DataHash)
	if err != nil {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeInternalError,
			Message: "signing failed",
		}
		return resp
	}

	// Encode signature (DER format simplified)
	signature := encodeSignature(r, s, key.privateKey.Curve)

	resp.Result = mustMarshal(phone.SignResult{
		Signature: signature,
	})

	return resp
}

func (m *MockPhone) handleDeleteKey(req *phone.Request) *phone.Response {
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
	if _, ok := m.keys[credID]; !ok {
		resp.Error = &phone.RPCError{
			Code:    phone.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	delete(m.keys, credID)
	resp.Result = mustMarshal(phone.DeleteKeyResult{Deleted: true})
	return resp
}

func (m *MockPhone) handleLoadKey(req *phone.Request) *phone.Response {
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
	key, ok := m.keys[credID]
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

// KeyCount returns the number of stored keys.
func (m *MockPhone) KeyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys)
}

// Helper functions

func curveForAlgorithm(alg int) elliptic.Curve {
	switch alg {
	case phone.COSEAlgES256:
		return elliptic.P256()
	case phone.COSEAlgES384:
		return elliptic.P384()
	case phone.COSEAlgES512:
		return elliptic.P521()
	default:
		return nil
	}
}

func encodeCOSEKey(key *ecdsa.PrivateKey, alg int) []byte {
	// Simplified COSE key encoding for testing
	// Real implementation would use proper CBOR encoding
	x := key.PublicKey.X.Bytes()
	y := key.PublicKey.Y.Bytes()

	// Pad to correct size
	size := (key.Curve.Params().BitSize + 7) / 8
	xPadded := make([]byte, size)
	yPadded := make([]byte, size)
	copy(xPadded[size-len(x):], x)
	copy(yPadded[size-len(y):], y)

	// Simple format: [alg(1)][x(size)][y(size)]
	result := make([]byte, 1+size*2)
	result[0] = byte(alg & 0xFF)
	copy(result[1:], xPadded)
	copy(result[1+size:], yPadded)
	return result
}

func encodeSignature(r, s *big.Int, curve elliptic.Curve) []byte {
	// Fixed-size signature encoding
	size := (curve.Params().BitSize + 7) / 8
	sig := make([]byte, size*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[size-len(rBytes):], rBytes)
	copy(sig[size*2-len(sBytes):], sBytes)
	return sig
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// unmarshalParams handles both json.RawMessage and map[string]interface{} params.
func unmarshalParams(params interface{}, v interface{}) error {
	if params == nil {
		return nil
	}

	// If already bytes, unmarshal directly
	if raw, ok := params.(json.RawMessage); ok {
		return json.Unmarshal(raw, v)
	}

	// Otherwise, re-marshal then unmarshal to convert the type
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
