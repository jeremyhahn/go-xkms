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

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// MockPhone simulates the Android phone's behavior for integration testing.
// It implements the same protocol as the real phone app but runs in-process.
type MockPhone struct {
	mu           sync.Mutex
	noiseSession *bootstrap.NoiseSession
	keys         map[string]*mockKey
	capabilities pairingproto.GetInfoResult
}

type mockKey struct {
	privateKey *ecdsa.PrivateKey
	algorithm  int
}

// NewMockPhone creates a new mock phone for testing.
func NewMockPhone() *MockPhone {
	return &MockPhone{
		keys: make(map[string]*mockKey),
		capabilities: pairingproto.GetInfoResult{
			Version:             "1.0.0-mock",
			DeviceName:          "Mock Phone",
			SupportedAlgorithms: []int{pairingproto.COSEAlgES256, pairingproto.COSEAlgES384, pairingproto.COSEAlgES512},
			MaxCredentials:      100,
			CurrentCredentials:  0,
		},
	}
}

// InitNoiseSession initializes the Noise session as responder.
func (m *MockPhone) InitNoiseSession() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
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
		return nil, false, &MessageError{Msg: "noise session not initialized"}
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
	var req pairingproto.Request
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

func (m *MockPhone) handleRequest(req *pairingproto.Request) *pairingproto.Response {
	resp := &pairingproto.Response{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      req.ID,
	}

	switch req.Method {
	case pairingproto.MethodPing:
		resp.Result = mustMarshal(pairingproto.PingResult{Pong: true})

	case pairingproto.MethodGetInfo:
		m.capabilities.CurrentCredentials = len(m.keys)
		resp.Result = mustMarshal(m.capabilities)

	case pairingproto.MethodGenerateKey:
		resp = m.handleGenerateKey(req)

	case pairingproto.MethodSign:
		resp = m.handleSign(req)

	case pairingproto.MethodDeleteKey:
		resp = m.handleDeleteKey(req)

	case pairingproto.MethodLoadKey:
		resp = m.handleLoadKey(req)

	default:
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeMethodNotFound,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		}
	}

	return resp
}

func (m *MockPhone) handleGenerateKey(req *pairingproto.Request) *pairingproto.Response {
	resp := &pairingproto.Response{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      req.ID,
	}

	var params pairingproto.GenerateKeyParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	// Get curve for algorithm
	curve := curveForAlgorithm(params.Algorithm)
	if curve == nil {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeUnsupportedAlg,
			Message: "unsupported algorithm",
		}
		return resp
	}

	// Generate key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeInternalError,
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
	resp.Result = mustMarshal(pairingproto.GenerateKeyResult{
		PublicKeyCOSE: coseKey,
	})

	return resp
}

func (m *MockPhone) handleSign(req *pairingproto.Request) *pairingproto.Response {
	resp := &pairingproto.Response{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      req.ID,
	}

	var params pairingproto.SignParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	// Find key
	credID := hex.EncodeToString(params.CredentialID)
	key, ok := m.keys[credID]
	if !ok {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	// DataHash is already the hash of the data to sign
	// Sign using the stored private key
	r, s, err := ecdsa.Sign(rand.Reader, key.privateKey, params.DataHash)
	if err != nil {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeInternalError,
			Message: "signing failed",
		}
		return resp
	}

	// Encode signature (DER format simplified)
	signature := encodeSignature(r, s, key.privateKey.Curve)

	resp.Result = mustMarshal(pairingproto.SignResult{
		Signature: signature,
	})

	return resp
}

func (m *MockPhone) handleDeleteKey(req *pairingproto.Request) *pairingproto.Response {
	resp := &pairingproto.Response{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      req.ID,
	}

	var params pairingproto.DeleteKeyParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	credID := hex.EncodeToString(params.CredentialID)
	if _, ok := m.keys[credID]; !ok {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	delete(m.keys, credID)
	resp.Result = mustMarshal(pairingproto.DeleteKeyResult{Deleted: true})
	return resp
}

func (m *MockPhone) handleLoadKey(req *pairingproto.Request) *pairingproto.Response {
	resp := &pairingproto.Response{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      req.ID,
	}

	var params pairingproto.LoadKeyParams
	if err := unmarshalParams(req.Params, &params); err != nil {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeInvalidParams,
			Message: "invalid params",
		}
		return resp
	}

	credID := hex.EncodeToString(params.CredentialID)
	key, ok := m.keys[credID]
	if !ok {
		resp.Error = &pairingproto.RPCError{
			Code:    pairingproto.ErrorCodeKeyNotFound,
			Message: "key not found",
		}
		return resp
	}

	coseKey := encodeCOSEKey(key.privateKey, key.algorithm)
	resp.Result = mustMarshal(pairingproto.LoadKeyResult{
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
	case pairingproto.COSEAlgES256:
		return elliptic.P256()
	case pairingproto.COSEAlgES384:
		return elliptic.P384()
	case pairingproto.COSEAlgES512:
		return elliptic.P521()
	default:
		return nil
	}
}

func encodeCOSEKey(key *ecdsa.PrivateKey, alg int) []byte {
	// Simplified COSE key encoding for testing
	// Real implementation would use proper CBOR encoding
	size := (key.Curve.Params().BitSize + 7) / 8

	// Derive the uncompressed public point (0x04 || X || Y) via crypto/ecdh
	// to avoid the deprecated big.Int coordinate accessors.
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		return nil
	}
	point := ecdhPub.Bytes() // 0x04 || X(size) || Y(size)

	xPadded := point[1 : 1+size]
	yPadded := point[1+size : 1+2*size]

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
