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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPhoneResponder simulates the phone side of the Noise channel.
// It reads encrypted requests from the transport, decrypts them with
// the responder's Noise session, routes to registered handlers, encrypts
// the response, and sends it back. This enables full end-to-end testing
// of PhoneKeyBackend methods with real Noise cryptography.
type mockPhoneResponder struct {
	transport *mockPipeTransport
	session   *NoiseSession
	t         *testing.T
	handlers  map[string]func(params json.RawMessage) (interface{}, error)
}

func newMockPhoneResponder(t *testing.T, transport *mockPipeTransport, session *NoiseSession) *mockPhoneResponder {
	t.Helper()

	r := &mockPhoneResponder{
		transport: transport,
		session:   session,
		t:         t,
		handlers:  make(map[string]func(params json.RawMessage) (interface{}, error)),
	}

	r.handlers[MethodGenerateKey] = r.handleGenerateKey
	r.handlers[MethodSign] = r.handleSign
	r.handlers[MethodLoadKey] = r.handleLoadKey
	r.handlers[MethodDeleteKey] = r.handleDeleteKey
	r.handlers[MethodGetInfo] = r.handleGetInfo
	r.handlers[MethodPing] = r.handlePing
	r.handlers[MethodLocalListFido2Credentials] = r.handleListFido2Credentials
	r.handlers[MethodLocalSignFido2Assertion] = r.handleSignFido2Assertion

	return r
}

// handleOne reads one encrypted request, decrypts it, routes to the
// appropriate handler, encrypts the response, and sends it back.
func (r *mockPhoneResponder) handleOne() {
	r.t.Helper()

	ctx := context.Background()

	// Read ciphertext sent by the initiator (PhoneKeyBackend).
	// The initiator's SendAndReceive calls Send (writes to initiator's sendCh)
	// then Receive (reads from initiator's recvCh). The responder reads from
	// its recvCh (which is the initiator's sendCh).
	ciphertext, err := r.transport.Receive(ctx)
	require.NoError(r.t, err, "responder: failed to receive ciphertext")

	// Decrypt with the responder's Noise session.
	plaintext, err := r.session.Decrypt(ciphertext)
	require.NoError(r.t, err, "responder: failed to decrypt request")

	// Decode the JSON-RPC request.
	var req Request
	err = json.Unmarshal(plaintext, &req)
	require.NoError(r.t, err, "responder: failed to unmarshal request")

	// Route to the appropriate handler.
	handler, ok := r.handlers[req.Method]
	require.True(r.t, ok, "responder: no handler registered for method: %s", req.Method)

	var rawParams json.RawMessage
	if req.Params != nil {
		rawParams, err = json.Marshal(req.Params)
		require.NoError(r.t, err, "responder: failed to re-marshal params")
	}

	result, handlerErr := handler(rawParams)

	// Build the JSON-RPC response.
	var resp Response
	resp.JSONRPC = JSONRPCVersion
	resp.ID = req.ID

	if handlerErr != nil {
		resp.Error = &RPCError{Code: -32000, Message: handlerErr.Error()}
	} else {
		resp.Result, err = json.Marshal(result)
		require.NoError(r.t, err, "responder: failed to marshal result")
	}

	// Encode, encrypt, and send the response.
	respBytes, err := json.Marshal(resp)
	require.NoError(r.t, err, "responder: failed to marshal response")

	respCiphertext, err := r.session.Encrypt(respBytes)
	require.NoError(r.t, err, "responder: failed to encrypt response")

	err = r.transport.Send(ctx, respCiphertext)
	require.NoError(r.t, err, "responder: failed to send response ciphertext")
}

// ---------------------------------------------------------------------------
// Mock phone response handlers
// ---------------------------------------------------------------------------

func (r *mockPhoneResponder) handleGenerateKey(_ json.RawMessage) (interface{}, error) {
	return &GenerateKeyResult{PublicKeyCOSE: []byte{0x01, 0x02, 0x03}}, nil
}

func (r *mockPhoneResponder) handleSign(_ json.RawMessage) (interface{}, error) {
	return &SignResult{Signature: []byte{0x30, 0x44}}, nil
}

func (r *mockPhoneResponder) handleLoadKey(_ json.RawMessage) (interface{}, error) {
	return &LoadKeyResult{Exists: true, PublicKeyCOSE: []byte{0x01, 0x02}}, nil
}

func (r *mockPhoneResponder) handleDeleteKey(_ json.RawMessage) (interface{}, error) {
	return &DeleteKeyResult{Deleted: true}, nil
}

func (r *mockPhoneResponder) handleGetInfo(_ json.RawMessage) (interface{}, error) {
	return &GetInfoResult{
		Version:             "1.0",
		DeviceName:          "Test Phone",
		SupportedAlgorithms: []int{COSEAlgES256, COSEAlgES384, COSEAlgES512},
		MaxCredentials:      100,
		CurrentCredentials:  5,
	}, nil
}

func (r *mockPhoneResponder) handlePing(_ json.RawMessage) (interface{}, error) {
	return &PingResult{Pong: true}, nil
}

func (r *mockPhoneResponder) handleListFido2Credentials(_ json.RawMessage) (interface{}, error) {
	return &LocalListFido2CredentialsResult{
		Credentials: []Fido2CredentialInfo{
			{
				CredentialID: []byte("cred-1"),
				RpID:         "example.com",
				UserName:     "alice",
			},
		},
	}, nil
}

func (r *mockPhoneResponder) handleSignFido2Assertion(_ json.RawMessage) (interface{}, error) {
	return &LocalSignFido2AssertionResult{
		AuthenticatorData: []byte{0xaa, 0xbb},
		Signature:         []byte{0x30, 0x45},
		SignCount:         42,
	}, nil
}

// ---------------------------------------------------------------------------
// Noise session pair setup
// ---------------------------------------------------------------------------

// setupNoiseSessionPair creates a connected pair of PhoneKeyBackend (initiator)
// and mock phone responder with a completed Noise XX handshake. The returned
// backend is fully connected and ready for encrypted RPC operations.
func setupNoiseSessionPair(t *testing.T) (*PhoneKeyBackend, *mockPhoneResponder) {
	t.Helper()

	initiatorTransport, responderTransport := newPipeTransports()

	cfg := &PhoneKeyBackendConfig{
		TrustNewDevices:  true,
		ScanTimeout:      5 * time.Second,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 10 * time.Second,
		Logger:           slog.Default(),
	}

	backend, err := NewPhoneKeyBackendWithTransport(cfg, initiatorTransport)
	require.NoError(t, err)

	// Run the responder side of the Noise XX handshake in a goroutine.
	// runResponderWithIdentity (from handshake_test.go) handles identity exchange
	// followed by the Noise XX handshake (msg1 -> msg2 -> msg3).
	responderDone := make(chan *NoiseSession, 1)
	go func() {
		responderDone <- runResponderWithIdentity(t, responderTransport)
	}()

	// Initiator performs the handshake via backend.Connect.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = backend.Connect(ctx)
	require.NoError(t, err)

	// Wait for the responder handshake to complete.
	responderSession := <-responderDone
	require.True(t, responderSession.IsHandshakeComplete())
	require.True(t, backend.IsConnected())

	responder := newMockPhoneResponder(t, responderTransport, responderSession)

	return backend, responder
}

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

func TestPhoneKeyBackend_Ping_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := backend.Ping(ctx)
	assert.NoError(t, err)
}

func TestPhoneKeyBackend_GetDeviceInfo_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := backend.GetDeviceInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, "Test Phone", info.DeviceName)
	assert.Equal(t, "1.0", info.Version)
	assert.Equal(t, []int{COSEAlgES256, COSEAlgES384, COSEAlgES512}, info.SupportedAlgorithms)
	assert.Equal(t, 100, info.MaxCredentials)
	assert.Equal(t, 5, info.CurrentCredentials)
}

func TestPhoneKeyBackend_GenerateCredentialKey_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	go responder.handleOne()

	handle, pubKey, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("test-cred-id"))
	require.NoError(t, err)
	require.NotNil(t, handle)
	assert.Equal(t, []byte("test-cred-id"), handle.CredentialID())
	assert.Equal(t, COSEAlgES256, handle.Algorithm())
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, pubKey)
}

func TestPhoneKeyBackend_Sign_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// Generate a key first to obtain a handle.
	go responder.handleOne()
	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("sign-cred"))
	require.NoError(t, err)

	// Sign with the handle.
	go responder.handleOne()
	sig, err := backend.Sign(handle, COSEAlgES256, []byte("test-data-hash"))
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x44}, sig)
}

func TestPhoneKeyBackend_LoadKey_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	go responder.handleOne()

	handle, err := backend.LoadKey([]byte("existing-cred"), COSEAlgES256)
	require.NoError(t, err)
	require.NotNil(t, handle)
	assert.Equal(t, []byte("existing-cred"), handle.CredentialID())
	assert.Equal(t, COSEAlgES256, handle.Algorithm())
}

func TestPhoneKeyBackend_LoadKey_CacheHit(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// First LoadKey goes over the wire.
	go responder.handleOne()
	handle1, err := backend.LoadKey([]byte("cached-cred"), COSEAlgES256)
	require.NoError(t, err)

	// Second LoadKey with the same credential ID should hit the local cache
	// and NOT require a responder goroutine.
	handle2, err := backend.LoadKey([]byte("cached-cred"), COSEAlgES256)
	require.NoError(t, err)

	assert.Equal(t, handle1.CredentialID(), handle2.CredentialID())
	assert.Equal(t, handle1.Algorithm(), handle2.Algorithm())
}

func TestPhoneKeyBackend_DeleteKey_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// Generate a key to obtain a handle.
	go responder.handleOne()
	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("delete-cred"))
	require.NoError(t, err)

	// Delete the key.
	go responder.handleOne()
	err = backend.DeleteKey(handle)
	assert.NoError(t, err)
}

func TestPhoneKeyBackend_ListFido2Credentials_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	creds, err := backend.ListFido2Credentials(ctx, "example.com")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "example.com", creds[0].RpID)
	assert.Equal(t, "alice", creds[0].UserName)
	assert.Equal(t, []byte("cred-1"), creds[0].CredentialID)
}

func TestPhoneKeyBackend_SignFido2Assertion_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := backend.SignFido2Assertion(ctx, &LocalSignFido2AssertionParams{
		CredentialID:   []byte("cred-1"),
		RpID:           "example.com",
		ClientDataHash: []byte("client-data-hash-32bytes-long!!!"),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x45}, result.Signature)
	assert.Equal(t, []byte{0xaa, 0xbb}, result.AuthenticatorData)
	assert.Equal(t, int64(42), result.SignCount)
}

// ---------------------------------------------------------------------------
// Multiple sequential operations on the same session
// ---------------------------------------------------------------------------

func TestPhoneKeyBackend_MultipleOperations_HappyPath(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// Operation 1: Ping
	go responder.handleOne()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := backend.Ping(ctx)
	cancel()
	require.NoError(t, err)

	// Operation 2: GetDeviceInfo
	go responder.handleOne()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	info, err := backend.GetDeviceInfo(ctx)
	cancel()
	require.NoError(t, err)
	assert.Equal(t, "Test Phone", info.DeviceName)

	// Operation 3: GenerateCredentialKey
	go responder.handleOne()
	handle, pubKey, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("multi-op-cred"))
	require.NoError(t, err)
	assert.NotNil(t, handle)
	assert.NotEmpty(t, pubKey)

	// Operation 4: Sign with the generated key
	go responder.handleOne()
	sig, err := backend.Sign(handle, COSEAlgES256, []byte("data-to-sign"))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Operation 5: DeleteKey
	go responder.handleOne()
	err = backend.DeleteKey(handle)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Error path tests with real Noise session
// ---------------------------------------------------------------------------

func TestPhoneKeyBackend_Ping_PhoneReturnsError(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// Override the ping handler to return an error.
	responder.handlers[MethodPing] = func(_ json.RawMessage) (interface{}, error) {
		return nil, errors.New("phone internal error")
	}

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := backend.Ping(ctx)
	assert.Error(t, err)
}

func TestPhoneKeyBackend_GetDeviceInfo_PhoneReturnsError(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	responder.handlers[MethodGetInfo] = func(_ json.RawMessage) (interface{}, error) {
		return nil, errors.New("device info unavailable")
	}

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := backend.GetDeviceInfo(ctx)
	assert.Error(t, err)
	assert.Nil(t, info)
}

func TestPhoneKeyBackend_GenerateCredentialKey_PhoneReturnsError(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	responder.handlers[MethodGenerateKey] = func(_ json.RawMessage) (interface{}, error) {
		return nil, errors.New("key generation failed on phone")
	}

	go responder.handleOne()

	handle, pubKey, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("fail-cred"))
	assert.Error(t, err)
	assert.Nil(t, handle)
	assert.Nil(t, pubKey)
}

func TestPhoneKeyBackend_Sign_PhoneReturnsError(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// Generate a key first.
	go responder.handleOne()
	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("sign-err-cred"))
	require.NoError(t, err)

	// Override sign handler to return an error.
	responder.handlers[MethodSign] = func(_ json.RawMessage) (interface{}, error) {
		return nil, errors.New("biometric timeout")
	}

	go responder.handleOne()

	sig, err := backend.Sign(handle, COSEAlgES256, []byte("data"))
	assert.Error(t, err)
	assert.Nil(t, sig)
}

func TestPhoneKeyBackend_LoadKey_KeyNotFound(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// Override loadKey handler to return exists=false.
	responder.handlers[MethodLoadKey] = func(_ json.RawMessage) (interface{}, error) {
		return &LoadKeyResult{Exists: false}, nil
	}

	go responder.handleOne()

	handle, err := backend.LoadKey([]byte("nonexistent-cred"), COSEAlgES256)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.Nil(t, handle)
}

func TestPhoneKeyBackend_Ping_PongFalse(t *testing.T) {
	t.Parallel()

	backend, responder := setupNoiseSessionPair(t)
	defer backend.Close()

	// Override ping handler to return pong=false.
	responder.handlers[MethodPing] = func(_ json.RawMessage) (interface{}, error) {
		return &PingResult{Pong: false}, nil
	}

	go responder.handleOne()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := backend.Ping(ctx)
	assert.ErrorIs(t, err, ErrProtocolError)
}

func TestPhoneKeyBackend_ExportPrivateKey_NotSupported(t *testing.T) {
	t.Parallel()

	backend, _ := setupNoiseSessionPair(t)
	defer backend.Close()

	handle := &phoneKeyHandle{credentialID: []byte("test"), algorithm: COSEAlgES256}
	data, err := backend.ExportPrivateKey(handle)
	assert.ErrorIs(t, err, ErrExportNotSupported)
	assert.Nil(t, data)
}

func TestPhoneKeyBackend_ImportPrivateKey_NotSupported(t *testing.T) {
	t.Parallel()

	backend, _ := setupNoiseSessionPair(t)
	defer backend.Close()

	handle, err := backend.ImportPrivateKey([]byte("test"), COSEAlgES256, []byte("pkcs8-key"))
	assert.ErrorIs(t, err, ErrImportNotSupported)
	assert.Nil(t, handle)
}
