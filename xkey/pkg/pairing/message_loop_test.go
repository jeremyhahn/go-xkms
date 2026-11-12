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

package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRequestHandler implements RequestHandler for testing inbound request dispatch.
type mockRequestHandler struct {
	handleFunc func(ctx context.Context, req *pairingproto.Request) *pairingproto.Response
}

func (m *mockRequestHandler) HandleRequest(ctx context.Context, req *pairingproto.Request) *pairingproto.Response {
	if m.handleFunc != nil {
		return m.handleFunc(ctx, req)
	}
	return nil
}

// setupHandshakedNoiseSessions creates a pair of Noise sessions that have
// completed a full XX handshake, ready for encrypted communication.
func setupHandshakedNoiseSessions(t *testing.T) (*bootstrap.NoiseSession, *bootstrap.NoiseSession) {
	t.Helper()

	initiator, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	responder, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	// XX handshake: 3 messages
	// msg1: initiator -> responder (e)
	msg1, complete, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	require.False(t, complete)
	require.NotEmpty(t, msg1)

	// msg2: responder reads msg1 and writes response (e, ee, s, es)
	msg2, complete, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	require.False(t, complete)
	require.NotEmpty(t, msg2)

	// msg3: initiator reads msg2 and writes final (s, se)
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	require.True(t, complete)
	require.NotEmpty(t, msg3)

	// Responder reads msg3 to complete handshake.
	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete)

	require.True(t, initiator.IsHandshakeComplete())
	require.True(t, responder.IsHandshakeComplete())

	return initiator, responder
}

// errMockRecv is returned by the mock transport when Receive is configured to fail.
var errMockRecv = errors.New("mock: receive failure")

// mockPipeTransport implements pairingproto.Transport using a pair of
// channels. One side writes to sendCh and reads from recvCh. A paired
// transport reads from the first's sendCh and writes to its recvCh, forming
// a bidirectional in-memory pipe.
type mockPipeTransport struct {
	sendCh    chan []byte
	recvCh    chan []byte
	connected atomic.Bool
	closed    atomic.Bool

	// sendErr, if non-nil, is returned from Send instead of writing to sendCh.
	sendErr error
	// recvErr, if non-nil, is returned from Receive instead of reading from recvCh.
	recvErr error
}

func (m *mockPipeTransport) Send(_ context.Context, message []byte) error {
	if m.closed.Load() {
		return pairingproto.ErrBackendClosed
	}
	if !m.connected.Load() {
		return pairingproto.ErrNotConnected
	}
	if m.sendErr != nil {
		return m.sendErr
	}
	cp := make([]byte, len(message))
	copy(cp, message)
	m.sendCh <- cp
	return nil
}

func (m *mockPipeTransport) Receive(_ context.Context) ([]byte, error) {
	if m.closed.Load() {
		return nil, pairingproto.ErrBackendClosed
	}
	if !m.connected.Load() {
		return nil, pairingproto.ErrNotConnected
	}
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	msg, ok := <-m.recvCh
	if !ok {
		return nil, pairingproto.ErrNotConnected
	}
	return msg, nil
}

func (m *mockPipeTransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := m.Send(ctx, message); err != nil {
		return nil, err
	}
	return m.Receive(ctx)
}

func (m *mockPipeTransport) IsConnected() bool {
	return m.connected.Load() && !m.closed.Load()
}

func (m *mockPipeTransport) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	m.connected.Store(false)
	return nil
}

// newPipeTransports creates a connected pair of mock transports.
func newPipeTransports() (*mockPipeTransport, *mockPipeTransport) {
	ch1 := make(chan []byte, 10)
	ch2 := make(chan []byte, 10)

	initiator := &mockPipeTransport{sendCh: ch1, recvCh: ch2}
	responder := &mockPipeTransport{sendCh: ch2, recvCh: ch1}

	initiator.connected.Store(true)
	responder.connected.Store(true)

	return initiator, responder
}

// TestNewMessageRouter_NilLogger verifies the constructor defaults to slog.Default().
func TestNewMessageRouter_NilLogger(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	transport, _ := newPipeTransports()
	initiator, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(transport, initiator, nil, nil)
	require.NotNil(t, router)
	assert.NotNil(t, router.logger)
	assert.NotNil(t, router.pending)
	assert.NotNil(t, router.done)
}

// TestNewMessageRouter_WithLogger verifies the constructor uses a provided logger.
func TestNewMessageRouter_WithLogger(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	transport, _ := newPipeTransports()
	initiator, _ := setupHandshakedNoiseSessions(t)
	logger := testLogger()

	router := NewMessageRouter(transport, initiator, nil, logger)
	require.NotNil(t, router)
	assert.NotNil(t, router.logger)
}

// TestMessageRouter_SendRequest_Response tests the full round-trip: send a
// request through the router, simulate the remote side decrypting and
// replying, and verify the correct response is returned.
func TestMessageRouter_SendRequest_Response(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Simulate the remote side in a goroutine: read encrypted request,
	// decrypt, build response, encrypt, send back.
	go func() {
		ciphertext, err := remoteTransport.Receive(context.Background())
		if err != nil {
			return
		}
		plaintext, err := remoteSession.Decrypt(ciphertext)
		if err != nil {
			return
		}

		var req pairingproto.Request
		if err := json.Unmarshal(plaintext, &req); err != nil {
			return
		}

		resp := &pairingproto.Response{
			JSONRPC:    pairingproto.JSONRPCVersion,
			ID:         req.ID,
			Generation: req.Generation,
			Result:     json.RawMessage(`{"pong":true}`),
		}
		respBytes, _ := json.Marshal(resp)
		respCiphertext, _ := remoteSession.Encrypt(respBytes)
		remoteTransport.Send(context.Background(), respCiphertext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, req.ID, resp.ID)
	assert.Nil(t, resp.Error)

	result, err := pairingproto.DecodeResult[pairingproto.PingResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Pong)
}

// TestMessageRouter_InboundRequest tests that the router correctly dispatches
// an inbound request from the remote peer to the RequestHandler and sends
// the encrypted response back.
func TestMessageRouter_InboundRequest(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handlerCalled := make(chan struct{}, 1)
	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, req *pairingproto.Request) *pairingproto.Response {
			handlerCalled <- struct{}{}
			resultData, _ := json.Marshal(&pairingproto.RemoteListBackendsResult{
				Backends: []pairingproto.BackendInfo{{Name: "tpm2", Type: "tpm2"}},
			})
			return &pairingproto.Response{
				JSONRPC:    pairingproto.JSONRPCVersion,
				ID:         req.ID,
				Generation: req.Generation,
				Result:     resultData,
			}
		},
	}

	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends an inbound request.
	inboundReq := &pairingproto.Request{
		JSONRPC:    pairingproto.JSONRPCVersion,
		ID:         42,
		Generation: 7,
		Method:     pairingproto.MethodRemoteListBackends,
	}
	reqBytes, err := json.Marshal(inboundReq)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(reqBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Wait for the handler to be called.
	select {
	case <-handlerCalled:
		// Handler was invoked.
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not called within timeout")
	}

	// Read the encrypted response sent back by the router.
	respCiphertext, err := remoteTransport.Receive(context.Background())
	require.NoError(t, err)

	respPlaintext, err := remoteSession.Decrypt(respCiphertext)
	require.NoError(t, err)

	var resp pairingproto.Response
	err = json.Unmarshal(respPlaintext, &resp)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), resp.ID)
	assert.Equal(t, uint64(7), resp.Generation, "the inbound handler must echo the request's generation verbatim")
	assert.Nil(t, resp.Error)

	var result pairingproto.RemoteListBackendsResult
	err = json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	require.Len(t, result.Backends, 1)
	assert.Equal(t, "tpm2", result.Backends[0].Name)
}

func TestMessageRouter_InboundRequest_WipesEncodedResult(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	encodedResult, err := json.Marshal(&pairingproto.RemoteDeriveKeyResult{SharedSecret: []byte("shared-secret")})
	require.NoError(t, err)
	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, req *pairingproto.Request) *pairingproto.Response {
			return &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: encodedResult}
		},
	}

	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	reqBytes, err := json.Marshal(&pairingproto.Request{JSONRPC: pairingproto.JSONRPCVersion, ID: 7, Method: pairingproto.MethodRemoteDeriveKey})
	require.NoError(t, err)
	ciphertext, err := remoteSession.Encrypt(reqBytes)
	require.NoError(t, err)
	require.NoError(t, remoteTransport.Send(context.Background(), ciphertext))

	respCiphertext, err := remoteTransport.Receive(context.Background())
	require.NoError(t, err)
	respPlaintext, err := remoteSession.Decrypt(respCiphertext)
	require.NoError(t, err)

	var resp pairingproto.Response
	require.NoError(t, json.Unmarshal(respPlaintext, &resp))
	var result pairingproto.RemoteDeriveKeyResult
	require.NoError(t, json.Unmarshal(resp.Result, &result))
	assert.Equal(t, []byte("shared-secret"), result.SharedSecret)
	// The handler's encoded result is wiped before the response is sent.
	assert.Equal(t, make([]byte, len(encodedResult)), encodedResult)
}

// TestMessageRouter_Stop_CancelsPending verifies that stopping the router
// while a request is pending causes the SendRequest to return ErrBackendClosed.
func TestMessageRouter_Stop_CancelsPending(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()

	// Send a request that will never get a response because nobody is
	// reading from the remote side's transport to produce one.
	// However, the send will succeed since the channel has a buffer.
	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := router.SendRequest(ctx, req)
		errCh <- err
	}()

	// Wait for req.ID to actually land in router.pending instead of sleeping
	// a fixed duration: req.ID is fixed at NewRequest time above, so it is
	// safe to read here before SendRequest runs.
	require.Eventually(t, func() bool {
		router.mu.Lock()
		defer router.mu.Unlock()
		_, ok := router.pending[req.ID]
		return ok
	}, 5*time.Second, time.Millisecond, "SendRequest never registered its pending request")

	// Stop the router, which should cancel the pending request.
	router.Stop()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, pairingproto.ErrBackendClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("SendRequest did not return after Stop()")
	}
}

// TestMessageRouter_NilHandler_InboundRequest verifies that receiving an
// inbound request with no handler configured does not panic and the
// receive loop continues.
func TestMessageRouter_NilHandler_InboundRequest(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	// No handler: nil.
	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends an inbound request.
	inboundReq := &pairingproto.Request{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      99,
		Method:  pairingproto.MethodRemoteListBackends,
	}
	reqBytes, err := json.Marshal(inboundReq)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(reqBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Now send a real outbound request to verify the loop is still running.
	// No wait needed before Receive: it blocks until the outbound request
	// below arrives, which is on a separate channel direction from the
	// dropped inbound request above (see newPipeTransports), so there is
	// nothing to race.
	go func() {
		// Simulate remote side responding to the outbound request.
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}

// TestMessageRouter_InvalidDecrypt tests that receiving invalid ciphertext
// (that fails decryption) does not crash the receive loop and it continues
// processing subsequent valid messages.
func TestMessageRouter_InvalidDecrypt(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Send garbage bytes that will fail decryption.
	err := remoteTransport.Send(context.Background(), []byte("this-is-not-valid-ciphertext-at-all"))
	require.NoError(t, err)

	// Then send a valid outbound request and remote side responds. No wait
	// needed before Receive: it blocks until the outbound request below
	// arrives, which is on a separate channel direction from the
	// undecryptable message above (see newPipeTransports), so there is
	// nothing to race.
	go func() {
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}

// TestMessageRouter_ContextCancel verifies that cancelling the context
// while waiting for a response returns the context error.
func TestMessageRouter_ContextCancel(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Use a context that will be cancelled almost immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestMessageRouter_SendRequest_Closed verifies that calling SendRequest
// on a closed router returns ErrBackendClosed immediately.
func TestMessageRouter_SendRequest_Closed(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	transport, _ := newPipeTransports()
	session, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(transport, session, nil, testLogger())
	router.Start()
	router.Stop()

	ctx := context.Background()
	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, pairingproto.ErrBackendClosed)
}

// TestMessageRouter_Stop_Idempotent verifies that calling Stop multiple
// times does not panic.
func TestMessageRouter_Stop_Idempotent(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	transport, _ := newPipeTransports()
	session, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(transport, session, nil, testLogger())
	router.Start()

	// Stop multiple times; should not panic.
	router.Stop()
	router.Stop()
	router.Stop()

	assert.True(t, router.closed.Load())
}

// TestMessageRouter_UnknownResponseID verifies that a response with an
// unknown ID is logged and dropped without affecting the router.
func TestMessageRouter_UnknownResponseID(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Send a response with an ID that nobody is waiting for.
	unknownResp := &pairingproto.Response{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      99999,
		Result:  json.RawMessage(`{"pong":true}`),
	}
	respBytes, err := json.Marshal(unknownResp)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(respBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Verify the loop is still running by doing a successful round-trip. No
	// wait needed before Receive: it blocks until the outbound request below
	// arrives, which is on a separate channel direction from the unknown
	// response above (see newPipeTransports), so there is nothing to race.
	go func() {
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestMessageRouter_InvalidJSON verifies that receiving valid ciphertext
// containing invalid JSON is handled gracefully (logged and skipped).
func TestMessageRouter_InvalidJSON(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Send valid ciphertext containing invalid JSON.
	invalidJSON := []byte("{{not json at all")
	ciphertext, err := remoteSession.Encrypt(invalidJSON)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Verify the loop survives by doing a round-trip. No wait needed before
	// Receive: it blocks until the outbound request below arrives, which is
	// on a separate channel direction from the invalid JSON above (see
	// newPipeTransports), so there is nothing to race.
	go func() {
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestMessageRouter_InboundRequest_NilResponse verifies that if the handler
// returns nil, no response is sent back and the loop continues.
func TestMessageRouter_InboundRequest_NilResponse(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handlerCalled := make(chan struct{}, 1)
	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, _ *pairingproto.Request) *pairingproto.Response {
			handlerCalled <- struct{}{}
			return nil // explicitly return nil
		},
	}

	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends an inbound request.
	inboundReq := &pairingproto.Request{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      77,
		Method:  pairingproto.MethodRemoteListBackends,
	}
	reqBytes, err := json.Marshal(inboundReq)
	require.NoError(t, err)
	ciphertext, err := remoteSession.Encrypt(reqBytes)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	select {
	case <-handlerCalled:
		// Handler was invoked.
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not called within timeout")
	}

	// Verify the loop is still alive by doing a round-trip.
	go func() {
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestMessageRouter_MessageProbe_RequestVsResponse verifies the message
// discrimination logic: messages with a method field are requests,
// messages without are responses.
func TestMessageRouter_MessageProbe_RequestVsResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		json      string
		isRequest bool
	}{
		{
			name:      "request with method",
			json:      `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
			isRequest: true,
		},
		{
			name:      "response with result",
			json:      `{"jsonrpc":"2.0","id":1,"result":{"pong":true}}`,
			isRequest: false,
		},
		{
			name:      "response with error",
			json:      `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}`,
			isRequest: false,
		},
		{
			name:      "request with empty string method",
			json:      `{"jsonrpc":"2.0","id":1,"method":""}`,
			isRequest: false, // empty method is treated as response
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var probe messageProbe
			err := json.Unmarshal([]byte(tc.json), &probe)
			require.NoError(t, err)

			if tc.isRequest {
				assert.NotEmpty(t, probe.Method)
			} else {
				assert.Empty(t, probe.Method)
			}
		})
	}
}

// TestBridge_ImplementsRequestHandler verifies that Bridge satisfies the
// RequestHandler interface at compile time.
func TestBridge_ImplementsRequestHandler(t *testing.T) {
	t.Parallel()

	var _ RequestHandler = (*Bridge)(nil)
}

// TestMessageRouter_TransportError verifies that a transport receive error
// (non-closed) causes the receive loop to exit.
func TestMessageRouter_TransportError(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	// Set the transport to return an error on Receive.
	initiatorTransport.recvErr = errMockRecv

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, slog.Default())
	router.Start()
	defer router.Stop()

	// No wait needed: recvErr is set before Start, so receiveLoop's first
	// Receive call returns it immediately and the loop exits well before
	// SendRequest's own context deadline below is reached.
	//
	// SendRequest should still fail gracefully (context timeout since loop
	// is dead and no response will come).
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	_, err := router.SendRequest(ctx, req)
	assert.Error(t, err)
}

// TestMessageRouter_ConcurrentSendRequests verifies that multiple concurrent
// SendRequest calls are correctly multiplexed and each gets the right response.
func TestMessageRouter_ConcurrentSendRequests(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	const numRequests = 5

	// Remote side reads all requests and responds to each.
	go func() {
		for i := 0; i < numRequests; i++ {
			ct, err := remoteTransport.Receive(context.Background())
			if err != nil {
				return
			}
			pt, err := remoteSession.Decrypt(ct)
			if err != nil {
				return
			}
			var req pairingproto.Request
			if err := json.Unmarshal(pt, &req); err != nil {
				return
			}

			resultJSON, _ := json.Marshal(map[string]interface{}{
				"pong": true,
				"echo": req.ID,
			})
			resp := &pairingproto.Response{
				JSONRPC:    pairingproto.JSONRPCVersion,
				ID:         req.ID,
				Generation: req.Generation,
				Result:     resultJSON,
			}
			rb, _ := json.Marshal(resp)
			rc, _ := remoteSession.Encrypt(rb)
			remoteTransport.Send(context.Background(), rc)
		}
	}()

	type result struct {
		id   uint64
		resp *pairingproto.Response
		err  error
	}

	results := make(chan result, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
			resp, err := router.SendRequest(ctx, req)
			results <- result{id: req.ID, resp: resp, err: err}
		}()
	}

	received := make(map[uint64]bool)
	for i := 0; i < numRequests; i++ {
		select {
		case r := <-results:
			require.NoError(t, r.err)
			require.NotNil(t, r.resp)
			assert.Equal(t, r.id, r.resp.ID, "response ID must match request ID")
			received[r.id] = true
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for concurrent responses")
		}
	}

	assert.Len(t, received, numRequests)
}

// testNotifier is a mock Notifier for testing biometric pending notifications.
type testNotifier struct {
	mu     sync.Mutex
	calls  []notify.TouchRequest
	closed bool
}

func (n *testNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, *req)
	return nil
}

func (n *testNotifier) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	return nil
}

// getCalls returns a snapshot of the recorded calls (thread-safe).
func (n *testNotifier) getCalls() []notify.TouchRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	result := make([]notify.TouchRequest, len(n.calls))
	copy(result, n.calls)
	return result
}

// TestNewMessageRouterWithNotifier verifies the constructor creates a router
// with a BiometricPendingHandler.
func TestNewMessageRouterWithNotifier(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	transport, _ := newPipeTransports()
	session, _ := setupHandshakedNoiseSessions(t)
	notifier := &testNotifier{}

	router := NewMessageRouterWithNotifier(transport, session, nil, notifier, nil)
	require.NotNil(t, router)
	assert.NotNil(t, router.biometricHandler)
}

// TestNewMessageRouterWithNotifier_NilNotifier verifies the constructor does
// not create a biometric handler when notifier is nil.
func TestNewMessageRouterWithNotifier_NilNotifier(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	transport, _ := newPipeTransports()
	session, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouterWithNotifier(transport, session, nil, nil, nil)
	require.NotNil(t, router)
	assert.Nil(t, router.biometricHandler)
}

// TestMessageRouter_SetBiometricHandler verifies the setter method.
func TestMessageRouter_SetBiometricHandler(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	transport, _ := newPipeTransports()
	session, _ := setupHandshakedNoiseSessions(t)
	notifier := &testNotifier{}

	router := NewMessageRouter(transport, session, nil, nil)
	assert.Nil(t, router.biometricHandler)

	handler := NewBiometricPendingHandler(notifier, nil)
	router.SetBiometricHandler(handler)
	assert.NotNil(t, router.biometricHandler)
}

// TestMessageRouter_BiometricPendingNotification verifies that the router
// correctly handles local.biometricPending notifications (fire-and-forget).
func TestMessageRouter_BiometricPendingNotification(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	notifier := &testNotifier{}
	router := NewMessageRouterWithNotifier(initiatorTransport, initiatorSession, nil, notifier, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends a biometric pending notification.
	params := &pairingproto.LocalBiometricPendingParams{
		Operation:   "sign",
		RPName:      "Test RP",
		TimeoutSecs: 30,
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	notification := &biometricPendingRequest{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      123,
		Method:  pairingproto.MethodLocalBiometricPending,
		Params:  paramsJSON,
	}
	notifBytes, err := json.Marshal(notification)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(notifBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Wait for the notifier to actually be called instead of sleeping a
	// fixed duration.
	require.Eventually(t, func() bool {
		return len(notifier.getCalls()) > 0
	}, 5*time.Second, time.Millisecond, "notifier was never called")

	// Verify the notifier was called.
	calls := notifier.getCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "phone:sign", calls[0].Operation)
	assert.Equal(t, "Test RP", calls[0].RPName)
}

// TestMessageRouter_BiometricPendingNotification_NoHandler verifies that
// receiving a biometric pending notification without a handler doesn't crash.
func TestMessageRouter_BiometricPendingNotification_NoHandler(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	// No biometric handler.
	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends a biometric pending notification.
	params := &pairingproto.LocalBiometricPendingParams{
		Operation:   "decrypt",
		RPName:      "Example",
		TimeoutSecs: 60,
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	notification := &biometricPendingRequest{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      456,
		Method:  pairingproto.MethodLocalBiometricPending,
		Params:  paramsJSON,
	}
	notifBytes, err := json.Marshal(notification)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(notifBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Verify the loop is still alive by doing a round-trip. No wait needed
	// before Receive: it blocks until the outbound request below arrives,
	// which is on a separate channel direction from the notification above
	// (see newPipeTransports), so there is nothing to race.
	go func() {
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestMessageRouter_BiometricPendingNotification_RequestHandlerNotCalled
// verifies that the request handler is NOT called for biometric pending
// notifications (fire-and-forget, no response needed).
func TestMessageRouter_BiometricPendingNotification_RequestHandlerNotCalled(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	notifier := &testNotifier{}

	// Track if the request handler was called.
	var handlerCallCount atomic.Int32
	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, _ *pairingproto.Request) *pairingproto.Response {
			handlerCallCount.Add(1)
			return nil
		},
	}

	router := NewMessageRouterWithNotifier(initiatorTransport, initiatorSession, handler, notifier, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends a biometric pending notification.
	params := &pairingproto.LocalBiometricPendingParams{
		Operation:   "attestKey",
		RPName:      "Test",
		TimeoutSecs: 45,
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	notification := &biometricPendingRequest{
		JSONRPC: pairingproto.JSONRPCVersion,
		ID:      789,
		Method:  pairingproto.MethodLocalBiometricPending,
		Params:  paramsJSON,
	}
	notifBytes, err := json.Marshal(notification)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(notifBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Wait for the notifier to actually be called instead of sleeping a
	// fixed duration.
	require.Eventually(t, func() bool {
		return len(notifier.getCalls()) > 0
	}, 5*time.Second, time.Millisecond, "notifier was never called")

	// Verify the notifier was called but the request handler was not.
	require.Len(t, notifier.getCalls(), 1)
	assert.Equal(t, int32(0), handlerCallCount.Load(), "request handler should not be called for biometric notifications")
}
