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
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRequestHandler implements RequestHandler for testing inbound request dispatch.
type mockRequestHandler struct {
	handleFunc func(ctx context.Context, req *Request) *Response
}

func (m *mockRequestHandler) HandleRequest(ctx context.Context, req *Request) *Response {
	if m.handleFunc != nil {
		return m.handleFunc(ctx, req)
	}
	return nil
}

// setupHandshakedNoiseSessions creates a pair of Noise sessions that have
// completed a full XX handshake, ready for encrypted communication.
func setupHandshakedNoiseSessions(t *testing.T) (*NoiseSession, *NoiseSession) {
	t.Helper()

	initiator, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	responder, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})
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

// TestNewMessageRouter_NilLogger verifies the constructor defaults to slog.Default().
func TestNewMessageRouter_NilLogger(t *testing.T) {
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

		var req Request
		if err := json.Unmarshal(plaintext, &req); err != nil {
			return
		}

		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Result:  json.RawMessage(`{"pong":true}`),
		}
		respBytes, _ := json.Marshal(resp)
		respCiphertext, _ := remoteSession.Encrypt(respBytes)
		remoteTransport.Send(context.Background(), respCiphertext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, req.ID, resp.ID)
	assert.Nil(t, resp.Error)

	result, err := DecodeResult[PingResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Pong)
}

// TestMessageRouter_InboundRequest tests that the router correctly dispatches
// an inbound request from the remote peer to the RequestHandler and sends
// the encrypted response back.
func TestMessageRouter_InboundRequest(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handlerCalled := make(chan struct{}, 1)
	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, req *Request) *Response {
			handlerCalled <- struct{}{}
			resultData, _ := json.Marshal(&RemoteListBackendsResult{
				Backends: []BackendInfo{{Name: "tpm2", Type: "tpm2"}},
			})
			return &Response{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Result:  resultData,
			}
		},
	}

	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends an inbound request.
	inboundReq := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      42,
		Method:  MethodRemoteListBackends,
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

	var resp Response
	err = json.Unmarshal(respPlaintext, &resp)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), resp.ID)
	assert.Nil(t, resp.Error)

	var result RemoteListBackendsResult
	err = json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	require.Len(t, result.Backends, 1)
	assert.Equal(t, "tpm2", result.Backends[0].Name)
}

// TestMessageRouter_Stop_CancelsPending verifies that stopping the router
// while a request is pending causes the SendRequest to return ErrBackendClosed.
func TestMessageRouter_Stop_CancelsPending(t *testing.T) {
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()

	// Send a request that will never get a response because nobody is
	// reading from the remote side's transport to produce one.
	// However, the send will succeed since the channel has a buffer.
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req := NewRequest(MethodPing, nil)
		_, err := router.SendRequest(ctx, req)
		errCh <- err
	}()

	// Give the goroutine time to register the pending request and send.
	time.Sleep(100 * time.Millisecond)

	// Stop the router, which should cancel the pending request.
	router.Stop()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrBackendClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("SendRequest did not return after Stop()")
	}
}

// TestMessageRouter_NilHandler_InboundRequest verifies that receiving an
// inbound request with no handler configured does not panic and the
// receive loop continues.
func TestMessageRouter_NilHandler_InboundRequest(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	// No handler: nil.
	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends an inbound request.
	inboundReq := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      99,
		Method:  MethodRemoteListBackends,
	}
	reqBytes, err := json.Marshal(inboundReq)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(reqBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Now send a real outbound request to verify the loop is still running.
	go func() {
		// Wait for the inbound request to be processed (dropped).
		time.Sleep(100 * time.Millisecond)

		// Simulate remote side responding to the outbound request.
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &Response{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}

// TestMessageRouter_InvalidDecrypt tests that receiving invalid ciphertext
// (that fails decryption) does not crash the receive loop and it continues
// processing subsequent valid messages.
func TestMessageRouter_InvalidDecrypt(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Send garbage bytes that will fail decryption.
	err := remoteTransport.Send(context.Background(), []byte("this-is-not-valid-ciphertext-at-all"))
	require.NoError(t, err)

	// Then send a valid outbound request and remote side responds.
	go func() {
		// Give the invalid message time to be processed.
		time.Sleep(100 * time.Millisecond)

		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &Response{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}

// TestMessageRouter_ContextCancel verifies that cancelling the context
// while waiting for a response returns the context error.
func TestMessageRouter_ContextCancel(t *testing.T) {
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Use a context that will be cancelled almost immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestMessageRouter_SendRequest_Closed verifies that calling SendRequest
// on a closed router returns ErrBackendClosed immediately.
func TestMessageRouter_SendRequest_Closed(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()
	session, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(transport, session, nil, testLogger())
	router.Start()
	router.Stop()

	ctx := context.Background()
	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// TestMessageRouter_Stop_Idempotent verifies that calling Stop multiple
// times does not panic.
func TestMessageRouter_Stop_Idempotent(t *testing.T) {
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
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Send a response with an ID that nobody is waiting for.
	unknownResp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      99999,
		Result:  json.RawMessage(`{"pong":true}`),
	}
	respBytes, err := json.Marshal(unknownResp)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(respBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Verify the loop is still running by doing a successful round-trip.
	go func() {
		time.Sleep(100 * time.Millisecond)
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &Response{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestMessageRouter_InvalidJSON verifies that receiving valid ciphertext
// containing invalid JSON is handled gracefully (logged and skipped).
func TestMessageRouter_InvalidJSON(t *testing.T) {
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

	// Verify the loop survives by doing a round-trip.
	go func() {
		time.Sleep(100 * time.Millisecond)
		ct, readErr := remoteTransport.Receive(context.Background())
		if readErr != nil {
			return
		}
		pt, decErr := remoteSession.Decrypt(ct)
		if decErr != nil {
			return
		}
		var req Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &Response{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestMessageRouter_InboundRequest_NilResponse verifies that if the handler
// returns nil, no response is sent back and the loop continues.
func TestMessageRouter_InboundRequest_NilResponse(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handlerCalled := make(chan struct{}, 1)
	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, _ *Request) *Response {
			handlerCalled <- struct{}{}
			return nil // explicitly return nil
		},
	}

	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends an inbound request.
	inboundReq := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      77,
		Method:  MethodRemoteListBackends,
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
		var req Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &Response{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := NewRequest(MethodPing, nil)
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
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	// Set the transport to return an error on Receive.
	initiatorTransport.recvErr = errMockRecv

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, slog.Default())
	router.Start()
	defer router.Stop()

	// Give the loop time to exit on error.
	time.Sleep(200 * time.Millisecond)

	// SendRequest should still fail gracefully (context timeout since loop
	// is dead and no response will come).
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	_, err := router.SendRequest(ctx, req)
	assert.Error(t, err)
}

// TestMessageRouter_ConcurrentSendRequests verifies that multiple concurrent
// SendRequest calls are correctly multiplexed and each gets the right response.
func TestMessageRouter_ConcurrentSendRequests(t *testing.T) {
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
			var req Request
			if err := json.Unmarshal(pt, &req); err != nil {
				return
			}

			resultJSON, _ := json.Marshal(map[string]interface{}{
				"pong": true,
				"echo": req.ID,
			})
			resp := &Response{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Result:  resultJSON,
			}
			rb, _ := json.Marshal(resp)
			rc, _ := remoteSession.Encrypt(rb)
			remoteTransport.Send(context.Background(), rc)
		}
	}()

	type result struct {
		id   uint64
		resp *Response
		err  error
	}

	results := make(chan result, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := NewRequest(MethodPing, nil)
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
	t.Parallel()

	transport, _ := newPipeTransports()
	session, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouterWithNotifier(transport, session, nil, nil, nil)
	require.NotNil(t, router)
	assert.Nil(t, router.biometricHandler)
}

// TestMessageRouter_SetBiometricHandler verifies the setter method.
func TestMessageRouter_SetBiometricHandler(t *testing.T) {
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
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	notifier := &testNotifier{}
	router := NewMessageRouterWithNotifier(initiatorTransport, initiatorSession, nil, notifier, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends a biometric pending notification.
	params := &LocalBiometricPendingParams{
		Operation:   "sign",
		RPName:      "Test RP",
		TimeoutSecs: 30,
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	notification := &biometricPendingRequest{
		JSONRPC: JSONRPCVersion,
		ID:      123,
		Method:  MethodLocalBiometricPending,
		Params:  paramsJSON,
	}
	notifBytes, err := json.Marshal(notification)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(notifBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Give time for the notification to be processed.
	time.Sleep(200 * time.Millisecond)

	// Verify the notifier was called.
	calls := notifier.getCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "phone:sign", calls[0].Operation)
	assert.Equal(t, "Test RP", calls[0].RPName)
}

// TestMessageRouter_BiometricPendingNotification_NoHandler verifies that
// receiving a biometric pending notification without a handler doesn't crash.
func TestMessageRouter_BiometricPendingNotification_NoHandler(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	// No biometric handler.
	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends a biometric pending notification.
	params := &LocalBiometricPendingParams{
		Operation:   "decrypt",
		RPName:      "Example",
		TimeoutSecs: 60,
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	notification := &biometricPendingRequest{
		JSONRPC: JSONRPCVersion,
		ID:      456,
		Method:  MethodLocalBiometricPending,
		Params:  paramsJSON,
	}
	notifBytes, err := json.Marshal(notification)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(notifBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Give time for the notification to be processed.
	time.Sleep(200 * time.Millisecond)

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
		var req Request
		if err := json.Unmarshal(pt, &req); err != nil {
			return
		}
		resp := &Response{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		rb, _ := json.Marshal(resp)
		rc, _ := remoteSession.Encrypt(rb)
		remoteTransport.Send(context.Background(), rc)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := NewRequest(MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestMessageRouter_BiometricPendingNotification_RequestHandlerNotCalled
// verifies that the request handler is NOT called for biometric pending
// notifications (fire-and-forget, no response needed).
func TestMessageRouter_BiometricPendingNotification_RequestHandlerNotCalled(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	notifier := &testNotifier{}

	// Track if the request handler was called.
	var handlerCallCount atomic.Int32
	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, _ *Request) *Response {
			handlerCallCount.Add(1)
			return nil
		},
	}

	router := NewMessageRouterWithNotifier(initiatorTransport, initiatorSession, handler, notifier, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends a biometric pending notification.
	params := &LocalBiometricPendingParams{
		Operation:   "attestKey",
		RPName:      "Test",
		TimeoutSecs: 45,
	}
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	notification := &biometricPendingRequest{
		JSONRPC: JSONRPCVersion,
		ID:      789,
		Method:  MethodLocalBiometricPending,
		Params:  paramsJSON,
	}
	notifBytes, err := json.Marshal(notification)
	require.NoError(t, err)

	ciphertext, err := remoteSession.Encrypt(notifBytes)
	require.NoError(t, err)

	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Give time for the notification to be processed.
	time.Sleep(200 * time.Millisecond)

	// Verify the notifier was called but the request handler was not.
	require.Len(t, notifier.getCalls(), 1)
	assert.Equal(t, int32(0), handlerCallCount.Load(), "request handler should not be called for biometric notifications")
}
