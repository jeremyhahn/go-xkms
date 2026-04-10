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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// RequestHandler processes inbound JSON-RPC requests from a remote peer.
// Implementations must be safe for concurrent use.
type RequestHandler interface {
	HandleRequest(ctx context.Context, req *Request) *Response
}

// MessageRouter handles bidirectional JSON-RPC message routing over an
// encrypted Noise channel. It runs a background receive loop that
// demultiplexes incoming messages into responses (matched to pending
// outbound requests) and inbound requests (dispatched to a handler).
//
// MessageRouter is safe for concurrent use from multiple goroutines.
type MessageRouter struct {
	transport        Transport
	session          *NoiseSession
	logger           *slog.Logger
	requestHandler   RequestHandler
	biometricHandler *BiometricPendingHandler

	mu      sync.Mutex
	pending map[uint64]chan *Response

	sendMu sync.Mutex // serializes encrypt+send (Noise CipherState is not concurrent-safe)

	done      chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool
}

// NewMessageRouter creates a new bidirectional message router.
// The transport and session must have completed the Noise handshake.
// The handler processes inbound requests (can be nil to reject all
// inbound requests with a warning log).
func NewMessageRouter(transport Transport, session *NoiseSession, handler RequestHandler, logger *slog.Logger) *MessageRouter {
	if logger == nil {
		logger = slog.Default()
	}
	return &MessageRouter{
		transport:      transport,
		session:        session,
		logger:         logger.With("component", "message_router"),
		requestHandler: handler,
		pending:        make(map[uint64]chan *Response),
		done:           make(chan struct{}),
	}
}

// NewMessageRouterWithNotifier creates a new bidirectional message router
// with a notifier for biometric pending notifications from the phone.
func NewMessageRouterWithNotifier(transport Transport, session *NoiseSession, handler RequestHandler, notifier notify.Notifier, logger *slog.Logger) *MessageRouter {
	if logger == nil {
		logger = slog.Default()
	}
	router := &MessageRouter{
		transport:      transport,
		session:        session,
		logger:         logger.With("component", "message_router"),
		requestHandler: handler,
		pending:        make(map[uint64]chan *Response),
		done:           make(chan struct{}),
	}
	if notifier != nil {
		router.biometricHandler = NewBiometricPendingHandler(notifier, logger)
	}
	return router
}

// SetBiometricHandler sets the handler for biometric pending notifications.
// This can be called before Start() to configure notification handling.
func (r *MessageRouter) SetBiometricHandler(handler *BiometricPendingHandler) {
	r.biometricHandler = handler
}

// Start begins the background receive loop. Must be called after the
// Noise handshake completes. Start must be called exactly once.
func (r *MessageRouter) Start() {
	go r.receiveLoop()
}

// Stop shuts down the receive loop and cancels all pending requests.
// Stop is safe to call multiple times.
func (r *MessageRouter) Stop() {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		close(r.done)

		// Cancel all pending requests by closing their channels.
		r.mu.Lock()
		for id, ch := range r.pending {
			close(ch)
			delete(r.pending, id)
		}
		r.mu.Unlock()
	})
}

// SendRequest sends an encrypted outbound request and waits for the
// matching response from the background receive loop.
func (r *MessageRouter) SendRequest(ctx context.Context, req *Request) (*Response, error) {
	if r.closed.Load() {
		return nil, ErrBackendClosed
	}

	// Create a buffered response channel and register it.
	respCh := make(chan *Response, 1)
	r.mu.Lock()
	r.pending[req.ID] = respCh
	r.mu.Unlock()

	// Ensure cleanup on exit.
	defer func() {
		r.mu.Lock()
		delete(r.pending, req.ID)
		r.mu.Unlock()
	}()

	// Encode and encrypt the request.
	plaintext, err := EncodeRequest(req)
	if err != nil {
		return nil, ErrProtocolError
	}

	// Serialize encrypt+send: Noise CipherState nonce is sequential.
	r.sendMu.Lock()
	ciphertext, err := r.session.Encrypt(plaintext)
	if err != nil {
		r.sendMu.Unlock()
		return nil, err
	}
	sendErr := r.transport.Send(ctx, ciphertext)
	r.sendMu.Unlock()
	if sendErr != nil {
		return nil, sendErr
	}

	// Wait for the matching response.
	select {
	case resp, ok := <-respCh:
		if !ok {
			return nil, ErrBackendClosed
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.done:
		return nil, ErrBackendClosed
	}
}

// receiveLoop continuously reads from the transport, decrypts messages,
// and dispatches them to the appropriate handler.
func (r *MessageRouter) receiveLoop() {
	for {
		select {
		case <-r.done:
			return
		default:
		}

		// Use a background context for receive -- the loop manages its
		// own lifecycle via the done channel.
		ciphertext, err := r.transport.Receive(context.Background())
		if err != nil {
			if r.closed.Load() {
				return
			}
			r.logger.Error("receive loop transport error", "error", err)
			return
		}

		plaintext, err := r.session.Decrypt(ciphertext)
		if err != nil {
			r.logger.Error("failed to decrypt received message", "error", err)
			continue
		}

		r.dispatchMessage(plaintext)
	}
}

// messageProbe is used to determine if a JSON message is a request or response
// without fully unmarshalling it.
type messageProbe struct {
	Method string          `json:"method,omitempty"`
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// handleInboundRequest processes an inbound JSON-RPC request from the remote
// peer. It dispatches to the RequestHandler, encrypts the response, and sends
// it back over the transport.
func (r *MessageRouter) handleInboundRequest(plaintext []byte, method string) {
	// Handle biometric pending notification specially (fire-and-forget, no response).
	if method == MethodLocalBiometricPending {
		r.handleBiometricPending(plaintext)
		return
	}

	if r.requestHandler == nil {
		r.logger.Warn("received inbound request but no handler configured")
		return
	}

	var req Request
	if err := json.Unmarshal(plaintext, &req); err != nil {
		r.logger.Error("failed to unmarshal inbound request", "error", err)
		return
	}

	r.logger.Debug("routing inbound request", "method", req.Method, "id", req.ID)

	resp := r.requestHandler.HandleRequest(context.Background(), &req)
	if resp == nil {
		return
	}

	// Encode, encrypt, and send the response back.
	respBytes, err := json.Marshal(resp)
	if err != nil {
		r.logger.Error("failed to marshal inbound response", "error", err)
		return
	}

	r.sendMu.Lock()
	ciphertext, err := r.session.Encrypt(respBytes)
	if err != nil {
		r.sendMu.Unlock()
		r.logger.Error("failed to encrypt inbound response", "error", err)
		return
	}
	sendErr := r.transport.Send(context.Background(), ciphertext)
	r.sendMu.Unlock()
	if sendErr != nil {
		r.logger.Error("failed to send inbound response", "error", sendErr)
	}
}

// biometricPendingRequest is used specifically for unmarshalling
// local.biometricPending notifications with json.RawMessage for params.
type biometricPendingRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// handleBiometricPending processes a local.biometricPending notification.
// This is a fire-and-forget notification from the phone indicating that
// biometric approval is pending. No response is sent back.
func (r *MessageRouter) handleBiometricPending(plaintext []byte) {
	var req biometricPendingRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		r.logger.Error("failed to unmarshal biometric pending request", "error", err)
		return
	}

	r.logger.Debug("received biometric pending notification", "id", req.ID)

	if r.biometricHandler == nil {
		r.logger.Debug("no biometric handler configured, ignoring notification")
		return
	}

	// Decode the params.
	var params LocalBiometricPendingParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			r.logger.Error("failed to unmarshal biometric pending params", "error", err)
			return
		}
	}

	// Handle the notification (show desktop notification).
	r.biometricHandler.HandleBiometricPending(&params)
}

// dispatchMessage determines if a decrypted message is a request or response
// and routes it accordingly.
func (r *MessageRouter) dispatchMessage(plaintext []byte) {
	var probe messageProbe
	if err := json.Unmarshal(plaintext, &probe); err != nil {
		r.logger.Error("failed to unmarshal message probe", "error", err)
		return
	}

	if probe.Method != "" {
		// Inbound request from the remote peer.
		r.handleInboundRequest(plaintext, probe.Method)
	} else {
		// Response to one of our outbound requests.
		r.routeResponse(plaintext, probe.ID)
	}
}

// routeResponse delivers a response to the pending request's channel.
func (r *MessageRouter) routeResponse(plaintext []byte, id uint64) {
	var resp Response
	if err := json.Unmarshal(plaintext, &resp); err != nil {
		r.logger.Error("failed to unmarshal response", "error", err)
		return
	}

	r.mu.Lock()
	ch, ok := r.pending[id]
	r.mu.Unlock()

	if !ok {
		r.logger.Warn("received response for unknown request", "id", id)
		return
	}

	select {
	case ch <- &resp:
	default:
		r.logger.Warn("response channel full, dropping response", "id", id)
	}
}
