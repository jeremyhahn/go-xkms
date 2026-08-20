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
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/internal/lifecycle"
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

	// started guards the receive loop's WaitGroup registration, under mu.
	// See Start.
	started bool

	// wg counts everything that reads the session: the background receive loop
	// and every in-flight SendRequest. Join waits on it, so a caller that
	// destroys the session's protected key only does so once nothing is still
	// decrypting or encrypting through it.
	wg sync.WaitGroup

	// joiner bounds Join's wait on wg with a single waiter goroutine for the
	// router's whole life. Join is public and callers retry; a waiter per
	// call would add a permanently blocked goroutine on every retry against a
	// receive loop that is already stuck.
	joiner lifecycle.Joiner
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

// Start begins the background receive loop. Call it after the Noise handshake
// completes.
//
// It is a no-op on a router that has already started or has been stopped.
// Both matter for more than tidiness: this Add takes the WaitGroup from zero
// to one, and an Add that starts from zero must happen before any Wait on
// that group. Registering outside mu let a Join racing Start — or simply
// running before it — observe an empty group, report the router drained, and
// license the owner to destroy the session key the receive loop was about to
// start reading.
//
// So the registration is paired with the closed check under mu, exactly as
// SendRequest's is.
func (r *MessageRouter) Start() {
	r.mu.Lock()
	if r.closed.Load() || r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.wg.Add(1)
	r.mu.Unlock()

	go r.receiveLoop()
}

// Stop shuts down the receive loop and cancels all pending requests.
// Stop is safe to call multiple times.
// Stop signals the router to shut down and cancels pending requests. It does
// NOT wait for the background loop to exit — see StopAndJoin for why it
// cannot promise that.
func (r *MessageRouter) Stop() {
	r.closeOnce.Do(func() {
		// Under mu so the check-and-register in SendRequest is atomic against
		// it; see the note there.
		r.mu.Lock()
		r.closed.Store(true)
		r.mu.Unlock()

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

// StopAndJoin stops the router and waits up to timeout for its background
// goroutines to exit, reporting whether they did.
//
// Callers that can unblock the transport should prefer Stop, then close the
// transport, then Join: receiveLoop sits in an uncancellable read, so this
// combined form waits out the whole timeout whenever the transport is idle.
//
// Callers that destroy the session's protected static key after shutdown must
// check the result: receiveLoop decrypts through the session, so freeing those
// pages while it still runs is a use-after-free. A false result means keep the
// key alive — leaking protected memory is the safe failure, freeing it is not.
//
// The join is bounded rather than unconditional because it cannot be
// guaranteed. receiveLoop blocks in Transport.Receive with a background
// context, so it only observes the done channel between messages; a transport
// sitting idle on a read will not notice the shutdown at all. Making this a
// hard join needs Receive to be cancellable across every Transport
// implementation, which is an interface-wide change and not one to make
// silently. Until then, an unbounded Wait here would hang shutdown, which is
// worse than the goroutine it was meant to fix.
func (r *MessageRouter) StopAndJoin(timeout time.Duration) bool {
	r.Stop()
	return r.Join(timeout)
}

// Join waits up to timeout for the background goroutines to exit, reporting
// whether they did. Call Stop first; Join alone does not signal shutdown.
//
// Separated from Stop so a caller can close the transport in between, which
// is the only thing that wakes a receiveLoop blocked in an idle read.
func (r *MessageRouter) Join(timeout time.Duration) bool {
	// Refuse to report a drain before Stop has run.
	//
	// The joiner latches: it starts one waiter, and whatever that waiter
	// observes is the answer every later Join gets. Before Stop the group can
	// still go from zero to one — Start may not have run yet, and SendRequest
	// is still admitted — so a waiter created now could latch "drained" on an
	// empty group and keep reporting success while the receive loop runs.
	//
	// After Stop neither can happen: Start returns early and SendRequest is
	// refused, both under mu. Reporting false here is also the safe answer in
	// its own right, since it makes the caller retain the key.
	if !r.closed.Load() {
		r.logger.Warn("Join called before Stop; refusing to report a drain " +
			"because the router can still register new work")
		return false
	}

	if r.joiner.Join(&r.wg, timeout) {
		return true
	}

	r.logger.Warn("message router did not exit within the shutdown window; "+
		"its session key must stay resident", "timeout", timeout)
	return false
}

// SendRequest sends an encrypted outbound request and waits for the
// matching response from the background receive loop.
func (r *MessageRouter) SendRequest(ctx context.Context, req *Request) (*Response, error) {
	// Register on the same WaitGroup Join waits for, and pair the closed check
	// with the Add under mu: a sender either registers before Stop marks the
	// router closed and is therefore counted, or sees closed and never
	// registers at all. Without this a sender could be encrypting through the
	// session after Join reported success and the owner freed the key — and
	// this method is public, and its constructor is re-exported from
	// xkey/pkg/phone, so a consumer can reach it without going through
	// PhoneKeyBackend's lease.
	respCh := make(chan *Response, 1)

	r.mu.Lock()
	if r.closed.Load() {
		r.mu.Unlock()
		return nil, ErrBackendClosed
	}
	r.wg.Add(1)
	r.pending[req.ID] = respCh
	r.mu.Unlock()

	defer r.wg.Done()

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
	defer r.wg.Done()

	for {
		select {
		case <-r.done:
			return
		default:
		}

		// This read is NOT cancellable, and the loop's lifecycle is only as
		// responsive as the traffic it carries: the done check above runs
		// between messages, so a transport sitting idle here never observes
		// shutdown at all. StopAndJoin bounds its wait for exactly this
		// reason, and callers must not free session-backed key material on
		// the strength of Stop alone.
		//
		// Making this cancellable means threading a context through every
		// Transport implementation. Tracked as go-xkms#30.
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

	// Lookup AND delivery under r.mu, not just the lookup.
	//
	// Stop closes every pending channel while holding r.mu. Releasing the
	// lock between finding the channel and sending on it left a window where
	// Stop could close it first — and a send on a closed channel panics, so a
	// peer response arriving during shutdown could crash the process. The
	// send is non-blocking and the receiver never holds r.mu, so holding it
	// here cannot deadlock.
	r.mu.Lock()
	defer r.mu.Unlock()

	ch, ok := r.pending[id]
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
