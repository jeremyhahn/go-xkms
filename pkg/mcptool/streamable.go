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

package mcptool

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	headerSessionID       = "Mcp-Session-Id"
	headerProtocolVersion = "Mcp-Protocol-Version"
	contentTypeJSON       = "application/json"
	contentTypeEventFeed  = "text/event-stream"
	// maxResponseBytes bounds one HTTP response body read from the server.
	maxResponseBytes = 32 << 20
	// closeTimeout bounds the DELETE that ends the session on Close.
	closeTimeout = 5 * time.Second
)

// ErrRedirectRefused is returned when the MCP server answers with a redirect.
// The client never follows one: a Location header could send the request and
// its credentials to another origin (GO-2026-6911).
var ErrRedirectRefused = errors.New("mcp server answered with a redirect; redirects are not followed")

// errTransportClosed is returned by a send on a closed transport.
var errTransportClosed = errors.New("mcp transport is closed")

// streamableHTTP is the client side of the MCP streamable HTTP transport.
// Every JSON-RPC message is one POST to a single endpoint URL; the server
// answers with a JSON body or an event stream that carries the response.
// It sends requests only to that URL and never follows a redirect, so no
// request, header or token reaches an origin the server names in a Location
// header. It implements mcp-go's transport.Interface and HTTPConnection.
type streamableHTTP struct {
	endpoint string
	http     *http.Client
	headers  map[string]string

	mu              sync.RWMutex
	sessionID       string
	protocolVersion string
	onNotification  func(mcp.JSONRPCNotification)
	closed          bool
	// inflight holds the cancel function of every POST whose response body
	// is still open, so Close interrupts requests a server holds open.
	inflight map[uint64]context.CancelFunc
	nextReq  uint64
}

// releasingBody closes the response body and then releases the request's
// registration and context in Close.
type releasingBody struct {
	io.ReadCloser
	release func()
}

func (b *releasingBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

var _ mcptransport.HTTPConnection = (*streamableHTTP)(nil)

// newStreamableHTTP returns a transport that posts to endpoint with the
// given round tripper and extra request headers. The headers map is copied.
func newStreamableHTTP(endpoint string, rt http.RoundTripper, headers map[string]string) *streamableHTTP {
	copied := make(map[string]string, len(headers))
	for k, v := range headers {
		copied[k] = v
	}
	return &streamableHTTP{
		endpoint: endpoint,
		http: &http.Client{
			Transport: rt,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		headers: copied,
	}
}

// Start implements transport.Interface. The transport holds no connection
// open between messages, so there is nothing to start.
func (s *streamableHTTP) Start(context.Context) error {
	return nil
}

// SendRequest posts one JSON-RPC request and returns the server's response.
func (s *streamableHTTP) SendRequest(ctx context.Context, request mcptransport.JSONRPCRequest) (*mcptransport.JSONRPCResponse, error) {
	resp, err := s.post(ctx, request, request.Header)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusBadRequest {
		return badRequest(resp, request)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp request %s: unexpected HTTP status %d", request.Method, resp.StatusCode)
	}
	if request.Method == string(mcp.MethodInitialize) {
		if id := resp.Header.Get(headerSessionID); id != "" {
			s.mu.Lock()
			s.sessionID = id
			s.mu.Unlock()
		}
	}

	body := io.LimitReader(resp.Body, maxResponseBytes)
	mediaType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	switch mediaType {
	case contentTypeJSON:
		var msg wireMessage
		if err := json.NewDecoder(body).Decode(&msg); err != nil {
			return nil, fmt.Errorf("mcp request %s: decode response: %w", request.Method, err)
		}
		if !msg.isResponse() {
			return nil, fmt.Errorf("mcp request %s: server body is not a JSON-RPC response", request.Method)
		}
		resp, err := msg.response(request.ID)
		if err != nil {
			return nil, fmt.Errorf("mcp request %s: %w", request.Method, err)
		}
		return resp, nil
	case contentTypeEventFeed:
		return s.readEventStream(body, request)
	default:
		return nil, fmt.Errorf("mcp request %s: unexpected content type %q", request.Method, mediaType)
	}
}

// SendNotification posts one JSON-RPC notification; the server accepts it
// without a response body.
func (s *streamableHTTP) SendNotification(ctx context.Context, notification mcp.JSONRPCNotification) error {
	resp, err := s.post(ctx, notification, nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mcp notification %s: unexpected HTTP status %d", notification.Method, resp.StatusCode)
	}
	return nil
}

// SetNotificationHandler implements transport.Interface.
func (s *streamableHTTP) SetNotificationHandler(handler func(notification mcp.JSONRPCNotification)) {
	s.mu.Lock()
	s.onNotification = handler
	s.mu.Unlock()
}

// SetProtocolVersion implements transport.HTTPConnection: the negotiated
// version goes on every later request.
func (s *streamableHTTP) SetProtocolVersion(version string) {
	s.mu.Lock()
	s.protocolVersion = version
	s.mu.Unlock()
}

// GetSessionId implements transport.Interface.
func (s *streamableHTTP) GetSessionId() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// Close ends the server session, when there is one, and refuses later sends.
// It is safe to call more than once.
func (s *streamableHTTP) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	sessionID := s.sessionID
	cancels := make([]context.CancelFunc, 0, len(s.inflight))
	for _, cancel := range s.inflight {
		cancels = append(cancels, cancel)
	}
	s.mu.Unlock()

	// Interrupt every request whose response is still open: a stalled
	// response or an unfinished event stream must not keep its goroutine
	// and connection after the client is closed.
	for _, cancel := range cancels {
		cancel()
	}

	if sessionID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
		defer cancel()
		if req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.endpoint, nil); err == nil {
			s.setHeaders(req, nil)
			if resp, err := s.http.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
	s.http.CloseIdleConnections()
	return nil
}

// post sends one JSON-RPC message to the endpoint. A redirect is an error.
func (s *streamableHTTP) post(ctx context.Context, message any, extra http.Header) (*http.Response, error) {
	data, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("mcp: encode message: %w", err)
	}

	// Register the request's cancel function under the same lock that Close
	// takes to mark the transport closed: a request either sees closed and
	// never starts, or is registered and cancelled by Close.
	reqCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		return nil, errTransportClosed
	}
	if s.inflight == nil {
		s.inflight = make(map[uint64]context.CancelFunc)
	}
	s.nextReq++
	key := s.nextReq
	s.inflight[key] = cancel
	s.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.inflight, key)
			s.mu.Unlock()
			cancel()
		})
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.endpoint, bytes.NewReader(data))
	if err != nil {
		release()
		return nil, fmt.Errorf("mcp: build request: %w", err)
	}
	s.setHeaders(req, extra)
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("Accept", contentTypeJSON+", "+contentTypeEventFeed)

	resp, err := s.http.Do(req)
	if err != nil {
		release()
		return nil, fmt.Errorf("mcp: send request: %w", err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		_ = resp.Body.Close()
		release()
		return nil, fmt.Errorf("%w (HTTP %d)", ErrRedirectRefused, resp.StatusCode)
	}
	resp.Body = &releasingBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// setHeaders puts the configured headers, the per-message headers and the
// session headers on req.
func (s *streamableHTTP) setHeaders(req *http.Request, extra http.Header) {
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sessionID != "" {
		req.Header.Set(headerSessionID, s.sessionID)
	}
	if s.protocolVersion != "" {
		req.Header.Set(headerProtocolVersion, s.protocolVersion)
	}
}

// readEventStream reads server-sent events until the response to request
// arrives. Notifications on the way go to the notification handler; requests
// from the server are not supported by this client and are dropped.
func (s *streamableHTTP) readEventStream(body io.Reader, request mcptransport.JSONRPCRequest) (*mcptransport.JSONRPCResponse, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxResponseBytes)
	var data strings.Builder
	for {
		more := scanner.Scan()
		line := scanner.Text()
		if !more || line == "" {
			if data.Len() > 0 {
				resp, err := s.dispatchEvent(data.String(), request.ID)
				if err != nil {
					return nil, fmt.Errorf("mcp request %s: %w", request.Method, err)
				}
				if resp != nil {
					return resp, nil
				}
				data.Reset()
			}
			if !more {
				break
			}
			continue
		}
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(value, " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("mcp request %s: read event stream: %w", request.Method, err)
	}
	return nil, fmt.Errorf("mcp request %s: event stream ended without a response", request.Method)
}

// dispatchEvent handles one event's data. It returns the response when the
// event carries one, and nil otherwise.
func (s *streamableHTTP) dispatchEvent(data string, id mcp.RequestId) (*mcptransport.JSONRPCResponse, error) {
	var msg wireMessage
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, nil
	}
	if msg.isResponse() {
		return msg.response(id)
	}
	if msg.Method != "" && msg.ID == nil {
		var notification mcp.JSONRPCNotification
		if err := json.Unmarshal([]byte(data), &notification); err != nil {
			return nil, nil
		}
		s.mu.RLock()
		handler := s.onNotification
		s.mu.RUnlock()
		if handler != nil {
			handler(notification)
		}
	}
	return nil, nil
}

// wireMessage is the part of a JSON-RPC message the transport inspects.
// badRequest handles an HTTP 400 answer to request. A server that rejects
// the request at the protocol level, such as an unsupported protocol
// version, says why in a JSON-RPC error response for the request's id: that
// response is returned so the client sees the error's code and data. Any
// other HTTP 400 is an HTTP error.
func badRequest(resp *http.Response, request mcptransport.JSONRPCRequest) (*mcptransport.JSONRPCResponse, error) {
	statusErr := fmt.Errorf("mcp request %s: unexpected HTTP status %d", request.Method, resp.StatusCode)
	mediaType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if mediaType != contentTypeJSON {
		return nil, statusErr
	}
	var msg wireMessage
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&msg); err != nil {
		return nil, statusErr
	}
	if msg.Method != "" || msg.Error == nil || msg.Result != nil {
		return nil, statusErr
	}
	rpcResp, err := msg.response(request.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", statusErr, err)
	}
	return rpcResp, nil
}

type wireMessage struct {
	JSONRPC string                   `json:"jsonrpc"`
	ID      json.RawMessage          `json:"id,omitempty"`
	Method  string                   `json:"method,omitempty"`
	Result  json.RawMessage          `json:"result,omitempty"`
	Error   *mcp.JSONRPCErrorDetails `json:"error,omitempty"`
}

// isResponse reports whether the message is a result or an error.
func (m *wireMessage) isResponse() bool {
	return m.Method == "" && (m.Result != nil || m.Error != nil)
}

// response converts the message to mcp-go's response type. One POST carries
// one request, so the response takes that request's id.
func (m *wireMessage) response(id mcp.RequestId) (*mcptransport.JSONRPCResponse, error) {
	if m.JSONRPC != mcp.JSONRPC_VERSION {
		return nil, fmt.Errorf("response has JSON-RPC version %q, want %q", m.JSONRPC, mcp.JSONRPC_VERSION)
	}
	want, err := id.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("encode request id: %w", err)
	}
	if len(m.ID) == 0 || string(m.ID) == "null" {
		return nil, fmt.Errorf("response has no id, want %s", want)
	}
	var received mcp.RequestId
	if err := received.UnmarshalJSON(m.ID); err != nil {
		return nil, fmt.Errorf("decode response id: %w", err)
	}
	got, err := received.MarshalJSON()
	if err != nil || received.IsNil() || !bytes.Equal(got, want) {
		return nil, fmt.Errorf("response id %s does not match request id %s", m.ID, want)
	}
	return &mcptransport.JSONRPCResponse{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      id,
		Result:  m.Result,
		Error:   m.Error,
	}, nil
}
