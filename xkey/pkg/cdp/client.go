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

// Package cdp provides a minimal Chrome DevTools Protocol client for the
// WebAuthn domain. It connects to a running Chrome instance over its
// debugging WebSocket and manages virtual authenticators for FIDO2 testing.
package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

// Client connects to Chrome's debugging WebSocket and controls the WebAuthn domain.
type Client struct {
	conn    *websocket.Conn
	nextID  atomic.Int64
	logger  *slog.Logger
	mu      sync.Mutex
	pending map[int64]chan rawResponse
	done    chan struct{}
}

// rawResponse holds the CDP response payload or an error from the protocol.
type rawResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *protocolError  `json:"error,omitempty"`
}

// protocolError represents a CDP protocol-level error.
type protocolError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cdpRequest is the wire format for a CDP JSON-RPC-style request.
type cdpRequest struct {
	ID     int64       `json:"id"`
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

// cdpResponse is the wire format for a CDP JSON-RPC-style response.
type cdpResponse struct {
	ID     int64           `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *protocolError  `json:"error,omitempty"`
}

// versionResponse is the JSON returned by Chrome's /json/version endpoint.
type versionResponse struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// pageTarget is a single entry from Chrome's /json endpoint listing open tabs.
type pageTarget struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Title                string `json:"title"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// AuthenticatorOptions configures a CDP virtual authenticator.
type AuthenticatorOptions struct {
	Protocol                    string `json:"protocol"`
	Transport                   string `json:"transport"`
	HasResidentKey              bool   `json:"hasResidentKey"`
	HasUserVerification         bool   `json:"hasUserVerification"`
	IsUserVerified              bool   `json:"isUserVerified"`
	AutomaticPresenceSimulation bool   `json:"automaticPresenceSimulation"`
}

// Credential matches the CDP WebAuthn.Credential type for adding
// pre-existing credentials to a virtual authenticator.
type Credential struct {
	CredentialID         string `json:"credentialId"`
	IsResidentCredential bool   `json:"isResidentCredential"`
	RpID                 string `json:"rpId"`
	PrivateKey           string `json:"privateKey"`
	UserHandle           string `json:"userHandle,omitempty"`
	SignCount            int    `json:"signCount"`
}

// addAuthenticatorResult holds the authenticatorId returned by
// WebAuthn.addVirtualAuthenticator.
type addAuthenticatorResult struct {
	AuthenticatorID string `json:"authenticatorId"`
}

// NewClient connects to Chrome's debugging port, discovers the WebSocket
// URL via /json/version, and establishes a persistent WebSocket connection.
func NewClient(host string, port int, logger *slog.Logger) (*Client, error) {
	wsURL, err := discoverWebSocketURL(host, port)
	if err != nil {
		return nil, err
	}

	logger.Info("connecting to Chrome DevTools", slog.String("url", wsURL))

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCDPConnectionFailed, err)
	}

	c := &Client{
		conn:    conn,
		logger:  logger,
		pending: make(map[int64]chan rawResponse),
		done:    make(chan struct{}),
	}

	go c.readLoop()

	return c, nil
}

// discoverWebSocketURL discovers a page-level DevTools WebSocket URL from
// Chrome's /json endpoint. The WebAuthn domain is only available on page
// targets, not the browser-level target returned by /json/version.
// If no page targets exist, a new blank tab is created via PUT /json/new.
func discoverWebSocketURL(host string, port int) (string, error) {
	baseURL := fmt.Sprintf("http://%s:%d", host, port)

	// Try to find an existing page target.
	wsURL, err := findPageTarget(baseURL)
	if err == nil {
		return wsURL, nil
	}

	// No page targets found — create a blank tab.
	wsURL, err = createBlankTarget(baseURL)
	if err != nil {
		return "", fmt.Errorf("%w: no page targets and failed to create one: %w",
			ErrCDPWebSocketURLNotFound, err)
	}

	return wsURL, nil
}

// findPageTarget queries /json for the first available page target.
func findPageTarget(baseURL string) (string, error) {
	resp, err := http.Get(baseURL + "/json")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPVersionFetchFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPVersionFetchFailed, err)
	}

	var targets []pageTarget
	if err := json.Unmarshal(body, &targets); err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPResponseParseFailed, err)
	}

	for i := range targets {
		if targets[i].Type == "page" && targets[i].WebSocketDebuggerURL != "" {
			return targets[i].WebSocketDebuggerURL, nil
		}
	}

	return "", ErrCDPWebSocketURLNotFound
}

// createBlankTarget creates a new blank tab via PUT /json/new and returns
// its page-level WebSocket URL.
func createBlankTarget(baseURL string) (string, error) {
	req, err := http.NewRequest(http.MethodPut, baseURL+"/json/new?about:blank", nil)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPRequestFailed, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPVersionFetchFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPVersionFetchFailed, err)
	}

	var target pageTarget
	if err := json.Unmarshal(body, &target); err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPResponseParseFailed, err)
	}

	if target.WebSocketDebuggerURL == "" {
		return "", ErrCDPWebSocketURLNotFound
	}

	return target.WebSocketDebuggerURL, nil
}

// readLoop reads CDP responses from the WebSocket and dispatches them to
// waiting callers via the pending channel map.
func (c *Client) readLoop() {
	defer close(c.done)

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			c.logger.Debug("CDP read loop exiting", slog.String("reason", err.Error()))
			return
		}

		var resp cdpResponse
		if err := json.Unmarshal(message, &resp); err != nil {
			c.logger.Warn("CDP unparseable message", slog.String("error", err.Error()))
			continue
		}

		// Only dispatch responses with an ID (skip events).
		if resp.ID == 0 && resp.Result == nil && resp.Error == nil {
			continue
		}

		c.mu.Lock()
		ch, ok := c.pending[resp.ID]
		if ok {
			delete(c.pending, resp.ID)
		}
		c.mu.Unlock()

		if ok {
			ch <- rawResponse{
				Result: resp.Result,
				Error:  resp.Error,
			}
		}
	}
}

// send dispatches a CDP method call and waits for the corresponding response.
// It respects context cancellation for timeout and shutdown.
func (c *Client) send(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	id := c.nextID.Add(1)

	req := cdpRequest{
		ID:     id,
		Method: method,
		Params: params,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCDPRequestFailed, err)
	}

	ch := make(chan rawResponse, 1)

	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()

	c.logger.Debug("CDP send", slog.String("method", method), slog.Int64("id", id))

	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %w", ErrCDPWriteFailed, err)
	}

	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %w", ErrCDPRequestTimeout, ctx.Err())
	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("%w: code=%d message=%s",
				ErrCDPProtocolError, resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	case <-c.done:
		return nil, ErrCDPConnectionFailed
	}
}

// Enable activates the WebAuthn domain in Chrome DevTools.
func (c *Client) Enable(ctx context.Context) error {
	type enableParams struct {
		EnableUI bool `json:"enableUI"`
	}
	_, err := c.send(ctx, "WebAuthn.enable", &enableParams{EnableUI: false})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCDPEnableFailed, err)
	}
	return nil
}

// AddVirtualAuthenticator creates a virtual authenticator with the given
// options and returns its authenticator ID.
func (c *Client) AddVirtualAuthenticator(ctx context.Context, opts *AuthenticatorOptions) (string, error) {
	type addParams struct {
		Options *AuthenticatorOptions `json:"options"`
	}

	result, err := c.send(ctx, "WebAuthn.addVirtualAuthenticator", &addParams{Options: opts})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPAuthenticatorFailed, err)
	}

	var parsed addAuthenticatorResult
	if err := json.Unmarshal(result, &parsed); err != nil {
		return "", fmt.Errorf("%w: %w", ErrCDPResponseParseFailed, err)
	}

	c.logger.Info("virtual authenticator created",
		slog.String("authenticatorId", parsed.AuthenticatorID),
		slog.String("protocol", opts.Protocol),
		slog.String("transport", opts.Transport))

	return parsed.AuthenticatorID, nil
}

// AddCredential registers a credential with the specified virtual authenticator.
func (c *Client) AddCredential(ctx context.Context, authenticatorID string, cred *Credential) error {
	type addCredParams struct {
		AuthenticatorID string      `json:"authenticatorId"`
		Credential      *Credential `json:"credential"`
	}

	_, err := c.send(ctx, "WebAuthn.addCredential", &addCredParams{
		AuthenticatorID: authenticatorID,
		Credential:      cred,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCDPCredentialFailed, err)
	}

	c.logger.Debug("credential added",
		slog.String("authenticatorId", authenticatorID),
		slog.String("credentialId", cred.CredentialID),
		slog.String("rpId", cred.RpID))

	return nil
}

// RemoveVirtualAuthenticator removes a previously created virtual authenticator.
func (c *Client) RemoveVirtualAuthenticator(ctx context.Context, authenticatorID string) error {
	type removeParams struct {
		AuthenticatorID string `json:"authenticatorId"`
	}

	_, err := c.send(ctx, "WebAuthn.removeVirtualAuthenticator", &removeParams{
		AuthenticatorID: authenticatorID,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCDPRemoveFailed, err)
	}

	c.logger.Info("virtual authenticator removed",
		slog.String("authenticatorId", authenticatorID))

	return nil
}

// Disable deactivates the WebAuthn domain in Chrome DevTools.
func (c *Client) Disable(ctx context.Context) error {
	_, err := c.send(ctx, "WebAuthn.disable", nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCDPDisableFailed, err)
	}
	return nil
}

// Close gracefully shuts down the WebSocket connection and stops the read loop.
func (c *Client) Close() error {
	err := c.conn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
	)
	if err != nil {
		c.logger.Warn("CDP close write failed", slog.String("error", err.Error()))
	}

	closeErr := c.conn.Close()

	// Wait for the read loop to exit.
	<-c.done

	// Drain any remaining pending requests.
	c.mu.Lock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.mu.Unlock()

	if closeErr != nil {
		return fmt.Errorf("%w: %w", ErrCDPConnectionFailed, closeErr)
	}
	return nil
}

// MarshalRequest serializes a CDP request to JSON. Exported for testing
// request wire format without a live connection.
func MarshalRequest(method string, params interface{}) ([]byte, error) {
	req := cdpRequest{
		ID:     1,
		Method: method,
		Params: params,
	}
	return json.Marshal(req)
}

// UnmarshalResponse deserializes a CDP response from JSON. Exported for
// testing response parsing without a live connection.
func UnmarshalResponse(data []byte) (*cdpResponse, error) {
	var resp cdpResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCDPResponseParseFailed, err)
	}
	return &resp, nil
}
