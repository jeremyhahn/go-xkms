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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

const (
	// headerSessionID is the header key for passing session IDs between begin/finish calls.
	headerSessionID = "X-Session-Id"

	// headerUserID is the header key for passing user IDs.
	headerUserID = "X-User-Id"

	// headerAuthorization is the standard Authorization header.
	headerAuthorization = "Authorization"

	// headerContentType is the Content-Type header.
	headerContentType = "Content-Type"

	// contentTypeJSON is the JSON content type.
	contentTypeJSON = "application/json"

	// pathRegistrationBegin is the server endpoint for starting registration.
	pathRegistrationBegin = "/api/v1/webauthn/registration/begin"

	// pathRegistrationFinish is the server endpoint for finishing registration.
	pathRegistrationFinish = "/api/v1/webauthn/registration/finish"

	// pathLoginBegin is the server endpoint for starting login.
	pathLoginBegin = "/api/v1/webauthn/login/begin"

	// pathLoginFinish is the server endpoint for finishing login.
	pathLoginFinish = "/api/v1/webauthn/login/finish"

	// pathHealthCheck is used to verify server availability.
	pathHealthCheck = "/api/v1/webauthn/registration/status"

	// maxResponseBodySize is the maximum response body size we read (1MB).
	maxResponseBodySize = 1 << 20
)

// Client is a headless WebAuthn client that performs registration and
// authentication against a WebAuthn relying party server. It acts as the
// "browser" in the WebAuthn flow, bridging the RP server and a local
// authenticator.
type Client struct {
	mu         sync.RWMutex
	config     *Config
	httpClient *http.Client
	adapter    AuthenticatorAdapter
	serverURL  string
}

// NewClient creates a new headless WebAuthn client with the provided configuration.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	config.SetDefaults()

	if err := config.Validate(); err != nil {
		return nil, err
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		transport := &http.Transport{}
		if config.TLSConfig != nil {
			transport.TLSClientConfig = config.TLSConfig
		}
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		}
	}

	serverURL := strings.TrimRight(config.ServerURL, "/")

	return &Client{
		config:     config,
		httpClient: httpClient,
		adapter:    config.AuthenticatorAdapter,
		serverURL:  serverURL,
	}, nil
}

// Register performs a full WebAuthn registration ceremony:
//  1. POST registration/begin to get creation options from the server
//  2. Call the authenticator's MakeCredential with those options
//  3. POST registration/finish with the attestation response
func (c *Client) Register(ctx context.Context, req *RegistrationRequest) (*RegistrationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	adapter := c.adapter
	c.mu.RUnlock()

	if !adapter.Available() {
		return nil, ErrAuthenticatorNotFound
	}

	// Step 1: Begin registration with the server
	creationOptions, sessionID, err := c.beginRegistration(ctx, req)
	if err != nil {
		return nil, wrapError("begin registration", err)
	}

	// Step 2: Create credential with the authenticator
	attestationResponse, err := adapter.MakeCredential(creationOptions)
	if err != nil {
		return nil, wrapError("make credential", fmt.Errorf("%w: %w", ErrCTAPOperationFailed, err))
	}

	// Step 3: Finish registration with the server
	result, err := c.finishRegistration(ctx, sessionID, attestationResponse, req.AuthToken)
	if err != nil {
		return nil, wrapError("finish registration", err)
	}

	return result, nil
}

// Login performs a full WebAuthn authentication ceremony:
//  1. POST login/begin to get assertion options from the server
//  2. Call the authenticator's GetAssertion with those options
//  3. POST login/finish with the assertion response
func (c *Client) Login(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	adapter := c.adapter
	c.mu.RUnlock()

	if !adapter.Available() {
		return nil, ErrAuthenticatorNotFound
	}

	// Step 1: Begin login with the server
	assertionOptions, sessionID, userID, err := c.beginLogin(ctx, req)
	if err != nil {
		return nil, wrapError("begin login", err)
	}

	// Step 2: Get assertion from the authenticator
	assertionResponse, err := adapter.GetAssertion(assertionOptions)
	if err != nil {
		return nil, wrapError("get assertion", fmt.Errorf("%w: %w", ErrCTAPOperationFailed, err))
	}

	// Step 3: Finish login with the server
	result, err := c.finishLogin(ctx, sessionID, userID, assertionResponse, req.AuthToken)
	if err != nil {
		return nil, wrapError("finish login", err)
	}

	return result, nil
}

// Available checks if both the server and authenticator are reachable.
func (c *Client) Available(ctx context.Context) bool {
	c.mu.RLock()
	adapter := c.adapter
	c.mu.RUnlock()

	if !adapter.Available() {
		return false
	}

	return c.serverAvailable(ctx)
}

// beginRegistration sends the registration begin request to the server.
func (c *Client) beginRegistration(ctx context.Context, req *RegistrationRequest) ([]byte, string, error) {
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	body := beginRegistrationRequest{
		Email:       req.Username,
		DisplayName: displayName,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, "", wrapError("marshal request", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+pathRegistrationBegin, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)

	if req.AuthToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+req.AuthToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrServerUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, "", wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", parseServerError(resp.StatusCode, respBody)
	}

	sessionID := resp.Header.Get(headerSessionID)
	if sessionID == "" {
		return nil, "", ErrInvalidServerResponse
	}

	return respBody, sessionID, nil
}

// finishRegistration sends the registration finish request to the server.
func (c *Client) finishRegistration(ctx context.Context, sessionID string, attestation []byte, authToken string) (*RegistrationResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+pathRegistrationFinish, bytes.NewReader(attestation))
	if err != nil {
		return nil, wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)
	httpReq.Header.Set(headerSessionID, sessionID)

	if authToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+authToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrServerUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrRegistrationFailed, parseServerError(resp.StatusCode, respBody))
	}

	var authResp authResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %w", ErrInvalidServerResponse, err)
	}

	return &RegistrationResult{
		UserID: authResp.UserID,
		JWT:    authResp.Token,
	}, nil
}

// beginLogin sends the login begin request to the server.
func (c *Client) beginLogin(ctx context.Context, req *AuthenticationRequest) ([]byte, string, string, error) {
	body := beginLoginRequest{
		Email: req.Username,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, "", "", wrapError("marshal request", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+pathLoginBegin, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", "", wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)

	if req.AuthToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+req.AuthToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: %w", ErrServerUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, "", "", wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", parseServerError(resp.StatusCode, respBody)
	}

	sessionID := resp.Header.Get(headerSessionID)
	if sessionID == "" {
		return nil, "", "", ErrInvalidServerResponse
	}

	userID := resp.Header.Get(headerUserID)

	return respBody, sessionID, userID, nil
}

// finishLogin sends the login finish request to the server.
func (c *Client) finishLogin(ctx context.Context, sessionID, userID string, assertion []byte, authToken string) (*AuthenticationResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+pathLoginFinish, bytes.NewReader(assertion))
	if err != nil {
		return nil, wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)
	httpReq.Header.Set(headerSessionID, sessionID)

	if userID != "" {
		httpReq.Header.Set(headerUserID, userID)
	}

	if authToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+authToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrServerUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %w", ErrAuthenticationFailed, parseServerError(resp.StatusCode, respBody))
	}

	var authResp authResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %w", ErrInvalidServerResponse, err)
	}

	return &AuthenticationResult{
		UserID: authResp.UserID,
		JWT:    authResp.Token,
	}, nil
}

// serverAvailable checks if the server is reachable by issuing a lightweight
// GET to the registration status endpoint.
func (c *Client) serverAvailable(ctx context.Context) bool {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.serverURL+pathHealthCheck, nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain the body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode < 500
}

// parseServerError extracts an error from the response body.
func parseServerError(statusCode int, body []byte) error {
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return &ServerError{
			StatusCode: statusCode,
			Message:    string(body),
		}
	}
	return &ServerError{
		StatusCode: statusCode,
		ErrorCode:  errResp.Error,
		Message:    errResp.Message,
	}
}
