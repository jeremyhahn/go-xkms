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
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// closeResponseBody closes resp.Body and logs a failure at debug level.
// Every call site here has already decided its result before this deferred
// call runs, so a close failure changes nothing about the caller's outcome.
func closeResponseBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		slog.Debug("webauthn/client: failed to close HTTP response body", "error", err)
	}
}

// drainResponseBody discards the remainder of resp.Body so the underlying
// connection can be reused, and logs a failure at debug level. The caller's
// result has already been computed from the response status, so a drain
// failure changes nothing about the outcome -- it only costs the connection
// its reuse.
func drainResponseBody(resp *http.Response) {
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		slog.Debug("webauthn/client: failed to drain HTTP response body", "error", err)
	}
}

const (
	// headerSessionID is the header key for passing session IDs between begin/finish calls.
	headerSessionID = "X-Session-Id"

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
	pathHealthCheck = "/health"

	// maxResponseBodySize is the maximum response body size we read (1MB).
	maxResponseBodySize = 1 << 20
)

// HTTPRelyingParty is the browser-shaped RelyingParty implementation: it
// speaks the pkg/webauthn/http RP routes (registration/begin,
// registration/finish, login/begin, login/finish) exactly as a browser's
// fetch() calls would, including the AuthToken-as-bearer-header and
// X-Session-Id correlation header those routes expect.
type HTTPRelyingParty struct {
	httpClient *http.Client
	serverURL  string
}

var (
	_ RelyingParty        = (*HTTPRelyingParty)(nil)
	_ AvailabilityChecker = (*HTTPRelyingParty)(nil)
)

// NewHTTPRelyingParty constructs a RelyingParty that speaks the
// pkg/webauthn/http browser routes at serverURL. A nil httpClient builds a
// default client with a 30s timeout.
func NewHTTPRelyingParty(serverURL string, httpClient *http.Client) (*HTTPRelyingParty, error) {
	if serverURL == "" {
		return nil, ErrServerURLRequired
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPRelyingParty{
		httpClient: httpClient,
		serverURL:  strings.TrimRight(serverURL, "/"),
	}, nil
}

// newDefaultHTTPRelyingParty builds the default HTTPRelyingParty NewClient
// uses when Config.RelyingParty is nil, applying Config's HTTPClient,
// TLSConfig and Timeout the way the pre-RP-seam Client constructor did.
func newDefaultHTTPRelyingParty(config *Config) (*HTTPRelyingParty, error) {
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
	return NewHTTPRelyingParty(config.ServerURL, httpClient)
}

// BeginRegistration sends the registration begin request to the server.
func (rp *HTTPRelyingParty) BeginRegistration(ctx context.Context, req *RegistrationRequest) (*BeginResult, error) {
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
		return nil, wrapError("marshal request", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		rp.serverURL+pathRegistrationBegin, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)

	if req.AuthToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+req.AuthToken)
	}

	resp, err := rp.httpClient.Do(httpReq)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrServerUnavailable, Cause: err}
	}
	defer closeResponseBody(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseServerError(resp.StatusCode, respBody)
	}

	sessionID := resp.Header.Get(headerSessionID)
	if sessionID == "" {
		return nil, ErrInvalidServerResponse
	}

	return &BeginResult{OptionsJSON: respBody, SessionID: sessionID}, nil
}

// FinishRegistration sends the registration finish request to the server.
func (rp *HTTPRelyingParty) FinishRegistration(ctx context.Context, begin *BeginResult, req *RegistrationRequest, attestation []byte) (*RegistrationResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		rp.serverURL+pathRegistrationFinish, bytes.NewReader(attestation))
	if err != nil {
		return nil, wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)
	httpReq.Header.Set(headerSessionID, begin.SessionID)

	if req.AuthToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+req.AuthToken)
	}

	resp, err := rp.httpClient.Do(httpReq)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrServerUnavailable, Cause: err}
	}
	defer closeResponseBody(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &errs.Joined{Lead: ErrRegistrationFailed, Cause: parseServerError(resp.StatusCode, respBody)}
	}

	var authResp authResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidServerResponse, Detail: "failed to decode response", Cause: err}
	}

	return &RegistrationResult{
		UserID: authResp.UserID,
		JWT:    authResp.Token,
	}, nil
}

// BeginAuthentication sends the login begin request to the server.
func (rp *HTTPRelyingParty) BeginAuthentication(ctx context.Context, req *AuthenticationRequest) (*BeginResult, error) {
	body := beginLoginRequest{
		Email: req.Username,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, wrapError("marshal request", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		rp.serverURL+pathLoginBegin, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)

	if req.AuthToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+req.AuthToken)
	}

	resp, err := rp.httpClient.Do(httpReq)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrServerUnavailable, Cause: err}
	}
	defer closeResponseBody(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseServerError(resp.StatusCode, respBody)
	}

	sessionID := resp.Header.Get(headerSessionID)
	if sessionID == "" {
		return nil, ErrInvalidServerResponse
	}

	return &BeginResult{
		OptionsJSON: respBody,
		SessionID:   sessionID,
	}, nil
}

// FinishAuthentication sends the login finish request to the server.
func (rp *HTTPRelyingParty) FinishAuthentication(ctx context.Context, begin *BeginResult, req *AuthenticationRequest, assertion []byte) (*AuthenticationResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		rp.serverURL+pathLoginFinish, bytes.NewReader(assertion))
	if err != nil {
		return nil, wrapError("create request", err)
	}
	httpReq.Header.Set(headerContentType, contentTypeJSON)
	httpReq.Header.Set(headerSessionID, begin.SessionID)

	if req.AuthToken != "" {
		httpReq.Header.Set(headerAuthorization, "Bearer "+req.AuthToken)
	}

	resp, err := rp.httpClient.Do(httpReq)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrServerUnavailable, Cause: err}
	}
	defer closeResponseBody(resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, wrapError("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &errs.Joined{Lead: ErrAuthenticationFailed, Cause: parseServerError(resp.StatusCode, respBody)}
	}

	var authResp authResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidServerResponse, Detail: "failed to decode response", Cause: err}
	}

	return &AuthenticationResult{
		UserID: authResp.UserID,
		JWT:    authResp.Token,
	}, nil
}

// Available checks if the server is reachable by issuing a lightweight GET
// to the server's health endpoint.
func (rp *HTTPRelyingParty) Available(ctx context.Context) bool {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		rp.serverURL+pathHealthCheck, nil)
	if err != nil {
		return false
	}

	resp, err := rp.httpClient.Do(httpReq)
	if err != nil {
		return false
	}
	defer closeResponseBody(resp)
	drainResponseBody(resp)

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

// beginRegistrationRequest is the request body for the registration/begin endpoint.
type beginRegistrationRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
}

// beginLoginRequest is the request body for the login/begin endpoint.
type beginLoginRequest struct {
	Email string `json:"email,omitempty"`
}

// authResponse is the response from the server after successful registration or login.
type authResponse struct {
	Token  string `json:"token"`
	UserID string `json:"user_id"`
}

// errorResponse is the error response format from the server.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
