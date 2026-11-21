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

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freeLoopbackPort returns a loopback port that is currently free, for
// tests that need Login to bind a real listener.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}

// newCredentialsTokenServer returns a mock AWS token endpoint that answers
// every request with valid DPoP-bound credentials.
func newCredentialsTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RawTokenResponse{
			AccessToken: &AccessTokenCredentials{
				AccessKeyID:     "AKIATEST",
				SecretAccessKey: "secret",
				SessionToken:    "session-token",
				Expiration:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
			TokenType:    "DPoP",
			ExpiresIn:    3600,
			RefreshToken: "refresh-abc",
		})
	}))
}

// deliverCallback simulates the browser's return trip: it parses the
// state out of authURL and sends the local callback listener a GET
// carrying code and, unless overrideState is non-empty, the matching
// state.
func deliverCallback(t *testing.T, callback oidc.Callback, authURL, code, overrideState string) {
	t.Helper()
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	state := u.Query().Get("state")
	if overrideState != "" {
		state = overrideState
	}

	redirect := callback.AWSRedirectURL() + "?state=" + url.QueryEscape(state)
	if code != "" {
		redirect += "&code=" + url.QueryEscape(code)
	}
	resp, getErr := http.Get(redirect) //nolint:noctx // fixed test-local callback URL
	require.NoError(t, getErr)
	_ = resp.Body.Close()
}

// TestLogin_Success proves the shared flow that both the CLI's "xkey oidc
// aws" command and the GUI's OIDC service depend on: it builds the
// authorization URL, waits for the local callback, and exchanges the code
// for DPoP-bound AWS credentials.
func TestLogin_Success(t *testing.T) {
	tokenServer := newCredentialsTokenServer(t)
	defer tokenServer.Close()

	callback := oidc.Callback{Host: "127.0.0.1", Port: freeLoopbackPort(t)}

	type outcome struct {
		result *LoginResult
		err    error
	}
	done := make(chan outcome, 1)
	var gotAuthURL string

	go func() {
		result, err := Login(context.Background(), LoginOptions{
			Region:                "us-east-1",
			Callback:              callback,
			TokenEndpointOverride: tokenServer.URL,
			Timeout:               5 * time.Second,
		}, func(authURL string) {
			gotAuthURL = authURL
			deliverCallback(t, callback, authURL, "test-code", "")
		})
		done <- outcome{result, err}
	}()

	select {
	case out := <-done:
		require.NoError(t, out.err)
		require.NotNil(t, out.result)
		assert.NotEmpty(t, gotAuthURL)
		assert.Equal(t, gotAuthURL, out.result.AuthURL)
		require.NotNil(t, out.result.TokenResponse)
		assert.True(t, out.result.TokenResponse.HasCredentials())
		assert.Equal(t, "refresh-abc", out.result.TokenResponse.RefreshToken)
		require.NotNil(t, out.result.DPoPKey)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Login()")
	}
}

// TestLogin_MissingRegion proves Login refuses to start without a region,
// before any listener is bound or browser callback invoked.
func TestLogin_MissingRegion(t *testing.T) {
	called := false
	_, err := Login(context.Background(), LoginOptions{}, func(string) { called = true })
	assert.ErrorIs(t, err, ErrMissingRegion)
	assert.False(t, called, "onAuthURL must not run when the login is refused up front")
}

// TestLogin_StateMismatch proves a callback whose state parameter does not
// match the one Login generated is rejected rather than treated as a
// completed login (CSRF protection).
func TestLogin_StateMismatch(t *testing.T) {
	tokenServer := newCredentialsTokenServer(t)
	defer tokenServer.Close()

	callback := oidc.Callback{Host: "127.0.0.1", Port: freeLoopbackPort(t)}

	type outcome struct {
		result *LoginResult
		err    error
	}
	done := make(chan outcome, 1)

	go func() {
		result, err := Login(context.Background(), LoginOptions{
			Region:                "us-east-1",
			Callback:              callback,
			TokenEndpointOverride: tokenServer.URL,
			Timeout:               5 * time.Second,
		}, func(authURL string) {
			deliverCallback(t, callback, authURL, "test-code", "not-the-real-state")
		})
		done <- outcome{result, err}
	}()

	select {
	case out := <-done:
		assert.ErrorIs(t, out.err, ErrStateMismatch)
		assert.Nil(t, out.result)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Login()")
	}
}

// TestLogin_CallbackDeniedByProvider proves an "error" query parameter on
// the callback (the user denying consent at AWS) surfaces as
// ErrCallbackFailed instead of hanging until the timeout.
func TestLogin_CallbackDeniedByProvider(t *testing.T) {
	callback := oidc.Callback{Host: "127.0.0.1", Port: freeLoopbackPort(t)}

	type outcome struct {
		result *LoginResult
		err    error
	}
	done := make(chan outcome, 1)

	go func() {
		result, err := Login(context.Background(), LoginOptions{
			Region:   "us-east-1",
			Callback: callback,
			Timeout:  5 * time.Second,
		}, func(authURL string) {
			u, parseErr := url.Parse(authURL)
			require.NoError(t, parseErr)
			redirect := callback.AWSRedirectURL() + "?error=access_denied&error_description=user+declined&state=" + u.Query().Get("state")
			resp, getErr := http.Get(redirect) //nolint:noctx // fixed test-local callback URL
			require.NoError(t, getErr)
			_ = resp.Body.Close()
		})
		done <- outcome{result, err}
	}()

	select {
	case out := <-done:
		assert.ErrorIs(t, out.err, ErrCallbackFailed)
		assert.Nil(t, out.result)
		assert.Contains(t, out.err.Error(), "access_denied")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Login()")
	}
}

// TestLogin_TokenExchangeFailed proves a token endpoint error response is
// surfaced as ErrTokenExchangeFailed rather than a generic failure.
func TestLogin_TokenExchangeFailed(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid_grant", ErrorDescription: "code expired"})
	}))
	defer tokenServer.Close()

	callback := oidc.Callback{Host: "127.0.0.1", Port: freeLoopbackPort(t)}

	type outcome struct {
		result *LoginResult
		err    error
	}
	done := make(chan outcome, 1)

	go func() {
		result, err := Login(context.Background(), LoginOptions{
			Region:                "us-east-1",
			Callback:              callback,
			TokenEndpointOverride: tokenServer.URL,
			Timeout:               5 * time.Second,
		}, func(authURL string) {
			deliverCallback(t, callback, authURL, "test-code", "")
		})
		done <- outcome{result, err}
	}()

	select {
	case out := <-done:
		assert.ErrorIs(t, out.err, ErrTokenExchangeFailed)
		assert.Nil(t, out.result)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Login()")
	}
}

// TestLogin_Timeout proves Login gives up rather than blocking forever
// when no callback ever arrives.
func TestLogin_Timeout(t *testing.T) {
	callback := oidc.Callback{Host: "127.0.0.1", Port: freeLoopbackPort(t)}

	_, err := Login(context.Background(), LoginOptions{
		Region:   "us-east-1",
		Callback: callback,
		Timeout:  50 * time.Millisecond,
	}, nil)

	assert.ErrorIs(t, err, ErrLoginTimeout)
}

// --- handleLoginCallback ---

func TestHandleLoginCallback_DeliversCodeAndState(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	var state atomic.Value

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=auth-code&state=xyz", nil)

	handleLoginCallback(recorder, req, codeChan, errChan, &state)

	select {
	case code := <-codeChan:
		assert.Equal(t, "auth-code", code)
	default:
		t.Fatal("no authorization code delivered")
	}

	assert.Equal(t, "xyz", state.Load(),
		"the state parameter must be captured so CSRF can be checked")
	assert.Contains(t, recorder.Body.String(), "AWS Authentication Successful")
	assert.Equal(t, "text/html; charset=utf-8", recorder.Header().Get("Content-Type"))
}

func TestHandleLoginCallback_ReportsProviderError(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	var state atomic.Value

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?error=access_denied&error_description=user+declined", nil)

	handleLoginCallback(recorder, req, codeChan, errChan, &state)

	select {
	case err := <-errChan:
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrAuthorizationFailed))
		assert.Contains(t, err.Error(), "access_denied")
		assert.Contains(t, err.Error(), "user declined")
	default:
		t.Fatal("no error delivered")
	}

	assert.Contains(t, recorder.Body.String(), "AWS Authentication Failed")
	assert.Empty(t, codeChan, "an error response must not also deliver a code")
}

// TestHandleLoginCallback_ErrorPageIsInertUnderInjection proves a hostile
// error redirect reaches the browser as none of its markup, on a page
// served with the loopback security headers (#1013).
func TestHandleLoginCallback_ErrorPageIsInertUnderInjection(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	var state atomic.Value
	query := url.Values{
		"error":             {"<script>alert(1)</script>"},
		"error_description": {`"><img src=x onerror=alert(1)>`},
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?"+query.Encode(), nil)

	handleLoginCallback(recorder, req, codeChan, errChan, &state)

	body := recorder.Body.String()
	assert.Contains(t, body, "<h1>AWS Authentication Failed</h1>")
	assert.NotContains(t, body, "<script>")
	assert.NotContains(t, body, "<img")
	assert.NotContains(t, body, "alert(1)")
	assert.Equal(t, "text/html; charset=utf-8", recorder.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "default-src 'none'; style-src 'unsafe-inline'", recorder.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "no-referrer", recorder.Header().Get("Referrer-Policy"))

	select {
	case err := <-errChan:
		assert.ErrorIs(t, err, ErrAuthorizationFailed)
	default:
		t.Fatal("no error delivered")
	}
}

func TestHandleLoginCallback_RejectsMissingCode(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	var state atomic.Value

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)

	handleLoginCallback(recorder, req, codeChan, errChan, &state)

	select {
	case err := <-errChan:
		assert.ErrorIs(t, err, ErrNoAuthorizationCode)
	default:
		t.Fatal("no error delivered")
	}
	assert.Contains(t, recorder.Body.String(), "No authorization code received")
}

// --- RefreshCredentials ---

func TestRefreshCredentials_Success(t *testing.T) {
	tokenServer := newCredentialsTokenServer(t)
	defer tokenServer.Close()

	dpopKey, err := oidc.GenerateDPoPKey()
	require.NoError(t, err)

	client, err := NewClient(&ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: tokenServer.URL,
	}, dpopKey)
	require.NoError(t, err)

	tokenResp, nextRefreshToken, err := RefreshCredentials(context.Background(), client, "old-refresh-token")
	require.NoError(t, err)
	require.NotNil(t, tokenResp)
	assert.True(t, tokenResp.HasCredentials())
	assert.Equal(t, "refresh-abc", nextRefreshToken,
		"a rotated refresh token from the response must be what the caller persists next")
}

func TestRefreshCredentials_Failed(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid_grant", ErrorDescription: "refresh token revoked"})
	}))
	defer tokenServer.Close()

	dpopKey, err := oidc.GenerateDPoPKey()
	require.NoError(t, err)

	client, err := NewClient(&ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: tokenServer.URL,
	}, dpopKey)
	require.NoError(t, err)

	_, _, err = RefreshCredentials(context.Background(), client, "old-refresh-token")
	assert.ErrorIs(t, err, ErrRefreshFailed)
}

// hostileProviderText carries an OSC 52 clipboard write, a clear-screen
// CSI, an 8-bit CSI and a NUL between two words; sanitised it reads
// "deniedend".
const hostileProviderText = "denied\x1b]52;c;ZXZpbA==\x07\x1b[2J\u009b31m\x00end"

// TestHandleLoginCallback_ProviderErrorIsTerminalInert proves the callback's
// error and error_description reach the returned error sanitised, so a
// hostile redirect cannot drive the terminal the error is printed to
// (#1015).
func TestHandleLoginCallback_ProviderErrorIsTerminalInert(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	var state atomic.Value
	query := url.Values{"error": {hostileProviderText}, "error_description": {hostileProviderText}}

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?"+query.Encode(), nil)
	handleLoginCallback(httptest.NewRecorder(), req, codeChan, errChan, &state)

	select {
	case err := <-errChan:
		assert.ErrorIs(t, err, ErrAuthorizationFailed)
		assert.Equal(t, "aws: authorization failed: deniedend: deniedend", err.Error())
	default:
		t.Fatal("no error delivered")
	}
}

// TestClient_DoTokenRequest_ErrorDescriptionIsTerminalInert proves a hostile
// token endpoint's error_description, and its error code when the
// description is absent, reach the returned error sanitised (#1015).
func TestClient_DoTokenRequest_ErrorDescriptionIsTerminalInert(t *testing.T) {
	for name, body := range map[string]map[string]string{
		"description": {"error": "invalid_grant", "error_description": hostileProviderText},
		"code only":   {"error": hostileProviderText},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				assert.NoError(t, json.NewEncoder(w).Encode(body))
			}))
			defer server.Close()

			dpopKey, err := oidc.GenerateDPoPKey()
			require.NoError(t, err)
			client, err := NewClient(&ClientConfig{Region: "us-east-1", TokenEndpointOverride: server.URL}, dpopKey)
			require.NoError(t, err)

			_, err = client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
				State:        "test-state",
				CodeVerifier: "test-verifier-that-is-long-enough",
			})
			require.ErrorIs(t, err, ErrTokenRequestFailed)
			assert.Equal(t, "aws: token request failed: deniedend", err.Error())
		})
	}
}
