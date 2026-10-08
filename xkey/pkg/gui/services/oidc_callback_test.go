// Copyright (C) 2026 Jeremy Hahn
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
)

// TestOIDCService_Callback_DefaultsAndSetCallback proves the service starts
// on the built-in oidc defaults and that SetCallback replaces them, so the
// GUI login binds what the oidc section says (#140, item 8).
func TestOIDCService_Callback_DefaultsAndSetCallback(t *testing.T) {
	svc := NewOIDCService(nil)
	assert.Equal(t, oidc.Callback{Host: "localhost", Port: 8085}, svc.Callback())

	svc.SetCallback("127.0.0.1", 9090)
	assert.Equal(t, oidc.Callback{Host: "127.0.0.1", Port: 9090}, svc.Callback())
}

// TestOIDCService_AddProvider_DefaultRedirectFollowsTheCallback proves a
// provider added without a redirect URL is saved with the configured
// callback host and port, not a literal.
func TestOIDCService_AddProvider_DefaultRedirectFollowsTheCallback(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetCallback("127.0.0.1", 9090)
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{Name: "p", Issuer: "https://example.com", ClientID: "cid"}))

	p, err := svc.GetProvider("p")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:9090/callback", p.RedirectURL)
}

// discoveryIssuer serves an OIDC discovery document for the login flow.
func discoveryIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/jwks",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

// loginResult runs Login and returns its result, failing the test if the
// login is still waiting after a few seconds: the flows under test must
// fail at the bind, and a listener that came up somewhere else would
// otherwise sit in the five-minute callback wait.
func loginResult(t *testing.T, svc *OIDCService, provider string) *OIDCLoginResult {
	t.Helper()
	type outcome struct {
		result *OIDCLoginResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := svc.Login(provider)
		done <- outcome{result, err}
	}()
	select {
	case o := <-done:
		require.NoError(t, o.err)
		return o.result
	case <-time.After(10 * time.Second):
		t.Fatal("login did not fail at the bind: the listener came up on an address other than the configured one")
		return nil
	}
}

// TestOIDCService_Login_BindsTheConfiguredCallbackHost proves, through the
// real login flow up to the listener, that the GUI callback server binds the
// configured host on the redirect URL's port: with that loopback port taken,
// the login fails naming exactly that address, where main bound ":<port>"
// on every interface with SO_REUSEADDR.
func TestOIDCService_Login_BindsTheConfiguredCallbackHost(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = taken.Close() })
	port := taken.Addr().(*net.TCPAddr).Port

	svc := NewOIDCService(nil)
	svc.browserOpen = func(string) error { return nil }
	svc.SetCallback("127.0.0.1", port)
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{Name: "p", Issuer: discoveryIssuer(t).URL, ClientID: "cid", Scopes: []string{"openid"}}))

	result := loginResult(t, svc, "p")
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "failed to start callback server")
	assert.Contains(t, result.Error, "127.0.0.1:"+strconv.Itoa(port))
}

// TestOIDCService_Login_RefusesAHostThatCannotServeTheRedirect proves that a
// callback host the browser would never reach for the provider's redirect
// URL fails the login before any browser opens, with the typed reason.
func TestOIDCService_Login_RefusesAHostThatCannotServeTheRedirect(t *testing.T) {
	svc := NewOIDCService(nil)
	opened := false
	svc.browserOpen = func(string) error { opened = true; return nil }
	svc.SetCallback("10.0.0.5", 8085)
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name: "p", Issuer: discoveryIssuer(t).URL, ClientID: "cid", Scopes: []string{"openid"},
		RedirectURL: "http://localhost:8085/callback",
	}))

	result := loginResult(t, svc, "p")
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "cannot serve the redirect host localhost")
	assert.False(t, opened, "no browser may open before the refusal")
}

// TestOIDCService_Login_AnswersOnTheRedirectURLPath proves end to end that
// the GUI callback handler answers exactly the provider's redirect path, not
// a fixed one and not a pattern: the authorization URL carries that redirect
// URI, requests to a subtree, sibling or root get 404 without ending the
// login, and a request to exactly that address and path ends it.
func TestOIDCService_Login_AnswersOnTheRedirectURLPath(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	require.NoError(t, probe.Close())
	redirect := "http://127.0.0.1:" + port + "/oauth/callback"

	svc := NewOIDCService(nil)
	var authURL atomic.Value
	svc.browserOpen = func(u string) error { authURL.Store(u); return nil }
	svc.SetCallback("127.0.0.1", 8085)
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name: "p", Issuer: discoveryIssuer(t).URL, ClientID: "cid", Scopes: []string{"openid"}, RedirectURL: redirect,
	}))

	done := make(chan *OIDCLoginResult, 1)
	go func() {
		result, loginErr := svc.Login("p")
		require.NoError(t, loginErr)
		done <- result
	}()

	require.Eventually(t, func() bool {
		return authURL.Load() != nil
	}, 10*time.Second, 20*time.Millisecond, "the browser was never opened")
	assert.Contains(t, authURL.Load().(string), "redirect_uri=http%3A%2F%2F127.0.0.1%3A"+port+"%2Foauth%2Fcallback")

	for _, other := range []string{"/oauth/callback/", "/oauth/callback/x", "/oauth/other", "/"} {
		stray, err := http.Get("http://127.0.0.1:" + port + other + "?error=access_denied")
		require.NoError(t, err)
		require.NoError(t, stray.Body.Close())
		require.Equal(t, http.StatusNotFound, stray.StatusCode, "%s must not reach the callback handler", other)
	}
	select {
	case result := <-done:
		t.Fatalf("a request to another path ended the login: %+v", result)
	case <-time.After(200 * time.Millisecond):
	}

	resp, err := http.Get(redirect + "?error=access_denied&error_description=declined")
	require.NoError(t, err, "the redirect address must be served by the listener")
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, "the handler must answer on the redirect path, not 404")

	select {
	case result := <-done:
		require.False(t, result.Success)
		assert.True(t, strings.Contains(result.Error, "access_denied") || strings.Contains(result.Error, "declined"), result.Error)
	case <-time.After(10 * time.Second):
		t.Fatal("the callback did not end the login")
	}
}

// TestOIDCService_Login_CallbackErrorPageIsInertUnderInjection proves the
// GUI's callback listener answers a hostile error redirect with a page that
// carries none of its markup and the loopback security headers, while the
// login still ends with the provider's error (#1013).
func TestOIDCService_Login_CallbackErrorPageIsInertUnderInjection(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	require.NoError(t, probe.Close())
	redirect := "http://127.0.0.1:" + port + "/callback"

	svc := NewOIDCService(nil)
	var authURL atomic.Value
	svc.browserOpen = func(u string) error { authURL.Store(u); return nil }
	svc.SetCallback("127.0.0.1", 8085)
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name: "p", Issuer: discoveryIssuer(t).URL, ClientID: "cid", Scopes: []string{"openid"}, RedirectURL: redirect,
	}))

	type loginOutcome struct {
		result *OIDCLoginResult
		err    error
	}
	done := make(chan loginOutcome, 1)
	go func() {
		result, loginErr := svc.Login("p")
		done <- loginOutcome{result: result, err: loginErr}
	}()

	require.Eventually(t, func() bool {
		return authURL.Load() != nil
	}, 10*time.Second, 20*time.Millisecond, "the browser was never opened")

	query := url.Values{
		"error":             {"<script>alert(1)</script>"},
		"error_description": {`"><img src=x onerror=alert(1)>`},
	}
	resp, err := http.Get(redirect + "?" + query.Encode())
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "<h1>Authentication Failed</h1>")
	assert.NotContains(t, string(body), "<script>")
	assert.NotContains(t, string(body), "<img")
	assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "default-src 'none'; style-src 'unsafe-inline'", resp.Header.Get("Content-Security-Policy"))
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))

	select {
	case outcome := <-done:
		require.NoError(t, outcome.err)
		require.False(t, outcome.result.Success)
		assert.Contains(t, outcome.result.Error, "<script>alert(1)</script>")
	case <-time.After(10 * time.Second):
		t.Fatal("the callback did not end the login")
	}
}

// TestOIDCService_Login_FailsClosedWhenTheCallbackConfigIsUnavailable proves
// that a configuration the app could not load is not silently replaced by
// the built-in callback: Login refuses with the cause before discovery or
// any browser, and a later SetCallback clears the refusal.
func TestOIDCService_Login_FailsClosedWhenTheCallbackConfigIsUnavailable(t *testing.T) {
	svc := NewOIDCService(nil)
	opened := false
	svc.browserOpen = func(string) error { opened = true; return nil }
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{Name: "p", Issuer: "https://issuer.invalid", ClientID: "cid", Scopes: []string{"openid"}}))

	svc.SetCallbackUnavailable(errors.New("config: oidc.callback_port must be between 1 and 65535, got 70000"))
	result, err := svc.Login("p")
	require.NoError(t, err)
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "OIDC callback configuration unavailable")
	assert.Contains(t, result.Error, "70000")
	assert.False(t, opened, "no browser may open while the callback configuration is unavailable")
	assert.Equal(t, oidc.Callback{Host: "localhost", Port: 8085}, svc.Callback(), "the built-in callback is kept but not used for login")

	svc.SetCallback("127.0.0.1", 9090)
	assert.NoError(t, svc.callbackReady(), "SetCallback clears the refusal")
}

// hostileProviderText carries an OSC 52 clipboard write, a clear-screen
// CSI, an 8-bit CSI and a NUL between two words; sanitised it reads
// "deniedend".
const hostileProviderText = "denied\x1b]52;c;ZXZpbA==\x07\x1b[2J\u009b31m\x00end"

// TestOIDCService_Login_CallbackErrorIsTerminalInert proves the callback's
// error and error_description reach the login result, and the log line the
// service writes, sanitised (#1015).
func TestOIDCService_Login_CallbackErrorIsTerminalInert(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	require.NoError(t, probe.Close())
	redirect := "http://127.0.0.1:" + port + "/callback"

	var logs bytes.Buffer
	svc := NewOIDCService(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	var authURL atomic.Value
	svc.browserOpen = func(u string) error { authURL.Store(u); return nil }
	svc.SetCallback("127.0.0.1", 8085)
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name: "p", Issuer: discoveryIssuer(t).URL, ClientID: "cid", Scopes: []string{"openid"}, RedirectURL: redirect,
	}))

	type loginOutcome struct {
		result *OIDCLoginResult
		err    error
	}
	done := make(chan loginOutcome, 1)
	go func() {
		result, loginErr := svc.Login("p")
		done <- loginOutcome{result: result, err: loginErr}
	}()
	require.Eventually(t, func() bool {
		return authURL.Load() != nil
	}, 10*time.Second, 20*time.Millisecond, "the browser was never opened")

	query := url.Values{"error": {hostileProviderText}, "error_description": {hostileProviderText}}
	resp, err := http.Get(redirect + "?" + query.Encode())
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	select {
	case outcome := <-done:
		require.NoError(t, outcome.err)
		require.False(t, outcome.result.Success)
		assert.Equal(t, "deniedend: deniedend", outcome.result.Error)
	case <-time.After(10 * time.Second):
		t.Fatal("the callback did not end the login")
	}
	assert.Contains(t, logs.String(), "deniedend: deniedend")
	assert.NotContains(t, logs.String(), "ZXZpbA==")
}

// TestOIDCService_RefreshToken_TokenEndpointErrorIsTerminalInert proves a
// hostile token endpoint's error_description reaches the refresh error
// sanitised (#1015).
func TestOIDCService_RefreshToken_TokenEndpointErrorIsTerminalInert(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"jwks_uri":               server.URL + "/jwks",
			}))
		case "/token":
			w.WriteHeader(http.StatusBadRequest)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": hostileProviderText,
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	svc := NewOIDCService(nil)
	store := newTestOIDCTokenStore(t)
	svc.SetTokenStore(store)
	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{Name: "p", Issuer: server.URL, ClientID: "cid"}))
	require.NoError(t, store.Save(server.URL, &oidc.TokenResponse{AccessToken: "at", RefreshToken: "rt"}))

	_, err := svc.RefreshToken("p")
	require.ErrorIs(t, err, ErrOIDCRefreshFailed)
	assert.True(t, strings.HasSuffix(err.Error(), ": deniedend"), err.Error())
	assert.NotContains(t, err.Error(), "\x1b")
	assert.NotContains(t, err.Error(), "ZXZpbA==")
}
