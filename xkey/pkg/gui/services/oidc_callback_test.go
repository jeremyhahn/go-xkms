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
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
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
