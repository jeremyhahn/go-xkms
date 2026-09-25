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

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
)

// withLoadedConfig installs cfg as the loaded configuration for the test.
func withLoadedConfig(t *testing.T, cfg *xkeyconfig.Config) {
	t.Helper()
	previous := loadedConfig
	loadedConfig = cfg
	t.Cleanup(func() { loadedConfig = previous })
}

// callbackTestCmd returns a command carrying the callback flags.
func callbackTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "callback-test"}
	registerOIDCCallbackFlags(cmd.Flags())
	return cmd
}

// mustResolve resolves the callback for cmd, failing the test on error.
func mustResolve(t *testing.T, cmd *cobra.Command) oidc.Callback {
	t.Helper()
	callback, err := resolveOIDCCallback(cmd)
	require.NoError(t, err)
	return callback
}

// TestResolveOIDCCallback_ConfigurationThenFlags proves the precedence: the
// built-in defaults when nothing is loaded, the loaded oidc section when it
// is, and --callback-host / --callback-port over the section when set
// (#140, items 7 and 13).
func TestResolveOIDCCallback_ConfigurationThenFlags(t *testing.T) {
	withLoadedConfig(t, nil)
	assert.Equal(t, oidc.Callback{Host: "localhost", Port: 8085}, mustResolve(t, callbackTestCmd()))

	cfg := xkeyconfig.DefaultConfig()
	cfg.OIDC.CallbackHost = "10.0.0.5"
	cfg.OIDC.CallbackPort = 9090
	withLoadedConfig(t, cfg)
	assert.Equal(t, oidc.Callback{Host: "10.0.0.5", Port: 9090}, mustResolve(t, callbackTestCmd()))

	cmd := callbackTestCmd()
	require.NoError(t, cmd.Flags().Set("callback-host", "::1"))
	assert.Equal(t, oidc.Callback{Host: "::1", Port: 9090}, mustResolve(t, cmd), "the host flag overrides the section, the port keeps the section")

	require.NoError(t, cmd.Flags().Set("callback-port", "9191"))
	assert.Equal(t, oidc.Callback{Host: "::1", Port: 9191}, mustResolve(t, cmd))
}

// TestResolveOIDCCallback_RejectsAPortOutsideTheRange proves that an explicit
// --callback-port is held to the same 1-65535 bound as oidc.callback_port,
// with a typed error naming the value, and that the bounds are accepted.
func TestResolveOIDCCallback_RejectsAPortOutsideTheRange(t *testing.T) {
	withLoadedConfig(t, nil)
	for _, value := range []string{"0", "-1", "65536"} {
		cmd := callbackTestCmd()
		require.NoError(t, cmd.Flags().Set("callback-port", value))
		callback, err := resolveOIDCCallback(cmd)
		require.Error(t, err, "port %s", value)
		var portErr *OIDCCallbackPortError
		require.True(t, errors.As(err, &portErr))
		assert.Equal(t, value, portErr.Value)
		assert.Contains(t, err.Error(), value)
		assert.Equal(t, oidc.Callback{}, callback)
	}
	for _, value := range []string{"1", "65535"} {
		cmd := callbackTestCmd()
		require.NoError(t, cmd.Flags().Set("callback-port", value))
		require.NoError(t, cmd.Flags().Set("callback-port", value))
		callback := mustResolve(t, cmd)
		assert.Equal(t, value, strconv.Itoa(callback.Port))
	}
}

// TestResolveOIDCCallback_ToleratesCommandsWithoutTheFlags proves that a
// command that never registered the flags still resolves the configured
// section, so the background workers and provider paths need no flags.
func TestResolveOIDCCallback_ToleratesCommandsWithoutTheFlags(t *testing.T) {
	cfg := xkeyconfig.DefaultConfig()
	cfg.OIDC.CallbackPort = 7777
	withLoadedConfig(t, cfg)
	assert.Equal(t, oidc.Callback{Host: "localhost", Port: 7777}, mustResolve(t, &cobra.Command{Use: "bare"}))
}

// freeLoopbackPort returns a loopback port that is currently free.
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	return port
}

// occupyLoopbackPort binds a loopback port for the test and returns it.
func occupyLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().(*net.TCPAddr).Port
}

// loginError runs login and returns its error, failing the test if login is
// still running after a few seconds: the flows under test must fail at the
// bind, and a listener that came up somewhere else would otherwise sit in
// the five-minute callback wait.
func loginError(t *testing.T, login func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- login() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("login did not fail at the bind: the listener came up on an address other than the configured one")
		return nil
	}
}

// fakeIssuer serves an OIDC discovery document for the login flow.
func fakeIssuer(t *testing.T) *httptest.Server {
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

// oidcLoginTestCmd returns a login command with the flags runOIDCLogin reads.
func oidcLoginTestCmd(t *testing.T, issuer string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	cmd, buf, _ := oidcTestCmd(t)
	registerOIDCCallbackFlags(cmd.Flags())
	cmd.Flags().Bool("no-browser", false, "")
	setOIDCFlags(t, cmd, map[string]string{
		"issuer":     issuer,
		"client-id":  "client",
		"no-browser": "true",
		"scopes":     "openid",
	})
	return cmd, buf
}

// TestRunOIDCLogin_BindsTheConfiguredCallbackHostAndPort proves, through the
// real login flow up to the listener, that the callback server binds
// oidc.callback_host (localhost: the loopback pair, IPv4 required) on the
// default redirect URL's port: with that loopback port already taken, the
// login fails naming exactly that address, where main bound ":<port>" on
// every interface (#140, item 7).
func TestRunOIDCLogin_BindsTheConfiguredCallbackHostAndPort(t *testing.T) {
	withLoadedConfig(t, nil)
	port := occupyLoopbackPort(t)
	cmd, _ := oidcLoginTestCmd(t, fakeIssuer(t).URL)
	require.NoError(t, cmd.Flags().Set("callback-port", strconv.Itoa(port)))

	err := loginError(t, func() error { return runOIDCLogin(cmd, nil) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start callback server")
	assert.Contains(t, err.Error(), "127.0.0.1:"+strconv.Itoa(port))
}

// TestRunOIDCLogin_ExplicitRedirectURLKeepsItsPort proves that an explicit
// --redirect-url decides the port the listener serves, since that URL is the
// one registered with the provider, while the host is still configuration.
func TestRunOIDCLogin_ExplicitRedirectURLKeepsItsPort(t *testing.T) {
	cfg := xkeyconfig.DefaultConfig()
	cfg.OIDC.CallbackPort = 1
	withLoadedConfig(t, cfg)
	port := occupyLoopbackPort(t)
	cmd, _ := oidcLoginTestCmd(t, fakeIssuer(t).URL)
	require.NoError(t, cmd.Flags().Set("redirect-url", "http://localhost:"+strconv.Itoa(port)+"/callback"))

	err := loginError(t, func() error { return runOIDCLogin(cmd, nil) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "127.0.0.1:"+strconv.Itoa(port))
}

// lockedBuffer is a bytes.Buffer safe to read while the login goroutine
// writes to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRunOIDCLogin_GeneratedRedirectReachesTheListener proves end to end
// that with a non-loopback-name callback host the browser is sent to the
// host the listener serves: the printed authorization URL carries
// redirect_uri=http://127.0.0.1:<port>/callback, and a request to exactly
// that address reaches the callback handler, which ends the login.
func TestRunOIDCLogin_GeneratedRedirectReachesTheListener(t *testing.T) {
	withLoadedConfig(t, nil)
	port := freeLoopbackPort(t)
	cmd, _, _ := oidcTestCmd(t)
	registerOIDCCallbackFlags(cmd.Flags())
	cmd.Flags().Bool("no-browser", false, "")
	out := &lockedBuffer{}
	cmd.SetOut(out)
	setOIDCFlags(t, cmd, map[string]string{
		"issuer":        fakeIssuer(t).URL,
		"client-id":     "client",
		"no-browser":    "true",
		"scopes":        "openid",
		"callback-host": "127.0.0.1",
		"callback-port": port,
	})

	done := make(chan error, 1)
	go func() { done <- runOIDCLogin(cmd, nil) }()

	wantRedirect := "redirect_uri=http%3A%2F%2F127.0.0.1%3A" + port + "%2Fcallback"
	require.Eventually(t, func() bool {
		return strings.Contains(out.String(), wantRedirect)
	}, 10*time.Second, 20*time.Millisecond, "the authorization URL never carried %s; output:\n%s", wantRedirect, out.String())

	resp, err := http.Get("http://127.0.0.1:" + port + "/callback?error=access_denied&error_description=declined")
	require.NoError(t, err, "the redirect host must be served by the listener")
	require.NoError(t, resp.Body.Close())

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
	case <-time.After(10 * time.Second):
		t.Fatal("the callback did not end the login")
	}
}

// TestRunOIDCLogin_RejectsAnInvalidCallbackPortFlag proves that an explicit
// --callback-port outside the range stops the login before discovery.
func TestRunOIDCLogin_RejectsAnInvalidCallbackPortFlag(t *testing.T) {
	withLoadedConfig(t, nil)
	cmd, _ := oidcLoginTestCmd(t, "http://127.0.0.1:1")
	require.NoError(t, cmd.Flags().Set("callback-port", "0"))

	err := runOIDCLogin(cmd, nil)
	var portErr *OIDCCallbackPortError
	require.True(t, errors.As(err, &portErr), "got %T: %v", err, err)
}

// TestRunOIDCLogin_RejectsAnUnservableRedirectURL proves that a redirect URL
// the listener cannot serve, an https one included, stops the flow before
// any browser is opened, and that a callback host that cannot serve the
// redirect host does the same.
func TestRunOIDCLogin_RejectsAnUnservableRedirectURL(t *testing.T) {
	withLoadedConfig(t, nil)
	for _, redirect := range []string{"ftp://localhost/callback", "https://localhost:8443/callback"} {
		cmd, _ := oidcLoginTestCmd(t, fakeIssuer(t).URL)
		require.NoError(t, cmd.Flags().Set("redirect-url", redirect))
		err := runOIDCLogin(cmd, nil)
		var redirectErr *oidc.RedirectURLError
		require.True(t, errors.As(err, &redirectErr), "%s: got %T: %v", redirect, err, err)
	}

	cmd, out := oidcLoginTestCmd(t, fakeIssuer(t).URL)
	require.NoError(t, cmd.Flags().Set("callback-host", "10.0.0.5"))
	require.NoError(t, cmd.Flags().Set("redirect-url", "http://localhost:8085/callback"))
	err := runOIDCLogin(cmd, nil)
	var hostErr *oidc.CallbackHostError
	require.True(t, errors.As(err, &hostErr), "got %T: %v", err, err)
	assert.NotContains(t, out.String(), "redirect_uri", "no authorization URL may be shown before the refusal")
}

// TestRunAWSLogin_BindsTheConfiguredCallbackHostAndPort proves the same for
// the AWS flow: the listener binds the configured host on the AWS redirect
// URL's port, which is oidc.callback_port rather than a literal 8085 (#140,
// item 13).
func TestRunAWSLogin_BindsTheConfiguredCallbackHostAndPort(t *testing.T) {
	port := occupyLoopbackPort(t)
	dir := t.TempDir()
	var buf bytes.Buffer
	err := loginError(t, func() error {
		return runAWSLogin(&buf, "us-east-1", "default", false, true, "none",
			filepath.Join(dir, "credentials"), "", 0, filepath.Join(dir, "session.json"), false, "", "",
			oidc.Callback{Host: "127.0.0.1", Port: port})
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws: login failed")
	assert.Contains(t, err.Error(), "127.0.0.1:"+strconv.Itoa(port))
}

// TestRunAWSLogin_RefusesAHostThatCannotServeTheAWSRedirect proves that a
// callback host AWS's fixed 127.0.0.1 redirect cannot reach stops the flow
// before any browser opens, with the typed error.
func TestRunAWSLogin_RefusesAHostThatCannotServeTheAWSRedirect(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	err := loginError(t, func() error {
		return runAWSLogin(&buf, "us-east-1", "default", false, true, "none",
			filepath.Join(dir, "credentials"), "", 0, filepath.Join(dir, "session.json"), false, "", "",
			oidc.Callback{Host: "::1", Port: 8085})
	})
	var hostErr *oidc.CallbackHostError
	require.True(t, errors.As(err, &hostErr), "got %T: %v", err, err)
	assert.NotContains(t, buf.String(), "http", "no authorization URL may be shown before the refusal")
}

// TestRunOIDCProvidersAdd_DefaultsTheRedirectURLFromTheCallbackPort proves
// that a provider added without --redirect-url is saved with the configured
// callback port, not a literal 8085.
func TestRunOIDCProvidersAdd_DefaultsTheRedirectURLFromTheCallbackPort(t *testing.T) {
	cfg := xkeyconfig.DefaultConfig()
	cfg.OIDC.CallbackPort = 9090
	withLoadedConfig(t, cfg)

	cmd, _, store := oidcTestCmd(t)
	registerOIDCCallbackFlags(cmd.Flags())
	setOIDCFlags(t, cmd, map[string]string{
		"name":      "okta",
		"issuer":    "https://example.okta.com",
		"client-id": "abc123",
	})
	require.NoError(t, runOIDCProvidersAdd(cmd, nil))

	config, err := loadOIDCConfig(getConfigPath(store))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)
	assert.Equal(t, "http://localhost:9090/callback", config.Providers[0].RedirectURL)
}

// TestRunOIDCLogin_AnswersOnTheRedirectURLPath proves the CLI callback
// handler answers exactly the redirect URL's path: with an explicit
// --redirect-url on a provider-specific path, the authorization URL carries
// it, requests to a subtree, sibling or root get 404 without ending the
// login, and a request to exactly that path ends it.
func TestRunOIDCLogin_AnswersOnTheRedirectURLPath(t *testing.T) {
	withLoadedConfig(t, nil)
	port := freeLoopbackPort(t)
	cmd, _, _ := oidcTestCmd(t)
	registerOIDCCallbackFlags(cmd.Flags())
	cmd.Flags().Bool("no-browser", false, "")
	out := &lockedBuffer{}
	cmd.SetOut(out)
	setOIDCFlags(t, cmd, map[string]string{
		"issuer":       fakeIssuer(t).URL,
		"client-id":    "client",
		"no-browser":   "true",
		"scopes":       "openid",
		"redirect-url": "http://127.0.0.1:" + port + "/oauth/cb",
	})

	done := make(chan error, 1)
	go func() { done <- runOIDCLogin(cmd, nil) }()

	wantRedirect := "redirect_uri=http%3A%2F%2F127.0.0.1%3A" + port + "%2Foauth%2Fcb"
	require.Eventually(t, func() bool {
		return strings.Contains(out.String(), wantRedirect)
	}, 10*time.Second, 20*time.Millisecond, "the authorization URL never carried %s; output:\n%s", wantRedirect, out.String())

	for _, other := range []string{"/oauth/cb/", "/oauth/cb/x", "/oauth/other", "/"} {
		stray, err := http.Get("http://127.0.0.1:" + port + other + "?error=access_denied")
		require.NoError(t, err)
		require.NoError(t, stray.Body.Close())
		require.Equal(t, http.StatusNotFound, stray.StatusCode, "%s must not reach the callback handler", other)
	}
	select {
	case err := <-done:
		t.Fatalf("a request to another path ended the login: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	resp, err := http.Get("http://127.0.0.1:" + port + "/oauth/cb?error=access_denied&error_description=declined")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, "the handler must answer on the redirect path, not 404")

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
	case <-time.After(10 * time.Second):
		t.Fatal("the callback did not end the login")
	}
}
