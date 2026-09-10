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

package oidc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCallback_RedirectURLs proves the default OIDC redirect URL sends
// the browser to a host the listener serves: localhost for the loopback pair
// and the every-interface host, the callback host itself otherwise (IPv6
// bracketed); and that the AWS redirect keeps its fixed host with the
// configured port.
func TestCallback_RedirectURLs(t *testing.T) {
	for host, want := range map[string]string{
		"localhost": "http://localhost:9090/callback",
		"":          "http://localhost:9090/callback",
		"127.0.0.1": "http://127.0.0.1:9090/callback",
		"10.0.0.5":  "http://10.0.0.5:9090/callback",
		"::1":       "http://[::1]:9090/callback",
	} {
		assert.Equal(t, want, Callback{Host: host, Port: 9090}.RedirectURL(), "host %q", host)
	}
	assert.Equal(t, "http://127.0.0.1:9090/oauth/callback", Callback{Host: "10.0.0.5", Port: 9090}.AWSRedirectURL())
}

// TestCallback_ListenAddrs proves the listener binds, on the redirect
// URL's port, addresses that serve the redirect URL's host: the loopback
// pair for a localhost redirect, the literal for an IP redirect, the
// configured address for a named redirect, every interface for an empty
// callback host; and that the port comes from the redirect URL.
func TestCallback_ListenAddrs(t *testing.T) {
	pair := func(port string) []CallbackAddr { return LoopbackPair(port) }
	cases := []struct {
		name     string
		host     string
		redirect string
		want     []CallbackAddr
	}{
		{"localhost redirect, localhost host: loopback pair", "localhost", "http://localhost:8085/callback", pair("8085")},
		{"localhost redirect, loopback address host: loopback pair", "127.0.0.1", "http://localhost:8085/callback", pair("8085")},
		{"localhost redirect, ipv6 loopback host: loopback pair", "::1", "http://localhost:8085/callback", pair("8085")},
		{"redirect port wins over the callback port", "localhost", "http://localhost:9000/callback", pair("9000")},
		{"http default port", "localhost", "http://localhost/callback", pair("80")},
		{"ip redirect, same host", "10.0.0.5", "http://10.0.0.5:8085/callback", []CallbackAddr{{Addr: "10.0.0.5:8085"}}},
		{"ipv6 redirect, same host, bracketed", "fd00::1", "http://[fd00::1]:8085/callback", []CallbackAddr{{Addr: "[fd00::1]:8085"}}},
		{"loopback ip redirect, localhost host", "localhost", "http://127.0.0.1:9000/callback", []CallbackAddr{{Addr: "127.0.0.1:9000"}}},
		{"named redirect, configured address", "10.0.0.5", "http://callbacks.example.com:8085/callback", []CallbackAddr{{Addr: "10.0.0.5:8085"}}},
		{"empty host binds every interface for any redirect", "", "http://callbacks.example.com:8085/callback", []CallbackAddr{{Addr: ":8085"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Callback{Host: tc.host, Port: 8085}.ListenAddrs(tc.redirect)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.Addrs)
			assert.Equal(t, "/callback", got.Path)
		})
	}
}

// TestCallback_ListenAddrs_RefusesHostsThatCannotServeTheRedirect proves
// that a callback host the browser would never reach for the redirect URL's
// host is a typed refusal naming both hosts, before any browser opens.
func TestCallback_ListenAddrs_RefusesHostsThatCannotServeTheRedirect(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		redirect string
	}{
		{"localhost redirect from a lan address", "10.0.0.5", "http://localhost:8085/callback"},
		{"ip redirect from localhost", "localhost", "http://10.0.0.5:8085/callback"},
		{"ip redirect from another address", "10.0.0.6", "http://10.0.0.5:8085/callback"},
		{"named redirect from localhost", "localhost", "http://callbacks.example.com:8085/callback"},
		{"named redirect from a loopback address", "127.0.0.1", "http://callbacks.example.com:8085/callback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Callback{Host: tc.host, Port: 8085}.ListenAddrs(tc.redirect)
			require.Error(t, err)
			assert.Equal(t, Listener{}, got)
			var hostErr *CallbackHostError
			require.True(t, errors.As(err, &hostErr))
			assert.Equal(t, tc.host, hostErr.Host)
			assert.Contains(t, err.Error(), tc.host)
			assert.Contains(t, err.Error(), hostErr.RedirectHost)
		})
	}
}

// TestCallback_ListenAddrs_RejectsUnservableRedirects proves that a
// redirect URL that does not parse, names no host, or is not plain http (the
// listener cannot answer TLS) is a typed error naming the URL.
func TestCallback_ListenAddrs_RejectsUnservableRedirects(t *testing.T) {
	for _, redirect := range []string{
		"://broken", "ftp://localhost/callback", "localhost/callback",
		"https://localhost:8443/callback", "https://localhost/callback", "http:///callback",
	} {
		t.Run(redirect, func(t *testing.T) {
			got, err := Callback{Host: "localhost", Port: 8085}.ListenAddrs(redirect)
			require.Error(t, err)
			assert.Equal(t, Listener{}, got)
			var redirectErr *RedirectURLError
			require.True(t, errors.As(err, &redirectErr))
			assert.Equal(t, redirect, redirectErr.URL)
			assert.Contains(t, err.Error(), redirect)
		})
	}
}

// TestCallback_AWSListenAddrs proves that the AWS listener always serves
// the fixed 127.0.0.1 redirect host: localhost and 127.0.0.1 bind it, an
// empty host binds every interface, and any other host is a typed refusal
// naming both hosts, before a browser could be sent somewhere unserved.
func TestCallback_AWSListenAddrs(t *testing.T) {
	for host, want := range map[string]string{"localhost": "127.0.0.1:8085", "127.0.0.1": "127.0.0.1:8085", "": ":8085"} {
		got, err := Callback{Host: host, Port: 8085}.AWSListenAddrs()
		require.NoError(t, err, "host %q", host)
		assert.Equal(t, Listener{Addrs: []CallbackAddr{{Addr: want}}, Path: "/oauth/callback"}, got, "host %q", host)
	}
	for _, host := range []string{"::1", "10.0.0.5", "callbacks.example.com"} {
		got, err := Callback{Host: host, Port: 8085}.AWSListenAddrs()
		require.Error(t, err, "host %q", host)
		assert.Equal(t, Listener{}, got)
		var hostErr *CallbackHostError
		require.True(t, errors.As(err, &hostErr))
		assert.Equal(t, host, hostErr.Host)
		assert.Equal(t, "127.0.0.1", hostErr.RedirectHost)
		assert.Contains(t, err.Error(), host)
	}
}

// TestBindCallback_LoopbackPair proves the loopback pair binds and serves on
// both families where available, and that a taken required address fails
// the bind and releases the optional one that was already opened.
func TestBindCallback_LoopbackPair(t *testing.T) {
	port := strconv.Itoa(occupyLoopbackPort(t))
	free := freeLoopbackPort(t)

	listeners, err := BindCallback(context.Background(), nil, []CallbackAddr{{Addr: "127.0.0.1:" + free}, {Addr: "[::1]:" + free, Optional: true}})
	require.NoError(t, err)
	require.NotEmpty(t, listeners)
	for _, listener := range listeners {
		require.NoError(t, listener.Close())
	}

	listeners, err = BindCallback(context.Background(), nil, []CallbackAddr{{Addr: "[::1]:" + free, Optional: true}, {Addr: "127.0.0.1:" + port}})
	require.Error(t, err)
	assert.Nil(t, listeners)
	assert.Contains(t, err.Error(), "127.0.0.1:"+port)
	released, err := net.Listen("tcp", "127.0.0.1:"+free)
	require.NoError(t, err, "the optional listener must be released when the required bind fails")
	require.NoError(t, released.Close())
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

// TestCallback_ListenAddrs_PathFollowsTheRedirectURL proves the handler path
// comes from the redirect URL, so a provider registered with any path is
// answered there: the default, a provider-specific path, and "/" for a URL
// with no path.
func TestCallback_ListenAddrs_PathFollowsTheRedirectURL(t *testing.T) {
	for redirect, want := range map[string]string{
		"http://localhost:8085/callback":       "/callback",
		"http://localhost:8085/oauth/callback": "/oauth/callback",
		"http://localhost:8085/auth/cb/":       "/auth/cb/",
		"http://localhost:8085":                "/",
	} {
		got, err := Callback{Host: "localhost", Port: 8085}.ListenAddrs(redirect)
		require.NoError(t, err, redirect)
		assert.Equal(t, want, got.Path, redirect)
	}
}

// TestExactPathHandler_ServesOnlyTheExactPath proves the callback handler
// answers exactly the redirect path: a subpath, a sibling, the path with a
// trailing slash, and a wildcard-looking path get 404 rather than a match,
// and a path that a ServeMux pattern would reject registers fine.
func TestExactPathHandler_ServesOnlyTheExactPath(t *testing.T) {
	for _, path := range []string{"/oauth/callback", "/oauth/callback/", "/oauth/{cb}", "/"} {
		served := 0
		h := ExactPathHandler(path, func(w http.ResponseWriter, _ *http.Request) { served++; w.WriteHeader(http.StatusOK) })
		mux := http.NewServeMux()
		mux.Handle("/", h)

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+"?error=access_denied", nil))
		assert.Equal(t, http.StatusOK, rec.Code, "exact %q", path)
		assert.Equal(t, 1, served, "exact %q", path)

		for _, other := range []string{path + "x", "/other", "/oauth/callback/more", "/oauth/anything"} {
			if other == path {
				continue
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, other+"?error=access_denied", nil))
			assert.Equal(t, http.StatusNotFound, rec.Code, "%q must not reach the handler for %q", other, path)
		}
		assert.Equal(t, 1, served, "only the exact path may reach the handler for %q", path)
	}
}
