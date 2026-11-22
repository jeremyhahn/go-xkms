// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const sdkCORSOrigin = "https://app.example"

// TestServiceModule_CORSThroughSDK: a host that builds the module through
// this SDK alone can enable the cross-origin policy, and the module then
// answers a browser preflight from an allowed origin with the CORS headers
// and gives a disallowed origin none.
func TestServiceModule_CORSThroughSDK(t *testing.T) {
	module, err := NewServiceModule(func() *pkgxkms.XKMSService { return nil },
		WithServiceModuleCORS(&ServiceModuleCORSOptions{
			AllowedOrigins:   []string{sdkCORSOrigin},
			AllowCredentials: true,
		}))
	require.NoError(t, err)

	mux := chi.NewRouter()
	gate := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	module.RegisterHTTP(qrdbserver.NewModuleHTTPRegistrar(mux,
		func(method, pattern string, _ qrdbsdk.Permission, _ http.HandlerFunc) {
			mux.MethodFunc(method, pattern, gate)
		},
		func(method, pattern string, h http.HandlerFunc) { mux.MethodFunc(method, pattern, h) },
		func(method, pattern string, h http.HandlerFunc) { mux.MethodFunc(method, pattern, h) }))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var path string
	for _, spec := range rest.Routes() {
		if spec.Method == http.MethodPost && spec.Auth == rest.RouteAuthPublic &&
			strings.Contains(spec.Pattern, "webauthn") && !strings.Contains(spec.Pattern, "{") {
			path = spec.Pattern
			break
		}
	}
	require.NotEmpty(t, path, "no public webauthn POST route")

	preflight := func(origin string) *http.Response {
		req, err := http.NewRequest(http.MethodOptions, srv.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp
	}

	ok := preflight(sdkCORSOrigin)
	assert.Equal(t, http.StatusNoContent, ok.StatusCode)
	assert.Equal(t, sdkCORSOrigin, ok.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", ok.Header.Get("Access-Control-Allow-Credentials"))

	refused := preflight("https://evil.example")
	assert.Empty(t, refused.Header.Get("Access-Control-Allow-Origin"))
	assert.NotEqual(t, http.StatusNoContent, refused.StatusCode)
}
