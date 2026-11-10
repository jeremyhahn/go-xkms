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

package apimodule

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// corsHeaderNames returns the Access-Control-* header names of a response.
func corsHeaderNames(h http.Header) []string {
	var names []string
	for name := range h {
		if strings.HasPrefix(name, "Access-Control-") {
			names = append(names, name)
		}
	}
	return names
}

// TestRegisterHTTP_AppliesTheConfiguredCORSPolicy: the routes the module
// registers on the unified API surface do not pass through the chi router's
// global middleware chain, so the module itself applies the REST server's
// CORS policy to each route and answers the preflight of each pattern.
func TestRegisterHTTP_AppliesTheConfiguredCORSPolicy(t *testing.T) {
	const allowed = "https://rp.example"
	const other = "https://other.example"

	srv, err := rest.NewServer(&rest.Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		CORS:          &rest.CORSOptions{AllowedOrigins: []string{allowed}},
	})
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	// One public POST route, and the preflight route of the same pattern.
	var post, preflight http.HandlerFunc
	var pattern string
	for _, rec := range *recs {
		if rec.public && rec.method == http.MethodPost {
			post, pattern = rec.handler, rec.pattern
			break
		}
	}
	require.NotNil(t, post, "a public POST route must be registered")
	options := 0
	for _, rec := range *recs {
		if rec.method == http.MethodOptions && rec.pattern == pattern {
			options++
			assert.True(t, rec.public, "the preflight route of %s must be public", pattern)
			preflight = rec.handler
		}
	}
	require.Equal(t, 1, options, "OPTIONS %s must be registered exactly once", pattern)

	send := func(h http.HandlerFunc, method, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, pattern, strings.NewReader("{}"))
		req.Header.Set("Origin", origin)
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		}
		w := httptest.NewRecorder()
		h(w, req)
		return w
	}

	// Allowed origin: the response of the route carries the origin.
	w := send(post, http.MethodPost, allowed)
	assert.Equal(t, allowed, w.Header().Get("Access-Control-Allow-Origin"))

	// Allowed origin: the preflight is answered with the policy.
	w = send(preflight, http.MethodOptions, allowed)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, allowed, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-Session-Id")

	// Any other origin: no CORS header, and the preflight serves nothing.
	w = send(post, http.MethodPost, other)
	assert.Empty(t, corsHeaderNames(w.Header()))
	w = send(preflight, http.MethodOptions, other)
	assert.Empty(t, corsHeaderNames(w.Header()))
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Empty(t, w.Body.String())
}
