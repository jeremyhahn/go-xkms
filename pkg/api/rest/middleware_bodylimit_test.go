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

package rest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
)

// jsonBodyOfSize returns a JSON object of exactly n bytes whose single string
// field is padding, so it is well-formed up to the point a bound cuts it.
func jsonBodyOfSize(field string, n int) []byte {
	prefix := `{"` + field + `":"`
	suffix := `"}`
	return []byte(prefix + strings.Repeat("a", n-len(prefix)-len(suffix)) + suffix)
}

// oversizedRequest builds a POST whose body is over DefaultMaxBodyBytes.
// chunked hides the length (ContentLength -1) so only the streaming bound
// can catch it.
func oversizedRequest(target string, size int, chunked bool) *http.Request {
	body := jsonBodyOfSize("refresh_token", size)
	var r io.Reader = bytes.NewReader(body)
	if chunked {
		r = io.MultiReader(r) // not a length-known type: ContentLength = -1
	}
	req := httptest.NewRequest(http.MethodPost, target, r)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func assertTooLarge(t *testing.T, w *httptest.ResponseRecorder, limit int64) {
	t.Helper()
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code, "body: %s", w.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), "413 must carry one well-formed JSON error, got %q", w.Body.String())
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code)
	assert.Equal(t, (&RequestTooLargeError{Limit: limit}).Error(), resp.Error)
}

// TestBodyLimit_UnauthenticatedRoute covers /api/v1/auth/refresh, which any
// caller reaches without credentials.
func TestBodyLimit_UnauthenticatedRoute(t *testing.T) {
	server := newAuthTestServer(t, nil)
	for _, chunked := range []bool{false, true} {
		w := doAuthRequest(t, server, oversizedRequest("/api/v1/auth/refresh", int(DefaultMaxBodyBytes)+1, chunked))
		assertTooLarge(t, w, DefaultMaxBodyBytes)
	}
}

// TestBodyLimit_AuthenticatedRoute covers a permission route behind the
// /api/v1 authentication middleware.
func TestBodyLimit_AuthenticatedRoute(t *testing.T) {
	server := newAuthTestServer(t, nil)
	for _, chunked := range []bool{false, true} {
		w := doAuthRequest(t, server, oversizedRequest("/api/v1/keys", int(DefaultMaxBodyBytes)+1, chunked))
		assertTooLarge(t, w, DefaultMaxBodyBytes)
	}
}

// TestBodyLimit_WithinBoundReachesHandler proves a body at the bound is not
// refused: the handler answers on its own terms.
func TestBodyLimit_WithinBoundReachesHandler(t *testing.T) {
	server := newAuthTestServer(t, nil)
	w := doAuthRequest(t, server, oversizedRequest("/api/v1/auth/refresh", int(DefaultMaxBodyBytes), true))
	assert.NotEqual(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "an unknown refresh token is refused by the handler")
}

// TestBodyLimit_BulkRoute proves data-plane routes accept bodies above the
// default bound and are still bounded at BulkMaxBodyBytes.
func TestBodyLimit_BulkRoute(t *testing.T) {
	server := newAuthTestServer(t, nil)

	w := doAuthRequest(t, server, oversizedRequest("/api/v1/keys/k1/sign", int(DefaultMaxBodyBytes)*2, true))
	assert.NotEqual(t, http.StatusRequestEntityTooLarge, w.Code, "a 2 MiB sign body is within the bulk bound")

	w = doAuthRequest(t, server, oversizedRequest("/api/v1/keys/k1/sign", int(BulkMaxBodyBytes)+1, false))
	assertTooLarge(t, w, BulkMaxBodyBytes)
}

// TestBodyLimit_BindRoute proves the unified-server mount enforces the same
// bound as the legacy router.
func TestBodyLimit_BindRoute(t *testing.T) {
	server := newAuthTestServer(t, nil)
	for _, route := range []RouteSpec{
		findRoute(t, http.MethodPost, "/api/v1/auth/refresh"),
		findRoute(t, http.MethodPost, "/api/v1/keys"),
	} {
		h := server.BindRoute(route)
		for _, chunked := range []bool{false, true} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, oversizedRequest(route.Pattern, int(DefaultMaxBodyBytes)+1, chunked))
			assertTooLarge(t, w, DefaultMaxBodyBytes)
		}
	}
}

// TestBodyLimitMiddleware_Passthrough covers the writer wrapper's
// pass-through paths: an empty body, and a handler writing without an
// explicit WriteHeader.
func TestBodyLimitMiddleware_Passthrough(t *testing.T) {
	h := BodyLimitMiddleware(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		_, err = w.Write(body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusTeapot) // superfluous: must be ignored
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", io.MultiReader(strings.NewReader("hello"))))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "hello", w.Body.String())

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())
}

// TestBodyLimitMiddleware_ReplacesHandlerResponse proves the handler's own
// error (and anything it writes after) is replaced by one 413.
func TestBodyLimitMiddleware_ReplacesHandlerResponse(t *testing.T) {
	h := BodyLimitMiddleware(4)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err == nil {
			t.Error("reading past the bound must fail")
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		_, _ = w.Write([]byte("trailing"))
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", io.MultiReader(strings.NewReader("0123456789"))))
	assertTooLarge(t, w, 4)
	assert.NotContains(t, w.Body.String(), "bad request")
	assert.NotContains(t, w.Body.String(), "trailing")

	rc := http.NewResponseController(&bodyLimitWriter{ResponseWriter: httptest.NewRecorder()})
	assert.NoError(t, rc.Flush(), "the wrapper must unwrap to the underlying writer")
}

// TestRoutes_BodyLimits pins which routes get the bulk bound; every other
// route gets the default.
func TestRoutes_BodyLimits(t *testing.T) {
	bulk := map[string]bool{
		"POST /api/v1/keys/{id}/sign":    true,
		"POST /api/v1/keys/{id}/verify":  true,
		"POST /api/v1/keys/{id}/encrypt": true,
		"POST /api/v1/keys/{id}/decrypt": true,
		"POST /api/v1/seal":              true,
		"POST /api/v1/unseal":            true,
		// An OTA image is signed whole unless the caller sends its digest.
		"POST /api/v1/ota-image-keys/{board}/sign": true,
	}
	for _, spec := range Routes() {
		want := DefaultMaxBodyBytes
		if bulk[spec.Method+" "+spec.Pattern] {
			want = BulkMaxBodyBytes
		}
		assert.Equal(t, want, spec.bodyLimit(), "%s %s", spec.Method, spec.Pattern)
	}
}

// TestNewServer_ReadHeaderTimeout proves the listener bounds header reads.
func TestNewServer_ReadHeaderTimeout(t *testing.T) {
	server := newAuthTestServer(t, nil)
	assert.Equal(t, 10*time.Second, server.server.ReadHeaderTimeout)

	server = newAuthTestServer(t, func(c *Config) { c.ReadHeaderTimeout = 3 * time.Second })
	assert.Equal(t, 3*time.Second, server.server.ReadHeaderTimeout)
}

// TestAuthRateLimiter_IgnoresUntrustedForwardedFor drives the real router:
// rotating X-Forwarded-For from one untrusted peer, or reconnecting from a
// new port, must not escape the login limiter; a trusted proxy's header does
// select the client.
func TestAuthRateLimiter_IgnoresUntrustedForwardedFor(t *testing.T) {
	proxies, err := ratelimit.ParseTrustedProxies([]string{"10.0.0.1"})
	require.NoError(t, err)
	limiter := ratelimit.New(&ratelimit.Config{Enabled: true, RequestsPerMinute: 1, Burst: 1})
	t.Cleanup(limiter.Stop)
	server := newAuthTestServer(t, func(c *Config) {
		c.AuthRateLimiter = limiter
		c.TrustedProxies = proxies
	})

	refresh := func(remoteAddr, xff string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"x"}`))
		req.RemoteAddr = remoteAddr
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		return doAuthRequest(t, server, req).Code
	}

	assert.NotEqual(t, http.StatusTooManyRequests, refresh("192.0.2.7:1000", "203.0.113.1"))
	assert.Equal(t, http.StatusTooManyRequests, refresh("192.0.2.7:1000", "203.0.113.2"), "rotated XFF from an untrusted peer")
	assert.Equal(t, http.StatusTooManyRequests, refresh("192.0.2.7:1001", ""), "new connection from the same IP")

	assert.NotEqual(t, http.StatusTooManyRequests, refresh("10.0.0.1:1000", "198.51.100.1"), "client behind the trusted proxy")
	assert.Equal(t, http.StatusTooManyRequests, refresh("10.0.0.1:1001", "198.51.100.1"), "same client via the trusted proxy")
	assert.NotEqual(t, http.StatusTooManyRequests, refresh("10.0.0.1:1002", "198.51.100.2"), "another client via the trusted proxy")
}
