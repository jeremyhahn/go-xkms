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

package gui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCSPMiddleware_SetsHeaderAndDelegates verifies cspMiddleware stamps the
// policy on every response and still lets the wrapped handler run and write
// its own body.
func TestCSPMiddleware_SetsHeaderAndDelegates(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("body"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	cspMiddleware(next).ServeHTTP(rec, req)

	assert.True(t, called, "the wrapped handler must still run")
	assert.Equal(t, ContentSecurityPolicy, rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "body", rec.Body.String())
}

// TestCSPMiddleware_AppliesEvenWhenNextWritesNoHeader verifies the CSP
// header is present even for a handler that never calls WriteHeader
// explicitly (the common case: an asset server that just writes a body).
func TestCSPMiddleware_AppliesEvenWhenNextWritesNoHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("asset"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	cspAssetServerMiddleware(next).ServeHTTP(rec, req)

	assert.Equal(t, ContentSecurityPolicy, rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "asset", rec.Body.String())
}
