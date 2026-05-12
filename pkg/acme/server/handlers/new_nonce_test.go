//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNonceHandler_HEAD(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodHead, "/acme/new-nonce", nil)
	w := httptest.NewRecorder()

	service.NewNonceHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("Replay-Nonce"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Header().Get("Link"), "/acme/directory")
}

func TestNewNonceHandler_GET(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/new-nonce", nil)
	w := httptest.NewRecorder()

	service.NewNonceHandler(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.NotEmpty(t, w.Header().Get("Replay-Nonce"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Header().Get("Link"), "/acme/directory")
}

func TestNewNonceHandler_InvalidMethod(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/acme/new-nonce", nil)
	w := httptest.NewRecorder()

	service.NewNonceHandler(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestNewNonceHandler_UniquenessVerification(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	nonces := make(map[string]bool)

	// Generate 100 nonces and verify uniqueness
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodHead, "/acme/new-nonce", nil)
		w := httptest.NewRecorder()

		service.NewNonceHandler(w, req)

		nonce := w.Header().Get("Replay-Nonce")
		assert.NotEmpty(t, nonce, "Nonce should not be empty")
		assert.False(t, nonces[nonce], "Nonce should be unique")
		nonces[nonce] = true
	}

	assert.Equal(t, 100, len(nonces), "Should have 100 unique nonces")
}
