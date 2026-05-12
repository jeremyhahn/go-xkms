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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectoryHandler_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
	w := httptest.NewRecorder()

	service.DirectoryHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var directory common.Directory
	err := json.Unmarshal(w.Body.Bytes(), &directory)
	require.NoError(t, err)

	// Verify all required endpoints are present
	assert.Contains(t, directory.NewNonce, "/acme/new-nonce")
	assert.Contains(t, directory.NewAccount, "/acme/new-account")
	assert.Contains(t, directory.NewOrder, "/acme/new-order")
	assert.Contains(t, directory.RevokeCert, "/acme/revoke-cert")
	assert.Contains(t, directory.KeyChange, "/acme/key-change")

	// Verify metadata
	assert.NotEmpty(t, directory.Meta.TermsOfService)
	assert.NotEmpty(t, directory.Meta.Website)
	assert.NotNil(t, directory.Meta.CAAIdentities)
}

func TestDirectoryHandler_HTTPMethods(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	tests := []struct {
		name       string
		method     string
		expectCode int
	}{
		{"GET request", http.MethodGet, http.StatusOK},
		{"POST request", http.MethodPost, http.StatusOK}, // RFC allows POST
		{"HEAD request", http.MethodHead, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/acme/directory", nil)
			w := httptest.NewRecorder()

			service.DirectoryHandler(w, req)

			assert.Equal(t, tt.expectCode, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		})
	}
}
