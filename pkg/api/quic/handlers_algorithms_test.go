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

// handlers_algorithms_test.go covers the QUIC algorithm discovery endpoint.
package quic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestHandleAlgorithms_Success proves the route is mounted and reports a real
// inventory. The endpoint exists so a caller can ask "can this deployment do
// X?" without generating a key, so an empty answer would defeat its purpose.
func TestHandleAlgorithms_Success(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/algorithms", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp transport.AlgorithmsResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Signing, "a build with a software backend must report signing algorithms")

	for _, a := range resp.Signing {
		assert.NotEmpty(t, a.Algorithm, "every entry must name its algorithm")
		assert.NotEmpty(t, a.Backends, "every entry must name the backends providing it")
	}
}

// TestHandleAlgorithms_NoAuthRequired pins the endpoint as public discovery,
// matching the REST route it mirrors: the same question must not be
// answerable on one transport and gated on another.
func TestHandleAlgorithms_NoAuthRequired(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/algorithms", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusForbidden, w.Code)
}

func TestHandleAlgorithms_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/algorithms", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}
