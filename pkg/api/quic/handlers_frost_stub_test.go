//go:build !frost

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

package quic

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
)

// TestSetupFrostRoutesStubCoverageVersion tests the FROST routes stub
func TestSetupFrostRoutesStubCoverageVersion(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// The setupFrostRoutes stub should be called during NewServer
	// We verify by ensuring the server was created successfully
	assert.NotNil(t, server)

	// Test that FROST endpoints return 404 since they're not implemented
	t.Run("FROST endpoint returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keygen", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// FROST routes are not registered, so expect 404
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
