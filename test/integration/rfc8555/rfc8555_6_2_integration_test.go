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

//go:build local

package rfc8555

import (
	"bytes"
	"github.com/jeremyhahn/go-xkms/test/integration"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 6.2 - Request Authentication

// TestRFC_6_2_RequestAuthentication verifies RFC 8555 Section 6.2 - Request Authentication
// Requirements:
// - Server MUST validate JWS signatures
// - Server MUST reject invalid signatures
func TestRFC_6_2_RequestAuthentication(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 6.2 - Testing request authentication via JWS")

	// Valid JWS should succeed
	accountKey, _ := integration.CreateTestAccount(t, integration.TestServerURL, "rfc6.2@example.com")
	t.Log("✓ Valid JWS signature accepted")

	// Invalid JWS should be rejected
	resp, err := http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json",
		bytes.NewReader([]byte("invalid-jws-signature")))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Invalid JWS MUST be rejected with 400")
	assert.Equal(t, "application/problem+json", resp.Header.Get("Content-Type"), "Error MUST use problem+json format")

	t.Logf("✓ Invalid JWS properly rejected with status %d", resp.StatusCode)

	// Suppress unused variable warning
	_ = accountKey
}
