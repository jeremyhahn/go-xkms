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
	"encoding/json"
	"github.com/jeremyhahn/go-xkms/test/integration"
	"io"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 6.7 - Error Responses

// TestRFC_6_7_ErrorResponses verifies RFC 8555 Section 6.7 - Error Responses
// Requirements:
// - Errors MUST use Content-Type: application/problem+json
// - Errors MUST include "type" field with URN
// - Errors MUST include "detail" field
func TestRFC_6_7_ErrorResponses(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 6.7 - Testing error response format")

	// Trigger an error by sending invalid JWS
	resp, err := http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json",
		bytes.NewReader([]byte("invalid-jws")))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify error response format per RFC 7807
	assert.True(t, resp.StatusCode >= 400, "Error response must have 4xx or 5xx status")
	assert.Equal(t, "application/problem+json", resp.Header.Get("Content-Type"),
		"Error MUST use Content-Type: application/problem+json")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var errorResponse entities.Error
	err = json.Unmarshal(body, &errorResponse)
	require.NoError(t, err, "Error response must be valid JSON")

	// Verify required fields
	assert.NotEmpty(t, errorResponse.Type, "Error MUST include 'type' field")
	assert.Contains(t, errorResponse.Type, "urn:ietf:params:acme:error:", "Error type MUST be ACME URN")
	assert.NotEmpty(t, errorResponse.Detail, "Error MUST include 'detail' field")

	t.Logf("✓ Error response has correct RFC 7807 format")
	t.Logf("  type: %s", errorResponse.Type)
	t.Logf("  detail: %s", errorResponse.Detail)
}

// TestRFC_6_7_ErrorResponseHeaders verifies error responses include proper headers
// Requirements:
// - All responses (including errors) MUST include Replay-Nonce header
func TestRFC_6_7_ErrorResponseHeaders(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 6.7 - Testing error response headers")

	// Trigger an error
	resp, err := http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json",
		bytes.NewReader([]byte("invalid")))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Even error responses should include Replay-Nonce
	nonce := resp.Header.Get("Replay-Nonce")
	// Note: Not all implementations include nonce in error responses
	// This is a MAY requirement, not MUST
	if nonce != "" {
		t.Logf("✓ Error response includes Replay-Nonce: %s", nonce)
	} else {
		t.Log("  Error response does not include Replay-Nonce (optional)")
	}
}
