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
	"encoding/base64"
	"github.com/jeremyhahn/go-xkms/test/integration"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 7.2 - Getting a Nonce

// TestRFC_7_2_GetNonce_HEAD verifies RFC 8555 Section 7.2 - Getting a Nonce via HEAD
// Requirements:
// - HEAD request to newNonce MUST return Replay-Nonce header
// - Response MUST include HTTP 200 status
func TestRFC_7_2_GetNonce_HEAD(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.2 - Testing nonce generation via HEAD request")

	req, err := http.NewRequest("HEAD", integration.TestServerURL+"/acme/new-nonce", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode, "HEAD newNonce MUST return 200 OK")

	nonce := resp.Header.Get("Replay-Nonce")
	assert.NotEmpty(t, nonce, "Response MUST include Replay-Nonce header")

	t.Logf("✓ HEAD newNonce returns valid nonce: %s", nonce)
}

// TestRFC_7_2_GetNonce_GET verifies RFC 8555 Section 7.2 - Getting a Nonce via GET
// Requirements:
// - GET request to newNonce MUST return Replay-Nonce header
// - Response MUST include HTTP 200 status
// - Response body SHOULD be empty or contain minimal content
func TestRFC_7_2_GetNonce_GET(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.2 - Testing nonce generation via GET request")

	resp, err := http.Get(integration.TestServerURL + "/acme/new-nonce")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response (RFC 8555 allows 200 or 204)
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent,
		"GET newNonce MUST return 200 OK or 204 No Content")

	nonce := resp.Header.Get("Replay-Nonce")
	assert.NotEmpty(t, nonce, "Response MUST include Replay-Nonce header")

	t.Logf("✓ GET newNonce returns valid nonce: %s", nonce)
}

// TestRFC_7_2_NonceUniqueness verifies RFC 8555 Section 7.2 - Nonce Uniqueness
// Requirements:
// - Each nonce MUST be unique
// - Server MUST generate fresh nonces
func TestRFC_7_2_NonceUniqueness(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.2 - Testing nonce uniqueness")

	nonces := make(map[string]bool)
	iterations := 10

	for i := 0; i < iterations; i++ {
		req, err := http.NewRequest("HEAD", integration.TestServerURL+"/acme/new-nonce", nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		nonce := resp.Header.Get("Replay-Nonce")
		require.NotEmpty(t, nonce)

		assert.False(t, nonces[nonce], "Nonce %s was already used (iteration %d)", nonce, i)
		nonces[nonce] = true
	}

	assert.Len(t, nonces, iterations, "All nonces must be unique")
	t.Logf("✓ Generated %d unique nonces", iterations)
}

// TestRFC_7_2_NonceFormat verifies RFC 8555 Section 7.2 - Nonce Format
// Requirements:
// - Nonce MUST be base64url encoded
// - Nonce MUST have sufficient entropy
func TestRFC_7_2_NonceFormat(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.2 - Testing nonce format")

	nonce := integration.GetNonce(t, integration.TestServerURL)
	require.NotEmpty(t, nonce)

	// Verify it's valid base64url
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	assert.NoError(t, err, "Nonce MUST be valid base64url encoding")
	assert.NotEmpty(t, decoded, "Decoded nonce must not be empty")

	// Verify minimum length (sufficient entropy)
	assert.GreaterOrEqual(t, len(decoded), 16, "Nonce should have at least 128 bits of entropy")

	t.Logf("✓ Nonce is valid base64url with %d bytes of entropy", len(decoded))
}
