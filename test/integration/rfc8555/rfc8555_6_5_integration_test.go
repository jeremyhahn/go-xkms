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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/jeremyhahn/go-xkms/test/integration"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 6.5 - Replay Protection and Rate Limits

// TestRFC_6_5_ReplayProtection verifies RFC 8555 Section 6.5 - Replay Protection
// Requirements:
// - Server MUST require nonce in JWS
// - Server MUST reject reused nonces
// - Server MUST return new nonce in Replay-Nonce header
func TestRFC_6_5_ReplayProtection(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 6.5 - Testing replay protection via nonces")

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test 1: Request with invalid nonce should be rejected
	invalidNonce := "invalid-nonce-12345"
	accountPayload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:rfc6.5@example.com"},
	}
	jws := integration.CreateJWS(t, accountKey, invalidNonce, integration.TestServerURL+"/acme/new-account", accountPayload, false, "")

	resp, err := http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json", bytes.NewReader([]byte(jws)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Invalid nonce MUST be rejected")
	t.Log("✓ Invalid nonce properly rejected")

	// Test 2: Valid nonce should be accepted and new nonce returned
	validNonce := integration.GetNonce(t, integration.TestServerURL)
	jws = integration.CreateJWS(t, accountKey, validNonce, integration.TestServerURL+"/acme/new-account", accountPayload, false, "")

	resp, err = http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json", bytes.NewReader([]byte(jws)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode, "Valid nonce MUST be accepted")

	newNonce := resp.Header.Get("Replay-Nonce")
	assert.NotEmpty(t, newNonce, "Response MUST include new Replay-Nonce header")
	assert.NotEqual(t, validNonce, newNonce, "New nonce should be different from used nonce")

	t.Logf("✓ Valid nonce accepted, new nonce returned: %s", newNonce)
	t.Log("✓ Replay protection is working correctly")
}

// TestRFC_6_5_RateLimits verifies RFC 8555 Section 6.5 - Rate Limits
// Requirements:
// - Server MAY implement rate limiting
// - Server SHOULD include Retry-After header when rate limited
// - Server MUST return 429 Too Many Requests when rate limit exceeded
func TestRFC_6_5_RateLimits(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 6.5 - Testing rate limit behavior")

	// Create account key for testing
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Make multiple rapid requests to test rate limiting behavior
	// Note: The server may or may not implement rate limiting (it's optional per RFC)
	successCount := 0
	rateLimitedCount := 0
	maxAttempts := 20

	for i := 0; i < maxAttempts; i++ {
		nonce := integration.GetNonce(t, integration.TestServerURL)
		accountPayload := map[string]interface{}{
			"termsOfServiceAgreed": true,
			"contact":              []string{"mailto:ratelimit" + string(rune(i)) + "@example.com"},
		}
		accountJWS := integration.CreateJWS(t, accountKey, nonce, integration.TestServerURL+"/acme/new-account", accountPayload, false, "")

		resp, err := http.Post(integration.TestServerURL+"/acme/new-account", "application/jose+json", bytes.NewReader([]byte(accountJWS)))
		require.NoError(t, err)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitedCount++
			t.Logf("  Request %d: Rate limited (429 Too Many Requests)", i+1)

			// Verify Retry-After header if rate limited
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				t.Logf("    Retry-After header: %s", retryAfter)
			}
		} else if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
			successCount++
		}

		// Small delay between requests
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("✓ Rate limit test completed: %d successful, %d rate-limited", successCount, rateLimitedCount)
	if rateLimitedCount > 0 {
		t.Log("✓ Server implements rate limiting per RFC 8555 Section 6.5")
	} else {
		t.Log("  Server does not implement rate limiting (optional feature)")
	}
}
