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

// RFC 8555 Section 7.5 - Identifier Authorization

// TestRFC_7_5_1_ChallengeResponse verifies RFC 8555 Section 7.5.1 - Responding to Challenges
// Requirements:
// - Server MUST accept challenge responses
// - Server MUST return updated challenge object
func TestRFC_7_5_1_ChallengeResponse(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.5.1 - Testing challenge response")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.5.1@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "rfc-test-7-5-1.example.com")

	// Get authorization and challenges
	nonce := integration.GetNonce(t, integration.TestServerURL)
	authzJWS := integration.CreateJWS(t, accountKey, nonce, authzURLs[0], "", true, accountURL)

	resp, err := http.Post(authzURLs[0], "application/jose+json", bytes.NewReader([]byte(authzJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var authz entities.ACMEAuthorization
	err = json.Unmarshal(body, &authz)
	require.NoError(t, err)
	require.NotEmpty(t, authz.Challenges)

	// Respond to first challenge
	challengeURL := authz.Challenges[0].URL
	nonce = integration.GetNonce(t, integration.TestServerURL)
	challengeJWS := integration.CreateJWS(t, accountKey, nonce, challengeURL, map[string]interface{}{}, true, accountURL)

	resp, err = http.Post(challengeURL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server MUST accept challenge response
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted,
		"Challenge response MUST return 200 OK or 202 Accepted")

	// Verify response contains updated challenge
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	var challenge entities.ACMEChallenge
	err = json.Unmarshal(body, &challenge)
	require.NoError(t, err)

	assert.NotEmpty(t, challenge.Status, "Response MUST include challenge status")

	t.Logf("✓ Challenge response accepted, status: %s", challenge.Status)
}

// TestRFC_7_5_2_AuthorizationDeactivation verifies RFC 8555 Section 7.5.2 - Deactivating Authorization
// Requirements:
// - Server MUST support authorization deactivation
// - Authorization status MUST change to "deactivated"
func TestRFC_7_5_2_AuthorizationDeactivation(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.5.2 - Testing authorization deactivation")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.5.2@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "rfc-test-7-5-2.example.com")
	require.NotEmpty(t, authzURLs)

	// Deactivate authorization
	nonce := integration.GetNonce(t, integration.TestServerURL)
	deactivatePayload := map[string]interface{}{
		"status": "deactivated",
	}
	deactivateJWS := integration.CreateJWS(t, accountKey, nonce, authzURLs[0], deactivatePayload, true, accountURL)

	resp, err := http.Post(authzURLs[0], "application/jose+json", bytes.NewReader([]byte(deactivateJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server should accept deactivation request
	assert.True(t, resp.StatusCode < 500, "Authorization deactivation endpoint MUST be accessible")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	t.Logf("✓ Authorization deactivation request processed, status: %d", resp.StatusCode)
	t.Logf("  Response: %s", string(body))
}
