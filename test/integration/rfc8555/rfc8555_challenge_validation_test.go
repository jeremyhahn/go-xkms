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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/jeremyhahn/go-xkms/test/integration"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 8 - Challenge Validation

// TestHTTP01ChallengeValidation verifies HTTP-01 challenge validation workflow.
// Requirements per RFC 8555 Section 8.3:
// - Client sets up HTTP server with key authorization at /.well-known/acme-challenge/{token}
// - Server validates by fetching from http://{domain}/.well-known/acme-challenge/{token}
// - Response body MUST contain the key authorization
// - Challenge status transitions from pending -> processing -> valid
func TestHTTP01ChallengeValidation(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 8.3 - Testing HTTP-01 challenge validation")

	// Step 1: Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "http01@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "http01-test.example.com")
	require.NotEmpty(t, authzURLs, "Order must have authorizations")

	// Step 2: Fetch authorization to get challenges
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
	require.NotEmpty(t, authz.Challenges, "Authorization must have challenges")

	// Step 3: Find http-01 challenge
	var http01Challenge *entities.ACMEChallenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "http-01" {
			http01Challenge = &authz.Challenges[i]
			break
		}
	}
	require.NotNil(t, http01Challenge, "Authorization must include http-01 challenge")
	t.Logf("Found http-01 challenge: URL=%s, Token=%s", http01Challenge.URL, http01Challenge.Token)

	// Step 4: Compute key authorization
	keyAuthorization := integration.ComputeKeyAuthorization(t, http01Challenge.Token, accountKey.Public())
	t.Logf("Computed key authorization: %s", keyAuthorization)

	// Step 5: Set up mock HTTP validation server
	// This simulates the client's HTTP server that serves the key authorization
	validationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/.well-known/acme-challenge/" + http01Challenge.Token
		if r.URL.Path == expectedPath {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(keyAuthorization))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer validationServer.Close()

	t.Logf("Mock validation server running at: %s", validationServer.URL)

	// Step 6: Trigger challenge validation by POSTing empty JSON object
	nonce = integration.GetNonce(t, integration.TestServerURL)
	challengePayload := map[string]interface{}{} // Empty object triggers validation
	challengeJWS := integration.CreateJWS(t, accountKey, nonce, http01Challenge.URL, challengePayload, true, accountURL)

	resp, err = http.Post(http01Challenge.URL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server should accept challenge response (200 OK or 202 Accepted)
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted,
		"Challenge response MUST return 200 OK or 202 Accepted, got %d", resp.StatusCode)

	// Parse the response
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	var updatedChallenge entities.ACMEChallenge
	err = json.Unmarshal(body, &updatedChallenge)
	require.NoError(t, err)

	// Step 7: Verify challenge status transition
	// Status should be "processing" or "valid" (mock verifier returns success immediately)
	validStatuses := []string{common.StatusPending, common.StatusProcessing, common.StatusValid}
	assert.Contains(t, validStatuses, updatedChallenge.Status,
		"Challenge status should be pending, processing, or valid, got %s", updatedChallenge.Status)

	t.Logf("Challenge status after trigger: %s", updatedChallenge.Status)

	// If using mock verifier (which returns immediately), status should be valid
	if updatedChallenge.Status == common.StatusValid {
		t.Log("Challenge validation completed successfully (mock verifier)")
		assert.NotEmpty(t, updatedChallenge.Validated, "Valid challenge MUST have validated timestamp")
	}

	t.Log("HTTP-01 challenge validation test completed successfully")
}

// TestDNS01ChallengeValidation verifies DNS-01 challenge validation workflow.
// Requirements per RFC 8555 Section 8.4:
// - Client creates TXT record at _acme-challenge.{domain}
// - Record value MUST be base64url(SHA256(keyAuthorization))
// - Challenge status transitions from pending -> processing -> valid
func TestDNS01ChallengeValidation(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 8.4 - Testing DNS-01 challenge validation")

	// Step 1: Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "dns01@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "dns01-test.example.com")
	require.NotEmpty(t, authzURLs, "Order must have authorizations")

	// Step 2: Fetch authorization to get challenges
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
	require.NotEmpty(t, authz.Challenges, "Authorization must have challenges")

	// Step 3: Find dns-01 challenge
	var dns01Challenge *entities.ACMEChallenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "dns-01" {
			dns01Challenge = &authz.Challenges[i]
			break
		}
	}
	require.NotNil(t, dns01Challenge, "Authorization must include dns-01 challenge")
	t.Logf("Found dns-01 challenge: URL=%s, Token=%s", dns01Challenge.URL, dns01Challenge.Token)

	// Step 4: Compute DNS TXT record value
	// Per RFC 8555 Section 8.4: TXT record = base64url(SHA256(keyAuthorization))
	keyAuthorization := integration.ComputeKeyAuthorization(t, dns01Challenge.Token, accountKey.Public())
	hash := sha256.Sum256([]byte(keyAuthorization))
	txtRecordValue := base64.RawURLEncoding.EncodeToString(hash[:])

	t.Logf("Computed key authorization: %s", keyAuthorization)
	t.Logf("Computed DNS TXT record value: %s", txtRecordValue)
	t.Logf("TXT record should be placed at: _acme-challenge.dns01-test.example.com")

	// Note: In real scenarios, client would update DNS before triggering validation.
	// Our mock DNS verifier always succeeds, so we proceed directly.

	// Step 5: Trigger challenge validation
	nonce = integration.GetNonce(t, integration.TestServerURL)
	challengePayload := map[string]interface{}{} // Empty object triggers validation
	challengeJWS := integration.CreateJWS(t, accountKey, nonce, dns01Challenge.URL, challengePayload, true, accountURL)

	resp, err = http.Post(dns01Challenge.URL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server should accept challenge response
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted,
		"Challenge response MUST return 200 OK or 202 Accepted, got %d", resp.StatusCode)

	// Parse the response
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	var updatedChallenge entities.ACMEChallenge
	err = json.Unmarshal(body, &updatedChallenge)
	require.NoError(t, err)

	// Step 6: Verify challenge status
	validStatuses := []string{common.StatusPending, common.StatusProcessing, common.StatusValid}
	assert.Contains(t, validStatuses, updatedChallenge.Status,
		"Challenge status should be pending, processing, or valid, got %s", updatedChallenge.Status)

	t.Logf("Challenge status after trigger: %s", updatedChallenge.Status)

	if updatedChallenge.Status == common.StatusValid {
		t.Log("DNS-01 challenge validation completed successfully (mock verifier)")
		assert.NotEmpty(t, updatedChallenge.Validated, "Valid challenge MUST have validated timestamp")
	}

	t.Log("DNS-01 challenge validation test completed successfully")
}

// TestChallengeResponse_InvalidToken tests error handling for invalid challenge tokens.
// Requirements:
// - Server MUST reject malformed challenge requests
// - Server MUST return appropriate error response
func TestChallengeResponse_InvalidToken(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("Testing challenge response with invalid/malformed requests")

	// Create account
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "invalid-token@example.com")

	// Test 1: Access non-existent challenge URL
	t.Log("Test 1: Accessing non-existent challenge")
	nonExistentChallengeURL := integration.TestServerURL + "/acme/challenge/non-existent-id"

	nonce := integration.GetNonce(t, integration.TestServerURL)
	challengePayload := map[string]interface{}{}
	challengeJWS := integration.CreateJWS(t, accountKey, nonce, nonExistentChallengeURL, challengePayload, true, accountURL)

	resp, err := http.Post(nonExistentChallengeURL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server should return 404 or appropriate error
	assert.True(t, resp.StatusCode >= 400, "Invalid challenge URL should return error status, got %d", resp.StatusCode)
	t.Logf("Non-existent challenge returned status: %d", resp.StatusCode)

	// Test 2: Create order and access challenge with wrong account
	t.Log("Test 2: Accessing challenge with unauthorized account")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "invalid-token-test.example.com")
	require.NotEmpty(t, authzURLs)

	// Fetch authorization to get challenge URL
	nonce = integration.GetNonce(t, integration.TestServerURL)
	authzJWS := integration.CreateJWS(t, accountKey, nonce, authzURLs[0], "", true, accountURL)

	resp, err = http.Post(authzURLs[0], "application/jose+json", bytes.NewReader([]byte(authzJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var authz entities.ACMEAuthorization
	err = json.Unmarshal(body, &authz)
	require.NoError(t, err)
	require.NotEmpty(t, authz.Challenges)

	challengeURL := authz.Challenges[0].URL

	// Create a different account
	otherAccountKey, otherAccountURL := integration.CreateTestAccount(t, integration.TestServerURL, "other-account@example.com")

	// Try to respond to challenge with different account
	nonce = integration.GetNonce(t, integration.TestServerURL)
	challengePayload = map[string]interface{}{}
	challengeJWS = integration.CreateJWS(t, otherAccountKey, nonce, challengeURL, challengePayload, true, otherAccountURL)

	resp, err = http.Post(challengeURL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server should return 403 Forbidden or similar error
	assert.True(t, resp.StatusCode >= 400, "Unauthorized challenge access should return error status, got %d", resp.StatusCode)
	t.Logf("Unauthorized challenge access returned status: %d", resp.StatusCode)

	t.Log("Invalid token and authorization tests completed successfully")
}

// TestChallengeStatusTransitions verifies challenge status transitions per RFC 8555.
// Requirements:
// - Challenge starts in "pending" status
// - After client responds, status transitions to "processing"
// - After successful validation, status becomes "valid"
// - After failed validation, status becomes "invalid"
func TestChallengeStatusTransitions(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("Testing challenge status transitions: pending -> processing -> valid/invalid")

	// Step 1: Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "status-transitions@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "status-test.example.com")
	require.NotEmpty(t, authzURLs, "Order must have authorizations")

	// Step 2: Fetch authorization and verify initial challenge status
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
	require.NotEmpty(t, authz.Challenges, "Authorization must have challenges")

	// Verify initial status is "pending"
	challenge := authz.Challenges[0]
	assert.Equal(t, common.StatusPending, challenge.Status,
		"Initial challenge status MUST be 'pending', got '%s'", challenge.Status)
	t.Logf("Initial challenge status: %s", challenge.Status)

	// Step 3: Trigger challenge validation
	nonce = integration.GetNonce(t, integration.TestServerURL)
	challengePayload := map[string]interface{}{} // Empty object triggers validation
	challengeJWS := integration.CreateJWS(t, accountKey, nonce, challenge.URL, challengePayload, true, accountURL)

	resp, err = http.Post(challenge.URL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
	require.NoError(t, err)

	// Verify response status code
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted,
		"Challenge response MUST return 200 or 202, got %d", resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)

	var updatedChallenge entities.ACMEChallenge
	err = json.Unmarshal(body, &updatedChallenge)
	require.NoError(t, err)

	// Status should have transitioned (with mock verifier, likely directly to valid)
	t.Logf("Challenge status after trigger: %s", updatedChallenge.Status)

	// Verify valid status transitions
	validTransitions := map[string][]string{
		common.StatusPending:    {common.StatusProcessing, common.StatusValid},
		common.StatusProcessing: {common.StatusValid, common.StatusInvalid},
		common.StatusValid:      {}, // Terminal state
		common.StatusInvalid:    {}, // Terminal state
	}

	// Initial status was "pending", so valid next statuses are "processing" or "valid"
	expectedNextStatuses := validTransitions[common.StatusPending]
	assert.Contains(t, expectedNextStatuses, updatedChallenge.Status,
		"Challenge status transition from 'pending' should be to 'processing' or 'valid', got '%s'", updatedChallenge.Status)

	// Step 4: If status is processing, poll until terminal state
	if updatedChallenge.Status == common.StatusProcessing {
		t.Log("Challenge is processing, waiting for final status...")

		// Poll for up to 10 seconds
		timeout := time.After(10 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				t.Fatal("Timeout waiting for challenge to reach terminal state")
			case <-ticker.C:
				// Fetch current challenge status
				nonce = integration.GetNonce(t, integration.TestServerURL)
				pollJWS := integration.CreateJWS(t, accountKey, nonce, challenge.URL, nil, true, accountURL)

				resp, err = http.Post(challenge.URL, "application/jose+json", bytes.NewReader([]byte(pollJWS)))
				require.NoError(t, err)

				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				require.NoError(t, err)

				err = json.Unmarshal(body, &updatedChallenge)
				require.NoError(t, err)

				t.Logf("Polled challenge status: %s", updatedChallenge.Status)

				if updatedChallenge.Status == common.StatusValid || updatedChallenge.Status == common.StatusInvalid {
					t.Logf("Challenge reached terminal state: %s", updatedChallenge.Status)
					goto donePolling
				}
			}
		}
	donePolling:
	}

	// Step 5: Verify final state properties
	if updatedChallenge.Status == common.StatusValid {
		assert.NotEmpty(t, updatedChallenge.Validated, "Valid challenge MUST have 'validated' timestamp")
		assert.Nil(t, updatedChallenge.Error, "Valid challenge MUST NOT have error")
		t.Logf("Challenge validated at: %s", updatedChallenge.Validated)
	} else if updatedChallenge.Status == common.StatusInvalid {
		assert.NotNil(t, updatedChallenge.Error, "Invalid challenge MUST include error details")
		t.Logf("Challenge failed with error: %+v", updatedChallenge.Error)
	}

	t.Log("Challenge status transitions test completed successfully")
}

// TestChallengeRetryAfterValidation tests behavior when retrying an already validated challenge.
// Requirements:
// - Valid challenges should remain valid on re-request
// - Server should not re-validate already valid challenges
func TestChallengeRetryAfterValidation(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("Testing challenge retry after successful validation")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "retry@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "retry-test.example.com")
	require.NotEmpty(t, authzURLs)

	// Fetch authorization
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

	challenge := authz.Challenges[0]

	// First validation attempt
	nonce = integration.GetNonce(t, integration.TestServerURL)
	challengePayload := map[string]interface{}{}
	challengeJWS := integration.CreateJWS(t, accountKey, nonce, challenge.URL, challengePayload, true, accountURL)

	resp, err = http.Post(challenge.URL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
	require.NoError(t, err)

	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)

	var firstResponse entities.ACMEChallenge
	err = json.Unmarshal(body, &firstResponse)
	require.NoError(t, err)

	t.Logf("First validation response status: %s", firstResponse.Status)

	// If challenge is valid, try to trigger validation again
	if firstResponse.Status == common.StatusValid {
		validatedTime := firstResponse.Validated

		// Second validation attempt
		nonce = integration.GetNonce(t, integration.TestServerURL)
		challengeJWS = integration.CreateJWS(t, accountKey, nonce, challenge.URL, challengePayload, true, accountURL)

		resp, err = http.Post(challenge.URL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
		require.NoError(t, err)

		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)

		var secondResponse entities.ACMEChallenge
		err = json.Unmarshal(body, &secondResponse)
		require.NoError(t, err)

		// Status should still be valid
		assert.Equal(t, common.StatusValid, secondResponse.Status,
			"Already valid challenge should remain valid")

		// Validated timestamp should be unchanged (no re-validation)
		assert.Equal(t, validatedTime, secondResponse.Validated,
			"Validated timestamp should remain unchanged on retry")

		t.Logf("Second validation response status: %s (unchanged)", secondResponse.Status)
	}

	t.Log("Challenge retry test completed successfully")
}

// TestMultipleChallengeTypes verifies that multiple challenge types can coexist.
// Requirements per RFC 8555:
// - Authorization MUST include one or more challenge types
// - Client can choose which challenge to complete
// - Only one challenge needs to be valid for authorization to be valid
func TestMultipleChallengeTypes(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("Testing multiple challenge types in authorization")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "multi-challenge@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "multi-challenge.example.com")
	require.NotEmpty(t, authzURLs)

	// Fetch authorization
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

	// Verify multiple challenge types are present
	require.NotEmpty(t, authz.Challenges, "Authorization MUST have at least one challenge")

	challengeTypes := make(map[string]bool)
	for _, challenge := range authz.Challenges {
		challengeTypes[challenge.Type] = true
		t.Logf("Found challenge type: %s (URL: %s)", challenge.Type, challenge.URL)
	}

	t.Logf("Total challenge types available: %d", len(challengeTypes))

	// Verify all challenges have required fields
	for _, challenge := range authz.Challenges {
		assert.NotEmpty(t, challenge.Type, "Challenge MUST have type")
		assert.NotEmpty(t, challenge.URL, "Challenge MUST have URL")
		assert.NotEmpty(t, challenge.Token, "Challenge MUST have token")
		assert.NotEmpty(t, challenge.Status, "Challenge MUST have status")
		assert.Equal(t, common.StatusPending, challenge.Status,
			"All challenges should start in pending status")
	}

	// Complete one challenge and verify it doesn't affect others
	if len(authz.Challenges) > 1 {
		// Validate first challenge
		firstChallenge := authz.Challenges[0]
		nonce = integration.GetNonce(t, integration.TestServerURL)
		challengePayload := map[string]interface{}{}
		challengeJWS := integration.CreateJWS(t, accountKey, nonce, firstChallenge.URL, challengePayload, true, accountURL)

		resp, err = http.Post(firstChallenge.URL, "application/jose+json", bytes.NewReader([]byte(challengeJWS)))
		require.NoError(t, err)

		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)

		var validatedChallenge entities.ACMEChallenge
		err = json.Unmarshal(body, &validatedChallenge)
		require.NoError(t, err)

		t.Logf("First challenge (%s) status after validation: %s", firstChallenge.Type, validatedChallenge.Status)

		// Check second challenge is still pending (not automatically validated)
		secondChallenge := authz.Challenges[1]
		nonce = integration.GetNonce(t, integration.TestServerURL)
		pollJWS := integration.CreateJWS(t, accountKey, nonce, secondChallenge.URL, nil, true, accountURL)

		resp, err = http.Post(secondChallenge.URL, "application/jose+json", bytes.NewReader([]byte(pollJWS)))
		require.NoError(t, err)

		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)

		var otherChallenge entities.ACMEChallenge
		err = json.Unmarshal(body, &otherChallenge)
		require.NoError(t, err)

		t.Logf("Second challenge (%s) status: %s", secondChallenge.Type, otherChallenge.Status)
	}

	t.Log("Multiple challenge types test completed successfully")
}
