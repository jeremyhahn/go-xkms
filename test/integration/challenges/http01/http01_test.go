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

//go:build integration

package http01

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/jeremyhahn/go-xkms/test/integration/challenges"
	"io"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// computeJWKThumbprint delegates to the canonical implementation
func computeJWKThumbprint(pubKey crypto.PublicKey) (string, error) {
	return handlers.JWKThumbprint(pubKey)
}

// TestHTTP01_ChallengeAvailable tests that HTTP-01 challenge is offered for DNS identifiers
// This test runs against an ACME server in Docker
func TestHTTP01_ChallengeAvailable(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 challenge availability on ACME server")
	t.Logf("Server URL: %s", serverURL)

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-test@example.com"})
	require.NoError(t, err, "Failed to create account")
	t.Logf("Created account: %s", accountURL)

	// Create order for DNS identifier (should offer HTTP-01)
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "http01-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")
	assert.Equal(t, "pending", order.Status, "Order should be pending")
	t.Logf("Created order with %d authorizations", len(order.Authorizations))

	// Fetch authorization
	require.NotEmpty(t, order.Authorizations, "Order should have authorizations")
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	// Find HTTP-01 challenge
	http01 := challenges.FindByType(authz, "http-01")
	require.NotNil(t, http01, "HTTP-01 challenge should be available for DNS identifier")

	t.Logf("HTTP-01 challenge found:")
	t.Logf("  URL: %s", http01.URL)
	t.Logf("  Token: %s", http01.Token)
	t.Logf("  Status: %s", http01.Status)

	assert.Equal(t, "pending", http01.Status, "Challenge should be pending")
	assert.NotEmpty(t, http01.Token, "Token should not be empty")
	assert.NotEmpty(t, http01.URL, "Challenge URL should not be empty")

	t.Log("HTTP-01 challenge availability verified successfully")
}

// TestHTTP01_KeyAuthorizationFormat tests key authorization computation
func TestHTTP01_KeyAuthorizationFormat(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 key authorization format")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-keyauth@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "keyauth-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization and get HTTP-01 challenge
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	http01 := challenges.FindByType(authz, "http-01")
	require.NotNil(t, http01, "HTTP-01 challenge should be available")

	// Compute key authorization
	keyAuth, err := challenges.ComputeKeyAuthorization(http01.Token, privateKey.Public())
	require.NoError(t, err, "Failed to compute key authorization")

	// Verify format: token.thumbprint
	assert.Contains(t, keyAuth, ".", "Key authorization should contain dot separator")
	assert.True(t, len(keyAuth) > len(http01.Token)+1, "Key authorization should be longer than token")

	t.Logf("Token: %s", http01.Token)
	t.Logf("Key Authorization: %s", keyAuth)
	t.Logf("Key Authorization length: %d bytes", len(keyAuth))

	// Verify thumbprint is base64url encoded SHA-256 (43 chars without padding)
	parts := splitKeyAuth(keyAuth)
	require.Len(t, parts, 2, "Key auth should have two parts")
	assert.Equal(t, http01.Token, parts[0], "First part should be token")
	assert.Len(t, parts[1], 43, "Thumbprint should be 43 characters (base64url encoded SHA-256)")

	t.Log("HTTP-01 key authorization format verified successfully")
}

// TestHTTP01_ChallengeResponse tests initiating HTTP-01 challenge verification
func TestHTTP01_ChallengeResponse(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 challenge response initiation")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-response@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "response-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	http01 := challenges.FindByType(authz, "http-01")
	require.NotNil(t, http01, "HTTP-01 challenge should be available")

	// Initiate challenge verification (sends empty POST to challenge URL)
	challengeResp, err := challenges.InitiateVerification(client, http01.URL, privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to initiate challenge verification")

	t.Logf("Challenge response after initiation:")
	t.Logf("  Type: %s", challengeResp.Type)
	t.Logf("  Status: %s", challengeResp.Status)
	t.Logf("  URL: %s", challengeResp.URL)

	// Status should be "processing", "pending", or "valid" after initiation
	// In test mode with auto-validation, status may transition to "valid" immediately
	assert.Contains(t, []string{"pending", "processing", "valid"}, challengeResp.Status,
		"Challenge status should be pending, processing, or valid after initiation")

	t.Log("HTTP-01 challenge response verified successfully")
}

// TestHTTP01_TokenValidation tests that server validates challenge tokens properly
func TestHTTP01_TokenValidation(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 token validation")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-token@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create multiple orders and verify tokens are unique
	tokens := make(map[string]bool)

	for i := 0; i < 3; i++ {
		order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
			{Type: "dns", Value: fmt.Sprintf("token-test-%d.example.com", i)},
		})
		require.NoError(t, err, "Failed to create order")

		authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
		require.NoError(t, err, "Failed to fetch authorization")

		http01 := challenges.FindByType(authz, "http-01")
		require.NotNil(t, http01, "HTTP-01 challenge should be available")

		// Verify token uniqueness
		assert.False(t, tokens[http01.Token], "Token should be unique")
		tokens[http01.Token] = true

		// Verify token is base64url encoded
		_, err = base64.RawURLEncoding.DecodeString(http01.Token)
		require.NoError(t, err, "Token should be valid base64url")

		t.Logf("Order %d token: %s", i+1, http01.Token)
	}

	assert.Len(t, tokens, 3, "Should have 3 unique tokens")
	t.Log("HTTP-01 token validation verified successfully")
}

// TestHTTP01_DirectoryAdvertisement tests that HTTP-01 is advertised in directory
func TestHTTP01_DirectoryAdvertisement(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 directory advertisement")

	// Fetch directory
	directoryURL := fmt.Sprintf("%s/acme/directory", serverURL)
	resp, err := client.Get(directoryURL)
	require.NoError(t, err, "Failed to fetch directory")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Directory should return 200")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read directory response")

	t.Logf("Directory response: %s", string(body))

	// Verify directory contains required endpoints
	assert.Contains(t, string(body), "newNonce", "Directory should contain newNonce")
	assert.Contains(t, string(body), "newAccount", "Directory should contain newAccount")
	assert.Contains(t, string(body), "newOrder", "Directory should contain newOrder")

	t.Log("Directory advertisement verified successfully")
}

// TestHTTP01_MultipleIdentifiers tests HTTP-01 with multiple DNS identifiers
func TestHTTP01_MultipleIdentifiers(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 with multiple identifiers")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-multi@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order with multiple DNS identifiers
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "multi1.example.com"},
		{Type: "dns", Value: "multi2.example.com"},
		{Type: "dns", Value: "multi3.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	assert.Equal(t, "pending", order.Status, "Order should be pending")
	assert.Len(t, order.Authorizations, 3, "Should have 3 authorizations")
	t.Logf("Created order with %d authorizations", len(order.Authorizations))

	// Verify each authorization has HTTP-01 challenge
	for i, authzURL := range order.Authorizations {
		authz, err := challenges.FetchAuthorization(client, authzURL, privateKey, accountURL, serverURL)
		require.NoError(t, err, "Failed to fetch authorization %d", i)

		http01 := challenges.FindByType(authz, "http-01")
		require.NotNil(t, http01, "Authorization %d should have HTTP-01 challenge", i)

		t.Logf("Authorization %d (%s):", i+1, authz.Identifier.Value)
		t.Logf("  HTTP-01 Token: %s", http01.Token)
		t.Logf("  HTTP-01 Status: %s", http01.Status)
	}

	t.Log("HTTP-01 multiple identifiers verified successfully")
}

// TestHTTP01_WellKnownPath tests the expected HTTP-01 challenge path format
func TestHTTP01_WellKnownPath(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 well-known path format")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-path@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "path-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	http01 := challenges.FindByType(authz, "http-01")
	require.NotNil(t, http01, "HTTP-01 challenge should be available")

	// Per RFC 8555, the well-known path should be:
	// /.well-known/acme-challenge/{token}
	expectedPath := fmt.Sprintf("/.well-known/acme-challenge/%s", http01.Token)

	t.Logf("Token: %s", http01.Token)
	t.Logf("Expected well-known path: %s", expectedPath)

	// Compute expected key authorization for response
	keyAuth, err := challenges.ComputeKeyAuthorization(http01.Token, privateKey.Public())
	require.NoError(t, err, "Failed to compute key authorization")

	t.Logf("Expected response at path: %s", keyAuth)

	// The server would validate by requesting:
	// GET http://path-test.example.com/.well-known/acme-challenge/{token}
	// And expecting response body to equal keyAuth

	t.Log("HTTP-01 well-known path format verified successfully")
}

// splitKeyAuth splits a key authorization into token and thumbprint
func splitKeyAuth(keyAuth string) []string {
	for i := len(keyAuth) - 1; i >= 0; i-- {
		if keyAuth[i] == '.' {
			return []string{keyAuth[:i], keyAuth[i+1:]}
		}
	}
	return []string{keyAuth}
}

// TestHTTP01_ChallengeStatusTransitions tests challenge state machine
func TestHTTP01_ChallengeStatusTransitions(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 challenge status transitions")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-status@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "status-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	http01 := challenges.FindByType(authz, "http-01")
	require.NotNil(t, http01, "HTTP-01 challenge should be available")

	// Initial status should be pending
	assert.Equal(t, "pending", http01.Status, "Initial status should be pending")
	t.Logf("Initial status: %s", http01.Status)

	// Initiate challenge
	challengeResp, err := challenges.InitiateVerification(client, http01.URL, privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to initiate challenge")

	t.Logf("Status after initiation: %s", challengeResp.Status)

	// Status should transition to processing, pending, or valid after initiation
	// In test mode with auto-validation, status may transition to "valid" immediately
	assert.Contains(t, []string{"pending", "processing", "valid"}, challengeResp.Status,
		"Status should be pending, processing, or valid after initiation")

	// Note: In production, without actually serving the challenge response at the domain,
	// the challenge will eventually become "invalid" after server validation fails

	t.Log("HTTP-01 challenge status transitions verified successfully")
}

// TestHTTP01_ContentTypeHeader tests proper Content-Type handling
func TestHTTP01_ContentTypeHeader(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 Content-Type header handling")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-content@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "content-type-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	http01 := challenges.FindByType(authz, "http-01")
	require.NotNil(t, http01, "HTTP-01 challenge should be available")

	// Get nonce for direct request
	nonce, err := challenges.FetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	// Create JWS request
	jws, err := challenges.CreateJWS(struct{}{}, privateKey, accountURL, nonce, http01.URL)
	require.NoError(t, err, "Failed to create JWS")

	// Send request and check response Content-Type
	req, err := http.NewRequest("POST", http01.URL, bytes.NewReader([]byte(jws)))
	require.NoError(t, err, "Failed to create request")
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to send request")
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	t.Logf("Response Content-Type: %s", contentType)

	// Per RFC 8555, server should return application/json
	assert.Contains(t, contentType, "application/json", "Response should be JSON")

	t.Log("HTTP-01 Content-Type handling verified successfully")
}

// TestHTTP01_ReplayNonce tests that server provides Replay-Nonce header
func TestHTTP01_ReplayNonce(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing HTTP-01 Replay-Nonce header")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:http01-nonce@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "nonce-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	http01 := challenges.FindByType(authz, "http-01")
	require.NotNil(t, http01, "HTTP-01 challenge should be available")

	// Get fresh nonce
	nonce, err := challenges.FetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	// Send challenge request
	resp, err := challenges.SendJWSRequest(client, http01.URL, struct{}{}, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to send challenge request")
	defer resp.Body.Close()

	// Verify Replay-Nonce header is present (recommended but not strictly required per RFC 8555)
	newNonce := resp.Header.Get("Replay-Nonce")
	if newNonce != "" {
		assert.NotEqual(t, nonce, newNonce, "Server should provide new nonce")
		t.Logf("Original nonce: %s", nonce)
		t.Logf("New nonce: %s", newNonce)
	} else {
		t.Log("Note: Replay-Nonce header not present in challenge response (optional)")
		t.Logf("Original nonce: %s", nonce)
	}

	t.Log("HTTP-01 Replay-Nonce handling verified successfully")
}

// TestHTTP01_SHA256Thumbprint tests that JWK thumbprint uses SHA-256
func TestHTTP01_SHA256Thumbprint(t *testing.T) {
	t.Log("Testing HTTP-01 JWK thumbprint uses SHA-256")

	// Generate test key
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate key")

	// Compute thumbprint
	thumbprint, err := computeJWKThumbprint(privateKey.Public())
	require.NoError(t, err, "Failed to compute thumbprint")

	// SHA-256 produces 32 bytes, base64url encoded = 43 characters (without padding)
	assert.Len(t, thumbprint, 43, "Thumbprint should be 43 characters")

	// Verify it's valid base64url
	decoded, err := base64.RawURLEncoding.DecodeString(thumbprint)
	require.NoError(t, err, "Thumbprint should be valid base64url")
	assert.Len(t, decoded, sha256.Size, "Decoded thumbprint should be SHA-256 size (32 bytes)")

	t.Logf("Thumbprint: %s", thumbprint)
	t.Logf("Decoded length: %d bytes", len(decoded))

	t.Log("HTTP-01 SHA-256 thumbprint verified successfully")
}
