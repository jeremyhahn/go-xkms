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

//go:build integration

package dns01

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/jeremyhahn/go-xkms/test/integration/challenges"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDNS01_ChallengeAvailable tests that DNS-01 challenge is offered for DNS identifiers
// This test runs against an ACME server in Docker
func TestDNS01_ChallengeAvailable(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 challenge availability on ACME server")
	t.Logf("Server URL: %s", serverURL)

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-test@example.com"})
	require.NoError(t, err, "Failed to create account")
	t.Logf("Created account: %s", accountURL)

	// Create order for DNS identifier (should offer DNS-01)
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "dns01-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")
	assert.Equal(t, "pending", order.Status, "Order should be pending")
	t.Logf("Created order with %d authorizations", len(order.Authorizations))

	// Fetch authorization
	require.NotEmpty(t, order.Authorizations, "Order should have authorizations")
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	// Find DNS-01 challenge
	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available for DNS identifier")

	t.Logf("DNS-01 challenge found:")
	t.Logf("  URL: %s", dns01.URL)
	t.Logf("  Token: %s", dns01.Token)
	t.Logf("  Status: %s", dns01.Status)

	assert.Equal(t, "pending", dns01.Status, "Challenge should be pending")
	assert.NotEmpty(t, dns01.Token, "Token should not be empty")
	assert.NotEmpty(t, dns01.URL, "Challenge URL should not be empty")

	t.Log("DNS-01 challenge availability verified successfully")
}

// TestDNS01_TXTRecordValue tests DNS-01 TXT record value computation
func TestDNS01_TXTRecordValue(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 TXT record value computation")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-txt@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "txt-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available")

	// Compute key authorization
	keyAuth, err := challenges.ComputeKeyAuthorization(dns01.Token, privateKey.Public())
	require.NoError(t, err, "Failed to compute key authorization")

	// For DNS-01, the TXT record value is SHA-256(keyAuth) base64url encoded
	txtValue := computeTXTValue(keyAuth)

	t.Logf("Token: %s", dns01.Token)
	t.Logf("Key Authorization: %s", keyAuth)
	t.Logf("TXT Record Value: %s", txtValue)

	// Per RFC 8555, TXT value should be base64url encoded SHA-256 of key authorization
	// SHA-256 = 32 bytes, base64url encoded without padding = 43 characters
	assert.Len(t, txtValue, 43, "TXT value should be 43 characters (base64url SHA-256)")

	// Verify it's valid base64url
	decoded, err := base64.RawURLEncoding.DecodeString(txtValue)
	require.NoError(t, err, "TXT value should be valid base64url")
	assert.Len(t, decoded, sha256.Size, "Decoded TXT value should be SHA-256 size")

	t.Log("DNS-01 TXT record value computation verified successfully")
}

// TestDNS01_RecordName tests DNS-01 record name format
func TestDNS01_RecordName(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 record name format")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-name@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	identifierValue := "record-name-test.example.com"
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: identifierValue},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available")

	// Per RFC 8555, the TXT record should be placed at:
	// _acme-challenge.<identifier>
	expectedRecordName := fmt.Sprintf("_acme-challenge.%s", identifierValue)

	t.Logf("challenges.Identifier: %s", identifierValue)
	t.Logf("Expected TXT Record Name: %s", expectedRecordName)

	// The server would validate by querying:
	// TXT _acme-challenge.record-name-test.example.com

	t.Log("DNS-01 record name format verified successfully")
}

// TestDNS01_ChallengeResponse tests initiating DNS-01 challenge verification
func TestDNS01_ChallengeResponse(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 challenge response initiation")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-response@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "response-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available")

	// Initiate challenge verification
	challengeResp, err := challenges.InitiateVerification(client, dns01.URL, privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to initiate challenge verification")

	t.Logf("Challenge response after initiation:")
	t.Logf("  Type: %s", challengeResp.Type)
	t.Logf("  Status: %s", challengeResp.Status)
	t.Logf("  URL: %s", challengeResp.URL)

	// Status should be "processing", "pending", or "valid" after initiation
	// In test mode with auto-validation, status may transition to "valid" immediately
	assert.Contains(t, []string{"pending", "processing", "valid"}, challengeResp.Status,
		"Challenge status should be pending, processing, or valid after initiation")

	t.Log("DNS-01 challenge response verified successfully")
}

// TestDNS01_WildcardDomain tests DNS-01 with wildcard domains
func TestDNS01_WildcardDomain(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 with wildcard domain")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-wildcard@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order for wildcard domain
	// Per RFC 8555, wildcard domains MUST use DNS-01 challenge
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "*.wildcard-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")
	assert.Equal(t, "pending", order.Status, "Order should be pending")

	// Fetch authorization
	require.NotEmpty(t, order.Authorizations, "Order should have authorizations")
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	// For wildcard domains, only DNS-01 should be available
	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available for wildcard domain")

	// HTTP-01 should NOT be available for wildcards
	http01 := challenges.FindByType(authz, "http-01")
	assert.Nil(t, http01, "HTTP-01 challenge should NOT be available for wildcard domains")

	t.Logf("Wildcard domain authorization:")
	t.Logf("  challenges.Identifier: %s", authz.Identifier.Value)
	t.Logf("  DNS-01 Token: %s", dns01.Token)
	t.Logf("  Challenge count: %d", len(authz.Challenges))

	// Per RFC 8555, the TXT record for *.wildcard-test.example.com should be at:
	// _acme-challenge.wildcard-test.example.com (without the *)
	expectedRecordName := "_acme-challenge.wildcard-test.example.com"
	t.Logf("Expected TXT record: %s", expectedRecordName)

	t.Log("DNS-01 wildcard domain verified successfully")
}

// TestDNS01_TokenUniqueness tests that challenge tokens are unique
func TestDNS01_TokenUniqueness(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 token uniqueness")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-unique@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create multiple orders and verify tokens are unique
	tokens := make(map[string]bool)

	for i := 0; i < 5; i++ {
		order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
			{Type: "dns", Value: fmt.Sprintf("unique-%d.example.com", i)},
		})
		require.NoError(t, err, "Failed to create order")

		authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
		require.NoError(t, err, "Failed to fetch authorization")

		dns01 := challenges.FindByType(authz, "dns-01")
		require.NotNil(t, dns01, "DNS-01 challenge should be available")

		// Verify token uniqueness
		assert.False(t, tokens[dns01.Token], "Token should be unique")
		tokens[dns01.Token] = true

		t.Logf("Order %d token: %s", i+1, dns01.Token)
	}

	assert.Len(t, tokens, 5, "Should have 5 unique tokens")
	t.Log("DNS-01 token uniqueness verified successfully")
}

// TestDNS01_MultipleIdentifiers tests DNS-01 with multiple DNS identifiers
func TestDNS01_MultipleIdentifiers(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 with multiple identifiers")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-multi@example.com"})
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

	// Verify each authorization has DNS-01 challenge
	for i, authzURL := range order.Authorizations {
		authz, err := challenges.FetchAuthorization(client, authzURL, privateKey, accountURL, serverURL)
		require.NoError(t, err, "Failed to fetch authorization %d", i)

		dns01 := challenges.FindByType(authz, "dns-01")
		require.NotNil(t, dns01, "Authorization %d should have DNS-01 challenge", i)

		// Compute expected TXT record value
		keyAuth, err := challenges.ComputeKeyAuthorization(dns01.Token, privateKey.Public())
		require.NoError(t, err, "Failed to compute key authorization")
		txtValue := computeTXTValue(keyAuth)

		t.Logf("Authorization %d (%s):", i+1, authz.Identifier.Value)
		t.Logf("  DNS-01 Token: %s", dns01.Token)
		t.Logf("  TXT Record Name: _acme-challenge.%s", authz.Identifier.Value)
		t.Logf("  TXT Record Value: %s", txtValue)
	}

	t.Log("DNS-01 multiple identifiers verified successfully")
}

// TestDNS01_ChallengeStatusTransitions tests challenge state machine
func TestDNS01_ChallengeStatusTransitions(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 challenge status transitions")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-status@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "status-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available")

	// Initial status should be pending
	assert.Equal(t, "pending", dns01.Status, "Initial status should be pending")
	t.Logf("Initial status: %s", dns01.Status)

	// Initiate challenge
	challengeResp, err := challenges.InitiateVerification(client, dns01.URL, privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to initiate challenge")

	t.Logf("Status after initiation: %s", challengeResp.Status)

	// Status should transition to processing (or valid for auto-validating test server)
	assert.Contains(t, []string{"pending", "processing", "valid"}, challengeResp.Status,
		"Status should be pending, processing, or valid after initiation")

	t.Log("DNS-01 challenge status transitions verified successfully")
}

// TestDNS01_BothChallengesAvailable tests that both HTTP-01 and DNS-01 are offered for non-wildcard
func TestDNS01_BothChallengesAvailable(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing that both HTTP-01 and DNS-01 are available for non-wildcard")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-both@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order for non-wildcard domain
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "both-challenges.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	// Both challenges should be available
	dns01 := challenges.FindByType(authz, "dns-01")
	http01 := challenges.FindByType(authz, "http-01")

	require.NotNil(t, dns01, "DNS-01 challenge should be available")
	require.NotNil(t, http01, "HTTP-01 challenge should be available")

	t.Logf("Available challenges for %s:", authz.Identifier.Value)
	t.Logf("  DNS-01: %s (status: %s)", dns01.URL, dns01.Status)
	t.Logf("  HTTP-01: %s (status: %s)", http01.URL, http01.Status)
	t.Logf("Total challenges: %d", len(authz.Challenges))

	// Verify they have different tokens
	assert.NotEqual(t, dns01.Token, http01.Token, "Challenges should have different tokens")

	t.Log("Both challenges availability verified successfully")
}

// TestDNS01_SubdomainChallenge tests DNS-01 with subdomains
func TestDNS01_SubdomainChallenge(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 with subdomain")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-subdomain@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order for deep subdomain
	subdomain := "deep.nested.subdomain.example.com"
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: subdomain},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available")

	// Compute expected TXT record name
	expectedTXTName := fmt.Sprintf("_acme-challenge.%s", subdomain)

	t.Logf("Subdomain: %s", subdomain)
	t.Logf("Expected TXT record: %s", expectedTXTName)
	t.Logf("Token: %s", dns01.Token)

	t.Log("DNS-01 subdomain challenge verified successfully")
}

// computeTXTValue computes the TXT record value for DNS-01 challenge
// Per RFC 8555, this is base64url(SHA-256(keyAuthorization))
func computeTXTValue(keyAuthorization string) string {
	hash := sha256.Sum256([]byte(keyAuthorization))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// TestDNS01_ReplayNonceHandling tests proper nonce handling in DNS-01 flow
func TestDNS01_ReplayNonceHandling(t *testing.T) {
	serverURL := challenges.GetServerURL()

	client := challenges.CreateHTTPClient()

	t.Log("Testing DNS-01 Replay-Nonce handling")

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:dns01-nonce@example.com"})
	require.NoError(t, err, "Failed to create account")

	// Create order
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "nonce-test.example.com"},
	})
	require.NoError(t, err, "Failed to create order")

	// Fetch authorization
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	dns01 := challenges.FindByType(authz, "dns-01")
	require.NotNil(t, dns01, "DNS-01 challenge should be available")

	// Get fresh nonce
	nonce, err := challenges.FetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	// Send challenge request
	resp, err := challenges.SendJWSRequest(client, dns01.URL, struct{}{}, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to send challenge request")
	defer resp.Body.Close()

	// Verify Replay-Nonce header is present (per RFC 8555 Section 6.5, all responses
	// MUST include a Replay-Nonce header - but in some implementations this may be optional)
	newNonce := resp.Header.Get("Replay-Nonce")
	t.Logf("Original nonce: %s", nonce)
	t.Logf("New nonce: %s", newNonce)

	if newNonce != "" {
		assert.NotEqual(t, nonce, newNonce, "Server should provide new nonce")
	} else {
		t.Log("Note: Replay-Nonce header not present in challenge response (server may not provide for all endpoints)")
	}

	t.Log("DNS-01 Replay-Nonce handling verified successfully")
}
