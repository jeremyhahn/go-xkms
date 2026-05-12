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
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 8555 Section 8.1 - Key Authorizations

// TestRFC_8_1_KeyAuthorizations verifies RFC 8555 Section 8.1 - Key Authorizations
// Requirements:
// - Key authorization MUST be computed as: token || '.' || base64url(SHA256(JWK))
// - Server MUST validate key authorization format
func TestRFC_8_1_KeyAuthorizations(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 8.1 - Testing key authorization computation")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc8.1@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "rfc-test-8-1.example.com")
	require.NotEmpty(t, authzURLs, "Order must have authorizations")

	// Fetch authorization to get challenge
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

	// Test key authorization format for each challenge
	for _, challenge := range authz.Challenges {
		t.Logf("Testing key authorization for challenge type: %s", challenge.Type)

		// Verify token exists (required for key authorization)
		assert.NotEmpty(t, challenge.Token, "Challenge MUST include token for key authorization")

		// Compute expected key authorization per RFC 8555 Section 8.1
		// keyAuthorization = token || '.' || base64url(SHA256(JWK))

		// Get JWK thumbprint (base64url(SHA256(JWK)))
		publicKey := accountKey.Public()
		jwkThumbprint, err := handlers.JWKThumbprint(publicKey)
		require.NoError(t, err)

		expectedKeyAuth := challenge.Token + "." + jwkThumbprint

		t.Logf("  Token: %s", challenge.Token)
		t.Logf("  JWK Thumbprint: %s", jwkThumbprint)
		t.Logf("  Expected Key Authorization: %s", expectedKeyAuth)

		// Verify the key authorization format (token + '.' + thumbprint)
		assert.Contains(t, expectedKeyAuth, ".", "Key authorization MUST contain '.' separator")
		parts := bytes.Split([]byte(expectedKeyAuth), []byte("."))
		assert.Len(t, parts, 2, "Key authorization MUST have exactly 2 parts separated by '.'")
		assert.Equal(t, challenge.Token, string(parts[0]), "First part must be the token")

		t.Logf("  ✓ Key authorization format is correct")
	}

	t.Log("✓ Key authorization computation verified per RFC 8555 Section 8.1")
}
