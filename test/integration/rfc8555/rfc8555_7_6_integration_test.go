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

// RFC 8555 Section 7.6 - Certificate Revocation

// TestRFC_7_6_CertificateRevocation verifies RFC 8555 Section 7.6 - Certificate Revocation
// Requirements:
// - Server MUST provide revokeCert endpoint
// - Server MUST accept revocation requests
func TestRFC_7_6_CertificateRevocation(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 7.6 - Testing certificate revocation endpoint")

	// Create account
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc7.6@example.com")

	// Test revocation endpoint (with dummy certificate)
	nonce := integration.GetNonce(t, integration.TestServerURL)
	revocationPayload := map[string]interface{}{
		"certificate": "dummy-cert-base64",
		"reason":      0,
	}
	revocationJWS := integration.CreateJWS(t, accountKey, nonce, integration.TestServerURL+"/acme/revoke-cert", revocationPayload, true, accountURL)

	resp, err := http.Post(integration.TestServerURL+"/acme/revoke-cert", "application/jose+json", bytes.NewReader([]byte(revocationJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Endpoint must be accessible (will fail with invalid cert, but should respond)
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "Revocation endpoint MUST exist")
	assert.True(t, resp.StatusCode < 500, "Revocation endpoint MUST handle requests")

	t.Logf("✓ Certificate revocation endpoint is accessible, status: %d", resp.StatusCode)
}
