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

// RFC 8555 Section 6.3 - POST-as-GET Requests

// TestRFC_6_3_POSTasGET verifies RFC 8555 Section 6.3 - POST-as-GET Requests
// Requirements:
// - Server MUST support POST-as-GET with empty payload
// - Server MUST return resource representation
func TestRFC_6_3_POSTasGET(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 6.3 - Testing POST-as-GET requests")

	// Create account and order
	accountKey, accountURL := integration.CreateTestAccount(t, integration.TestServerURL, "rfc6.3@example.com")
	_, authzURLs := integration.CreateTestOrder(t, integration.TestServerURL, accountKey, accountURL, "rfc-test-6-3.example.com")

	// POST-as-GET with empty payload ("")
	nonce := integration.GetNonce(t, integration.TestServerURL)
	postAsGetJWS := integration.CreateJWS(t, accountKey, nonce, authzURLs[0], "", true, accountURL)

	resp, err := http.Post(authzURLs[0], "application/jose+json", bytes.NewReader([]byte(postAsGetJWS)))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "POST-as-GET MUST return 200 OK")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var authz entities.ACMEAuthorization
	err = json.Unmarshal(body, &authz)
	require.NoError(t, err, "POST-as-GET MUST return resource representation")

	assert.NotEmpty(t, authz.Identifier, "POST-as-GET response must include resource data")

	t.Logf("✓ POST-as-GET successfully retrieved authorization")
}
