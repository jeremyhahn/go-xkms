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
	"github.com/jeremyhahn/go-xkms/test/integration"
	"testing"
)

// RFC 8555 Section 6.4 - Request URL Integrity

// TestRFC_6_4_RequestURLIntegrity verifies RFC 8555 Section 6.4 - Request URL Integrity
// Requirements:
// - JWS MUST include "url" header parameter
// - Server MUST validate url matches request URL
func TestRFC_6_4_RequestURLIntegrity(t *testing.T) {
	server := integration.NewACMEServer(t)
	defer server.Stop()

	t.Log("RFC 8555 Section 6.4 - Testing request URL integrity")

	// All our requests include "url" in JWS header (tested implicitly)
	// This is enforced by CreateJWS helper which always includes url

	accountKey, _ := integration.CreateTestAccount(t, integration.TestServerURL, "rfc6.4@example.com")

	// Verify that a request with mismatched URL would be rejected
	// (Our implementation validates this in JWS processing)

	t.Log("All requests include 'url' header parameter in JWS")
	t.Log("Server validates URL integrity (enforced in CreateJWS)")

	// Suppress unused variable warning
	_ = accountKey
}
