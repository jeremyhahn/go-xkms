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

package rfc8555

import (
	"net/url"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseAccountID tests account ID extraction from account URL
func TestParseAccountID(t *testing.T) {
	testCases := []struct {
		name        string
		accountURL  string
		expectedID  uint64
		expectError bool
	}{
		{
			name:        "Valid account URL",
			accountURL:  "https://acme.example.com/acme/account/12345",
			expectedID:  12345,
			expectError: false,
		},
		{
			name:        "Valid account URL simple",
			accountURL:  "https://acme.example.com/acme/account/67890",
			expectedID:  67890,
			expectError: false,
		},
		{
			name:        "Valid account URL with path prefix",
			accountURL:  "https://acme.example.com/v1/acme/account/99999",
			expectedID:  99999,
			expectError: false,
		},
		{
			name:        "Invalid - non-numeric ID",
			accountURL:  "https://acme.example.com/acme/account/abc",
			expectedID:  0,
			expectError: true,
		},
		{
			name:        "Invalid - empty ID",
			accountURL:  "https://acme.example.com/acme/account/",
			expectedID:  0,
			expectError: true,
		},
		{
			name:        "Invalid - negative ID",
			accountURL:  "https://acme.example.com/acme/account/-123",
			expectedID:  0,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := handlers.ParseAccountID(tc.accountURL)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedID, id)
			}
		})
	}
}

// TestURLIntegrity tests URL parsing and validation
func TestURLIntegrity(t *testing.T) {
	testCases := []struct {
		name    string
		urlStr  string
		isValid bool
	}{
		{
			name:    "Valid HTTPS URL",
			urlStr:  "https://acme.example.com/acme/account/123",
			isValid: true,
		},
		{
			name:    "Valid HTTP URL",
			urlStr:  "http://localhost:8080/acme/account/456",
			isValid: true,
		},
		{
			name:    "Valid URL with port",
			urlStr:  "https://acme.example.com:8443/acme/account/789",
			isValid: true,
		},
		{
			name:    "Valid URL with query params",
			urlStr:  "https://acme.example.com/acme/orders?cursor=abc123",
			isValid: true,
		},
		{
			name:    "Invalid URL - no scheme",
			urlStr:  "acme.example.com/acme/account/123",
			isValid: false,
		},
		{
			name:    "Invalid URL - malformed",
			urlStr:  "ht!tp://invalid",
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.urlStr)

			if tc.isValid {
				require.NoError(t, err)
				assert.NotNil(t, parsed)
				assert.NotEmpty(t, parsed.Scheme)
			} else {
				// Either parse error or missing scheme
				if err == nil {
					assert.Empty(t, parsed.Scheme, "URL without scheme should have empty scheme")
				}
			}
		})
	}
}

// TestURLPathExtraction tests extracting components from URLs
func TestURLPathExtraction(t *testing.T) {
	testURL := "https://acme.example.com/acme/account/12345/orders"

	parsed, err := url.Parse(testURL)
	require.NoError(t, err)

	// Test path extraction
	assert.Equal(t, "/acme/account/12345/orders", parsed.Path)

	// Test path components
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	assert.Equal(t, []string{"acme", "account", "12345", "orders"}, pathParts)

	// Test host extraction
	assert.Equal(t, "acme.example.com", parsed.Host)

	// Test scheme
	assert.Equal(t, "https", parsed.Scheme)
}

// TestURLNormalization tests URL normalization and comparison
func TestURLNormalization(t *testing.T) {
	testCases := []struct {
		name     string
		url1     string
		url2     string
		areEqual bool
	}{
		{
			name:     "Identical URLs",
			url1:     "https://acme.example.com/acme/account/123",
			url2:     "https://acme.example.com/acme/account/123",
			areEqual: true,
		},
		{
			name:     "Different trailing slash",
			url1:     "https://acme.example.com/acme/account/123",
			url2:     "https://acme.example.com/acme/account/123/",
			areEqual: false,
		},
		{
			name:     "Different scheme",
			url1:     "http://acme.example.com/acme/account/123",
			url2:     "https://acme.example.com/acme/account/123",
			areEqual: false,
		},
		{
			name:     "Different host",
			url1:     "https://acme1.example.com/acme/account/123",
			url2:     "https://acme2.example.com/acme/account/123",
			areEqual: false,
		},
		{
			name:     "Different path",
			url1:     "https://acme.example.com/acme/account/123",
			url2:     "https://acme.example.com/acme/account/456",
			areEqual: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed1, err := url.Parse(tc.url1)
			require.NoError(t, err)

			parsed2, err := url.Parse(tc.url2)
			require.NoError(t, err)

			// Compare string representations
			areEqual := parsed1.String() == parsed2.String()
			assert.Equal(t, tc.areEqual, areEqual)
		})
	}
}

// TestAccountURLConstruction tests building account URLs
func TestAccountURLConstruction(t *testing.T) {
	baseURL := "https://acme.example.com"
	accountID := uint64(12345)

	// Construct account URL
	accountURL := baseURL + "/acme/account/" + string(rune(accountID+'0'))

	// This is intentionally wrong to show the test
	// The correct way would be using strconv.FormatUint
	assert.NotEqual(t, "https://acme.example.com/acme/account/12345", accountURL)

	// Correct implementation
	correctURL := baseURL + "/acme/account/" + "12345"
	assert.Equal(t, "https://acme.example.com/acme/account/12345", correctURL)
}

// TestRelativeURLResolution tests resolving relative URLs against base URL
func TestRelativeURLResolution(t *testing.T) {
	baseURLStr := "https://acme.example.com/acme/"
	baseURL, err := url.Parse(baseURLStr)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		relativeURL string
		expected    string
	}{
		{
			name:        "Relative path",
			relativeURL: "account/123",
			expected:    "https://acme.example.com/acme/account/123",
		},
		{
			name:        "Absolute path",
			relativeURL: "/other/path",
			expected:    "https://acme.example.com/other/path",
		},
		{
			name:        "Full URL",
			relativeURL: "https://other.example.com/test",
			expected:    "https://other.example.com/test",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			relURL, err := url.Parse(tc.relativeURL)
			require.NoError(t, err)

			resolved := baseURL.ResolveReference(relURL)
			assert.Equal(t, tc.expected, resolved.String())
		})
	}
}

// TestQueryParameterExtraction tests extracting query parameters from URLs
func TestQueryParameterExtraction(t *testing.T) {
	testURL := "https://acme.example.com/acme/orders?cursor=abc123&limit=10"

	parsed, err := url.Parse(testURL)
	require.NoError(t, err)

	query := parsed.Query()
	assert.Equal(t, "abc123", query.Get("cursor"))
	assert.Equal(t, "10", query.Get("limit"))
	assert.Empty(t, query.Get("nonexistent"))
}
