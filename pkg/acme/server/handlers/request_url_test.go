//go:build codec_json

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

package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequestURL_NoPathPrefix verifies correct URL construction when
// baseRESTURI has no path prefix (e.g., https://acme.example.com).
func TestRequestURL_NoPathPrefix(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Default test service has baseRESTURI = "https://acme.test.example.com"
	req := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)

	url, err := service.requestURL(req)
	require.NoError(t, err)
	assert.Equal(t, "https://acme.test.example.com/acme/new-account", url)
}

// TestRequestURL_WithAPIPrefix verifies correct URL construction when
// baseRESTURI includes a path prefix like /api/v1. This is the regression
// test for the double-path bug where r.URL.Path includes the same prefix,
// causing URLs like https://host/api/v1/api/v1/acme/new-account.
func TestRequestURL_WithAPIPrefix(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Override baseRESTURI to include /api/v1 prefix (production scenario)
	service.baseRESTURI = "https://server.example.internal:9443/api/v1"

	// gorilla/mux subrouters do NOT strip the prefix from r.URL.Path,
	// so the request path includes the full /api/v1 prefix
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acme/new-account", nil)

	url, err := service.requestURL(req)
	require.NoError(t, err)

	// Must NOT double the prefix
	assert.Equal(t, "https://server.example.internal:9443/api/v1/acme/new-account", url)
	assert.NotContains(t, url, "/api/v1/api/v1",
		"URL must not contain doubled path prefix")
}

// TestRequestURL_WithDeepPrefix verifies correct URL construction when
// baseRESTURI includes a multi-level path prefix.
func TestRequestURL_WithDeepPrefix(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.baseRESTURI = "https://host.example.com:8443/platform/api/v2"

	req := httptest.NewRequest(http.MethodPost, "/platform/api/v2/acme/new-order", nil)

	url, err := service.requestURL(req)
	require.NoError(t, err)
	assert.Equal(t, "https://host.example.com:8443/platform/api/v2/acme/new-order", url)
}

// TestRequestURL_InvalidBaseURI verifies error handling for malformed base URIs.
func TestRequestURL_InvalidBaseURI(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.baseRESTURI = "://invalid"

	req := httptest.NewRequest(http.MethodPost, "/acme/new-account", nil)

	_, err := service.requestURL(req)
	assert.Error(t, err)
}

// TestParseJWS_WithAPIPrefix verifies that parseJWS correctly validates the
// JWS url header when routes are mounted under a path prefix. This is the
// end-to-end regression test for the ACME "Failed to parse account key" bug.
func TestParseJWS_WithAPIPrefix(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Simulate production: baseRESTURI includes /api/v1
	service.baseRESTURI = "https://server.example.internal:9443/api/v1"

	key := generateTestKey(t)

	// The JWS url field must match what the directory handler returns:
	// baseRESTURI + "/acme/new-account"
	jwsURL := "https://server.example.internal:9443/api/v1/acme/new-account"

	// Create a JWS request where URL in JWS header matches the directory URL
	req := createJWSRequest(t, service, key, jwsURL, map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:test@example.com"},
	}, false, 0)

	// Override the request URL path to simulate gorilla/mux behavior
	// (subrouters keep the full path including prefix)
	req.URL.Path = "/api/v1/acme/new-account"

	jwk, payload, err := service.parseJWS(req)
	require.NoError(t, err, "parseJWS must succeed when baseRESTURI has path prefix")
	assert.NotNil(t, jwk)
	assert.NotEmpty(t, payload)
}

// TestParseJWS_WithAPIPrefix_URLMismatch verifies that parseJWS correctly
// rejects JWS requests where the url field doesn't match.
func TestParseJWS_WithAPIPrefix_URLMismatch(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.baseRESTURI = "https://server.example.internal:9443/api/v1"

	key := generateTestKey(t)

	// JWS url field points to a different endpoint
	wrongURL := "https://server.example.internal:9443/api/v1/acme/new-order"

	req := createJWSRequest(t, service, key, wrongURL, map[string]interface{}{
		"termsOfServiceAgreed": true,
	}, false, 0)

	// But the actual request path is /acme/new-account
	req.URL.Path = "/api/v1/acme/new-account"

	_, _, err := service.parseJWS(req)
	assert.Error(t, err, "parseJWS must reject JWS with mismatched url")
	assert.Contains(t, err.Error(), "url header does not match")
}

// TestParseKID_WithAPIPrefix verifies that parseKID correctly validates the
// JWS url header when routes are mounted under a path prefix.
func TestParseKID_WithAPIPrefix(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Simulate production: baseRESTURI includes /api/v1
	service.baseRESTURI = "https://server.example.internal:9443/api/v1"

	key := generateTestKey(t)

	// First, create an account so we have a valid KID
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	// Serialize the public key as PEM (matching new_account.go storage format)
	keyPEM, err := xkmssdk.EncodePublicKeyPEM(key.PublicKey)
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:      1,
		Status:  "valid",
		Contact: []string{"mailto:test@example.com"},
		Key:     string(keyPEM),
	}
	ctx := t.Context()
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	// The JWS url field matches the directory-derived URL
	jwsURL := fmt.Sprintf("https://server.example.internal:9443/api/v1/acme/account/%d", account.ID)

	// Create JWS with KID
	req := createJWSRequest(t, service, key, jwsURL, nil, true, account.ID)

	// Override the request URL path to simulate gorilla/mux behavior
	req.URL.Path = fmt.Sprintf("/api/v1/acme/account/%d", account.ID)

	acct, _, err := service.parseKID(ctx, req)
	require.NoError(t, err, "parseKID must succeed when baseRESTURI has path prefix")
	assert.Equal(t, account.ID, acct.ID)
}

// TestRequestURL_AllACMEEndpoints ensures requestURL produces correct URLs
// for all ACME endpoints when mounted under /api/v1.
func TestRequestURL_AllACMEEndpoints(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	service.baseRESTURI = "https://server.example.com:9443/api/v1"

	endpoints := []struct {
		path     string
		expected string
	}{
		{"/api/v1/acme/directory", "https://server.example.com:9443/api/v1/acme/directory"},
		{"/api/v1/acme/new-nonce", "https://server.example.com:9443/api/v1/acme/new-nonce"},
		{"/api/v1/acme/new-account", "https://server.example.com:9443/api/v1/acme/new-account"},
		{"/api/v1/acme/new-order", "https://server.example.com:9443/api/v1/acme/new-order"},
		{"/api/v1/acme/revoke-cert", "https://server.example.com:9443/api/v1/acme/revoke-cert"},
		{"/api/v1/acme/key-change", "https://server.example.com:9443/api/v1/acme/key-change"},
		{"/api/v1/acme/authz/123", "https://server.example.com:9443/api/v1/acme/authz/123"},
		{"/api/v1/acme/order/456/finalize", "https://server.example.com:9443/api/v1/acme/order/456/finalize"},
		{"/api/v1/acme/cert/789", "https://server.example.com:9443/api/v1/acme/cert/789"},
		{"/api/v1/acme/account/1", "https://server.example.com:9443/api/v1/acme/account/1"},
	}

	for _, ep := range endpoints {
		t.Run(strings.TrimPrefix(ep.path, "/api/v1"), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, ep.path, nil)
			url, err := service.requestURL(req)
			require.NoError(t, err)
			assert.Equal(t, ep.expected, url)
			assert.NotContains(t, url, "/api/v1/api/v1",
				"URL must not contain doubled path prefix")
		})
	}
}
